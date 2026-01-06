use cryptomator::crypto::{
    CipherCombo, Cryptor, MasterKey, MasterKeyJson, Vault, DEFAULT_FORMAT, DEFAULT_MASTER_KEY_FILE,
    DEFAULT_SHORTENING_THRESHOLD, DEFAULT_VAULT_FILENAME,
};
use cryptomator::cryptofs::{parent_path, CryptoFs, FileSystem, OpenOptions};
use cryptomator::logging::init_logger;
use cryptomator::providers::LocalFs;

use tracing::info;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, ValueEnum};

use cryptomator::frontends::auth::WebDavAuth;
use cryptomator::frontends::mount::mount_nfs;
use cryptomator::frontends::mount::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

const DEFAULT_STORAGE_SUB_FOLDER: &str = "d";

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum FilesystemProvider {
    Local,
}

#[derive(Parser)]
#[command(version = "0.1.0", author = "pr0n00gler <pr0n00gler@yandex.ru>")]
struct Opts {
    /// Path to a storage
    #[arg(short, long)]
    storage_path: String,

    /// Path to a vault file. By default in the storage directory
    #[arg(short, long)]
    vault_path: Option<String>,

    /// Filesystem provider. Supported values: only "local" for now
    #[arg(value_enum, default_value_t = FilesystemProvider::Local)]
    filesystem_provider: FilesystemProvider,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    subcmd: Command,
}

#[derive(Parser)]
enum Command {
    /// Unlocks a vault
    Unlock(Unlock),

    /// Creates a new vault at the given path
    Create(Create),

    /// Migrates a vault from v7 to v8
    MigrateV7ToV8,
}

#[derive(Parser)]
struct Create {
    /// The Scrypt parameter N
    #[arg(default_value_t = 16384)]
    scrypt_cost: u64,

    /// The Scrypt parameter r
    #[arg(default_value_t = 8)]
    scrypt_block_size: u32,
}

#[derive(Parser)]
struct Unlock {
    /// Webdav-server listen address
    #[arg(short, long)]
    webdav_listen_address: Option<String>,

    /// Webdav-server username for Basic Auth
    #[arg(long)]
    webdav_user: Option<String>,

    /// Webdav-server password for Basic Auth
    #[arg(long)]
    webdav_password: Option<String>,

    /// NFS-server listen address
    #[arg(short, long, default_value = "127.0.0.1:11111")]
    nfs_listen_address: String,
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();

    env::set_var("RUST_LOG", opts.log_level);
    let _guard = init_logger();

    let storage_path = std::path::Path::new(opts.storage_path.as_str()).to_path_buf();

    let vault_path = match opts.vault_path {
        Some(m) => std::path::Path::new(m.as_str()).to_path_buf(),
        None => storage_path.join(DEFAULT_VAULT_FILENAME),
    };

    let full_storage_path = storage_path.join(DEFAULT_STORAGE_SUB_FOLDER);

    match opts.subcmd {
        Command::Create(c) => match opts.filesystem_provider {
            FilesystemProvider::Local => {
                create_command(LocalFs::new(), &vault_path, &full_storage_path, c)
            }
        },
        Command::MigrateV7ToV8 => match opts.filesystem_provider {
            FilesystemProvider::Local => migrate_v7_to_v8_command(LocalFs::new(), &vault_path),
        },
        Command::Unlock(u) => match opts.filesystem_provider {
            FilesystemProvider::Local => {
                unlock_command(LocalFs::new(), &vault_path, &full_storage_path, u).await
            }
        },
    }
}

fn create_command<FS: FileSystem, P: AsRef<Path>>(
    fs: FS,
    vault_path: P,
    full_storage_path: P,
    c: Create,
) {
    let pass = rpassword::prompt_password("Vault password: ").expect("Unable to read password");

    info!("Generating master key...");
    let mk_json = MasterKeyJson::create(pass.as_str(), c.scrypt_cost, c.scrypt_block_size)
        .expect("Failed to generate master key file");
    info!("Master key generated!");

    info!("Saving master key to a file...");
    let mk_path = parent_path(&vault_path).join(DEFAULT_MASTER_KEY_FILE);
    let mk_file = fs
        .create_file(mk_path)
        .expect("Failed to open masterkey file");
    serde_json::to_writer(mk_file, &mk_json).expect("Failed to write master key file");
    info!("Master key saved!");

    let masterkey = MasterKey::from_masterkey_json(mk_json, &pass).unwrap();
    let mut key: Vec<u8> = Vec::with_capacity(64);
    key.extend_from_slice(&masterkey.primary_master_key);
    key.extend_from_slice(&masterkey.hmac_master_key);

    let vault = Vault::create_vault(
        &key,
        DEFAULT_FORMAT,
        CipherCombo::SIV_CTRMAC,
        DEFAULT_SHORTENING_THRESHOLD,
    )
    .expect("failed to create vault");
    let mut vault_file = fs
        .create_file(vault_path)
        .expect("failed to create a file for a vault");
    vault_file
        .write_all(vault.as_bytes())
        .expect("failed to write data to a vault file");

    fs.create_dir(full_storage_path)
        .expect("Failed to create folder for the storage");
}

fn migrate_v7_to_v8_command<FS: FileSystem, P: AsRef<Path>>(fs: FS, vault_path: P) {
    let pass = rpassword::prompt_password("Vault password: ").expect("Unable to read password");

    info!("Reading old masterkey file...");
    let mk_path = parent_path(&vault_path).join(DEFAULT_MASTER_KEY_FILE);
    let mut mk_file = fs
        .open_file(&mk_path, OpenOptions::new())
        .expect("Failed to open masterkey file");

    let mut mk_json: MasterKeyJson =
        serde_json::from_reader(&mut mk_file).expect("failed to read masterkey file");

    fs.remove_file(&mk_path)
        .expect("failed to delete old masterkey file");

    let masterkey = MasterKey::from_masterkey_json(mk_json.clone(), pass.as_str())
        .expect("Failed to decrypt master key file");
    mk_file.seek(SeekFrom::Start(0)).unwrap();

    let mut key: Vec<u8> = Vec::with_capacity(64);
    key.extend_from_slice(&masterkey.primary_master_key);
    key.extend_from_slice(&masterkey.hmac_master_key);

    info!("Creating a vault...");
    let vault = Vault::create_vault(
        &key,
        DEFAULT_FORMAT,
        CipherCombo::SIV_CTRMAC,
        DEFAULT_SHORTENING_THRESHOLD,
    )
    .expect("failed to create vault");

    mk_json.version = 999;
    let mut version_mac: Hmac<Sha256> = Hmac::new_from_slice(&masterkey.hmac_master_key).unwrap();
    version_mac.update(&mk_json.version.to_be_bytes());
    let version_mac_bytes = version_mac.finalize().into_bytes();
    mk_json.versionMac = STANDARD.encode(version_mac_bytes);

    info!("Rewriting masterkey file...");
    let mk_file = fs
        .create_file(mk_path)
        .expect("failed to create new masterkey file");
    serde_json::to_writer(mk_file, &mk_json).expect("failed to write data to a masterkey file");

    info!("Writing a vault file...");
    let mut vault_file = fs
        .create_file(vault_path)
        .expect("failed to create a file for a vault");
    vault_file
        .write_all(vault.as_bytes())
        .expect("failed to write data to a vault file");
}

async fn unlock_command<FS: 'static + FileSystem, P: AsRef<Path>>(
    fs: FS,
    vault_path: P,
    full_storage_path: P,
    u: Unlock,
) {
    let pass = rpassword::prompt_password("Vault password: ").expect("Unable to read password");
    info!("Unlocking the storage...");

    info!("Deriving keys...");

    let vault = Vault::open(&fs, vault_path, pass).expect("failed to open vault");

    let cryptor = Cryptor::new(vault);
    let crypto_fs = CryptoFs::new(
        full_storage_path
            .as_ref()
            .to_str()
            .expect("Failed to convert Path to &str"),
        cryptor,
        fs,
    )
    .expect("Failed to unblock storage");
    info!("Storage unlocked!");

    if let Some(webdav_listen_address) = &u.webdav_listen_address {
        let auth = u.webdav_user.as_ref().map(|user| {
            let pass = u.webdav_password.clone().unwrap_or_else(|| {
                rpassword::prompt_password(format!("WebDAV password for {}: ", user))
                    .expect("Unable to read WebDAV password")
            });
            WebDavAuth::new(user, &pass)
        });

        info!("Starting WebDav server...");
        mount_webdav(webdav_listen_address.clone(), crypto_fs, auth).await;
        return;
    }

    info!("Starting NFS server...");
    mount_nfs(u.nfs_listen_address, crypto_fs).await;
}
