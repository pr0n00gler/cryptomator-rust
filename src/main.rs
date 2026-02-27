use cryptomator::crypto::{
    CipherCombo, Cryptor, DEFAULT_FORMAT, DEFAULT_MASTER_KEY_FILE, DEFAULT_SHORTENING_THRESHOLD,
    DEFAULT_VAULT_FILENAME, MasterKey, MasterKeyJson, Vault,
};
use cryptomator::cryptofs::{CryptoFs, FileSystem, OpenOptions, parent_path};
use cryptomator::logging::init_logger;
use cryptomator::providers::LocalFs;

use tracing::info;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, ValueEnum};
use zeroize::Zeroizing;

use cryptomator::frontends::auth::WebDavAuth;
use cryptomator::frontends::mount::mount_nfs;
use cryptomator::frontends::mount::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;
use std::io::Write;
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

    /// Webdav-server username for Basic Auth.
    /// When provided, the WebDAV password is always read from the interactive
    /// prompt and never accepted on the command line — passing a password via
    /// CLI arguments exposes it in shell history and `ps` output.
    #[arg(long)]
    webdav_user: Option<String>,

    /// NFS-server listen address
    #[arg(short, long, default_value = "127.0.0.1:11111")]
    nfs_listen_address: String,

    /// Start in read-only mode (block write operations)
    #[arg(long)]
    read_only: bool,
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();

    unsafe { env::set_var("RUST_LOG", opts.log_level) };
    let _guard = init_logger();

    let storage_path = Path::new(opts.storage_path.as_str()).to_path_buf();

    let vault_path = match opts.vault_path {
        Some(m) => Path::new(m.as_str()).to_path_buf(),
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
    // Wrap immediately in Zeroizing so the plaintext password is wiped from
    // the heap when `pass` goes out of scope at the end of this function,
    // regardless of the return path.
    let pass = Zeroizing::new(
        rpassword::prompt_password("Vault password: ").expect("Unable to read password"),
    );

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

    let masterkey = MasterKey::from_masterkey_json(mk_json, pass.as_str()).unwrap();
    let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    key.extend_from_slice(masterkey.primary_master_key.as_ref());
    key.extend_from_slice(masterkey.hmac_master_key.as_ref());

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
    // Wrap immediately in Zeroizing so the plaintext password is wiped from
    // the heap when `pass` drops at the end of this function.
    let pass = Zeroizing::new(
        rpassword::prompt_password("Vault password: ").expect("Unable to read password"),
    );

    info!("Reading old masterkey file...");
    let mk_path = parent_path(&vault_path).join(DEFAULT_MASTER_KEY_FILE);
    let mut mk_file = fs
        .open_file(&mk_path, OpenOptions::new())
        .expect("Failed to open masterkey file");

    // Deserialize into a local binding that is consumed (not cloned) below.
    // Cloning MasterKeyJson would leave a second copy of the base64-encoded
    // wrapped key material on the heap with no zeroize semantics — a full
    // vault-compromise vector if the process is inspected via crash dump or
    // memory scan.
    let mk_json: MasterKeyJson =
        serde_json::from_reader(&mut mk_file).expect("failed to read masterkey file");

    // Snapshot the non-sensitive fields we need to reconstruct the masterkey
    // file BEFORE consuming mk_json.  These are all public, non-secret values.
    let scrypt_salt = mk_json.scryptSalt.clone();
    let scrypt_cost_param = mk_json.scryptCostParam;
    let scrypt_block_size = mk_json.scryptBlockSize;
    let primary_master_key_enc = mk_json.primaryMasterKey.clone();
    let hmac_master_key_enc = mk_json.hmacMasterKey.clone();

    fs.remove_file(&mk_path)
        .expect("failed to delete old masterkey file");

    // Consume mk_json — no clone.  The base64-encoded wrapped keys inside it
    // are moved into from_masterkey_json and dropped at the end of that call.
    let masterkey = MasterKey::from_masterkey_json(mk_json, pass.as_str())
        .expect("Failed to decrypt master key file");
    // `pass` is no longer needed after key derivation.  Drop it explicitly
    // here so the plaintext password bytes are zeroed before the function
    // continues — rather than waiting until the end of the outer scope.
    drop(pass);

    let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    key.extend_from_slice(masterkey.primary_master_key.as_ref());
    key.extend_from_slice(masterkey.hmac_master_key.as_ref());

    info!("Creating a vault...");
    let vault = Vault::create_vault(
        &key,
        DEFAULT_FORMAT,
        CipherCombo::SIV_CTRMAC,
        DEFAULT_SHORTENING_THRESHOLD,
    )
    .expect("failed to create vault");

    // Recompute the versionMac over the new version number (999) using the
    // unwrapped HMAC master key.  We rebuild MasterKeyJson from scratch rather
    // than mutating a leftover clone, so there is never a second live copy of
    // the wrapped key material.
    let new_version: u32 = 999;
    let mut version_mac: Hmac<Sha256> =
        Hmac::new_from_slice(masterkey.hmac_master_key.as_ref()).unwrap();
    version_mac.update(&new_version.to_be_bytes());
    let version_mac_bytes = version_mac.finalize().into_bytes();

    let updated_mk_json = MasterKeyJson {
        version: new_version,
        scryptSalt: scrypt_salt,
        scryptCostParam: scrypt_cost_param,
        scryptBlockSize: scrypt_block_size,
        primaryMasterKey: primary_master_key_enc,
        hmacMasterKey: hmac_master_key_enc,
        versionMac: STANDARD.encode(version_mac_bytes),
    };

    info!("Rewriting masterkey file...");
    let mk_file = fs
        .create_file(mk_path)
        .expect("failed to create new masterkey file");
    serde_json::to_writer(mk_file, &updated_mk_json)
        .expect("failed to write data to a masterkey file");

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
    // Wrap immediately in Zeroizing so the plaintext vault password is wiped
    // from the heap as soon as key derivation finishes.  The `Zeroizing`
    // binding is dropped at the end of the inner block below, before any
    // long-running async server tasks are started.
    let vault = {
        let pass = Zeroizing::new(
            rpassword::prompt_password("Vault password: ").expect("Unable to read password"),
        );
        info!("Unlocking the storage...");
        info!("Deriving keys...");
        Vault::open(&fs, vault_path, pass.as_str()).expect("failed to open vault")
        // `pass` is dropped (and zeroed) here — before the server loop begins.
    };

    let cryptor = Cryptor::new(vault);
    let crypto_fs = if u.read_only {
        info!("Starting in read-only mode...");
        CryptoFs::new_read_only(
            full_storage_path
                .as_ref()
                .to_str()
                .expect("Failed to convert Path to &str"),
            cryptor,
            fs,
        )
        .expect("Failed to initialize read-only storage")
    } else {
        CryptoFs::new(
            full_storage_path
                .as_ref()
                .to_str()
                .expect("Failed to convert Path to &str"),
            cryptor,
            fs,
        )
        .expect("Failed to initialize storage")
    };
    info!("Storage unlocked!");

    if let Some(webdav_listen_address) = &u.webdav_listen_address {
        let auth = u.webdav_user.as_ref().map(|user| {
            // SEC: always prompt for the WebDAV password interactively.
            // Accepting it via a CLI flag would expose the credential in shell
            // history and `ps` output.
            // Wrap in Zeroizing immediately so the plaintext password is wiped
            // from the heap when `webdav_pass` drops at the end of this closure.
            let webdav_pass = Zeroizing::new(
                rpassword::prompt_password(format!("WebDAV password for {user}: "))
                    .expect("Unable to read WebDAV password"),
            );
            WebDavAuth::new(user, webdav_pass.as_str())
        });

        info!("Starting WebDav server...");
        mount_webdav(webdav_listen_address.clone(), crypto_fs, auth).await;
        return;
    }

    info!("Starting NFS server...");
    mount_nfs(u.nfs_listen_address, crypto_fs).await;
}
