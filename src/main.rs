use cryptomator::crypto::{
    CipherCombo, Cryptor, MasterKey, MasterKeyJson, Vault, DEFAULT_FORMAT, DEFAULT_MASTER_KEY_FILE,
    DEFAULT_SHORTENING_THRESHOLD, DEFAULT_VAULT_FILENAME,
};
use cryptomator::cryptofs::{parent_path, CryptoFs};
use cryptomator::logging::init_logger;
use cryptomator::providers::LocalFs;

use tracing::info;

use clap::Clap;

use cryptomator::frontends::mount::*;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use std::env;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};

const DEFAULT_STORAGE_SUB_FOLDER: &str = "d";

#[derive(Clap)]
#[clap(version = "0.1.0", author = "pr0n00gler <pr0n00gler@yandex.ru>")]
struct Opts {
    /// Path to a storage
    #[clap(short, long)]
    storage_path: String,

    /// Path to a vault file. By default in the storage directory
    #[clap(short, long)]
    vault_path: Option<String>,

    /// Log level
    #[clap(short, long, default_value = "info")]
    log_level: String,

    #[clap(subcommand)]
    subcmd: Command,
}

#[derive(Clap)]
enum Command {
    /// Unlocks a vault
    Unlock(Unlock),

    /// Creates a new vault at the given path
    Create(Create),

    /// Migrates a vault from v7 to v8
    MigrateV7ToV8,
}

#[derive(Clap)]
struct Create {
    /// The Scrypt parameter N
    #[clap(default_value = "16384")]
    scrypt_cost: u64,

    /// The Scrypt parameter r
    #[clap(default_value = "8")]
    scrypt_block_size: u32,
}

#[derive(Clap)]
struct Unlock {
    /// Webdav-server listen address
    #[clap(short, long, default_value = "127.0.0.1:4918")]
    webdav_listen_address: String,

    /// Mountpoint for mounting FUSE filesystem (and Dokan in the future)
    #[cfg(unix)]
    #[clap(short, long)]
    mountpoint: Option<String>,

    /// Options for the FUSE module
    #[cfg(unix)]
    #[clap(short, long, default_value = "-o ro -o fsname=hello")]
    fuse_options: String,
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
        Command::Create(c) => {
            let pass = rpassword::prompt_password_stdout("Vault password: ")
                .expect("Unable to read password");

            info!("Generating master key...");
            let mk_json = MasterKeyJson::create(pass.as_str(), c.scrypt_cost, c.scrypt_block_size)
                .expect("Failed to generate master key file");
            info!("Master key generated!");

            info!("Saving master key to a file...");
            let mk_path = parent_path(&vault_path).join(DEFAULT_MASTER_KEY_FILE);
            let mk_file = OpenOptions::new()
                .write(true)
                .read(true)
                .create(true)
                .open(mk_path)
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
            let mut vault_file =
                std::fs::File::create(vault_path).expect("failed to create a file for a vault");
            vault_file
                .write_all(vault.as_bytes())
                .expect("failed to write data to a vault file");

            std::fs::create_dir(full_storage_path)
                .expect("Failed to create folder for the storage");
        }
        Command::MigrateV7ToV8 => {
            let pass = rpassword::prompt_password_stdout("Vault password: ")
                .expect("Unable to read password");

            info!("Reading old masterkey file...");
            let mk_path = parent_path(&vault_path).join(DEFAULT_MASTER_KEY_FILE);
            let mut mk_file = OpenOptions::new()
                .write(true)
                .read(true)
                .open(mk_path)
                .expect("Failed to open masterkey file");

            let mut mk_json: MasterKeyJson =
                serde_json::from_reader(&mk_file).expect("failed to read masterkey file");

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
            let mut version_mac: Hmac<Sha256> =
                Hmac::new_from_slice(&masterkey.hmac_master_key).unwrap();
            version_mac.update(&mk_json.version.to_be_bytes());
            let version_mac_bytes = version_mac.finalize().into_bytes();
            mk_json.versionMac = base64::encode(version_mac_bytes);

            info!("Rewriting masterkey file...");
            mk_file.set_len(0).unwrap();
            serde_json::to_writer(mk_file, &mk_json)
                .expect("failed to write data to a masterkey file");

            info!("Writing a vault file...");
            let mut vault_file =
                std::fs::File::create(vault_path).expect("failed to create a file for a vault");
            vault_file
                .write_all(vault.as_bytes())
                .expect("failed to write data to a vault file");
        }
        Command::Unlock(u) => {
            let local_fs = LocalFs::new();
            let pass = rpassword::prompt_password_stdout("Vault password: ")
                .expect("Unable to read password");
            info!("Unlocking the storage...");

            info!("Deriving keys...");

            let vault = Vault::open(vault_path, pass).expect("failed to open vault");

            let cryptor = Cryptor::new(vault);
            let crypto_fs = CryptoFs::new(
                full_storage_path
                    .to_str()
                    .expect("Failed to convert Path to &str"),
                cryptor,
                local_fs,
            )
            .expect("Failed to unblock storage");
            info!("Storage unlocked!");

            #[cfg(unix)]
            if let Some(mountpoint) = u.mountpoint {
                mount_fuse(mountpoint, u.fuse_options, crypto_fs);
                return;
            }

            info!("Starting WebDav server...");
            mount_webdav(u.webdav_listen_address, crypto_fs).await;
        }
    }
}
