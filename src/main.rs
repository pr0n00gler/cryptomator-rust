use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, ValueEnum};
use dotenvy::dotenv;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use tracing::info;
use zeroize::Zeroizing;

use cryptomator::crypto::{
    CipherCombo, Cryptor, DEFAULT_FORMAT, DEFAULT_MASTER_KEY_FILE, DEFAULT_SHORTENING_THRESHOLD,
    DEFAULT_VAULT_FILENAME, MasterKey, MasterKeyJson, Vault,
};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig, FileSystem, OpenOptions, parent_path};
use cryptomator::frontends::auth::WebDavAuth;
use cryptomator::frontends::mount::mount_nfs;
use cryptomator::frontends::mount::*;
use cryptomator::logging::init_logger;
use cryptomator::providers::{LocalFs, S3Fs, S3FsConfig, WebDavFs};

const DEFAULT_STORAGE_SUB_FOLDER: &str = "d";

/// Errors that can occur when loading or parsing S3 configuration.
#[derive(Debug, Error)]
pub enum S3ConfigError {
    #[error("invalid S3 config: {0}")]
    InvalidConfig(String),
    #[error("missing required S3 configuration: {0}")]
    MissingConfig(String),
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum FilesystemProvider {
    Local,
    S3,
    WebDav,
}

#[derive(Parser)]
#[command(version = "0.1.0", author = "pr0n00gler <pr0n00gler@yandex.ru>")]
struct Opts {
    /// Path to a storage (local path or S3 prefix)
    #[arg(short, long)]
    storage_path: String,

    /// Path to a vault file. By default in the storage directory
    #[arg(short, long)]
    vault_path: Option<String>,

    /// Filesystem provider. Supported values: "local", "web-dav" and "s3"
    #[arg(value_enum, default_value_t = FilesystemProvider::Local)]
    filesystem_provider: FilesystemProvider,

    /// WebDAV server URL for the WebDav filesystem provider
    #[arg(long)]
    webdav_provider_url: Option<String>,

    /// WebDAV server username for the WebDav filesystem provider
    #[arg(long)]
    webdav_provider_user: Option<String>,

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

    let _guard = init_logger(&opts.log_level);

    let storage_path = Path::new(opts.storage_path.as_str()).to_path_buf();

    let build_webdav = || {
        let url = opts
            .webdav_provider_url
            .as_deref()
            .expect("--webdav-provider-url is required for web-dav provider");
        let user = opts.webdav_provider_user.as_deref();
        let pass = user.map(|u| {
            Zeroizing::new(
                rpassword::prompt_password(format!("WebDAV provider password for {u}: "))
                    .expect("Unable to read WebDAV provider password"),
            )
        });
        WebDavFs::new(url, user, pass.as_deref().map(|z| z.as_str()))
    };

    // Resolves vault and storage paths based on the filesystem provider.
    // For S3 the storage_path is ignored (the prefix lives in the S3 config),
    // so default paths are relative. For local and WebDAV providers the paths
    // are resolved relative to storage_path.
    let resolve_paths = |provider: FilesystemProvider| -> (PathBuf, PathBuf) {
        let vault_path = match opts.vault_path.as_deref() {
            Some(m) => Path::new(m).to_path_buf(),
            None => match provider {
                FilesystemProvider::S3 => Path::new(DEFAULT_VAULT_FILENAME).to_path_buf(),
                _ => storage_path.join(DEFAULT_VAULT_FILENAME),
            },
        };
        let full_storage_path = match provider {
            FilesystemProvider::S3 => Path::new(DEFAULT_STORAGE_SUB_FOLDER).to_path_buf(),
            _ => storage_path.join(DEFAULT_STORAGE_SUB_FOLDER),
        };
        (vault_path, full_storage_path)
    };

    match opts.subcmd {
        Command::Create(c) => {
            let (vault_path, full_storage_path) = resolve_paths(opts.filesystem_provider);
            match opts.filesystem_provider {
                FilesystemProvider::Local => {
                    create_command(LocalFs::new(), &vault_path, &full_storage_path, c)
                }
                FilesystemProvider::S3 => {
                    create_command(require_s3_fs(), &vault_path, &full_storage_path, c)
                }
                FilesystemProvider::WebDav => {
                    create_command(build_webdav(), &vault_path, &full_storage_path, c)
                }
            }
        }
        Command::MigrateV7ToV8 => {
            let (vault_path, _) = resolve_paths(opts.filesystem_provider);
            match opts.filesystem_provider {
                FilesystemProvider::Local => {
                    migrate_v7_to_v8_command(LocalFs::new(), &vault_path)
                }
                FilesystemProvider::S3 => {
                    migrate_v7_to_v8_command(require_s3_fs(), &vault_path)
                }
                FilesystemProvider::WebDav => {
                    migrate_v7_to_v8_command(build_webdav(), &vault_path)
                }
            }
        }
        Command::Unlock(u) => {
            let (vault_path, full_storage_path) = resolve_paths(opts.filesystem_provider);
            match opts.filesystem_provider {
                FilesystemProvider::Local => {
                    unlock_command(LocalFs::new(), &vault_path, &full_storage_path, u).await
                }
                FilesystemProvider::S3 => {
                    unlock_command(require_s3_fs(), &vault_path, &full_storage_path, u).await
                }
                FilesystemProvider::WebDav => {
                    unlock_command(build_webdav(), &vault_path, &full_storage_path, u).await
                }
            }
        }
    }
}

fn create_command<FS: FileSystem, P: AsRef<Path>>(
    fs: FS,
    vault_path: P,
    full_storage_path: P,
    c: Create,
) {
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
    let pass = Zeroizing::new(
        rpassword::prompt_password("Vault password: ").expect("Unable to read password"),
    );

    info!("Reading old masterkey file...");
    let mk_path = parent_path(&vault_path).join(DEFAULT_MASTER_KEY_FILE);
    let mut mk_file = fs
        .open_file(&mk_path, OpenOptions::new())
        .expect("Failed to open masterkey file");

    let mut mk_bytes = Zeroizing::new(Vec::new());
    mk_file
        .read_to_end(&mut mk_bytes)
        .expect("failed to read masterkey file");
    let mk_json: MasterKeyJson =
        serde_json::from_slice(&mk_bytes).expect("failed to parse masterkey file");

    let scrypt_salt = mk_json.scryptSalt.clone();
    let scrypt_cost_param = mk_json.scryptCostParam;
    let scrypt_block_size = mk_json.scryptBlockSize;
    let primary_master_key_enc = mk_json.primaryMasterKey.clone();
    let hmac_master_key_enc = mk_json.hmacMasterKey.clone();

    fs.remove_file(&mk_path)
        .expect("failed to delete old masterkey file");

    let masterkey = MasterKey::from_masterkey_json(mk_json, pass.as_str())
        .expect("Failed to decrypt master key file");
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
    let vault = {
        let pass = Zeroizing::new(
            rpassword::prompt_password("Vault password: ").expect("Unable to read password"),
        );
        info!("Unlocking the storage...");
        info!("Deriving keys...");
        Vault::open(&fs, vault_path, pass.as_str()).expect("failed to open vault")
    };

    let cryptor = Cryptor::new(vault);
    let config = CryptoFsConfig {
        read_only: u.read_only,
        ..Default::default()
    };
    if u.read_only {
        info!("Starting in read-only mode...");
    }
    let crypto_fs = CryptoFs::new(
        full_storage_path
            .as_ref()
            .to_str()
            .expect("Failed to convert Path to &str"),
        cryptor,
        fs,
        config,
    )
    .expect("Failed to initialize storage");
    info!("Storage unlocked!");

    if let Some(webdav_listen_address) = &u.webdav_listen_address {
        let auth = u.webdav_user.as_ref().map(|user| {
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

/// Loads S3 configuration from environment variables.
fn load_s3_from_env() -> Result<S3FsConfig, S3ConfigError> {
    let bucket = env::var("S3_BUCKET")
        .map_err(|_| S3ConfigError::MissingConfig("S3_BUCKET is required".to_string()))?;

    let region = env::var("S3_REGION")
        .map_err(|_| S3ConfigError::MissingConfig("S3_REGION is required".to_string()))?;

    let prefix = env::var("S3_PREFIX").ok();
    let endpoint = env::var("S3_ENDPOINT").ok();

    let force_path_style = env::var("S3_FORCE_PATH_STYLE")
        .ok()
        .map(|v| v.parse::<bool>())
        .transpose()
        .map_err(|e| {
            S3ConfigError::InvalidConfig(format!("S3_FORCE_PATH_STYLE must be a boolean: {e}"))
        })?
        .unwrap_or(false);

    let validate_bucket = env::var("S3_VALIDATE_BUCKET")
        .ok()
        .map(|v| v.parse::<bool>())
        .transpose()
        .map_err(|e| {
            S3ConfigError::InvalidConfig(format!("S3_VALIDATE_BUCKET must be a boolean: {e}"))
        })?
        .unwrap_or(false);

    let access_key = env::var("S3_ACCESS_KEY").ok();
    let secret_key = env::var("S3_SECRET_KEY").ok();
    let session_token = env::var("S3_SESSION_TOKEN").ok();

    let request_timeout_seconds = env::var("S3_REQUEST_TIMEOUT_SECONDS")
        .ok()
        .map(|v| v.parse::<u64>())
        .transpose()
        .map_err(|e| {
            S3ConfigError::InvalidConfig(format!(
                "S3_REQUEST_TIMEOUT_SECONDS must be a positive integer: {e}"
            ))
        })?;

    let request_timeout = match request_timeout_seconds {
        Some(0) => {
            return Err(S3ConfigError::InvalidConfig(
                "S3_REQUEST_TIMEOUT_SECONDS must be greater than zero".to_string(),
            ));
        }
        Some(seconds) => Some(Duration::from_secs(seconds)),
        None => None,
    };

    Ok(S3FsConfig {
        bucket,
        prefix,
        region,
        endpoint,
        force_path_style,
        validate_bucket,
        access_key: access_key.map(Zeroizing::new),
        secret_key: secret_key.map(Zeroizing::new),
        session_token: session_token.map(Zeroizing::new),
        request_timeout,
    })
}

/// Loads the S3 filesystem from environment variables, or exits the process
/// with a user-facing error message if initialization fails.
fn require_s3_fs() -> S3Fs {
    let _ = dotenv();

    let config = match load_s3_from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("failed to initialize S3 filesystem: {err}");
            std::process::exit(2);
        }
    };

    S3Fs::new(config).expect("failed to create S3 filesystem")
}
