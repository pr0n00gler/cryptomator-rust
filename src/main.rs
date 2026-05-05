use anyhow::Context;
use cryptomator::crypto::{Cryptor, DEFAULT_VAULT_FILENAME, Vault};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig, FileSystem};
use cryptomator::logging::init_logger;
use cryptomator::operations::{create_vault, migrate_v7_to_v8};
use cryptomator::providers::{LocalFs, WebDavFs};

use tracing::info;

use clap::{Parser, ValueEnum};
use zeroize::Zeroizing;

use cryptomator::frontends::auth::WebDavAuth;
use cryptomator::frontends::mount::{mount_nfs, mount_webdav};
use std::path::Path;

const DEFAULT_STORAGE_SUB_FOLDER: &str = "d";

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum FilesystemProvider {
    Local,
    WebDav,
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

    /// Filesystem provider. Supported values: "local", "web-dav"
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
async fn main() -> anyhow::Result<()> {
    let opts: Opts = Opts::parse();

    let _guard = init_logger(&opts.log_level);

    let storage_path = Path::new(opts.storage_path.as_str()).to_path_buf();

    let vault_path = match opts.vault_path {
        Some(m) => Path::new(m.as_str()).to_path_buf(),
        None => storage_path.join(DEFAULT_VAULT_FILENAME),
    };

    let full_storage_path = storage_path.join(DEFAULT_STORAGE_SUB_FOLDER);

    let build_webdav = || -> anyhow::Result<WebDavFs> {
        let url = opts.webdav_provider_url.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--webdav-provider-url is required for web-dav provider")
        })?;
        let user = opts.webdav_provider_user.as_deref();
        let pass = match user {
            Some(u) => Some(Zeroizing::new(
                rpassword::prompt_password(format!("WebDAV provider password for {u}: "))
                    .context("unable to read WebDAV provider password")?,
            )),
            None => None,
        };
        WebDavFs::new(url, user, pass.as_deref().map(|z| z.as_str()))
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    };

    match opts.subcmd {
        Command::Create(c) => match opts.filesystem_provider {
            FilesystemProvider::Local => {
                create_command(LocalFs::new(), &vault_path, &full_storage_path, c)?
            }
            FilesystemProvider::WebDav => {
                create_command(build_webdav()?, &vault_path, &full_storage_path, c)?
            }
        },
        Command::MigrateV7ToV8 => match opts.filesystem_provider {
            FilesystemProvider::Local => migrate_v7_to_v8_command(LocalFs::new(), &vault_path)?,
            FilesystemProvider::WebDav => migrate_v7_to_v8_command(build_webdav()?, &vault_path)?,
        },
        Command::Unlock(u) => match opts.filesystem_provider {
            FilesystemProvider::Local => {
                unlock_command(LocalFs::new(), &vault_path, &full_storage_path, u).await?
            }
            FilesystemProvider::WebDav => {
                unlock_command(build_webdav()?, &vault_path, &full_storage_path, u).await?
            }
        },
    };
    Ok(())
}

fn create_command<FS, P>(
    fs: FS,
    vault_path: P,
    full_storage_path: P,
    c: Create,
) -> anyhow::Result<()>
where
    FS: FileSystem + 'static,
    P: AsRef<Path>,
{
    // Wrap immediately in Zeroizing so the plaintext password is wiped from
    // the heap when `pass` goes out of scope at the end of this function,
    // regardless of the return path.
    let pass = Zeroizing::new(
        rpassword::prompt_password("Vault password: ").context("unable to read password")?,
    );
    create_vault(
        fs,
        vault_path,
        full_storage_path,
        pass.as_str(),
        c.scrypt_cost,
        c.scrypt_block_size,
    )
}

fn migrate_v7_to_v8_command<FS: FileSystem + 'static, P: AsRef<Path>>(
    fs: FS,
    vault_path: P,
) -> anyhow::Result<()> {
    // Wrap immediately in Zeroizing so the plaintext password is wiped from
    // the heap when `pass` drops at the end of this function.
    let pass = Zeroizing::new(
        rpassword::prompt_password("Vault password: ").context("unable to read password")?,
    );
    migrate_v7_to_v8(fs, vault_path, pass.as_str())
}

async fn unlock_command<FS: 'static + FileSystem, P: AsRef<Path>>(
    fs: FS,
    vault_path: P,
    full_storage_path: P,
    u: Unlock,
) -> anyhow::Result<()> {
    // Wrap immediately in Zeroizing so the plaintext vault password is wiped
    // from the heap as soon as key derivation finishes.  The `Zeroizing`
    // binding is dropped at the end of the inner block below, before any
    // long-running async server tasks are started.
    let vault = {
        let pass = Zeroizing::new(
            rpassword::prompt_password("Vault password: ").context("unable to read password")?,
        );
        info!("Unlocking the storage...");
        info!("Deriving keys...");
        Vault::open(&fs, vault_path, pass.as_str()).context("failed to open vault")?
        // `pass` is dropped (and zeroed) here — before the server loop begins.
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
            .context("failed to convert storage path to UTF-8")?,
        cryptor,
        fs,
        config,
    )
    .context("failed to initialize storage")?;
    info!("Storage unlocked!");

    if let Some(webdav_listen_address) = &u.webdav_listen_address {
        let auth = if let Some(user) = u.webdav_user.as_ref() {
            // SEC: always prompt for the WebDAV password interactively.
            // Accepting it via a CLI flag would expose the credential in shell
            // history and `ps` output.
            // Wrap in Zeroizing immediately so the plaintext password is wiped
            // from the heap when `webdav_pass` drops at the end of this closure.
            let webdav_pass = Zeroizing::new(
                rpassword::prompt_password(format!("WebDAV password for {user}: "))
                    .context("unable to read WebDAV password")?,
            );
            Some(WebDavAuth::new(user, webdav_pass.as_str()))
        } else {
            None
        };

        info!("Starting WebDav server...");
        mount_webdav(webdav_listen_address.clone(), crypto_fs, auth).await?;
        return Ok(());
    }

    info!("Starting NFS server...");
    mount_nfs(u.nfs_listen_address, crypto_fs).await?;
    Ok(())
}
