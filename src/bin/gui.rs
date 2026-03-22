#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use eframe::egui;
use zeroize::Zeroizing;

use cryptomator::crypto::{Cryptor, DEFAULT_VAULT_FILENAME, Vault};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig, FileSystem, IoStats};
use cryptomator::frontends::auth::WebDavAuth;
use cryptomator::frontends::mount::{mount_nfs, mount_webdav};
use cryptomator::operations::{DEFAULT_STORAGE_SUB_FOLDER, create_vault, migrate_v7_to_v8};
use cryptomator::providers::{LocalFs, WebDavFs};

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

const MAX_LOG_ENTRIES: usize = 1000;

/// Messages sent from background threads back to the UI.
enum LogMsg {
    Info(String),
    Error(String),
    Done(String),
    /// The server is now running (vault unlocked).
    ServerRunning(String),
    /// The server has stopped (vault locked).
    ServerStopped(String),
    /// Carries IoStats from the unlock thread to the GUI.
    Stats(IoStats),
}

/// Shared log buffer that is rendered in the status area.
struct LogBuffer {
    entries: VecDeque<(LogLevel, String)>,
}

#[derive(Clone, Copy, PartialEq)]
enum LogLevel {
    Info,
    Error,
    Done,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    fn push(&mut self, level: LogLevel, msg: String) {
        if self.entries.len() >= MAX_LOG_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back((level, msg));
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Create,
    Unlock,
    Migrate,
    Advanced,
}

#[derive(Clone, Copy, PartialEq)]
enum FsProvider {
    Local,
    WebDav,
}

#[derive(Clone, Copy, PartialEq)]
enum Frontend {
    Nfs,
    WebDav,
}

// ---------------------------------------------------------------------------
// BusyGuard -- resets busy flag on drop (panic-safe)
// ---------------------------------------------------------------------------

struct BusyGuard(Arc<Mutex<bool>>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct CryptomatorGui {
    active_tab: Tab,

    // -- shared fields --
    storage_path: String,
    vault_path_override: String,
    fs_provider: FsProvider,
    webdav_provider_url: String,
    webdav_provider_user: String,
    webdav_provider_pass: Zeroizing<String>,
    vault_password: Zeroizing<String>,

    // -- create fields --
    vault_password_confirm: Zeroizing<String>,
    scrypt_cost: String,
    scrypt_block_size: String,

    // -- simple mount fields (Unlock tab) --
    mount_folder: String,

    // -- advanced unlock fields --
    frontend: Frontend,
    webdav_listen_address: String,
    webdav_frontend_user: String,
    webdav_frontend_pass: Zeroizing<String>,
    nfs_listen_address: String,
    read_only: bool,

    // -- status / log --
    log: LogBuffer,
    log_rx: mpsc::Receiver<LogMsg>,
    log_tx: mpsc::Sender<LogMsg>,
    busy: Arc<Mutex<bool>>,

    // -- unlock lifecycle --
    /// When a vault is unlocked and a server is running, this holds the
    /// oneshot sender that shuts down the server when fired.
    unlock_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// True while a server (WebDAV/NFS) is actively serving.
    unlocked: Arc<Mutex<bool>>,
    /// When using simple mount mode, stores the active mount folder path
    /// so we know what to `umount` on lock.
    active_mount_folder: Option<String>,

    // -- I/O stats --
    io_stats: Option<IoStats>,
    prev_bytes_read: u64,
    prev_bytes_written: u64,
    last_stats_instant: std::time::Instant,
    read_throughput: f64,
    write_throughput: f64,
}

impl Default for CryptomatorGui {
    fn default() -> Self {
        let (log_tx, log_rx) = mpsc::channel();
        Self {
            active_tab: Tab::Unlock,

            storage_path: String::new(),
            vault_path_override: String::new(),
            fs_provider: FsProvider::Local,
            webdav_provider_url: String::new(),
            webdav_provider_user: String::new(),
            webdav_provider_pass: Zeroizing::new(String::new()),
            vault_password: Zeroizing::new(String::new()),

            vault_password_confirm: Zeroizing::new(String::new()),
            scrypt_cost: "16384".to_owned(),
            scrypt_block_size: "8".to_owned(),

            mount_folder: String::new(),

            frontend: Frontend::Nfs,
            webdav_listen_address: "127.0.0.1:8080".to_owned(),
            webdav_frontend_user: String::new(),
            webdav_frontend_pass: Zeroizing::new(String::new()),
            nfs_listen_address: "127.0.0.1:11111".to_owned(),
            read_only: false,

            log: LogBuffer::new(),
            log_rx,
            log_tx,
            busy: Arc::new(Mutex::new(false)),

            unlock_shutdown: None,
            unlocked: Arc::new(Mutex::new(false)),
            active_mount_folder: None,

            io_stats: None,
            prev_bytes_read: 0,
            prev_bytes_written: 0,
            last_stats_instant: std::time::Instant::now(),
            read_throughput: 0.0,
            write_throughput: 0.0,
        }
    }
}

impl CryptomatorGui {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }

    // -- helpers -----------------------------------------------------------

    fn resolved_vault_path(&self) -> PathBuf {
        if self.vault_path_override.is_empty() {
            Path::new(&self.storage_path).join(DEFAULT_VAULT_FILENAME)
        } else {
            PathBuf::from(&self.vault_path_override)
        }
    }

    fn full_storage_path(&self) -> PathBuf {
        Path::new(&self.storage_path).join(DEFAULT_STORAGE_SUB_FOLDER)
    }

    fn is_busy(&self) -> bool {
        *self.busy.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_busy(&self, val: bool) {
        *self.busy.lock().unwrap_or_else(|e| e.into_inner()) = val;
    }

    // -- drain channel into log buffer -------------------------------------

    fn drain_log_channel(&mut self) {
        while let Ok(msg) = self.log_rx.try_recv() {
            match msg {
                LogMsg::Info(s) => self.log.push(LogLevel::Info, s),
                LogMsg::Error(s) => self.log.push(LogLevel::Error, s),
                LogMsg::Done(s) => {
                    self.log.push(LogLevel::Done, s);
                }
                LogMsg::ServerRunning(s) => {
                    self.log.push(LogLevel::Done, s);
                    self.set_busy(false);
                    *self.unlocked.lock().unwrap_or_else(|e| e.into_inner()) = true;
                }
                LogMsg::ServerStopped(s) => {
                    self.log.push(LogLevel::Info, s);
                    *self.unlocked.lock().unwrap_or_else(|e| e.into_inner()) = false;
                    self.unlock_shutdown = None;
                    self.active_mount_folder = None;
                    self.io_stats = None;
                    self.read_throughput = 0.0;
                    self.write_throughput = 0.0;
                }
                LogMsg::Stats(stats) => {
                    self.prev_bytes_read = stats.bytes_read();
                    self.prev_bytes_written = stats.bytes_written();
                    self.io_stats = Some(stats);
                    self.read_throughput = 0.0;
                    self.write_throughput = 0.0;
                    self.last_stats_instant = std::time::Instant::now();
                }
            }
        }
    }

    // -- actions -----------------------------------------------------------

    fn run_create(&mut self) {
        if self.storage_path.is_empty() {
            self.log
                .push(LogLevel::Error, "Storage path is required.".into());
            return;
        }
        if self.vault_password.is_empty() {
            self.log
                .push(LogLevel::Error, "Password is required.".into());
            return;
        }
        if *self.vault_password != *self.vault_password_confirm {
            self.log
                .push(LogLevel::Error, "Passwords do not match.".into());
            return;
        }
        let scrypt_cost: u64 = match self.scrypt_cost.parse() {
            Ok(v) => v,
            Err(_) => {
                self.log
                    .push(LogLevel::Error, "Invalid scrypt cost value.".into());
                return;
            }
        };
        let scrypt_block_size: u32 = match self.scrypt_block_size.parse() {
            Ok(v) => v,
            Err(_) => {
                self.log
                    .push(LogLevel::Error, "Invalid scrypt block size.".into());
                return;
            }
        };

        // Validate scrypt parameters
        if scrypt_cost < 2 || (scrypt_cost & (scrypt_cost - 1)) != 0 {
            self.log.push(
                LogLevel::Error,
                "Scrypt cost (N) must be a power of 2 and >= 2.".into(),
            );
            return;
        }
        if scrypt_block_size == 0 {
            self.log.push(
                LogLevel::Error,
                "Scrypt block size (r) must not be zero.".into(),
            );
            return;
        }
        let mem_usage = 128u128 * u128::from(scrypt_block_size) * u128::from(scrypt_cost);
        if mem_usage > 2_147_483_648 {
            self.log.push(
                LogLevel::Error,
                format!(
                    "Scrypt parameters too large: 128 * r * N = {mem_usage} exceeds 2 GB limit."
                ),
            );
            return;
        }

        let vault_path = self.resolved_vault_path();
        let full_storage_path = self.full_storage_path();
        let password = Zeroizing::new(String::from(&**self.vault_password));
        let tx = self.log_tx.clone();
        let busy = self.busy.clone();
        let provider = self.fs_provider;
        let webdav_url = self.webdav_provider_url.clone();
        let webdav_user = self.webdav_provider_user.clone();
        let webdav_pass = Zeroizing::new(String::from(&**self.webdav_provider_pass));

        self.set_busy(true);
        self.log.push(LogLevel::Info, "Creating vault...".into());

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);
            let result = match provider {
                FsProvider::Local => create_vault(
                    LocalFs::new(),
                    &vault_path,
                    &full_storage_path,
                    password.as_str(),
                    scrypt_cost,
                    scrypt_block_size,
                ),
                FsProvider::WebDav => {
                    let user = if webdav_user.is_empty() {
                        None
                    } else {
                        Some(webdav_user.as_str())
                    };
                    let pass = if webdav_pass.is_empty() {
                        None
                    } else {
                        Some(webdav_pass.as_str())
                    };
                    create_vault(
                        WebDavFs::new(&webdav_url, user, pass),
                        &vault_path,
                        &full_storage_path,
                        password.as_str(),
                        scrypt_cost,
                        scrypt_block_size,
                    )
                }
            };
            match result {
                Ok(()) => {
                    let _ = tx.send(LogMsg::Done("Vault created successfully.".into()));
                }
                Err(e) => {
                    let _ = tx.send(LogMsg::Error(format!("Create failed: {e:#}")));
                    let _ = tx.send(LogMsg::Done(
                        "Create operation finished with errors.".into(),
                    ));
                }
            }
        });
    }

    fn run_migrate(&mut self) {
        if self.storage_path.is_empty() {
            self.log
                .push(LogLevel::Error, "Storage path is required.".into());
            return;
        }
        if self.vault_password.is_empty() {
            self.log
                .push(LogLevel::Error, "Password is required.".into());
            return;
        }

        let vault_path = self.resolved_vault_path();
        let password = Zeroizing::new(String::from(&**self.vault_password));
        let tx = self.log_tx.clone();
        let busy = self.busy.clone();
        let provider = self.fs_provider;
        let webdav_url = self.webdav_provider_url.clone();
        let webdav_user = self.webdav_provider_user.clone();
        let webdav_pass = Zeroizing::new(String::from(&**self.webdav_provider_pass));

        self.set_busy(true);
        self.log
            .push(LogLevel::Info, "Migrating vault v7 -> v8...".into());

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);
            let result = match provider {
                FsProvider::Local => {
                    migrate_v7_to_v8(LocalFs::new(), &vault_path, password.as_str())
                }
                FsProvider::WebDav => {
                    let user = if webdav_user.is_empty() {
                        None
                    } else {
                        Some(webdav_user.as_str())
                    };
                    let pass = if webdav_pass.is_empty() {
                        None
                    } else {
                        Some(webdav_pass.as_str())
                    };
                    migrate_v7_to_v8(
                        WebDavFs::new(&webdav_url, user, pass),
                        &vault_path,
                        password.as_str(),
                    )
                }
            };
            match result {
                Ok(()) => {
                    let _ = tx.send(LogMsg::Done("Migration completed successfully.".into()));
                }
                Err(e) => {
                    let _ = tx.send(LogMsg::Error(format!("Migration failed: {e:#}")));
                    let _ = tx.send(LogMsg::Done("Migration finished with errors.".into()));
                }
            }
        });
    }

    /// Simple mount mode: find a free port, start NFS server, then run
    /// `mount_nfs` OS command to mount the share to the user-specified folder.
    fn run_simple_mount(&mut self) {
        if self.storage_path.is_empty() {
            self.log
                .push(LogLevel::Error, "Storage path is required.".into());
            return;
        }
        if self.vault_password.is_empty() {
            self.log
                .push(LogLevel::Error, "Password is required.".into());
            return;
        }
        if self.mount_folder.is_empty() {
            self.log
                .push(LogLevel::Error, "Mount folder is required.".into());
            return;
        }

        // Validate mount folder path: must be absolute and not a system directory.
        {
            let mount_path = Path::new(&self.mount_folder);
            if !mount_path.is_absolute() {
                self.log.push(
                    LogLevel::Error,
                    "Mount folder must be an absolute path.".into(),
                );
                return;
            }
            const FORBIDDEN_DIRS: &[&str] = &[
                "/", "/etc", "/usr", "/bin", "/sbin", "/System", "/var", "/tmp", "/private",
                "/Library", "/dev", "/proc", "/boot", "/opt", "/home", "/Volumes",
            ];

            // Check the raw path first.
            let raw_str = match mount_path.to_str() {
                Some(s) => s,
                None => {
                    self.log.push(
                        LogLevel::Error,
                        "Mount folder path contains non-UTF-8 characters.".into(),
                    );
                    return;
                }
            };
            let raw_trimmed = raw_str.trim_end_matches('/');
            if FORBIDDEN_DIRS.iter().any(|d| raw_trimmed == *d) {
                self.log.push(
                    LogLevel::Error,
                    format!(
                        "Mount folder must not be a system directory: {}",
                        self.mount_folder
                    ),
                );
                return;
            }

            // Normalize the path to resolve ".." and "." segments, then re-check.
            let mut normalized = PathBuf::new();
            for component in mount_path.components() {
                match component {
                    Component::ParentDir => {
                        normalized.pop();
                    }
                    Component::CurDir => {}
                    c => normalized.push(c),
                }
            }
            let normalized_str = match normalized.to_str() {
                Some(s) => s,
                None => {
                    self.log.push(
                        LogLevel::Error,
                        "Normalized mount path contains non-UTF-8 characters.".into(),
                    );
                    return;
                }
            };
            let normalized_trimmed = normalized_str.trim_end_matches('/');

            if FORBIDDEN_DIRS.iter().any(|d| normalized_trimmed == *d) {
                self.log.push(
                    LogLevel::Error,
                    format!(
                        "Mount folder resolves to a system directory: {}",
                        normalized_trimmed
                    ),
                );
                return;
            }

            // Also reject paths that are children of forbidden directories
            // (e.g. /etc/myvault, /dev/something).
            if FORBIDDEN_DIRS
                .iter()
                .any(|d| *d != "/" && normalized_trimmed.starts_with(&format!("{d}/")))
            {
                self.log.push(
                    LogLevel::Error,
                    format!(
                        "Mount folder must not be inside a system directory: {}",
                        normalized_trimmed
                    ),
                );
                return;
            }
        }

        let vault_path = self.resolved_vault_path();
        let full_storage_path = self.full_storage_path();
        let password = Zeroizing::new(String::from(&**self.vault_password));
        let tx = self.log_tx.clone();
        let busy = self.busy.clone();
        let provider = self.fs_provider;
        let webdav_url = self.webdav_provider_url.clone();
        let webdav_user = self.webdav_provider_user.clone();
        let webdav_pass = Zeroizing::new(String::from(&**self.webdav_provider_pass));
        let read_only = self.read_only;
        let mount_folder = self.mount_folder.clone();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.unlock_shutdown = Some(shutdown_tx);
        self.active_mount_folder = Some(mount_folder.clone());

        self.set_busy(true);
        self.log.push(LogLevel::Info, "Mounting vault...".into());

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);

            let result = match provider {
                FsProvider::Local => do_simple_mount(
                    LocalFs::new(),
                    &vault_path,
                    &full_storage_path,
                    password.as_str(),
                    read_only,
                    &mount_folder,
                    &tx,
                    shutdown_rx,
                ),
                FsProvider::WebDav => {
                    let user = if webdav_user.is_empty() {
                        None
                    } else {
                        Some(webdav_user.as_str())
                    };
                    let pass = if webdav_pass.is_empty() {
                        None
                    } else {
                        Some(webdav_pass.as_str())
                    };
                    do_simple_mount(
                        WebDavFs::new(&webdav_url, user, pass),
                        &vault_path,
                        &full_storage_path,
                        password.as_str(),
                        read_only,
                        &mount_folder,
                        &tx,
                        shutdown_rx,
                    )
                }
            };

            match result {
                Ok(()) => {
                    let _ = tx.send(LogMsg::ServerStopped(
                        "Vault unmounted. Server stopped.".into(),
                    ));
                }
                Err(e) => {
                    let _ = tx.send(LogMsg::Error(format!("Mount failed: {e:#}")));
                    let _ = tx.send(LogMsg::ServerStopped(
                        "Mount failed. Server stopped.".into(),
                    ));
                }
            }
        });
    }

    /// Advanced mode unlock: starts the NFS or WebDAV server without OS-level
    /// mounting (the user connects manually).
    fn run_unlock(&mut self) {
        if self.storage_path.is_empty() {
            self.log
                .push(LogLevel::Error, "Storage path is required.".into());
            return;
        }
        if self.vault_password.is_empty() {
            self.log
                .push(LogLevel::Error, "Password is required.".into());
            return;
        }

        // Validate listen address before spawning thread (Issue 11)
        let listen_addr_str = match self.frontend {
            Frontend::WebDav => &self.webdav_listen_address,
            Frontend::Nfs => &self.nfs_listen_address,
        };
        if listen_addr_str.parse::<std::net::SocketAddr>().is_err() {
            self.log.push(
                LogLevel::Error,
                format!("Invalid listen address: {listen_addr_str}"),
            );
            return;
        }

        let vault_path = self.resolved_vault_path();
        let full_storage_path = self.full_storage_path();
        let password = Zeroizing::new(String::from(&**self.vault_password));
        let tx = self.log_tx.clone();
        let busy = self.busy.clone();
        let provider = self.fs_provider;
        let webdav_url = self.webdav_provider_url.clone();
        let webdav_user = self.webdav_provider_user.clone();
        let webdav_pass = Zeroizing::new(String::from(&**self.webdav_provider_pass));
        let frontend = self.frontend;
        let webdav_listen = self.webdav_listen_address.clone();
        let webdav_fe_user = self.webdav_frontend_user.clone();
        let webdav_fe_pass = Zeroizing::new(String::from(&**self.webdav_frontend_pass));
        let nfs_listen = self.nfs_listen_address.clone();
        let read_only = self.read_only;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.unlock_shutdown = Some(shutdown_tx);
        self.active_mount_folder = None;

        self.set_busy(true);
        self.log.push(LogLevel::Info, "Unlocking vault...".into());

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);
            #[allow(clippy::too_many_arguments)]
            fn do_unlock<FS: FileSystem + 'static>(
                fs: FS,
                vault_path: &Path,
                full_storage_path: &Path,
                password: &str,
                read_only: bool,
                frontend: Frontend,
                webdav_listen: &str,
                webdav_fe_user: &str,
                webdav_fe_pass: &str,
                nfs_listen: &str,
                tx: &mpsc::Sender<LogMsg>,
                shutdown_rx: tokio::sync::oneshot::Receiver<()>,
            ) -> anyhow::Result<()> {
                let _ = tx.send(LogMsg::Info("Deriving keys...".into()));
                let vault = Vault::open(&fs, vault_path, password)
                    .map_err(|e| anyhow::anyhow!("Failed to open vault: {e}"))?;

                let cryptor = Cryptor::new(vault);
                let config = CryptoFsConfig {
                    read_only,
                    ..Default::default()
                };

                let full_path_str = full_storage_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid storage path encoding"))?;

                let crypto_fs = CryptoFs::new(full_path_str, cryptor, fs, config)
                    .map_err(|e| anyhow::anyhow!("Failed to initialize storage: {e}"))?;

                let _ = tx.send(LogMsg::Stats(crypto_fs.io_stats().clone()));

                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| anyhow::anyhow!("Failed to create tokio runtime: {e}"))?;

                match frontend {
                    Frontend::WebDav => {
                        let auth = if webdav_fe_user.is_empty() {
                            None
                        } else {
                            let pass = if webdav_fe_pass.is_empty() {
                                ""
                            } else {
                                webdav_fe_pass
                            };
                            Some(WebDavAuth::new(webdav_fe_user, pass))
                        };
                        let addr = webdav_listen.to_owned();
                        let _ = tx.send(LogMsg::ServerRunning(format!(
                            "Vault unlocked. WebDAV server listening on {webdav_listen}"
                        )));
                        rt.block_on(async {
                            tokio::select! {
                                _ = mount_webdav(addr, crypto_fs, auth) => {}
                                _ = shutdown_rx => {}
                            }
                        });
                    }
                    Frontend::Nfs => {
                        let addr = nfs_listen.to_owned();
                        let _ = tx.send(LogMsg::ServerRunning(format!(
                            "Vault unlocked. NFS server listening on {nfs_listen}"
                        )));
                        rt.block_on(async {
                            tokio::select! {
                                _ = mount_nfs(addr, crypto_fs) => {}
                                _ = shutdown_rx => {}
                            }
                        });
                    }
                }
                Ok(())
            }

            let result = match provider {
                FsProvider::Local => do_unlock(
                    LocalFs::new(),
                    &vault_path,
                    &full_storage_path,
                    password.as_str(),
                    read_only,
                    frontend,
                    &webdav_listen,
                    &webdav_fe_user,
                    webdav_fe_pass.as_str(),
                    &nfs_listen,
                    &tx,
                    shutdown_rx,
                ),
                FsProvider::WebDav => {
                    let user = if webdav_user.is_empty() {
                        None
                    } else {
                        Some(webdav_user.as_str())
                    };
                    let pass = if webdav_pass.is_empty() {
                        None
                    } else {
                        Some(webdav_pass.as_str())
                    };
                    do_unlock(
                        WebDavFs::new(&webdav_url, user, pass),
                        &vault_path,
                        &full_storage_path,
                        password.as_str(),
                        read_only,
                        frontend,
                        &webdav_listen,
                        &webdav_fe_user,
                        webdav_fe_pass.as_str(),
                        &nfs_listen,
                        &tx,
                        shutdown_rx,
                    )
                }
            };

            match result {
                Ok(()) => {
                    let _ = tx.send(LogMsg::ServerStopped(
                        "Vault locked. Server stopped.".into(),
                    ));
                }
                Err(e) => {
                    let _ = tx.send(LogMsg::Error(format!("Unlock failed: {e:#}")));
                    let _ = tx.send(LogMsg::ServerStopped(
                        "Unlock failed. Server stopped.".into(),
                    ));
                }
            }
        });
    }

    /// Lock/unmount: if we are in simple mount mode, run `umount` first, then
    /// send the shutdown signal. For advanced mode, just send the shutdown.
    fn run_lock(&mut self) {
        // Guard against double-click: if shutdown was already taken, do nothing.
        if self.unlock_shutdown.is_none() {
            return;
        }
        let shutdown_tx = self.unlock_shutdown.take();
        let folder = self.active_mount_folder.clone();
        let log_tx = self.log_tx.clone();
        let busy = self.busy.clone();

        self.set_busy(true);
        self.log.push(LogLevel::Info, "Locking vault...".into());

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);
            if let Some(folder) = folder {
                let _ = log_tx.send(LogMsg::Info(format!("Unmounting {folder}...")));

                let output = std::process::Command::new("umount").arg(&folder).output();

                match output {
                    Ok(out) => {
                        if out.status.success() {
                            let _ = log_tx
                                .send(LogMsg::Info(format!("Unmounted {folder} successfully.")));
                        } else {
                            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                            let _ = log_tx.send(LogMsg::Error(format!("umount warning: {stderr}")));
                        }
                    }
                    Err(e) => {
                        let _ = log_tx.send(LogMsg::Error(format!("Failed to run umount: {e}")));
                    }
                }
            }

            if let Some(tx) = shutdown_tx {
                let _ = tx.send(());
            }
        });
    }

    // -- UI drawing --------------------------------------------------------

    fn draw_fs_provider_section(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filesystem provider:");
            ui.selectable_value(&mut self.fs_provider, FsProvider::Local, "Local");
            ui.selectable_value(&mut self.fs_provider, FsProvider::WebDav, "WebDAV");
        });

        if self.fs_provider == FsProvider::WebDav {
            ui.add_space(4.0);
            ui.group(|ui| {
                ui.label("WebDAV Provider Settings");
                ui.add_space(4.0);
                labeled_text_field(
                    ui,
                    "URL:",
                    &mut self.webdav_provider_url,
                    "https://example.com/dav",
                );
                labeled_text_field(ui, "Username:", &mut self.webdav_provider_user, "");
                labeled_password_field(ui, "Password:", &mut self.webdav_provider_pass);
            });
        }
    }

    fn draw_storage_fields(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Storage path:");
            ui.add(
                egui::TextEdit::singleline(&mut self.storage_path)
                    .hint_text("/path/to/vault/storage")
                    .desired_width(f32::INFINITY),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Vault path (override):");
            ui.add(
                egui::TextEdit::singleline(&mut self.vault_path_override)
                    .hint_text("Leave empty for default")
                    .desired_width(f32::INFINITY),
            );
        });
    }

    fn draw_create_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create New Vault");
        ui.add_space(8.0);

        self.draw_storage_fields(ui);
        ui.add_space(8.0);
        self.draw_fs_provider_section(ui);
        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label("Vault Password");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.vault_password)
                        .password(true)
                        .desired_width(300.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Confirm:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.vault_password_confirm)
                        .password(true)
                        .desired_width(300.0),
                );
            });
        });

        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label("Scrypt Parameters");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Cost (N):");
                ui.add(egui::TextEdit::singleline(&mut self.scrypt_cost).desired_width(100.0));
            });
            ui.horizontal(|ui| {
                ui.label("Block size (r):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.scrypt_block_size).desired_width(100.0),
                );
            });
        });

        ui.add_space(12.0);

        let busy = self.is_busy();
        ui.add_enabled_ui(!busy, |ui| {
            if ui
                .button(egui::RichText::new("  Create Vault  ").size(16.0))
                .clicked()
            {
                self.run_create();
            }
        });
    }

    fn draw_unlock_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Mount Vault");
        ui.add_space(8.0);

        self.draw_storage_fields(ui);
        ui.add_space(8.0);
        self.draw_fs_provider_section(ui);
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Vault password:");
            ui.add(
                egui::TextEdit::singleline(&mut *self.vault_password)
                    .password(true)
                    .desired_width(300.0),
            );
        });

        ui.add_space(8.0);

        ui.checkbox(&mut self.read_only, "Read-only mode");

        ui.add_space(8.0);

        labeled_text_field(
            ui,
            "Mount folder:",
            &mut self.mount_folder,
            "/Volumes/MyVault",
        );

        ui.add_space(12.0);

        let busy = self.is_busy();
        let unlocked = *self.unlocked.lock().unwrap_or_else(|e| e.into_inner());

        if unlocked {
            ui.add_enabled_ui(!busy, |ui| {
                if ui
                    .button(
                        egui::RichText::new("  Unmount  ")
                            .size(16.0)
                            .color(egui::Color32::from_rgb(255, 100, 100)),
                    )
                    .clicked()
                {
                    self.run_lock();
                }
            });
        } else {
            ui.add_enabled_ui(!busy && !unlocked, |ui| {
                if ui
                    .button(egui::RichText::new("  Mount  ").size(16.0))
                    .clicked()
                {
                    self.run_simple_mount();
                }
            });
        }
    }

    fn draw_advanced_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Advanced Settings");
        ui.add_space(8.0);

        self.draw_storage_fields(ui);
        ui.add_space(8.0);
        self.draw_fs_provider_section(ui);
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Vault password:");
            ui.add(
                egui::TextEdit::singleline(&mut *self.vault_password)
                    .password(true)
                    .desired_width(300.0),
            );
        });

        ui.add_space(8.0);

        ui.checkbox(&mut self.read_only, "Read-only mode");

        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label("Frontend Server");
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.frontend, Frontend::Nfs, "NFS");
                ui.selectable_value(&mut self.frontend, Frontend::WebDav, "WebDAV");
            });

            ui.add_space(4.0);

            match self.frontend {
                Frontend::Nfs => {
                    labeled_text_field(
                        ui,
                        "NFS listen address:",
                        &mut self.nfs_listen_address,
                        "127.0.0.1:11111",
                    );
                }
                Frontend::WebDav => {
                    labeled_text_field(
                        ui,
                        "WebDAV listen address:",
                        &mut self.webdav_listen_address,
                        "127.0.0.1:8080",
                    );
                    labeled_text_field(
                        ui,
                        "WebDAV auth user:",
                        &mut self.webdav_frontend_user,
                        "Leave empty for no auth",
                    );
                    labeled_password_field(
                        ui,
                        "WebDAV auth password:",
                        &mut self.webdav_frontend_pass,
                    );
                }
            }
        });

        ui.add_space(12.0);

        let busy = self.is_busy();
        let unlocked = *self.unlocked.lock().unwrap_or_else(|e| e.into_inner());

        if unlocked {
            ui.add_enabled_ui(!busy, |ui| {
                if ui
                    .button(
                        egui::RichText::new("  Stop Server  ")
                            .size(16.0)
                            .color(egui::Color32::from_rgb(255, 100, 100)),
                    )
                    .clicked()
                {
                    self.run_lock();
                }
            });
        } else {
            ui.add_enabled_ui(!busy && !unlocked, |ui| {
                if ui
                    .button(egui::RichText::new("  Start Server  ").size(16.0))
                    .clicked()
                {
                    self.run_unlock();
                }
            });
        }
    }

    fn draw_migrate_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Migrate Vault (v7 to v8)");
        ui.add_space(8.0);

        self.draw_storage_fields(ui);
        ui.add_space(8.0);
        self.draw_fs_provider_section(ui);
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Vault password:");
            ui.add(
                egui::TextEdit::singleline(&mut *self.vault_password)
                    .password(true)
                    .desired_width(300.0),
            );
        });

        ui.add_space(12.0);

        let busy = self.is_busy();
        ui.add_enabled_ui(!busy, |ui| {
            if ui
                .button(egui::RichText::new("  Migrate Vault  ").size(16.0))
                .clicked()
            {
                self.run_migrate();
            }
        });
    }

    fn update_stats(&mut self) {
        if let Some(ref stats) = self.io_stats {
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(self.last_stats_instant).as_secs_f64();
            if elapsed >= 1.0 {
                let current_read = stats.bytes_read();
                let current_written = stats.bytes_written();

                let read_delta = current_read.saturating_sub(self.prev_bytes_read);
                let write_delta = current_written.saturating_sub(self.prev_bytes_written);

                self.read_throughput = read_delta as f64 / elapsed;
                self.write_throughput = write_delta as f64 / elapsed;

                self.prev_bytes_read = current_read;
                self.prev_bytes_written = current_written;
                self.last_stats_instant = now;
            }
        }
    }

    fn draw_stats_panel(&self, ui: &mut egui::Ui) {
        if let Some(ref stats) = self.io_stats {
            let total_read = stats.bytes_read();
            let total_written = stats.bytes_written();

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 16.0;
                ui.label(
                    egui::RichText::new(format!(
                        "Read: {} ({})  ",
                        format_bytes_per_sec(self.read_throughput),
                        format_bytes(total_read),
                    ))
                    .color(egui::Color32::from_rgb(100, 180, 255))
                    .monospace(),
                );
                ui.label(
                    egui::RichText::new(format!(
                        "Write: {} ({})  ",
                        format_bytes_per_sec(self.write_throughput),
                        format_bytes(total_written),
                    ))
                    .color(egui::Color32::from_rgb(255, 180, 100))
                    .monospace(),
                );
            });
        }
    }

    fn draw_log_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Status");
            if ui.button("Clear").clicked() {
                self.log.clear();
            }
        });
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for (level, msg) in &self.log.entries {
                    let color = match level {
                        LogLevel::Info => egui::Color32::from_rgb(180, 180, 180),
                        LogLevel::Error => egui::Color32::from_rgb(255, 100, 100),
                        LogLevel::Done => egui::Color32::from_rgb(100, 220, 100),
                    };
                    let prefix = match level {
                        LogLevel::Info => "[INFO]",
                        LogLevel::Error => "[ERROR]",
                        LogLevel::Done => "[DONE]",
                    };
                    ui.label(egui::RichText::new(format!("{prefix} {msg}")).color(color));
                }
            });
    }
}

// ---------------------------------------------------------------------------
// Helper UI widgets
// ---------------------------------------------------------------------------

fn labeled_text_field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(f32::INFINITY),
        );
    });
}

fn labeled_password_field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .password(true)
                .desired_width(f32::INFINITY),
        );
    });
}

fn format_bytes_per_sec(bps: f64) -> String {
    if bps >= 1_073_741_824.0 {
        format!("{:.1} GB/s", bps / 1_073_741_824.0)
    } else if bps >= 1_048_576.0 {
        format!("{:.1} MB/s", bps / 1_048_576.0)
    } else if bps >= 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else {
        format!("{bps:.0} B/s")
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// eframe::App implementation
// ---------------------------------------------------------------------------

impl eframe::App for CryptomatorGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain background messages.
        self.drain_log_channel();
        self.update_stats();

        // Fast polling while busy (waiting for log messages from background threads).
        // Once unlocked and idle, repaint once per second to update the stats panel.
        if self.is_busy() {
            ctx.request_repaint();
        } else if *self.unlocked.lock().unwrap_or_else(|e| e.into_inner()) {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }

        // Sidebar with tab navigation.
        egui::SidePanel::left("nav_panel")
            .resizable(false)
            .exact_width(140.0)
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.heading("Cryptomator");
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                if ui
                    .selectable_label(self.active_tab == Tab::Unlock, "Unlock")
                    .clicked()
                {
                    self.active_tab = Tab::Unlock;
                }
                ui.add_space(4.0);
                if ui
                    .selectable_label(self.active_tab == Tab::Create, "Create")
                    .clicked()
                {
                    self.active_tab = Tab::Create;
                }
                ui.add_space(4.0);
                if ui
                    .selectable_label(self.active_tab == Tab::Migrate, "Migrate")
                    .clicked()
                {
                    self.active_tab = Tab::Migrate;
                }
                ui.add_space(4.0);
                if ui
                    .selectable_label(self.active_tab == Tab::Advanced, "Advanced")
                    .clicked()
                {
                    self.active_tab = Tab::Advanced;
                }
            });

        // Bottom panel for status/log.
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .min_height(100.0)
            .default_height(160.0)
            .show(ctx, |ui| {
                self.draw_log_panel(ui);
            });

        // Stats panel (only visible when vault is unlocked, sits above the log).
        if self.io_stats.is_some() {
            egui::TopBottomPanel::bottom("stats_panel")
                .resizable(false)
                .show(ctx, |ui| {
                    self.draw_stats_panel(ui);
                });
        }

        // Central panel with the active tab content.
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.active_tab {
                Tab::Create => self.draw_create_tab(ui),
                Tab::Unlock => self.draw_unlock_tab(ui),
                Tab::Migrate => self.draw_migrate_tab(ui),
                Tab::Advanced => self.draw_advanced_tab(ui),
            });
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn do_simple_mount<FS: FileSystem + 'static>(
    fs: FS,
    vault_path: &Path,
    full_storage_path: &Path,
    password: &str,
    read_only: bool,
    mount_folder: &str,
    tx: &mpsc::Sender<LogMsg>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let _ = tx.send(LogMsg::Info("Deriving keys...".into()));
    let vault = Vault::open(&fs, vault_path, password)
        .map_err(|e| anyhow::anyhow!("Failed to open vault: {e}"))?;

    let cryptor = Cryptor::new(vault);
    let config = CryptoFsConfig {
        read_only,
        ..Default::default()
    };

    let full_path_str = full_storage_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid storage path encoding"))?;

    let crypto_fs = CryptoFs::new(full_path_str, cryptor, fs, config)
        .map_err(|e| anyhow::anyhow!("Failed to initialize storage: {e}"))?;

    let _ = tx.send(LogMsg::Stats(crypto_fs.io_stats().clone()));

    // Find an available port.
    let _ = tx.send(LogMsg::Info("Finding available port...".into()));
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| anyhow::anyhow!("Failed to find available port: {e}"))?;
        listener.local_addr()?.port()
    };
    let listen_address = format!("127.0.0.1:{port}");
    let _ = tx.send(LogMsg::Info(format!("Using port {port} for server")));

    // Create mount folder if it doesn't exist.
    std::fs::create_dir_all(mount_folder)
        .map_err(|e| anyhow::anyhow!("Failed to create mount folder '{mount_folder}': {e}"))?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow::anyhow!("Failed to create tokio runtime: {e}"))?;

    let mount_folder_owned = mount_folder.to_owned();
    let tx_clone = tx.clone();

    let mount_succeeded = rt.block_on(async {
        // Spawn the NFS server as a background task.
        let nfs_handle = tokio::spawn(mount_nfs(listen_address.clone(), crypto_fs));

        // Wait briefly for the NFS server to start listening, then
        // verify it is reachable before running the OS mount command.
        let mut connected = false;
        for attempt in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if tokio::net::TcpStream::connect(&listen_address)
                .await
                .is_ok()
            {
                connected = true;
                break;
            }
            if attempt == 19 {
                let _ = tx_clone.send(LogMsg::Error(
                    "Timed out waiting for server to start".into(),
                ));
            }
        }

        if !connected {
            nfs_handle.abort();
            return false;
        }

        // Mount the NFS share to the user-specified folder.
        let _ = tx_clone.send(LogMsg::Info(format!("Mounting to {mount_folder_owned}...")));

        #[cfg(target_os = "macos")]
        let mount_result = tokio::process::Command::new("mount_nfs")
            .arg("-o")
            .arg(format!(
                "nolocks,locallocks,vers=3,tcp,port={port},mountport={port},rsize=65536,wsize=65536"
            ))
            .arg("127.0.0.1:/")
            .arg(&mount_folder_owned)
            .output()
            .await;

        #[cfg(target_os = "unix")]
        let mount_result = tokio::process::Command::new("mount.nfs")
            .arg(format!("127.0.0.1:/"))
            .arg(&mount_folder_owned)
            .arg("-o")
            .arg(format!(
                "nolocks,locallocks,vers=3,tcp,port={port},mountport={port},rsize=65536,wsize=65536"
            ))
            .output()
            .await;

        match mount_result {
            Ok(output) => {
                if output.status.success() {
                    let _ = tx_clone.send(LogMsg::ServerRunning(format!(
                        "Vault mounted at {mount_folder_owned}"
                    )));
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let _ = tx_clone.send(LogMsg::Error(format!("NFS mount failed: {stderr}")));
                    nfs_handle.abort();
                    return false;
                }
            }
            Err(e) => {
                let _ = tx_clone.send(LogMsg::Error(format!(
                    "Failed to run NFS mount command: {e}"
                )));
                nfs_handle.abort();
                return false;
            }
        }

        // Wait until shutdown is requested or NFS server exits.
        tokio::select! {
            result = nfs_handle => {
                match result {
                    Ok(()) => {}
                    Err(e) => {
                        let _ = tx_clone.send(LogMsg::Error(format!(
                            "NFS server task failed: {e}"
                        )));
                    }
                }
            }
            _ = shutdown_rx => {}
        }

        true
    });

    if mount_succeeded {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Mount failed"))
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 600.0])
            .with_min_inner_size([520.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Cryptomator",
        options,
        Box::new(|cc| Ok(Box::new(CryptomatorGui::new(cc)))),
    )
}
