use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use uuid::Uuid;
use zeroize::Zeroizing;

use cryptomator::crypto::{Cryptor, DEFAULT_MASTER_KEY_FILE, DEFAULT_VAULT_FILENAME, Vault};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig, FileSystem, IoStats};
use cryptomator::frontends::auth::WebDavAuth;
use cryptomator::frontends::mount::{mount_nfs, mount_webdav};
use cryptomator::operations::DEFAULT_STORAGE_SUB_FOLDER;
use cryptomator::providers::{LocalFs, WebDavFs};

use crate::storage::{FsProviderConfig, IdleLockConfig, VaultEntry, VolumeType};
use crate::widgets::{BusyGuard, LogLevel, LogMsg};

// ---------------------------------------------------------------------------
// Vault status
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub enum VaultStatus {
    Locked,
    Unlocking,
    Unlocked,
    Locking,
}

// ---------------------------------------------------------------------------
// Per-vault runtime state
// ---------------------------------------------------------------------------

pub struct VaultRuntime {
    #[allow(dead_code)]
    pub vault_id: Uuid,
    pub status: VaultStatus,
    pub log_tx: mpsc::Sender<LogMsg>,
    pub log_rx: mpsc::Receiver<LogMsg>,
    pub shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    pub io_stats: Option<IoStats>,
    /// Active NFS mount folder, if this vault is currently mounted via NFS.
    pub active_mount_folder: Option<String>,
    pub busy: Arc<Mutex<bool>>,
    pub last_activity: Instant,

    // Throughput tracking
    pub prev_bytes_read: u64,
    pub prev_bytes_written: u64,
    pub last_stats_instant: Instant,
    pub read_throughput: f64,
    pub write_throughput: f64,
}

impl VaultRuntime {
    pub fn new(vault_id: Uuid) -> Self {
        let (log_tx, log_rx) = mpsc::channel();
        Self {
            vault_id,
            status: VaultStatus::Locked,
            log_tx,
            log_rx,
            shutdown_tx: None,
            io_stats: None,
            active_mount_folder: None,
            busy: Arc::new(Mutex::new(false)),
            last_activity: Instant::now(),
            prev_bytes_read: 0,
            prev_bytes_written: 0,
            last_stats_instant: Instant::now(),
            read_throughput: 0.0,
            write_throughput: 0.0,
        }
    }

    pub fn is_busy(&self) -> bool {
        *self.busy.lock().unwrap_or_else(|e| {
            eprintln!("Recovering from poisoned busy mutex in is_busy()");
            e.into_inner()
        })
    }

    fn set_busy(&self, val: bool) {
        *self.busy.lock().unwrap_or_else(|e| {
            eprintln!("Recovering from poisoned busy mutex in set_busy()");
            e.into_inner()
        }) = val;
    }

    /// Drain messages from the background thread.
    /// Returns a list of log entries for the global log.
    pub fn drain_log_channel(&mut self) -> Vec<(LogLevel, String)> {
        let mut entries = Vec::new();
        while let Ok(msg) = self.log_rx.try_recv() {
            match msg {
                LogMsg::Info(s) => entries.push((LogLevel::Info, s)),
                LogMsg::Error(s) => entries.push((LogLevel::Error, s)),
                LogMsg::Done(s) => {
                    entries.push((LogLevel::Done, s));
                }
                LogMsg::ServerRunning(s) => {
                    entries.push((LogLevel::Done, s));
                    self.set_busy(false);
                    self.status = VaultStatus::Unlocked;
                    self.last_activity = Instant::now();
                }
                LogMsg::ServerStopped(s) => {
                    entries.push((LogLevel::Info, s));
                    self.status = VaultStatus::Locked;
                    self.shutdown_tx = None;
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
                    self.last_stats_instant = Instant::now();
                }
            }
        }
        entries
    }

    pub fn update_stats(&mut self) {
        if let Some(ref stats) = self.io_stats {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_stats_instant).as_secs_f64();
            if elapsed >= 1.0 {
                let current_read = stats.bytes_read();
                let current_written = stats.bytes_written();

                let read_delta = current_read.saturating_sub(self.prev_bytes_read);
                let write_delta = current_written.saturating_sub(self.prev_bytes_written);

                self.read_throughput = read_delta as f64 / elapsed;
                self.write_throughput = write_delta as f64 / elapsed;

                // Detect activity for idle lock
                if read_delta > 0 || write_delta > 0 {
                    self.last_activity = Instant::now();
                }

                self.prev_bytes_read = current_read;
                self.prev_bytes_written = current_written;
                self.last_stats_instant = now;
            }
        }
    }

    /// Returns true if the vault should be auto-locked due to idle timeout.
    pub fn check_idle_timer(&self, idle_lock: Option<&IdleLockConfig>) -> bool {
        if self.status != VaultStatus::Unlocked {
            return false;
        }
        let Some(config) = idle_lock else {
            return false;
        };
        let idle_duration = std::time::Duration::from_secs(config.minutes as u64 * 60);
        self.last_activity.elapsed() >= idle_duration
    }

    // -- Actions --------------------------------------------------------------

    /// Mount the vault using NFS (simple mount mode).
    pub fn run_mount(
        &mut self,
        entry: &VaultEntry,
        password: &str,
        webdav_provider_password: Option<&str>,
    ) {
        let vault_path = resolved_vault_path(entry);
        let full_storage_path = full_storage_path(entry);
        let mount_folder = match &entry.mounting.volume_type {
            VolumeType::Nfs => {
                let mount_folder = match &entry.mounting.mount_point {
                    Some(folder) => folder.clone(),
                    None => {
                        let _ = self
                            .log_tx
                            .send(LogMsg::Error("Mount point not configured.".into()));
                        return;
                    }
                };

                if let Err(msg) = validate_mount_folder(&mount_folder) {
                    let _ = self.log_tx.send(LogMsg::Error(msg));
                    return;
                }

                Some(mount_folder)
            }
            VolumeType::WebDav { .. } => None,
        };

        let password = Zeroizing::new(password.to_owned());
        let webdav_provider_password =
            webdav_provider_password.map(|p| Zeroizing::new(p.to_owned()));
        let tx = self.log_tx.clone();
        let busy = self.busy.clone();
        let provider = entry.provider.clone();
        let volume_type = entry.mounting.volume_type.clone();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Set state AFTER all validation checks to avoid orphaned state on early return.
        self.shutdown_tx = Some(shutdown_tx);
        self.active_mount_folder = mount_folder.clone();
        self.status = VaultStatus::Unlocking;

        self.set_busy(true);
        let _ = tx.send(LogMsg::Info("Mounting vault...".into()));

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);

            let result = match &provider {
                FsProviderConfig::Local { .. } => do_mount(
                    LocalFs::new(),
                    &vault_path,
                    &full_storage_path,
                    password.as_str(),
                    mount_folder.as_deref(),
                    &volume_type,
                    &tx,
                    shutdown_rx,
                ),
                FsProviderConfig::WebDav { url, username } => {
                    let user = username.as_deref();
                    let pass = webdav_provider_password.as_deref().map(|z| z.as_str());
                    match WebDavFs::new(url, user, pass) {
                        Ok(fs) => do_mount(
                            fs,
                            &vault_path,
                            &full_storage_path,
                            password.as_str(),
                            mount_folder.as_deref(),
                            &volume_type,
                            &tx,
                            shutdown_rx,
                        ),
                        Err(e) => Err(anyhow::anyhow!(e.to_string())),
                    }
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

    /// Lock/unmount the vault.
    pub fn run_lock(&mut self) {
        if self.shutdown_tx.is_none() {
            return;
        }
        let shutdown_tx = self.shutdown_tx.take();
        let folder = self.active_mount_folder.clone();
        let log_tx = self.log_tx.clone();
        let busy = self.busy.clone();

        self.status = VaultStatus::Locking;
        self.set_busy(true);
        let _ = log_tx.send(LogMsg::Info("Locking vault...".into()));

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);
            if let Some(folder) = folder {
                // Re-validate the mount folder path before passing to umount.
                let folder = match std::fs::canonicalize(&folder) {
                    Ok(canon) => {
                        if !canon.is_dir() {
                            let _ = log_tx.send(LogMsg::Error(format!(
                                "Mount folder is not a directory: {}",
                                canon.display()
                            )));
                            if let Some(tx) = shutdown_tx {
                                let _ = tx.send(());
                            }
                            return;
                        }
                        canon.to_string_lossy().to_string()
                    }
                    Err(e) => {
                        let _ = log_tx.send(LogMsg::Error(format!(
                            "Cannot resolve mount folder '{folder}': {e}"
                        )));
                        // Fall through with original path to attempt umount anyway
                        folder
                    }
                };
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
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn resolved_vault_path(entry: &VaultEntry) -> PathBuf {
    if entry.vault_file_path.is_empty() {
        Path::new(&entry.storage_path).join(DEFAULT_VAULT_FILENAME)
    } else {
        normalize_vault_manifest_path(Path::new(&entry.vault_file_path))
    }
}

fn normalize_vault_manifest_path(path: &Path) -> PathBuf {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(DEFAULT_MASTER_KEY_FILE) => path.with_file_name(DEFAULT_VAULT_FILENAME),
        _ => path.to_path_buf(),
    }
}

fn full_storage_path(entry: &VaultEntry) -> PathBuf {
    Path::new(&entry.storage_path).join(DEFAULT_STORAGE_SUB_FOLDER)
}

// ---------------------------------------------------------------------------
// Mount folder validation
// ---------------------------------------------------------------------------

fn validate_mount_folder(mount_folder: &str) -> Result<(), String> {
    let mount_path = Path::new(mount_folder);
    if !mount_path.is_absolute() {
        return Err("Mount folder must be an absolute path.".into());
    }

    // Removed "/home" and "/opt" since they contain user directories on Linux.
    const FORBIDDEN_DIRS: &[&str] = &[
        "/", "/etc", "/usr", "/bin", "/sbin", "/System", "/var", "/tmp", "/private", "/Library",
        "/dev", "/proc", "/boot", "/Volumes",
    ];

    // If the mount folder already exists, resolve symlinks before checking against
    // forbidden dirs to prevent symlink-based bypass.
    let resolved_path = if mount_path.exists() {
        std::fs::canonicalize(mount_path)
            .map_err(|e| format!("Failed to resolve mount folder path: {e}"))?
    } else {
        mount_path.to_path_buf()
    };

    let raw_str = resolved_path
        .to_str()
        .ok_or_else(|| "Mount folder path contains non-UTF-8 characters.".to_string())?;
    let raw_trimmed = raw_str.trim_end_matches('/');
    if FORBIDDEN_DIRS.contains(&raw_trimmed) {
        return Err(format!(
            "Mount folder must not be a system directory: {mount_folder}"
        ));
    }

    let mut normalized = PathBuf::new();
    for component in resolved_path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            c => normalized.push(c),
        }
    }
    let normalized_str = normalized
        .to_str()
        .ok_or_else(|| "Normalized mount path contains non-UTF-8 characters.".to_string())?;
    let normalized_trimmed = normalized_str.trim_end_matches('/');

    if FORBIDDEN_DIRS.contains(&normalized_trimmed) {
        return Err(format!(
            "Mount folder resolves to a system directory: {normalized_trimmed}"
        ));
    }

    if FORBIDDEN_DIRS
        .iter()
        .any(|d| *d != "/" && normalized_trimmed.starts_with(&format!("{d}/")))
    {
        return Err(format!(
            "Mount folder must not be inside a system directory: {normalized_trimmed}"
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Mount implementation (generic over filesystem)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn do_mount<FS: FileSystem + 'static>(
    fs: FS,
    vault_path: &Path,
    full_storage_path: &Path,
    password: &str,
    mount_folder: Option<&str>,
    volume_type: &VolumeType,
    tx: &mpsc::Sender<LogMsg>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let _ = tx.send(LogMsg::Info("Deriving keys...".into()));
    let vault = Vault::open(&fs, vault_path, password)
        .map_err(|e| anyhow::anyhow!("Failed to open vault: {e}"))?;

    let cryptor = Cryptor::new(vault);
    let config = CryptoFsConfig {
        read_only: false,
        ..Default::default()
    };

    let full_path_str = full_storage_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid storage path encoding"))?;

    let crypto_fs = CryptoFs::new(full_path_str, cryptor, fs, config)
        .map_err(|e| anyhow::anyhow!("Failed to initialize storage: {e}"))?;

    let _ = tx.send(LogMsg::Stats(crypto_fs.io_stats().clone()));

    match volume_type {
        VolumeType::Nfs => do_nfs_mount(
            crypto_fs,
            mount_folder.ok_or_else(|| anyhow::anyhow!("Mount point not configured."))?,
            tx,
            shutdown_rx,
        ),
        VolumeType::WebDav {
            host,
            port,
            auth_user,
            auth_password,
        } => do_webdav_mount(
            crypto_fs,
            host,
            *port,
            auth_user.as_deref(),
            auth_password.as_deref(),
            tx,
            shutdown_rx,
        ),
    }
}

/// Mount via NFS. Windows is not yet supported; cfg attributes already limit compilation
/// to macOS and Linux.
fn do_nfs_mount<FS: FileSystem + 'static>(
    crypto_fs: CryptoFs<FS>,
    mount_folder: &str,
    tx: &mpsc::Sender<LogMsg>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let _ = tx.send(LogMsg::Info("Finding available port...".into()));
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| anyhow::anyhow!("Failed to find available port: {e}"))?;
        listener.local_addr()?.port()
    };
    let listen_address = format!("127.0.0.1:{port}");
    let _ = tx.send(LogMsg::Info(format!("Using port {port} for NFS server")));

    std::fs::create_dir_all(mount_folder)
        .map_err(|e| anyhow::anyhow!("Failed to create mount folder '{mount_folder}': {e}"))?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow::anyhow!("Failed to create tokio runtime: {e}"))?;

    let mount_folder_owned = mount_folder.to_owned();
    let tx_clone = tx.clone();

    let mount_succeeded = rt.block_on(async {
        let nfs_handle = tokio::spawn(mount_nfs(listen_address.clone(), crypto_fs));

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

        #[cfg(all(unix, not(target_os = "macos")))]
        let mount_result = tokio::process::Command::new("mount.nfs")
            .arg("127.0.0.1:/")
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

        tokio::select! {
            result = nfs_handle => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        let _ = tx_clone.send(LogMsg::Error(format!(
                            "NFS server failed: {e}"
                        )));
                    }
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

fn do_webdav_mount<FS: FileSystem + 'static>(
    crypto_fs: CryptoFs<FS>,
    host: &str,
    port: u16,
    auth_user: Option<&str>,
    auth_password: Option<&str>,
    tx: &mpsc::Sender<LogMsg>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let listen_address = format!("{host}:{port}");
    let socket_addr: SocketAddr = listen_address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid WebDAV listen address '{listen_address}': {e}"))?;

    let auth = auth_user.map(|user| WebDavAuth::new(user, auth_password.unwrap_or("")));

    // Fail before updating UI state if the address is already in use.
    //
    // NOTE: This is a TOCTOU check -- the port could become unavailable between
    // this probe and the actual bind inside `mount_webdav`. The check exists
    // only to give a friendlier early error in the common case; the real bind
    // inside the server will still fail safely if the port is taken.
    std::net::TcpListener::bind(socket_addr)
        .map_err(|e| anyhow::anyhow!("Failed to bind WebDAV server on {listen_address}: {e}"))?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow::anyhow!("Failed to create tokio runtime: {e}"))?;

    rt.block_on(async move {
        let mut webdav_handle = tokio::spawn(mount_webdav(listen_address.clone(), crypto_fs, auth));
        let mut ready = false;

        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            if tokio::net::TcpStream::connect(socket_addr).await.is_ok() {
                ready = true;
                break;
            }

            if webdav_handle.is_finished() {
                match webdav_handle.await {
                    Ok(Ok(())) => {
                        return Err(anyhow::anyhow!(
                            "WebDAV server exited before accepting connections"
                        ));
                    }
                    Ok(Err(e)) => {
                        return Err(anyhow::anyhow!("WebDAV server failed: {e}"));
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("WebDAV server task failed: {e}"));
                    }
                }
            }
        }

        if !ready {
            webdav_handle.abort();
            let _ = webdav_handle.await;
            return Err(anyhow::anyhow!(
                "Timed out waiting for the WebDAV server to start"
            ));
        }

        let _ = tx.send(LogMsg::ServerRunning(format!(
            "Vault unlocked. WebDAV server listening on {listen_address}"
        )));

        tokio::select! {
            result = &mut webdav_handle => {
                match result {
                    Ok(Ok(())) => Err(anyhow::anyhow!("WebDAV server stopped unexpectedly")),
                    Ok(Err(e)) => Err(anyhow::anyhow!("WebDAV server failed: {e}")),
                    Err(e) => Err(anyhow::anyhow!("WebDAV server task failed: {e}")),
                }
            }
            _ = shutdown_rx => {
                webdav_handle.abort();
                let _ = webdav_handle.await;
                Ok(())
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Reveal drive
// ---------------------------------------------------------------------------

/// Open the given path in the platform file manager.
///
/// NOTE: Windows is not yet supported. The cfg attributes already limit compilation
/// to macOS and Linux.
pub fn reveal_in_file_manager(path: &str) {
    let p = Path::new(path);
    if !p.is_dir() {
        eprintln!("reveal_in_file_manager: path is not an existing directory: {path}");
        return;
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(path).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::resolved_vault_path;
    use crate::storage::{FsProviderConfig, MountingConfig, VaultEntry};
    use std::path::Path;
    use uuid::Uuid;

    fn entry_with_vault_file_path(vault_file_path: &str) -> VaultEntry {
        VaultEntry {
            id: Uuid::nil(),
            name: "Vault".into(),
            storage_path: "/tmp/Vault".into(),
            vault_file_path: vault_file_path.into(),
            provider: FsProviderConfig::Local {
                base_path: "/tmp/Vault".into(),
            },
            mounting: MountingConfig::default(),
            idle_lock: None,
        }
    }

    #[test]
    fn resolved_vault_path_normalizes_legacy_masterkey_selection() {
        let entry = entry_with_vault_file_path("/tmp/Vault/masterkey.cryptomator");
        assert_eq!(
            resolved_vault_path(&entry),
            Path::new("/tmp/Vault/vault.cryptomator")
        );
    }

    #[test]
    fn resolved_vault_path_defaults_to_vault_file_name() {
        let mut entry = entry_with_vault_file_path("");
        entry.storage_path = "/tmp/Vault".into();
        assert_eq!(
            resolved_vault_path(&entry),
            Path::new("/tmp/Vault/vault.cryptomator")
        );
    }
}
