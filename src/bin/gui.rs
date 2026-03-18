#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use eframe::egui;
use zeroize::Zeroizing;

use cryptomator::crypto::{Cryptor, Vault, DEFAULT_VAULT_FILENAME};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig, FileSystem};
use cryptomator::frontends::auth::WebDavAuth;
use cryptomator::frontends::mount::{mount_nfs, mount_webdav};
use cryptomator::operations::{create_vault, migrate_v7_to_v8, DEFAULT_STORAGE_SUB_FOLDER};
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

    // -- unlock fields --
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
                }
            }
        }
    }

    // -- actions -----------------------------------------------------------

    fn run_create(&mut self) {
        if self.storage_path.is_empty() {
            self.log.push(LogLevel::Error, "Storage path is required.".into());
            return;
        }
        if self.vault_password.is_empty() {
            self.log.push(LogLevel::Error, "Password is required.".into());
            return;
        }
        if *self.vault_password != *self.vault_password_confirm {
            self.log.push(LogLevel::Error, "Passwords do not match.".into());
            return;
        }
        let scrypt_cost: u64 = match self.scrypt_cost.parse() {
            Ok(v) => v,
            Err(_) => {
                self.log.push(LogLevel::Error, "Invalid scrypt cost value.".into());
                return;
            }
        };
        let scrypt_block_size: u32 = match self.scrypt_block_size.parse() {
            Ok(v) => v,
            Err(_) => {
                self.log.push(LogLevel::Error, "Invalid scrypt block size.".into());
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
                    "Scrypt parameters too large: 128 * r * N = {} exceeds 2 GB limit.",
                    mem_usage
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
                    let user = if webdav_user.is_empty() { None } else { Some(webdav_user.as_str()) };
                    let pass = if webdav_pass.is_empty() { None } else { Some(webdav_pass.as_str()) };
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
                Ok(()) => { let _ = tx.send(LogMsg::Done("Vault created successfully.".into())); }
                Err(e) => {
                    let _ = tx.send(LogMsg::Error(format!("Create failed: {e:#}")));
                    let _ = tx.send(LogMsg::Done("Create operation finished with errors.".into()));
                }
            }
        });
    }

    fn run_migrate(&mut self) {
        if self.storage_path.is_empty() {
            self.log.push(LogLevel::Error, "Storage path is required.".into());
            return;
        }
        if self.vault_password.is_empty() {
            self.log.push(LogLevel::Error, "Password is required.".into());
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
        self.log.push(LogLevel::Info, "Migrating vault v7 -> v8...".into());

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);
            let result = match provider {
                FsProvider::Local => {
                    migrate_v7_to_v8(LocalFs::new(), &vault_path, password.as_str())
                }
                FsProvider::WebDav => {
                    let user = if webdav_user.is_empty() { None } else { Some(webdav_user.as_str()) };
                    let pass = if webdav_pass.is_empty() { None } else { Some(webdav_pass.as_str()) };
                    migrate_v7_to_v8(
                        WebDavFs::new(&webdav_url, user, pass),
                        &vault_path,
                        password.as_str(),
                    )
                }
            };
            match result {
                Ok(()) => { let _ = tx.send(LogMsg::Done("Migration completed successfully.".into())); }
                Err(e) => {
                    let _ = tx.send(LogMsg::Error(format!("Migration failed: {e:#}")));
                    let _ = tx.send(LogMsg::Done("Migration finished with errors.".into()));
                }
            }
        });
    }

    fn run_unlock(&mut self) {
        if self.storage_path.is_empty() {
            self.log.push(LogLevel::Error, "Storage path is required.".into());
            return;
        }
        if self.vault_password.is_empty() {
            self.log.push(LogLevel::Error, "Password is required.".into());
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

        self.set_busy(true);
        self.log.push(LogLevel::Info, "Unlocking vault...".into());

        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);
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

                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| anyhow::anyhow!("Failed to create tokio runtime: {e}"))?;

                match frontend {
                    Frontend::WebDav => {
                        let auth = if webdav_fe_user.is_empty() {
                            None
                        } else {
                            let pass = if webdav_fe_pass.is_empty() { "" } else { webdav_fe_pass };
                            Some(WebDavAuth::new(webdav_fe_user, pass))
                        };
                        let addr = webdav_listen.to_owned();
                        let _ = tx.send(LogMsg::ServerRunning(
                            format!("Vault unlocked. WebDAV server listening on {webdav_listen}"),
                        ));
                        rt.block_on(async {
                            tokio::select! {
                                _ = mount_webdav(addr, crypto_fs, auth) => {}
                                _ = shutdown_rx => {}
                            }
                        });
                    }
                    Frontend::Nfs => {
                        let addr = nfs_listen.to_owned();
                        let _ = tx.send(LogMsg::ServerRunning(
                            format!("Vault unlocked. NFS server listening on {nfs_listen}"),
                        ));
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
                    let user = if webdav_user.is_empty() { None } else { Some(webdav_user.as_str()) };
                    let pass = if webdav_pass.is_empty() { None } else { Some(webdav_pass.as_str()) };
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
                    let _ = tx.send(LogMsg::ServerStopped("Vault locked. Server stopped.".into()));
                }
                Err(e) => {
                    let _ = tx.send(LogMsg::Error(format!("Unlock failed: {e:#}")));
                    let _ = tx.send(LogMsg::Done("Unlock failed.".into()));
                }
            }
        });
    }

    fn run_lock(&mut self) {
        if let Some(tx) = self.unlock_shutdown.take() {
            let _ = tx.send(());
            self.log.push(LogLevel::Info, "Locking vault...".into());
        }
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
                labeled_text_field(ui, "URL:", &mut self.webdav_provider_url, "https://example.com/dav");
                labeled_text_field(ui, "Username:", &mut self.webdav_provider_user, "");
                labeled_password_field(ui, "Password:", &mut *self.webdav_provider_pass);
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
                ui.add(
                    egui::TextEdit::singleline(&mut self.scrypt_cost)
                        .desired_width(100.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Block size (r):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.scrypt_block_size)
                        .desired_width(100.0),
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
        ui.heading("Unlock Vault");
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
            ui.label("Mount Frontend");
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
                        &mut *self.webdav_frontend_pass,
                    );
                }
            }
        });

        ui.add_space(12.0);

        let busy = self.is_busy();
        let unlocked = *self.unlocked.lock().unwrap_or_else(|e| e.into_inner());

        if unlocked {
            if ui
                .button(egui::RichText::new("  Lock Vault  ").size(16.0).color(egui::Color32::from_rgb(255, 100, 100)))
                .clicked()
            {
                self.run_lock();
            }
        } else {
            ui.add_enabled_ui(!busy, |ui| {
                if ui
                    .button(egui::RichText::new("  Unlock & Mount  ").size(16.0))
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

// ---------------------------------------------------------------------------
// eframe::App implementation
// ---------------------------------------------------------------------------

impl eframe::App for CryptomatorGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain background messages.
        self.drain_log_channel();

        // If busy or unlocked, request continuous repaints so we pick up log messages.
        if self.is_busy() || *self.unlocked.lock().unwrap_or_else(|e| e.into_inner()) {
            ctx.request_repaint();
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
            });

        // Bottom panel for status/log.
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .min_height(100.0)
            .default_height(160.0)
            .show(ctx, |ui| {
                self.draw_log_panel(ui);
            });

        // Central panel with the active tab content.
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.active_tab {
                    Tab::Create => self.draw_create_tab(ui),
                    Tab::Unlock => self.draw_unlock_tab(ui),
                    Tab::Migrate => self.draw_migrate_tab(ui),
                }
            });
        });
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
