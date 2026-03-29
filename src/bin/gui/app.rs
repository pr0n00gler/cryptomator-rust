use std::collections::HashMap;

use eframe::egui;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::create_flow::CreateVaultModal;
use crate::modals::{ConfirmModal, Modal, ModalResult, PasswordModal, SuccessModal};
use crate::open_flow::OpenVaultModal;
use crate::settings_window::{self, SettingsAction, VaultSettingsState};
use crate::sidebar::{self, SidebarAction};
use crate::storage::AppStorage;
use crate::vault_runtime::{VaultRuntime, VaultStatus, reveal_in_file_manager};
use crate::vault_view::{self, VaultViewAction};
use crate::widgets::{self, LogBuffer, LogLevel};

// ---------------------------------------------------------------------------
// Active modal enum -- wraps all possible modal types
// ---------------------------------------------------------------------------

enum ActiveModal {
    Password(PasswordModal),
    #[allow(dead_code)]
    Success(SuccessModal),
    Confirm(ConfirmModal),
    Create(Box<CreateVaultModal>),
    Open(Box<OpenVaultModal>),
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

pub struct CryptomatorApp {
    pub storage: AppStorage,
    pub selected_vault_id: Option<Uuid>,
    pub vault_runtimes: HashMap<Uuid, VaultRuntime>,

    active_modal: Option<ActiveModal>,
    settings_window: Option<VaultSettingsState>,

    log: LogBuffer,
}

impl CryptomatorApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            storage: AppStorage::load(),
            selected_vault_id: None,
            vault_runtimes: HashMap::new(),
            active_modal: None,
            settings_window: None,
            log: LogBuffer::new(),
        }
    }

    fn get_or_create_runtime(&mut self, vault_id: Uuid) -> &mut VaultRuntime {
        self.vault_runtimes
            .entry(vault_id)
            .or_insert_with(|| VaultRuntime::new(vault_id))
    }

    /// Drain all vault runtime log channels into the global log.
    fn drain_all_runtimes(&mut self) {
        let ids: Vec<Uuid> = self.vault_runtimes.keys().copied().collect();
        for id in ids {
            if let Some(rt) = self.vault_runtimes.get_mut(&id) {
                let entries = rt.drain_log_channel();
                for (level, msg) in entries {
                    let vault_name = self
                        .storage
                        .find_vault(id)
                        .map(|v| v.name.as_str())
                        .unwrap_or("?");
                    self.log.push(level, format!("[{vault_name}] {msg}"));
                }
                rt.update_stats();

                // Check idle timer
                let idle_lock = self
                    .storage
                    .find_vault(id)
                    .and_then(|v| v.idle_lock.as_ref());
                if rt.check_idle_timer(idle_lock) {
                    rt.run_lock();
                    self.log.push(
                        LogLevel::Info,
                        format!(
                            "[{}] Auto-locked due to inactivity.",
                            self.storage
                                .find_vault(id)
                                .map(|v| v.name.as_str())
                                .unwrap_or("?")
                        ),
                    );
                }
            }
        }
    }

    fn handle_sidebar_action(&mut self, action: SidebarAction) {
        match action {
            SidebarAction::None => {}
            SidebarAction::SelectVault(id) => {
                self.selected_vault_id = Some(id);
            }
            SidebarAction::CreateNewVault => {
                self.active_modal = Some(ActiveModal::Create(Box::new(CreateVaultModal::new())));
            }
            SidebarAction::OpenExistingVault => {
                self.active_modal = Some(ActiveModal::Open(Box::new(OpenVaultModal::new())));
            }
            SidebarAction::RemoveVault(id) => {
                let name = self
                    .storage
                    .find_vault(id)
                    .map(|v| v.name.clone())
                    .unwrap_or_default();
                self.active_modal = Some(ActiveModal::Confirm(ConfirmModal::new(
                    id,
                    "Remove Vault".into(),
                    format!(
                        "Remove \"{name}\" from the vault list?\nThis will not delete the vault files."
                    ),
                )));
            }
            SidebarAction::OpenSettings(id) => {
                if let Some(entry) = self.storage.find_vault(id) {
                    self.settings_window = Some(VaultSettingsState::from_entry(entry));
                }
            }
        }
    }

    fn handle_vault_view_action(&mut self, action: VaultViewAction) {
        match action {
            VaultViewAction::None => {}
            VaultViewAction::Unlock(id) => {
                let entry = self.storage.find_vault(id);
                let name = entry.map(|v| v.name.clone()).unwrap_or_default();
                let needs_webdav = entry
                    .map(|v| matches!(v.provider, crate::storage::FsProviderConfig::WebDav { .. }))
                    .unwrap_or(false);
                self.active_modal = Some(ActiveModal::Password(PasswordModal::new(
                    id,
                    name,
                    needs_webdav,
                )));
            }
            VaultViewAction::Lock(id) => {
                if let Some(rt) = self.vault_runtimes.get_mut(&id) {
                    rt.run_lock();
                }
            }
            VaultViewAction::RevealDrive(path) => {
                reveal_in_file_manager(&path);
            }
        }
    }

    fn process_modal(&mut self, ctx: &egui::Context) {
        let modal = match self.active_modal.as_mut() {
            Some(m) => m,
            None => return,
        };

        let should_close = match modal {
            ActiveModal::Password(pm) => {
                let result = pm.show(ctx);
                match result {
                    ModalResult::Closed => {
                        if pm.confirmed {
                            let vault_id = pm.vault_id;
                            let password = Zeroizing::new(String::from(pm.password.as_str()));
                            let webdav_password = if pm.webdav_password.is_empty() {
                                None
                            } else {
                                Some(Zeroizing::new(String::from(pm.webdav_password.as_str())))
                            };
                            // Start unlock
                            if let Some(entry) = self.storage.find_vault(vault_id) {
                                let entry = entry.clone();
                                let rt = self.get_or_create_runtime(vault_id);
                                rt.run_mount(
                                    &entry,
                                    &password,
                                    webdav_password.as_deref().map(|s| s.as_str()),
                                );
                            }
                        }
                        true
                    }
                    ModalResult::Open => false,
                }
            }
            ActiveModal::Success(sm) => {
                let result = sm.show(ctx);
                match result {
                    ModalResult::Closed => {
                        if sm.reveal_requested {
                            if let Some(ref path) = sm.mount_path {
                                reveal_in_file_manager(path);
                            }
                        }
                        true
                    }
                    ModalResult::Open => false,
                }
            }
            ActiveModal::Confirm(cm) => {
                let result = cm.show(ctx);
                match result {
                    ModalResult::Closed => {
                        if cm.confirmed {
                            let vault_id = cm.vault_id;
                            // Lock if unlocked
                            if let Some(rt) = self.vault_runtimes.get_mut(&vault_id) {
                                if rt.status == VaultStatus::Unlocked {
                                    rt.run_lock();
                                }
                            }
                            self.vault_runtimes.remove(&vault_id);
                            self.storage.remove_vault(vault_id);
                            if self.selected_vault_id == Some(vault_id) {
                                self.selected_vault_id = None;
                            }
                        }
                        true
                    }
                    ModalResult::Open => false,
                }
            }
            ActiveModal::Create(cm) => {
                let result = cm.show(ctx);
                match result {
                    ModalResult::Closed => {
                        if let Some(entry) = cm.created_entry.take() {
                            let id = entry.id;
                            self.storage.add_vault(entry);
                            self.selected_vault_id = Some(id);
                        }
                        true
                    }
                    ModalResult::Open => {
                        ctx.request_repaint();
                        false
                    }
                }
            }
            ActiveModal::Open(om) => {
                let result = om.show(ctx);
                match result {
                    ModalResult::Closed => {
                        if let Some(entry) = om.opened_entry.take() {
                            let id = entry.id;
                            self.storage.add_vault(entry);
                            self.selected_vault_id = Some(id);
                        }
                        true
                    }
                    ModalResult::Open => false,
                }
            }
        };

        if should_close {
            self.active_modal = None;
        }
    }

    fn draw_log_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .min_height(80.0)
            .default_height(140.0)
            .show(ctx, |ui| {
                widgets::draw_log_panel(&mut self.log, ui);
            });
    }

    fn draw_settings(&mut self, ctx: &egui::Context) {
        let state = match self.settings_window.as_mut() {
            Some(s) => s,
            None => return,
        };

        let action = settings_window::draw_settings_window(state, ctx);
        match action {
            SettingsAction::Saved => {
                state.apply(&mut self.storage);
                self.settings_window = None;
            }
            SettingsAction::Cancelled => {
                self.settings_window = None;
            }
            SettingsAction::None => {}
        }
    }
}

// ---------------------------------------------------------------------------
// eframe::App implementation
// ---------------------------------------------------------------------------

impl eframe::App for CryptomatorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain all background threads and check timers.
        self.drain_all_runtimes();
        // Determine repaint schedule
        let any_busy = self.vault_runtimes.values().any(|r| r.is_busy());
        let any_unlocked = self
            .vault_runtimes
            .values()
            .any(|r| r.status == VaultStatus::Unlocked);

        if any_busy {
            ctx.request_repaint();
        } else if any_unlocked {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }

        let modal_active = self.active_modal.is_some();

        // Draw sidebar
        let sidebar_action = sidebar::draw_sidebar(self, ctx);

        // Draw bottom log panel (must be added before CentralPanel)
        self.draw_log_panel(ctx);

        // Draw main vault view
        let view_action = vault_view::draw_vault_view(self, ctx);

        // Handle actions only when no modal is blocking interaction.
        if !modal_active {
            self.handle_sidebar_action(sidebar_action);
            self.handle_vault_view_action(view_action);
        }

        // Draw settings window (non-modal, separate from the main modal)
        self.draw_settings(ctx);

        // Draw active modal on top of everything
        self.process_modal(ctx);
    }
}
