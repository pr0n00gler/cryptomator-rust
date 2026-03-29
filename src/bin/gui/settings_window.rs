use eframe::egui;
use uuid::Uuid;

use cryptomator::crypto::DEFAULT_VAULT_FILENAME;

use crate::storage::{
    AppStorage, FsProviderConfig, IdleLockConfig, MountingConfig, VaultEntry, VolumeType,
};
use crate::widgets::{labeled_password_field, labeled_text_field};

// ---------------------------------------------------------------------------
// Settings state
// ---------------------------------------------------------------------------

#[derive(PartialEq)]
enum SettingsTab {
    General,
    Filesystem,
    Mounting,
}

#[derive(PartialEq, Clone, Copy)]
enum ProviderChoice {
    Local,
    WebDav,
}

#[derive(PartialEq, Clone, Copy)]
enum VolumeChoice {
    Nfs,
    WebDav,
}

pub struct VaultSettingsState {
    pub vault_id: Uuid,
    pub open: bool,
    tab: SettingsTab,

    // General
    name: String,
    idle_lock_enabled: bool,
    idle_lock_minutes: String,

    // Filesystem
    provider: ProviderChoice,
    local_base_path: String,
    webdav_url: String,
    webdav_username: String,

    // Mounting
    volume_choice: VolumeChoice,
    mount_point: String,
    webdav_host: String,
    webdav_port: String,
    webdav_auth_user: String,
    /// WebDAV auth password is not persisted for security reasons and must be
    /// re-entered on each unlock. This field is only used during a single
    /// settings session.
    webdav_auth_pass: String,
}

impl VaultSettingsState {
    pub fn from_entry(entry: &VaultEntry) -> Self {
        let (provider, local_base_path, webdav_url, webdav_username) = match &entry.provider {
            FsProviderConfig::Local { base_path } => (
                ProviderChoice::Local,
                base_path.clone(),
                String::new(),
                String::new(),
            ),
            FsProviderConfig::WebDav { url, username, .. } => (
                ProviderChoice::WebDav,
                String::new(),
                url.clone(),
                username.clone().unwrap_or_default(),
            ),
        };

        let (volume_choice, webdav_host, webdav_port, webdav_auth_user, webdav_auth_pass) =
            match &entry.mounting.volume_type {
                VolumeType::Nfs => (
                    VolumeChoice::Nfs,
                    "127.0.0.1".to_owned(),
                    "4919".to_owned(),
                    String::new(),
                    String::new(),
                ),
                VolumeType::WebDav {
                    host,
                    port,
                    auth_user,
                    auth_password,
                } => (
                    VolumeChoice::WebDav,
                    host.clone(),
                    port.to_string(),
                    auth_user.clone().unwrap_or_default(),
                    auth_password.clone().unwrap_or_default(),
                ),
            };

        let (idle_lock_enabled, idle_lock_minutes) = match &entry.idle_lock {
            Some(config) => (true, config.minutes.to_string()),
            None => (false, "30".to_owned()),
        };

        Self {
            vault_id: entry.id,
            open: true,
            tab: SettingsTab::General,
            name: entry.name.clone(),
            idle_lock_enabled,
            idle_lock_minutes,
            provider,
            local_base_path,
            webdav_url,
            webdav_username,
            volume_choice,
            mount_point: entry.mounting.mount_point.clone().unwrap_or_default(),
            webdav_host,
            webdav_port,
            webdav_auth_user,
            webdav_auth_pass,
        }
    }

    /// Apply the settings back to storage.
    pub fn apply(&self, storage: &mut AppStorage) {
        if let Some(entry) = storage.find_vault_mut(self.vault_id) {
            entry.name = self.name.clone();

            entry.idle_lock = if self.idle_lock_enabled {
                Some(IdleLockConfig {
                    minutes: self.idle_lock_minutes.parse().unwrap_or(30),
                })
            } else {
                None
            };

            let provider = match self.provider {
                ProviderChoice::Local => FsProviderConfig::Local {
                    base_path: self.local_base_path.clone(),
                },
                ProviderChoice::WebDav => FsProviderConfig::WebDav {
                    url: self.webdav_url.clone(),
                    username: if self.webdav_username.is_empty() {
                        None
                    } else {
                        Some(self.webdav_username.clone())
                    },
                },
            };
            let (storage_path, vault_file_path) = remap_storage_paths(entry, &provider);
            entry.storage_path = storage_path;
            entry.vault_file_path = vault_file_path;
            entry.provider = provider;

            entry.mounting = MountingConfig {
                volume_type: match self.volume_choice {
                    VolumeChoice::Nfs => VolumeType::Nfs,
                    VolumeChoice::WebDav => {
                        let existing_auth_password = match &entry.mounting.volume_type {
                            VolumeType::WebDav { auth_password, .. } => auth_password.clone(),
                            _ => None,
                        };
                        VolumeType::WebDav {
                            host: self.webdav_host.clone(),
                            port: self.webdav_port.parse().unwrap_or(4919),
                            auth_user: if self.webdav_auth_user.is_empty() {
                                None
                            } else {
                                Some(self.webdav_auth_user.clone())
                            },
                            auth_password: if self.webdav_auth_pass.is_empty() {
                                existing_auth_password
                            } else {
                                Some(self.webdav_auth_pass.clone())
                            },
                        }
                    }
                },
                mount_point: if self.mount_point.is_empty() {
                    None
                } else {
                    Some(self.mount_point.clone())
                },
            };
        }
        storage.save();
    }
}

// ---------------------------------------------------------------------------
// Draw
// ---------------------------------------------------------------------------

pub enum SettingsAction {
    None,
    Saved,
    Cancelled,
}

pub fn draw_settings_window(state: &mut VaultSettingsState, ctx: &egui::Context) -> SettingsAction {
    let mut action = SettingsAction::None;
    let mut is_open = state.open;

    egui::Window::new("Vault Settings")
        .open(&mut is_open)
        .resizable(false)
        .default_width(450.0)
        .show(ctx, |ui| {
            // Tab bar
            ui.horizontal(|ui| {
                ui.selectable_value(&mut state.tab, SettingsTab::General, "General");
                ui.selectable_value(&mut state.tab, SettingsTab::Filesystem, "Filesystem");
                ui.selectable_value(&mut state.tab, SettingsTab::Mounting, "Mounting");
            });
            ui.separator();
            ui.add_space(8.0);

            match state.tab {
                SettingsTab::General => draw_general_tab(state, ui),
                SettingsTab::Filesystem => draw_filesystem_tab(state, ui),
                SettingsTab::Mounting => draw_mounting_tab(state, ui),
            }

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    action = SettingsAction::Cancelled;
                }
                if ui.button(egui::RichText::new("Save").strong()).clicked() {
                    action = SettingsAction::Saved;
                }
            });
        });

    state.open = is_open;

    if !state.open && matches!(action, SettingsAction::None) {
        action = SettingsAction::Cancelled;
    }

    action
}

fn draw_general_tab(state: &mut VaultSettingsState, ui: &mut egui::Ui) {
    labeled_text_field(ui, "Vault name:", &mut state.name, "My Vault");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.checkbox(&mut state.idle_lock_enabled, "Lock when idle for");
        ui.add_enabled(
            state.idle_lock_enabled,
            egui::TextEdit::singleline(&mut state.idle_lock_minutes)
                .desired_width(40.0)
                .hint_text("30"),
        );
        ui.label("minutes");
    });
}

fn draw_filesystem_tab(state: &mut VaultSettingsState, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Provider:");
        ui.selectable_value(&mut state.provider, ProviderChoice::Local, "Local");
        ui.selectable_value(&mut state.provider, ProviderChoice::WebDav, "WebDAV");
    });

    ui.add_space(8.0);

    match state.provider {
        ProviderChoice::Local => {
            ui.horizontal(|ui| {
                ui.label("Location:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.local_base_path)
                        .hint_text("/path/to/vault")
                        .desired_width(280.0),
                );
                // Known limitation: pick_folder() may briefly block the UI on macOS.
                if ui.button("Browse...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Choose vault location")
                        .pick_folder()
                    {
                        state.local_base_path = path.to_string_lossy().to_string();
                    }
                }
            });
        }
        ProviderChoice::WebDav => {
            labeled_text_field(ui, "URL:", &mut state.webdav_url, "https://example.com/dav");
            labeled_text_field(ui, "Username:", &mut state.webdav_username, "");
        }
    }
}

fn draw_mounting_tab(state: &mut VaultSettingsState, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Mount point:");
        ui.add(
            egui::TextEdit::singleline(&mut state.mount_point)
                .hint_text("/Volumes/MyVault")
                .desired_width(280.0),
        );
        // Known limitation: pick_folder() may briefly block the UI on macOS.
        if ui.button("Browse...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Choose mount point")
                .pick_folder()
            {
                state.mount_point = path.to_string_lossy().to_string();
            }
        }
    });

    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Volume type:");
        ui.selectable_value(&mut state.volume_choice, VolumeChoice::Nfs, "NFS");
        ui.selectable_value(&mut state.volume_choice, VolumeChoice::WebDav, "WebDAV");
    });

    if state.volume_choice == VolumeChoice::WebDav {
        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label("WebDAV Server Options");
            ui.add_space(4.0);
            labeled_text_field(ui, "Host:", &mut state.webdav_host, "127.0.0.1");
            labeled_text_field(ui, "Port:", &mut state.webdav_port, "4919");
            ui.add_space(4.0);
            ui.label("Authentication (optional):");
            labeled_text_field(ui, "User:", &mut state.webdav_auth_user, "");
            labeled_password_field(ui, "Password:", &mut state.webdav_auth_pass);
        });
    }
}

fn remap_storage_paths(entry: &VaultEntry, provider: &FsProviderConfig) -> (String, String) {
    let current_root = provider_root(&entry.provider);
    let new_root = provider_root(provider);
    let storage_path = remap_path_prefix(&entry.storage_path, current_root, new_root)
        .unwrap_or_else(|| new_root.to_owned());
    let vault_file_path =
        remap_path_prefix(&entry.vault_file_path, &entry.storage_path, &storage_path)
            .unwrap_or_else(|| {
                format!(
                    "{}/{}",
                    storage_path.trim_end_matches('/'),
                    DEFAULT_VAULT_FILENAME
                )
            });
    (storage_path, vault_file_path)
}

fn provider_root(provider: &FsProviderConfig) -> &str {
    match provider {
        FsProviderConfig::Local { base_path } => base_path,
        FsProviderConfig::WebDav { url, .. } => url,
    }
}

fn remap_path_prefix(path: &str, old_prefix: &str, new_prefix: &str) -> Option<String> {
    let old_trimmed = old_prefix.trim_end_matches('/');
    let new_trimmed = new_prefix.trim_end_matches('/');

    if path == old_prefix || path == old_trimmed {
        return Some(new_trimmed.to_owned());
    }

    let suffix = path
        .strip_prefix(old_prefix)
        .or_else(|| path.strip_prefix(old_trimmed))?;
    let suffix = suffix.trim_start_matches('/');

    if suffix.is_empty() {
        Some(new_trimmed.to_owned())
    } else {
        Some(format!("{new_trimmed}/{suffix}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{provider_root, remap_storage_paths};
    use crate::storage::{FsProviderConfig, MountingConfig, VaultEntry, VolumeType};
    use cryptomator::crypto::DEFAULT_VAULT_FILENAME;
    use uuid::Uuid;

    #[test]
    fn remaps_local_storage_and_vault_paths() {
        let entry = VaultEntry {
            id: Uuid::nil(),
            name: "Vault".into(),
            storage_path: "/old/location/Vault".into(),
            vault_file_path: "/old/location/Vault/masterkey.cryptomator".into(),
            provider: FsProviderConfig::Local {
                base_path: "/old/location/Vault".into(),
            },
            mounting: MountingConfig::default(),
            idle_lock: None,
        };
        let new_provider = FsProviderConfig::Local {
            base_path: "/new/location/Vault".into(),
        };

        let (storage_path, vault_file_path) = remap_storage_paths(&entry, &new_provider);

        assert_eq!(storage_path, "/new/location/Vault");
        assert_eq!(vault_file_path, "/new/location/Vault/masterkey.cryptomator");
    }

    #[test]
    fn remaps_webdav_storage_using_provider_prefix() {
        let entry = VaultEntry {
            id: Uuid::nil(),
            name: "Vault".into(),
            storage_path: "https://old.example/dav/Vault".into(),
            vault_file_path: "https://old.example/dav/Vault/vault.cryptomator".into(),
            provider: FsProviderConfig::WebDav {
                url: "https://old.example/dav".into(),
                username: Some("alice".into()),
            },
            mounting: MountingConfig {
                volume_type: VolumeType::Nfs,
                mount_point: None,
            },
            idle_lock: None,
        };
        let new_provider = FsProviderConfig::WebDav {
            url: "https://new.example/dav".into(),
            username: Some("alice".into()),
        };

        let (storage_path, vault_file_path) = remap_storage_paths(&entry, &new_provider);

        assert_eq!(provider_root(&new_provider), "https://new.example/dav");
        assert_eq!(storage_path, "https://new.example/dav/Vault");
        assert_eq!(
            vault_file_path,
            format!("https://new.example/dav/Vault/{DEFAULT_VAULT_FILENAME}")
        );
    }
}
