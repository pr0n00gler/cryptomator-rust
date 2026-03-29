use std::path::Path;

use eframe::egui;
use uuid::Uuid;

use cryptomator::crypto::DEFAULT_VAULT_FILENAME;

use crate::modals::{Modal, ModalResult, draw_modal_overlay};
use crate::storage::{FsProviderConfig, MountingConfig, VaultEntry};
use crate::widgets::labeled_text_field;

// ---------------------------------------------------------------------------
// Provider choice
// ---------------------------------------------------------------------------

#[derive(PartialEq)]
enum ProviderChoice {
    Local,
    WebDav,
}

// ---------------------------------------------------------------------------
// Open Vault Modal
// ---------------------------------------------------------------------------

pub struct OpenVaultModal {
    provider: ProviderChoice,
    local_file_path: String,
    webdav_url: String,
    webdav_vault_path: String,
    webdav_username: String,
    pub opened_entry: Option<VaultEntry>,
    pub closed: bool,
    error_msg: Option<String>,
}

impl OpenVaultModal {
    pub fn new() -> Self {
        Self {
            provider: ProviderChoice::Local,
            local_file_path: String::new(),
            webdav_url: String::new(),
            webdav_vault_path: String::new(),
            webdav_username: String::new(),
            opened_entry: None,
            closed: false,
            error_msg: None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        match self.provider {
            ProviderChoice::Local => {
                if self.local_file_path.trim().is_empty() {
                    return Err("Please select a vault file.".into());
                }
                let path = Path::new(self.local_file_path.trim());
                if !path.exists() {
                    return Err("File does not exist.".into());
                }
                if path.extension().and_then(|e| e.to_str()) != Some("cryptomator") {
                    return Err("File must have a .cryptomator extension.".into());
                }
            }
            ProviderChoice::WebDav => {
                let url = self.webdav_url.trim();
                if url.is_empty() {
                    return Err("WebDAV URL is required.".into());
                }
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    return Err("WebDAV URL must start with http:// or https://.".into());
                }
            }
        }
        Ok(())
    }

    fn build_entry(&self) -> VaultEntry {
        match self.provider {
            ProviderChoice::Local => vault_entry_from_path(Path::new(&self.local_file_path)),
            ProviderChoice::WebDav => {
                let base_url = self.webdav_url.trim().trim_end_matches('/');
                let vault_path = self
                    .webdav_vault_path
                    .trim()
                    .trim_start_matches('/')
                    .trim_end_matches('/');

                let storage_path = if vault_path.is_empty() {
                    base_url.to_owned()
                } else {
                    format!("{base_url}/{vault_path}")
                };
                let vault_file_path = format!("{storage_path}/{DEFAULT_VAULT_FILENAME}");

                let name = vault_path
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("Vault")
                    .to_owned();

                let username = if self.webdav_username.trim().is_empty() {
                    None
                } else {
                    Some(self.webdav_username.trim().to_owned())
                };

                VaultEntry {
                    id: Uuid::new_v4(),
                    name,
                    storage_path,
                    vault_file_path,
                    provider: FsProviderConfig::WebDav {
                        url: base_url.to_owned(),
                        username,
                    },
                    mounting: MountingConfig::default(),
                    idle_lock: None,
                }
            }
        }
    }

    fn draw_form(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.label("Location:");
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.provider, ProviderChoice::Local, "Local");
            ui.selectable_value(&mut self.provider, ProviderChoice::WebDav, "WebDAV");
        });

        ui.add_space(4.0);
        match self.provider {
            ProviderChoice::Local => {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.local_file_path)
                            .hint_text("masterkey.cryptomator")
                            .desired_width(300.0),
                    );
                    if ui.button("Browse...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Select masterkey.cryptomator or vault.cryptomator")
                            .add_filter("Cryptomator Vault", &["cryptomator"])
                            .pick_file()
                        {
                            self.local_file_path = path_to_string(&path);
                        }
                    }
                });
            }
            ProviderChoice::WebDav => {
                labeled_text_field(ui, "URL:", &mut self.webdav_url, "https://example.com/dav");
                labeled_text_field(
                    ui,
                    "Vault path:",
                    &mut self.webdav_vault_path,
                    "/path/to/MyVault",
                );
                labeled_text_field(ui, "Username:", &mut self.webdav_username, "");
            }
        }

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() {
                self.closed = true;
            }
            if ui
                .button(egui::RichText::new("Open Vault").strong())
                .clicked()
            {
                match self.validate() {
                    Ok(()) => {
                        self.error_msg = None;
                        self.opened_entry = Some(self.build_entry());
                        self.closed = true;
                    }
                    Err(e) => self.error_msg = Some(e),
                }
            }
        });

        if let Some(err) = &self.error_msg {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(err).color(egui::Color32::from_rgb(255, 100, 100)));
        }
    }
}

impl Modal for OpenVaultModal {
    fn show(&mut self, ctx: &egui::Context) -> ModalResult {
        draw_modal_overlay(ctx);

        let mut open = true;
        egui::Window::new("Open Existing Vault")
            .collapsible(false)
            .resizable(false)
            .default_width(420.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                self.draw_form(ui);
            });

        if !open {
            self.closed = true;
        }

        if self.closed {
            ModalResult::Closed
        } else {
            ModalResult::Open
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn path_to_string(p: &Path) -> String {
    p.to_str()
        .map_or_else(|| p.to_string_lossy().into_owned(), str::to_owned)
}

fn vault_entry_from_path(file_path: &Path) -> VaultEntry {
    let parent = file_path.parent().unwrap_or(file_path);
    let vault_root = path_to_string(parent);

    let name = parent
        .file_name()
        .map(|n| {
            n.to_str()
                .map_or_else(|| n.to_string_lossy().into_owned(), str::to_owned)
        })
        .unwrap_or_else(|| "Vault".to_string());

    VaultEntry {
        id: Uuid::new_v4(),
        name,
        storage_path: vault_root.clone(),
        vault_file_path: path_to_string(file_path),
        provider: FsProviderConfig::Local {
            base_path: vault_root,
        },
        mounting: MountingConfig::default(),
        idle_lock: None,
    }
}
