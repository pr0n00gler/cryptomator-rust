use std::path::Path;
use std::sync::mpsc;

use eframe::egui;
use uuid::Uuid;
use zeroize::Zeroizing;

use cryptomator::crypto::DEFAULT_VAULT_FILENAME;
use cryptomator::operations::{DEFAULT_STORAGE_SUB_FOLDER, create_vault};
use cryptomator::providers::{LocalFs, WebDavFs};

use crate::modals::{Modal, ModalResult, draw_modal_overlay};
use crate::storage::{FsProviderConfig, MountingConfig, VaultEntry};
use crate::widgets::{labeled_password_field, labeled_text_field};

const DEFAULT_SCRYPT_COST: u64 = 16384;
const DEFAULT_SCRYPT_BLOCK_SIZE: u32 = 8;

// ---------------------------------------------------------------------------
// Create result sent back from background thread
// ---------------------------------------------------------------------------

pub enum CreateResult {
    Success,
    Error(String),
}

// ---------------------------------------------------------------------------
// Create Vault Modal
// ---------------------------------------------------------------------------

#[derive(PartialEq)]
enum ProviderChoice {
    Local,
    WebDav,
}

enum CreateStep {
    Form,
    Creating,
    Done,
    Failed(String),
}

pub struct CreateVaultModal {
    step: CreateStep,
    vault_name: String,
    local_path: String,
    provider: ProviderChoice,
    webdav_url: String,
    webdav_user: String,
    webdav_pass: Zeroizing<String>,
    password: Zeroizing<String>,
    password_confirm: Zeroizing<String>,
    result_rx: Option<mpsc::Receiver<CreateResult>>,
    pub created_entry: Option<VaultEntry>,
    /// Entry awaiting confirmation from the background thread before being promoted
    /// to `created_entry`.
    pending_entry: Option<VaultEntry>,
    pub closed: bool,
}

impl CreateVaultModal {
    pub fn new() -> Self {
        Self {
            step: CreateStep::Form,
            vault_name: String::new(),
            local_path: String::new(),
            provider: ProviderChoice::Local,
            webdav_url: String::new(),
            webdav_user: String::new(),
            webdav_pass: Zeroizing::new(String::new()),
            password: Zeroizing::new(String::new()),
            password_confirm: Zeroizing::new(String::new()),
            result_rx: None,
            created_entry: None,
            pending_entry: None,
            closed: false,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.vault_name.trim().is_empty() {
            return Err("Vault name is required.".into());
        }
        match self.provider {
            ProviderChoice::Local => {
                if self.local_path.trim().is_empty() {
                    return Err("Local path is required.".into());
                }
            }
            ProviderChoice::WebDav => {
                if self.webdav_url.trim().is_empty() {
                    return Err("WebDAV URL is required.".into());
                }
            }
        }
        if self.password.is_empty() {
            return Err("Password is required.".into());
        }
        if *self.password != *self.password_confirm {
            return Err("Passwords do not match.".into());
        }
        Ok(())
    }

    fn start_create(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.result_rx = Some(rx);
        self.step = CreateStep::Creating;

        let vault_name = self.vault_name.trim().to_owned();
        let password = Zeroizing::new(String::from(&**self.password));

        let (storage_path, provider_config) = match self.provider {
            ProviderChoice::Local => {
                let base = self.local_path.trim().to_owned();
                let storage_path = Path::new(&base)
                    .join(&vault_name)
                    .to_string_lossy()
                    .to_string();
                let config = FsProviderConfig::Local {
                    base_path: storage_path.clone(),
                };
                (storage_path, config)
            }
            ProviderChoice::WebDav => {
                let url = self.webdav_url.trim().to_owned();
                let user = if self.webdav_user.is_empty() {
                    None
                } else {
                    Some(self.webdav_user.clone())
                };
                let storage_path = format!("{}/{}", url.trim_end_matches('/'), vault_name);
                let config = FsProviderConfig::WebDav {
                    url: url.clone(),
                    username: user,
                };
                (storage_path, config)
            }
        };

        let vault_path = Path::new(&storage_path).join(DEFAULT_VAULT_FILENAME);
        let full_storage_path = Path::new(&storage_path).join(DEFAULT_STORAGE_SUB_FOLDER);

        let id = Uuid::new_v4();
        let entry = VaultEntry {
            id,
            name: vault_name,
            storage_path: storage_path.clone(),
            vault_file_path: vault_path
                .to_str()
                .map_or_else(|| vault_path.to_string_lossy().into_owned(), str::to_owned),
            provider: provider_config,
            mounting: MountingConfig::default(),
            idle_lock: None,
        };
        let entry_clone = entry.clone();

        let webdav_url = self.webdav_url.clone();
        let webdav_user = self.webdav_user.clone();
        let webdav_pass = Zeroizing::new(String::from(&**self.webdav_pass));
        let provider = if self.provider == ProviderChoice::Local {
            ProviderChoice::Local
        } else {
            ProviderChoice::WebDav
        };

        std::thread::spawn(move || {
            let result = match provider {
                ProviderChoice::Local => {
                    // Create the storage directory first
                    let _ = std::fs::create_dir_all(&storage_path);
                    create_vault(
                        LocalFs::new(),
                        &vault_path,
                        &full_storage_path,
                        password.as_str(),
                        DEFAULT_SCRYPT_COST,
                        DEFAULT_SCRYPT_BLOCK_SIZE,
                    )
                }
                ProviderChoice::WebDav => {
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
                        DEFAULT_SCRYPT_COST,
                        DEFAULT_SCRYPT_BLOCK_SIZE,
                    )
                }
            };

            match result {
                Ok(()) => {
                    let _ = tx.send(CreateResult::Success);
                }
                Err(e) => {
                    let _ = tx.send(CreateResult::Error(format!("{e:#}")));
                }
            }
        });

        self.pending_entry = Some(entry_clone);
    }
}

impl Modal for CreateVaultModal {
    fn show(&mut self, ctx: &egui::Context) -> ModalResult {
        // Check for background result
        if let Some(ref rx) = self.result_rx {
            if let Ok(result) = rx.try_recv() {
                match result {
                    CreateResult::Success => {
                        self.step = CreateStep::Done;
                        self.created_entry = self.pending_entry.take();
                    }
                    CreateResult::Error(e) => {
                        self.step = CreateStep::Failed(e);
                        self.pending_entry = None;
                    }
                }
                self.result_rx = None;
            }
        }

        draw_modal_overlay(ctx);

        let mut open = true;
        egui::Window::new("Create New Vault")
            .collapsible(false)
            .resizable(false)
            .default_width(420.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| match &self.step {
                CreateStep::Form => {
                    self.draw_form(ui);
                }
                CreateStep::Creating => {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.spinner();
                        ui.add_space(8.0);
                        ui.label("Creating vault...");
                    });
                    ui.add_space(20.0);
                    ctx.request_repaint();
                }
                CreateStep::Done => {
                    ui.add_space(12.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("\u{2714}")
                                .size(48.0)
                                .color(egui::Color32::from_rgb(100, 220, 100)),
                        );
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Vault created successfully!").size(16.0));
                        ui.add_space(8.0);
                        ui.label("You can now unlock it from the sidebar.");
                    });
                    ui.add_space(16.0);
                    ui.vertical_centered(|ui| {
                        if ui.button("Done").clicked() {
                            self.closed = true;
                        }
                    });
                }
                CreateStep::Failed(err) => {
                    ui.add_space(12.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("\u{2716}")
                                .size(48.0)
                                .color(egui::Color32::from_rgb(255, 100, 100)),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("Failed to create vault")
                                .size(16.0)
                                .color(egui::Color32::from_rgb(255, 100, 100)),
                        );
                        ui.add_space(4.0);
                        ui.label(err.as_str());
                    });
                    ui.add_space(16.0);
                    ui.vertical_centered(|ui| {
                        if ui.button("Close").clicked() {
                            self.closed = true;
                            self.pending_entry = None;
                        }
                    });
                }
            });

        if !open {
            self.closed = true;
            if !matches!(self.step, CreateStep::Done) {
                self.pending_entry = None;
            }
        }

        if self.closed {
            ModalResult::Closed
        } else {
            ModalResult::Open
        }
    }
}

impl CreateVaultModal {
    fn draw_form(&mut self, ui: &mut egui::Ui) {
        let mut error_msg: Option<String> = None;

        ui.add_space(8.0);
        labeled_text_field(ui, "Vault name:", &mut self.vault_name, "My Vault");

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
                        egui::TextEdit::singleline(&mut self.local_path)
                            .hint_text("/path/to/vaults")
                            .desired_width(300.0),
                    );
                    if ui.button("Browse...").clicked() {
                        // Known limitation: pick_folder() may briefly block the UI on macOS.
                        // Refactoring to a background thread would significantly complicate
                        // the modal flow for minimal benefit.
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Choose vault location")
                            .pick_folder()
                        {
                            self.local_path = path.to_string_lossy().to_string();
                        }
                    }
                });
            }
            ProviderChoice::WebDav => {
                labeled_text_field(ui, "URL:", &mut self.webdav_url, "https://example.com/dav");
                labeled_text_field(ui, "Username:", &mut self.webdav_user, "");
                labeled_password_field(ui, "Password:", &mut self.webdav_pass);
            }
        }

        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label("Vault Password");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.password)
                        .password(true)
                        .desired_width(250.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Confirm:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.password_confirm)
                        .password(true)
                        .desired_width(250.0),
                );
            });
        });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() {
                self.closed = true;
            }
            if ui
                .button(egui::RichText::new("Create Vault").strong())
                .clicked()
            {
                match self.validate() {
                    Ok(()) => self.start_create(),
                    Err(e) => error_msg = Some(e),
                }
            }
        });

        if let Some(err) = error_msg {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(err).color(egui::Color32::from_rgb(255, 100, 100)));
        }
    }
}
