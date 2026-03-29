use eframe::egui;
use uuid::Uuid;

use crate::app::CryptomatorApp;
use crate::vault_runtime::VaultStatus;
use crate::widgets::{format_bytes, format_bytes_per_sec};

// ---------------------------------------------------------------------------
// Actions from the vault view
// ---------------------------------------------------------------------------

pub enum VaultViewAction {
    None,
    Unlock(Uuid),
    Lock(Uuid),
    RevealDrive(String),
}

// ---------------------------------------------------------------------------
// Draw main vault view
// ---------------------------------------------------------------------------

pub fn draw_vault_view(app: &CryptomatorApp, ctx: &egui::Context) -> VaultViewAction {
    let mut action = VaultViewAction::None;

    egui::CentralPanel::default().show(ctx, |ui| {
        let Some(vault_id) = app.selected_vault_id else {
            // No vault selected -- show empty state
            draw_empty_state(ui);
            return;
        };

        let Some(entry) = app.storage.find_vault(vault_id) else {
            draw_empty_state(ui);
            return;
        };

        let runtime = app.vault_runtimes.get(&vault_id);
        let status = runtime.map(|r| r.status).unwrap_or(VaultStatus::Locked);
        let busy = runtime.map(|r| r.is_busy()).unwrap_or(false);

        ui.add_space(24.0);

        // Header
        ui.vertical_centered(|ui| {
            ui.heading(egui::RichText::new(&entry.name).size(28.0).strong());
            ui.add_space(4.0);

            let location = match &entry.provider {
                crate::storage::FsProviderConfig::Local { base_path } => base_path.clone(),
                crate::storage::FsProviderConfig::WebDav { url, .. } => url.clone(),
            };
            ui.label(
                egui::RichText::new(&location)
                    .size(13.0)
                    .color(egui::Color32::from_rgb(160, 160, 160)),
            );

            ui.add_space(8.0);

            // Status badge
            let (status_text, status_color) = match status {
                VaultStatus::Locked => ("\u{1F512} Locked", egui::Color32::from_rgb(255, 100, 100)),
                VaultStatus::Unlocked => {
                    ("\u{1F513} Unlocked", egui::Color32::from_rgb(100, 220, 100))
                }
                VaultStatus::Unlocking => (
                    "\u{23F3} Unlocking...",
                    egui::Color32::from_rgb(255, 200, 100),
                ),
                VaultStatus::Locking => (
                    "\u{23F3} Locking...",
                    egui::Color32::from_rgb(255, 200, 100),
                ),
            };
            ui.label(
                egui::RichText::new(status_text)
                    .size(16.0)
                    .color(status_color),
            );

            ui.add_space(24.0);

            // Main action button
            match status {
                VaultStatus::Locked => {
                    ui.add_enabled_ui(!busy, |ui| {
                        if ui
                            .button(
                                egui::RichText::new("  \u{1F511}  Unlock  ")
                                    .size(22.0)
                                    .strong(),
                            )
                            .clicked()
                        {
                            action = VaultViewAction::Unlock(vault_id);
                        }
                    });
                }
                VaultStatus::Unlocked => {
                    ui.add_enabled_ui(!busy, |ui| {
                        if ui
                            .button(
                                egui::RichText::new("  \u{1F512}  Lock  ")
                                    .size(22.0)
                                    .strong()
                                    .color(egui::Color32::from_rgb(255, 100, 100)),
                            )
                            .clicked()
                        {
                            action = VaultViewAction::Lock(vault_id);
                        }
                    });

                    ui.add_space(12.0);

                    // Reveal drive button
                    if let Some(rt) = runtime {
                        if let Some(ref mount_path) = rt.active_mount_folder {
                            if ui
                                .button(egui::RichText::new("\u{1F4BF} Reveal drive").size(14.0))
                                .clicked()
                            {
                                action = VaultViewAction::RevealDrive(mount_path.clone());
                            }
                        }
                    }
                }
                VaultStatus::Unlocking | VaultStatus::Locking => {
                    ui.spinner();
                }
            }
        });

        // Vault Statistics pinned to the bottom
        if let Some(rt) = runtime {
            if rt.io_stats.is_some() {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    draw_stats_section(ui, rt);
                });
            }
        }
    });

    action
}

fn draw_empty_state(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() / 3.0);
        ui.label(
            egui::RichText::new("\u{1F512}")
                .size(64.0)
                .color(egui::Color32::from_rgb(100, 100, 100)),
        );
        ui.add_space(12.0);
        ui.label(
            egui::RichText::new("Cryptomator")
                .size(24.0)
                .color(egui::Color32::from_rgb(140, 140, 140)),
        );
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Select a vault or create a new one")
                .size(14.0)
                .color(egui::Color32::from_rgb(120, 120, 120)),
        );
    });
}

fn draw_stats_section(ui: &mut egui::Ui, rt: &crate::vault_runtime::VaultRuntime) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Vault Statistics").strong());
        ui.add_space(4.0);

        if let Some(ref stats) = rt.io_stats {
            let total_read = stats.bytes_read();
            let total_written = stats.bytes_written();

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 16.0;
                ui.label(
                    egui::RichText::new(format!(
                        "\u{2B07} Read: {} ({})",
                        format_bytes_per_sec(rt.read_throughput),
                        format_bytes(total_read),
                    ))
                    .color(egui::Color32::from_rgb(100, 180, 255))
                    .monospace(),
                );
                ui.label(
                    egui::RichText::new(format!(
                        "\u{2B06} Write: {} ({})",
                        format_bytes_per_sec(rt.write_throughput),
                        format_bytes(total_written),
                    ))
                    .color(egui::Color32::from_rgb(255, 180, 100))
                    .monospace(),
                );
            });
        }
    });
}
