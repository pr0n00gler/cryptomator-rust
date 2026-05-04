use eframe::egui;
use uuid::Uuid;

use crate::app::CryptomatorApp;
use crate::vault_runtime::VaultStatus;

// ---------------------------------------------------------------------------
// Sidebar actions communicated back to app
// ---------------------------------------------------------------------------

pub enum SidebarAction {
    None,
    SelectVault(Uuid),
    CreateNewVault,
    OpenExistingVault,
    RemoveVault(Uuid),
    OpenSettings(Uuid),
}

// ---------------------------------------------------------------------------
// Draw sidebar
// ---------------------------------------------------------------------------

pub fn draw_sidebar(app: &CryptomatorApp, ctx: &egui::Context) -> SidebarAction {
    let mut action = SidebarAction::None;

    egui::SidePanel::left("vault_sidebar")
        .resizable(false)
        .exact_width(200.0)
        .show(ctx, |ui| {
            ui.add_space(12.0);
            ui.heading("Cryptomator");
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            // Vault list
            let available = ui.available_height() - 50.0; // reserve space for + button
            egui::ScrollArea::vertical()
                .max_height(available.max(100.0))
                .show(ui, |ui| {
                    for vault in &app.storage.vaults {
                        let is_selected = app.selected_vault_id == Some(vault.id);

                        let status = app
                            .vault_runtimes
                            .get(&vault.id)
                            .map(|r| r.status)
                            .unwrap_or(VaultStatus::Locked);

                        let status_icon = match status {
                            VaultStatus::Locked => "\u{1F512}",
                            VaultStatus::Unlocked => "\u{1F513}",
                            VaultStatus::Unlocking | VaultStatus::Locking => "\u{23F3}",
                        };

                        let label = format!("{status_icon} {}", vault.name);
                        let full_width = ui.available_width();
                        let response = ui.add_sized(
                            [full_width, 0.0],
                            egui::SelectableLabel::new(is_selected, &label),
                        );

                        if response.clicked() {
                            action = SidebarAction::SelectVault(vault.id);
                        }

                        // Right-click context menu
                        response.context_menu(|ui| {
                            if ui.button("\u{2699} Settings").clicked() {
                                action = SidebarAction::OpenSettings(vault.id);
                                ui.close_menu();
                            }
                            if ui
                                .button(
                                    egui::RichText::new("\u{2716} Remove vault")
                                        .color(egui::Color32::from_rgb(255, 100, 100)),
                                )
                                .clicked()
                            {
                                action = SidebarAction::RemoveVault(vault.id);
                                ui.close_menu();
                            }
                        });
                    }

                    if app.storage.vaults.is_empty() {
                        ui.label(
                            egui::RichText::new("No vaults yet.\nClick + to add one.")
                                .color(egui::Color32::from_rgb(140, 140, 140)),
                        );
                    }
                });

            // + button at bottom
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                let btn = ui.button(egui::RichText::new("+ Add Vault").strong());
                let popup_id = ui.make_persistent_id("add_vault_popup");
                if btn.clicked() {
                    ui.memory_mut(|m| m.toggle_popup(popup_id));
                }
                egui::popup_below_widget(
                    ui,
                    popup_id,
                    &btn,
                    egui::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(160.0);
                        if ui.button("\u{2795} Create new vault").clicked() {
                            action = SidebarAction::CreateNewVault;
                        }
                        if ui.button("\u{1F4C2} Open existing vault").clicked() {
                            action = SidebarAction::OpenExistingVault;
                        }
                    },
                );
            });
        });

    action
}
