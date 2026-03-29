use eframe::egui;
use uuid::Uuid;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Modal trait & result
// ---------------------------------------------------------------------------

pub enum ModalResult {
    Open,
    Closed,
}

pub trait Modal {
    fn show(&mut self, ctx: &egui::Context) -> ModalResult;
}

/// Draw the darkening overlay behind a modal.
///
/// The overlay is non-interactable (purely visual) so it does not steal
/// clicks from the modal window drawn on top of it. Background panel
/// actions must be suppressed separately in `app.rs` while a modal is active.
pub fn draw_modal_overlay(ctx: &egui::Context) {
    egui::Area::new(egui::Id::new("modal_overlay"))
        .fixed_pos(egui::pos2(0.0, 0.0))
        .order(egui::Order::Foreground)
        .interactable(false)
        .show(ctx, |ui| {
            let screen = ctx.screen_rect();
            ui.painter()
                .rect_filled(screen, 0.0, egui::Color32::from_black_alpha(128));
        });
}

// ---------------------------------------------------------------------------
// Password Modal
// ---------------------------------------------------------------------------

pub struct PasswordModal {
    pub vault_id: Uuid,
    pub vault_name: String,
    pub password: Zeroizing<String>,
    pub confirmed: bool,
    pub cancelled: bool,
    focus_set: bool,
}

impl PasswordModal {
    pub fn new(vault_id: Uuid, vault_name: String) -> Self {
        Self {
            vault_id,
            vault_name,
            password: Zeroizing::new(String::new()),
            confirmed: false,
            cancelled: false,
            focus_set: false,
        }
    }
}

impl Modal for PasswordModal {
    fn show(&mut self, ctx: &egui::Context) -> ModalResult {
        draw_modal_overlay(ctx);

        let mut open = true;
        egui::Window::new("Unlock Vault")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("\u{1F512} {}", self.vault_name))
                        .size(16.0)
                        .strong(),
                );
                ui.add_space(12.0);

                ui.label("Enter vault password:");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut *self.password)
                        .password(true)
                        .desired_width(300.0),
                );

                if !self.focus_set {
                    response.request_focus();
                    self.focus_set = true;
                }

                // Enter key confirms
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.confirmed = true;
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.cancelled = true;
                    }
                    if ui
                        .button(egui::RichText::new("\u{1F511} Unlock").strong())
                        .clicked()
                    {
                        self.confirmed = true;
                    }
                });
            });

        if !open {
            self.cancelled = true;
        }

        if self.confirmed || self.cancelled {
            ModalResult::Closed
        } else {
            ModalResult::Open
        }
    }
}

// ---------------------------------------------------------------------------
// Success Modal
// ---------------------------------------------------------------------------

pub struct SuccessModal {
    pub message: String,
    pub mount_path: Option<String>,
    pub done: bool,
    pub reveal_requested: bool,
}

impl SuccessModal {
    #[allow(dead_code)]
    pub fn new(message: String, mount_path: Option<String>) -> Self {
        Self {
            message,
            mount_path,
            done: false,
            reveal_requested: false,
        }
    }
}

impl Modal for SuccessModal {
    fn show(&mut self, ctx: &egui::Context) -> ModalResult {
        draw_modal_overlay(ctx);

        let mut open = true;
        egui::Window::new("Success")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("\u{2714}")
                            .size(48.0)
                            .color(egui::Color32::from_rgb(100, 220, 100)),
                    );
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(&self.message).size(16.0));
                });
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if ui.button("Done").clicked() {
                        self.done = true;
                    }
                    if self.mount_path.is_some()
                        && ui
                            .button(egui::RichText::new("\u{1F4BF} Reveal drive"))
                            .clicked()
                    {
                        self.reveal_requested = true;
                        self.done = true;
                    }
                });
            });

        if !open {
            self.done = true;
        }

        if self.done {
            ModalResult::Closed
        } else {
            ModalResult::Open
        }
    }
}

// ---------------------------------------------------------------------------
// Confirm Modal
// ---------------------------------------------------------------------------

pub struct ConfirmModal {
    pub vault_id: Uuid,
    pub title: String,
    pub message: String,
    pub confirmed: bool,
    pub cancelled: bool,
}

impl ConfirmModal {
    pub fn new(vault_id: Uuid, title: String, message: String) -> Self {
        Self {
            vault_id,
            title,
            message,
            confirmed: false,
            cancelled: false,
        }
    }
}

impl Modal for ConfirmModal {
    fn show(&mut self, ctx: &egui::Context) -> ModalResult {
        draw_modal_overlay(ctx);

        let mut open = true;
        egui::Window::new(&self.title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label(&self.message);
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.cancelled = true;
                    }
                    if ui
                        .button(
                            egui::RichText::new("Remove")
                                .color(egui::Color32::from_rgb(255, 100, 100)),
                        )
                        .clicked()
                    {
                        self.confirmed = true;
                    }
                });
            });

        if !open {
            self.cancelled = true;
        }

        if self.confirmed || self.cancelled {
            ModalResult::Closed
        } else {
            ModalResult::Open
        }
    }
}
