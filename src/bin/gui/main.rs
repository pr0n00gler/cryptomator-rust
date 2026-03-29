#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod create_flow;
mod modals;
mod open_flow;
mod settings_window;
mod sidebar;
mod storage;
mod vault_runtime;
mod vault_view;
mod widgets;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([820.0, 600.0])
            .with_min_inner_size([620.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Cryptomator",
        options,
        Box::new(|cc| Ok(Box::new(app::CryptomatorApp::new(cc)))),
    )
}
