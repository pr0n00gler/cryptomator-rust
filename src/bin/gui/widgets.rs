use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use eframe::egui;

use cryptomator::cryptofs::IoStats;

// ---------------------------------------------------------------------------
// Log types
// ---------------------------------------------------------------------------

pub const MAX_LOG_ENTRIES: usize = 1000;

/// Messages sent from background threads back to the UI.
pub enum LogMsg {
    Info(String),
    Error(String),
    #[allow(dead_code)]
    Done(String),
    /// The server is now running (vault unlocked).
    ServerRunning(String),
    /// The server has stopped (vault locked).
    ServerStopped(String),
    /// Carries IoStats from the unlock thread to the GUI.
    Stats(IoStats),
}

#[derive(Clone, Copy, PartialEq)]
pub enum LogLevel {
    Info,
    Error,
    Done,
}

pub struct LogBuffer {
    pub entries: VecDeque<(LogLevel, String)>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    pub fn push(&mut self, level: LogLevel, msg: String) {
        if self.entries.len() >= MAX_LOG_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back((level, msg));
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// BusyGuard -- resets busy flag on drop (panic-safe)
// ---------------------------------------------------------------------------

pub struct BusyGuard(pub Arc<Mutex<bool>>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

pub fn format_bytes_per_sec(bps: f64) -> String {
    if bps >= 1_073_741_824.0 {
        format!("{:.1} GB/s", bps / 1_073_741_824.0)
    } else if bps >= 1_048_576.0 {
        format!("{:.1} MB/s", bps / 1_048_576.0)
    } else if bps >= 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else {
        format!("{bps:.0} B/s")
    }
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// UI widget helpers
// ---------------------------------------------------------------------------

pub fn labeled_text_field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(f32::INFINITY),
        );
    });
}

pub fn labeled_password_field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .password(true)
                .desired_width(f32::INFINITY),
        );
    });
}

/// Draw the log panel contents.
pub fn draw_log_panel(log: &mut LogBuffer, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.heading("Logs");
        if ui.button("Clear").clicked() {
            log.clear();
        }
    });
    ui.separator();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show(ui, |ui| {
            for (level, msg) in &log.entries {
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
