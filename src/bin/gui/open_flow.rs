use std::path::Path;
use std::sync::mpsc;

use uuid::Uuid;

use crate::storage::{FsProviderConfig, MountingConfig, VaultEntry};

/// Result from the file picker background thread.
pub enum OpenResult {
    Picked(Box<VaultEntry>),
    Cancelled,
}

/// Launch a native file picker to select `masterkey.cryptomator`.
/// Returns a receiver that will eventually contain the result.
pub fn open_existing_vault() -> mpsc::Receiver<OpenResult> {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let file = rfd::FileDialog::new()
            .set_title("Select masterkey.cryptomator or vault.cryptomator")
            .add_filter("Cryptomator Vault", &["cryptomator"])
            .pick_file();

        match file {
            Some(path) => {
                let entry = vault_entry_from_path(&path);
                let _ = tx.send(OpenResult::Picked(Box::new(entry)));
            }
            None => {
                let _ = tx.send(OpenResult::Cancelled);
            }
        }
    });

    rx
}

fn path_to_string(p: &Path) -> String {
    p.to_str()
        .map_or_else(|| p.to_string_lossy().into_owned(), str::to_owned)
}

fn vault_entry_from_path(file_path: &Path) -> VaultEntry {
    // The vault root is the parent directory of the selected file.
    let parent = file_path.parent().unwrap_or(file_path);
    let vault_root = path_to_string(parent);

    // Derive a name from the vault root directory name.
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
