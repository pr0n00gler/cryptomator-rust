use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AppStorage {
    pub vaults: Vec<VaultEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultEntry {
    pub id: Uuid,
    pub name: String,
    /// Path to the vault root (parent of `d/`).
    pub storage_path: String,
    /// Path to `vault.cryptomator` (or `masterkey.cryptomator`).
    pub vault_file_path: String,
    pub provider: FsProviderConfig,
    pub mounting: MountingConfig,
    pub idle_lock: Option<IdleLockConfig>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum FsProviderConfig {
    Local {
        base_path: String,
    },
    WebDav {
        url: String,
        username: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MountingConfig {
    pub volume_type: VolumeType,
    pub mount_point: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum VolumeType {
    Nfs,
    WebDav {
        host: String,
        port: u16,
        auth_user: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdleLockConfig {
    pub minutes: u32,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

impl Default for MountingConfig {
    fn default() -> Self {
        Self {
            volume_type: VolumeType::Nfs,
            mount_point: None,
        }
    }
}

impl Default for VolumeType {
    fn default() -> Self {
        Self::Nfs
    }
}

impl Default for IdleLockConfig {
    fn default() -> Self {
        Self { minutes: 30 }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific app data directory
// ---------------------------------------------------------------------------

fn app_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("cryptomator-rust");
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("cryptomator-rust");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("cryptomator-rust");
        }
    }

    // Fallback: current directory
    PathBuf::from(".cryptomator-rust")
}

// ---------------------------------------------------------------------------
// Load / Save
// ---------------------------------------------------------------------------

impl AppStorage {
    fn storage_file() -> PathBuf {
        app_data_dir().join("vaults.json")
    }

    pub fn load() -> Self {
        let path = Self::storage_file();
        match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) {
        let path = Self::storage_file();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                let result = Self::write_file(&path, &json);
                if let Err(e) = result {
                    eprintln!("Failed to save vaults.json: {e}");
                }
            }
            Err(e) => {
                eprintln!("Failed to serialize vault storage: {e}");
            }
        }
    }

    fn write_file(path: &std::path::Path, json: &str) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(json.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, json)?;
        }
        Ok(())
    }

    pub fn add_vault(&mut self, entry: VaultEntry) {
        // Skip adding if a vault with the same vault_file_path already exists.
        if self
            .vaults
            .iter()
            .any(|v| v.vault_file_path == entry.vault_file_path)
        {
            eprintln!(
                "Vault with path '{}' already exists, skipping add.",
                entry.vault_file_path
            );
            return;
        }
        self.vaults.push(entry);
        self.save();
    }

    pub fn remove_vault(&mut self, id: Uuid) {
        self.vaults.retain(|v| v.id != id);
        self.save();
    }

    pub fn find_vault(&self, id: Uuid) -> Option<&VaultEntry> {
        self.vaults.iter().find(|v| v.id == id)
    }

    pub fn find_vault_mut(&mut self, id: Uuid) -> Option<&mut VaultEntry> {
        self.vaults.iter_mut().find(|v| v.id == id)
    }
}
