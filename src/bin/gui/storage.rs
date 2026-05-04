use serde::{Deserialize, Serialize};
use std::borrow::Cow;
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
    /// Path to `vault.cryptomator`.
    /// Legacy `masterkey.cryptomator` selections are normalized on open.
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
    /// Mount folder used for NFS mounts only.
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
        #[serde(skip, default)]
        auth_password: Option<String>,
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
        if self.insert_vault_if_new(entry) {
            self.save();
        }
    }

    fn insert_vault_if_new(&mut self, entry: VaultEntry) -> bool {
        // Skip adding if a vault with the same provider identity and
        // vault_file_path already exists.
        let duplicate_exists = self
            .vaults
            .iter()
            .any(|v| vault_duplicate_key(v) == vault_duplicate_key(&entry));
        if duplicate_exists {
            eprintln!(
                "Vault with path '{}' already exists, skipping add.",
                entry.vault_file_path
            );
            return false;
        }
        self.vaults.push(entry);
        true
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

#[derive(Debug, PartialEq, Eq)]
enum VaultDuplicateKey<'a> {
    Local {
        vault_file_path: &'a str,
    },
    WebDav {
        url: &'a str,
        username: Option<&'a str>,
        vault_file_path: Cow<'a, str>,
    },
}

fn vault_duplicate_key(entry: &VaultEntry) -> VaultDuplicateKey<'_> {
    match &entry.provider {
        FsProviderConfig::Local { .. } => VaultDuplicateKey::Local {
            vault_file_path: &entry.vault_file_path,
        },
        FsProviderConfig::WebDav { url, username } => VaultDuplicateKey::WebDav {
            url: url.trim_end_matches('/'),
            username: username.as_deref().filter(|value| !value.is_empty()),
            vault_file_path: normalize_webdav_vault_file_path(&entry.vault_file_path, url),
        },
    }
}

fn normalize_webdav_vault_file_path<'a>(vault_file_path: &'a str, url: &str) -> Cow<'a, str> {
    let url = url.trim_end_matches('/');

    if vault_file_path == url {
        return Cow::Borrowed("");
    }

    let normalized = match vault_file_path.strip_prefix(url) {
        Some(suffix) if suffix.starts_with('/') => suffix,
        _ => vault_file_path,
    };

    Cow::Borrowed(normalized.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::{AppStorage, FsProviderConfig, MountingConfig, VaultEntry, VolumeType};
    use uuid::Uuid;

    fn webdav_entry(url: &str, username: Option<&str>) -> VaultEntry {
        VaultEntry {
            id: Uuid::new_v4(),
            name: "Vault".into(),
            storage_path: "Vault".into(),
            vault_file_path: "Vault/vault.cryptomator".into(),
            provider: FsProviderConfig::WebDav {
                url: url.into(),
                username: username.map(str::to_owned),
            },
            mounting: MountingConfig::default(),
            idle_lock: None,
        }
    }

    #[test]
    fn skips_transient_webdav_auth_password_during_serialization() {
        let storage = AppStorage {
            vaults: vec![VaultEntry {
                id: Uuid::nil(),
                name: "Vault".into(),
                storage_path: "Vault".into(),
                vault_file_path: "Vault/vault.cryptomator".into(),
                provider: FsProviderConfig::WebDav {
                    url: "https://example.test/dav".into(),
                    username: Some("alice".into()),
                },
                mounting: MountingConfig {
                    volume_type: VolumeType::WebDav {
                        host: "127.0.0.1".into(),
                        port: 4919,
                        auth_user: Some("bob".into()),
                        auth_password: Some("mount-secret".into()),
                    },
                    mount_point: Some("/tmp/vault".into()),
                },
                idle_lock: None,
            }],
        };

        let json = serde_json::to_string(&storage).unwrap();

        assert!(!json.contains("mount-secret"));

        let decoded: AppStorage = serde_json::from_str(&json).unwrap();
        match &decoded.vaults[0].mounting.volume_type {
            VolumeType::WebDav { auth_password, .. } => assert_eq!(auth_password, &None),
            VolumeType::Nfs => panic!("expected webdav volume"),
        }
    }

    #[test]
    fn inserts_webdav_vaults_with_same_relative_path_on_different_urls() {
        let mut storage = AppStorage::default();

        assert!(
            storage
                .insert_vault_if_new(webdav_entry("https://one.example.test/dav", Some("alice")))
        );
        assert!(
            storage
                .insert_vault_if_new(webdav_entry("https://two.example.test/dav", Some("alice")))
        );

        assert_eq!(storage.vaults.len(), 2);
    }

    #[test]
    fn inserts_webdav_vaults_with_same_relative_path_for_different_users() {
        let mut storage = AppStorage::default();

        assert!(
            storage.insert_vault_if_new(webdav_entry("https://example.test/dav", Some("alice")))
        );
        assert!(storage.insert_vault_if_new(webdav_entry("https://example.test/dav", Some("bob"))));

        assert_eq!(storage.vaults.len(), 2);
    }

    #[test]
    fn skips_webdav_vault_with_same_provider_identity_and_relative_path() {
        let mut storage = AppStorage::default();

        assert!(
            storage.insert_vault_if_new(webdav_entry("https://example.test/dav", Some("alice")))
        );
        assert!(
            !storage.insert_vault_if_new(webdav_entry("https://example.test/dav/", Some("alice")))
        );

        assert_eq!(storage.vaults.len(), 1);
    }

    #[test]
    fn skips_webdav_vault_with_legacy_full_url_path_for_same_provider_identity() {
        let mut storage = AppStorage::default();
        let mut legacy_entry = webdav_entry("https://example.test/dav/", Some("alice"));
        legacy_entry.storage_path = "https://example.test/dav/Vault".into();
        legacy_entry.vault_file_path = "https://example.test/dav/Vault/vault.cryptomator".into();

        assert!(storage.insert_vault_if_new(legacy_entry));
        assert!(
            !storage.insert_vault_if_new(webdav_entry("https://example.test/dav", Some("alice")))
        );

        assert_eq!(storage.vaults.len(), 1);
    }

    #[test]
    fn skips_webdav_root_vault_with_legacy_full_url_path_for_same_provider_identity() {
        let mut storage = AppStorage::default();
        let mut legacy_entry = webdav_entry("https://example.test/dav/", Some("alice"));
        legacy_entry.storage_path = "https://example.test/dav".into();
        legacy_entry.vault_file_path = "https://example.test/dav/vault.cryptomator".into();
        let mut root_entry = webdav_entry("https://example.test/dav", Some("alice"));
        root_entry.storage_path = "".into();
        root_entry.vault_file_path = "/vault.cryptomator".into();

        assert!(storage.insert_vault_if_new(legacy_entry));
        assert!(!storage.insert_vault_if_new(root_entry));

        assert_eq!(storage.vaults.len(), 1);
    }
}
