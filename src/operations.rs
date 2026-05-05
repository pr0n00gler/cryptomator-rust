use crate::crypto::{
    CipherCombo, DEFAULT_FORMAT, DEFAULT_MASTER_KEY_FILE, DEFAULT_SHORTENING_THRESHOLD, MasterKey,
    MasterKeyJson, Vault,
};
use crate::cryptofs::{FileSystem, OpenOptions, parent_path};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};
use std::path::Path;
use tracing::info;
use zeroize::Zeroizing;

pub const DEFAULT_STORAGE_SUB_FOLDER: &str = "d";

fn temp_sibling(path: &Path, id: uuid::Uuid) -> std::path::PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cryptomator");
    path.with_file_name(format!("{file_name}.tmp-{id}"))
}

pub fn create_vault<FS, P>(
    fs: FS,
    vault_path: P,
    full_storage_path: P,
    password: &str,
    scrypt_cost: u64,
    scrypt_block_size: u32,
) -> Result<()>
where
    FS: FileSystem + 'static,
    P: AsRef<Path>,
{
    info!("Generating master key...");
    let mk_json = MasterKeyJson::create(password, scrypt_cost, scrypt_block_size)
        .context("failed to generate master key file")?;
    info!("Master key generated!");

    info!("Saving master key to a file...");
    let masterkey_path = parent_path(&vault_path).join(DEFAULT_MASTER_KEY_FILE);
    let mut mk_file = fs
        .clone()
        .create_file(masterkey_path)
        .map_err(|e| anyhow!("failed to create masterkey file: {e}"))?;
    serde_json::to_writer(&mut mk_file, &mk_json).context("failed to write master key file")?;
    mk_file.fsync().context("failed to fsync masterkey file")?;
    info!("Master key saved!");

    let masterkey =
        MasterKey::from_masterkey_json(mk_json, password).context("failed to decrypt masterkey")?;
    let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    key.extend_from_slice(masterkey.primary_master_key.as_ref());
    key.extend_from_slice(masterkey.hmac_master_key.as_ref());

    let vault = Vault::create_vault(
        &key,
        DEFAULT_FORMAT,
        CipherCombo::SIV_CTRMAC,
        DEFAULT_SHORTENING_THRESHOLD,
    )
    .context("failed to create vault")?;

    info!("Writing vault file...");
    let mut vault_file = fs
        .clone()
        .create_file(&vault_path)
        .map_err(|e| anyhow!("failed to create vault file: {e}"))?;
    vault_file
        .write_all(vault.as_bytes())
        .context("failed to write data to vault file")?;
    vault_file.fsync().context("failed to fsync vault file")?;

    fs.create_dir(&full_storage_path)
        .map_err(|e| anyhow!("failed to create storage directory: {e}"))?;
    info!("Vault created!");

    Ok(())
}

pub fn migrate_v7_to_v8<FS, P>(fs: FS, vault_path: P, password: &str) -> Result<()>
where
    FS: FileSystem + 'static,
    P: AsRef<Path>,
{
    info!("Reading old masterkey file...");
    let masterkey_path = parent_path(&vault_path).join(DEFAULT_MASTER_KEY_FILE);
    let mut mk_file = fs
        .clone()
        .open_file(&masterkey_path, OpenOptions::new())
        .map_err(|e| anyhow!("failed to open masterkey file: {e}"))?;

    // Deserialize into a local binding that is consumed (not cloned) below.
    // Cloning MasterKeyJson would leave a second copy of the base64-encoded
    // wrapped key material on the heap with no zeroize semantics — a full
    // vault-compromise vector if the process is inspected via crash dump or
    // memory scan.
    let mut mk_bytes = Zeroizing::new(Vec::new());
    mk_file
        .read_to_end(&mut mk_bytes)
        .context("failed to read masterkey file")?;
    let mk_json: MasterKeyJson =
        serde_json::from_slice(&mk_bytes).context("failed to parse masterkey file")?;

    // Snapshot the non-sensitive fields we need to reconstruct the masterkey
    // file BEFORE consuming mk_json.  These are all public, non-secret values.
    let scrypt_salt = mk_json.scryptSalt.clone();
    let scrypt_cost_param = mk_json.scryptCostParam;
    let scrypt_block_size = mk_json.scryptBlockSize;
    let primary_master_key_enc = mk_json.primaryMasterKey.clone();
    let hmac_master_key_enc = mk_json.hmacMasterKey.clone();

    // Consume mk_json — no clone.  The base64-encoded wrapped keys inside it
    // are moved into from_masterkey_json and dropped at the end of that call.
    let masterkey = MasterKey::from_masterkey_json(mk_json, password)
        .context("failed to decrypt master key file")?;

    let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    key.extend_from_slice(masterkey.primary_master_key.as_ref());
    key.extend_from_slice(masterkey.hmac_master_key.as_ref());

    info!("Creating new vault definition...");
    let vault = Vault::create_vault(
        &key,
        DEFAULT_FORMAT,
        CipherCombo::SIV_CTRMAC,
        DEFAULT_SHORTENING_THRESHOLD,
    )
    .context("failed to create vault")?;

    // Recompute the versionMac over the new version number (999) using the
    // unwrapped HMAC master key.  We rebuild MasterKeyJson from scratch rather
    // than mutating a leftover clone, so there is never a second live copy of
    // the wrapped key material.
    let new_version: u32 = 999;
    let mut version_mac: Hmac<Sha256> = Hmac::new_from_slice(masterkey.hmac_master_key.as_ref())
        .context("failed to create HMAC")?;
    version_mac.update(&new_version.to_be_bytes());
    let version_mac_bytes = version_mac.finalize().into_bytes();

    let updated_mk_json = MasterKeyJson {
        version: new_version,
        scryptSalt: scrypt_salt,
        scryptCostParam: scrypt_cost_param,
        scryptBlockSize: scrypt_block_size,
        primaryMasterKey: primary_master_key_enc,
        hmacMasterKey: hmac_master_key_enc,
        versionMac: STANDARD.encode(version_mac_bytes),
    };

    let migration_id = uuid::Uuid::new_v4();
    let tmp_masterkey_path = temp_sibling(&masterkey_path, migration_id);
    let vault_target_path = vault_path.as_ref().to_path_buf();
    let tmp_vault_path = temp_sibling(&vault_target_path, migration_id);

    info!("Writing temporary masterkey file...");
    let mut mk_file = fs
        .clone()
        .create_file(&tmp_masterkey_path)
        .map_err(|e| anyhow!("failed to create temporary masterkey file: {e}"))?;
    serde_json::to_writer(&mut mk_file, &updated_mk_json)
        .context("failed to write temporary masterkey file")?;
    mk_file
        .fsync()
        .context("failed to fsync temporary masterkey file")?;
    drop(mk_file);

    info!("Writing temporary vault file...");
    let mut vault_file = fs
        .clone()
        .create_file(&tmp_vault_path)
        .map_err(|e| anyhow!("failed to create temporary vault file: {e}"))?;
    vault_file
        .write_all(vault.as_bytes())
        .context("failed to write temporary vault file")?;
    vault_file
        .fsync()
        .context("failed to fsync temporary vault file")?;
    drop(vault_file);

    info!("Replacing vault file...");
    fs.clone()
        .move_file(&tmp_vault_path, &vault_target_path)
        .map_err(|e| anyhow!("failed to replace vault file: {e}"))?;

    info!("Replacing masterkey file...");
    fs.move_file(&tmp_masterkey_path, &masterkey_path)
        .map_err(|e| anyhow!("failed to replace masterkey file: {e}"))?;
    info!("Vault migrated!");

    Ok(())
}
