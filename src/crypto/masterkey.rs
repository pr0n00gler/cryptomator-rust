use std::fmt;

use serde::{Deserialize, Serialize};

use crate::crypto::error::MasterKeyError;

use rand::Rng;

use base64::{Engine as _, engine::r#general_purpose::STANDARD};
use hmac::digest::r#generic_array::GenericArray;
use hmac::{Hmac, Mac};
use scrypt::Params;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const P: u32 = 1;
const DEFAULT_IV: [u8; 8] = [0xA6; 8];

const FAKE_VAULT_VERSION: u32 = 999;

pub const DEFAULT_MASTER_KEY_FILE: &str = "masterkey.cryptomator";

// `Clone` is intentionally absent: cloning this struct would create a second
// heap copy of `primaryMasterKey` and `hmacMasterKey` (base64-encoded wrapped
// key material) with no zeroize semantics, constituting an untracked secret.
#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct MasterKeyJson {
    pub version: u32,
    pub scryptSalt: String,
    pub scryptCostParam: u64,
    pub scryptBlockSize: u32,
    pub primaryMasterKey: String,
    pub hmacMasterKey: String,
    pub versionMac: String,
}

impl MasterKeyJson {
    pub fn create(
        password: &str,
        scrypt_cost_param: u64,
        scrypt_block_size: u32,
    ) -> Result<MasterKeyJson, MasterKeyError> {
        // All intermediate key buffers are wrapped in Zeroizing so they are
        // wiped from memory when this function returns (or on any error path).
        let encryption_master_key = Zeroizing::new(rand::thread_rng().r#gen::<[u8; 32]>());
        let hmac_master_key = Zeroizing::new(rand::thread_rng().r#gen::<[u8; 32]>());
        let scrypt_salt = rand::thread_rng().r#gen::<[u8; 32]>();

        let mut kek = Zeroizing::new([0u8; 32]);
        let scrypt_params = Params::new(
            (scrypt_cost_param as f64).log2() as u8,
            scrypt_block_size,
            P,
            kek.len(),
        )?;
        scrypt::scrypt(
            password.as_bytes(),
            &scrypt_salt,
            &scrypt_params,
            kek.as_mut(),
        )?;

        let kek_aes_key = openssl::aes::AesKey::new_encrypt(kek.as_ref())?;

        let mut wrapped_master_key = Zeroizing::new([0u8; 40]);
        openssl::aes::wrap_key(
            &kek_aes_key,
            Some(DEFAULT_IV),
            wrapped_master_key.as_mut(),
            encryption_master_key.as_ref(),
        )?;

        let mut wrapped_hmac_master_key = Zeroizing::new([0u8; 40]);
        openssl::aes::wrap_key(
            &kek_aes_key,
            Some(DEFAULT_IV),
            wrapped_hmac_master_key.as_mut(),
            hmac_master_key.as_ref(),
        )?;

        let mut version_mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(hmac_master_key.as_ref())?;
        version_mac.update(&FAKE_VAULT_VERSION.to_be_bytes());

        let version_mac_bytes = version_mac.finalize().into_bytes();

        Ok(MasterKeyJson {
            version: FAKE_VAULT_VERSION,
            scryptSalt: STANDARD.encode(scrypt_salt),
            scryptCostParam: scrypt_cost_param,
            scryptBlockSize: scrypt_block_size,
            primaryMasterKey: STANDARD.encode(wrapped_master_key.as_ref()),
            hmacMasterKey: STANDARD.encode(wrapped_hmac_master_key.as_ref()),
            versionMac: STANDARD.encode(version_mac_bytes),
        })
    }
}

/// Struct for MasterKey
/// More info: https://docs.cryptomator.org/en/latest/security/architecture/#masterkey-derivation
///
/// Key material is stored in `Zeroizing` wrappers so both fields are
/// deterministically wiped from memory the moment a `MasterKey` is dropped.
/// `Copy` is intentionally absent: the type is non-`Copy` so the compiler
/// tracks every move of key material, preventing silent proliferation of
/// untracked copies on the stack or heap.
///
/// `Debug` is intentionally implemented manually (not derived) so that key
/// bytes are **never** printed to logs or panic messages, even when the
/// `tracing` or `log` crates format a containing struct in debug mode.
/// `Zeroizing<[u8; 32]>` delegates its `Debug` impl to the inner array,
/// which would print all 32 raw bytes — a direct key exfiltration path.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    pub primary_master_key: Zeroizing<[u8; 32]>,
    pub hmac_master_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose key bytes in debug output.
        f.debug_struct("MasterKey")
            .field("primary_master_key", &"[REDACTED]")
            .field("hmac_master_key", &"[REDACTED]")
            .finish()
    }
}

impl MasterKey {
    pub fn from_masterkey_json(
        mk_json: MasterKeyJson,
        password: &str,
    ) -> Result<MasterKey, MasterKeyError> {
        // Zeroizing wrappers ensure intermediate secret material is wiped on
        // early return (error paths) as well as the happy path.
        let scrypt_salt = Zeroizing::new(STANDARD.decode(mk_json.scryptSalt)?);
        let primary_master_key_enc = Zeroizing::new(STANDARD.decode(mk_json.primaryMasterKey)?);
        let hmac_master_key_enc = Zeroizing::new(STANDARD.decode(mk_json.hmacMasterKey)?);

        let mut kek = Zeroizing::new([0u8; 32]);
        let scrypt_params = Params::new(
            (mk_json.scryptCostParam as f64).log2() as u8,
            mk_json.scryptBlockSize,
            P,
            kek.len(),
        )?;
        scrypt::scrypt(
            password.as_bytes(),
            scrypt_salt.as_slice(),
            &scrypt_params,
            kek.as_mut(),
        )?;

        let kek_aes_key = openssl::aes::AesKey::new_decrypt(kek.as_ref())?;

        let mut unwrapped_master_key = Zeroizing::new([0u8; 32]);
        openssl::aes::unwrap_key(
            &kek_aes_key,
            Some(DEFAULT_IV),
            unwrapped_master_key.as_mut(),
            primary_master_key_enc.as_slice(),
        )?;

        let mut unwrapped_hmac_master_key = Zeroizing::new([0u8; 32]);
        openssl::aes::unwrap_key(
            &kek_aes_key,
            Some(DEFAULT_IV),
            unwrapped_hmac_master_key.as_mut(),
            hmac_master_key_enc.as_slice(),
        )?;

        let version = mk_json.version;
        let version_mac = STANDARD.decode(mk_json.versionMac)?;

        let mut calculated_version_mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(unwrapped_hmac_master_key.as_ref())?;
        calculated_version_mac.update(&version.to_be_bytes());
        calculated_version_mac.verify(GenericArray::from_slice(version_mac.as_slice()))?;

        Ok(MasterKey {
            primary_master_key: unwrapped_master_key,
            hmac_master_key: unwrapped_hmac_master_key,
        })
    }

    /// Returns a new MasterKey instance by reading io::Reader
    pub fn from_reader<R: std::io::Read>(
        file: R,
        password: &str,
    ) -> Result<MasterKey, MasterKeyError> {
        let mk_json: MasterKeyJson = serde_json::from_reader(file)?;
        MasterKey::from_masterkey_json(mk_json, password)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::crypto::MasterKey;
    use crate::crypto::masterkey::MasterKeyJson;
    use crate::cryptofs::{FileSystem, OpenOptions};
    use crate::providers::MemoryFs;

    const DEFAULT_PASSWORD: &str = "12345678";
    const DEFAULT_MK_FILE: &str = "masterkey.cryptomator";
    const SCRYPT_COST: u64 = 16384;
    const SCRYPT_BLOCK_SIZE: u32 = 8;

    #[test]
    fn create_master_key() {
        let memory_fs = MemoryFs::new();
        let mk_json =
            MasterKeyJson::create(DEFAULT_PASSWORD, SCRYPT_COST, SCRYPT_BLOCK_SIZE).unwrap();

        let mk_file = memory_fs.create_file(DEFAULT_MK_FILE).unwrap();
        serde_json::to_writer(mk_file, &mk_json).unwrap();

        let check_mk_file = memory_fs
            .open_file(DEFAULT_MK_FILE, OpenOptions::new())
            .unwrap();
        MasterKey::from_reader(check_mk_file, DEFAULT_PASSWORD).unwrap();
    }
}
