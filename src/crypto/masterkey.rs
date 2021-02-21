use serde::{Deserialize, Serialize};

use crate::crypto::error::MasterKeyError;

use rand::Rng;

const P: u32 = 1;
const DEFAULT_IV: [u8; 8] = [0xA6; 8];

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct MasterKeyJson {
    version: u8,
    scryptSalt: String,
    scryptCostParam: u64,
    scryptBlockSize: u32,
    primaryMasterKey: String,
    hmacMasterKey: String,
    versionMac: String,
}

impl MasterKeyJson {
    pub fn create(
        password: &str,
        scrypt_cost_param: u64,
        scrypt_block_size: u32,
    ) -> Result<MasterKeyJson, MasterKeyError> {
        let encryption_master_key = rand::thread_rng().gen::<[u8; 32]>();
        let hmac_master_key = rand::thread_rng().gen::<[u8; 32]>();
        let scrypt_salt = rand::thread_rng().gen::<[u8; 32]>();

        let scrypt_params = scrypt::ScryptParams::new(
            (scrypt_cost_param as f64).log2() as u8,
            scrypt_block_size,
            P,
        )?;
        let mut kek = [0u8; 32];
        scrypt::scrypt(password.as_bytes(), &scrypt_salt, &scrypt_params, &mut kek)?;

        let kek_aes_key = openssl::aes::AesKey::new_encrypt(&kek)?;

        let mut wrapped_master_key = [0u8; 40];
        openssl::aes::wrap_key(
            &kek_aes_key,
            Some(DEFAULT_IV),
            &mut wrapped_master_key,
            &encryption_master_key,
        )?;

        let mut wrapped_hmac_master_key = [0u8; 40];
        openssl::aes::wrap_key(
            &kek_aes_key,
            Some(DEFAULT_IV),
            &mut wrapped_hmac_master_key,
            &hmac_master_key,
        )?;

        Ok(MasterKeyJson {
            version: 7,
            scryptSalt: base64::encode(scrypt_salt),
            scryptCostParam: scrypt_cost_param,
            scryptBlockSize: scrypt_block_size,
            primaryMasterKey: base64::encode(wrapped_master_key),
            hmacMasterKey: base64::encode(wrapped_hmac_master_key),
            versionMac: "".to_string(), // TODO
        })
    }
}

/// Struct for MasterKey
/// More info: https://docs.cryptomator.org/en/latest/security/architecture/#masterkey-derivation
#[derive(Copy, Clone, Debug)]
pub struct MasterKey {
    pub primary_master_key: [u8; 32],
    pub hmac_master_key: [u8; 32],
}

impl MasterKey {
    /// Returns a new MasterKey instance by reading io::Reader
    pub fn from_reader<R: std::io::Read>(
        file: R,
        password: &str,
    ) -> Result<MasterKey, MasterKeyError> {
        let mk_json: MasterKeyJson = serde_json::from_reader(file)?;

        //TODO: check version
        let _version = mk_json.version;

        let scrypt_salt = base64::decode(mk_json.scryptSalt)?;
        let primary_master_key = base64::decode(mk_json.primaryMasterKey)?;
        let hmac_master_key = base64::decode(mk_json.hmacMasterKey)?;

        let scrypt_params = scrypt::ScryptParams::new(
            (mk_json.scryptCostParam as f64).log2() as u8,
            mk_json.scryptBlockSize,
            P,
        )?;

        let mut kek = [0u8; 32];
        scrypt::scrypt(
            password.as_bytes(),
            scrypt_salt.as_slice(),
            &scrypt_params,
            &mut kek,
        )?;

        let kek_aes_key = openssl::aes::AesKey::new_decrypt(&kek)?;

        let mut unwrapped_master_key = [0u8; 32];
        openssl::aes::unwrap_key(
            &kek_aes_key,
            Some(DEFAULT_IV),
            &mut unwrapped_master_key,
            primary_master_key.as_slice(),
        )?;

        let mut unwrapped_hmac_master_key = [0u8; 32];
        openssl::aes::unwrap_key(
            &kek_aes_key,
            Some(DEFAULT_IV),
            &mut unwrapped_hmac_master_key,
            hmac_master_key.as_slice(),
        )?;

        Ok(MasterKey {
            primary_master_key: unwrapped_master_key,
            hmac_master_key: unwrapped_hmac_master_key,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::crypto::masterkey::MasterKeyJson;
    use crate::crypto::MasterKey;
    use crate::cryptofs::FileSystem;
    use crate::providers::MemoryFS;

    const DEFAULT_PASSWORD: &str = "12345678";
    const DEFAULT_MK_FILE: &str = "masterkey.cryptomator";
    const SCRYPT_COST: u64 = 16384;
    const SCRYPT_BLOCK_SIZE: u32 = 8;

    #[test]
    fn create_master_key() {
        let memory_fs = MemoryFS::new();
        let mk_json =
            MasterKeyJson::create(DEFAULT_PASSWORD, SCRYPT_COST, SCRYPT_BLOCK_SIZE).unwrap();

        let mk_file = memory_fs.create_file(DEFAULT_MK_FILE).unwrap();
        serde_json::to_writer(mk_file, &mk_json).unwrap();

        let check_mk_file = memory_fs.open_file(DEFAULT_MK_FILE).unwrap();
        MasterKey::from_reader(check_mk_file, DEFAULT_PASSWORD).unwrap();
    }
}
