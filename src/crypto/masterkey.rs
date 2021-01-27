use serde_json::Value;

use std::fs;

use crate::crypto::error::MasterKeyError;

const P: u32 = 1;
const DEFAULT_IV: [u8; 8] = [0xA6; 8];

/// Struct for MasterKey
/// More info: https://docs.cryptomator.org/en/latest/security/architecture/#masterkey-derivation
#[derive(Copy, Clone)]
pub struct MasterKey {
    pub primary_master_key: [u8; 32],
    pub hmac_master_key: [u8; 32],
}

impl MasterKey {
    /// Returns a new MasterKey instance by reading a file
    pub fn from_file(filename: &str, password: &str) -> Result<MasterKey, MasterKeyError> {
        let file = fs::File::open(filename)?;
        let mk_json: Value = serde_json::from_reader(file)?;

        let scrypt_cost_param = mk_json["scryptCostParam"].as_u64().unwrap_or(0);
        let scrypt_block_size = mk_json["scryptBlockSize"].as_u64().unwrap_or(0);

        //TODO: check version
        let _version = mk_json["version"].as_u64().unwrap_or(0);

        let scrypt_salt = base64::decode(mk_json["scryptSalt"].as_str().unwrap_or(""))?;
        let primary_master_key =
            base64::decode(mk_json["primaryMasterKey"].as_str().unwrap_or(""))?;
        let hmac_master_key = base64::decode(mk_json["hmacMasterKey"].as_str().unwrap_or(""))?;

        let scrypt_params = scrypt::ScryptParams::new(
            (scrypt_cost_param as f64).log2() as u8,
            scrypt_block_size as u32,
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
