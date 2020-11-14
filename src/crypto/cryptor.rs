use crate::crypto::{MasterKey};
use crate::crypto::error::CryptoError;

use aes_siv::aead::{generic_array::GenericArray};
use aes_siv::siv::{Aes256Siv};

pub struct Cryptor {
    master_key: MasterKey
}

impl Cryptor {
    pub fn new(master_key: MasterKey) -> Cryptor {
        Cryptor{master_key}
    }

    pub fn decrypt_filename(&self, encrypted_filename: &str, parent_dir_id: &str) -> Result<Vec<u8>, CryptoError> {
        let encrypted_filename_bytes = base64::decode_config(encrypted_filename, base64::URL_SAFE)?;

        let mut long_key:Vec<u8> = vec![];
        long_key.extend(&self.master_key.hmac_master_key);
        long_key.extend(&self.master_key.primary_master_key);

        let aes_siv_key = GenericArray::from_slice(long_key.as_slice());

        let mut cipher = Aes256Siv::new(aes_siv_key.clone());

        let decrypted_filename = cipher.decrypt(&[parent_dir_id.as_bytes()], encrypted_filename_bytes.as_slice())?;
        Ok(decrypted_filename)
    }
}