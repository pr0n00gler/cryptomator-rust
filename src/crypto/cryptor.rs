use crate::crypto::{MasterKey};
use crate::crypto::error::CryptoError;

use aes_siv::aead::{generic_array::GenericArray};
use aes_siv::siv::{Aes256Siv};

use aes_ctr::Aes256Ctr;
use aes_ctr::cipher::{
    stream::{
        NewStreamCipher, SyncStreamCipher,
    }
};

use crate::crypto::common::clone_into_array;

use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};

type HmacSha256 = Hmac<Sha256>;

pub struct FileHeaderPayload {
    pub reserved: [u8; 8],
    pub content_key: [u8; 32]
}

pub struct FileHeader {
    pub nonce: [u8; 16],
    pub payload: FileHeaderPayload,
    pub mac: [u8; 32]
}

pub struct Cryptor {
    master_key: MasterKey
}

impl Cryptor {
    pub fn new(master_key: MasterKey) -> Cryptor {
        Cryptor{master_key}
    }

    pub fn decrypt_filename(&self, encrypted_filename: &str, parent_dir_id: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let encrypted_filename_bytes = base64::decode_config(encrypted_filename, base64::URL_SAFE)?;

        let mut long_key:Vec<u8> = vec![];
        long_key.extend(&self.master_key.hmac_master_key);
        long_key.extend(&self.master_key.primary_master_key);

        let aes_siv_key = GenericArray::from_slice(long_key.as_slice());

        let mut cipher = Aes256Siv::new(aes_siv_key.clone());

        let decrypted_filename = cipher.decrypt(&[parent_dir_id], encrypted_filename_bytes.as_slice())?;
        Ok(decrypted_filename)
    }

    pub fn decrypt_file_header(&self, encrypted_header: Vec<u8>) -> Result<FileHeader, CryptoError> {
        let nonce = &encrypted_header[..16];
        let hmac_data = &encrypted_header[56..];

        let mut cloned_header = encrypted_header.clone();

        //verify header payload
        let mut mac = HmacSha256::new_varkey(self.master_key.hmac_master_key.as_slice())?;
        let mut payload_to_verify = vec![];
        payload_to_verify.extend(nonce);
        payload_to_verify.extend(&cloned_header[16..56]);
        mac.update(payload_to_verify.as_slice());
        mac.verify(hmac_data)?;

        //decrypt header payload
        let mut cipher = Aes256Ctr::new(GenericArray::from_slice(self.master_key.primary_master_key.as_slice()),
                                    GenericArray::from_slice(nonce));
        cipher.apply_keystream(& mut cloned_header[16..56]);
        let decrypted_payload = &cloned_header[16..56];

        let file_header_payload = FileHeaderPayload{
            reserved: clone_into_array(&decrypted_payload[..8]),
            content_key: clone_into_array(&decrypted_payload[8..])
        };
        let file_header = FileHeader{
            nonce: clone_into_array(nonce),
            payload: file_header_payload,
            mac: clone_into_array(hmac_data)
        };

        Ok(file_header)
    }
}