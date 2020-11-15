use crate::crypto::{MasterKey};
use crate::crypto::error::CryptoError;

use byteorder::{BigEndian, WriteBytesExt};

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

const FILE_HEADER_NONCE_LENGTH: usize = 16;
const FILE_HEADER_PAYLOAD_LENGTH: usize = 40;
const FILE_HEADER_PAYLOAD_RESERVED_LENGTH: usize = 8;

const FILE_CONTENT_NONCE_LENGTH: usize = 16;
const FILE_CONTENT_MAC_LENGTH: usize = 32;

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

        let decrypted_filename = cipher.decrypt(&[parent_dir_id],
                                                encrypted_filename_bytes.as_slice())?;
        Ok(decrypted_filename)
    }

    pub fn decrypt_file_header(&self, mut encrypted_header: Vec<u8>) -> Result<FileHeader, CryptoError> {
        //verify header payload
        let mut mac = HmacSha256::new_varkey(self.master_key.hmac_master_key.as_slice())?;
        let mut payload_to_verify = vec![]; // nonce + ciphertext
        payload_to_verify.extend(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]); // nonce
        payload_to_verify.extend(&encrypted_header[FILE_HEADER_NONCE_LENGTH
            ..FILE_HEADER_NONCE_LENGTH+FILE_HEADER_PAYLOAD_LENGTH]); // encrypted payload
        mac.update(payload_to_verify.as_slice());
        mac.verify(&encrypted_header[FILE_HEADER_NONCE_LENGTH+FILE_HEADER_PAYLOAD_LENGTH..])?;

        //decrypt header payload
        let mut cipher = Aes256Ctr::new(GenericArray::from_slice(self.master_key.primary_master_key.as_slice()),
                                    GenericArray::from_slice(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]));
        cipher.apply_keystream(& mut encrypted_header[FILE_HEADER_NONCE_LENGTH
            ..FILE_HEADER_NONCE_LENGTH+FILE_HEADER_PAYLOAD_LENGTH]);
        let decrypted_payload = &encrypted_header[FILE_HEADER_NONCE_LENGTH
            ..FILE_HEADER_NONCE_LENGTH+FILE_HEADER_PAYLOAD_LENGTH];

        let file_header_payload = FileHeaderPayload{
            reserved: clone_into_array(&decrypted_payload[..FILE_HEADER_PAYLOAD_RESERVED_LENGTH]),
            content_key: clone_into_array(&decrypted_payload[FILE_HEADER_PAYLOAD_RESERVED_LENGTH..])
        };
        let file_header = FileHeader{
            nonce: clone_into_array(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]),
            payload: file_header_payload,
            mac: clone_into_array(&encrypted_header[FILE_HEADER_NONCE_LENGTH+FILE_HEADER_PAYLOAD_LENGTH..])
        };

        Ok(file_header)
    }

    pub fn decrypt_chunk(&self, header_nonce: &[u8], file_key: &[u8], chunk_number: usize,
                         mut encrypted_chunk: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let begin_of_mac = encrypted_chunk.len() - FILE_CONTENT_MAC_LENGTH;

        let mut chunk_number_big_endian = vec![];
        chunk_number_big_endian.write_u64::<BigEndian>(chunk_number as u64)?;

        // check MAC
        let mut mac = HmacSha256::new_varkey(self.master_key.hmac_master_key.as_slice())?;
        let mut payload_to_verify = vec![]; // header_nonce + chunk_number + chunk_nonce + ciphertext
        payload_to_verify.extend(header_nonce); // header_nonce
        payload_to_verify.extend(chunk_number_big_endian); // chunk_number
        payload_to_verify.extend(&encrypted_chunk[..FILE_CONTENT_NONCE_LENGTH]); // chunk_nonce
        payload_to_verify.extend(&encrypted_chunk[FILE_CONTENT_NONCE_LENGTH..begin_of_mac]); // ciphertext
        mac.update(payload_to_verify.as_slice());
        mac.verify(&encrypted_chunk[begin_of_mac..])?;

        // decrypt content
        let mut cipher = Aes256Ctr::new(GenericArray::from_slice(file_key),
                                        GenericArray::from_slice(&encrypted_chunk[..16]));
        cipher.apply_keystream(&mut encrypted_chunk[FILE_CONTENT_NONCE_LENGTH..begin_of_mac]);
        let decrypted_content = &encrypted_chunk[FILE_CONTENT_NONCE_LENGTH..begin_of_mac];

        Ok(Vec::from(decrypted_content))
    }
}