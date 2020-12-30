use crate::crypto::error::CryptoError;
use crate::crypto::MasterKey;

use std::io::{Read, Write};
use std::iter;

use rand::Rng;

use byteorder::{BigEndian, WriteBytesExt};

use aes_siv::aead::generic_array::GenericArray;
use aes_siv::siv::Aes256Siv;

use aes_ctr::cipher::stream::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;

use crate::crypto::common::clone_into_array;

use crate::crypto::error::CryptoError::{InvalidFileChunkLength, InvalidFileHeaderLength};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const FILE_HEADER_NONCE_LENGTH: usize = 16;
pub const FILE_HEADER_PAYLOAD_LENGTH: usize = 40;
pub const FILE_HEADER_PAYLOAD_RESERVED_LENGTH: usize = 8;
pub const FILE_HEADER_MAC_LENGTH: usize = 32;
pub const FILE_HEADER_LENGTH: usize =
    FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH + FILE_HEADER_MAC_LENGTH;

pub const FILE_CHUNK_CONTENT_NONCE_LENGTH: usize = 16;
pub const FILE_CHUNK_CONTENT_MAC_LENGTH: usize = 32;
pub const FILE_CHUNK_CONTENT_PAYLOAD_LENGTH: usize = 32 * 1024;

pub const FILE_CHUNK_LENGTH: usize = FILE_CHUNK_CONTENT_NONCE_LENGTH
    + FILE_CHUNK_CONTENT_PAYLOAD_LENGTH
    + FILE_CHUNK_CONTENT_MAC_LENGTH;

pub fn calculate_cleartext_size(ciphertext_size: u64) -> u64 {
    let ciphertext_size = ciphertext_size - FILE_HEADER_LENGTH as u64;
    let overhead_per_chunk =
        (FILE_CHUNK_CONTENT_MAC_LENGTH + FILE_CHUNK_CONTENT_NONCE_LENGTH) as u64;
    let full_chunks_number = ciphertext_size / FILE_CHUNK_LENGTH as u64;
    let additional_ciphertext_bytes = ciphertext_size % FILE_CHUNK_LENGTH as u64;
    let additional_cleartext_bytes = if additional_ciphertext_bytes == 0 {
        0
    } else {
        additional_ciphertext_bytes - overhead_per_chunk
    };
    FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64 * full_chunks_number + additional_cleartext_bytes
}

pub struct FileHeaderPayload {
    pub reserved: [u8; 8],
    pub content_key: [u8; 32],
}

pub struct FileHeader {
    pub nonce: [u8; 16],
    pub payload: FileHeaderPayload,
    pub mac: [u8; 32],
}

pub struct Cryptor<'gc> {
    master_key: &'gc MasterKey,
}

impl<'gc> Cryptor<'gc> {
    pub fn new(master_key: &'gc MasterKey) -> Cryptor {
        Cryptor { master_key }
    }

    pub fn get_dir_id_hash(&self, dir_id: &[u8]) -> Result<String, CryptoError> {
        let mut long_key: Vec<u8> = vec![];
        long_key.extend(&self.master_key.hmac_master_key);
        long_key.extend(&self.master_key.primary_master_key);
        let aes_siv_key = GenericArray::clone_from_slice(long_key.as_slice());

        let mut cipher = Aes256Siv::new(aes_siv_key);
        let encrypted_dir_id = cipher.encrypt(iter::empty::<&[u8]>(), dir_id)?;

        let mut sha1_hasher = sha1::Sha1::new();
        sha1_hasher.update(encrypted_dir_id.as_slice());
        let sha1_hash = sha1_hasher.digest().bytes();
        let dir_id_hash_base32_encoded = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            sha1_hash.as_ref(),
        );
        Ok(dir_id_hash_base32_encoded)
    }

    pub fn encrypt_filename(
        &self,
        cleartext_name: &str,
        parent_dir_id: &[u8],
    ) -> Result<String, CryptoError> {
        let mut long_key: Vec<u8> = vec![];
        long_key.extend(&self.master_key.hmac_master_key);
        long_key.extend(&self.master_key.primary_master_key);
        let aes_siv_key = GenericArray::clone_from_slice(long_key.as_slice());

        let mut cipher = Aes256Siv::new(aes_siv_key);
        let encrypted_filename = cipher.encrypt(&[parent_dir_id], cleartext_name.as_bytes())?;

        let encoded_ciphertext = base64::encode_config(encrypted_filename, base64::URL_SAFE);
        Ok(encoded_ciphertext)
    }

    pub fn decrypt_filename(
        &self,
        encrypted_filename: &str,
        parent_dir_id: &[u8],
    ) -> Result<String, CryptoError> {
        let encrypted_filename_bytes = base64::decode_config(encrypted_filename, base64::URL_SAFE)?;

        let mut long_key: Vec<u8> = vec![];
        long_key.extend(&self.master_key.hmac_master_key);
        long_key.extend(&self.master_key.primary_master_key);

        let aes_siv_key = GenericArray::clone_from_slice(long_key.as_slice());

        let mut cipher = Aes256Siv::new(aes_siv_key);

        let decrypted_filename =
            cipher.decrypt(&[parent_dir_id], encrypted_filename_bytes.as_slice())?;

        Ok(String::from_utf8(decrypted_filename)?)
    }

    pub fn create_file_header(&self) -> FileHeader {
        FileHeader {
            nonce: rand::thread_rng().gen::<[u8; 16]>(),
            payload: FileHeaderPayload {
                reserved: [0xFu8; 8],
                content_key: rand::thread_rng().gen::<[u8; 32]>(),
            },
            mac: [0u8; 32],
        }
    }

    pub fn encrypt_file_header(&self, file_header: &FileHeader) -> Result<Vec<u8>, CryptoError> {
        let mut encrypted_header: Vec<u8> = vec![];

        let mut payload: Vec<u8> = vec![];
        payload.extend_from_slice(file_header.payload.reserved.as_ref());
        payload.extend_from_slice(file_header.payload.content_key.as_ref());

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(self.master_key.primary_master_key.as_slice()),
            GenericArray::from_slice(file_header.nonce.as_ref()),
        );
        cipher.apply_keystream(&mut payload);

        let mut mac_payload: Vec<u8> = vec![];
        mac_payload.extend_from_slice(file_header.nonce.as_ref());
        mac_payload.extend(&payload);
        let mut mac = HmacSha256::new_varkey(self.master_key.hmac_master_key.as_slice())?;
        mac.update(mac_payload.as_slice());
        let mac_bytes = mac.finalize().into_bytes();

        encrypted_header.extend_from_slice(file_header.nonce.as_ref());
        encrypted_header.extend_from_slice(payload.as_slice());
        encrypted_header.extend_from_slice(mac_bytes.as_slice());

        Ok(encrypted_header)
    }

    pub fn decrypt_file_header(&self, encrypted_header: &[u8]) -> Result<FileHeader, CryptoError> {
        if encrypted_header.len() < FILE_HEADER_LENGTH {
            return Err(InvalidFileHeaderLength(format!(
                "file header must be exactly {} bytes length, got: {}",
                FILE_HEADER_LENGTH,
                encrypted_header.len()
            )));
        }

        //verify header payload
        let mut mac = HmacSha256::new_varkey(self.master_key.hmac_master_key.as_slice())?;
        let mut payload_to_verify = vec![]; // nonce + ciphertext
        payload_to_verify.extend(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]); // nonce
        payload_to_verify.extend(
            &encrypted_header
                [FILE_HEADER_NONCE_LENGTH..FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH],
        ); // encrypted payload
        mac.update(payload_to_verify.as_slice());
        mac.verify(&encrypted_header[FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH..])?;

        //decrypt header payload
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(self.master_key.primary_master_key.as_slice()),
            GenericArray::from_slice(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]),
        );
        let mut decrypted_payload = Vec::from(
            &encrypted_header
                [FILE_HEADER_NONCE_LENGTH..FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH],
        );
        cipher.apply_keystream(&mut decrypted_payload);

        let file_header_payload = FileHeaderPayload {
            reserved: clone_into_array(&decrypted_payload[..FILE_HEADER_PAYLOAD_RESERVED_LENGTH]),
            content_key: clone_into_array(
                &decrypted_payload[FILE_HEADER_PAYLOAD_RESERVED_LENGTH..],
            ),
        };
        let file_header = FileHeader {
            nonce: clone_into_array(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]),
            payload: file_header_payload,
            mac: clone_into_array(
                &encrypted_header[FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH..],
            ),
        };

        Ok(file_header)
    }

    pub fn encrypt_content<R: Read, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
    ) -> Result<(), CryptoError> {
        let file_header = self.create_file_header();
        let encrypted_header = self.encrypt_file_header(&file_header)?;
        output.write_all(encrypted_header.as_slice())?;

        let mut file_chunk = [0u8; FILE_CHUNK_CONTENT_PAYLOAD_LENGTH];
        let mut chunk_number: usize = 0;
        loop {
            let read_bytes = input.read(&mut file_chunk)?;
            let encrypted_chunk = self.encrypt_chunk(
                file_header.nonce.as_ref(),
                file_header.payload.content_key.as_ref(),
                chunk_number,
                &file_chunk[..read_bytes],
            )?;
            output.write_all(encrypted_chunk.as_slice())?;
            if read_bytes < FILE_CHUNK_CONTENT_PAYLOAD_LENGTH {
                break;
            }
            chunk_number += 1;
        }
        Ok(())
    }

    pub fn decrypt_content<R: Read, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
    ) -> Result<(), CryptoError> {
        let mut header_bytes = [0u8; FILE_HEADER_LENGTH];
        input.read_exact(&mut header_bytes)?;
        let file_header = self.decrypt_file_header(&header_bytes)?;

        let mut file_chunk = [0u8; FILE_CHUNK_LENGTH];
        let mut chunk_number: usize = 0;
        loop {
            let read_bytes = input.read(&mut file_chunk)?;
            let chunk_content = self.decrypt_chunk(
                file_header.nonce.as_ref(),
                file_header.payload.content_key.as_ref(),
                chunk_number,
                &file_chunk[..read_bytes],
            )?;
            output.write_all(chunk_content.as_slice())?;
            if read_bytes < FILE_CHUNK_CONTENT_PAYLOAD_LENGTH {
                break;
            }
            chunk_number += 1;
        }
        Ok(())
    }

    pub fn encrypt_chunk(
        &self,
        header_nonce: &[u8],
        file_key: &[u8],
        chunk_number: usize,
        chunk_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let chunk_nonce = rand::thread_rng().gen::<[u8; 16]>();

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(file_key),
            GenericArray::from_slice(chunk_nonce.as_ref()),
        );
        let mut encrypted_chunk_data = Vec::from(chunk_data);
        cipher.apply_keystream(&mut encrypted_chunk_data);

        let mut chunk_number_big_endian = vec![];
        chunk_number_big_endian.write_u64::<BigEndian>(chunk_number as u64)?;

        let mut mac_payload: Vec<u8> = vec![];
        mac_payload.extend_from_slice(header_nonce.as_ref());
        mac_payload.extend(&chunk_number_big_endian);
        mac_payload.extend_from_slice(chunk_nonce.as_ref());
        mac_payload.extend(&encrypted_chunk_data);

        let mut mac = HmacSha256::new_varkey(self.master_key.hmac_master_key.as_slice())?;
        mac.update(mac_payload.as_slice());
        let mac_bytes = mac.finalize().into_bytes();

        let mut encrypted_chunk: Vec<u8> = vec![];
        encrypted_chunk.extend_from_slice(chunk_nonce.as_ref());
        encrypted_chunk.extend(encrypted_chunk_data);
        encrypted_chunk.extend(mac_bytes);

        Ok(encrypted_chunk)
    }

    pub fn decrypt_chunk(
        &self,
        header_nonce: &[u8],
        file_key: &[u8],
        chunk_number: usize,
        encrypted_chunk: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if encrypted_chunk.len() < FILE_CHUNK_CONTENT_MAC_LENGTH + FILE_CHUNK_CONTENT_NONCE_LENGTH {
            return Err(InvalidFileChunkLength(format!(
                "file chunk must be more than {} bytes length, got: {}",
                FILE_CHUNK_CONTENT_MAC_LENGTH + FILE_CHUNK_CONTENT_NONCE_LENGTH,
                encrypted_chunk.len()
            )));
        }

        let begin_of_mac = encrypted_chunk.len() - FILE_CHUNK_CONTENT_MAC_LENGTH;

        let mut chunk_number_big_endian = vec![];
        chunk_number_big_endian.write_u64::<BigEndian>(chunk_number as u64)?;

        // check MAC
        let mut mac = HmacSha256::new_varkey(self.master_key.hmac_master_key.as_slice())?;
        let mut payload_to_verify = vec![]; // header_nonce + chunk_number + chunk_nonce + ciphertext
        payload_to_verify.extend(header_nonce); // header_nonce
        payload_to_verify.extend(chunk_number_big_endian); // chunk_number
        payload_to_verify.extend(&encrypted_chunk[..FILE_CHUNK_CONTENT_NONCE_LENGTH]); // chunk_nonce
        payload_to_verify.extend(&encrypted_chunk[FILE_CHUNK_CONTENT_NONCE_LENGTH..begin_of_mac]); // ciphertext
        mac.update(payload_to_verify.as_slice());
        mac.verify(&encrypted_chunk[begin_of_mac..])?;

        // decrypt content
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(file_key),
            GenericArray::from_slice(&encrypted_chunk[..16]),
        );
        let mut decrypted_content =
            Vec::from(&encrypted_chunk[FILE_CHUNK_CONTENT_NONCE_LENGTH..begin_of_mac]);
        cipher.apply_keystream(&mut decrypted_content);

        Ok(decrypted_content)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::crypto;
    use std::io::Cursor;
    const PATH_TO_MASTER_KEY: &str = "tests/test_storage/masterkey.cryptomator";
    const DEFAULT_PASSWORD: &str = "12345678";

    const ROOT_DIR_ID_HASH: &str = "HIRW3L6XRAPFC2UCK5QY37Q2U552IRPE";
    const ROOT_DIR_ID: &[u8] = b"";

    const TEST_FILENAME: &str = "lorem-ipsum.pdf";
    const ENCRYPTED_TEST_FILENAME: &str = "fXQEfw6iSwP1esHbRznuVFZqv_LQFqNwC2r2LOQa-A==";

    #[test]
    fn test_encrypt_dir_id() {
        let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(&mk);
        let dir_id_hash = cryptor.get_dir_id_hash(ROOT_DIR_ID).unwrap();
        assert_eq!(ROOT_DIR_ID_HASH, dir_id_hash.as_str());
    }

    #[test]
    fn test_encrypt_filename() {
        let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(&mk);
        let encrypted_filename = cryptor
            .encrypt_filename(TEST_FILENAME, ROOT_DIR_ID)
            .unwrap();
        assert_eq!(ENCRYPTED_TEST_FILENAME, encrypted_filename.as_str())
    }

    #[test]
    fn test_decrypt_filename() {
        let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(&mk);
        let decrypted_filename = cryptor
            .decrypt_filename(ENCRYPTED_TEST_FILENAME, ROOT_DIR_ID)
            .unwrap();
        assert_eq!(TEST_FILENAME, decrypted_filename.as_str())
    }

    #[test]
    fn test_encrypt_decrypt_header() {
        let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(&mk);

        let header = cryptor.create_file_header();
        let encrypted_header = cryptor.encrypt_file_header(&header).unwrap();
        let decrypted_header = cryptor
            .decrypt_file_header(encrypted_header.as_slice())
            .unwrap();

        assert_eq!(header.nonce, decrypted_header.nonce);
        assert_eq!(header.payload.reserved, decrypted_header.payload.reserved);
        assert_eq!(
            header.payload.content_key,
            decrypted_header.payload.content_key
        );
    }

    #[test]
    fn test_encrypt_decrypt_chunk() {
        let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(&mk);

        let header = cryptor.create_file_header();
        let chunk_data: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();

        let encrypted_chunk = cryptor
            .encrypt_chunk(
                header.nonce.as_ref(),
                header.payload.content_key.as_ref(),
                0,
                chunk_data.as_slice(),
            )
            .unwrap();
        let decrypted_chunk = cryptor
            .decrypt_chunk(
                header.nonce.as_ref(),
                header.payload.content_key.as_ref(),
                0,
                encrypted_chunk.as_slice(),
            )
            .unwrap();

        assert_eq!(chunk_data, decrypted_chunk);
    }

    #[test]
    fn test_encrypt_decrypt_content() {
        let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(&mk);

        let content_data: Vec<u8> = (0..10 * 1024 * 1024)
            .map(|_| rand::random::<u8>())
            .collect();
        let mut raw_content_reader = Cursor::new(content_data);

        let mut encrypted_content = Cursor::new(Vec::new());
        let mut decrypted_content = Cursor::new(Vec::new());

        cryptor
            .encrypt_content(&mut raw_content_reader, &mut encrypted_content)
            .unwrap();
        encrypted_content.set_position(0);

        cryptor
            .decrypt_content(&mut encrypted_content, &mut decrypted_content)
            .unwrap();

        assert_eq!(raw_content_reader.get_ref(), decrypted_content.get_ref());
    }
}
