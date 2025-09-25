use crate::crypto::error::CryptoError;
use crate::crypto::Vault;

use std::io::{Read, Write};
use std::iter;

use rand::Rng;

use aes::Aes256;
use aes_siv::siv::Aes256Siv;
use aes_siv::{aead::generic_array::GenericArray, KeyInit};
use base32::Alphabet;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::crypto::common::clone_into_array;

use crate::crypto::error::CryptoError::{InvalidFileChunkLength, InvalidFileHeaderLength};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha256;

/// File header nonce used during header payload encryption
pub const FILE_HEADER_NONCE_LENGTH: usize = 16;

/// AES-CTR encrypted payload length
pub const FILE_HEADER_PAYLOAD_LENGTH: usize = 40;

/// Length of a file content key in the payload
pub const FILE_HEADER_PAYLOAD_CONTENT_KEY_LENGTH: usize = 32;

/// Length of reserved bytes in payload
pub const FILE_HEADER_PAYLOAD_RESERVED_LENGTH: usize = 8;

/// Length of a MAC
pub const FILE_HEADER_MAC_LENGTH: usize = 32;

/// Total file header length
pub const FILE_HEADER_LENGTH: usize =
    FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH + FILE_HEADER_MAC_LENGTH;

/// File chunk's nonce length
pub const FILE_CHUNK_CONTENT_NONCE_LENGTH: usize = 16;

/// File chunk's mac length
pub const FILE_CHUNK_CONTENT_MAC_LENGTH: usize = 32;

/// Max length of file chunk's payload
pub const FILE_CHUNK_CONTENT_PAYLOAD_LENGTH: usize = 32 * 1024;

/// Total length of a file chunk
pub const FILE_CHUNK_LENGTH: usize = FILE_CHUNK_CONTENT_NONCE_LENGTH
    + FILE_CHUNK_CONTENT_PAYLOAD_LENGTH
    + FILE_CHUNK_CONTENT_MAC_LENGTH;

const AES_SIV_KEY_LENGTH: usize = 64;

/// Calculates the size of the cleartext payload by ciphertext
#[inline]
pub fn calculate_cleartext_size(ciphertext_size: u64) -> u64 {
    if ciphertext_size < FILE_HEADER_LENGTH as u64 {
        return 0;
    }
    let ciphertext_size = ciphertext_size - FILE_HEADER_LENGTH as u64;
    let overhead_per_chunk = FILE_CHUNK_LENGTH as u64 - FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64;
    let full_chunks_number = ciphertext_size / FILE_CHUNK_LENGTH as u64;
    let additional_ciphertext_bytes = ciphertext_size % FILE_CHUNK_LENGTH as u64;
    let additional_cleartext_bytes = additional_ciphertext_bytes.saturating_sub(overhead_per_chunk);
    FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64 * full_chunks_number + additional_cleartext_bytes
}

#[inline]
pub fn shorten_name<P: AsRef<str>>(name: P) -> String {
    let mut hasher = Sha1::new();
    hasher.update(name.as_ref().as_bytes());
    URL_SAFE.encode(hasher.finalize())
}

/// Contains reserved bytes and content key
#[derive(Debug)]
pub struct FileHeaderPayload {
    pub reserved: [u8; 8],
    pub content_key: [u8; 32],
}

/// Contains nonce, payload and mac
#[derive(Debug)]
pub struct FileHeader {
    pub nonce: [u8; 16],
    pub payload: FileHeaderPayload,
    pub mac: [u8; 32],
}

/// The core crypto instance to encrypt/decrypt data
#[derive(Copy, Clone, Debug)]
pub struct Cryptor {
    pub vault: Vault,
}

impl Cryptor {
    #[inline]
    fn fill_aes_siv_key(&self, out: &mut [u8; AES_SIV_KEY_LENGTH]) {
        let hmac_key = &self.vault.master_key.hmac_master_key;
        let primary_key = &self.vault.master_key.primary_master_key;

        debug_assert_eq!(hmac_key.len() + primary_key.len(), AES_SIV_KEY_LENGTH);

        let (left, right) = out.split_at_mut(hmac_key.len());
        left.copy_from_slice(hmac_key);
        right[..primary_key.len()].copy_from_slice(primary_key);
    }

    /// Creates a new cryptor instance
    pub fn new(vault: Vault) -> Cryptor {
        Cryptor { vault }
    }

    /// Returns hash of the directory by a provided unique dir_id
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#directory-ids
    pub fn get_dir_id_hash(&self, dir_id: &[u8]) -> Result<String, CryptoError> {
        let mut long_key = [0u8; AES_SIV_KEY_LENGTH];
        self.fill_aes_siv_key(&mut long_key);

        let mut cipher = Aes256Siv::new(GenericArray::from_slice(&long_key));
        let encrypted_dir_id = cipher.encrypt(iter::empty::<&[u8]>(), dir_id)?;

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(encrypted_dir_id.as_slice());
        let sha1_hash = sha1_hasher.finalize();
        let dir_id_hash_base32_encoded =
            base32::encode(Alphabet::Rfc4648 { padding: false }, sha1_hash.as_slice());
        Ok(dir_id_hash_base32_encoded)
    }

    /// Encrypts a filename using a parent dir_id
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#filename-encryption
    pub fn encrypt_filename<S: AsRef<str>>(
        &self,
        cleartext_name: S,
        parent_dir_id: &[u8],
    ) -> Result<String, CryptoError> {
        let mut long_key = [0u8; AES_SIV_KEY_LENGTH];
        self.fill_aes_siv_key(&mut long_key);

        let mut cipher = Aes256Siv::new(GenericArray::from_slice(&long_key));
        let encrypted_filename =
            cipher.encrypt([parent_dir_id], cleartext_name.as_ref().as_bytes())?;

        let encoded_ciphertext = URL_SAFE.encode(encrypted_filename);
        Ok(encoded_ciphertext)
    }

    /// Decrypts a ciphertext filename using a parent dir_id
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#filename-encryption
    pub fn decrypt_filename<S: AsRef<str>>(
        &self,
        encrypted_filename: S,
        parent_dir_id: &[u8],
    ) -> Result<String, CryptoError> {
        let encrypted_filename_bytes = URL_SAFE.decode(encrypted_filename.as_ref())?;

        let mut long_key = [0u8; AES_SIV_KEY_LENGTH];
        self.fill_aes_siv_key(&mut long_key);

        let mut cipher = Aes256Siv::new(GenericArray::from_slice(&long_key));

        let decrypted_filename =
            cipher.decrypt([parent_dir_id], encrypted_filename_bytes.as_slice())?;

        Ok(String::from_utf8(decrypted_filename)?)
    }

    /// Returns a new FileHeader
    pub fn create_file_header(&self) -> FileHeader {
        FileHeader {
            nonce: rand::thread_rng().gen::<[u8; FILE_HEADER_NONCE_LENGTH]>(),
            payload: FileHeaderPayload {
                reserved: [0xFu8; FILE_HEADER_PAYLOAD_RESERVED_LENGTH],
                content_key: rand::thread_rng()
                    .gen::<[u8; FILE_HEADER_PAYLOAD_CONTENT_KEY_LENGTH]>(),
            },
            mac: [0u8; FILE_HEADER_MAC_LENGTH],
        }
    }

    /// Encrypts a FileHeader
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-header-encryption
    pub fn encrypt_file_header(&self, file_header: &FileHeader) -> Result<Vec<u8>, CryptoError> {
        let mut encrypted_header = Vec::with_capacity(FILE_HEADER_LENGTH);

        let mut payload = [0u8; FILE_HEADER_PAYLOAD_LENGTH];
        payload[..FILE_HEADER_PAYLOAD_RESERVED_LENGTH].copy_from_slice(&file_header.payload.reserved);
        payload[FILE_HEADER_PAYLOAD_RESERVED_LENGTH..]
            .copy_from_slice(&file_header.payload.content_key);

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(&self.vault.master_key.primary_master_key),
            GenericArray::from_slice(&file_header.nonce),
        );
        cipher.apply_keystream(&mut payload);

        let mut mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.vault.master_key.hmac_master_key)?;
        mac.update(&file_header.nonce);
        mac.update(&payload);
        let mac_bytes = mac.finalize().into_bytes();

        encrypted_header.extend_from_slice(&file_header.nonce);
        encrypted_header.extend_from_slice(&payload);
        encrypted_header.extend_from_slice(&mac_bytes);

        Ok(encrypted_header)
    }

    /// Decrypts a FileHeader
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-header-encryption
    pub fn decrypt_file_header(&self, encrypted_header: &[u8]) -> Result<FileHeader, CryptoError> {
        if encrypted_header.len() < FILE_HEADER_LENGTH {
            return Err(InvalidFileHeaderLength(format!(
                "file header must be exactly {} bytes length, got: {}",
                FILE_HEADER_LENGTH,
                encrypted_header.len()
            )));
        }

        //verify header payload
        let mut mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.vault.master_key.hmac_master_key)?;
        mac.update(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]);
        mac.update(
            &encrypted_header
                [FILE_HEADER_NONCE_LENGTH..FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH],
        );
        mac.verify(GenericArray::from_slice(
            &encrypted_header[FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH..],
        ))?;

        //decrypt header payload
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(&self.vault.master_key.primary_master_key),
            GenericArray::from_slice(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]),
        );
        let mut decrypted_payload = [0u8; FILE_HEADER_PAYLOAD_LENGTH];
        decrypted_payload.copy_from_slice(
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

    /// Encrypts a data
    /// Encrypted data will be written to a output
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-content-encryption
    #[inline]
    pub fn encrypt_content<R: Read, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
    ) -> Result<(), CryptoError> {
        let file_header = self.create_file_header();
        let encrypted_header = self.encrypt_file_header(&file_header)?;
        output.write_all(&encrypted_header)?;

        let mut file_chunk = [0u8; FILE_CHUNK_CONTENT_PAYLOAD_LENGTH];
        let mut chunk_number: u64 = 0;
        loop {
            let read_bytes = input.read(&mut file_chunk)?;
            let encrypted_chunk = self.encrypt_chunk(
                file_header.nonce.as_ref(),
                file_header.payload.content_key.as_ref(),
                chunk_number,
                &file_chunk[..read_bytes],
            )?;
            output.write_all(&encrypted_chunk)?;
            if read_bytes < FILE_CHUNK_CONTENT_PAYLOAD_LENGTH {
                break;
            }
            chunk_number += 1;
        }
        Ok(())
    }

    /// Decrypts a data
    /// Decrypted data will be written to a output
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-content-encryption
    #[inline]
    pub fn decrypt_content<R: Read, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
    ) -> Result<(), CryptoError> {
        let mut header_bytes = [0u8; FILE_HEADER_LENGTH];
        input.read_exact(&mut header_bytes)?;
        let file_header = self.decrypt_file_header(&header_bytes)?;

        let mut file_chunk = [0u8; FILE_CHUNK_LENGTH];
        let mut chunk_number: u64 = 0;
        loop {
            let read_bytes = input.read(&mut file_chunk)?;
            let chunk_content = self.decrypt_chunk(
                file_header.nonce.as_ref(),
                file_header.payload.content_key.as_ref(),
                chunk_number,
                &file_chunk[..read_bytes],
            )?;
            output.write_all(&chunk_content)?;
            if read_bytes < FILE_CHUNK_CONTENT_PAYLOAD_LENGTH {
                break;
            }
            chunk_number += 1;
        }
        Ok(())
    }

    /// Encrypts a chunk of data using a header's nonce, a file_key and chunk_number
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-content-encryption
    pub fn encrypt_chunk(
        &self,
        header_nonce: &[u8],
        file_key: &[u8],
        chunk_number: u64,
        chunk_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if chunk_data.len() > FILE_CHUNK_CONTENT_PAYLOAD_LENGTH {
            return Err(InvalidFileChunkLength(format!(
                "file chunk can't be more than {} bytes length, got: {}",
                FILE_CHUNK_CONTENT_PAYLOAD_LENGTH,
                chunk_data.len()
            )));
        }
        let chunk_nonce = rand::thread_rng().gen::<[u8; FILE_CHUNK_CONTENT_NONCE_LENGTH]>();

        // Pre-allocate the vector with the exact size needed
        let mut encrypted_chunk = Vec::with_capacity(
            FILE_CHUNK_CONTENT_NONCE_LENGTH + chunk_data.len() + FILE_CHUNK_CONTENT_MAC_LENGTH,
        );
        
        // Use unsafe for performance-critical code to avoid bounds checking
        unsafe {
            let ptr = encrypted_chunk.as_mut_ptr();
            
            // Copy nonce
            std::ptr::copy_nonoverlapping(
                chunk_nonce.as_ptr(),
                ptr,
                FILE_CHUNK_CONTENT_NONCE_LENGTH,
            );
            
            // Copy chunk data
            std::ptr::copy_nonoverlapping(
                chunk_data.as_ptr(),
                ptr.add(FILE_CHUNK_CONTENT_NONCE_LENGTH),
                chunk_data.len(),
            );
            
            // Set the length of the vector
            encrypted_chunk.set_len(FILE_CHUNK_CONTENT_NONCE_LENGTH + chunk_data.len());
        }

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(file_key),
            GenericArray::from_slice(&chunk_nonce),
        );
        cipher.apply_keystream(&mut encrypted_chunk[FILE_CHUNK_CONTENT_NONCE_LENGTH..]);

        let chunk_number_be = chunk_number.to_be_bytes();

        let mut mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.vault.master_key.hmac_master_key)?;
        mac.update(header_nonce);
        mac.update(&chunk_number_be);
        mac.update(&encrypted_chunk);
        let mac_bytes = mac.finalize().into_bytes();

        encrypted_chunk.extend_from_slice(&mac_bytes);

        Ok(encrypted_chunk)
    }

    /// Decrypts a ciphered chunk of data using a header's nonce, a file_key and chunk_number
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-content-encryption
    pub fn decrypt_chunk(
        &self,
        header_nonce: &[u8],
        file_key: &[u8],
        chunk_number: u64,
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
        let payload_length = begin_of_mac - FILE_CHUNK_CONTENT_NONCE_LENGTH;

        let chunk_number_be = chunk_number.to_be_bytes();

        // check MAC
        let mut mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.vault.master_key.hmac_master_key)?;
        mac.update(header_nonce);
        mac.update(&chunk_number_be);
        mac.update(&encrypted_chunk[..begin_of_mac]);
        mac.verify(GenericArray::from_slice(&encrypted_chunk[begin_of_mac..]))?;

        // decrypt content
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(file_key),
            GenericArray::from_slice(&encrypted_chunk[..FILE_CHUNK_CONTENT_NONCE_LENGTH]),
        );
        
        // Pre-allocate vector with exact size needed
        let mut decrypted_content = Vec::with_capacity(payload_length);
        unsafe {
            decrypted_content.set_len(payload_length);
        }
        decrypted_content.copy_from_slice(&encrypted_chunk[FILE_CHUNK_CONTENT_NONCE_LENGTH..begin_of_mac]);
        cipher.apply_keystream(&mut decrypted_content);

        Ok(decrypted_content)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::crypto;
    use crate::crypto::Vault;
    use crate::providers::LocalFs;
    use std::io::Cursor;

    const PATH_TO_VAULT: &str = "tests/test_storage/vault.cryptomator";
    const DEFAULT_PASSWORD: &str = "12345678";

    const ROOT_DIR_ID_HASH: &str = "HIRW3L6XRAPFC2UCK5QY37Q2U552IRPE";
    const ROOT_DIR_ID: &[u8] = b"";

    const TEST_FILENAME: &str = "lorem-ipsum.pdf";
    const ENCRYPTED_TEST_FILENAME: &str = "fXQEfw6iSwP1esHbRznuVFZqv_LQFqNwC2r2LOQa-A==";

    #[test]
    fn test_encrypt_dir_id() {
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);
        let dir_id_hash = cryptor.get_dir_id_hash(ROOT_DIR_ID).unwrap();
        assert_eq!(ROOT_DIR_ID_HASH, dir_id_hash.as_str());
    }

    #[test]
    fn test_encrypt_filename() {
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);
        let encrypted_filename = cryptor
            .encrypt_filename(TEST_FILENAME, ROOT_DIR_ID)
            .unwrap();
        assert_eq!(ENCRYPTED_TEST_FILENAME, encrypted_filename.as_str())
    }

    #[test]
    fn test_decrypt_filename() {
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);
        let decrypted_filename = cryptor
            .decrypt_filename(ENCRYPTED_TEST_FILENAME, ROOT_DIR_ID)
            .unwrap();
        assert_eq!(TEST_FILENAME, decrypted_filename.as_str())
    }

    #[test]
    fn test_encrypt_decrypt_header() {
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);

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
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);

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
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);

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
