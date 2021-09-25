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
use sha1::{Digest, Sha1};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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

const U64_SIZE: usize = 8;

/// Calculates the size of the cleartext payload by ciphertext
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

pub fn shorten_name<P: AsRef<str>>(name: P) -> String {
    let mut hasher = Sha1::new();
    hasher.update(name.as_ref().as_bytes());
    base64::encode_config(hasher.finalize().as_slice(), base64::URL_SAFE)
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
    master_key: MasterKey,
}

impl Cryptor {
    /// Creates a new cryptor instance
    pub fn new(master_key: MasterKey) -> Cryptor {
        Cryptor { master_key }
    }

    /// Returns hash of the directory by a provided unique dir_id
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#directory-ids
    pub fn get_dir_id_hash(&self, dir_id: &[u8]) -> Result<String, CryptoError> {
        let mut long_key: Vec<u8> = Vec::with_capacity(AES_SIV_KEY_LENGTH);
        long_key.extend(&self.master_key.hmac_master_key);
        long_key.extend(&self.master_key.primary_master_key);
        let aes_siv_key = GenericArray::clone_from_slice(long_key.as_slice());

        let mut cipher = Aes256Siv::new(aes_siv_key);
        let encrypted_dir_id = cipher.encrypt(iter::empty::<&[u8]>(), dir_id)?;

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(encrypted_dir_id.as_slice());
        let sha1_hash = sha1_hasher.finalize();
        let dir_id_hash_base32_encoded = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            sha1_hash.as_slice(),
        );
        Ok(dir_id_hash_base32_encoded)
    }

    /// Encrypts a filename using a parent dir_id
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#filename-encryption
    pub fn encrypt_filename<S: AsRef<str>>(
        &self,
        cleartext_name: S,
        parent_dir_id: &[u8],
    ) -> Result<String, CryptoError> {
        let mut long_key: Vec<u8> = Vec::with_capacity(AES_SIV_KEY_LENGTH);
        long_key.extend(&self.master_key.hmac_master_key);
        long_key.extend(&self.master_key.primary_master_key);
        let aes_siv_key = GenericArray::clone_from_slice(long_key.as_slice());

        let mut cipher = Aes256Siv::new(aes_siv_key);
        let encrypted_filename =
            cipher.encrypt(&[parent_dir_id], cleartext_name.as_ref().as_bytes())?;

        let encoded_ciphertext = base64::encode_config(encrypted_filename, base64::URL_SAFE);
        Ok(encoded_ciphertext)
    }

    /// Decrypts a ciphertext filename using a parent dir_id
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#filename-encryption
    pub fn decrypt_filename<S: AsRef<str>>(
        &self,
        encrypted_filename: S,
        parent_dir_id: &[u8],
    ) -> Result<String, CryptoError> {
        let encrypted_filename_bytes =
            base64::decode_config(encrypted_filename.as_ref(), base64::URL_SAFE)?;

        let mut long_key: Vec<u8> = Vec::with_capacity(AES_SIV_KEY_LENGTH);
        long_key.extend(&self.master_key.hmac_master_key);
        long_key.extend(&self.master_key.primary_master_key);

        let aes_siv_key = GenericArray::clone_from_slice(long_key.as_slice());

        let mut cipher = Aes256Siv::new(aes_siv_key);

        let decrypted_filename =
            cipher.decrypt(&[parent_dir_id], encrypted_filename_bytes.as_slice())?;

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
        let mut encrypted_header: Vec<u8> = Vec::with_capacity(FILE_HEADER_LENGTH);

        let mut payload: Vec<u8> = Vec::with_capacity(
            file_header.payload.reserved.len() + file_header.payload.content_key.len(),
        );
        payload.extend_from_slice(&file_header.payload.reserved);
        payload.extend_from_slice(&file_header.payload.content_key);

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(&self.master_key.primary_master_key),
            GenericArray::from_slice(file_header.nonce.as_ref()),
        );
        cipher.apply_keystream(&mut payload);

        let mut mac_payload: Vec<u8> = Vec::with_capacity(FILE_HEADER_MAC_LENGTH);
        mac_payload.extend_from_slice(&file_header.nonce);
        mac_payload.extend(&payload);
        let mut mac = HmacSha256::new_varkey(&self.master_key.hmac_master_key)?;
        mac.update(mac_payload.as_slice());
        let mac_bytes = mac.finalize().into_bytes();

        encrypted_header.extend_from_slice(&file_header.nonce);
        encrypted_header.extend_from_slice(payload.as_slice());
        encrypted_header.extend_from_slice(mac_bytes.as_slice());

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
        let mut mac = HmacSha256::new_varkey(&self.master_key.hmac_master_key)?;
        let mut payload_to_verify = Vec::with_capacity(FILE_HEADER_LENGTH); // nonce + ciphertext
        payload_to_verify.extend(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]); // nonce
        payload_to_verify.extend(
            &encrypted_header
                [FILE_HEADER_NONCE_LENGTH..FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH],
        ); // encrypted payload
        mac.update(payload_to_verify.as_slice());
        mac.verify(&encrypted_header[FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH..])?;

        //decrypt header payload
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(&self.master_key.primary_master_key),
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

    /// Encrypts a data
    /// Encrypted data will be written to a output
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-content-encryption
    pub fn encrypt_content<R: Read, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
    ) -> Result<(), CryptoError> {
        let file_header = self.create_file_header();
        let encrypted_header = self.encrypt_file_header(&file_header)?;
        output.write_all(encrypted_header.as_slice())?;

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
            output.write_all(encrypted_chunk.as_slice())?;
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
            output.write_all(chunk_content.as_slice())?;
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

        let mut encrypted_chunk: Vec<u8> = Vec::with_capacity(
            chunk_nonce.len() + chunk_data.len() + FILE_CHUNK_CONTENT_MAC_LENGTH,
        );
        encrypted_chunk.extend_from_slice(&chunk_nonce);
        encrypted_chunk.extend_from_slice(chunk_data);

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(file_key),
            GenericArray::from_slice(&chunk_nonce),
        );
        cipher.apply_keystream(&mut encrypted_chunk[FILE_CHUNK_CONTENT_NONCE_LENGTH..]);

        let mut mac_payload: Vec<u8> = Vec::with_capacity(
            header_nonce.len() + U64_SIZE + chunk_nonce.len() + chunk_data.len(),
        );
        mac_payload.extend_from_slice(header_nonce);
        mac_payload.write_u64::<BigEndian>(chunk_number)?;
        mac_payload.extend_from_slice(&encrypted_chunk);

        let mut mac = HmacSha256::new_varkey(&self.master_key.hmac_master_key)?;
        mac.update(mac_payload.as_slice());
        let mac_bytes = mac.finalize().into_bytes();

        encrypted_chunk.extend_from_slice(mac_bytes.as_slice());

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

        let mut chunk_number_big_endian = Vec::with_capacity(U64_SIZE);
        chunk_number_big_endian.write_u64::<BigEndian>(chunk_number as u64)?;

        // check MAC
        let mut mac = HmacSha256::new_varkey(&self.master_key.hmac_master_key)?;
        let mut payload_to_verify = Vec::with_capacity(
            header_nonce.len()
                + chunk_number_big_endian.len()
                + encrypted_chunk[..begin_of_mac].len(),
        ); // header_nonce + chunk_number + chunk_nonce + ciphertext
        payload_to_verify.extend(header_nonce); // header_nonce
        payload_to_verify.extend(chunk_number_big_endian); // chunk_number
                                                           // payload_to_verify.extend(&encrypted_chunk[..FILE_CHUNK_CONTENT_NONCE_LENGTH]); // chunk_nonce
        payload_to_verify.extend(&encrypted_chunk[..begin_of_mac]); // ciphertext
        mac.update(payload_to_verify.as_slice());
        mac.verify(&encrypted_chunk[begin_of_mac..])?;

        // decrypt content
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(file_key),
            GenericArray::from_slice(&encrypted_chunk[..FILE_HEADER_NONCE_LENGTH]),
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
        let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
        let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(mk);
        let dir_id_hash = cryptor.get_dir_id_hash(ROOT_DIR_ID).unwrap();
        assert_eq!(ROOT_DIR_ID_HASH, dir_id_hash.as_str());
    }

    #[test]
    fn test_encrypt_filename() {
        let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
        let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(mk);
        let encrypted_filename = cryptor
            .encrypt_filename(TEST_FILENAME, ROOT_DIR_ID)
            .unwrap();
        assert_eq!(ENCRYPTED_TEST_FILENAME, encrypted_filename.as_str())
    }

    #[test]
    fn test_decrypt_filename() {
        let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
        let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(mk);
        let decrypted_filename = cryptor
            .decrypt_filename(ENCRYPTED_TEST_FILENAME, ROOT_DIR_ID)
            .unwrap();
        assert_eq!(TEST_FILENAME, decrypted_filename.as_str())
    }

    #[test]
    fn test_encrypt_decrypt_header() {
        let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
        let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(mk);

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
        let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
        let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(mk);

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
        let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
        let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(mk);

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
