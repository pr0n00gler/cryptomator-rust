use crate::crypto::error::CryptoError;
use crate::crypto::Vault;

use std::fmt;
use std::io::{Read, Write};
use std::iter;

use rand::Rng;

use aes::Aes256;
use aes_siv::siv::Aes256Siv;
use aes_siv::{aead::generic_array::GenericArray, KeyInit};
use base32::Alphabet;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use ctr::cipher::{KeyIvInit, StreamCipher};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

/// Contains reserved bytes and the per-file AES-CTR content key.
///
/// `ZeroizeOnDrop` ensures the `content_key` bytes are deterministically
/// wiped from memory when this value is dropped — preventing the plaintext
/// key from lingering in heap or stack memory after the struct's lifetime
/// ends (e.g. readable via crash dump, swap partition, or memory scan).
///
/// `Debug` is implemented manually to avoid ever printing raw key bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileHeaderPayload {
    pub reserved: [u8; FILE_HEADER_PAYLOAD_RESERVED_LENGTH],
    /// Per-file AES-CTR key.  Wrapped in `Zeroizing` so the 32 key bytes are
    /// wiped on drop in addition to the outer `ZeroizeOnDrop` on the struct.
    pub content_key: Zeroizing<[u8; FILE_HEADER_PAYLOAD_CONTENT_KEY_LENGTH]>,
}

impl fmt::Debug for FileHeaderPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose key material in debug output.
        f.debug_struct("FileHeaderPayload")
            .field("reserved", &self.reserved)
            .field("content_key", &"[REDACTED]")
            .finish()
    }
}

/// Contains nonce, payload and mac.
///
/// `ZeroizeOnDrop` is inherited through `FileHeaderPayload` and ensures all
/// sensitive fields are wiped when the header is dropped.
///
/// `Debug` is implemented manually to prevent transitive leakage of the
/// `content_key` through `FileHeaderPayload`'s fields.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileHeader {
    pub nonce: [u8; FILE_HEADER_NONCE_LENGTH],
    pub payload: FileHeaderPayload,
    pub mac: [u8; FILE_HEADER_MAC_LENGTH],
}

impl fmt::Debug for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Expose only non-sensitive fields.
        f.debug_struct("FileHeader")
            .field("nonce", &self.nonce)
            .field("payload", &self.payload)
            .field("mac", &self.mac)
            .finish()
    }
}

/// The core crypto instance to encrypt/decrypt data.
///
/// `Copy` is intentionally absent: `Vault` embeds a `MasterKey` whose fields
/// are `Zeroizing<[u8; 32]>`, which is non-`Copy` by design to prevent silent
/// proliferation of key material on the stack.
///
/// `Debug` is intentionally implemented manually (not derived) because `Vault`
/// embeds `MasterKey`, and a derived `Debug` would transitively print raw key
/// bytes via `Zeroizing<[u8; 32]>`'s `Debug` impl.
#[derive(Clone)]
pub struct Cryptor {
    pub vault: Vault,
}

impl fmt::Debug for Cryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose key material in debug output.
        f.debug_struct("Cryptor").finish_non_exhaustive()
    }
}

impl Cryptor {
    /// Fills a caller-supplied `Zeroizing` buffer with the 64-byte AES-SIV key
    /// (hmac_master_key ‖ primary_master_key).
    ///
    /// Accepting `&mut Zeroizing<[u8; AES_SIV_KEY_LENGTH]>` ensures the
    /// assembled key is deterministically wiped when the *caller's* binding
    /// goes out of scope, preventing the 64-byte key from persisting on the
    /// stack after use.
    #[inline]
    fn fill_aes_siv_key(&self, out: &mut Zeroizing<[u8; AES_SIV_KEY_LENGTH]>) {
        let hmac_key = self.vault.master_key.hmac_master_key.as_ref();
        let primary_key = self.vault.master_key.primary_master_key.as_ref();

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
        let mut long_key = Zeroizing::new([0u8; AES_SIV_KEY_LENGTH]);
        self.fill_aes_siv_key(&mut long_key);

        let mut cipher = Aes256Siv::new(GenericArray::from_slice(long_key.as_ref()));
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
        let mut long_key = Zeroizing::new([0u8; AES_SIV_KEY_LENGTH]);
        self.fill_aes_siv_key(&mut long_key);

        let mut cipher = Aes256Siv::new(GenericArray::from_slice(long_key.as_ref()));
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

        let mut long_key = Zeroizing::new([0u8; AES_SIV_KEY_LENGTH]);
        self.fill_aes_siv_key(&mut long_key);

        let mut cipher = Aes256Siv::new(GenericArray::from_slice(long_key.as_ref()));

        let decrypted_filename =
            cipher.decrypt([parent_dir_id], encrypted_filename_bytes.as_slice())?;

        Ok(String::from_utf8(decrypted_filename)?)
    }

    /// Returns a new FileHeader with a freshly generated random content key.
    pub fn create_file_header(&self) -> FileHeader {
        FileHeader {
            nonce: rand::thread_rng().gen::<[u8; FILE_HEADER_NONCE_LENGTH]>(),
            payload: FileHeaderPayload {
                reserved: [0xFu8; FILE_HEADER_PAYLOAD_RESERVED_LENGTH],
                // Wrap in Zeroizing so the random key bytes are wiped when
                // FileHeaderPayload (and its enclosing FileHeader) is dropped.
                content_key: Zeroizing::new(
                    rand::thread_rng().gen::<[u8; FILE_HEADER_PAYLOAD_CONTENT_KEY_LENGTH]>(),
                ),
            },
            mac: [0u8; FILE_HEADER_MAC_LENGTH],
        }
    }

    /// Encrypts a FileHeader
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-header-encryption
    pub fn encrypt_file_header(&self, file_header: &FileHeader) -> Result<Vec<u8>, CryptoError> {
        let mut encrypted_header = Vec::with_capacity(FILE_HEADER_LENGTH);

        // Assemble the plaintext payload (reserved || content_key) in a
        // Zeroizing buffer so the 40 bytes of key material are deterministically
        // wiped from memory when this binding goes out of scope — preventing
        // them from lingering on the stack after `encrypt_file_header` returns.
        let mut payload = Zeroizing::new([0u8; FILE_HEADER_PAYLOAD_LENGTH]);
        payload[..FILE_HEADER_PAYLOAD_RESERVED_LENGTH]
            .copy_from_slice(&file_header.payload.reserved);
        payload[FILE_HEADER_PAYLOAD_RESERVED_LENGTH..]
            .copy_from_slice(file_header.payload.content_key.as_ref());

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(self.vault.master_key.primary_master_key.as_ref()),
            GenericArray::from_slice(&file_header.nonce),
        );
        cipher.apply_keystream(payload.as_mut());

        let mut mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(self.vault.master_key.hmac_master_key.as_ref())?;
        mac.update(&file_header.nonce);
        mac.update(payload.as_ref());
        let mac_bytes = mac.finalize().into_bytes();

        encrypted_header.extend_from_slice(&file_header.nonce);
        encrypted_header.extend_from_slice(payload.as_ref());
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
            <Hmac<Sha256> as Mac>::new_from_slice(self.vault.master_key.hmac_master_key.as_ref())?;
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
            GenericArray::from_slice(self.vault.master_key.primary_master_key.as_ref()),
            GenericArray::from_slice(&encrypted_header[..FILE_HEADER_NONCE_LENGTH]),
        );
        // Wrap in Zeroizing so the 40 bytes of plaintext key material
        // (reserved || content_key) are deterministically wiped from the
        // stack/heap when this binding goes out of scope, regardless of
        // whether the function returns normally or via `?`.
        let mut decrypted_payload = Zeroizing::new([0u8; FILE_HEADER_PAYLOAD_LENGTH]);
        decrypted_payload.copy_from_slice(
            &encrypted_header
                [FILE_HEADER_NONCE_LENGTH..FILE_HEADER_NONCE_LENGTH + FILE_HEADER_PAYLOAD_LENGTH],
        );
        cipher.apply_keystream(decrypted_payload.as_mut());

        let file_header_payload = FileHeaderPayload {
            reserved: clone_into_array(&decrypted_payload[..FILE_HEADER_PAYLOAD_RESERVED_LENGTH]),
            // The content_key bytes are copied out of the Zeroizing buffer and
            // re-wrapped in their own Zeroizing so they remain protected for
            // the full lifetime of the FileHeader.
            content_key: Zeroizing::new(clone_into_array(
                &decrypted_payload[FILE_HEADER_PAYLOAD_RESERVED_LENGTH..],
            )),
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
        let mut output_buffer = [0u8; FILE_CHUNK_LENGTH];
        let mut chunk_number: u64 = 0;
        loop {
            let read_bytes = input.read(&mut file_chunk)?;

            // A 0-byte read signals true EOF.  We must check *before* calling
            // encrypt_chunk: if we passed a 0-byte slice through we would write
            // a spurious empty authenticated chunk, corrupting the ciphertext
            // for any file whose cleartext size is an exact multiple of
            // FILE_CHUNK_CONTENT_PAYLOAD_LENGTH (32,768 bytes).  The
            // corresponding decrypt_content loop would then attempt to verify
            // and decrypt that phantom chunk, producing a MAC error or
            // returning unexpected trailing zero bytes.
            if read_bytes == 0 {
                break;
            }

            let written = self.encrypt_chunk(
                file_header.nonce.as_ref(),
                file_header.payload.content_key.as_ref(),
                chunk_number,
                &file_chunk[..read_bytes],
                &mut output_buffer,
            )?;
            output.write_all(&output_buffer[..written])?;

            // Increment chunk_number unconditionally after each successful
            // write, then break if this was a partial (last) chunk.
            chunk_number += 1;
            if read_bytes < FILE_CHUNK_CONTENT_PAYLOAD_LENGTH {
                break;
            }
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
        let mut output_buffer = [0u8; FILE_CHUNK_CONTENT_PAYLOAD_LENGTH];
        let mut chunk_number: u64 = 0;
        loop {
            let read_bytes = input.read(&mut file_chunk)?;

            // A 0-byte read signals true EOF.  We must check *before* calling
            // decrypt_chunk: if we passed a 0-byte slice through we would
            // return an InvalidFileChunkLength error for any file whose
            // ciphertext size is an exact multiple of FILE_CHUNK_LENGTH
            // (32,816 bytes).  This mirrors the identical guard in
            // encrypt_content and is the fix for SEC-1.
            if read_bytes == 0 {
                break;
            }

            let written = self.decrypt_chunk(
                file_header.nonce.as_ref(),
                file_header.payload.content_key.as_ref(),
                chunk_number,
                &file_chunk[..read_bytes],
                &mut output_buffer,
            )?;
            output.write_all(&output_buffer[..written])?;
            // The loop must terminate when the read returns fewer bytes than a
            // full *encrypted* chunk (FILE_CHUNK_LENGTH = 32,816), not fewer
            // than a full *plaintext* chunk (FILE_CHUNK_CONTENT_PAYLOAD_LENGTH
            // = 32,768).  Using the plaintext constant here was a bug: any
            // short read returning between 32,768 and 32,815 bytes — a valid
            // outcome from a buffered Read impl — would have silently truncated
            // the decrypted output.
            if read_bytes < FILE_CHUNK_LENGTH {
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
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if chunk_data.len() > FILE_CHUNK_CONTENT_PAYLOAD_LENGTH {
            return Err(InvalidFileChunkLength(format!(
                "file chunk can't be more than {} bytes length, got: {}",
                FILE_CHUNK_CONTENT_PAYLOAD_LENGTH,
                chunk_data.len()
            )));
        }

        let required_len =
            FILE_CHUNK_CONTENT_NONCE_LENGTH + chunk_data.len() + FILE_CHUNK_CONTENT_MAC_LENGTH;
        if output.len() < required_len {
            return Err(InvalidFileChunkLength(format!(
                "output buffer too small, need {} bytes, got: {}",
                required_len,
                output.len()
            )));
        }

        let chunk_nonce = rand::thread_rng().gen::<[u8; FILE_CHUNK_CONTENT_NONCE_LENGTH]>();

        output[..FILE_CHUNK_CONTENT_NONCE_LENGTH].copy_from_slice(&chunk_nonce);

        // Copy data to output buffer where it will be encrypted in place
        let payload_end = FILE_CHUNK_CONTENT_NONCE_LENGTH + chunk_data.len();
        output[FILE_CHUNK_CONTENT_NONCE_LENGTH..payload_end].copy_from_slice(chunk_data);

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(file_key),
            GenericArray::from_slice(&chunk_nonce),
        );
        cipher.apply_keystream(&mut output[FILE_CHUNK_CONTENT_NONCE_LENGTH..payload_end]);

        let chunk_number_be = chunk_number.to_be_bytes();

        let mut mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(self.vault.master_key.hmac_master_key.as_ref())?;
        mac.update(header_nonce);
        mac.update(&chunk_number_be);
        mac.update(&output[..payload_end]);
        let mac_bytes = mac.finalize().into_bytes();

        let mac_end = payload_end + FILE_CHUNK_CONTENT_MAC_LENGTH;
        output[payload_end..mac_end].copy_from_slice(&mac_bytes);

        Ok(mac_end)
    }

    /// Decrypts a ciphered chunk of data using a header's nonce, a file_key and chunk_number
    /// More info: https://docs.cryptomator.org/en/latest/security/architecture/#file-content-encryption
    pub fn decrypt_chunk(
        &self,
        header_nonce: &[u8],
        file_key: &[u8],
        chunk_number: u64,
        encrypted_chunk: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if encrypted_chunk.len() < FILE_CHUNK_CONTENT_MAC_LENGTH + FILE_CHUNK_CONTENT_NONCE_LENGTH {
            return Err(InvalidFileChunkLength(format!(
                "file chunk must be more than {} bytes length, got: {}",
                FILE_CHUNK_CONTENT_MAC_LENGTH + FILE_CHUNK_CONTENT_NONCE_LENGTH,
                encrypted_chunk.len()
            )));
        }

        let begin_of_mac = encrypted_chunk.len() - FILE_CHUNK_CONTENT_MAC_LENGTH;
        let payload_length = begin_of_mac - FILE_CHUNK_CONTENT_NONCE_LENGTH;

        if output.len() < payload_length {
            return Err(InvalidFileChunkLength(format!(
                "output buffer too small, need {} bytes, got: {}",
                payload_length,
                output.len()
            )));
        }

        let chunk_number_be = chunk_number.to_be_bytes();

        // check MAC
        let mut mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(self.vault.master_key.hmac_master_key.as_ref())?;
        mac.update(header_nonce);
        mac.update(&chunk_number_be);
        mac.update(&encrypted_chunk[..begin_of_mac]);
        mac.verify(GenericArray::from_slice(&encrypted_chunk[begin_of_mac..]))?;

        // decrypt content
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(file_key),
            GenericArray::from_slice(&encrypted_chunk[..FILE_CHUNK_CONTENT_NONCE_LENGTH]),
        );

        // Copy encrypted content to output buffer
        output[..payload_length]
            .copy_from_slice(&encrypted_chunk[FILE_CHUNK_CONTENT_NONCE_LENGTH..begin_of_mac]);

        // Decrypt in place
        cipher.apply_keystream(&mut output[..payload_length]);

        Ok(payload_length)
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

        let mut encrypted_chunk = vec![0u8; super::FILE_CHUNK_LENGTH];
        let encrypted_len = cryptor
            .encrypt_chunk(
                header.nonce.as_ref(),
                header.payload.content_key.as_ref(),
                0,
                chunk_data.as_slice(),
                &mut encrypted_chunk,
            )
            .unwrap();

        let mut decrypted_chunk = vec![0u8; chunk_data.len()];
        let decrypted_len = cryptor
            .decrypt_chunk(
                header.nonce.as_ref(),
                header.payload.content_key.as_ref(),
                0,
                &encrypted_chunk[..encrypted_len],
                &mut decrypted_chunk,
            )
            .unwrap();

        assert_eq!(chunk_data, decrypted_chunk[..decrypted_len]);
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

    /// Regression test for the spurious empty terminal chunk bug.
    ///
    /// When the cleartext size is an exact multiple of
    /// `FILE_CHUNK_CONTENT_PAYLOAD_LENGTH` (32,768 bytes), the old loop read
    /// a 0-byte final chunk and encrypted it, producing a phantom MAC'd empty
    /// chunk at the end of the ciphertext.  `decrypt_content` would then try
    /// to authenticate and decrypt that phantom chunk, corrupting the output.
    ///
    /// This test pins the exact boundary condition: 2 × 32,768 = 65,536 bytes.
    #[test]
    fn test_encrypt_decrypt_content_exact_chunk_multiple() {
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);

        // Exactly two full chunks — the boundary that previously triggered the bug.
        let content_data: Vec<u8> = (0..2 * super::FILE_CHUNK_CONTENT_PAYLOAD_LENGTH)
            .map(|_| rand::random::<u8>())
            .collect();
        let mut raw_content_reader = Cursor::new(content_data.clone());

        let mut encrypted_content = Cursor::new(Vec::new());
        let mut decrypted_content = Cursor::new(Vec::new());

        cryptor
            .encrypt_content(&mut raw_content_reader, &mut encrypted_content)
            .unwrap();

        // The ciphertext must be exactly: header + 2 full encrypted chunks.
        // Any extra bytes indicate a phantom trailing chunk was written.
        let expected_ciphertext_len = super::FILE_HEADER_LENGTH + 2 * super::FILE_CHUNK_LENGTH;
        assert_eq!(
            encrypted_content.get_ref().len(),
            expected_ciphertext_len,
            "ciphertext length mismatch: spurious terminal chunk may have been written"
        );

        encrypted_content.set_position(0);
        cryptor
            .decrypt_content(&mut encrypted_content, &mut decrypted_content)
            .unwrap();

        assert_eq!(&content_data, decrypted_content.get_ref());
    }

    /// Regression test: a single exact full chunk (1 × FILE_CHUNK_CONTENT_PAYLOAD_LENGTH).
    ///
    /// Before the SEC-1 fix, `decrypt_content` would loop back after the first
    /// full-chunk read, call `read` again (getting 0 bytes), and immediately
    /// pass a 0-length slice to `decrypt_chunk`, which returned
    /// `InvalidFileChunkLength`.  This test pins that exact single-chunk
    /// boundary in addition to the two-chunk case above.
    #[test]
    fn test_encrypt_decrypt_content_single_exact_chunk() {
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);

        // Exactly one full chunk — the smallest exact-multiple boundary.
        let content_data: Vec<u8> = (0..super::FILE_CHUNK_CONTENT_PAYLOAD_LENGTH)
            .map(|_| rand::random::<u8>())
            .collect();
        let mut raw_content_reader = Cursor::new(content_data.clone());

        let mut encrypted_content = Cursor::new(Vec::new());
        let mut decrypted_content = Cursor::new(Vec::new());

        cryptor
            .encrypt_content(&mut raw_content_reader, &mut encrypted_content)
            .unwrap();

        // Ciphertext must be: header + exactly 1 encrypted chunk, no more.
        let expected_ciphertext_len = super::FILE_HEADER_LENGTH + super::FILE_CHUNK_LENGTH;
        assert_eq!(
            encrypted_content.get_ref().len(),
            expected_ciphertext_len,
            "ciphertext length mismatch: spurious terminal chunk may have been written"
        );

        encrypted_content.set_position(0);
        cryptor
            .decrypt_content(&mut encrypted_content, &mut decrypted_content)
            .unwrap();

        assert_eq!(&content_data, decrypted_content.get_ref());
    }

    /// Regression test: empty file (0-byte cleartext).
    ///
    /// An empty file produces ciphertext containing only the file header and
    /// zero chunks.  Both `encrypt_content` and `decrypt_content` must handle
    /// this without errors or spurious output.
    #[test]
    fn test_encrypt_decrypt_content_empty_file() {
        let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
        let cryptor = crypto::Cryptor::new(vault);

        let content_data: Vec<u8> = vec![];
        let mut raw_content_reader = Cursor::new(content_data.clone());

        let mut encrypted_content = Cursor::new(Vec::new());
        let mut decrypted_content = Cursor::new(Vec::new());

        cryptor
            .encrypt_content(&mut raw_content_reader, &mut encrypted_content)
            .unwrap();

        // An empty file produces only the file header, no chunk bytes at all.
        assert_eq!(
            encrypted_content.get_ref().len(),
            super::FILE_HEADER_LENGTH,
            "empty file should produce only the file header, no chunk bytes"
        );

        encrypted_content.set_position(0);
        cryptor
            .decrypt_content(&mut encrypted_content, &mut decrypted_content)
            .unwrap();

        assert!(
            decrypted_content.get_ref().is_empty(),
            "decrypting an empty file should produce zero output bytes"
        );
    }
}
