mod masterkey;

use cryptomator::crypto;
use cryptomator::crypto::{Cryptor, MasterKey};
use masterkey::{DEFAULT_PASSWORD, PATH_TO_MASTER_KEY};

use std::io::Cursor;

const ROOT_DIR_ID_HASH: &str = "HIRW3L6XRAPFC2UCK5QY37Q2U552IRPE";
const ROOT_DIR_ID: &[u8] = b"";

const TEST_FILENAME: &str = "lorem-ipsum.pdf";
const ENCRYPTED_TEST_FILENAME: &str = "fXQEfw6iSwP1esHbRznuVFZqv_LQFqNwC2r2LOQa-A==";

fn get_test_master_key() -> MasterKey {
    crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap()
}

fn get_test_cryptor(mk: &MasterKey) -> Cryptor {
    Cryptor::new(mk)
}

#[test]
fn test_encrypt_dir_id() {
    let mk = get_test_master_key();
    let cryptor = get_test_cryptor(&mk);
    let dir_id_hash = cryptor.get_dir_id_hash(ROOT_DIR_ID).unwrap();
    assert_eq!(ROOT_DIR_ID_HASH, dir_id_hash.as_str());
}

#[test]
fn test_encrypt_filename() {
    let mk = get_test_master_key();
    let cryptor = get_test_cryptor(&mk);
    let encrypted_filename = cryptor
        .encrypt_filename(TEST_FILENAME, ROOT_DIR_ID)
        .unwrap();
    assert_eq!(ENCRYPTED_TEST_FILENAME, encrypted_filename.as_str())
}

#[test]
fn test_decrypt_filename() {
    let mk = get_test_master_key();
    let cryptor = get_test_cryptor(&mk);
    let decrypted_filename = cryptor
        .decrypt_filename(ENCRYPTED_TEST_FILENAME, ROOT_DIR_ID)
        .unwrap();
    assert_eq!(TEST_FILENAME, decrypted_filename.as_str())
}

#[test]
fn test_encrypt_decrypt_header() {
    let mk = get_test_master_key();
    let cryptor = get_test_cryptor(&mk);

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
    let mk = get_test_master_key();
    let cryptor = get_test_cryptor(&mk);

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
    let mk = get_test_master_key();
    let cryptor = get_test_cryptor(&mk);

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
