mod masterkey;
mod cryptor;

use std::io::Cursor;
use cryptomator::cryptofs::{CryptoFS, FileSystem};
use cryptomator::providers::LocalFS;
use cryptor::{get_test_cryptor, get_test_master_key};

const TEST_STORAGE_PATH: &str = "tests/test_storage/d";
const TEST_FILE_PATH: &str = "tests/lorem-ipsum.pdf";

#[test]
fn test_crypto_fs_seek_and_read() {
    let mk = get_test_master_key();
    let cryptor = get_test_cryptor(&mk);

    let content_data: Vec<u8> = (0..10 * 1024 * 1024 + 6425)
        .map(|_| rand::random::<u8>())
        .collect();
    let mut raw_content_reader = Cursor::new(content_data);

    let local_fs = LocalFS::new();
    let crypto_fs = CryptoFS::new(TEST_STORAGE_PATH, &cryptor, &local_fs).unwrap();

    let mut cleartext_test_file = local_fs.open_file(TEST_FILE_PATH).unwrap();
    let cleartext_file_size = cleartext_test_file.seek(std::io::SeekFrom::End(0)).unwrap();

    let mut ciphertext_test_file = crypto_fs.open_file("/lorem-ipsum.pdf").unwrap();
    let ciphertext_file_size = ciphertext_test_file.seek(std::io::SeekFrom::End(0)).unwrap();

    println!("{}, {}", cleartext_file_size, ciphertext_file_size);
}