use cryptomator::crypto;
use cryptomator::cryptofs::{CryptoFS, FileSystem};
use cryptomator::providers::LocalFS;
use std::io::Read;

const TEST_STORAGE_PATH: &str = "tests/test_storage/d";
const TEST_FILE_PATH: &str = "tests/lorem-ipsum.pdf";
const PATH_TO_MASTER_KEY: &str = "tests/test_storage/masterkey.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";

#[test]
fn test_crypto_fs_seek_and_read() {
    let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(&mk);

    let local_fs = LocalFS::new();
    let crypto_fs = CryptoFS::new(TEST_STORAGE_PATH, &cryptor, &local_fs).unwrap();

    let mut cleartext_test_file = local_fs.open_file(TEST_FILE_PATH).unwrap();
    let cleartext_file_size = cleartext_test_file.seek(std::io::SeekFrom::End(0)).unwrap();

    let mut ciphertext_test_file = crypto_fs.open_file("/lorem-ipsum.pdf").unwrap();
    let ciphertext_file_size = ciphertext_test_file
        .seek(std::io::SeekFrom::End(0))
        .unwrap();
    assert_eq!(cleartext_file_size, ciphertext_file_size);

    let mut cleartext_data: Vec<u8> = vec![];
    let cleartext_read_count = cleartext_test_file
        .read_to_end(&mut cleartext_data)
        .unwrap();

    let mut ciphertext_data: Vec<u8> = vec![];
    let ciphertext_read_count = ciphertext_test_file
        .read_to_end(&mut ciphertext_data)
        .unwrap();
    assert_eq!(cleartext_read_count, ciphertext_read_count);
    assert_eq!(cleartext_data, ciphertext_data);

    const OFFSET: u64 = 4590;
    const SIZE: usize = 33600;
    cleartext_test_file
        .seek(std::io::SeekFrom::Start(OFFSET))
        .unwrap();
    let mut cleartext_part_data: Vec<u8> = vec![0; SIZE];
    let cleartext_read_count = cleartext_test_file.read(&mut cleartext_part_data).unwrap();

    ciphertext_test_file
        .seek(std::io::SeekFrom::Start(OFFSET))
        .unwrap();
    let mut ciphertext_part_data: Vec<u8> = vec![0; SIZE];
    let ciphertext_read_count = ciphertext_test_file
        .read(&mut ciphertext_part_data)
        .unwrap();
    assert_eq!(cleartext_read_count, ciphertext_read_count);
    assert_eq!(cleartext_part_data, ciphertext_part_data);
}

#[test]
fn test_crypto_fs_write() {
    let test_write_file: &str = "/test.dat";
    let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(&mk);

    let local_fs = LocalFS::new();
    let crypto_fs = CryptoFS::new(TEST_STORAGE_PATH, &cryptor, &local_fs).unwrap();

    let mut random_data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();

    let mut test_file = crypto_fs.create_file(test_write_file).unwrap();
    test_file.write_all(random_data.as_slice()).unwrap();
    test_file.flush().unwrap();

    let mut check_file = crypto_fs.open_file(test_write_file).unwrap();
    let mut check_data: Vec<u8> = vec![];
    let count = check_file.read_to_end(&mut check_data).unwrap();
    assert_eq!(count, random_data.len());
    assert_eq!(check_data, random_data);

    let slice_offset = 33405;
    let random_slice: Vec<u8> = (0..33415).map(|_| rand::random::<u8>()).collect();
    for (i, b) in random_slice.iter().enumerate() {
        random_data[i + slice_offset] = *b
    }
    let mut dat_file = crypto_fs.open_file(test_write_file).unwrap();
    dat_file
        .seek(std::io::SeekFrom::Start(slice_offset as u64))
        .unwrap();
    dat_file.write_all(&random_slice).unwrap();

    check_file.seek(std::io::SeekFrom::Start(0)).unwrap();
    let mut check_data: Vec<u8> = vec![];
    let count = check_file.read_to_end(&mut check_data).unwrap();
    assert_eq!(count, random_data.len());
    assert_eq!(check_data, random_data);

    crypto_fs.remove_file(test_write_file).unwrap();
}

#[test]
fn test_crypto_fs_exists() {
    let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(&mk);

    let local_fs = LocalFS::new();
    let crypto_fs = CryptoFS::new(TEST_STORAGE_PATH, &cryptor, &local_fs).unwrap();

    assert_eq!(crypto_fs.exists("/lorem-ipsum.pdf"), true);
    assert_eq!(crypto_fs.exists("/404.file"), false);
}
