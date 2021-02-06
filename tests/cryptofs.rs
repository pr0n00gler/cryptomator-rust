use cryptomator::crypto;
use cryptomator::cryptofs::{CryptoFS, FileSystem};
use cryptomator::providers::{LocalFS, MemoryFS};
use std::io::Read;

const TEST_STORAGE_PATH: &str = "tests/test_storage/d";
const TEST_FILE_PATH: &str = "tests/lorem-ipsum.pdf";
const PATH_TO_MASTER_KEY: &str = "tests/test_storage/masterkey.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";
const VFS_STORAGE_PATH: &str = "/";

#[test]
fn test_crypto_fs_seek_and_read() {
    let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = LocalFS::new();
    let crypto_fs = CryptoFS::new(TEST_STORAGE_PATH, cryptor, local_fs.clone()).unwrap();

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
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = MemoryFS::new();
    let crypto_fs = CryptoFS::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

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
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = MemoryFS::new();
    let crypto_fs = CryptoFS::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    crypto_fs.create_file("/test.txt").unwrap();

    assert_eq!(crypto_fs.exists("/test.txt"), true);
    assert_eq!(crypto_fs.exists("/404.file"), false);
}

#[test]
fn test_crypto_fs_remove_dir() {
    //TODO: remake this test
    let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = MemoryFS::new();
    let crypto_fs = CryptoFS::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let dir_to_remove = "/dirs/to/remove";
    let files: [&str; 3] = [
        "/dirs/to/remove/file1.dat",
        "/dirs/to/remove/file2.dat",
        "/dirs/to/remove/file3.dat",
    ];

    crypto_fs.create_dir(dir_to_remove).unwrap();
    for f in files.iter() {
        crypto_fs.create_file(*f).unwrap();
    }
    crypto_fs.remove_dir("/dirs").unwrap();

    assert_eq!(crypto_fs.exists(dir_to_remove), false);
    for f in files.iter() {
        assert_eq!(crypto_fs.exists(*f), false);
    }
}

#[test]
fn test_crypto_fs_copy_file() {
    let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = MemoryFS::new();
    let crypto_fs = CryptoFS::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let file_to_copy = "/test.pdf";
    let copied_file = "/test-copy.pdf";

    let data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();

    let mut f = crypto_fs.create_file(file_to_copy).unwrap();
    f.write_all(data.as_slice()).unwrap();

    //test copy to the same folder
    crypto_fs.copy_file(file_to_copy, copied_file).unwrap();

    let mut file = crypto_fs.open_file(file_to_copy).unwrap();
    let mut data: Vec<u8> = vec![];
    file.read_to_end(&mut data).unwrap();

    let mut file_copy = crypto_fs.open_file(copied_file).unwrap();
    let mut data_copy: Vec<u8> = vec![];
    file_copy.read_to_end(&mut data_copy).unwrap();
    assert_eq!(data, data_copy);

    //test copy to another folder
    let dir_to_copy = "/dir-to-copy";
    let copied_file_full_path = "/dir-to-copy/test-copy.pdf";
    crypto_fs.create_dir(dir_to_copy).unwrap();
    crypto_fs
        .copy_file(file_to_copy, copied_file_full_path)
        .unwrap();
    let mut file_copy2 = crypto_fs.open_file(copied_file_full_path).unwrap();
    let mut data_copy2: Vec<u8> = vec![];
    file_copy2.read_to_end(&mut data_copy2).unwrap();
    assert_eq!(data, data_copy2);

    crypto_fs.remove_dir(dir_to_copy).unwrap();
    crypto_fs.remove_file(copied_file).unwrap();
}

#[test]
fn test_crypto_fs_move_file() {
    let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = MemoryFS::new();
    let crypto_fs = CryptoFS::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let file_to_move = "/test.dat";
    let moved_file = "/test_moved.dat";

    let data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();
    let mut test_file = crypto_fs.create_file(file_to_move).unwrap();
    test_file.write_all(data.as_slice()).unwrap();
    test_file.flush().unwrap();

    crypto_fs.move_file(file_to_move, moved_file).unwrap();
    let mut check_file = crypto_fs.open_file(moved_file).unwrap();
    let mut data_check: Vec<u8> = vec![];
    check_file.read_to_end(&mut data_check).unwrap();
    assert_eq!(data, data_check);

    let dir_for_moved_file = "/dir_for_moved_file";
    let moved_file_to_folder = "/dir_for_moved_file/test_moved_to_folder.dat";
    crypto_fs.create_dir(dir_for_moved_file).unwrap();

    crypto_fs
        .move_file(moved_file, moved_file_to_folder)
        .unwrap();
    let mut check_file = crypto_fs.open_file(moved_file_to_folder).unwrap();
    let mut data_check: Vec<u8> = vec![];
    check_file.read_to_end(&mut data_check).unwrap();
    assert_eq!(data, data_check);

    crypto_fs.remove_dir(dir_for_moved_file).unwrap();
}

#[test]
fn test_crypto_fs_move_dir() {
    let mk = crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = MemoryFS::new();
    let crypto_fs = CryptoFS::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let dir_to_move = "/dir1";
    let dirs_to_move = "/dir1/dir2";
    let test_filename = "/dir1/dir2/test.dat";
    let dest_dir = "/dest_dir";
    let moved_file_path = "/dest_dir/dir2/test.dat";

    crypto_fs.create_dir(dirs_to_move).unwrap();

    let data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();
    let mut test_file = crypto_fs.create_file(test_filename).unwrap();
    test_file.write_all(data.as_slice()).unwrap();
    test_file.flush().unwrap();

    crypto_fs.move_dir(dir_to_move, dest_dir).unwrap();
    let mut check_file = crypto_fs.open_file(moved_file_path).unwrap();
    let mut data_check: Vec<u8> = vec![];
    check_file.read_to_end(&mut data_check).unwrap();
    assert_eq!(data, data_check);
    crypto_fs.remove_dir(dest_dir).unwrap();

    //test move folder into folder
    let moved_file_path = "/dest_dir/dir1/dir2/test.dat";

    crypto_fs.create_dir(dirs_to_move).unwrap();
    crypto_fs.create_dir(dest_dir).unwrap();

    let data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();
    let mut test_file = crypto_fs.create_file(test_filename).unwrap();
    test_file.write_all(data.as_slice()).unwrap();
    test_file.flush().unwrap();

    crypto_fs.move_dir(dir_to_move, dest_dir).unwrap();
    let mut check_file = crypto_fs.open_file(moved_file_path).unwrap();
    let mut data_check: Vec<u8> = vec![];
    check_file.read_to_end(&mut data_check).unwrap();
    assert_eq!(data, data_check);
}
