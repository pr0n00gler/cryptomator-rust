use cryptomator::crypto;
use cryptomator::crypto::{Vault, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH};
use cryptomator::cryptofs::{CryptoFs, FileSystem, OpenOptions};
use cryptomator::providers::{LocalFs, MemoryFs};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::io::{Read, Seek, Write};
use std::path::Path;

const TEST_STORAGE_PATH: &str = "tests/test_storage/d";
const TEST_FILE_PATH: &str = "tests/lorem-ipsum.pdf";
const PATH_TO_VAULT: &str = "tests/test_storage/vault.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";
const VFS_STORAGE_PATH: &str = "/";

fn random_alphanumeric_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .take(len)
        .collect()
}

#[test]
fn test_crypto_fs_seek_and_read() {
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = LocalFs::new();
    let crypto_fs = CryptoFs::new(TEST_STORAGE_PATH, cryptor, local_fs.clone()).unwrap();

    let mut cleartext_test_file = local_fs
        .open_file(TEST_FILE_PATH, OpenOptions::new())
        .unwrap();
    let cleartext_file_size = cleartext_test_file.seek(std::io::SeekFrom::End(0)).unwrap();

    let mut ciphertext_test_file = crypto_fs
        .open_file("/lorem-ipsum.pdf", OpenOptions::new())
        .unwrap();
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
    crypto_fs_write("/test.dat");
    let long_name = random_alphanumeric_string(300);
    crypto_fs_write("/".to_string() + long_name.as_str());
}

#[test]
fn test_crypto_fs_sparse_write_and_read() {
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let file_path = "/sparse.dat";
    let mut file = crypto_fs.create_file(file_path).unwrap();

    let offset = (FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64 * 2) + 123;
    let payload = b"after-gap";

    file.seek(std::io::SeekFrom::Start(offset)).unwrap();
    file.write_all(payload).unwrap();
    file.flush().unwrap();
    drop(file);

    let mut reader = crypto_fs.open_file(file_path, OpenOptions::new()).unwrap();

    let mut data = Vec::new();
    reader.read_to_end(&mut data).unwrap();

    assert_eq!(data.len(), offset as usize + payload.len());
    assert!(data[..offset as usize].iter().all(|&b| b == 0));
    assert_eq!(&data[offset as usize..], payload);
}

fn crypto_fs_write<P: AsRef<Path>>(filename: P) {
    let test_write_file: P = filename;
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let mut random_data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();

    let mut test_file = crypto_fs.create_file(&test_write_file).unwrap();
    test_file.write_all(random_data.as_slice()).unwrap();
    test_file.flush().unwrap();

    let mut check_file = crypto_fs
        .open_file(&test_write_file, OpenOptions::new())
        .unwrap();
    let mut check_data: Vec<u8> = vec![];
    let count = check_file.read_to_end(&mut check_data).unwrap();
    assert_eq!(count, random_data.len());
    assert_eq!(check_data, random_data);

    let slice_offset = 33405;
    let random_slice: Vec<u8> = (0..33415).map(|_| rand::random::<u8>()).collect();
    for (i, b) in random_slice.iter().enumerate() {
        random_data[i + slice_offset] = *b
    }
    let mut dat_file = crypto_fs
        .open_file(&test_write_file, *OpenOptions::new().write(true))
        .unwrap();
    dat_file
        .seek(std::io::SeekFrom::Start(slice_offset as u64))
        .unwrap();
    dat_file.write_all(&random_slice).unwrap();

    check_file.seek(std::io::SeekFrom::Start(0)).unwrap();
    let mut check_data: Vec<u8> = vec![];
    let count = check_file.read_to_end(&mut check_data).unwrap();
    assert_eq!(count, random_data.len());
    assert_eq!(check_data, random_data);

    crypto_fs.remove_file(&test_write_file).unwrap();
}

#[test]
fn test_crypto_fs_exists() {
    crypto_fs_exists("/test.txt");
    let long_name = random_alphanumeric_string(300);
    crypto_fs_exists("/".to_string() + long_name.as_str());
}

fn crypto_fs_exists<P: AsRef<Path>>(filename: P) {
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    crypto_fs.create_file(&filename).unwrap();

    assert!(crypto_fs.exists(&filename));
    assert!(!crypto_fs.exists("/404.file"));
}

#[test]
fn test_crypto_fs_remove_dir() {
    crypto_fs_remove_dir(
        vec![
            "/dirs/to/remove/file1.dat",
            "/dirs/to/remove/file2.dat",
            "/dirs/to/remove/file3.dat",
        ],
        "/dirs/to/remove",
        "/dirs",
    );
    let long_dir_name = random_alphanumeric_string(300);
    let dir_to_remove = Path::new("/dirs/child/");
    let dir_to_remove = dir_to_remove.join(long_dir_name.as_str());
    #[allow(clippy::unnecessary_to_owned)]
    crypto_fs_remove_dir(
        vec![
            dir_to_remove.join("file1.dat"),
            dir_to_remove.join("file2.dat"),
            dir_to_remove.join("file3.dat"),
        ],
        dir_to_remove,
        Path::new("/dirs").to_path_buf(),
    );
}

fn crypto_fs_remove_dir<P: AsRef<Path>>(files: Vec<P>, dir_to_remove: P, parent_dir: P) {
    //TODO: remake this test
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    crypto_fs.create_dir(&dir_to_remove).unwrap();
    for f in files.iter() {
        crypto_fs.create_file(f).unwrap();
    }
    crypto_fs.remove_dir(&parent_dir).unwrap();

    assert!(!crypto_fs.exists(dir_to_remove));
    for f in files.iter() {
        assert!(!crypto_fs.exists(f));
    }
}

#[test]
fn test_crypto_fs_copy_file() {
    crypto_fs_copy_file("/test.pdf", "/test-copy.pdf", "/dir-to-copy");

    let long_dir_name = random_alphanumeric_string(300);
    let long_src_name = random_alphanumeric_string(300);
    #[allow(clippy::unnecessary_to_owned)]
    crypto_fs_copy_file(
        "/".to_string() + long_src_name.as_str(),
        "/test-copy.pdf".to_string(),
        "/".to_string() + long_dir_name.as_str(),
    );

    let long_dir_name = random_alphanumeric_string(300);
    let long_dst_name = random_alphanumeric_string(300);
    #[allow(clippy::unnecessary_to_owned)]
    crypto_fs_copy_file(
        "/test.pdf".to_string(),
        "/".to_string() + long_dst_name.as_str(),
        "/".to_string() + long_dir_name.as_str(),
    );
}

fn crypto_fs_copy_file<P: AsRef<Path>>(src_file: P, dst_file: P, dir: P) {
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let file_to_copy = &src_file;
    let copied_file = &dst_file;

    let data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();

    let mut f = crypto_fs.create_file(file_to_copy).unwrap();
    f.write_all(data.as_slice()).unwrap();

    //test copy to the same folder
    crypto_fs.copy_file(file_to_copy, copied_file).unwrap();

    let mut file = crypto_fs
        .open_file(file_to_copy, OpenOptions::new())
        .unwrap();
    let mut data: Vec<u8> = vec![];
    file.read_to_end(&mut data).unwrap();

    let mut file_copy = crypto_fs
        .open_file(copied_file, OpenOptions::new())
        .unwrap();
    let mut data_copy: Vec<u8> = vec![];
    file_copy.read_to_end(&mut data_copy).unwrap();
    assert_eq!(data, data_copy);

    //test copy to another folder
    let dir_to_copy = dir.as_ref();
    let copied_file_full_path = dir_to_copy.join(copied_file);
    crypto_fs.create_dir(dir_to_copy).unwrap();
    crypto_fs
        .copy_file(file_to_copy.as_ref(), copied_file_full_path.as_path())
        .unwrap();
    let mut file_copy2 = crypto_fs
        .open_file(copied_file_full_path, OpenOptions::new())
        .unwrap();
    let mut data_copy2: Vec<u8> = vec![];
    file_copy2.read_to_end(&mut data_copy2).unwrap();
    assert_eq!(data, data_copy2);

    crypto_fs.remove_dir(dir_to_copy).unwrap();
    crypto_fs.remove_file(copied_file).unwrap();
}

#[test]
fn test_crypto_fs_move_file() {
    crypto_fs_move_file("/test.dat", "test_moved.dat", "/dir_for_moved_file");

    let long_dst_name = random_alphanumeric_string(300);
    let long_src_name = random_alphanumeric_string(300);
    #[allow(clippy::unnecessary_to_owned)]
    crypto_fs_move_file(
        "/".to_string() + long_src_name.as_str(),
        long_dst_name,
        "/dir_for_moved_file".to_string(),
    );
}

fn crypto_fs_move_file<P: AsRef<Path>>(src_file: P, dst_file: P, dst_dir: P) {
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let root = Path::new("/");
    let file_to_move = &src_file;
    let moved_file = root.join(&dst_file);

    let data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();
    let mut test_file = crypto_fs.create_file(file_to_move).unwrap();
    test_file.write_all(data.as_slice()).unwrap();
    test_file.flush().unwrap();

    crypto_fs
        .move_file(file_to_move.as_ref(), moved_file.as_path())
        .unwrap();
    let mut check_file = crypto_fs
        .open_file(&moved_file, OpenOptions::new())
        .unwrap();
    let mut data_check: Vec<u8> = vec![];
    check_file.read_to_end(&mut data_check).unwrap();
    assert_eq!(data, data_check);

    let dir_for_moved_file = dst_dir.as_ref();
    let moved_file_to_folder = dir_for_moved_file.join(&dst_file);
    crypto_fs.create_dir(dir_for_moved_file).unwrap();

    crypto_fs
        .move_file(&moved_file, &moved_file_to_folder)
        .unwrap();
    let mut check_file = crypto_fs
        .open_file(moved_file_to_folder, OpenOptions::new())
        .unwrap();
    let mut data_check: Vec<u8> = vec![];
    check_file.read_to_end(&mut data_check).unwrap();
    assert_eq!(data, data_check);

    crypto_fs.remove_dir(dir_for_moved_file).unwrap();
}

#[test]
fn test_crypto_fs_move_dir() {
    crypto_fs_move_dir("dir1", "dir2", "test.dat", "/dest_dir");

    let long_dir1_name = random_alphanumeric_string(300);
    let long_dir2_name = random_alphanumeric_string(300);
    let long_file_name = random_alphanumeric_string(300);
    let dest_dir = "/dest_dir";

    #[allow(clippy::unnecessary_to_owned)]
    crypto_fs_move_dir(
        long_dir1_name,
        long_dir2_name,
        long_file_name,
        dest_dir.to_string(),
    );
}

fn crypto_fs_move_dir<P: AsRef<Path>>(dir1: P, child_dir: P, file: P, dst_dir: P) {
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let root = Path::new("/");

    let dir_to_move = dir1.as_ref();
    let dirs_to_move = dir_to_move.join(&child_dir);
    let test_filename = &dirs_to_move.join(&file);
    let dest_dir = dst_dir.as_ref();
    let moved_file_path = dest_dir.join(child_dir.as_ref().join(file));

    crypto_fs.create_dir(root.join(&dirs_to_move)).unwrap();

    let data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();
    let mut test_file = crypto_fs.create_file(root.join(test_filename)).unwrap();
    test_file.write_all(data.as_slice()).unwrap();
    test_file.flush().unwrap();

    crypto_fs
        .move_dir(root.join(dir_to_move).as_path(), dest_dir)
        .unwrap();
    let mut check_file = crypto_fs
        .open_file(moved_file_path, OpenOptions::new())
        .unwrap();
    let mut data_check: Vec<u8> = vec![];
    check_file.read_to_end(&mut data_check).unwrap();
    assert_eq!(data, data_check);
    crypto_fs.remove_dir(dest_dir).unwrap();

    //test move folder into folder
    let moved_file_path = dest_dir.join(test_filename);

    crypto_fs.create_dir(root.join(dirs_to_move)).unwrap();
    crypto_fs.create_dir(dest_dir).unwrap();

    let data: Vec<u8> = (0..32 * 1024 * 3 + 2465)
        .map(|_| rand::random::<u8>())
        .collect();
    let mut test_file = crypto_fs.create_file(root.join(test_filename)).unwrap();
    test_file.write_all(data.as_slice()).unwrap();
    test_file.flush().unwrap();

    crypto_fs
        .move_dir(root.join(dir_to_move).as_path(), dest_dir)
        .unwrap();
    let mut check_file = crypto_fs
        .open_file(moved_file_path, OpenOptions::new())
        .unwrap();
    let mut data_check: Vec<u8> = vec![];
    check_file.read_to_end(&mut data_check).unwrap();
    assert_eq!(data, data_check);
}

/// Tests for NFS write issues - opening empty files for writing
#[test]
fn test_open_empty_file_for_write() {
    // Test that opening a newly created empty file for write works
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let file_path = "/empty-file-test.dat";

    // Create a file using create_file (which writes the header)
    crypto_fs.create_file(file_path).unwrap();

    // Now open the file with write mode - this should NOT fail with UnexpectedEof
    let mut file = crypto_fs
        .open_file(file_path, *OpenOptions::new().write(true))
        .unwrap();

    // Write some data
    let test_data = b"Hello, World!";
    file.write_all(test_data).unwrap();
    file.flush().unwrap();
    drop(file);

    // Reopen and verify the data
    let mut file = crypto_fs.open_file(file_path, OpenOptions::new()).unwrap();
    let mut read_data = Vec::new();
    file.read_to_end(&mut read_data).unwrap();
    assert_eq!(read_data, test_data);

    crypto_fs.remove_file(file_path).unwrap();
}

#[test]
fn test_nfs_style_write_to_empty_file() {
    // Simulates NFS behavior: open empty file with write flag and write to it
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let file_path = "/nfs-style-test.dat";

    // Step 1: Create the file (simulates NFS create)
    {
        let mut file = crypto_fs
            .open_file(file_path, *OpenOptions::new().write(true).create(true))
            .unwrap();

        // Step 2: Write data directly (this is where UnexpectedEof would occur)
        let test_data = b"NFS style write test data";
        file.write_all(test_data).unwrap();
        file.flush().unwrap();
    }

    // Verify the file was written correctly
    let mut file = crypto_fs.open_file(file_path, OpenOptions::new()).unwrap();
    let mut read_data = Vec::new();
    file.read_to_end(&mut read_data).unwrap();
    assert_eq!(read_data, b"NFS style write test data");

    crypto_fs.remove_file(file_path).unwrap();
}

#[test]
fn test_write_operations_on_reopened_file() {
    // Test that multiple write operations work correctly on a reopened file
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let file_path = "/reopen-write-test.dat";

    // Create initial file with some data
    {
        let mut file = crypto_fs.create_file(file_path).unwrap();
        file.write_all(b"Initial data").unwrap();
        file.flush().unwrap();
    }

    // Reopen and append more data
    {
        let mut file = crypto_fs
            .open_file(file_path, *OpenOptions::new().write(true))
            .unwrap();
        file.seek(std::io::SeekFrom::End(0)).unwrap();
        file.write_all(b" - appended data").unwrap();
        file.flush().unwrap();
    }

    // Verify complete data
    let mut file = crypto_fs.open_file(file_path, OpenOptions::new()).unwrap();
    let mut read_data = Vec::new();
    file.read_to_end(&mut read_data).unwrap();
    assert_eq!(read_data, b"Initial data - appended data");

    crypto_fs.remove_file(file_path).unwrap();
}

#[test]
fn test_no_unexpected_eof_on_empty_read() {
    // Ensure reading from an empty file doesn't cause UnexpectedEof
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(vault);

    let local_fs = MemoryFs::new();
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let file_path = "/empty-read-test.dat";

    // Create file
    crypto_fs.create_file(file_path).unwrap();

    // Open for read (empty file should not cause errors)
    let mut file = crypto_fs.open_file(file_path, OpenOptions::new()).unwrap();

    // Read should return 0 bytes (empty file)
    let mut buf = [0u8; 100];
    let read_count = file.read(&mut buf).unwrap();
    assert_eq!(read_count, 0);

    crypto_fs.remove_file(file_path).unwrap();
}
