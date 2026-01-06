use cryptomator::crypto::{Cryptor, Vault, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH};
use cryptomator::cryptofs::CryptoFs;
use cryptomator::frontends::nfs::NfsServer;
use cryptomator::providers::{LocalFs, MemoryFs};
use nfsserve::nfs::{ftype3, nfsstring, sattr3};
use nfsserve::vfs::NFSFileSystem;

const PATH_TO_VAULT: &str = "tests/test_storage/vault.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";
const VFS_STORAGE_PATH: &str = "/";

fn setup_nfs_server() -> NfsServer<MemoryFs> {
    let mem_fs = MemoryFs::new();
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = Cryptor::new(vault);
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, mem_fs).unwrap();
    NfsServer::new(crypto_fs)
}

#[tokio::test]
async fn test_nfs_getattr_root() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let result = nfs.getattr(root_handle).await;
    assert!(result.is_ok());

    let attr = result.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3DIR));
}

#[tokio::test]
async fn test_nfs_create_and_getattr() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"test.txt".to_vec().into();
    let sattr = sattr3::default();

    let result = nfs.create(root_handle, &filename, sattr).await;
    assert!(result.is_ok(), "Failed to create file: {:?}", result);

    let (file_handle, attr) = result.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3REG));
    assert_eq!(attr.size, 0);

    // Verify we can get attributes
    let attr_result = nfs.getattr(file_handle).await;
    assert!(attr_result.is_ok());
}

#[tokio::test]
async fn test_nfs_lookup() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"lookup_test.txt".to_vec().into();
    let sattr = sattr3::default();

    // Create a file
    let create_result = nfs.create(root_handle, &filename, sattr).await;
    assert!(create_result.is_ok());
    let (created_handle, _) = create_result.unwrap();

    // Lookup the file
    let lookup_result = nfs.lookup(root_handle, &filename).await;
    assert!(lookup_result.is_ok());
    let looked_up_handle = lookup_result.unwrap();

    assert_eq!(created_handle, looked_up_handle);
}

#[tokio::test]
async fn test_nfs_write_to_new_file() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"write_test.txt".to_vec().into();
    let sattr = sattr3::default();

    // Create a file
    let create_result = nfs.create(root_handle, &filename, sattr).await;
    assert!(create_result.is_ok(), "Failed to create file");
    let (file_handle, _) = create_result.unwrap();

    // Write data to the file
    let test_data = b"Hello, NFS World!";
    let write_result = nfs.write(file_handle, 0, test_data).await;
    assert!(
        write_result.is_ok(),
        "Failed to write to file: {:?}",
        write_result.err()
    );

    let attr = write_result.unwrap();
    assert_eq!(
        attr.size,
        test_data.len() as u64,
        "File size should match written data"
    );
}

#[tokio::test]
async fn test_nfs_write_and_read() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"write_read_test.txt".to_vec().into();
    let sattr = sattr3::default();

    // Create a file
    let (file_handle, _) = nfs.create(root_handle, &filename, sattr).await.unwrap();

    // Write data
    let test_data = b"Hello, NFS World! This is a test.";
    let write_result = nfs.write(file_handle, 0, test_data).await;
    assert!(
        write_result.is_ok(),
        "Failed to write: {:?}",
        write_result.err()
    );

    // Read data back
    let read_result = nfs.read(file_handle, 0, test_data.len() as u32).await;
    assert!(
        read_result.is_ok(),
        "Failed to read: {:?}",
        read_result.err()
    );

    let (read_data, eof) = read_result.unwrap();
    assert_eq!(read_data, test_data);
    assert!(eof);
}

#[tokio::test]
async fn test_nfs_write_at_offset() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"offset_write_test.txt".to_vec().into();
    let sattr = sattr3::default();

    // Create a file
    let (file_handle, _) = nfs.create(root_handle, &filename, sattr).await.unwrap();

    // Write initial data
    let initial_data = b"0123456789";
    nfs.write(file_handle, 0, initial_data).await.unwrap();

    // Write at offset
    let offset_data = b"ABCD";
    let write_result = nfs.write(file_handle, 3, offset_data).await;
    assert!(
        write_result.is_ok(),
        "Failed to write at offset: {:?}",
        write_result.err()
    );

    // Read entire file
    let (read_data, _) = nfs.read(file_handle, 0, 100).await.unwrap();
    let expected = b"012ABCD789";
    assert_eq!(&read_data[..expected.len()], expected);
}

#[tokio::test]
async fn test_nfs_write_beyond_file_size() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"sparse_write_test.txt".to_vec().into();
    let sattr = sattr3::default();

    // Create a file
    let (file_handle, _) = nfs.create(root_handle, &filename, sattr).await.unwrap();

    // First write some initial data
    let initial_data = vec![0u8; 100];
    nfs.write(file_handle, 0, &initial_data).await.unwrap();

    // Now write data at offset 100
    let test_data = b"DATA";
    let write_result = nfs.write(file_handle, 100, test_data).await;
    assert!(
        write_result.is_ok(),
        "Failed to write at offset: {:?}",
        write_result.err()
    );

    // Verify file size
    let attr = nfs.getattr(file_handle).await.unwrap();
    assert_eq!(attr.size, 104, "File size should be 104 bytes");

    // Verify the data at offset 100
    let (read_data, _) = nfs.read(file_handle, 100, 4).await.unwrap();
    assert_eq!(&read_data[..], test_data);
}

#[tokio::test]
async fn test_nfs_multiple_writes() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"multi_write_test.txt".to_vec().into();
    let sattr = sattr3::default();

    // Create a file
    let (file_handle, _) = nfs.create(root_handle, &filename, sattr).await.unwrap();

    // Perform multiple writes
    let writes = vec![
        (0u64, b"Part1" as &[u8]),
        (5u64, b"Part2"),
        (10u64, b"Part3"),
    ];

    for (offset, data) in writes {
        let result = nfs.write(file_handle, offset, data).await;
        assert!(
            result.is_ok(),
            "Failed to write at offset {}: {:?}",
            offset,
            result.err()
        );
    }

    // Read and verify
    let (read_data, _) = nfs.read(file_handle, 0, 100).await.unwrap();
    let expected = b"Part1Part2Part3";
    assert_eq!(&read_data[..expected.len()], expected);
}

#[tokio::test]
async fn test_nfs_sparse_write_and_read() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"sparse_gap.dat".to_vec().into();
    let sattr = sattr3::default();

    let (file_handle, _) = nfs.create(root_handle, &filename, sattr).await.unwrap();

    let offset = (FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64 * 2) + 321;
    let payload = b"nfs-gap";

    nfs.write(file_handle, offset, payload).await.unwrap();

    let attr = nfs.getattr(file_handle).await.unwrap();
    assert_eq!(attr.size, offset + payload.len() as u64);

    let (leading, _) = nfs.read(file_handle, 0, 1024).await.unwrap();
    assert_eq!(leading.len(), 1024);
    assert!(leading.iter().all(|&b| b == 0));

    let (tail, _) = nfs
        .read(file_handle, offset, payload.len() as u32)
        .await
        .unwrap();
    assert_eq!(tail, payload);
}

#[tokio::test]
async fn test_nfs_mkdir_and_create_file_in_dir() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let dirname: nfsstring = b"testdir".to_vec().into();
    let result = nfs.mkdir(root_handle, &dirname).await;
    assert!(result.is_ok());

    let (dir_handle, attr) = result.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3DIR));

    // Create a file in the directory
    let filename: nfsstring = b"file_in_dir.txt".to_vec().into();
    let sattr = sattr3::default();
    let create_result = nfs.create(dir_handle, &filename, sattr).await;
    assert!(create_result.is_ok());

    let (file_handle, _) = create_result.unwrap();

    // Write to the file
    let test_data = b"File in directory";
    let write_result = nfs.write(file_handle, 0, test_data).await;
    assert!(
        write_result.is_ok(),
        "Failed to write to file in directory: {:?}",
        write_result.err()
    );
}

#[tokio::test]
async fn test_nfs_remove_file() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"to_remove.txt".to_vec().into();
    let sattr = sattr3::default();

    // Create and write to a file
    let (file_handle, _) = nfs.create(root_handle, &filename, sattr).await.unwrap();
    nfs.write(file_handle, 0, b"test").await.unwrap();

    // Remove the file
    let result = nfs.remove(root_handle, &filename).await;
    assert!(result.is_ok());

    // Verify file is gone
    let lookup_result = nfs.lookup(root_handle, &filename).await;
    assert!(lookup_result.is_err());
}

#[tokio::test]
async fn test_nfs_rename_file() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let old_name: nfsstring = b"old_name.txt".to_vec().into();
    let new_name: nfsstring = b"new_name.txt".to_vec().into();
    let sattr = sattr3::default();

    // Create and write to a file
    let (file_handle, _) = nfs.create(root_handle, &old_name, sattr).await.unwrap();
    let test_data = b"rename test data";
    nfs.write(file_handle, 0, test_data).await.unwrap();

    // Rename the file
    let result = nfs
        .rename(root_handle, &old_name, root_handle, &new_name)
        .await;
    assert!(result.is_ok());

    // Verify old name doesn't exist
    let old_lookup = nfs.lookup(root_handle, &old_name).await;
    assert!(old_lookup.is_err());

    // Verify new name exists
    let new_lookup = nfs.lookup(root_handle, &new_name).await;
    assert!(new_lookup.is_ok());

    // Verify data is intact
    let new_handle = new_lookup.unwrap();
    let (read_data, _) = nfs.read(new_handle, 0, 100).await.unwrap();
    assert_eq!(&read_data[..test_data.len()], test_data);
}

#[tokio::test]
async fn test_nfs_readdir() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    // Create multiple files
    for i in 0..5 {
        let filename: nfsstring = format!("file{}.txt", i).into_bytes().into();
        let sattr = sattr3::default();
        nfs.create(root_handle, &filename, sattr).await.unwrap();
    }

    // Read directory
    let result = nfs.readdir(root_handle, 0, 100).await;
    assert!(result.is_ok());

    let dir_result = result.unwrap();
    assert_eq!(dir_result.entries.len(), 5);
}

#[tokio::test]
async fn test_nfs_large_write() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"large_file.dat".to_vec().into();
    let sattr = sattr3::default();

    // Create a file
    let (file_handle, _) = nfs.create(root_handle, &filename, sattr).await.unwrap();

    // Write a large amount of data
    let large_data: Vec<u8> = (0..100000).map(|i| (i % 256) as u8).collect();
    let write_result = nfs.write(file_handle, 0, &large_data).await;
    assert!(
        write_result.is_ok(),
        "Failed to write large data: {:?}",
        write_result.err()
    );

    // Verify size
    let attr = nfs.getattr(file_handle).await.unwrap();
    assert_eq!(attr.size, large_data.len() as u64);

    // Read back and verify
    let (read_data, _) = nfs
        .read(file_handle, 0, large_data.len() as u32)
        .await
        .unwrap();
    assert_eq!(read_data, large_data);
}
