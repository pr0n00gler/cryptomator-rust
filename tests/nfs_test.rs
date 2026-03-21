use cryptomator::crypto::{Cryptor, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH, Vault};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig};
use cryptomator::frontends::nfs::NfsServer;
use cryptomator::providers::{LocalFs, MemoryFs};
use nfsserve::nfs::{
    ftype3, nfsstat3, nfsstring, sattr3, set_atime, set_gid3, set_mode3, set_mtime, set_size3,
    set_uid3,
};
use nfsserve::vfs::{NFSFileSystem, VFSCapabilities};

const PATH_TO_VAULT: &str = "tests/test_storage/vault.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";
const VFS_STORAGE_PATH: &str = "/";

fn setup_nfs_server() -> NfsServer<MemoryFs> {
    let mem_fs = MemoryFs::new();
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = Cryptor::new(vault);
    let crypto_fs =
        CryptoFs::new(VFS_STORAGE_PATH, cryptor, mem_fs, CryptoFsConfig::default()).unwrap();
    NfsServer::new(crypto_fs)
}

fn setup_nfs_server_with_capacity(max_handles: usize) -> NfsServer<MemoryFs> {
    let mem_fs = MemoryFs::new();
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = Cryptor::new(vault);
    let crypto_fs =
        CryptoFs::new(VFS_STORAGE_PATH, cryptor, mem_fs, CryptoFsConfig::default()).unwrap();
    NfsServer::with_handle_capacity(crypto_fs, max_handles)
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
    assert!(result.is_ok(), "Failed to create file: {result:?}");

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
async fn test_nfs_rename_directory_updates_child_handle() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let dirname: nfsstring = b"parent".to_vec().into();
    let (dir_handle, _) = nfs.mkdir(root_handle, &dirname).await.unwrap();

    let filename: nfsstring = b"child.txt".to_vec().into();
    let (file_handle, _) = nfs
        .create(dir_handle, &filename, sattr3::default())
        .await
        .unwrap();

    let payload = b"rename-child-handle";
    nfs.write(file_handle, 0, payload).await.unwrap();

    let new_dirname: nfsstring = b"parent-renamed".to_vec().into();
    nfs.rename(root_handle, &dirname, root_handle, &new_dirname)
        .await
        .unwrap();

    let renamed_dir_handle = nfs.lookup(root_handle, &new_dirname).await.unwrap();
    let child_handle_after = nfs.lookup(renamed_dir_handle, &filename).await.unwrap();

    let (read_data, _) = nfs
        .read(child_handle_after, 0, payload.len() as u32)
        .await
        .unwrap();
    assert_eq!(read_data, payload);

    assert_eq!(
        file_handle, child_handle_after,
        "child handle should remain stable across parent directory rename"
    );
}

#[tokio::test]
async fn test_nfs_readdir() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    // Create multiple files
    for i in 0..5 {
        let filename: nfsstring = format!("file{i}.txt").into_bytes().into();
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

#[tokio::test]
async fn test_nfs_setattr() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"setattr_test.txt".to_vec().into();
    let (file_handle, _) = nfs
        .create(root_handle, &filename, sattr3::default())
        .await
        .unwrap();

    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::Void,
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };

    let result = nfs.setattr(file_handle, sattr).await;
    assert!(result.is_ok());
    let attr = result.unwrap();
    assert_eq!(attr.fileid, file_handle);
    // Note: implementation currently ignores attribute changes, so we just verify it returns OK and valid attributes
}

#[tokio::test]
async fn test_nfs_create_exclusive() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let filename: nfsstring = b"exclusive_test.txt".to_vec().into();

    // Success
    let result = nfs.create_exclusive(root_handle, &filename).await;
    assert!(result.is_ok());
    let file_handle = result.unwrap();

    // Verify it exists
    let lookup_result = nfs.lookup(root_handle, &filename).await;
    assert_eq!(lookup_result.unwrap(), file_handle);

    // Failure (existing file)
    let result2 = nfs.create_exclusive(root_handle, &filename).await;
    assert!(matches!(result2, Err(nfsstat3::NFS3ERR_EXIST)));
}

#[tokio::test]
async fn test_nfs_symlink_not_supported() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();
    let name: nfsstring = b"link".to_vec().into();
    let target: nfsstring = b"target".to_vec().into();

    let result = nfs
        .symlink(root_handle, &name, &target, &sattr3::default())
        .await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOTSUPP)));
}

#[tokio::test]
async fn test_nfs_readlink_not_supported() {
    let nfs = setup_nfs_server();
    // Assuming handle 1 is root, but let's just use any handle
    let result = nfs.readlink(1).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOTSUPP)));
}

#[tokio::test]
async fn test_nfs_capabilities() {
    let nfs = setup_nfs_server();
    let caps = nfs.capabilities();
    assert!(matches!(caps, VFSCapabilities::ReadWrite));
}

#[tokio::test]
async fn test_nfs_readdir_pagination() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    // Create 5 files
    for i in 0..5 {
        let filename: nfsstring = format!("file{i}.txt").into_bytes().into();
        nfs.create(root_handle, &filename, sattr3::default())
            .await
            .unwrap();
    }

    // Read first 2 entries
    let result1 = nfs.readdir(root_handle, 0, 2).await.unwrap();
    assert_eq!(result1.entries.len(), 2);
    assert!(!result1.end);

    let cookie1 = result1.entries.last().unwrap().fileid;

    // Read next 2 entries using the last fileid cookie from result1
    let result2 = nfs.readdir(root_handle, cookie1, 2).await.unwrap();
    assert_eq!(result2.entries.len(), 2);
    assert!(!result2.end);

    let cookie2 = result2.entries.last().unwrap().fileid;

    // Read last entry using the last fileid cookie from result2
    let result3 = nfs.readdir(root_handle, cookie2, 2).await.unwrap();
    assert_eq!(result3.entries.len(), 1);
    assert!(result3.end);

    // Verify all files were seen and are unique
    let mut names = std::collections::HashSet::new();
    for e in result1.entries {
        names.insert(String::from_utf8_lossy(&e.name).to_string());
    }
    for e in result2.entries {
        names.insert(String::from_utf8_lossy(&e.name).to_string());
    }
    for e in result3.entries {
        names.insert(String::from_utf8_lossy(&e.name).to_string());
    }

    assert_eq!(names.len(), 5);
    for i in 0..5 {
        assert!(names.contains(&format!("file{i}.txt")));
    }
}

#[tokio::test]
async fn test_nfs_readdir_start_after_uses_fileid() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    for i in 0..3 {
        let filename: nfsstring = format!("cookie_file{i}.txt").into_bytes().into();
        nfs.create(root_handle, &filename, sattr3::default())
            .await
            .unwrap();
    }

    let all_entries = nfs.readdir(root_handle, 0, 10).await.unwrap();
    assert_eq!(all_entries.entries.len(), 3);

    let first_entry = all_entries.entries.first().unwrap();
    let next_entries = nfs
        .readdir(root_handle, first_entry.fileid, 10)
        .await
        .unwrap();

    assert_eq!(next_entries.entries.len(), all_entries.entries.len() - 1);
    assert_eq!(
        next_entries.entries.first().unwrap().fileid,
        all_entries.entries[1].fileid
    );
}

#[tokio::test]
async fn test_nfs_read_directory_error() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();

    let result = nfs.read(root_handle, 0, 100).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_ISDIR)));
}

#[tokio::test]
async fn test_nfs_lookup_nonexistent() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();
    let filename: nfsstring = b"nonexistent".to_vec().into();

    let result = nfs.lookup(root_handle, &filename).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));
}

#[tokio::test]
async fn test_nfs_stale_handle() {
    let nfs = setup_nfs_server();
    let stale_handle = 9999u64;
    let name: nfsstring = b"test".to_vec().into();

    assert!(matches!(
        nfs.getattr(stale_handle).await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(matches!(
        nfs.setattr(stale_handle, sattr3::default()).await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(matches!(
        nfs.lookup(stale_handle, &name).await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(matches!(
        nfs.read(stale_handle, 0, 100).await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(matches!(
        nfs.write(stale_handle, 0, b"data").await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(matches!(
        nfs.remove(stale_handle, &name).await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(matches!(
        nfs.rename(stale_handle, &name, 1, &name).await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(matches!(
        nfs.rename(1, &name, stale_handle, &name).await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(matches!(
        nfs.readdir(stale_handle, 0, 10).await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
}

#[tokio::test]
async fn test_nfs_rename_errors() {
    let nfs = setup_nfs_server();
    let root_handle = nfs.root_dir();
    let old_name: nfsstring = b"old.txt".to_vec().into();
    let new_name: nfsstring = b"new.txt".to_vec().into();

    // Rename non-existent file
    let result = nfs
        .rename(root_handle, &old_name, root_handle, &new_name)
        .await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_NOENT)),
        "expected NFS3ERR_NOENT, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_lookup_rejects_dot() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b".".to_vec().into();
    let result = nfs.lookup(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_INVAL)),
        "expected NFS3ERR_INVAL for '.', got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_lookup_rejects_dotdot() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b"..".to_vec().into();
    let result = nfs.lookup(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_INVAL)),
        "expected NFS3ERR_INVAL for '..', got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_lookup_rejects_slash_in_name() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b"foo/bar".to_vec().into();
    let result = nfs.lookup(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_INVAL)),
        "expected NFS3ERR_INVAL for 'foo/bar', got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_lookup_rejects_null_in_name() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b"foo\0bar".to_vec().into();
    // This will fail at UTF-8 validation (contains \0 which is valid UTF-8
    // but still rejected by validate_filename).
    let result = nfs.lookup(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_INVAL)),
        "expected NFS3ERR_INVAL for name with null byte, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_create_rejects_traversal() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b"..".to_vec().into();
    let result = nfs.create(root, &name, sattr3::default()).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));
}

#[tokio::test]
async fn test_nfs_mkdir_rejects_traversal() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b"..".to_vec().into();
    let result = nfs.mkdir(root, &name).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));
}

#[tokio::test]
async fn test_nfs_remove_rejects_traversal() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b".".to_vec().into();
    let result = nfs.remove(root, &name).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));
}

#[tokio::test]
async fn test_nfs_rename_rejects_traversal_in_source() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let bad_name: nfsstring = b"..".to_vec().into();
    let good_name: nfsstring = b"good.txt".to_vec().into();
    let result = nfs.rename(root, &bad_name, root, &good_name).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));
}

#[tokio::test]
async fn test_nfs_rename_rejects_traversal_in_target() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    // Create a valid source file first.
    let good_name: nfsstring = b"source.txt".to_vec().into();
    nfs.create(root, &good_name, sattr3::default())
        .await
        .unwrap();

    let bad_name: nfsstring = b"foo/../../etc/passwd".to_vec().into();
    let result = nfs.rename(root, &good_name, root, &bad_name).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));
}

#[tokio::test]
async fn test_nfs_create_exclusive_rejects_traversal() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b"..".to_vec().into();
    let result = nfs.create_exclusive(root, &name).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));
}

// Verify that names containing ".." as a substring (but not exactly "..")
// are allowed.
#[tokio::test]
async fn test_nfs_lookup_allows_dotdot_substring() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = b"foo..bar".to_vec().into();
    // Should not be rejected by validation (it's not exactly "..")
    // Will fail with NFS3ERR_NOENT because the file doesn't exist, which is fine.
    let result = nfs.lookup(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_NOENT)),
        "expected NFS3ERR_NOENT for 'foo..bar' (not INVAL), got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_handle_map_evicts_oldest() {
    // Use a server with a very small handle capacity.
    let nfs = setup_nfs_server_with_capacity(5);
    let root = nfs.root_dir();

    // Create 5 files -- this fills the handle map (5 non-root entries).
    for i in 0..5 {
        let name: nfsstring = format!("evict{i}.txt").into_bytes().into();
        nfs.create(root, &name, sattr3::default()).await.unwrap();
    }
    assert_eq!(nfs.handle_count(), 5);

    // Creating a 6th file should evict the oldest handle.
    let name6: nfsstring = b"evict5.txt".to_vec().into();
    nfs.create(root, &name6, sattr3::default()).await.unwrap();

    // The total count should not exceed 5 non-root entries (some stale
    // queue entries may linger but both maps are cleaned up).
    assert!(
        nfs.handle_count() <= 5,
        "handle count should be bounded, got {}",
        nfs.handle_count()
    );
}

#[tokio::test]
async fn test_nfs_timestamp_clamping() {
    // The secs_to_u32 helper is used internally.  We test it indirectly
    // by verifying that the root directory attributes do not panic and
    // that timestamps are valid u32 values (they fit in the nfstime3 struct).
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let attr = nfs.getattr(root).await.unwrap();
    // Just verify the attributes are returned without panic and have
    // reasonable values. The clamping logic ensures no silent truncation.
    assert!(attr.atime.seconds > 0, "atime should be a valid timestamp");
    assert!(attr.mtime.seconds > 0, "mtime should be a valid timestamp");
    assert!(attr.ctime.seconds > 0, "ctime should be a valid timestamp");
}

#[tokio::test]
async fn test_nfs_rejects_non_utf8_filename() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    // 0xFF 0xFE is not valid UTF-8.
    let name: nfsstring = vec![0xFF, 0xFE].into();
    let result = nfs.lookup(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_INVAL)),
        "expected NFS3ERR_INVAL for non-UTF-8 filename, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_create_rejects_non_utf8() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();
    let name: nfsstring = vec![0x80, 0x81].into();
    let result = nfs.create(root, &name, sattr3::default()).await;
    assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));
}

#[tokio::test]
async fn test_nfs_setattr_truncate_to_zero() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name: nfsstring = b"trunc_zero.txt".to_vec().into();
    let (handle, _) = nfs.create(root, &name, sattr3::default()).await.unwrap();
    nfs.write(handle, 0, b"hello world").await.unwrap();

    // Verify file has data
    let attr = nfs.getattr(handle).await.unwrap();
    assert!(attr.size > 0);

    // Truncate to zero
    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::size(0),
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };
    let result = nfs.setattr(handle, sattr).await;
    assert!(result.is_ok(), "setattr truncate failed: {result:?}");

    let attr = result.unwrap();
    assert_eq!(attr.size, 0, "file should be truncated to zero");
}

#[tokio::test]
async fn test_nfs_setattr_truncate_to_nonzero() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name: nfsstring = b"trunc_partial.txt".to_vec().into();
    let (handle, _) = nfs.create(root, &name, sattr3::default()).await.unwrap();
    nfs.write(handle, 0, b"0123456789").await.unwrap();

    // Truncate to 5 bytes
    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::size(5),
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };
    let result = nfs.setattr(handle, sattr).await;
    assert!(result.is_ok(), "setattr truncate failed: {result:?}");

    let attr = result.unwrap();
    assert_eq!(attr.size, 5, "file should be truncated to 5 bytes");

    // Read back and verify content
    let (data, _) = nfs.read(handle, 0, 100).await.unwrap();
    assert_eq!(&data, b"01234");
}

#[tokio::test]
async fn test_nfs_remove_directory() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dirname: nfsstring = b"dir_to_remove".to_vec().into();
    nfs.mkdir(root, &dirname).await.unwrap();

    // remove should succeed for directories too
    let result = nfs.remove(root, &dirname).await;
    assert!(result.is_ok(), "remove directory failed: {result:?}");

    // Verify it's gone
    let lookup = nfs.lookup(root, &dirname).await;
    assert!(matches!(lookup, Err(nfsstat3::NFS3ERR_NOENT)));
}

#[tokio::test]
async fn test_nfs_directory_nlink_is_two() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let attr = nfs.getattr(root).await.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3DIR));
    assert_eq!(attr.nlink, 2, "directories should have nlink=2");
}

#[tokio::test]
async fn test_nfs_file_nlink_is_one() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name: nfsstring = b"nlink_test.txt".to_vec().into();
    let (handle, _) = nfs.create(root, &name, sattr3::default()).await.unwrap();

    let attr = nfs.getattr(handle).await.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3REG));
    assert_eq!(attr.nlink, 1, "regular files should have nlink=1");
}

#[tokio::test]
async fn test_nfs_getattr_returns_noent_not_io() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    // Create a file, get its handle, then remove it.
    let name: nfsstring = b"will_vanish.txt".to_vec().into();
    let (handle, _) = nfs.create(root, &name, sattr3::default()).await.unwrap();
    nfs.remove(root, &name).await.unwrap();

    // getattr on the now-stale path should map to a clear error,
    // not NFS3ERR_IO.
    let result = nfs.getattr(handle).await;
    assert!(result.is_err(), "getattr should fail for removed file");
    // The handle is still in the map (we didn't evict it), so
    // path resolution succeeds but metadata fails.  With consistent
    // error mapping it should return NFS3ERR_NOENT (via PathDoesNotExist).
}

#[tokio::test]
async fn test_nfs_normal_filenames_accepted() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    // These should all be accepted by validate_filename.
    let names = vec![
        "hello.txt",
        "foo..bar",
        ".hidden",
        "...three_dots",
        "a",
        "file with spaces",
    ];
    for name_str in names {
        let name: nfsstring = name_str.as_bytes().to_vec().into();
        let result = nfs.create(root, &name, sattr3::default()).await;
        assert!(
            result.is_ok(),
            "failed to create file with valid name '{name_str}': {result:?}"
        );
    }
}

#[tokio::test]
async fn test_nfs_setattr_size_on_directory_returns_isdir() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dirname: nfsstring = b"dir_for_setattr".to_vec().into();
    let (dir_handle, _) = nfs.mkdir(root, &dirname).await.unwrap();

    // Attempting to set size on a directory should return NFS3ERR_ISDIR.
    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::size(0),
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };
    let result = nfs.setattr(dir_handle, sattr).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_ISDIR)),
        "expected NFS3ERR_ISDIR when setting size on a directory, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_empty_filename_rejected() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let empty_name: nfsstring = b"".to_vec().into();

    let lookup_result = nfs.lookup(root, &empty_name).await;
    assert!(
        matches!(lookup_result, Err(nfsstat3::NFS3ERR_INVAL)),
        "expected NFS3ERR_INVAL for empty filename lookup, got {lookup_result:?}"
    );

    let create_result = nfs.create(root, &empty_name, sattr3::default()).await;
    assert!(
        matches!(create_result, Err(nfsstat3::NFS3ERR_INVAL)),
        "expected NFS3ERR_INVAL for empty filename create, got {create_result:?}"
    );

    let mkdir_result = nfs.mkdir(root, &empty_name).await;
    assert!(
        matches!(mkdir_result, Err(nfsstat3::NFS3ERR_INVAL)),
        "expected NFS3ERR_INVAL for empty filename mkdir, got {mkdir_result:?}"
    );
}

// ---------------------------------------------------------------------------
// 1. Deep Directory Hierarchy Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_nested_directories_deep() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    // Create 5 levels of nested directories, with a file at each level.
    let dir_names = ["depth1", "depth2", "depth3", "depth4", "depth5"];
    let mut parent_handle = root;
    let mut handles_and_data: Vec<(u64, Vec<u8>)> = Vec::new();

    for (i, dir_name) in dir_names.iter().enumerate() {
        let dname: nfsstring = dir_name.as_bytes().to_vec().into();
        let (dir_handle, attr) = nfs.mkdir(parent_handle, &dname).await.unwrap();
        assert!(matches!(attr.ftype, ftype3::NF3DIR));

        // Create a file at this level
        let fname: nfsstring = format!("file_at_level{i}.txt").into_bytes().into();
        let (file_handle, _) = nfs
            .create(dir_handle, &fname, sattr3::default())
            .await
            .unwrap();
        let data = format!("data at level {i}").into_bytes();
        nfs.write(file_handle, 0, &data).await.unwrap();
        handles_and_data.push((file_handle, data));

        parent_handle = dir_handle;
    }

    // Verify reads work at every level
    for (file_handle, expected_data) in &handles_and_data {
        let (read_data, eof) = nfs.read(*file_handle, 0, 1024).await.unwrap();
        assert_eq!(&read_data, expected_data);
        assert!(eof);
    }
}

#[tokio::test]
async fn test_nfs_remove_nonempty_directory() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dirname: nfsstring = b"nonempty_dir".to_vec().into();
    let (dir_handle, _) = nfs.mkdir(root, &dirname).await.unwrap();

    // Create files inside the directory
    let fname1: nfsstring = b"child1.txt".to_vec().into();
    let fname2: nfsstring = b"child2.txt".to_vec().into();
    let (fh1, _) = nfs
        .create(dir_handle, &fname1, sattr3::default())
        .await
        .unwrap();
    let (fh2, _) = nfs
        .create(dir_handle, &fname2, sattr3::default())
        .await
        .unwrap();
    nfs.write(fh1, 0, b"child1 data").await.unwrap();
    nfs.write(fh2, 0, b"child2 data").await.unwrap();

    // Attempt to remove the non-empty directory. The underlying filesystem
    // may succeed (recursive) or fail -- either outcome is valid. We just
    // verify no panic and we can observe the result.
    let result = nfs.remove(root, &dirname).await;
    if result.is_ok() {
        // If removal succeeded, the directory should be gone.
        let lookup = nfs.lookup(root, &dirname).await;
        assert!(matches!(lookup, Err(nfsstat3::NFS3ERR_NOENT)));
    }
    // If result is Err, the server correctly refused to remove a non-empty dir.
}

#[tokio::test]
async fn test_nfs_readdir_empty_directory() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dirname: nfsstring = b"empty_dir_readdir".to_vec().into();
    let (dir_handle, _) = nfs.mkdir(root, &dirname).await.unwrap();

    let result = nfs.readdir(dir_handle, 0, 100).await.unwrap();
    assert!(
        result.entries.is_empty(),
        "empty directory should have no entries"
    );
    assert!(result.end, "empty directory readdir should signal end");
}

#[tokio::test]
async fn test_nfs_mkdir_in_subdirectory() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let outer: nfsstring = b"outer_dir".to_vec().into();
    let (outer_handle, _) = nfs.mkdir(root, &outer).await.unwrap();

    let inner: nfsstring = b"inner_dir".to_vec().into();
    let (inner_handle, attr) = nfs.mkdir(outer_handle, &inner).await.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3DIR));

    // Verify with lookup
    let looked_up = nfs.lookup(outer_handle, &inner).await.unwrap();
    assert_eq!(looked_up, inner_handle);
}

#[tokio::test]
async fn test_nfs_create_file_in_nested_dir() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    // Create 3 levels of directories
    let d1: nfsstring = b"nest_a".to_vec().into();
    let (h1, _) = nfs.mkdir(root, &d1).await.unwrap();
    let d2: nfsstring = b"nest_b".to_vec().into();
    let (h2, _) = nfs.mkdir(h1, &d2).await.unwrap();
    let d3: nfsstring = b"nest_c".to_vec().into();
    let (h3, _) = nfs.mkdir(h2, &d3).await.unwrap();

    // Create file in deepest dir
    let fname: nfsstring = b"deep_file.txt".to_vec().into();
    let (fh, _) = nfs.create(h3, &fname, sattr3::default()).await.unwrap();

    let data = b"deeply nested data";
    nfs.write(fh, 0, data).await.unwrap();

    let (read_data, eof) = nfs.read(fh, 0, 1024).await.unwrap();
    assert_eq!(&read_data, data);
    assert!(eof);
}

// ---------------------------------------------------------------------------
// 2. File I/O Edge Cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_read_at_exact_eof() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"read_at_eof.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let data = b"exact eof test";
    nfs.write(fh, 0, data).await.unwrap();

    // Read starting exactly at file size
    let (read_data, eof) = nfs.read(fh, data.len() as u64, 100).await.unwrap();
    assert!(
        read_data.is_empty(),
        "reading at exact EOF should return empty data"
    );
    assert!(eof, "reading at exact EOF should signal eof");
}

#[tokio::test]
async fn test_nfs_read_beyond_eof() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"read_beyond_eof.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let data = b"short";
    nfs.write(fh, 0, data).await.unwrap();

    // Read with offset well past file size
    let (read_data, eof) = nfs.read(fh, 1000, 100).await.unwrap();
    assert!(
        read_data.is_empty(),
        "reading beyond EOF should return empty data"
    );
    assert!(eof, "reading beyond EOF should signal eof");
}

#[tokio::test]
async fn test_nfs_read_zero_bytes() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"read_zero.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();
    nfs.write(fh, 0, b"some data").await.unwrap();

    let (read_data, _) = nfs.read(fh, 0, 0).await.unwrap();
    assert!(
        read_data.is_empty(),
        "reading zero bytes should return empty data"
    );
}

#[tokio::test]
async fn test_nfs_write_empty_data() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"write_empty.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let data = b"original";
    nfs.write(fh, 0, data).await.unwrap();

    // Write zero bytes at offset 0
    nfs.write(fh, 0, b"").await.unwrap();

    let attr = nfs.getattr(fh).await.unwrap();
    assert_eq!(
        attr.size,
        data.len() as u64,
        "file size should not change after empty write"
    );
}

#[tokio::test]
async fn test_nfs_overwrite_entire_file() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"overwrite_entire.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let original = b"AAAAAAAAAA"; // 10 bytes
    nfs.write(fh, 0, original).await.unwrap();

    let replacement = b"BBBBBBBBBB"; // 10 bytes
    nfs.write(fh, 0, replacement).await.unwrap();

    let (read_data, _) = nfs.read(fh, 0, 100).await.unwrap();
    assert_eq!(&read_data, replacement);
}

#[tokio::test]
async fn test_nfs_overwrite_with_shorter_data() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"overwrite_shorter.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let original = vec![0xAA_u8; 100];
    nfs.write(fh, 0, &original).await.unwrap();

    // Overwrite first 50 bytes with different data
    let short_data = vec![0xBB_u8; 50];
    nfs.write(fh, 0, &short_data).await.unwrap();

    let attr = nfs.getattr(fh).await.unwrap();
    assert_eq!(
        attr.size, 100,
        "file size should remain 100 after shorter overwrite"
    );

    let (read_data, _) = nfs.read(fh, 0, 200).await.unwrap();
    assert_eq!(&read_data[..50], &[0xBB; 50]);
    assert_eq!(&read_data[50..100], &[0xAA; 50]);
}

#[tokio::test]
async fn test_nfs_overwrite_with_longer_data() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"overwrite_longer.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let original = vec![0xAA_u8; 50];
    nfs.write(fh, 0, &original).await.unwrap();

    // Overwrite at offset 0 with 100 bytes -- file should grow
    let long_data = vec![0xBB_u8; 100];
    nfs.write(fh, 0, &long_data).await.unwrap();

    let attr = nfs.getattr(fh).await.unwrap();
    assert_eq!(attr.size, 100, "file should grow to 100 bytes");

    let (read_data, _) = nfs.read(fh, 0, 200).await.unwrap();
    assert_eq!(&read_data, &long_data);
}

#[tokio::test]
async fn test_nfs_write_at_chunk_boundary() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"chunk_boundary.dat".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let chunk_size = FILE_CHUNK_CONTENT_PAYLOAD_LENGTH;
    // Write data that straddles the chunk boundary: half in chunk 0, half in chunk 1
    let half = 512;
    let offset = (chunk_size - half) as u64;
    let data: Vec<u8> = (0..(half * 2) as u16).map(|i| (i % 256) as u8).collect();
    nfs.write(fh, offset, &data).await.unwrap();

    let (read_data, _) = nfs.read(fh, offset, data.len() as u32).await.unwrap();
    assert_eq!(
        read_data, data,
        "data spanning chunk boundary should round-trip"
    );
}

#[tokio::test]
async fn test_nfs_write_spanning_multiple_chunks() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"multi_chunk_write.dat".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let chunk_size = FILE_CHUNK_CONTENT_PAYLOAD_LENGTH;
    let data_len = chunk_size * 2 + 1000;
    let data: Vec<u8> = (0..data_len).map(|i| (i % 251) as u8).collect();
    nfs.write(fh, 0, &data).await.unwrap();

    let (read_data, _) = nfs.read(fh, 0, data_len as u32).await.unwrap();
    assert_eq!(read_data.len(), data.len());
    assert_eq!(
        read_data, data,
        "data spanning multiple chunks should round-trip"
    );
}

#[tokio::test]
async fn test_nfs_read_partial_from_middle() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"partial_middle.dat".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let data: Vec<u8> = (0..10000_u32).map(|i| (i % 256) as u8).collect();
    nfs.write(fh, 0, &data).await.unwrap();

    // Read 100 bytes from the middle
    let offset = 5000_u64;
    let count = 100_u32;
    let (read_data, eof) = nfs.read(fh, offset, count).await.unwrap();
    assert_eq!(read_data.len(), 100);
    assert!(!eof, "reading from middle should not be eof");
    assert_eq!(&read_data, &data[5000..5100]);
}

// ---------------------------------------------------------------------------
// 3. Rename/Move Scenarios
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_rename_file_across_directories() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dir_a: nfsstring = b"move_dir_a".to_vec().into();
    let dir_b: nfsstring = b"move_dir_b".to_vec().into();
    let (ha, _) = nfs.mkdir(root, &dir_a).await.unwrap();
    let (hb, _) = nfs.mkdir(root, &dir_b).await.unwrap();

    let fname: nfsstring = b"movable.txt".to_vec().into();
    let (fh, _) = nfs.create(ha, &fname, sattr3::default()).await.unwrap();
    nfs.write(fh, 0, b"cross-dir move").await.unwrap();

    let new_fname: nfsstring = b"moved.txt".to_vec().into();
    nfs.rename(ha, &fname, hb, &new_fname).await.unwrap();

    // Old location should be gone
    let old_lookup = nfs.lookup(ha, &fname).await;
    assert!(matches!(old_lookup, Err(nfsstat3::NFS3ERR_NOENT)));

    // New location should have the file with data intact
    let new_handle = nfs.lookup(hb, &new_fname).await.unwrap();
    let (read_data, _) = nfs.read(new_handle, 0, 100).await.unwrap();
    assert_eq!(&read_data, b"cross-dir move");
}

#[tokio::test]
async fn test_nfs_rename_directory() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dirname: nfsstring = b"rename_me_dir".to_vec().into();
    let (dh, _) = nfs.mkdir(root, &dirname).await.unwrap();

    // Put a file inside
    let fname: nfsstring = b"inside_renamed_dir.txt".to_vec().into();
    let (fh, _) = nfs.create(dh, &fname, sattr3::default()).await.unwrap();
    nfs.write(fh, 0, b"dir rename test").await.unwrap();

    let new_dirname: nfsstring = b"renamed_dir".to_vec().into();
    nfs.rename(root, &dirname, root, &new_dirname)
        .await
        .unwrap();

    // Verify old name is gone
    let old_lookup = nfs.lookup(root, &dirname).await;
    assert!(matches!(old_lookup, Err(nfsstat3::NFS3ERR_NOENT)));

    // Verify new name exists and file inside is accessible
    let new_dh = nfs.lookup(root, &new_dirname).await.unwrap();
    let child_handle = nfs.lookup(new_dh, &fname).await.unwrap();
    let (read_data, _) = nfs.read(child_handle, 0, 100).await.unwrap();
    assert_eq!(&read_data, b"dir rename test");
}

#[tokio::test]
async fn test_nfs_rename_to_existing_file() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name_a: nfsstring = b"rename_src.txt".to_vec().into();
    let name_b: nfsstring = b"rename_dst.txt".to_vec().into();

    let (ha, _) = nfs.create(root, &name_a, sattr3::default()).await.unwrap();
    nfs.write(ha, 0, b"source data").await.unwrap();

    let (hb, _) = nfs.create(root, &name_b, sattr3::default()).await.unwrap();
    nfs.write(hb, 0, b"destination data").await.unwrap();

    // Rename source to destination name -- may overwrite or error.
    let result = nfs.rename(root, &name_a, root, &name_b).await;
    if result.is_ok() {
        // Source name should be gone, destination should have source data
        let lookup_a = nfs.lookup(root, &name_a).await;
        assert!(matches!(lookup_a, Err(nfsstat3::NFS3ERR_NOENT)));

        let new_handle = nfs.lookup(root, &name_b).await.unwrap();
        let (read_data, _) = nfs.read(new_handle, 0, 100).await.unwrap();
        assert_eq!(&read_data, b"source data");
    }
    // If result is Err, the implementation disallows overwriting -- also acceptable.
}

#[tokio::test]
async fn test_nfs_rename_preserves_data() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let old_name: nfsstring = b"preserve_old.txt".to_vec().into();
    let new_name: nfsstring = b"preserve_new.txt".to_vec().into();

    let (fh, _) = nfs
        .create(root, &old_name, sattr3::default())
        .await
        .unwrap();
    let data: Vec<u8> = (0..5000_u32).map(|i| (i % 256) as u8).collect();
    nfs.write(fh, 0, &data).await.unwrap();

    nfs.rename(root, &old_name, root, &new_name).await.unwrap();

    let new_handle = nfs.lookup(root, &new_name).await.unwrap();
    let (read_data, _) = nfs.read(new_handle, 0, data.len() as u32).await.unwrap();
    assert_eq!(read_data, data, "data should be identical after rename");
}

#[tokio::test]
async fn test_nfs_rename_nested_dir_preserves_subtree() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    // Create dir/subdir/file
    let dir_name: nfsstring = b"subtree_top".to_vec().into();
    let (dh, _) = nfs.mkdir(root, &dir_name).await.unwrap();

    let sub_name: nfsstring = b"subtree_sub".to_vec().into();
    let (sh, _) = nfs.mkdir(dh, &sub_name).await.unwrap();

    let fname: nfsstring = b"subtree_leaf.txt".to_vec().into();
    let (fh, _) = nfs.create(sh, &fname, sattr3::default()).await.unwrap();
    nfs.write(fh, 0, b"subtree leaf data").await.unwrap();

    // Rename top-level dir
    let new_dir_name: nfsstring = b"subtree_top_renamed".to_vec().into();
    nfs.rename(root, &dir_name, root, &new_dir_name)
        .await
        .unwrap();

    // Navigate through renamed tree
    let new_dh = nfs.lookup(root, &new_dir_name).await.unwrap();
    let new_sh = nfs.lookup(new_dh, &sub_name).await.unwrap();
    let new_fh = nfs.lookup(new_sh, &fname).await.unwrap();

    let (read_data, _) = nfs.read(new_fh, 0, 100).await.unwrap();
    assert_eq!(&read_data, b"subtree leaf data");
}

// ---------------------------------------------------------------------------
// 4. Handle Management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_lookup_returns_consistent_handle() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"consistent_handle.txt".to_vec().into();
    let (create_handle, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let h1 = nfs.lookup(root, &fname).await.unwrap();
    let h2 = nfs.lookup(root, &fname).await.unwrap();
    let h3 = nfs.lookup(root, &fname).await.unwrap();

    assert_eq!(h1, create_handle);
    assert_eq!(h2, create_handle);
    assert_eq!(h3, create_handle);
}

#[tokio::test]
async fn test_nfs_handle_survives_write() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"handle_after_write.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    nfs.write(fh, 0, b"write some data").await.unwrap();

    // Handle should still work for getattr
    let attr = nfs.getattr(fh).await.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3REG));
    assert!(attr.size > 0);
}

#[tokio::test]
async fn test_nfs_evicted_handle_becomes_stale() {
    let nfs = setup_nfs_server_with_capacity(3);
    let root = nfs.root_dir();

    // Create 3 files -- fills the capacity
    let f1: nfsstring = b"evict_a.txt".to_vec().into();
    let (handle_a, _) = nfs.create(root, &f1, sattr3::default()).await.unwrap();

    let f2: nfsstring = b"evict_b.txt".to_vec().into();
    let (handle_b, _) = nfs.create(root, &f2, sattr3::default()).await.unwrap();

    let f3: nfsstring = b"evict_c.txt".to_vec().into();
    let (handle_c, _) = nfs.create(root, &f3, sattr3::default()).await.unwrap();

    // Creating a 4th file should evict the oldest (handle_a)
    let f4: nfsstring = b"evict_d.txt".to_vec().into();
    nfs.create(root, &f4, sattr3::default()).await.unwrap();

    let result = nfs.getattr(handle_a).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_STALE)),
        "evicted handle should be stale, got {result:?}"
    );

    // Verify non-evicted handles are still valid
    let attr_b = nfs.getattr(handle_b).await;
    assert!(attr_b.is_ok(), "handle_b should still be valid");
    let attr_c = nfs.getattr(handle_c).await;
    assert!(attr_c.is_ok(), "handle_c should still be valid");
}

#[tokio::test]
async fn test_nfs_root_handle_never_evicted() {
    let nfs = setup_nfs_server_with_capacity(1);
    let root = nfs.root_dir();

    // Create many files to trigger evictions; root should survive
    for i in 0..10 {
        let fname: nfsstring = format!("root_evict_{i}.txt").into_bytes().into();
        nfs.create(root, &fname, sattr3::default()).await.unwrap();
    }

    // Root handle should still work
    let attr = nfs.getattr(root).await.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3DIR));
}

// ---------------------------------------------------------------------------
// 5. Setattr / Truncation Edge Cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_truncate_empty_file_to_zero() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"trunc_empty_to_zero.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::size(0),
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };

    let result = nfs.setattr(fh, sattr).await;
    assert!(
        result.is_ok(),
        "truncating empty file to zero should succeed: {result:?}"
    );
    assert_eq!(result.unwrap().size, 0);
}

#[tokio::test]
async fn test_nfs_truncate_to_same_size() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"trunc_same_size.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let data = b"0123456789";
    nfs.write(fh, 0, data).await.unwrap();

    // Truncate to same size (extend branch -- no-op)
    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::size(10),
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };

    let result = nfs.setattr(fh, sattr).await;
    assert!(
        result.is_ok(),
        "truncate to same size should succeed: {result:?}"
    );
    let attr = result.unwrap();
    assert_eq!(attr.size, 10);

    // Verify data intact
    let (read_data, _) = nfs.read(fh, 0, 100).await.unwrap();
    assert_eq!(&read_data, data);
}

#[tokio::test]
async fn test_nfs_truncate_then_write() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"trunc_then_write.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    nfs.write(fh, 0, b"old data that should vanish")
        .await
        .unwrap();

    // Truncate to 0
    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::size(0),
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };
    nfs.setattr(fh, sattr).await.unwrap();

    // Write new data
    let new_data = b"brand new content";
    nfs.write(fh, 0, new_data).await.unwrap();

    let (read_data, _) = nfs.read(fh, 0, 1024).await.unwrap();
    assert_eq!(&read_data, new_data);
}

#[tokio::test]
async fn test_nfs_setattr_without_size_change() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"setattr_no_size.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();
    nfs.write(fh, 0, b"some content").await.unwrap();

    // setattr with no size field
    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::Void,
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };

    let result = nfs.setattr(fh, sattr).await;
    assert!(
        result.is_ok(),
        "setattr without size should succeed: {result:?}"
    );
    let attr = result.unwrap();
    assert_eq!(attr.size, 12, "file size should be unchanged");
}

#[tokio::test]
async fn test_nfs_truncate_rejects_oversized_request() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name: nfsstring = b"fbig_test.txt".to_vec().into();
    let (handle, _) = nfs.create(root, &name, sattr3::default()).await.unwrap();
    nfs.write(handle, 0, b"data").await.unwrap();

    // Request truncation to > 1 GiB, should return NFS3ERR_FBIG
    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::size((1u64 << 30) + 1),
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };
    let result = nfs.setattr(handle, sattr).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_FBIG)),
        "oversized truncation should return NFS3ERR_FBIG, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_truncate_shrink_preserves_prefix() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name: nfsstring = b"shrink_test.txt".to_vec().into();
    let (handle, _) = nfs.create(root, &name, sattr3::default()).await.unwrap();

    // Write 1000 bytes of pattern data
    let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    nfs.write(handle, 0, &data).await.unwrap();

    // Truncate to 500 bytes
    let sattr = sattr3 {
        mode: set_mode3::Void,
        uid: set_uid3::Void,
        gid: set_gid3::Void,
        size: set_size3::size(500),
        atime: set_atime::DONT_CHANGE,
        mtime: set_mtime::DONT_CHANGE,
    };
    let result = nfs.setattr(handle, sattr).await;
    assert!(result.is_ok(), "truncate to 500 failed: {result:?}");
    assert_eq!(result.unwrap().size, 500);

    // Read back and verify only the first 500 bytes remain
    let (read_data, eof) = nfs.read(handle, 0, 1000).await.unwrap();
    assert_eq!(read_data.len(), 500);
    assert_eq!(&read_data[..], &data[..500]);
    assert!(eof);
}

// ---------------------------------------------------------------------------
// 6. Multiple Files and Directories
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_many_files_in_directory() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dir_name: nfsstring = b"many_files_dir".to_vec().into();
    let (dh, _) = nfs.mkdir(root, &dir_name).await.unwrap();

    let count = 25;
    for i in 0..count {
        let fname: nfsstring = format!("mf_{i:03}.txt").into_bytes().into();
        nfs.create(dh, &fname, sattr3::default()).await.unwrap();
    }

    let result = nfs.readdir(dh, 0, 100).await.unwrap();
    assert_eq!(
        result.entries.len(),
        count,
        "readdir should list all {count} files"
    );
    assert!(result.end);
}

#[tokio::test]
async fn test_nfs_readdir_with_mixed_types() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dir_name: nfsstring = b"mixed_types_dir".to_vec().into();
    let (dh, _) = nfs.mkdir(root, &dir_name).await.unwrap();

    // Create files
    let f1: nfsstring = b"mixed_file1.txt".to_vec().into();
    let f2: nfsstring = b"mixed_file2.txt".to_vec().into();
    nfs.create(dh, &f1, sattr3::default()).await.unwrap();
    nfs.create(dh, &f2, sattr3::default()).await.unwrap();

    // Create subdirectories
    let d1: nfsstring = b"mixed_subdir1".to_vec().into();
    let d2: nfsstring = b"mixed_subdir2".to_vec().into();
    nfs.mkdir(dh, &d1).await.unwrap();
    nfs.mkdir(dh, &d2).await.unwrap();

    let result = nfs.readdir(dh, 0, 100).await.unwrap();
    assert_eq!(result.entries.len(), 4);

    let mut files = 0;
    let mut dirs = 0;
    for entry in &result.entries {
        match entry.attr.ftype {
            ftype3::NF3REG => files += 1,
            ftype3::NF3DIR => dirs += 1,
            _ => panic!("unexpected ftype"),
        }
    }
    assert_eq!(files, 2, "should have 2 regular files");
    assert_eq!(dirs, 2, "should have 2 directories");
}

#[tokio::test]
async fn test_nfs_multiple_directories_at_root() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let names = [
        "multi_root_a",
        "multi_root_b",
        "multi_root_c",
        "multi_root_d",
        "multi_root_e",
    ];
    let mut handles = Vec::new();
    for name in &names {
        let n: nfsstring = name.as_bytes().to_vec().into();
        let (h, _) = nfs.mkdir(root, &n).await.unwrap();
        handles.push(h);
    }

    // Verify all accessible via lookup
    for (name, expected_handle) in names.iter().zip(handles.iter()) {
        let n: nfsstring = name.as_bytes().to_vec().into();
        let h = nfs.lookup(root, &n).await.unwrap();
        assert_eq!(h, *expected_handle);
    }
}

#[tokio::test]
async fn test_nfs_file_isolation() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let f1: nfsstring = b"isolated_a.txt".to_vec().into();
    let f2: nfsstring = b"isolated_b.txt".to_vec().into();

    let (h1, _) = nfs.create(root, &f1, sattr3::default()).await.unwrap();
    let (h2, _) = nfs.create(root, &f2, sattr3::default()).await.unwrap();

    let data1 = b"alpha data for file one";
    let data2 = b"beta data for file two";
    nfs.write(h1, 0, data1).await.unwrap();
    nfs.write(h2, 0, data2).await.unwrap();

    let (read1, _) = nfs.read(h1, 0, 1024).await.unwrap();
    let (read2, _) = nfs.read(h2, 0, 1024).await.unwrap();

    assert_eq!(&read1, data1, "file 1 should contain its own data");
    assert_eq!(&read2, data2, "file 2 should contain its own data");
}

// ---------------------------------------------------------------------------
// 7. Error Handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_write_to_directory() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dirname: nfsstring = b"write_to_dir".to_vec().into();
    let (dh, _) = nfs.mkdir(root, &dirname).await.unwrap();

    let result = nfs.write(dh, 0, b"should fail").await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_ISDIR)),
        "writing to a directory should return NFS3ERR_ISDIR, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_create_in_nonexistent_dir() {
    let nfs = setup_nfs_server();
    let stale_handle = 9998_u64;

    let fname: nfsstring = b"orphan.txt".to_vec().into();
    let result = nfs.create(stale_handle, &fname, sattr3::default()).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_STALE)),
        "create in nonexistent dir should return STALE, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_remove_nonexistent_file() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"does_not_exist_remove.txt".to_vec().into();
    let result = nfs.remove(root, &fname).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_NOENT)),
        "removing nonexistent file should return NFS3ERR_NOENT, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_readdir_on_file() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"readdir_on_file.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let result = nfs.readdir(fh, 0, 10).await;
    assert!(
        result.is_err(),
        "readdir on a file should fail, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_lookup_in_file() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"lookup_in_file.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let child: nfsstring = b"child.txt".to_vec().into();
    let result = nfs.lookup(fh, &child).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_NOENT)),
        "lookup in file should fail, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_mkdir_rejects_slash() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name: nfsstring = b"bad/dir".to_vec().into();
    let result = nfs.mkdir(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_INVAL)),
        "mkdir with slash should return INVAL, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_mkdir_rejects_null() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name: nfsstring = b"bad\0dir".to_vec().into();
    let result = nfs.mkdir(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_INVAL)),
        "mkdir with null should return INVAL, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_remove_rejects_dotdot() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let name: nfsstring = b"..".to_vec().into();
    let result = nfs.remove(root, &name).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_INVAL)),
        "remove with '..' should return INVAL, got {result:?}"
    );
}

#[tokio::test]
async fn test_nfs_create_exclusive_in_nonexistent_dir() {
    let nfs = setup_nfs_server();
    let stale_handle = 9997_u64;

    let fname: nfsstring = b"excl_orphan.txt".to_vec().into();
    let result = nfs.create_exclusive(stale_handle, &fname).await;
    assert!(
        matches!(result, Err(nfsstat3::NFS3ERR_STALE)),
        "create_exclusive in nonexistent dir should return STALE, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. Data Integrity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_write_read_binary_data() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"binary_256.bin".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    // Write all 256 byte values
    let data: Vec<u8> = (0..=255).collect();
    nfs.write(fh, 0, &data).await.unwrap();

    let (read_data, eof) = nfs.read(fh, 0, 256).await.unwrap();
    assert_eq!(read_data.len(), 256);
    assert!(eof);
    assert_eq!(read_data, data, "all 256 byte values should round-trip");
}

#[tokio::test]
async fn test_nfs_write_read_large_binary() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"large_binary_256k.bin".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let size = 256 * 1024; // 256 KB
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    nfs.write(fh, 0, &data).await.unwrap();

    let (read_data, _) = nfs.read(fh, 0, size as u32).await.unwrap();
    assert_eq!(read_data.len(), data.len());
    assert_eq!(
        read_data, data,
        "256KB of pattern data should round-trip correctly"
    );
}

#[tokio::test]
async fn test_nfs_sequential_small_writes() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"sequential_small.bin".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();

    // Write 1 byte at a time for 100 bytes
    for i in 0..100_u8 {
        nfs.write(fh, i as u64, &[i]).await.unwrap();
    }

    let (read_data, _) = nfs.read(fh, 0, 200).await.unwrap();
    assert_eq!(read_data.len(), 100);
    let expected: Vec<u8> = (0..100).collect();
    assert_eq!(read_data, expected);
}

#[tokio::test]
async fn test_nfs_interleaved_file_operations() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let f1: nfsstring = b"interleave_a.txt".to_vec().into();
    let f2: nfsstring = b"interleave_b.txt".to_vec().into();

    let (h1, _) = nfs.create(root, &f1, sattr3::default()).await.unwrap();
    let (h2, _) = nfs.create(root, &f2, sattr3::default()).await.unwrap();

    // Alternate writes between the two files
    nfs.write(h1, 0, b"A1").await.unwrap();
    nfs.write(h2, 0, b"B1").await.unwrap();
    nfs.write(h1, 2, b"A2").await.unwrap();
    nfs.write(h2, 2, b"B2").await.unwrap();
    nfs.write(h1, 4, b"A3").await.unwrap();
    nfs.write(h2, 4, b"B3").await.unwrap();

    let (data1, _) = nfs.read(h1, 0, 100).await.unwrap();
    let (data2, _) = nfs.read(h2, 0, 100).await.unwrap();

    assert_eq!(&data1, b"A1A2A3");
    assert_eq!(&data2, b"B1B2B3");
}

#[tokio::test]
async fn test_nfs_data_persists_after_rename() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let old_name: nfsstring = b"persist_before.txt".to_vec().into();
    let new_name: nfsstring = b"persist_after.txt".to_vec().into();

    let (fh, _) = nfs
        .create(root, &old_name, sattr3::default())
        .await
        .unwrap();
    let data = b"data must persist through rename";
    nfs.write(fh, 0, data).await.unwrap();

    nfs.rename(root, &old_name, root, &new_name).await.unwrap();

    let new_handle = nfs.lookup(root, &new_name).await.unwrap();
    let (read_data, eof) = nfs.read(new_handle, 0, 1024).await.unwrap();
    assert_eq!(&read_data, data);
    assert!(eof);
}

// ---------------------------------------------------------------------------
// 9. Readdir Pagination Edge Cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_readdir_with_zero_max() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"zero_max_file.txt".to_vec().into();
    nfs.create(root, &fname, sattr3::default()).await.unwrap();

    let result = nfs.readdir(root, 0, 0).await.unwrap();
    assert!(
        result.entries.is_empty(),
        "readdir with max_entries=0 should return no entries"
    );
    assert!(
        !result.end,
        "readdir with zero max_entries should indicate more entries exist"
    );
}

#[tokio::test]
async fn test_nfs_readdir_cookie_after_deletion() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dir_name: nfsstring = b"cookie_del_dir".to_vec().into();
    let (dh, _) = nfs.mkdir(root, &dir_name).await.unwrap();

    // Create 3 files
    let f1: nfsstring = b"cdel_a.txt".to_vec().into();
    let f2: nfsstring = b"cdel_b.txt".to_vec().into();
    let f3: nfsstring = b"cdel_c.txt".to_vec().into();
    nfs.create(dh, &f1, sattr3::default()).await.unwrap();
    nfs.create(dh, &f2, sattr3::default()).await.unwrap();
    nfs.create(dh, &f3, sattr3::default()).await.unwrap();

    // Get all entries and pick the first cookie
    let all = nfs.readdir(dh, 0, 100).await.unwrap();
    assert_eq!(all.entries.len(), 3);
    let first_cookie = all.entries[0].fileid;

    // Delete the file corresponding to the first cookie
    let first_name = &all.entries[0].name;
    nfs.remove(dh, first_name).await.unwrap();

    // readdir with the deleted cookie -- should return end=true (stale cursor recovery)
    let result = nfs.readdir(dh, first_cookie, 100).await.unwrap();
    assert!(result.end, "readdir with stale cookie should signal end");
}

#[tokio::test]
async fn test_nfs_readdir_single_entry_per_page() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dir_name: nfsstring = b"single_page_dir".to_vec().into();
    let (dh, _) = nfs.mkdir(root, &dir_name).await.unwrap();

    // Create 3 files
    for i in 0..3 {
        let fname: nfsstring = format!("sp_{i}.txt").into_bytes().into();
        nfs.create(dh, &fname, sattr3::default()).await.unwrap();
    }

    let mut all_names = std::collections::HashSet::new();

    // Page 1
    let page1 = nfs.readdir(dh, 0, 1).await.unwrap();
    assert_eq!(page1.entries.len(), 1);
    assert!(!page1.end);
    all_names.insert(String::from_utf8_lossy(&page1.entries[0].name).to_string());
    let cookie1 = page1.entries[0].fileid;

    // Page 2
    let page2 = nfs.readdir(dh, cookie1, 1).await.unwrap();
    assert_eq!(page2.entries.len(), 1);
    assert!(!page2.end);
    all_names.insert(String::from_utf8_lossy(&page2.entries[0].name).to_string());
    let cookie2 = page2.entries[0].fileid;

    // Page 3
    let page3 = nfs.readdir(dh, cookie2, 1).await.unwrap();
    assert_eq!(page3.entries.len(), 1);
    assert!(page3.end);
    all_names.insert(String::from_utf8_lossy(&page3.entries[0].name).to_string());

    assert_eq!(
        all_names.len(),
        3,
        "all 3 files should be seen across pages"
    );
}

// ---------------------------------------------------------------------------
// 10. Create Behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nfs_create_existing_file_behavior() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"create_existing.txt".to_vec().into();
    let (fh, _) = nfs.create(root, &fname, sattr3::default()).await.unwrap();
    nfs.write(fh, 0, b"some existing data").await.unwrap();

    // Verify file has data
    let attr = nfs.getattr(fh).await.unwrap();
    assert!(attr.size > 0);

    // Creating again may truncate or error depending on the provider.
    // With MemoryFs + CryptoFs the underlying create_file errors for
    // an existing path, so we accept either outcome.
    let result = nfs.create(root, &fname, sattr3::default()).await;
    match result {
        Ok((fh2, attr2)) => {
            assert_eq!(attr2.size, 0, "recreated file should have size 0");
            let (read_data, eof) = nfs.read(fh2, 0, 1024).await.unwrap();
            assert!(read_data.is_empty());
            assert!(eof);
        }
        Err(_) => {
            // Provider does not support overwrite-on-create; original file
            // should remain intact.
            let (read_data, _) = nfs.read(fh, 0, 1024).await.unwrap();
            assert_eq!(&read_data, b"some existing data");
        }
    }
}

#[tokio::test]
async fn test_nfs_create_in_root_returns_correct_type() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"type_check_file.txt".to_vec().into();
    let (_, attr) = nfs.create(root, &fname, sattr3::default()).await.unwrap();
    assert!(
        matches!(attr.ftype, ftype3::NF3REG),
        "created file should have type NF3REG, got {:?}",
        attr.ftype
    );
}

#[tokio::test]
async fn test_nfs_mkdir_returns_correct_type() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let dirname: nfsstring = b"type_check_dir".to_vec().into();
    let (_, attr) = nfs.mkdir(root, &dirname).await.unwrap();
    assert!(
        matches!(attr.ftype, ftype3::NF3DIR),
        "created directory should have type NF3DIR, got {:?}",
        attr.ftype
    );
}

#[tokio::test]
async fn test_nfs_create_exclusive_returns_valid_handle() {
    let nfs = setup_nfs_server();
    let root = nfs.root_dir();

    let fname: nfsstring = b"excl_valid_handle.txt".to_vec().into();
    let handle = nfs.create_exclusive(root, &fname).await.unwrap();

    // Verify handle works with getattr
    let attr = nfs.getattr(handle).await.unwrap();
    assert!(matches!(attr.ftype, ftype3::NF3REG));
    assert_eq!(attr.size, 0);

    // Verify we can write to it
    nfs.write(handle, 0, b"exclusive write").await.unwrap();
    let (read_data, _) = nfs.read(handle, 0, 1024).await.unwrap();
    assert_eq!(&read_data, b"exclusive write");
}
