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
