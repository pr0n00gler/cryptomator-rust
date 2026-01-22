use cryptomator::crypto::{Cryptor, Vault};
use cryptomator::cryptofs::CryptoFs;
use cryptomator::frontends::webdav::WebDav;
use cryptomator::providers::{LocalFs, MemoryFs};
use std::io::SeekFrom;
use webdav_handler::davpath::DavPath;
use webdav_handler::fs::{DavFileSystem, OpenOptions};

const PATH_TO_VAULT: &str = "tests/test_storage/vault.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";
const VFS_STORAGE_PATH: &str = "/";

fn setup_webdav_server() -> WebDav<MemoryFs> {
    let mem_fs = MemoryFs::new();
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = Cryptor::new(vault);
    let crypto_fs = CryptoFs::new(VFS_STORAGE_PATH, cryptor, mem_fs).unwrap();
    WebDav::new(crypto_fs)
}

#[tokio::test]
async fn test_webdav_metadata_root() {
    let webdav = setup_webdav_server();
    let root_path = DavPath::new("/").unwrap();

    let result = webdav.metadata(&root_path).await;
    assert!(result.is_ok(), "Failed to get root metadata");

    let metadata = result.unwrap();
    assert!(metadata.is_dir(), "Root should be a directory");
}

#[tokio::test]
async fn test_webdav_create_and_metadata() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/test.txt").unwrap();

    // Create a file
    let options = OpenOptions {
        read: false,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let result = webdav.open(&file_path, options).await;
    assert!(result.is_ok(), "Failed to create file: {:?}", result.err());

    drop(result.unwrap());

    // Get metadata
    let metadata_result = webdav.metadata(&file_path).await;
    assert!(metadata_result.is_ok());

    let metadata = metadata_result.unwrap();
    assert!(!metadata.is_dir());
    assert_eq!(metadata.len(), 0);
}

#[tokio::test]
async fn test_webdav_write_to_new_file() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/write_test.txt").unwrap();

    // Create and open file for writing
    let options = OpenOptions {
        read: true,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&file_path, options).await.unwrap();

    // Write data
    let test_data = b"Hello, WebDAV World!";
    file.write_bytes(bytes::Bytes::from(test_data.to_vec()))
        .await
        .unwrap();
    file.flush().await.unwrap();

    // Get metadata to verify size
    let metadata = file.metadata().await.unwrap();
    assert_eq!(metadata.len(), test_data.len() as u64);
}

#[tokio::test]
async fn test_webdav_write_and_read() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/write_read_test.txt").unwrap();

    // Create and write
    let options = OpenOptions {
        read: true,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&file_path, options).await.unwrap();
    let test_data = b"Hello, WebDAV World! This is a test.";
    file.write_bytes(bytes::Bytes::from(test_data.to_vec()))
        .await
        .unwrap();
    file.flush().await.unwrap();
    drop(file);

    // Read back
    let read_options = OpenOptions {
        read: true,
        write: false,
        append: false,
        truncate: false,
        create: false,
        create_new: false,
    };

    let mut file = webdav.open(&file_path, read_options).await.unwrap();
    let read_data = file.read_bytes(test_data.len()).await.unwrap();
    assert_eq!(read_data.as_ref(), test_data);
}

#[tokio::test]
async fn test_webdav_seek_and_write() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/seek_write_test.txt").unwrap();

    let options = OpenOptions {
        read: true,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&file_path, options).await.unwrap();

    // Write initial data
    let initial_data = b"0123456789";
    file.write_bytes(bytes::Bytes::from(initial_data.to_vec()))
        .await
        .unwrap();
    file.flush().await.unwrap();

    // Seek and overwrite
    file.seek(SeekFrom::Start(3)).await.unwrap();
    let overwrite_data = b"ABCD";
    file.write_bytes(bytes::Bytes::from(overwrite_data.to_vec()))
        .await
        .unwrap();
    file.flush().await.unwrap();

    // Read and verify
    file.seek(SeekFrom::Start(0)).await.unwrap();
    let read_data = file.read_bytes(10).await.unwrap();
    let expected = b"012ABCD789";
    assert_eq!(&read_data[..], expected);
}

#[tokio::test]
async fn test_webdav_large_write() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/large_file.dat").unwrap();

    let options = OpenOptions {
        read: true,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&file_path, options).await.unwrap();

    // Write large amount of data
    let large_data: Vec<u8> = (0..100000).map(|i| (i % 256) as u8).collect();
    file.write_bytes(bytes::Bytes::from(large_data.clone()))
        .await
        .unwrap();
    file.flush().await.unwrap();

    // Verify size
    let metadata = file.metadata().await.unwrap();
    assert_eq!(metadata.len(), large_data.len() as u64);

    // Read back and verify
    file.seek(SeekFrom::Start(0)).await.unwrap();
    let read_data = file.read_bytes(large_data.len()).await.unwrap();
    assert_eq!(read_data.as_ref(), &large_data[..]);
}

#[tokio::test]
async fn test_webdav_create_dir() {
    let webdav = setup_webdav_server();
    let dir_path = DavPath::new("/testdir").unwrap();

    let result = webdav.create_dir(&dir_path).await;
    assert!(result.is_ok(), "Failed to create directory");

    // Verify directory exists and is a directory
    let metadata = webdav.metadata(&dir_path).await.unwrap();
    assert!(metadata.is_dir());
}

#[tokio::test]
async fn test_webdav_create_file_in_dir() {
    let webdav = setup_webdav_server();
    let dir_path = DavPath::new("/dir_with_file").unwrap();
    let file_path = DavPath::new("/dir_with_file/file.txt").unwrap();

    // Create directory
    webdav.create_dir(&dir_path).await.unwrap();

    // Create file in directory
    let options = OpenOptions {
        read: true,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&file_path, options).await.unwrap();
    let test_data = b"File in directory";
    file.write_bytes(bytes::Bytes::from(test_data.to_vec()))
        .await
        .unwrap();
    file.flush().await.unwrap();

    // Verify file metadata
    let metadata = file.metadata().await.unwrap();
    assert_eq!(metadata.len(), test_data.len() as u64);
}

#[tokio::test]
async fn test_webdav_remove_file() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/to_remove.txt").unwrap();

    // Create file
    let options = OpenOptions {
        read: false,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&file_path, options).await.unwrap();
    file.write_bytes(bytes::Bytes::from(b"test".to_vec()))
        .await
        .unwrap();
    file.flush().await.unwrap();
    drop(file);

    // Remove file
    let result = webdav.remove_file(&file_path).await;
    assert!(result.is_ok());

    // Verify file is gone
    let metadata_result = webdav.metadata(&file_path).await;
    assert!(metadata_result.is_err());
}

#[tokio::test]
async fn test_webdav_write_buf() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/write_buf_test.txt").unwrap();

    let options = OpenOptions {
        read: true,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&file_path, options).await.unwrap();

    // Write data using write_buf
    let test_data = b"Hello from write_buf!";
    let buf = Box::new(std::io::Cursor::new(test_data.to_vec()));
    file.write_buf(buf).await.unwrap();
    file.flush().await.unwrap();

    // Verify
    file.seek(SeekFrom::Start(0)).await.unwrap();
    let read_data = file.read_bytes(test_data.len()).await.unwrap();
    assert_eq!(read_data.as_ref(), test_data);
}

#[tokio::test]
async fn test_webdav_get_quota() {
    let webdav = setup_webdav_server();
    let result = webdav.get_quota().await;
    assert!(result.is_ok());
    let (used, total) = result.unwrap();
    // In MemoryFs, stats might be 0 or some default
    assert!(total.is_some());
    assert!(total.unwrap() >= used);
}

#[tokio::test]
async fn test_webdav_open_create_new_exists() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/exists.txt").unwrap();

    // Create it first
    let options = OpenOptions {
        read: false,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };
    webdav.open(&file_path, options).await.unwrap();

    // Try to create_new
    let options_new = OpenOptions {
        read: false,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: true,
    };
    let result = webdav.open(&file_path, options_new).await;
    assert!(result.is_err());
    // Should be FsError::Exists
    if let Err(e) = result {
        assert_eq!(e, webdav_handler::fs::FsError::Exists);
    }
}

#[tokio::test]
async fn test_webdav_open_not_found() {
    let webdav = setup_webdav_server();
    let file_path = DavPath::new("/not_found.txt").unwrap();

    let options = OpenOptions {
        read: true,
        write: false,
        append: false,
        truncate: false,
        create: false,
        create_new: false,
    };
    let result = webdav.open(&file_path, options).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_webdav_read_dir_not_found() {
    let webdav = setup_webdav_server();
    let dir_path = DavPath::new("/nonexistent_dir").unwrap();

    use webdav_handler::fs::ReadDirMeta;
    let result = webdav.read_dir(&dir_path, ReadDirMeta::None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_webdav_copy_file() {
    let webdav = setup_webdav_server();
    let source_path = DavPath::new("/source.txt").unwrap();
    let dest_path = DavPath::new("/dest.txt").unwrap();

    // Create and write source file
    let options = OpenOptions {
        read: true,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&source_path, options).await.unwrap();
    let test_data = b"copy test data";
    file.write_bytes(bytes::Bytes::from(test_data.to_vec()))
        .await
        .unwrap();
    file.flush().await.unwrap();
    drop(file);

    // Copy file
    let result = webdav.copy(&source_path, &dest_path).await;
    assert!(result.is_ok());

    // Verify both files exist
    assert!(webdav.metadata(&source_path).await.is_ok());
    assert!(webdav.metadata(&dest_path).await.is_ok());

    // Verify copied data
    let read_options = OpenOptions {
        read: true,
        write: false,
        append: false,
        truncate: false,
        create: false,
        create_new: false,
    };

    let mut dest_file = webdav.open(&dest_path, read_options).await.unwrap();
    let read_data = dest_file.read_bytes(test_data.len()).await.unwrap();
    assert_eq!(read_data.as_ref(), test_data);
}

#[tokio::test]
async fn test_webdav_read_dir() {
    let webdav = setup_webdav_server();
    let root_path = DavPath::new("/").unwrap();

    // Create multiple files
    for i in 0..5 {
        let file_path = DavPath::new(&format!("/file{}.txt", i)).unwrap();
        let options = OpenOptions {
            read: false,
            write: true,
            append: false,
            truncate: false,
            create: true,
            create_new: false,
        };

        let mut file = webdav.open(&file_path, options).await.unwrap();
        file.write_bytes(bytes::Bytes::from(b"test".to_vec()))
            .await
            .unwrap();
        file.flush().await.unwrap();
    }

    // Read directory
    use futures::StreamExt;
    use webdav_handler::fs::ReadDirMeta;

    let result = webdav.read_dir(&root_path, ReadDirMeta::None).await;
    assert!(result.is_ok());

    let mut stream = result.unwrap();
    let mut count = 0;
    while let Some(_entry) = stream.next().await {
        count += 1;
    }

    assert_eq!(count, 5, "Should have 5 files in directory");
}

#[tokio::test]
async fn test_webdav_remove_dir() {
    let webdav = setup_webdav_server();
    let dir_path = DavPath::new("/dir_to_remove").unwrap();

    // Create directory
    webdav.create_dir(&dir_path).await.unwrap();

    // Verify it exists
    assert!(webdav.metadata(&dir_path).await.is_ok());

    // Remove directory
    let result = webdav.remove_dir(&dir_path).await;
    assert!(result.is_ok());

    // Verify it's gone
    let metadata_result = webdav.metadata(&dir_path).await;
    assert!(metadata_result.is_err());
}

#[tokio::test]
async fn test_webdav_rename_file() {
    let webdav = setup_webdav_server();
    let source_path = DavPath::new("/source_rename.txt").unwrap();
    let dest_path = DavPath::new("/dest_rename.txt").unwrap();

    // 1. Create and write source file
    let options = OpenOptions {
        read: false,
        write: true,
        append: false,
        truncate: false,
        create: true,
        create_new: false,
    };

    let mut file = webdav.open(&source_path, options).await.unwrap();
    let test_data = b"rename test data";
    file.write_bytes(bytes::Bytes::from(test_data.to_vec()))
        .await
        .unwrap();
    file.flush().await.unwrap();
    drop(file);

    // 2. Perform Rename
    let result = webdav.rename(&source_path, &dest_path).await;
    assert!(result.is_ok(), "Rename failed: {:?}", result.err());

    // 3. Verify destination exists and source is gone
    assert!(
        webdav.metadata(&dest_path).await.is_ok(),
        "Destination file should exist"
    );
    assert!(
        webdav.metadata(&source_path).await.is_err(),
        "Source file should no longer exist"
    );

    // 4. Verify content integrity in destination
    let read_options = OpenOptions {
        read: true,
        write: false,
        append: false,
        truncate: false,
        create: false,
        create_new: false,
    };
    let mut dest_file = webdav.open(&dest_path, read_options).await.unwrap();
    let read_data = dest_file.read_bytes(test_data.len()).await.unwrap();
    assert_eq!(
        read_data.as_ref(),
        test_data,
        "Data corruption after rename"
    );
}
