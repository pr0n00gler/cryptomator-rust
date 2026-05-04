/// Integration tests for: MemFs (dav-server) -> WebDAV server -> WebDavFs -> CryptoFs
///
/// This test suite exercises every CryptoFs filesystem operation when
/// backed by the WebDAV provider (`WebDavFs`).  The WebDAV server is a
/// plain in-memory server (`dav_server::memfs::MemFs`) — no encryption on
/// the server side — so CryptoFs is the only encryption layer.
use cryptomator::crypto::{Cryptor, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH, Vault};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig, File, FileSystemError, OpenOptions};
use cryptomator::providers::{LocalFs, WebDavFs};
use std::io::{Read, Seek, SeekFrom, Write};

const PATH_TO_VAULT: &str = "tests/test_storage/vault.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";
const VFS_STORAGE_PATH: &str = "/";

// ============================================================================
// Test infrastructure
// ============================================================================

/// Start a plain WebDAV server backed by `dav_server::memfs::MemFs`.
/// Returns the base URL and a handle to the server task.
async fn setup_plain_webdav_server() -> (String, tokio::task::JoinHandle<()>) {
    use dav_server::DavHandler;
    use dav_server::fakels::FakeLs;
    use dav_server::memfs::MemFs;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        let dav_handler = DavHandler::builder()
            .filesystem(MemFs::new())
            .locksystem(FakeLs::new())
            .build_handler();

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let io = TokioIo::new(stream);
            let dav_handler = dav_handler.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let dav_handler = dav_handler.clone();
                    async move { Ok::<_, std::convert::Infallible>(dav_handler.handle(req).await) }
                });
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // Wait for the server to accept connections.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return (base_url, handle);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("WebDAV server did not start within 1 second");
}

/// Run a closure on a plain OS thread so `reqwest::blocking::Client` does
/// not detect the ambient async runtime.
fn run_blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::thread::spawn(f).join().expect("test thread panicked")
}

/// Build a `CryptoFs<WebDavFs>` that stores encrypted data on the given
/// WebDAV server.
fn make_crypto_fs(base_url: &str) -> CryptoFs<WebDavFs> {
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = Cryptor::new(vault);
    let webdav_fs = WebDavFs::new(base_url, None, None);
    CryptoFs::new(
        VFS_STORAGE_PATH,
        cryptor,
        webdav_fs,
        CryptoFsConfig::default(),
    )
    .unwrap()
}

/// Build a `CryptoFs<WebDavFs>` with a custom config.
fn make_crypto_fs_with_config(base_url: &str, config: CryptoFsConfig) -> CryptoFs<WebDavFs> {
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = Cryptor::new(vault);
    let webdav_fs = WebDavFs::new(base_url, None, None);
    CryptoFs::new(VFS_STORAGE_PATH, cryptor, webdav_fs, config).unwrap()
}

/// Spins up a WebDAV server, creates a `CryptoFs` on top of it, and runs
/// the given closure.  The server task handle is aborted after the closure
/// returns so the background task does not leak.
async fn with_crypto_fs(f: impl FnOnce(CryptoFs<WebDavFs>) + Send + 'static) {
    let (base_url, handle) = setup_plain_webdav_server().await;
    run_blocking(move || {
        let fs = make_crypto_fs(&base_url);
        f(fs);
    });
    // Abort the background server task so it does not outlive the test.
    handle.abort();
}

/// Same as `with_crypto_fs` but accepts a custom `CryptoFsConfig`.
async fn with_crypto_fs_config(
    config: CryptoFsConfig,
    f: impl FnOnce(CryptoFs<WebDavFs>) + Send + 'static,
) {
    let (base_url, handle) = setup_plain_webdav_server().await;
    run_blocking(move || {
        let fs = make_crypto_fs_with_config(&base_url, config);
        f(fs);
    });
    handle.abort();
}

// ============================================================================
// File creation & basic read/write
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_file_and_read_back() {
    with_crypto_fs(|fs| {
        let mut file = fs.create_file("/hello.txt").unwrap();
        file.write_all(b"hello world").unwrap();
        file.flush().unwrap();
        drop(file);

        let mut file = fs.open_file("/hello.txt", OpenOptions::new()).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_empty_file() {
    with_crypto_fs(|fs| {
        let mut f = fs.create_file("/empty.txt").unwrap();
        f.flush().unwrap();
        drop(f);

        let mut file = fs.open_file("/empty.txt", OpenOptions::new()).unwrap();
        let mut buf = Vec::new();
        let n = file.read_to_end(&mut buf).unwrap();
        assert_eq!(n, 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_write_large_file() {
    with_crypto_fs(|fs| {
        // ~100 KB of patterned data (spans multiple encryption chunks)
        let data: Vec<u8> = (0..100 * 1024).map(|i| (i % 251) as u8).collect();

        let mut file = fs.create_file("/large.dat").unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        drop(file);

        let mut file = fs.open_file("/large.dat", OpenOptions::new()).unwrap();
        let mut result = Vec::new();
        file.read_to_end(&mut result).unwrap();
        assert_eq!(result.len(), data.len());
        assert_eq!(result, data);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_overwrite_file_via_remove_and_recreate() {
    with_crypto_fs(|fs| {
        // Write initial content
        let mut file = fs.create_file("/overwrite.txt").unwrap();
        file.write_all(b"initial content that is long").unwrap();
        file.flush().unwrap();
        drop(file);

        // Overwrite with shorter content by removing and recreating
        fs.remove_file("/overwrite.txt").unwrap();
        let mut file = fs.create_file("/overwrite.txt").unwrap();
        file.write_all(b"short").unwrap();
        file.flush().unwrap();
        drop(file);

        // Read back -- should be just "short", not the old longer content
        let mut file = fs.open_file("/overwrite.txt", OpenOptions::new()).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "short");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_write_at_offset() {
    with_crypto_fs(|fs| {
        // Write initial data
        let mut data = vec![0u8; 256];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut file = fs.create_file("/offset.dat").unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        drop(file);

        // Overwrite bytes 100..110 with 0xFF
        let patch = vec![0xFFu8; 10];
        let mut file = fs
            .open_file("/offset.dat", *OpenOptions::new().write(true))
            .unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(&patch).unwrap();
        file.flush().unwrap();
        drop(file);

        // Verify full content
        data[100..110].copy_from_slice(&patch);
        let mut file = fs.open_file("/offset.dat", OpenOptions::new()).unwrap();
        let mut result = Vec::new();
        file.read_to_end(&mut result).unwrap();
        assert_eq!(result, data);
    })
    .await;
}

// ============================================================================
// Seek & partial reads
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_seek_and_read_partial() {
    with_crypto_fs(|fs| {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let mut file = fs.create_file("/partial.dat").unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        drop(file);

        // Read bytes 100..200 via seek
        let mut file = fs.open_file("/partial.dat", OpenOptions::new()).unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = vec![0u8; 100];
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, &data[100..200]);

        // SeekFrom::End
        file.seek(SeekFrom::End(-50)).unwrap();
        let mut buf = vec![0u8; 50];
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, &data[974..1024]);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_seek_end_returns_file_size() {
    with_crypto_fs(|fs| {
        let data = vec![0xABu8; 5000];
        let mut file = fs.create_file("/size.dat").unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        drop(file);

        let mut file = fs.open_file("/size.dat", OpenOptions::new()).unwrap();
        let size = file.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(size, 5000);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_past_eof() {
    with_crypto_fs(|fs| {
        let mut f = fs.create_file("/short.dat").unwrap();
        f.write_all(b"short").unwrap();
        f.flush().unwrap();
        drop(f);

        let mut file = fs.open_file("/short.dat", OpenOptions::new()).unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = vec![0xFFu8; 10];
        let n = file.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sparse_write_and_read() {
    with_crypto_fs(|fs| {
        let mut file = fs.create_file("/sparse.dat").unwrap();
        let offset = (FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64 * 2) + 123;
        let payload = b"after-gap";

        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(payload).unwrap();
        file.flush().unwrap();
        drop(file);

        let mut reader = fs.open_file("/sparse.dat", OpenOptions::new()).unwrap();
        let mut data = Vec::new();
        reader.read_to_end(&mut data).unwrap();

        assert_eq!(data.len(), offset as usize + payload.len());
        assert!(data[..offset as usize].iter().all(|&b| b == 0));
        assert_eq!(&data[offset as usize..], payload);
    })
    .await;
}

// ============================================================================
// exists
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exists_file() {
    with_crypto_fs(|fs| {
        let mut f = fs.create_file("/exists.txt").unwrap();
        f.flush().unwrap();
        drop(f);
        assert!(fs.exists("/exists.txt"));
        assert!(!fs.exists("/nope.txt"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exists_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/mydir").unwrap();
        assert!(fs.exists("/mydir"));
        assert!(!fs.exists("/nodir"));
    })
    .await;
}

// ============================================================================
// Directories: create, read, remove
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/newdir").unwrap();
        assert!(fs.exists("/newdir"));

        let meta = fs.metadata("/newdir").unwrap();
        assert!(meta.is_dir);
        assert!(!meta.is_file);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_dir_all_nested() {
    with_crypto_fs(|fs| {
        fs.create_dir("/a/b/c").unwrap();
        assert!(fs.exists("/a"));
        assert!(fs.exists("/a/b"));
        assert!(fs.exists("/a/b/c"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_file_in_subdir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/subdir").unwrap();

        let mut f = fs.create_file("/subdir/file.txt").unwrap();
        f.write_all(b"in subdir").unwrap();
        f.flush().unwrap();
        drop(f);

        let mut f = fs
            .open_file("/subdir/file.txt", OpenOptions::new())
            .unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "in subdir");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/listdir").unwrap();
        let mut f = fs.create_file("/listdir/a.txt").unwrap();
        f.flush().unwrap();
        drop(f);
        let mut f = fs.create_file("/listdir/b.txt").unwrap();
        f.flush().unwrap();
        drop(f);
        fs.create_dir("/listdir/child").unwrap();

        let entries: Vec<_> = fs.read_dir("/listdir").unwrap().collect();
        assert_eq!(entries.len(), 3);

        let mut names: Vec<String> = entries
            .iter()
            .map(|e| e.file_name.to_str().unwrap().to_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.txt", "b.txt", "child"]);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_dir_root() {
    with_crypto_fs(|fs| {
        // Initially root should be empty
        let entries: Vec<_> = fs.read_dir("/").unwrap().collect();
        assert!(entries.is_empty());

        // Add some items
        let mut f = fs.create_file("/root_file.txt").unwrap();
        f.flush().unwrap();
        drop(f);
        fs.create_dir("/root_dir").unwrap();

        let entries: Vec<_> = fs.read_dir("/").unwrap().collect();
        assert_eq!(entries.len(), 2);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remove_dir_with_contents() {
    with_crypto_fs(|fs| {
        fs.create_dir("/rmdir").unwrap();
        let mut f = fs.create_file("/rmdir/file1.txt").unwrap();
        f.write_all(b"data").unwrap();
        f.flush().unwrap();
        drop(f);
        let mut f = fs.create_file("/rmdir/file2.txt").unwrap();
        f.write_all(b"data").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.remove_dir("/rmdir").unwrap();

        assert!(!fs.exists("/rmdir"));
        assert!(!fs.exists("/rmdir/file1.txt"));
        assert!(!fs.exists("/rmdir/file2.txt"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remove_nested_dirs() {
    with_crypto_fs(|fs| {
        fs.create_dir("/parent/child").unwrap();
        let mut f = fs.create_file("/parent/child/deep.txt").unwrap();
        f.write_all(b"deep").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.remove_dir("/parent").unwrap();
        assert!(!fs.exists("/parent"));
        assert!(!fs.exists("/parent/child"));
    })
    .await;
}

// ============================================================================
// Remove file
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remove_file() {
    with_crypto_fs(|fs| {
        let mut f = fs.create_file("/todelete.txt").unwrap();
        f.write_all(b"delete me").unwrap();
        f.flush().unwrap();
        drop(f);

        assert!(fs.exists("/todelete.txt"));
        fs.remove_file("/todelete.txt").unwrap();
        assert!(!fs.exists("/todelete.txt"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remove_file_in_subdir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/deldir").unwrap();
        let mut f = fs.create_file("/deldir/target.txt").unwrap();
        f.write_all(b"data").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.remove_file("/deldir/target.txt").unwrap();
        assert!(!fs.exists("/deldir/target.txt"));
        // Directory should still exist
        assert!(fs.exists("/deldir"));
    })
    .await;
}

// ============================================================================
// Copy file
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_copy_file_same_dir() {
    with_crypto_fs(|fs| {
        let data: Vec<u8> = (0..32 * 1024 + 123).map(|_| rand::random::<u8>()).collect();

        let mut f = fs.create_file("/original.dat").unwrap();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        drop(f);

        fs.copy_file("/original.dat", "/copy.dat").unwrap();

        // Both files should exist
        assert!(fs.exists("/original.dat"));
        assert!(fs.exists("/copy.dat"));

        // Content should match
        let mut f = fs.open_file("/copy.dat", OpenOptions::new()).unwrap();
        let mut result = Vec::new();
        f.read_to_end(&mut result).unwrap();
        assert_eq!(result, data);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_copy_file_to_subdir() {
    with_crypto_fs(|fs| {
        let data = b"copy to subdir";
        let mut f = fs.create_file("/src.txt").unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        drop(f);

        fs.create_dir("/destdir").unwrap();
        fs.copy_file("/src.txt", "/destdir/copied.txt").unwrap();

        let mut f = fs
            .open_file("/destdir/copied.txt", OpenOptions::new())
            .unwrap();
        let mut result = Vec::new();
        f.read_to_end(&mut result).unwrap();
        assert_eq!(result, data);

        // Source should still exist
        assert!(fs.exists("/src.txt"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_copy_file_preserves_content_integrity() {
    with_crypto_fs(|fs| {
        // Large file spanning multiple encryption chunks
        let data: Vec<u8> = (0..96 * 1024).map(|i| (i % 251) as u8).collect();
        let mut f = fs.create_file("/big_src.dat").unwrap();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        drop(f);

        fs.copy_file("/big_src.dat", "/big_copy.dat").unwrap();

        let mut src = fs.open_file("/big_src.dat", OpenOptions::new()).unwrap();
        let mut src_data = Vec::new();
        src.read_to_end(&mut src_data).unwrap();

        let mut dst = fs.open_file("/big_copy.dat", OpenOptions::new()).unwrap();
        let mut dst_data = Vec::new();
        dst.read_to_end(&mut dst_data).unwrap();

        assert_eq!(src_data, dst_data);
        assert_eq!(src_data, data);
    })
    .await;
}

// ============================================================================
// Move file (rename)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_move_file_same_dir() {
    with_crypto_fs(|fs| {
        let data: Vec<u8> = (0..32 * 1024 + 999).map(|_| rand::random::<u8>()).collect();
        let mut f = fs.create_file("/move_src.dat").unwrap();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        drop(f);

        fs.move_file("/move_src.dat", "/move_dst.dat").unwrap();

        assert!(!fs.exists("/move_src.dat"));
        assert!(fs.exists("/move_dst.dat"));

        let mut f = fs.open_file("/move_dst.dat", OpenOptions::new()).unwrap();
        let mut result = Vec::new();
        f.read_to_end(&mut result).unwrap();
        assert_eq!(result, data);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_move_file_to_subdir() {
    with_crypto_fs(|fs| {
        let data = b"moving to folder";
        let mut f = fs.create_file("/mv_src.txt").unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        drop(f);

        fs.create_dir("/mv_dest").unwrap();
        fs.move_file("/mv_src.txt", "/mv_dest/moved.txt").unwrap();

        assert!(!fs.exists("/mv_src.txt"));
        assert!(fs.exists("/mv_dest/moved.txt"));

        let mut f = fs
            .open_file("/mv_dest/moved.txt", OpenOptions::new())
            .unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "moving to folder");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rename_file() {
    with_crypto_fs(|fs| {
        let data = b"rename me";
        let mut f = fs.create_file("/before_rename.txt").unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        drop(f);

        // Rename is just move_file within the same directory
        fs.move_file("/before_rename.txt", "/after_rename.txt")
            .unwrap();

        assert!(!fs.exists("/before_rename.txt"));

        let mut f = fs
            .open_file("/after_rename.txt", OpenOptions::new())
            .unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "rename me");
    })
    .await;
}

// ============================================================================
// Move directory
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_move_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/src_dir/child").unwrap();
        let data: Vec<u8> = (0..32 * 1024 + 500).map(|_| rand::random::<u8>()).collect();
        let mut f = fs.create_file("/src_dir/child/file.dat").unwrap();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        drop(f);

        fs.move_dir("/src_dir", "/dst_dir").unwrap();

        assert!(!fs.exists("/src_dir"));
        assert!(fs.exists("/dst_dir"));
        assert!(fs.exists("/dst_dir/child"));

        let mut f = fs
            .open_file("/dst_dir/child/file.dat", OpenOptions::new())
            .unwrap();
        let mut result = Vec::new();
        f.read_to_end(&mut result).unwrap();
        assert_eq!(result, data);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_move_dir_into_existing_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/movable").unwrap();
        let mut f = fs.create_file("/movable/item.txt").unwrap();
        f.write_all(b"moved item").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.create_dir("/container").unwrap();
        fs.move_dir("/movable", "/container").unwrap();

        // After move, /movable should appear inside /container
        assert!(!fs.exists("/movable"));

        // /container should still exist as a directory
        let container_meta = fs.metadata("/container").unwrap();
        assert!(container_meta.is_dir);

        let mut f = fs
            .open_file("/container/movable/item.txt", OpenOptions::new())
            .unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "moved item");
    })
    .await;
}

// ============================================================================
// Metadata
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metadata_file() {
    with_crypto_fs(|fs| {
        let data = b"metadata test content";
        let mut f = fs.create_file("/meta.txt").unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        drop(f);

        let meta = fs.metadata("/meta.txt").unwrap();
        assert!(meta.is_file);
        assert!(!meta.is_dir);
        assert_eq!(meta.len, data.len() as u64);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metadata_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/metadir").unwrap();

        let meta = fs.metadata("/metadir").unwrap();
        assert!(meta.is_dir);
        assert!(!meta.is_file);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metadata_root() {
    with_crypto_fs(|fs| {
        let meta = fs.metadata("/").unwrap();
        assert!(meta.is_dir);
    })
    .await;
}

// ============================================================================
// Multiple files, directory listings with data integrity
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multiple_files_in_same_dir() {
    with_crypto_fs(|fs| {
        let files = vec![
            ("/file_a.txt", "content A"),
            ("/file_b.txt", "content B"),
            ("/file_c.txt", "content C"),
        ];

        for (path, content) in &files {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(content.as_bytes()).unwrap();
            f.flush().unwrap();
            drop(f);
        }

        // Verify all files
        for (path, expected) in &files {
            let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
            let mut buf = String::new();
            f.read_to_string(&mut buf).unwrap();
            assert_eq!(&buf, expected, "content mismatch for {path}");
        }

        // Verify directory listing
        let entries: Vec<_> = fs.read_dir("/").unwrap().collect();
        assert_eq!(entries.len(), files.len());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_deeply_nested_structure() {
    with_crypto_fs(|fs| {
        fs.create_dir("/l1/l2/l3").unwrap();

        let mut f = fs.create_file("/l1/l2/l3/deep.txt").unwrap();
        f.write_all(b"deep nested file").unwrap();
        f.flush().unwrap();
        drop(f);

        // Verify intermediate dirs exist
        assert!(fs.exists("/l1"));
        assert!(fs.exists("/l1/l2"));
        assert!(fs.exists("/l1/l2/l3"));

        // Verify file
        let mut f = fs
            .open_file("/l1/l2/l3/deep.txt", OpenOptions::new())
            .unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "deep nested file");
    })
    .await;
}

// ============================================================================
// Edge cases
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_file_then_remove_then_recreate() {
    with_crypto_fs(|fs| {
        // Create
        let mut f = fs.create_file("/cycle.txt").unwrap();
        f.write_all(b"first").unwrap();
        f.flush().unwrap();
        drop(f);

        // Remove
        fs.remove_file("/cycle.txt").unwrap();
        assert!(!fs.exists("/cycle.txt"));

        // Recreate with different content
        let mut f = fs.create_file("/cycle.txt").unwrap();
        f.write_all(b"second").unwrap();
        f.flush().unwrap();
        drop(f);

        let mut f = fs.open_file("/cycle.txt", OpenOptions::new()).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "second");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_write_read_binary_data() {
    with_crypto_fs(|fs| {
        // Binary data with all byte values
        let data: Vec<u8> = (0..=255u8).collect();
        let mut f = fs.create_file("/binary.dat").unwrap();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        drop(f);

        let mut f = fs.open_file("/binary.dat", OpenOptions::new()).unwrap();
        let mut result = Vec::new();
        f.read_to_end(&mut result).unwrap();
        assert_eq!(result, data);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sequential_chunk_reads() {
    with_crypto_fs(|fs| {
        // Create file with known pattern: 10 chunks of 1000 bytes
        let chunk_size = 1000;
        let num_chunks = 10;
        let mut data = Vec::with_capacity(chunk_size * num_chunks);
        for i in 0..num_chunks {
            data.extend(std::iter::repeat_n(i as u8, chunk_size));
        }

        let mut f = fs.create_file("/chunks.dat").unwrap();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        drop(f);

        // Read each chunk by seeking to its offset
        let mut f = fs.open_file("/chunks.dat", OpenOptions::new()).unwrap();
        for i in 0..num_chunks {
            let offset = (i * chunk_size) as u64;
            f.seek(SeekFrom::Start(offset)).unwrap();
            let mut buf = vec![0u8; chunk_size];
            f.read_exact(&mut buf).unwrap();
            assert!(
                buf.iter().all(|&b| b == i as u8),
                "chunk {i} has wrong data"
            );
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multiple_files_in_nested_dirs_with_operations() {
    with_crypto_fs(|fs| {
        // Create structure
        fs.create_dir("/project").unwrap();
        fs.create_dir("/project/src").unwrap();
        fs.create_dir("/project/docs").unwrap();

        let mut f = fs.create_file("/project/src/main.rs").unwrap();
        f.write_all(b"fn main() {}").unwrap();
        f.flush().unwrap();
        drop(f);

        let mut f = fs.create_file("/project/src/lib.rs").unwrap();
        f.write_all(b"pub mod utils;").unwrap();
        f.flush().unwrap();
        drop(f);

        let mut f = fs.create_file("/project/docs/readme.txt").unwrap();
        f.write_all(b"documentation").unwrap();
        f.flush().unwrap();
        drop(f);

        // Verify listings
        let src_entries: Vec<_> = fs.read_dir("/project/src").unwrap().collect();
        assert_eq!(src_entries.len(), 2);

        let doc_entries: Vec<_> = fs.read_dir("/project/docs").unwrap().collect();
        assert_eq!(doc_entries.len(), 1);

        let project_entries: Vec<_> = fs.read_dir("/project").unwrap().collect();
        assert_eq!(project_entries.len(), 2); // src and docs

        // Copy a file across dirs
        fs.copy_file("/project/src/main.rs", "/project/docs/main_backup.rs")
            .unwrap();
        let mut f = fs
            .open_file("/project/docs/main_backup.rs", OpenOptions::new())
            .unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "fn main() {}");

        // Move a file
        fs.move_file("/project/src/lib.rs", "/project/docs/lib.rs")
            .unwrap();
        assert!(!fs.exists("/project/src/lib.rs"));
        let mut f = fs
            .open_file("/project/docs/lib.rs", OpenOptions::new())
            .unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "pub mod utils;");

        // Remove a file
        fs.remove_file("/project/docs/readme.txt").unwrap();
        assert!(!fs.exists("/project/docs/readme.txt"));

        // Final listing of docs: main_backup.rs and lib.rs
        let doc_entries: Vec<_> = fs.read_dir("/project/docs").unwrap().collect();
        assert_eq!(doc_entries.len(), 2);
    })
    .await;
}

// ============================================================================
// Copy directory
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_copy_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/cpdir").unwrap();
        let mut f = fs.create_file("/cpdir/file.txt").unwrap();
        f.write_all(b"copy dir content").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.copy_dir("/cpdir", "/cpdir_copy").unwrap();

        // Both should exist
        assert!(fs.exists("/cpdir"));
        assert!(fs.exists("/cpdir_copy"));

        let mut f = fs
            .open_file("/cpdir_copy/file.txt", OpenOptions::new())
            .unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "copy dir content");
    })
    .await;
}

// ============================================================================
// Stats / quota
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats() {
    with_crypto_fs(|fs| {
        // Verify that stats() does not error.  Exact values depend on the
        // in-memory provider and are not meaningful to assert on.
        let _stats = fs.stats("/").unwrap();
    })
    .await;
}

// ============================================================================
// File metadata via file handle
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_file_handle_metadata() {
    with_crypto_fs(|fs| {
        let data = b"metadata via handle";
        let mut f = fs.create_file("/handle_meta.txt").unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();

        let meta = f.metadata().unwrap();
        assert_eq!(meta.len, data.len() as u64);
        assert!(meta.is_file);
    })
    .await;
}

// ============================================================================
// Append-like writes (sequential writes extending file)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sequential_writes_extend_file() {
    with_crypto_fs(|fs| {
        let mut f = fs.create_file("/append.dat").unwrap();
        f.write_all(b"part1").unwrap();
        f.write_all(b"part2").unwrap();
        f.write_all(b"part3").unwrap();
        f.flush().unwrap();
        drop(f);

        let mut f = fs.open_file("/append.dat", OpenOptions::new()).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "part1part2part3");
    })
    .await;
}

// ============================================================================
// Interleaved read/write on same file
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_write_then_seek_back_and_read() {
    with_crypto_fs(|fs| {
        let mut f = fs.create_file("/interleave.dat").unwrap();
        f.write_all(b"abcdef").unwrap();
        f.flush().unwrap();

        // Seek back and read what we wrote
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0u8; 6];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abcdef");

        // Write more at the end
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(b"ghij").unwrap();
        f.flush().unwrap();
        drop(f);

        // Re-open and verify full content
        let mut f = fs.open_file("/interleave.dat", OpenOptions::new()).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "abcdefghij");
    })
    .await;
}

// ============================================================================
// SeekFrom::Current
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_seek_from_current() {
    with_crypto_fs(|fs| {
        let data = b"0123456789abcdef";
        let mut f = fs.create_file("/seekcur.dat").unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        drop(f);

        let mut f = fs.open_file("/seekcur.dat", OpenOptions::new()).unwrap();

        // Read 4 bytes (position now at 4)
        let mut buf = vec![0u8; 4];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"0123");

        // Skip forward 2 bytes (position now at 6)
        f.seek(SeekFrom::Current(2)).unwrap();
        let mut buf = vec![0u8; 4];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"6789");
    })
    .await;
}

// ============================================================================
// DirEntry metadata in read_dir results
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_dir_entry_metadata() {
    with_crypto_fs(|fs| {
        fs.create_dir("/entries").unwrap();

        let mut f = fs.create_file("/entries/data.txt").unwrap();
        f.write_all(b"hello").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.create_dir("/entries/subdir").unwrap();

        let entries: Vec<_> = fs.read_dir("/entries").unwrap().collect();
        assert_eq!(entries.len(), 2);

        for entry in &entries {
            if entry.file_name == "data.txt" {
                assert!(entry.metadata.is_file);
                assert!(!entry.metadata.is_dir);
                assert_eq!(entry.metadata.len, 5);
            } else if entry.file_name == "subdir" {
                assert!(entry.metadata.is_dir);
                assert!(!entry.metadata.is_file);
            } else {
                panic!("unexpected entry: {:?}", entry.file_name);
            }
        }
    })
    .await;
}

// ============================================================================
// Negative / error-path tests
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_open_nonexistent_file_errors() {
    with_crypto_fs(|fs| {
        let result = fs.open_file("/does_not_exist.txt", OpenOptions::new());
        assert!(result.is_err(), "opening a nonexistent file should error");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remove_nonexistent_file_errors() {
    with_crypto_fs(|fs| {
        let result = fs.remove_file("/does_not_exist.txt");
        assert!(result.is_err(), "removing a nonexistent file should error");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metadata_nonexistent_path_errors() {
    with_crypto_fs(|fs| {
        let result = fs.metadata("/does_not_exist");
        assert!(
            result.is_err(),
            "metadata on a nonexistent path should error"
        );
    })
    .await;
}

// ============================================================================
// copy_path / move_path (type-agnostic variants)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_copy_path_file() {
    with_crypto_fs(|fs| {
        let mut f = fs.create_file("/cp_src.txt").unwrap();
        f.write_all(b"copy_path file").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.copy_path("/cp_src.txt", "/cp_dst.txt").unwrap();

        assert!(fs.exists("/cp_src.txt"));
        assert!(fs.exists("/cp_dst.txt"));

        let mut f = fs.open_file("/cp_dst.txt", OpenOptions::new()).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "copy_path file");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_copy_path_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/cpd_src").unwrap();
        let mut f = fs.create_file("/cpd_src/item.txt").unwrap();
        f.write_all(b"item").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.copy_path("/cpd_src", "/cpd_dst").unwrap();

        assert!(fs.exists("/cpd_src"));
        assert!(fs.exists("/cpd_dst"));
        assert!(fs.exists("/cpd_dst/item.txt"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_move_path_file() {
    with_crypto_fs(|fs| {
        let mut f = fs.create_file("/mp_src.txt").unwrap();
        f.write_all(b"move_path file").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.move_path("/mp_src.txt", "/mp_dst.txt").unwrap();

        assert!(!fs.exists("/mp_src.txt"));
        assert!(fs.exists("/mp_dst.txt"));

        let mut f = fs.open_file("/mp_dst.txt", OpenOptions::new()).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "move_path file");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_move_path_dir() {
    with_crypto_fs(|fs| {
        fs.create_dir("/mpd_src").unwrap();
        let mut f = fs.create_file("/mpd_src/item.txt").unwrap();
        f.write_all(b"item").unwrap();
        f.flush().unwrap();
        drop(f);

        fs.move_path("/mpd_src", "/mpd_dst").unwrap();

        assert!(!fs.exists("/mpd_src"));
        assert!(fs.exists("/mpd_dst"));
        assert!(fs.exists("/mpd_dst/item.txt"));
    })
    .await;
}

// ============================================================================
// Read-only mode
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_only_mode_rejects_create_file() {
    let config = CryptoFsConfig {
        read_only: true,
        ..CryptoFsConfig::default()
    };
    with_crypto_fs_config(config, |fs| {
        let result = fs.create_file("/should_fail.txt");
        assert!(result.is_err());
        match result.unwrap_err() {
            FileSystemError::ReadOnly => {} // expected
            other => panic!("expected FileSystemError::ReadOnly, got: {other}"),
        }
    })
    .await;
}
