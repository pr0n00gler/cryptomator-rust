use cryptomator::crypto::{Cryptor, Vault};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig, FileSystem, OpenOptions};
use cryptomator::frontends::mount::mount_webdav;
use cryptomator::providers::{LocalFs, MemoryFs, WebDavFs};
use std::io::{Read, Seek, SeekFrom, Write};

const PATH_TO_VAULT: &str = "tests/test_storage/vault.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";
const VFS_STORAGE_PATH: &str = "/";

struct CleanupFile<'a> {
    fs: &'a WebDavFs,
    path: &'a str,
}

impl<'a> Drop for CleanupFile<'a> {
    fn drop(&mut self) {
        let _ = self.fs.remove_file(self.path);
    }
}

struct CleanupDir<'a> {
    fs: &'a WebDavFs,
    path: &'a str,
}

impl<'a> Drop for CleanupDir<'a> {
    fn drop(&mut self) {
        let _ = self.fs.remove_dir(self.path);
    }
}

async fn setup_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let mem_fs = MemoryFs::new();
    let vault = Vault::open(&LocalFs::new(), PATH_TO_VAULT, DEFAULT_PASSWORD).unwrap();
    let cryptor = Cryptor::new(vault);
    let crypto_fs =
        CryptoFs::new(VFS_STORAGE_PATH, cryptor, mem_fs, CryptoFsConfig::default()).unwrap();

    // Bind to port 0 to let the OS pick an available port, then extract
    // the actual address before handing the listener to mount_webdav.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let base_url = format!("http://127.0.0.1:{}", addr.port());
    let listen_addr = addr.to_string();

    let handle = tokio::spawn(async move {
        mount_webdav(listen_addr, crypto_fs, None).await;
    });

    // Wait for the server to be ready by polling TCP connectivity.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return (base_url, handle);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("WebDAV server did not start within 1 second");
}

/// Run a closure that uses `reqwest::blocking` on a plain OS thread
/// (not a tokio worker) so that `reqwest::blocking::Client` does not
/// detect the ambient async runtime and panic.
fn run_blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::thread::spawn(f).join().expect("test thread panicked")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_exists() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        assert!(fs.exists("/"));
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_create_and_read_file() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_create_and_read.txt";

        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        {
            let mut file = fs.open_file(path, opts).expect("failed to open file");
            file.write_all(b"hello webdav").expect("failed to write");
            file.flush().expect("failed to flush");
        }

        {
            let mut file = fs
                .open_file(path, OpenOptions::new())
                .expect("failed to open file for reading");
            let mut buf = String::new();
            file.read_to_string(&mut buf).expect("failed to read");
            assert_eq!(buf, "hello webdav");
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_create_dir() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_create_dir_webdav";

        let _ = fs.remove_dir(path);
        let _guard = CleanupDir { fs: &fs, path };

        fs.create_dir(path).expect("failed to create dir");
        assert!(fs.exists(path));
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_read_dir() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let dir = "/test_read_dir_webdav";
        let file = "/test_read_dir_webdav/child.txt";

        let _ = fs.remove_dir(dir);
        let _guard = CleanupDir { fs: &fs, path: dir };

        fs.create_dir(dir).expect("failed to create dir");

        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let mut f = fs
                .open_file(file, opts)
                .expect("failed to create child file");
            f.write_all(b"data").expect("failed to write");
            f.flush().expect("failed to flush");
        }

        let entries: Vec<_> = fs.read_dir(dir).expect("failed to read dir").collect();
        assert!(!entries.is_empty());
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_remove_file() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_remove_file_webdav.txt";

        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let mut f = fs.open_file(path, opts).expect("failed to create file");
            f.write_all(b"to delete").expect("failed to write");
            f.flush().expect("failed to flush");
        }

        assert!(fs.exists(path));
        fs.remove_file(path).expect("failed to remove file");
        assert!(!fs.exists(path));
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_remove_dir() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_remove_dir_webdav";

        let _ = fs.remove_dir(path);
        fs.create_dir(path).expect("failed to create dir");
        assert!(fs.exists(path));
        fs.remove_dir(path).expect("failed to remove dir");
        assert!(!fs.exists(path));
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_copy_file() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let src = "/test_copy_src_webdav.txt";
        let dest = "/test_copy_dest_webdav.txt";

        let _ = fs.remove_file(src);
        let _ = fs.remove_file(dest);
        let _guard_src = CleanupFile { fs: &fs, path: src };
        let _guard_dest = CleanupFile {
            fs: &fs,
            path: dest,
        };

        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let mut f = fs.open_file(src, opts).expect("failed to create source");
            f.write_all(b"copy me").expect("failed to write");
            f.flush().expect("failed to flush");
        }

        fs.copy_file(src, dest).expect("failed to copy file");
        assert!(fs.exists(dest));

        {
            let mut f = fs
                .open_file(dest, OpenOptions::new())
                .expect("failed to open dest");
            let mut buf = String::new();
            f.read_to_string(&mut buf).expect("failed to read");
            assert_eq!(buf, "copy me");
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_move_file() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let src = "/test_move_src_webdav.txt";
        let dest = "/test_move_dest_webdav.txt";

        let _ = fs.remove_file(src);
        let _ = fs.remove_file(dest);
        let _guard_src = CleanupFile { fs: &fs, path: src };
        let _guard_dest = CleanupFile {
            fs: &fs,
            path: dest,
        };

        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let mut f = fs.open_file(src, opts).expect("failed to create source");
            f.write_all(b"move me").expect("failed to write");
            f.flush().expect("failed to flush");
        }

        fs.move_file(src, dest).expect("failed to move file");
        assert!(!fs.exists(src));
        assert!(fs.exists(dest));
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_metadata() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_metadata_webdav.txt";

        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let mut f = fs.open_file(path, opts).expect("failed to create file");
            f.write_all(b"metadata test").expect("failed to write");
            f.flush().expect("failed to flush");
        }

        let meta = fs.metadata(path).expect("failed to get metadata");
        assert!(meta.is_file);
        assert!(!meta.is_dir);
        assert!(meta.len > 0);
    });
}

// ============================================================================
// Range-based I/O tests
// ============================================================================

/// Write data, flush, then read it back using Range GET by seeking
/// to specific offsets and reading sub-slices.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_range_read_partial() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_range_read_partial.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();

        {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(&data).unwrap();
            f.flush().unwrap();
        }

        // Read bytes 100..200 via seek + read
        {
            let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
            f.seek(SeekFrom::Start(100)).unwrap();
            let mut buf = vec![0u8; 100];
            f.read_exact(&mut buf).unwrap();
            assert_eq!(buf, &data[100..200]);
        }

        // Read last 50 bytes via SeekFrom::End
        {
            let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
            f.seek(SeekFrom::End(-50)).unwrap();
            let mut buf = vec![0u8; 50];
            f.read_exact(&mut buf).unwrap();
            assert_eq!(buf, &data[974..1024]);
        }

        // Read from the very beginning (first 10 bytes)
        {
            let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
            let mut buf = vec![0u8; 10];
            f.read_exact(&mut buf).unwrap();
            assert_eq!(buf, &data[0..10]);
        }
    });
}

/// Verify that SeekFrom::End(0) correctly reports the file size.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_seek_end_returns_file_size() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_seek_end_size.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        let data = vec![0xABu8; 5000];
        {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(&data).unwrap();
            f.flush().unwrap();
        }

        let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
        let size = f.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(size, 5000);
    });
}

/// Write at a specific offset within an existing file (read-modify-write),
/// then verify the entire file content is correct.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_write_at_offset() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_write_at_offset.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        // Write initial data
        let mut data = vec![0u8; 256];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = i as u8;
        }
        {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(&data).unwrap();
            f.flush().unwrap();
        }

        // Overwrite bytes 100..110 with 0xFF
        let patch = vec![0xFFu8; 10];
        {
            let mut f = fs.open_file(path, *OpenOptions::new().write(true)).unwrap();
            f.seek(SeekFrom::Start(100)).unwrap();
            f.write_all(&patch).unwrap();
            f.flush().unwrap();
        }

        // Verify
        data[100..110].copy_from_slice(&patch);
        {
            let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
            let mut result = Vec::new();
            f.read_to_end(&mut result).unwrap();
            assert_eq!(result, data);
        }
    });
}

/// Write data, then immediately read it back before flushing.
/// This tests that pending writes are visible to subsequent reads
/// (the overlay logic).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_read_pending_writes_before_flush() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_read_pending.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        let mut f = fs.create_file(path).unwrap();
        f.write_all(b"hello world").unwrap();
        // Do NOT flush — data is only in pending_writes

        // Seek back and read
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0u8; 11];
        let n = f.read(&mut buf).unwrap();
        assert_eq!(n, 11);
        assert_eq!(&buf, b"hello world");
    });
}

/// Write a large file (>64KB) to exercise multi-chunk behavior,
/// then read back specific ranges.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_large_file_range_read() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_large_range.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        // 100KB of patterned data
        let data: Vec<u8> = (0..100 * 1024).map(|i| (i % 251) as u8).collect();
        {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(&data).unwrap();
            f.flush().unwrap();
        }

        // Read a range in the middle: bytes 50000..50100
        {
            let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
            f.seek(SeekFrom::Start(50000)).unwrap();
            let mut buf = vec![0u8; 100];
            f.read_exact(&mut buf).unwrap();
            assert_eq!(buf, &data[50000..50100]);
        }

        // Read the last 1000 bytes
        {
            let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
            f.seek(SeekFrom::End(-1000)).unwrap();
            let mut buf = vec![0u8; 1000];
            f.read_exact(&mut buf).unwrap();
            let start = data.len() - 1000;
            assert_eq!(buf, &data[start..]);
        }
    });
}

/// Multiple sequential writes at different offsets, then flush once
/// and verify the merged result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_multiple_writes_single_flush() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_multi_write.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        let mut f = fs.create_file(path).unwrap();
        // Write "AAAA" at offset 0
        f.write_all(b"AAAA").unwrap();
        // Write "BBBB" at offset 10
        f.seek(SeekFrom::Start(10)).unwrap();
        f.write_all(b"BBBB").unwrap();
        // Write "CCCC" at offset 20
        f.seek(SeekFrom::Start(20)).unwrap();
        f.write_all(b"CCCC").unwrap();
        f.flush().unwrap();
        drop(f);

        let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
        let mut result = vec![0u8; 24];
        f.read_exact(&mut result).unwrap();

        // Bytes 0..4 = "AAAA", 4..10 = zeros, 10..14 = "BBBB", 14..20 = zeros, 20..24 = "CCCC"
        assert_eq!(&result[0..4], b"AAAA");
        assert_eq!(&result[4..10], &[0u8; 6]);
        assert_eq!(&result[10..14], b"BBBB");
        assert_eq!(&result[14..20], &[0u8; 6]);
        assert_eq!(&result[20..24], b"CCCC");
    });
}

/// Verify that pending writes overlay server-side data correctly when
/// reading a range that partially overlaps a pending write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_read_overlaps_pending_and_server_data() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_overlay.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        // Write initial server-side content: 20 bytes of 0x11
        {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(&[0x11u8; 20]).unwrap();
            f.flush().unwrap();
        }

        // Open, write 4 bytes at offset 5 (pending, not flushed), then
        // read the full 20-byte range — should see server data + overlay.
        {
            let mut f = fs.open_file(path, *OpenOptions::new().write(true)).unwrap();
            f.seek(SeekFrom::Start(5)).unwrap();
            f.write_all(&[0xFFu8; 4]).unwrap();

            // Read the full file
            f.seek(SeekFrom::Start(0)).unwrap();
            let mut buf = vec![0u8; 20];
            f.read_exact(&mut buf).unwrap();

            let mut expected = vec![0x11u8; 20];
            expected[5..9].fill(0xFF);
            assert_eq!(buf, expected);
        }
    });
}

/// Reading past EOF should return 0 bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_read_past_eof() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_eof.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(b"short").unwrap();
            f.flush().unwrap();
        }

        let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
        f.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = vec![0xFFu8; 10];
        let n = f.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    });
}

/// Verify metadata().len reflects pending writes that extend the file
/// beyond the server-side content_length.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_metadata_reflects_pending_writes() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_meta_pending.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        let mut f = fs.create_file(path).unwrap();
        // Server-side is empty (0 bytes)
        let meta = f.metadata().unwrap();
        assert_eq!(meta.len, 0);

        // Write 100 bytes (pending, not flushed)
        f.write_all(&[0xAA; 100]).unwrap();
        let meta = f.metadata().unwrap();
        assert_eq!(meta.len, 100);

        // Write 50 more at offset 200 (creates a gap)
        f.seek(SeekFrom::Start(200)).unwrap();
        f.write_all(&[0xBB; 50]).unwrap();
        let meta = f.metadata().unwrap();
        assert_eq!(meta.len, 250);
    });
}

/// Write, flush, then overwrite a sub-range and flush again.
/// Verifies the read-modify-write cycle works correctly on the second flush.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_double_flush_read_modify_write() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_double_flush.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        // First write + flush
        {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(&[0x00u8; 100]).unwrap();
            f.flush().unwrap();
        }

        // Second write at offset 50 + flush (read-modify-write cycle)
        {
            let mut f = fs.open_file(path, *OpenOptions::new().write(true)).unwrap();
            f.seek(SeekFrom::Start(50)).unwrap();
            f.write_all(&[0xFFu8; 20]).unwrap();
            f.flush().unwrap();
        }

        // Verify final content
        {
            let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
            let mut result = vec![0u8; 100];
            f.read_exact(&mut result).unwrap();

            assert!(result[..50].iter().all(|&b| b == 0x00));
            assert!(result[50..70].iter().all(|&b| b == 0xFF));
            assert!(result[70..100].iter().all(|&b| b == 0x00));
        }
    });
}

/// Sequential seek-read pattern mimicking how CryptoFs reads chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webdav_sequential_chunk_reads() {
    let (base_url, _handle) = setup_test_server().await;

    run_blocking(move || {
        let fs = WebDavFs::new(&base_url, None, None);
        let path = "/test_chunk_reads.dat";
        let _ = fs.remove_file(path);
        let _guard = CleanupFile { fs: &fs, path };

        // Create a file with known pattern: 10 chunks of 1000 bytes each
        let chunk_size = 1000;
        let num_chunks = 10;
        let mut data = Vec::with_capacity(chunk_size * num_chunks);
        for i in 0..num_chunks {
            data.extend(std::iter::repeat_n(i as u8, chunk_size));
        }
        {
            let mut f = fs.create_file(path).unwrap();
            f.write_all(&data).unwrap();
            f.flush().unwrap();
        }

        // Read each chunk by seeking to its offset, like CryptoFs does
        let mut f = fs.open_file(path, OpenOptions::new()).unwrap();
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
    });
}
