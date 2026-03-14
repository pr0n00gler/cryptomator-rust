use cryptomator::crypto::{Cryptor, Vault};
use cryptomator::cryptofs::{CryptoFs, CryptoFsConfig, FileSystem, OpenOptions};
use cryptomator::frontends::mount::mount_webdav;
use cryptomator::providers::{LocalFs, MemoryFs, WebDavFs};
use std::io::{Read, Write};

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
