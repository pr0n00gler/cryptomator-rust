use std::env;
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::thread;
use std::time::Duration;

use cryptomator::cryptofs::{FileSystem, OpenOptions};
use cryptomator::providers::{S3Fs, S3FsConfig};
use rand::RngCore;
use s3::creds::Credentials;
use s3::error::S3Error;
use s3::{Bucket, BucketConfiguration, Region};
use uuid::Uuid;
use zeroize::Zeroizing;

fn s3_config_from_env() -> Option<S3FsConfig> {
    fn non_empty_env(name: &str) -> Option<String> {
        env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    let endpoint = non_empty_env("S3_TEST_ENDPOINT")?;
    let endpoint = if endpoint.contains("://") {
        endpoint
    } else {
        format!("http://{endpoint}")
    };
    let bucket = non_empty_env("S3_TEST_BUCKET")?;
    let access_key = non_empty_env("S3_TEST_ACCESS_KEY")?;
    let secret_key = non_empty_env("S3_TEST_SECRET_KEY")?;

    let region = env::var("S3_TEST_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let base_prefix = env::var("S3_TEST_PREFIX").unwrap_or_else(|_| "cryptomator-test".to_string());
    let prefix = format!("{}/{}", base_prefix, Uuid::new_v4());
    let endpoint_hint = endpoint.to_lowercase();
    let default_path_style = endpoint_hint.contains("localhost")
        || endpoint_hint.contains("127.0.0.1")
        || endpoint_hint.contains("[::1]");
    let force_path_style = env::var("S3_TEST_PATH_STYLE")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(default_path_style);
    let force_session_token = env::var("S3_TEST_FORCE_SESSION_TOKEN")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(false);
    let session_token = if default_path_style && !force_session_token {
        None
    } else {
        non_empty_env("S3_TEST_SESSION_TOKEN")
    };

    Some(S3FsConfig {
        bucket,
        prefix: Some(prefix),
        region,
        endpoint: Some(endpoint),
        force_path_style,
        validate_bucket: true,
        access_key: Some(Zeroizing::new(access_key)),
        secret_key: Some(Zeroizing::new(secret_key)),
        session_token: session_token.map(Zeroizing::new),
        request_timeout: Some(Duration::from_secs(30)),
    })
}

fn s3_fs_from_env() -> Result<Option<S3Fs>, Box<dyn std::error::Error>> {
    let mut config = match s3_config_from_env() {
        Some(config) => config,
        None => {
            eprintln!("S3_TEST_* env vars not set; skipping S3 integration test");
            return Ok(None);
        }
    };

    ensure_bucket_exists(&config).map_err(|err| {
        Box::new(std::io::Error::other(format!(
            "ensure_bucket_exists failed: {err}"
        ))) as Box<dyn std::error::Error>
    })?;
    config.validate_bucket = false;
    let fs = S3Fs::new(config)?;
    Ok(Some(fs))
}

struct Cleanup {
    fs: S3Fs,
}

impl Cleanup {
    fn new(fs: &S3Fs) -> Self {
        Self { fs: fs.clone() }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Err(err) = self.fs.remove_dir("") {
            eprintln!("failed to clean up S3 test prefix: {err}");
        }
    }
}

fn assert_io_error_kind(err: &(dyn std::error::Error + 'static), kind: std::io::ErrorKind) {
    let io_err = err
        .downcast_ref::<std::io::Error>()
        .expect("expected io::Error from S3Fs");
    assert_eq!(io_err.kind(), kind);
}

fn assert_error_contains(err: &dyn std::error::Error, needle: &str) {
    let message = err.to_string();
    assert!(
        message.contains(needle),
        "expected error to contain '{needle}', got '{message}'"
    );
}

fn s3_region_from_config(config: &S3FsConfig) -> Result<Region, Box<dyn std::error::Error>> {
    let region = match config.endpoint.as_ref() {
        Some(endpoint) => Region::Custom {
            region: config.region.clone(),
            endpoint: endpoint.clone(),
        },
        None => config.region.parse()?,
    };
    Ok(region)
}

fn s3_credentials_from_config(
    config: &S3FsConfig,
) -> Result<Credentials, Box<dyn std::error::Error>> {
    let access_key = config.access_key.as_deref().map(String::as_str);
    let secret_key = config.secret_key.as_deref().map(String::as_str);
    let session_token = config.session_token.as_deref().map(String::as_str);
    let credentials = if access_key.is_some() {
        Credentials::new(access_key, secret_key, None, session_token, None)?
    } else {
        Credentials::default()?
    };
    Ok(credentials)
}

fn ensure_bucket_exists(s3_config: &S3FsConfig) -> Result<(), Box<dyn std::error::Error>> {
    let region = s3_region_from_config(s3_config)?;
    let bucket_name = s3_config.bucket.as_str();
    let bucket_config = BucketConfiguration::default();
    let create_result = if s3_config.force_path_style {
        Bucket::create_with_path_style(
            bucket_name,
            region,
            s3_credentials_from_config(s3_config)?,
            bucket_config,
        )
    } else {
        Bucket::create(
            bucket_name,
            region,
            s3_credentials_from_config(s3_config)?,
            bucket_config,
        )
    };

    match create_result {
        Ok(_) => Ok(()),
        Err(S3Error::HttpFailWithBody(409, _)) => Ok(()),
        Err(err) => Err(Box::new(err)),
    }
}

fn with_context<T>(
    result: Result<T, Box<dyn std::error::Error>>,
    context: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|err| {
        Box::new(std::io::Error::other(format!("{context} failed: {err}")))
            as Box<dyn std::error::Error>
    })
}

fn with_context_io<T>(
    result: Result<T, std::io::Error>,
    context: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|err| {
        Box::new(std::io::Error::other(format!("{context} failed: {err}")))
            as Box<dyn std::error::Error>
    })
}

#[test]
fn s3_fs_integration_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    with_context(fs.create_dir("dir"), "create_dir")?;

    let mut file = with_context(fs.create_file("dir/file.txt"), "create_file")?;
    with_context_io(file.write_all(b"hello"), "write_all")?;
    with_context_io(file.flush(), "flush")?;
    drop(file);

    let mut file = with_context(
        fs.open_file("dir/file.txt", OpenOptions::new()),
        "open_file",
    )?;
    let mut contents = String::new();
    with_context_io(file.read_to_string(&mut contents), "read_to_string")?;
    assert_eq!(contents, "hello");

    let entries: Vec<_> = with_context(fs.read_dir("dir"), "read_dir")?.collect();
    assert!(entries.iter().any(|entry| entry.file_name == "file.txt"));

    with_context(
        fs.copy_file("dir/file.txt", "dir/file-copy.txt"),
        "copy_file",
    )?;
    with_context(
        fs.move_file("dir/file-copy.txt", "dir/file-moved.txt"),
        "move_file",
    )?;

    with_context(fs.remove_file("dir/file.txt"), "remove_file")?;
    with_context(fs.remove_file("dir/file-moved.txt"), "remove_file_moved")?;
    with_context(fs.remove_dir("dir"), "remove_dir")?;

    Ok(())
}

#[test]
fn s3_fs_integration_error_cases() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    fs.create_dir("dir")?;
    let mut file = fs.create_file("dir/file.txt")?;
    file.write_all(b"hello")?;
    file.flush()?;

    let err = fs
        .open_file("dir/missing.txt", OpenOptions::new())
        .unwrap_err();
    assert_io_error_kind(err.as_ref(), std::io::ErrorKind::NotFound);

    let mut options = OpenOptions::new();
    options.write(true).create(true).create_new(true);
    let err = fs.open_file("dir/file.txt", options).unwrap_err();
    assert_io_error_kind(err.as_ref(), std::io::ErrorKind::AlreadyExists);

    let err = fs.create_dir("../evil").unwrap_err();
    assert_io_error_kind(err.as_ref(), std::io::ErrorKind::InvalidInput);

    let err = fs.move_dir("dir", "dir/subdir").unwrap_err();
    assert_io_error_kind(err.as_ref(), std::io::ErrorKind::InvalidInput);

    Ok(())
}

#[test]
fn s3_fs_integration_concurrent_writes_and_reads() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    fs.create_dir("concurrent")?;

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let fs = fs.clone();
            thread::spawn(move || {
                let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                    let path = format!("concurrent/file-{i}.txt");
                    let payload = format!("payload-{i}-{}", Uuid::new_v4());
                    let mut file = fs.create_file(&path)?;
                    file.write_all(payload.as_bytes())?;
                    file.flush()?;

                    let mut read_back = String::new();
                    let mut file = fs.open_file(&path, OpenOptions::new())?;
                    file.read_to_string(&mut read_back)?;
                    if read_back != payload {
                        return Err(Box::new(std::io::Error::other(
                            "concurrent readback mismatch",
                        )));
                    }
                    Ok(())
                })();
                result.expect("concurrent worker failed");
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("concurrent worker panicked");
    }

    Ok(())
}

#[test]
fn s3_fs_integration_streaming_and_seek() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    fs.create_dir("streaming")?;

    let mut data = vec![0u8; 64 * 1024];
    rand::thread_rng().fill_bytes(&mut data);
    let mut file = fs.create_file("streaming/data.bin")?;
    file.write_all(&data)?;
    file.flush()?;
    drop(file);

    let mut file = fs.open_file("streaming/data.bin", OpenOptions::new())?;
    let mut streamed = Vec::with_capacity(data.len());
    let mut buf = [0u8; 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        streamed.extend_from_slice(&buf[..read]);
    }
    assert_eq!(streamed, data);

    file.seek(SeekFrom::Start(12_345))?;
    let mut slice = [0u8; 256];
    let read = file.read(&mut slice)?;
    assert_eq!(read, slice.len());
    assert_eq!(&slice[..], &data[12_345..12_345 + 256]);

    file.seek(SeekFrom::End(-128))?;
    let mut tail = [0u8; 128];
    let read = file.read(&mut tail)?;
    assert_eq!(read, tail.len());
    assert_eq!(&tail[..], &data[data.len() - 128..]);

    Ok(())
}

#[test]
fn s3_fs_integration_path_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    fs.create_dir_all("edge/./nested/")?;
    assert!(fs.exists("edge/nested"));

    fs.create_dir_all("edge/unicode")?;
    let filename = "über-文件.txt";
    let path = format!("edge/unicode/{filename}");
    let mut file = fs.create_file(&path)?;
    file.write_all(b"unicode")?;
    file.flush()?;

    let entries: Vec<_> = fs.read_dir("edge/unicode")?.collect();
    assert!(
        entries
            .iter()
            .any(|entry| entry.file_name == OsStr::new(filename))
    );

    Ok(())
}

#[test]
fn s3_fs_integration_append_and_truncate() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    fs.create_dir("opts")?;
    let mut file = fs.create_file("opts/data.txt")?;
    file.write_all(b"hello")?;
    file.flush()?;
    drop(file);

    let mut options = OpenOptions::new();
    options.write(true).append(true);
    let mut file = fs.open_file("opts/data.txt", options)?;
    file.write_all(b" world")?;
    file.flush()?;
    drop(file);

    let mut file = fs.open_file("opts/data.txt", OpenOptions::new())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    assert_eq!(contents, "hello world");

    let mut options = OpenOptions::new();
    options.write(true).truncate(true);
    let mut file = fs.open_file("opts/data.txt", options)?;
    file.write_all(b"new")?;
    file.flush()?;
    drop(file);

    let mut file = fs.open_file("opts/data.txt", OpenOptions::new())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    assert_eq!(contents, "new");

    Ok(())
}

#[test]
fn s3_fs_integration_read_only_write_denied() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    fs.create_dir("readonly")?;
    let mut file = fs.create_file("readonly/data.txt")?;
    file.write_all(b"contents")?;
    file.flush()?;

    let mut file = fs.open_file("readonly/data.txt", OpenOptions::new())?;
    let err = file.write(b"nope").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    Ok(())
}

#[test]
fn s3_fs_integration_metadata_and_exists() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    assert!(!fs.exists("missing"));

    fs.create_dir_all("meta/dir")?;
    let mut file = fs.create_file("meta/dir/file.bin")?;
    file.write_all(b"1234")?;
    file.flush()?;

    let dir_meta = fs.metadata("meta/dir")?;
    assert!(dir_meta.is_dir);
    assert!(!dir_meta.is_file);

    let file_meta = fs.metadata("meta/dir/file.bin")?;
    assert!(file_meta.is_file);
    assert!(!file_meta.is_dir);
    assert_eq!(file_meta.len, 4);

    let err = fs.metadata("meta/dir/missing.bin").unwrap_err();
    assert_io_error_kind(err.as_ref(), std::io::ErrorKind::NotFound);

    Ok(())
}

#[test]
fn s3_fs_integration_read_dir_lists_files_and_dirs() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    fs.create_dir_all("listing/subdir")?;
    let mut file = fs.create_file("listing/subdir/data.txt")?;
    file.write_all(b"listing")?;
    file.flush()?;

    let entries: Vec<_> = fs.read_dir("listing")?.collect();
    assert!(entries.iter().any(|entry| entry.file_name == "subdir"));

    let entries: Vec<_> = fs.read_dir("listing/subdir")?.collect();
    assert!(entries.iter().any(|entry| entry.file_name == "data.txt"));

    Ok(())
}

#[test]
fn s3_fs_integration_remove_dir_non_empty() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    let mut file = fs.create_file("remove/dir/file.txt")?;
    file.write_all(b"remove")?;
    file.flush()?;

    fs.remove_dir("remove")?;
    assert!(!fs.exists("remove/dir/file.txt"));
    assert!(!fs.exists("remove/dir"));
    assert!(!fs.exists("remove"));

    Ok(())
}

#[test]
fn s3_fs_integration_move_dir_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    let mut file = fs.create_file("move/src/subdir/file.txt")?;
    file.write_all(b"move")?;
    file.flush()?;

    fs.move_dir("move/src", "move/dest")?;
    assert!(!fs.exists("move/src/subdir/file.txt"));
    assert!(fs.exists("move/dest/subdir/file.txt"));

    let mut file = fs.open_file("move/dest/subdir/file.txt", OpenOptions::new())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    assert_eq!(contents, "move");

    Ok(())
}

#[test]
fn s3_fs_integration_invalid_open_options() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fs) = s3_fs_from_env()? else {
        return Ok(());
    };
    let _cleanup = Cleanup::new(&fs);

    fs.create_dir("invalid")?;
    let mut file = fs.create_file("invalid/data.txt")?;
    file.write_all(b"invalid")?;
    file.flush()?;

    let mut options = OpenOptions::new();
    options.append(true);
    let err = fs.open_file("invalid/data.txt", options).unwrap_err();
    assert_error_contains(err.as_ref(), "write required for create/append/truncate");

    let mut options = OpenOptions::new();
    options.read(false).write(false);
    let err = fs.open_file("invalid/data.txt", options).unwrap_err();
    assert_error_contains(err.as_ref(), "open options must include read or write");

    Ok(())
}
