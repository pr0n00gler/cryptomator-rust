use std::env;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::time::Duration;

use cryptomator::cryptofs::{FileSystem, OpenOptions};
use cryptomator::providers::{S3Fs, S3FsConfig};
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
    let bucket = non_empty_env("S3_TEST_BUCKET")?;
    let access_key = non_empty_env("S3_TEST_ACCESS_KEY")?;
    let secret_key = non_empty_env("S3_TEST_SECRET_KEY")?;

    let region = env::var("S3_TEST_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let base_prefix = env::var("S3_TEST_PREFIX").unwrap_or_else(|_| "cryptomator-test".to_string());
    let prefix = format!("{}/{}", base_prefix, Uuid::new_v4());
    let force_path_style = env::var("S3_TEST_PATH_STYLE")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(false);
    let session_token = non_empty_env("S3_TEST_SESSION_TOKEN");

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

#[test]
fn s3_fs_integration_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let Some(config) = s3_config_from_env() else {
        eprintln!(
            "Skipping S3 integration test; set S3_TEST_ENDPOINT, S3_TEST_BUCKET, S3_TEST_ACCESS_KEY, S3_TEST_SECRET_KEY"
        );
        return Ok(());
    };

    let fs = S3Fs::new(config)?;

    fs.create_dir("dir")?;

    let mut file = fs.create_file("dir/file.txt")?;
    file.write_all(b"hello")?;
    file.flush()?;
    drop(file);

    let mut file = fs.open_file("dir/file.txt", OpenOptions::new())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    assert_eq!(contents, "hello");

    let entries: Vec<_> = fs.read_dir("dir")?.collect();
    assert!(entries
        .iter()
        .any(|entry| entry.file_name == OsString::from("file.txt")));

    fs.copy_file("dir/file.txt", "dir/file-copy.txt")?;
    fs.move_file("dir/file-copy.txt", "dir/file-moved.txt")?;

    fs.remove_file("dir/file.txt")?;
    fs.remove_file("dir/file-moved.txt")?;
    fs.remove_dir("dir")?;

    Ok(())
}
