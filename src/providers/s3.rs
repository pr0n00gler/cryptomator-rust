use std::fs::File;
use std::path::Path;
use std::process::exit;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::providers::s3_fs::{S3Fs, S3FsConfig};

/// Errors that can occur when loading or parsing S3 configuration.
#[derive(Debug, Error)]
pub enum S3ConfigError {
    #[error("failed to read S3 config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse S3 config file: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("invalid S3 config: {0}")]
    InvalidConfig(String),
}

/// Configuration for S3 filesystem loaded from a JSON file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3FsFileConfig {
    bucket: String,
    #[serde(default)]
    prefix: Option<String>,
    region: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    force_path_style: bool,
    #[serde(default)]
    validate_bucket: bool,
    #[serde(default)]
    access_key: Option<String>,
    #[serde(default)]
    secret_key: Option<String>,
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default)]
    request_timeout_seconds: Option<u64>,
}

impl S3FsFileConfig {
    /// Converts this file config into an [`S3FsConfig`] for initializing an S3 filesystem.
    pub fn into_s3_fs_config(self) -> Result<S3FsConfig, S3ConfigError> {
        let request_timeout = match self.request_timeout_seconds {
            Some(0) => {
                return Err(S3ConfigError::InvalidConfig(
                    "request_timeout_seconds must be greater than zero".to_string(),
                ));
            }
            Some(seconds) => Some(Duration::from_secs(seconds)),
            None => None,
        };

        Ok(S3FsConfig {
            bucket: self.bucket,
            prefix: self.prefix,
            region: self.region,
            endpoint: self.endpoint,
            force_path_style: self.force_path_style,
            validate_bucket: self.validate_bucket,
            access_key: self.access_key.map(Zeroizing::new),
            secret_key: self.secret_key.map(Zeroizing::new),
            session_token: self.session_token.map(Zeroizing::new),
            request_timeout,
        })
    }
}

/// Loads the S3 filesystem from the given config path, or exits the process
/// with a user-facing error message if initialization fails.
pub fn require_s3_fs(config_path: Option<&str>) -> S3Fs {
    match load_s3_fs(config_path) {
        Ok(fs) => fs,
        Err(err) => {
            eprintln!("failed to initialize S3 filesystem: {err}");
            exit(2);
        }
    }
}

/// Loads the S3 filesystem from the given config path.
fn load_s3_fs(config_path: Option<&str>) -> Result<S3Fs, S3ConfigError> {
    let config_path = match config_path {
        Some(path) => path,
        None => {
            return Err(S3ConfigError::InvalidConfig(
                "--s3-config must be provided when using the s3 provider".to_string(),
            ));
        }
    };

    let config = load_s3_config(config_path)?;
    S3Fs::new(config).map_err(|err| S3ConfigError::InvalidConfig(err.to_string()))
}

/// Loads S3 configuration from a JSON file.
fn load_s3_config<P: AsRef<Path>>(path: P) -> Result<S3FsConfig, S3ConfigError> {
    let config_file = File::open(path.as_ref())?;
    let config: S3FsFileConfig = serde_json::from_reader(config_file)?;
    config.into_s3_fs_config()
}
