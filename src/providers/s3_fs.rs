use std::path::Path;
use std::time::Duration;

use s3::creds::{Credentials, CredentialsError};
use s3::error::S3Error;
use s3::region::{Region, RegionError};
use s3::Bucket;
use thiserror::Error;
use zeroize::Zeroizing;

/// Configuration for connecting to S3-compatible storage.
#[derive(Clone, Debug)]
pub struct S3FsConfig {
    pub bucket: String,
    pub prefix: Option<String>,
    pub region: String,
    pub endpoint: Option<String>,
    pub force_path_style: bool,
    pub validate_bucket: bool,
    pub access_key: Option<Zeroizing<String>>,
    pub secret_key: Option<Zeroizing<String>>,
    pub session_token: Option<Zeroizing<String>>,
    pub request_timeout: Option<Duration>,
}

/// Errors returned by S3 filesystem initialization and operations.
#[derive(Debug, Error)]
pub enum S3FsError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("failed to parse region: {0}")]
    RegionParse(#[from] RegionError),
    #[error("credentials error: {0}")]
    Credentials(#[from] CredentialsError),
    #[error("s3 error: {0}")]
    S3(#[from] S3Error),
}

/// S3-backed filesystem provider.
#[derive(Clone, Debug)]
pub struct S3Fs {
    bucket: Box<Bucket>,
    prefix: String,
}

impl S3Fs {
    /// Creates a new S3 filesystem provider from configuration.
    pub fn new(config: S3FsConfig) -> Result<Self, S3FsError> {
        let bucket_name = config.bucket.trim();
        if bucket_name.is_empty() {
            return Err(S3FsError::InvalidConfig(
                "bucket name must be non-empty".to_string(),
            ));
        }
        let region_name = config.region.trim();
        if region_name.is_empty() {
            return Err(S3FsError::InvalidConfig(
                "region must be non-empty".to_string(),
            ));
        }

        let access_key_raw = config.access_key.as_deref().map(String::as_str);
        if access_key_raw.is_some_and(|value| value.trim().is_empty()) {
            return Err(S3FsError::InvalidConfig(
                "access_key must be non-empty".to_string(),
            ));
        }
        let access_key = access_key_raw.map(str::trim).filter(|s| !s.is_empty());

        let secret_key_raw = config.secret_key.as_deref().map(String::as_str);
        if secret_key_raw.is_some_and(|value| value.trim().is_empty()) {
            return Err(S3FsError::InvalidConfig(
                "secret_key must be non-empty".to_string(),
            ));
        }
        let secret_key = secret_key_raw.map(str::trim).filter(|s| !s.is_empty());

        let session_token_raw = config.session_token.as_deref().map(String::as_str);
        if session_token_raw.is_some_and(|value| value.trim().is_empty()) {
            return Err(S3FsError::InvalidConfig(
                "session_token must be non-empty".to_string(),
            ));
        }
        let session_token = session_token_raw.map(str::trim).filter(|s| !s.is_empty());

        let has_access_key = access_key.is_some();
        let has_secret_key = secret_key.is_some();
        let has_session_token = session_token.is_some();
        if has_access_key ^ has_secret_key {
            return Err(S3FsError::InvalidConfig(
                "access_key and secret_key must be provided together".to_string(),
            ));
        }
        if has_session_token && !(has_access_key && has_secret_key) {
            return Err(S3FsError::InvalidConfig(
                "session_token requires access_key and secret_key".to_string(),
            ));
        }

        let region = match config.endpoint.as_ref() {
            Some(endpoint) => Region::Custom {
                region: region_name.to_string(),
                endpoint: endpoint.clone(),
            },
            None => region_name.parse()?,
        };

        let credentials = if has_access_key {
            Credentials::new(access_key, secret_key, None, session_token, None)?
        } else {
            Credentials::default()?
        };

        let mut bucket = Bucket::new(bucket_name, region, credentials)?;
        if config.force_path_style {
            bucket = bucket.with_path_style();
        }
        if let Some(timeout) = config.request_timeout {
            bucket = bucket.with_request_timeout(timeout)?;
        }

        let prefix = Self::normalize_prefix(config.prefix.unwrap_or_default())?;
        if config.validate_bucket {
            let _ = bucket.list_page(prefix.clone(), None, None, None, Some(1))?;
        }

        Ok(S3Fs { bucket, prefix })
    }

    fn normalize_prefix(prefix: String) -> Result<String, S3FsError> {
        let parts = Self::normalized_parts(Path::new(prefix.trim()))?;
        Ok(parts.join("/"))
    }

    fn normalized_parts(path: &Path) -> Result<Vec<String>, S3FsError> {
        let mut parts = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::Normal(os) => {
                    let part = os.to_str().ok_or_else(|| {
                        S3FsError::InvalidPath("path is not valid UTF-8".to_string())
                    })?;
                    if !part.is_empty() {
                        parts.push(part.to_string());
                    }
                }
                std::path::Component::CurDir | std::path::Component::RootDir => {}
                std::path::Component::ParentDir => {
                    return Err(S3FsError::InvalidPath(
                        "path must not contain '..'".to_string(),
                    ));
                }
                std::path::Component::Prefix(_) => {
                    return Err(S3FsError::InvalidPath(
                        "absolute Windows paths are not supported".to_string(),
                    ));
                }
            }
        }
        Ok(parts)
    }

    #[allow(dead_code)]
    fn path_to_key<P: AsRef<Path>>(&self, path: P) -> Result<String, S3FsError> {
        let normalized = Self::normalized_parts(path.as_ref())?.join("/");
        if self.prefix.is_empty() {
            Ok(normalized)
        } else if normalized.is_empty() {
            Ok(self.prefix.clone())
        } else {
            Ok(format!("{}/{}", self.prefix, normalized))
        }
    }

    #[allow(dead_code)]
    fn dir_to_prefix<P: AsRef<Path>>(&self, path: P) -> Result<String, S3FsError> {
        let key = self.path_to_key(path)?;
        if key.is_empty() {
            Ok(String::new())
        } else if key.ends_with('/') {
            Ok(key)
        } else {
            Ok(format!("{key}/"))
        }
    }
}
