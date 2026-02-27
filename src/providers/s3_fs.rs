use std::ffi::OsString;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::Duration;

use s3::creds::{Credentials, CredentialsError};
use s3::error::S3Error;
use s3::region::{Region, RegionError};
use s3::Bucket;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::cryptofs::{DirEntry, File, FileSystem, Metadata, OpenOptions, Stats};

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
    #[error("unimplemented: {0}")]
    Unimplemented(&'static str),
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

impl FileSystem for S3Fs {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, Box<dyn std::error::Error>> {
        let dir_prefix = self
            .dir_to_prefix(&path)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let base_path = PathBuf::from(path.as_ref());
        let mut entries = Vec::new();

        let results = self
            .bucket
            .list(dir_prefix.clone(), Some("/".to_string()))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        for result in results {
            if let Some(prefixes) = result.common_prefixes {
                for common in prefixes {
                    let relative = common
                        .prefix
                        .strip_prefix(&dir_prefix)
                        .unwrap_or(&common.prefix)
                        .trim_end_matches('/');
                    if relative.is_empty() {
                        continue;
                    }
                    let name = Path::new(relative)
                        .file_name()
                        .map(OsString::from)
                        .unwrap_or_else(|| OsString::from(relative));
                    let mut metadata = Metadata::default();
                    metadata.is_dir = true;
                    metadata.is_file = false;
                    metadata.len = 0;
                    entries.push(DirEntry {
                        path: base_path.join(Path::new(&name)),
                        metadata,
                        file_name: name,
                    });
                }
            }

            for object in result.contents {
                if object.key == dir_prefix {
                    continue;
                }
                let relative = object.key.strip_prefix(&dir_prefix).unwrap_or(&object.key);
                if relative.is_empty() {
                    continue;
                }
                let name = Path::new(relative)
                    .file_name()
                    .map(OsString::from)
                    .unwrap_or_else(|| OsString::from(relative));
                let mut metadata = Metadata::default();
                metadata.is_dir = false;
                metadata.is_file = true;
                metadata.len = object.size;
                entries.push(DirEntry {
                    path: base_path.join(Path::new(&name)),
                    metadata,
                    file_name: name,
                });
            }
        }

        Ok(Box::new(entries.into_iter()))
    }

    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let dir_prefix = self
            .dir_to_prefix(&path)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        if dir_prefix.is_empty() {
            return Ok(());
        }
        let mut empty = Cursor::new(Vec::new());
        self.bucket
            .put_object_stream(&mut empty, dir_prefix)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(())
    }

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        self.create_dir(path)
    }

    fn open_file<P: AsRef<Path>>(
        &self,
        _path: P,
        _options: OpenOptions,
    ) -> Result<Box<dyn File>, Box<dyn std::error::Error>> {
        Err(Box::new(S3FsError::Unimplemented("open_file")))
    }

    fn create_file<P: AsRef<Path>>(
        &self,
        _path: P,
    ) -> Result<Box<dyn File>, Box<dyn std::error::Error>> {
        Err(Box::new(S3FsError::Unimplemented("create_file")))
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        let key = match self.path_to_key(&path) {
            Ok(key) => key,
            Err(_) => return false,
        };
        if key.is_empty() {
            return true;
        }

        if let Ok((result, _)) = self
            .bucket
            .list_page(key.clone(), None, None, None, Some(1))
        {
            if result.contents.iter().any(|object| object.key == key) {
                return true;
            }
        }

        let dir_prefix = if key.ends_with('/') {
            key
        } else {
            format!("{key}/")
        };
        if let Ok((result, _)) =
            self.bucket
                .list_page(dir_prefix, Some("/".to_string()), None, None, Some(1))
        {
            let has_contents = !result.contents.is_empty();
            let has_prefixes = result
                .common_prefixes
                .as_ref()
                .is_some_and(|prefixes| !prefixes.is_empty());
            return has_contents || has_prefixes;
        }

        false
    }

    fn remove_file<P: AsRef<Path>>(&self, _path: P) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(S3FsError::Unimplemented("remove_file")))
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let dir_prefix = self
            .dir_to_prefix(&path)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        if dir_prefix.is_empty() {
            return Ok(());
        }

        let results = self
            .bucket
            .list(dir_prefix.clone(), None)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        for result in results {
            for object in result.contents {
                self.bucket
                    .delete_object(&object.key)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            }
        }
        Ok(())
    }

    fn copy_file<P: AsRef<Path>>(
        &self,
        _src: P,
        _dest: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(S3FsError::Unimplemented("copy_file")))
    }

    fn move_file<P: AsRef<Path>>(
        &self,
        _src: P,
        _dest: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(S3FsError::Unimplemented("move_file")))
    }

    fn move_dir<P: AsRef<Path>>(
        &self,
        _src: P,
        _dest: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(S3FsError::Unimplemented("move_dir")))
    }

    fn metadata<P: AsRef<Path>>(&self, _path: P) -> Result<Metadata, Box<dyn std::error::Error>> {
        Err(Box::new(S3FsError::Unimplemented("metadata")))
    }

    fn stats<P: AsRef<Path>>(&self, _path: P) -> Result<Stats, Box<dyn std::error::Error>> {
        Err(Box::new(S3FsError::Unimplemented("stats")))
    }
}
