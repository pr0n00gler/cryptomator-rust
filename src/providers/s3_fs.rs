use std::ffi::OsString;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use s3::creds::{Credentials, CredentialsError};
use s3::error::S3Error;
use s3::region::{Region, RegionError};
use s3::Bucket;
use tempfile::NamedTempFile;
use thiserror::Error;
use tracing::warn;
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
    #[error("file already exists")]
    AlreadyExists,
    #[error("file does not exist")]
    NotFound,
    #[error("content length missing")]
    MissingContentLength,
    #[error("failed to parse region: {0}")]
    RegionParse(#[from] RegionError),
    #[error("credentials error: {0}")]
    Credentials(#[from] CredentialsError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("s3 error: {0}")]
    S3(#[from] S3Error),
    #[error("{op} failed with status {status}")]
    HttpStatus { op: &'static str, status: u16 },
}

/// S3-backed filesystem provider.
#[derive(Clone, Debug)]
pub struct S3Fs {
    bucket: Box<Bucket>,
    prefix: String,
}

struct S3File {
    bucket: Bucket,
    key: String,
    inner: S3FileInner,
}

enum S3FileInner {
    ReadOnly {
        size: u64,
        cursor: u64,
    },
    Staged {
        file: NamedTempFile,
        size: u64,
        dirty: bool,
    },
}

impl std::fmt::Debug for S3File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3File").field("key", &self.key).finish()
    }
}

impl S3File {
    fn new_read_only(bucket: Bucket, key: String, size: u64) -> Self {
        S3File {
            bucket,
            key,
            inner: S3FileInner::ReadOnly { size, cursor: 0 },
        }
    }

    fn new_staged(
        bucket: Bucket,
        key: String,
        file: NamedTempFile,
        size: u64,
        dirty: bool,
    ) -> Self {
        S3File {
            bucket,
            key,
            inner: S3FileInner::Staged { file, size, dirty },
        }
    }

    fn upload_if_dirty(&mut self) -> io::Result<()> {
        match &mut self.inner {
            S3FileInner::Staged { file, dirty, .. } => {
                if !*dirty {
                    return Ok(());
                }
                let handle = file.as_file_mut();
                let current_pos = handle.stream_position()?;
                handle.seek(SeekFrom::Start(0))?;
                let status = self
                    .bucket
                    .put_object_stream(handle, &self.key)
                    .map_err(io::Error::other)?;
                if !(200..300).contains(&status) {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("upload failed with status {status}"),
                    ));
                }
                handle.seek(SeekFrom::Start(current_pos))?;
                *dirty = false;
                Ok(())
            }
            S3FileInner::ReadOnly { .. } => Ok(()),
        }
    }

    fn read_only_seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            S3FileInner::ReadOnly { size, cursor } => {
                let new_pos = match pos {
                    SeekFrom::Start(offset) => offset as i64,
                    SeekFrom::Current(offset) => *cursor as i64 + offset,
                    SeekFrom::End(offset) => *size as i64 + offset,
                };
                if new_pos < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid seek to a negative position",
                    ));
                }
                *cursor = new_pos as u64;
                Ok(*cursor)
            }
            S3FileInner::Staged { .. } => Err(io::Error::new(
                io::ErrorKind::Other,
                "read_only_seek called on staged file",
            )),
        }
    }
}

impl Drop for S3File {
    fn drop(&mut self) {
        if let Err(err) = self.upload_if_dirty() {
            warn!(key = %self.key, error = %err, "failed to upload staged S3 object on drop");
        }
    }
}

impl Read for S3File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            S3FileInner::ReadOnly { size, cursor } => {
                if buf.is_empty() || *cursor >= *size {
                    return Ok(0);
                }
                let end = cursor
                    .checked_add(buf.len() as u64)
                    .and_then(|v| v.checked_sub(1))
                    .map(|v| v.min(*size - 1))
                    .unwrap_or(*size - 1);
                let response = self
                    .bucket
                    .get_object_range(&self.key, *cursor, Some(end))
                    .map_err(io::Error::other)?;
                let data = response.as_slice();
                let to_copy = data.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);
                *cursor += to_copy as u64;
                Ok(to_copy)
            }
            S3FileInner::Staged { file, .. } => file.as_file_mut().read(buf),
        }
    }
}

impl Write for S3File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            S3FileInner::ReadOnly { .. } => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file not opened for writing",
            )),
            S3FileInner::Staged { file, size, dirty } => {
                let written = file.as_file_mut().write(buf)?;
                let pos = file.as_file_mut().stream_position()?;
                if pos > *size {
                    *size = pos;
                }
                *dirty = true;
                Ok(written)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            S3FileInner::ReadOnly { .. } => Ok(()),
            S3FileInner::Staged { file, .. } => {
                file.as_file_mut().flush()?;
                self.upload_if_dirty()
            }
        }
    }
}

impl Seek for S3File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            S3FileInner::ReadOnly { .. } => self.read_only_seek(pos),
            S3FileInner::Staged { file, .. } => file.as_file_mut().seek(pos),
        }
    }
}

impl File for S3File {
    fn metadata(&self) -> Result<Metadata, Box<dyn std::error::Error>> {
        let size = match &self.inner {
            S3FileInner::ReadOnly { size, .. } => *size,
            S3FileInner::Staged { size, .. } => *size,
        };
        let mut metadata = Metadata::default();
        metadata.is_file = true;
        metadata.is_dir = false;
        metadata.len = size;
        Ok(metadata)
    }
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

    fn open_s3_file(&self, key: String, options: OpenOptions) -> Result<S3File, S3FsError> {
        let head_result = self.bucket.head_object(&key);
        let (head, exists) = match head_result {
            Ok((head, status)) => {
                if (200..300).contains(&status) {
                    (Some(head), true)
                } else if status == 404 {
                    (None, false)
                } else {
                    return Err(S3FsError::HttpStatus {
                        op: "head_object",
                        status,
                    });
                }
            }
            Err(S3Error::HttpFailWithBody(404, _)) => (None, false),
            Err(err) => return Err(S3FsError::S3(err)),
        };

        if options.create_new && exists {
            return Err(S3FsError::AlreadyExists);
        }

        let wants_write = options.write
            || options.append
            || options.truncate
            || options.create
            || options.create_new;
        if (options.create || options.create_new || options.truncate || options.append)
            && !options.write
        {
            return Err(S3FsError::InvalidConfig(
                "write required for create/append/truncate".to_string(),
            ));
        }
        if options.append && options.truncate {
            return Err(S3FsError::InvalidConfig(
                "append and truncate are mutually exclusive".to_string(),
            ));
        }
        if !options.read && !wants_write {
            return Err(S3FsError::InvalidConfig(
                "open options must include read or write".to_string(),
            ));
        }

        if !wants_write {
            if !exists {
                return Err(S3FsError::NotFound);
            }
            let head = head.ok_or(S3FsError::MissingContentLength)?;
            let size = head.content_length.ok_or(S3FsError::MissingContentLength)?;
            let size = if size < 0 { 0 } else { size as u64 };
            return Ok(S3File::new_read_only(
                self.bucket.as_ref().clone(),
                key,
                size,
            ));
        }

        if !exists && !(options.create || options.create_new) {
            return Err(S3FsError::NotFound);
        }

        let mut temp = NamedTempFile::new()?;
        let mut dirty = false;
        let mut size = 0u64;

        if exists && !options.truncate {
            let status = self.bucket.get_object_to_writer(&key, temp.as_file_mut())?;
            if !(200..300).contains(&status) {
                return Err(S3FsError::HttpStatus {
                    op: "get_object",
                    status,
                });
            }
            size = temp.as_file().metadata()?.len();
        } else {
            temp.as_file_mut().set_len(0)?;
            dirty = true;
        }

        let mut s3_file = S3File::new_staged(self.bucket.as_ref().clone(), key, temp, size, dirty);

        if options.append {
            s3_file.seek(SeekFrom::End(0))?;
        } else {
            s3_file.seek(SeekFrom::Start(0))?;
        }

        Ok(s3_file)
    }

    fn copy_object(&self, from_key: &str, to_key: &str) -> Result<(), S3FsError> {
        let status = self.bucket.copy_object_internal(from_key, to_key)?;
        if !(200..300).contains(&status) {
            return Err(S3FsError::HttpStatus {
                op: "copy_object",
                status,
            });
        }
        Ok(())
    }

    fn ensure_non_empty_key(key: &str) -> Result<(), S3FsError> {
        if key.is_empty() {
            return Err(S3FsError::InvalidPath("path must not be root".to_string()));
        }
        Ok(())
    }

    fn to_io_error(err: S3FsError) -> io::Error {
        match err {
            S3FsError::NotFound => io::Error::new(io::ErrorKind::NotFound, "object not found"),
            S3FsError::AlreadyExists => {
                io::Error::new(io::ErrorKind::AlreadyExists, "object already exists")
            }
            S3FsError::InvalidPath(msg) => io::Error::new(io::ErrorKind::InvalidInput, msg),
            other => io::Error::new(io::ErrorKind::Other, other.to_string()),
        }
    }

    fn boxed_error(err: S3FsError) -> Box<dyn std::error::Error> {
        Box::new(Self::to_io_error(err))
    }
}

impl FileSystem for S3Fs {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, Box<dyn std::error::Error>> {
        let dir_prefix = self.dir_to_prefix(&path).map_err(Self::boxed_error)?;
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
        let dir_prefix = self.dir_to_prefix(&path).map_err(Self::boxed_error)?;
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
        path: P,
        options: OpenOptions,
    ) -> Result<Box<dyn File>, Box<dyn std::error::Error>> {
        let key = self.path_to_key(path).map_err(Self::boxed_error)?;
        let file = self.open_s3_file(key, options).map_err(Self::boxed_error)?;
        Ok(Box::new(file))
    }

    fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn File>, Box<dyn std::error::Error>> {
        let options = OpenOptions {
            read: true,
            write: true,
            append: false,
            truncate: true,
            create: true,
            create_new: true,
        };
        self.open_file(path, options)
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

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let key = self.path_to_key(path).map_err(Self::boxed_error)?;
        if key.is_empty() {
            return Err(Self::boxed_error(S3FsError::InvalidPath(
                "file path must not be root".to_string(),
            )));
        }
        let response = self
            .bucket
            .delete_object(&key)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(Self::boxed_error(S3FsError::HttpStatus {
                op: "delete_object",
                status,
            }));
        }
        Ok(())
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let dir_prefix = self.dir_to_prefix(&path).map_err(Self::boxed_error)?;
        if dir_prefix.is_empty() {
            return Ok(());
        }

        let results = self
            .bucket
            .list(dir_prefix.clone(), None)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        for result in results {
            for object in result.contents {
                let response = self
                    .bucket
                    .delete_object(&object.key)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                let status = response.status_code();
                if !(200..300).contains(&status) {
                    return Err(Self::boxed_error(S3FsError::HttpStatus {
                        op: "delete_object",
                        status,
                    }));
                }
            }
        }
        Ok(())
    }

    fn copy_file<P: AsRef<Path>>(&self, src: P, dest: P) -> Result<(), Box<dyn std::error::Error>> {
        let src_key = self.path_to_key(src).map_err(Self::boxed_error)?;
        let dest_key = self.path_to_key(dest).map_err(Self::boxed_error)?;
        Self::ensure_non_empty_key(&src_key).map_err(Self::boxed_error)?;
        Self::ensure_non_empty_key(&dest_key).map_err(Self::boxed_error)?;
        self.copy_object(&src_key, &dest_key)
            .map_err(Self::boxed_error)
    }

    fn move_file<P: AsRef<Path>>(&self, src: P, dest: P) -> Result<(), Box<dyn std::error::Error>> {
        let src_key = self.path_to_key(&src).map_err(Self::boxed_error)?;
        let dest_key = self.path_to_key(&dest).map_err(Self::boxed_error)?;
        Self::ensure_non_empty_key(&src_key).map_err(Self::boxed_error)?;
        Self::ensure_non_empty_key(&dest_key).map_err(Self::boxed_error)?;
        if src_key == dest_key {
            return Ok(());
        }
        self.copy_object(&src_key, &dest_key)
            .map_err(Self::boxed_error)?;
        self.remove_file(src)
    }

    fn move_dir<P: AsRef<Path>>(&self, src: P, dest: P) -> Result<(), Box<dyn std::error::Error>> {
        let src_prefix = self.dir_to_prefix(&src).map_err(Self::boxed_error)?;
        let dest_prefix = self.dir_to_prefix(&dest).map_err(Self::boxed_error)?;

        if src_prefix.is_empty() {
            return Ok(());
        }
        if src_prefix == dest_prefix {
            return Ok(());
        }
        if dest_prefix.starts_with(&src_prefix) {
            return Err(Self::boxed_error(S3FsError::InvalidPath(
                "destination directory must not be inside source".to_string(),
            )));
        }

        let results = self
            .bucket
            .list(src_prefix.clone(), None)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let mut mappings = Vec::new();
        let mut delete_keys = Vec::new();
        for result in results {
            for object in result.contents {
                let src_key = object.key;
                let relative = src_key.strip_prefix(&src_prefix).unwrap_or(&src_key);
                let dest_key = if relative.is_empty() {
                    if dest_prefix.is_empty() {
                        delete_keys.push(src_key);
                        continue;
                    }
                    dest_prefix.clone()
                } else if dest_prefix.is_empty() {
                    relative.to_string()
                } else {
                    format!("{dest_prefix}{relative}")
                };
                mappings.push((src_key, dest_key));
            }
        }

        for (src_key, dest_key) in &mappings {
            self.copy_object(src_key, dest_key)
                .map_err(Self::boxed_error)?;
        }

        for (src_key, _) in &mappings {
            delete_keys.push(src_key.clone());
        }

        for src_key in delete_keys {
            let response = self
                .bucket
                .delete_object(&src_key)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            let status = response.status_code();
            if !(200..300).contains(&status) {
                return Err(Self::boxed_error(S3FsError::HttpStatus {
                    op: "delete_object",
                    status,
                }));
            }
        }

        Ok(())
    }

    fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, Box<dyn std::error::Error>> {
        let key = self.path_to_key(&path).map_err(Self::boxed_error)?;
        if key.is_empty() {
            let mut metadata = Metadata::default();
            metadata.is_dir = true;
            metadata.is_file = false;
            metadata.len = 0;
            return Ok(metadata);
        }

        let head_result = self.bucket.head_object(&key);
        match head_result {
            Ok((head, status)) if (200..300).contains(&status) => {
                let size = head.content_length.ok_or(S3FsError::MissingContentLength)?;
                let size = if size < 0 { 0 } else { size as u64 };
                let mut metadata = Metadata::default();
                metadata.is_dir = false;
                metadata.is_file = true;
                metadata.len = size;
                Ok(metadata)
            }
            Ok((_, status)) if status == 404 => {
                let dir_prefix = self.dir_to_prefix(&path).map_err(Self::boxed_error)?;
                let (result, status) = self
                    .bucket
                    .list_page(
                        dir_prefix.clone(),
                        Some("/".to_string()),
                        None,
                        None,
                        Some(1),
                    )
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                if !(200..300).contains(&status) {
                    return Err(Self::boxed_error(S3FsError::HttpStatus {
                        op: "list_objects",
                        status,
                    }));
                }
                let has_contents = !result.contents.is_empty();
                let has_prefixes = result
                    .common_prefixes
                    .as_ref()
                    .is_some_and(|prefixes| !prefixes.is_empty());
                if has_contents || has_prefixes {
                    let mut metadata = Metadata::default();
                    metadata.is_dir = true;
                    metadata.is_file = false;
                    metadata.len = 0;
                    Ok(metadata)
                } else {
                    Err(Self::boxed_error(S3FsError::NotFound))
                }
            }
            Ok((_, status)) => Err(Self::boxed_error(S3FsError::HttpStatus {
                op: "head_object",
                status,
            })),
            Err(S3Error::HttpFailWithBody(404, _)) => Err(Self::boxed_error(S3FsError::NotFound)),
            Err(err) => Err(Self::boxed_error(S3FsError::S3(err))),
        }
    }

    fn stats<P: AsRef<Path>>(&self, _path: P) -> Result<Stats, Box<dyn std::error::Error>> {
        Ok(Stats::default())
    }
}
