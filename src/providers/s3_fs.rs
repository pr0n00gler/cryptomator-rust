use std::ffi::OsString;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use s3::Bucket;
use s3::creds::Credentials;
use s3::creds::error::CredentialsError;
use s3::error::S3Error;
use s3::region::Region;
use tempfile::NamedTempFile;
use thiserror::Error;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::cryptofs::{DirEntry, File, FileSystem, Metadata, OpenOptions, Stats};

/// Configuration for connecting to S3-compatible storage.
///
/// # Security
///
/// The `Debug` implementation redacts credential fields (`access_key`,
/// `secret_key`, `session_token`) to prevent accidental leakage to logs.
/// `Clone` is intentionally not derived to discourage unnecessary copies of
/// credential material in memory.
pub struct S3FsConfig {
    /// Name of the S3 bucket that holds vault data.
    pub bucket: String,
    /// Optional key prefix applied to every object path within the bucket.
    /// Use this to store the vault under a sub-path, e.g. `"vaults/my-vault"`.
    pub prefix: Option<String>,
    /// AWS region name (e.g. `"us-east-1"`). Required even for custom endpoints.
    pub region: String,
    /// Custom endpoint URL for S3-compatible services (e.g. MinIO, LocalStack).
    /// When `None`, the standard AWS endpoint for the given region is used.
    pub endpoint: Option<String>,
    /// Use path-style bucket addressing (`https://host/bucket/key`) instead of
    /// the default virtual-hosted style (`https://bucket.host/key`).
    /// Required for LocalStack and some MinIO configurations.
    pub force_path_style: bool,
    /// When `true`, performs a lightweight list request during [`S3Fs::new`] to
    /// verify that the bucket is accessible. Useful for failing fast on
    /// misconfigured credentials.
    pub validate_bucket: bool,
    /// AWS access key ID. Must be provided together with [`Self::secret_key`].
    /// When `None`, the provider attempts to use ambient credentials
    /// (environment variables, instance metadata, etc.).
    pub access_key: Option<Zeroizing<String>>,
    /// AWS secret access key. Must be provided together with [`Self::access_key`].
    pub secret_key: Option<Zeroizing<String>>,
    /// Optional session token for temporary credentials (e.g. STS / IAM roles).
    /// Requires both [`Self::access_key`] and [`Self::secret_key`] to be set.
    pub session_token: Option<Zeroizing<String>>,
    /// Per-request timeout. `None` uses the `rust-s3` default.
    /// Must be greater than zero if set.
    pub request_timeout: Option<Duration>,
}

impl std::fmt::Debug for S3FsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3FsConfig")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("force_path_style", &self.force_path_style)
            .field("validate_bucket", &self.validate_bucket)
            .field(
                "access_key",
                &self.access_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

/// Errors returned by S3 filesystem initialization and operations.
#[derive(Debug, Error)]
pub enum S3FsError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("file already exists")]
    AlreadyExists,
    #[error("file does not exist")]
    NotFound,
    #[error("content length missing")]
    MissingContentLength,
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
///
/// # Credential lifetime caveat
///
/// Although [`S3FsConfig`] wraps credential fields in [`Zeroizing`] wrappers,
/// the underlying `rust-s3` crate copies them into plain `String` values inside
/// its [`Credentials`] / [`Bucket`] types. As a result, credential material
/// will remain in process memory as regular heap-allocated strings for the
/// lifetime of this struct and cannot be reliably zeroized on drop. If your
/// threat model requires strict in-memory credential hygiene, consider running
/// the S3 provider in a short-lived process or using ambient credential
/// mechanisms (e.g. instance metadata / IRSA) that avoid long-lived secrets.
#[derive(Clone, Debug)]
pub struct S3Fs {
    bucket: Arc<Bucket>,
    prefix: String,
}

/// An open S3 object handle that supports read, write, and seek.
///
/// # Important: flush before dropping
///
/// When opened for writing, the content is staged in a local temporary file
/// and uploaded to S3 on `flush()`. **Callers MUST call `flush()` before
/// dropping this handle** to guarantee the write is persisted. Any upload
/// error encountered during `Drop` is only logged as a warning and **not**
/// propagated — data will be silently lost if `flush()` is not called
/// explicitly.
struct S3File {
    bucket: Arc<Bucket>,
    key: String,
    inner: S3FileInner,
}

enum S3FileInner {
    ReadOnly {
        cursor: Cursor<Vec<u8>>,
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
    fn new_read_only(bucket: Arc<Bucket>, key: String, data: Vec<u8>) -> Self {
        S3File {
            bucket,
            key,
            inner: S3FileInner::ReadOnly {
                cursor: Cursor::new(data),
            },
        }
    }

    fn new_staged(
        bucket: Arc<Bucket>,
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
                    return Err(io::Error::other(format!(
                        "upload failed with status {status}"
                    )));
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
            S3FileInner::ReadOnly { cursor } => cursor.seek(pos),
            S3FileInner::Staged { .. } => {
                Err(io::Error::other("read_only_seek called on staged file"))
            }
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
            S3FileInner::ReadOnly { cursor } => cursor.read(buf),
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
            S3FileInner::ReadOnly { cursor } => cursor.get_ref().len() as u64,
            // Read the actual on-disk temp-file size to avoid reporting a stale
            // high-water-mark when the file has been seeked without writing.
            S3FileInner::Staged { file, .. } => file.as_file().metadata()?.len(),
        };
        Ok(Metadata {
            is_file: true,
            is_dir: false,
            len: size,
            ..Default::default()
        })
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
            None => region_name
                .parse()
                .map_err(|e| S3FsError::S3(S3Error::Utf8(e)))?,
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
        let bucket = Arc::new(*bucket);

        let prefix = Self::normalize_prefix(config.prefix.unwrap_or_default())?;
        if config.validate_bucket {
            // A failed list_page can produce an opaque XML deserialisation error
            // (e.g. "missing field `Name`") when the server returns an error envelope
            // rather than a valid ListObjectsV2 response.  The most common cause is
            // using virtual-hosted-style addressing against a self-hosted endpoint
            // (MinIO, LocalStack) that only supports path-style URLs — set
            // `force_path_style: true` in the config to fix this.
            bucket
                .list_page(prefix.clone(), None, None, None, Some(1))
                .map_err(|e| {
                    S3FsError::InvalidConfig(format!(
                        "bucket validation failed — check that the bucket exists, credentials are \
                     correct, and (for self-hosted endpoints) `force_path_style` is true: {e}"
                    ))
                })?;
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
        // Determine whether the object already exists via HEAD.
        //
        // Some S3-compatible backends (e.g. MinIO, LocalStack) return HTTP 500
        // instead of 404 when performing a HEAD on a key that does not exist.
        // To handle this gracefully we distinguish three outcomes:
        //
        //   - `Some(true)`  – object definitely exists (2xx)
        //   - `Some(false)` – object definitely does not exist (404)
        //   - `None`        – ambiguous: the backend returned an unexpected
        //                     error (e.g. 500).  When the caller intends to
        //                     create a new object we treat this as "not found"
        //                     and proceed with creation; for read-only opens we
        //                     surface the original error.
        let head_outcome: Option<bool>;
        let mut head_error: Option<S3FsError> = None;

        match self.bucket.head_object(&key) {
            Ok((_, status)) if (200..300).contains(&status) => {
                head_outcome = Some(true);
            }
            Ok((_, 404)) | Err(S3Error::HttpFailWithBody(404, _)) => {
                head_outcome = Some(false);
            }
            Ok((_, status)) => {
                head_error = Some(S3FsError::HttpStatus {
                    op: "head_object",
                    status,
                });
                head_outcome = None;
            }
            Err(err) => {
                head_error = Some(S3FsError::S3(err));
                head_outcome = None;
            }
        }

        let wants_create = options.create || options.create_new;

        // For ambiguous HEAD results: propagate the error only when the caller
        // is not trying to create the object (i.e. a read or an unconditional
        // write-without-create where existence is required).
        let exists = match head_outcome {
            Some(v) => v,
            None if wants_create => false, // treat ambiguous as "not found" and let create proceed
            None => return Err(head_error.expect("head_error is set when head_outcome is None")),
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
            // Pre-fetch the entire object into memory so that subsequent
            // `read()` calls are served from a local buffer instead of
            // issuing one S3 GET per call.
            let response = self.bucket.get_object(&key)?;
            let status = response.status_code();
            if !(200..300).contains(&status) {
                return Err(S3FsError::HttpStatus {
                    op: "get_object",
                    status,
                });
            }
            let data = response.to_vec();
            return Ok(S3File::new_read_only(Arc::clone(&self.bucket), key, data));
        }

        if !(exists || options.create || options.create_new) {
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

        let mut s3_file = S3File::new_staged(Arc::clone(&self.bucket), key, temp, size, dirty);

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
            other => io::Error::other(other.to_string()),
        }
    }

    fn boxed_error(err: S3FsError) -> Box<dyn std::error::Error> {
        Box::new(Self::to_io_error(err))
    }

    fn box_err<E: std::error::Error + 'static>(err: E) -> Box<dyn std::error::Error> {
        Box::new(err)
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
            .map_err(Self::box_err)?;

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
                    entries.push(DirEntry {
                        path: base_path.join(Path::new(&name)),
                        metadata: Metadata {
                            is_dir: true,
                            is_file: false,
                            len: 0,
                            ..Default::default()
                        },
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
                entries.push(DirEntry {
                    path: base_path.join(Path::new(&name)),
                    metadata: Metadata {
                        is_dir: false,
                        is_file: true,
                        len: object.size,
                        ..Default::default()
                    },
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
        let response = match self.bucket.put_object(&dir_prefix, &[]) {
            Ok(response) => response,
            Err(S3Error::HttpFailWithBody(400, ref body)) => {
                debug!(
                    prefix = %dir_prefix,
                    body = %body,
                    "create_dir: ignoring HTTP 400 from put_object"
                );
                return Ok(());
            }
            Err(err) => return Err(Self::box_err(err)),
        };
        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(Self::boxed_error(S3FsError::HttpStatus {
                op: "put_object",
                status,
            }));
        }
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

        // Try an exact HEAD first to avoid false positives from prefix-based
        // listing (e.g. key "foo" matching object "foobar").
        match self.bucket.head_object(&key) {
            Ok((_, status)) if (200..300).contains(&status) => return true,
            Ok((_, 404)) | Err(S3Error::HttpFailWithBody(404, _)) => {
                // Object does not exist as a file; fall through to directory check.
            }
            _ => {
                // Ambiguous error (e.g. 500) -- fall through to directory check
                // rather than returning a definitive answer.
            }
        }

        // Check whether the key represents a directory (has children).
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
        let response = self.bucket.delete_object(&key).map_err(Self::box_err)?;
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

        // NOTE: Objects are deleted one-by-one because `rust-s3` (v0.37) does
        // not expose the S3 multi-object delete (DeleteObjects) API in its
        // synchronous interface. If a future version adds batch delete support,
        // this loop should be replaced to reduce the number of HTTP round-trips.
        let results = self
            .bucket
            .list(dir_prefix.clone(), None)
            .map_err(Self::box_err)?;
        for result in results {
            for object in result.contents {
                let response = self
                    .bucket
                    .delete_object(&object.key)
                    .map_err(Self::box_err)?;
                let status = response.status_code();
                if !(200..300).contains(&status) {
                    if status == 400 && object.key.ends_with('/') {
                        // Some S3-compatible endpoints (e.g. older MinIO) return 400 when
                        // deleting zero-byte directory-marker objects; treat as success but
                        // log so operators can investigate if needed.
                        warn!(key = %object.key, status, "delete of directory marker returned unexpected status; ignoring");
                        continue;
                    }
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

    /// Moves a file from `src` to `dest` using a server-side copy followed by deletion.
    ///
    /// # Non-atomicity
    ///
    /// S3 does not support atomic renames. This operation performs two separate
    /// API calls:
    /// 1. `CopyObject` — copies `src` to `dest`.
    /// 2. `DeleteObject` — deletes `src`.
    ///
    /// If step 1 succeeds but step 2 fails (e.g. due to a transient network
    /// error), the object will exist at **both** the source and destination
    /// paths. The copy is considered the authoritative version; the lingering
    /// source is safe to delete manually.
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

    /// Moves a directory from `src` to `dest` using server-side copies
    /// followed by deletion of the source objects.
    ///
    /// # Non-atomicity and partial failure
    ///
    /// S3 does not support atomic directory renames. This method performs the
    /// move in two phases:
    ///
    /// 1. **Copy phase** -- each object under `src` is copied to the
    ///    corresponding key under `dest`. If any copy fails, the operation
    ///    stops immediately. Objects that were already copied to `dest` will
    ///    **not** be cleaned up automatically (the caller may need to remove
    ///    partial copies manually).
    /// 2. **Delete phase** -- only source keys whose copy succeeded are
    ///    deleted. If a delete fails, the operation stops; objects already
    ///    deleted cannot be recovered, while remaining source objects are left
    ///    intact. The copied versions at `dest` are considered authoritative.
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
            .map_err(Self::box_err)?;

        let mut mappings = Vec::new();
        let mut orphan_delete_keys = Vec::new();
        for result in results {
            for object in result.contents {
                let src_key = object.key;
                let relative = src_key.strip_prefix(&src_prefix).unwrap_or(&src_key);
                let dest_key = if relative.is_empty() {
                    if dest_prefix.is_empty() {
                        orphan_delete_keys.push(src_key);
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

        // Copy phase -- track which copies succeeded so we only delete those.
        let mut copied_src_keys: Vec<String> = Vec::with_capacity(mappings.len());
        for (src_key, dest_key) in &mappings {
            self.copy_object(src_key, dest_key)
                .map_err(Self::boxed_error)?;
            copied_src_keys.push(src_key.clone());
        }

        // Delete phase -- only delete source keys whose copy succeeded, plus
        // any orphan keys that had no corresponding destination.
        let delete_keys = copied_src_keys
            .into_iter()
            .chain(orphan_delete_keys);

        for src_key in delete_keys {
            let response = self.bucket.delete_object(&src_key).map_err(Self::box_err)?;
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
            return Ok(Metadata {
                is_dir: true,
                is_file: false,
                len: 0,
                ..Default::default()
            });
        }

        let head_result = self.bucket.head_object(&key);
        match head_result {
            Ok((head, status)) if (200..300).contains(&status) => {
                let size = head.content_length.ok_or(S3FsError::MissingContentLength)?;
                let size = if size < 0 {
                    warn!(key = %key, content_length = size, "head_object returned negative content_length; treating as 0");
                    0
                } else {
                    size as u64
                };
                Ok(Metadata {
                    is_dir: false,
                    is_file: true,
                    len: size,
                    ..Default::default()
                })
            }
            Ok((_, 404)) => {
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
                    .map_err(Self::box_err)?;
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
                    Ok(Metadata {
                        is_dir: true,
                        is_file: false,
                        len: 0,
                        ..Default::default()
                    })
                } else {
                    Err(Self::boxed_error(S3FsError::NotFound))
                }
            }
            Ok((_, status)) => Err(Self::boxed_error(S3FsError::HttpStatus {
                op: "head_object",
                status,
            })),
            Err(S3Error::HttpFailWithBody(404, _)) => {
                // Fall through to directory listing check, same as Ok((_, 404))
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
                    .map_err(Self::box_err)?;
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
                    Ok(Metadata {
                        is_dir: true,
                        is_file: false,
                        len: 0,
                        ..Default::default()
                    })
                } else {
                    Err(Self::boxed_error(S3FsError::NotFound))
                }
            }
            Err(err) => Err(Self::boxed_error(S3FsError::S3(err))),
        }
    }

    fn stats<P: AsRef<Path>>(&self, _path: P) -> Result<Stats, Box<dyn std::error::Error>> {
        Ok(Stats::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fs(prefix: &str) -> S3Fs {
        let region = Region::Custom {
            region: "test".to_string(),
            endpoint: "http://localhost".to_string(),
        };
        let credentials =
            Credentials::new(Some("ak"), Some("sk"), None, None, None).expect("credentials");
        let bucket = Bucket::new("bucket", region, credentials).expect("bucket");
        S3Fs {
            bucket: Arc::new(*bucket),
            prefix: prefix.to_string(),
        }
    }

    #[test]
    fn normalize_prefix_trims_slashes() {
        let normalized = S3Fs::normalize_prefix("/vault/root/".to_string()).expect("prefix");
        assert_eq!(normalized, "vault/root");
    }

    #[test]
    fn path_to_key_joins_prefix() {
        let fs = test_fs("vault");
        let key = fs.path_to_key("/dir/file.txt").expect("key");
        assert_eq!(key, "vault/dir/file.txt");
    }

    #[test]
    fn dir_to_prefix_adds_trailing_slash() {
        let fs = test_fs("vault");
        let prefix = fs.dir_to_prefix("dir").expect("prefix");
        assert_eq!(prefix, "vault/dir/");
    }

    #[test]
    fn path_to_key_rejects_parent_dir() {
        let fs = test_fs("vault");
        let result = fs.path_to_key("../evil");
        assert!(matches!(result, Err(S3FsError::InvalidPath(_))));
    }
}
