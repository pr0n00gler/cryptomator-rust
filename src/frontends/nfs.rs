use crate::cryptofs::{CryptoFs, FileSystem, FileSystemError, Metadata, OpenOptions};
use async_trait::async_trait;
use nfsserve::nfs::{
    fattr3, fileid3, ftype3, nfsstat3, nfsstring, nfstime3, sattr3, set_size3, specdata3,
};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;
use tracing::{debug, error, warn};

/// Maximum number of file handles the NFS server will track before
/// evicting the least-recently-created entries.  The root handle (1)
/// is never evicted.
const DEFAULT_MAX_HANDLES: usize = 10_000;

/// Maximum number of concurrent NFS connections.
///
/// Mirrors the WebDAV `MAX_WEBDAV_CONNECTIONS` limit to prevent
/// file-descriptor exhaustion.
pub const MAX_NFS_CONNECTIONS: usize = 64;

/// Maps a `FileSystemError` to an appropriate NFS status code.
///
/// `TooManyOpenFiles` is mapped to `NFS3ERR_JUKEBOX` ("resource temporarily
/// unavailable -- retry later") rather than `NFS3ERR_IO` (a non-retriable I/O
/// error).  This is the closest semantic match in the NFSv3 vocabulary and
/// tells well-behaved clients to back off and retry instead of reporting a
/// hard failure.
fn fs_err_to_nfsstat(e: &FileSystemError) -> nfsstat3 {
    match e {
        FileSystemError::TooManyOpenFiles => {
            warn!("NFS open file limit reached; returning NFS3ERR_JUKEBOX");
            nfsstat3::NFS3ERR_JUKEBOX
        }
        FileSystemError::PathDoesNotExist(_) => nfsstat3::NFS3ERR_NOENT,
        FileSystemError::InvalidPathError(_) => nfsstat3::NFS3ERR_INVAL,
        FileSystemError::ReadOnly => nfsstat3::NFS3ERR_ROFS,
        FileSystemError::IoError(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
            nfsstat3::NFS3ERR_NOENT
        }
        // The underlying filesystem provider may return errors as
        // `Box<dyn Error>` which get converted to `UnknownError`.
        // Detect common not-found patterns to avoid mapping them as
        // generic I/O errors.
        FileSystemError::UnknownError(msg)
            if msg.contains("not found")
                || msg.contains("Not found")
                || msg.contains("No such file")
                || msg.contains("entity not found") =>
        {
            nfsstat3::NFS3ERR_NOENT
        }
        _ => nfsstat3::NFS3ERR_IO,
    }
}

/// Validates that an NFS filename component is safe.
///
/// Rejects filenames that are exactly `.` or `..`, contain `/` or `\0`,
/// or are empty.  Returns `NFS3ERR_INVAL` for invalid names.
fn validate_filename(name: &str) -> Result<(), nfsstat3> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(nfsstat3::NFS3ERR_INVAL);
    }
    if name.contains('/') || name.contains('\0') {
        return Err(nfsstat3::NFS3ERR_INVAL);
    }
    Ok(())
}

/// Parses an NFS filename from raw bytes, rejecting non-UTF-8 input
/// and unsafe path components.
fn parse_nfs_name(name: &nfsstring) -> Result<String, nfsstat3> {
    let s = String::from_utf8(name.to_vec()).map_err(|_| {
        warn!("NFS filename is not valid UTF-8");
        nfsstat3::NFS3ERR_INVAL
    })?;
    validate_filename(&s)?;
    Ok(s)
}

/// Clamps a `u64` seconds value to `u32`, saturating at `u32::MAX`
/// instead of silently truncating.
fn secs_to_u32(secs: u64) -> u32 {
    u32::try_from(secs).unwrap_or(u32::MAX)
}

/// All NFS file-handle bookkeeping lives in a single struct protected by a
/// single `Mutex`.
///
/// The handle map is bounded: once `max_capacity` non-root entries exist,
/// the oldest entry (by insertion order) is evicted from both maps.
struct HandleState {
    path_to_handle: HashMap<PathBuf, u64>,
    handle_to_path: HashMap<u64, PathBuf>,
    /// Insertion-order queue for eviction.  The root handle is never
    /// enqueued and therefore never evicted.
    insertion_order: VecDeque<u64>,
    /// Maximum number of non-root entries.
    max_capacity: usize,
    /// Monotonically increasing counter; starts at 2 (1 is reserved for root).
    next_handle: u64,
}

impl HandleState {
    fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_HANDLES)
    }

    fn with_capacity(max_capacity: usize) -> Self {
        let root = PathBuf::from("/");
        let mut path_to_handle = HashMap::new();
        let mut handle_to_path = HashMap::new();
        handle_to_path.insert(1u64, root.clone());
        path_to_handle.insert(root, 1u64);
        HandleState {
            path_to_handle,
            handle_to_path,
            insertion_order: VecDeque::new(),
            max_capacity,
            next_handle: 2,
        }
    }

    /// Evict the oldest non-root entry if at capacity.
    fn evict_if_needed(&mut self) {
        while self.insertion_order.len() >= self.max_capacity {
            if let Some(old_handle) = self.insertion_order.pop_front() {
                if let Some(old_path) = self.handle_to_path.remove(&old_handle) {
                    self.path_to_handle.remove(&old_path);
                }
            } else {
                break;
            }
        }
    }

    /// Returns the existing handle for `path`, or allocates a new one.
    ///
    /// Because both the lookup and the insertion happen inside a single
    /// `MutexGuard` scope, there is no window for a concurrent caller to
    /// allocate a second handle for the same path.
    fn get_or_create(&mut self, path: PathBuf) -> Result<u64, nfsstat3> {
        if let Some(&handle) = self.path_to_handle.get(&path) {
            return Ok(handle);
        }

        // Evict oldest entries if at capacity.
        self.evict_if_needed();

        // Saturating-add guard: after u64::MAX allocations the counter would
        // wrap back to 0 and then 1 (the root handle).  Return NFS3ERR_NOSPC
        // rather than aliasing an existing handle.
        let handle = self
            .next_handle
            .checked_add(1)
            .map(|next| {
                let h = self.next_handle;
                self.next_handle = next;
                h
            })
            .ok_or(nfsstat3::NFS3ERR_NOSPC)?;
        self.path_to_handle.insert(path.clone(), handle);
        self.handle_to_path.insert(handle, path);
        self.insertion_order.push_back(handle);
        Ok(handle)
    }

    fn get_path(&self, handle: u64) -> Result<PathBuf, nfsstat3> {
        self.handle_to_path
            .get(&handle)
            .cloned()
            .ok_or(nfsstat3::NFS3ERR_STALE)
    }

    fn forget(&mut self, path: &PathBuf) {
        if let Some(handle) = self.path_to_handle.remove(path) {
            self.handle_to_path.remove(&handle);
            // Note: we do not remove from insertion_order here because
            // scanning a VecDeque is O(n).  Stale entries in the queue
            // are harmlessly skipped during eviction.
        }
    }

    /// Returns the current number of non-root entries tracked.
    fn len(&self) -> usize {
        // path_to_handle includes the root entry; subtract 1.
        self.path_to_handle.len().saturating_sub(1)
    }

    /// Atomically re-keys every path that starts with `old_path` to be rooted
    /// at `new_path` instead, updating both maps in the same lock scope.
    fn rename_prefix(&mut self, old_path: &PathBuf, new_path: PathBuf) {
        let updates: Vec<(PathBuf, PathBuf, u64)> = self
            .path_to_handle
            .iter()
            .filter(|(path, _)| path.starts_with(old_path))
            .map(|(path, &handle)| {
                let suffix = path.strip_prefix(old_path).unwrap_or(path.as_path());
                (path.clone(), new_path.join(suffix), handle)
            })
            .collect();

        for (old, new, handle) in updates {
            self.path_to_handle.remove(&old);
            self.path_to_handle.insert(new.clone(), handle);
            self.handle_to_path.insert(handle, new);
        }
    }
}

pub struct NfsServer<FS: FileSystem> {
    crypto_fs: CryptoFs<FS>,
    handles: Arc<Mutex<HandleState>>,
    /// Semaphore that limits the number of concurrent NFS operations.
    /// Currently unused because the `nfsserve` crate manages its own
    /// accept loop, but kept for future use when a custom accept loop
    /// is implemented.
    #[allow(dead_code)]
    conn_semaphore: Arc<tokio::sync::Semaphore>,
}

impl<FS: FileSystem> NfsServer<FS> {
    pub fn new(crypto_fs: CryptoFs<FS>) -> Self {
        NfsServer {
            crypto_fs,
            handles: Arc::new(Mutex::new(HandleState::new())),
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_NFS_CONNECTIONS)),
        }
    }

    #[doc(hidden)]
    pub fn with_handle_capacity(crypto_fs: CryptoFs<FS>, max_handles: usize) -> Self {
        NfsServer {
            crypto_fs,
            handles: Arc::new(Mutex::new(HandleState::with_capacity(max_handles))),
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_NFS_CONNECTIONS)),
        }
    }

    fn get_or_create_handle(&self, path: PathBuf) -> Result<u64, nfsstat3> {
        self.handles
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .get_or_create(path)
    }

    fn get_path_from_handle(&self, handle: u64) -> Result<PathBuf, nfsstat3> {
        self.handles
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .get_path(handle)
    }

    fn forget_path(&self, path: &PathBuf) -> Result<(), nfsstat3> {
        self.handles
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .forget(path);
        Ok(())
    }

    fn update_path(&self, old_path: &PathBuf, new_path: PathBuf) -> Result<(), nfsstat3> {
        self.handles
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .rename_prefix(old_path, new_path);
        Ok(())
    }

    #[doc(hidden)]
    pub fn handle_count(&self) -> usize {
        self.handles.lock().unwrap().len()
    }

    fn metadata_to_fattr3(metadata: Metadata, handle: u64) -> fattr3 {
        let size = metadata.len;
        let used = size;

        let mode = if metadata.is_dir {
            0o755 | 0o40000 // Directory
        } else {
            0o644 | 0o100000 // Regular file
        };

        let mtime = metadata
            .modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let atime = metadata
            .accessed
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ctime = metadata
            .created
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let (uid, gid) = {
            #[cfg(unix)]
            {
                (metadata.uid, metadata.gid)
            }
            #[cfg(not(unix))]
            {
                (0, 0)
            }
        };

        // Issue #11: directories should have nlink >= 2 (self + parent).
        let nlink = if metadata.is_dir { 2 } else { 1 };

        fattr3 {
            ftype: if metadata.is_dir {
                ftype3::NF3DIR
            } else {
                ftype3::NF3REG
            },
            mode,
            nlink,
            uid,
            gid,
            size,
            used,
            rdev: specdata3 {
                specdata1: 0,
                specdata2: 0,
            },
            fsid: 1,
            fileid: handle as fileid3,
            atime: nfstime3 {
                seconds: secs_to_u32(atime.as_secs()),
                nseconds: atime.subsec_nanos(),
            },
            mtime: nfstime3 {
                seconds: secs_to_u32(mtime.as_secs()),
                nseconds: mtime.subsec_nanos(),
            },
            ctime: nfstime3 {
                seconds: secs_to_u32(ctime.as_secs()),
                nseconds: ctime.subsec_nanos(),
            },
        }
    }
}

#[async_trait]
impl<FS: 'static + FileSystem> NFSFileSystem for NfsServer<FS> {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    fn root_dir(&self) -> u64 {
        1 // Root directory always has handle 1
    }

    async fn getattr(&self, handle: u64) -> Result<fattr3, nfsstat3> {
        debug!("NFS GETATTR: handle={}", handle);

        let path = self.get_path_from_handle(handle)?;

        let crypto_fs = self.crypto_fs.clone();
        tokio::task::spawn_blocking(move || {
            let metadata = crypto_fs
                .metadata(&path)
                .map_err(|e| fs_err_to_nfsstat(&e))?;

            Ok(NfsServer::<FS>::metadata_to_fattr3(metadata, handle))
        })
        .await
        .map_err(|e| {
            error!("NFS getattr task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })?
    }

    async fn setattr(&self, handle: u64, sattr: sattr3) -> Result<fattr3, nfsstat3> {
        debug!("NFS SETATTR: handle={}, sattr={:?}", handle, sattr);

        let path = self.get_path_from_handle(handle)?;

        let crypto_fs = self.crypto_fs.clone();
        tokio::task::spawn_blocking(move || {
            // Handle set_size (file truncation).
            if let set_size3::size(new_size) = sattr.size {
                let metadata = crypto_fs
                    .metadata(&path)
                    .map_err(|e| fs_err_to_nfsstat(&e))?;
                if metadata.is_dir {
                    return Err(nfsstat3::NFS3ERR_ISDIR);
                }

                // Cap the truncation buffer to prevent memory exhaustion
                // from malicious or buggy clients requesting huge sizes.
                const MAX_TRUNCATE_BUFFER_SIZE: u64 = 1 << 30; // 1 GiB
                if new_size > MAX_TRUNCATE_BUFFER_SIZE {
                    return Err(nfsstat3::NFS3ERR_FBIG);
                }

                // Note: the remove-and-recreate strategy below is not atomic.
                // A crash between the remove and the recreate will lose data.
                // This is an inherent limitation of the encrypted filesystem
                // provider, which does not support in-place truncation.
                if new_size == 0 {
                    // Truncate to zero: remove and recreate the file.
                    crypto_fs.remove_file(&path).map_err(|e| {
                        error!("Failed to remove file for truncation: {:?}", e);
                        fs_err_to_nfsstat(&e)
                    })?;
                    let file = crypto_fs.create_file(&path).map_err(|e| {
                        error!("Failed to recreate file for truncation: {:?}", e);
                        fs_err_to_nfsstat(&e)
                    })?;
                    drop(file);
                } else if new_size < metadata.len {
                    // Truncate to a non-zero size: read the data we want to
                    // keep, remove, recreate, and write it back.
                    let mut file = crypto_fs
                        .open_file(&path, *OpenOptions::new().read(true))
                        .map_err(|e| {
                            error!("Failed to open file for truncation read: {:?}", e);
                            fs_err_to_nfsstat(&e)
                        })?;
                    let mut buf = vec![0u8; new_size as usize];
                    file.read_exact(&mut buf).map_err(|e| {
                        error!("Failed to read file for truncation: {:?}", e);
                        nfsstat3::NFS3ERR_IO
                    })?;
                    drop(file);

                    crypto_fs.remove_file(&path).map_err(|e| {
                        error!("Failed to remove file for truncation: {:?}", e);
                        fs_err_to_nfsstat(&e)
                    })?;
                    let mut file = crypto_fs.create_file(&path).map_err(|e| {
                        error!("Failed to recreate file for truncation: {:?}", e);
                        fs_err_to_nfsstat(&e)
                    })?;
                    file.write_all(&buf).map_err(|e| {
                        error!("Failed to write truncated data: {:?}", e);
                        nfsstat3::NFS3ERR_IO
                    })?;
                    file.flush().map_err(|e| {
                        error!("Failed to flush truncated file: {:?}", e);
                        nfsstat3::NFS3ERR_IO
                    })?;
                    drop(file);
                }
                // If new_size >= metadata.len, extending is a no-op for now.
            }

            // Log unsupported attribute changes at debug level.
            if !matches!(sattr.mode, nfsserve::nfs::set_mode3::Void) {
                debug!("NFS SETATTR: ignoring mode change (not supported by encrypted FS)");
            }
            if !matches!(sattr.uid, nfsserve::nfs::set_uid3::Void) {
                debug!("NFS SETATTR: ignoring uid change (not supported by encrypted FS)");
            }
            if !matches!(sattr.gid, nfsserve::nfs::set_gid3::Void) {
                debug!("NFS SETATTR: ignoring gid change (not supported by encrypted FS)");
            }

            let metadata = crypto_fs
                .metadata(&path)
                .map_err(|e| fs_err_to_nfsstat(&e))?;
            Ok(NfsServer::<FS>::metadata_to_fattr3(metadata, handle))
        })
        .await
        .map_err(|e| {
            error!("NFS setattr task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })?
    }

    async fn lookup(&self, dir_handle: u64, name: &nfsstring) -> Result<u64, nfsstat3> {
        let name_str = parse_nfs_name(name)?;
        debug!("NFS LOOKUP: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(dir_handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let file_path = dir_path.join(&name_str);

        // We need to return handle, which requires self interaction (handle_map).
        // Since get_or_create_handle hits a mutex, it is blocking but fast (memory only).
        // However, crypto_fs.exists is blocking I/O.

        let exists = tokio::task::spawn_blocking(move || crypto_fs.exists(&file_path))
            .await
            .map_err(|e| {
                error!("NFS lookup task join error: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

        if exists {
            let file_path = dir_path.join(name_str);
            self.get_or_create_handle(file_path)
        } else {
            Err(nfsstat3::NFS3ERR_NOENT)
        }
    }

    async fn read(
        &self,
        handle: u64,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        debug!(
            "NFS READ: handle={}, offset={}, count={}",
            handle, offset, count
        );

        let path = self.get_path_from_handle(handle)?;

        let crypto_fs = self.crypto_fs.clone();
        tokio::task::spawn_blocking(move || {
            let metadata = crypto_fs
                .metadata(&path)
                .map_err(|e| fs_err_to_nfsstat(&e))?;

            if metadata.is_dir {
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }

            let mut file = crypto_fs
                .open_file(&path, *OpenOptions::new().read(true))
                .map_err(|e| {
                    error!("Failed to open file for read: {:?}", e);
                    fs_err_to_nfsstat(&e)
                })?;

            // Get the cleartext file size
            let file_size = file.seek(SeekFrom::End(0)).map_err(|e| {
                error!("Failed to get file size: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            file.seek(SeekFrom::Start(offset)).map_err(|e| {
                error!("Failed to seek: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            let mut buffer = vec![0u8; count as usize];
            let bytes_read = file.read(&mut buffer).map_err(|e| {
                error!("Failed to read: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            buffer.truncate(bytes_read);
            let eof = (offset + bytes_read as u64) >= file_size;

            Ok((buffer, eof))
        })
        .await
        .map_err(|e| {
            error!("NFS read task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })?
    }

    async fn write(&self, handle: u64, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        debug!(
            "NFS WRITE: handle={}, offset={}, len={}",
            handle,
            offset,
            data.len()
        );

        let path = self.get_path_from_handle(handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let data = data.to_vec(); // Need to own data to move it

        tokio::task::spawn_blocking(move || {
            let mut file = crypto_fs
                .open_file(&path, *OpenOptions::new().write(true).read(true))
                .map_err(|e| {
                    error!("Failed to open file for write: {:?}", e);
                    fs_err_to_nfsstat(&e)
                })?;

            file.seek(SeekFrom::Start(offset)).map_err(|e| {
                error!("Failed to seek: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            file.write_all(&data).map_err(|e| {
                error!("Failed to write: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            file.flush().map_err(|e| {
                error!("Failed to flush: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            // Explicitly drop the file to ensure it's closed and flushed before getting metadata
            drop(file);

            // Get metadata
            let metadata = crypto_fs
                .metadata(&path)
                .map_err(|e| fs_err_to_nfsstat(&e))?;

            Ok(NfsServer::<FS>::metadata_to_fattr3(metadata, handle))
        })
        .await
        .map_err(|e| {
            error!("NFS write task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })?
    }

    async fn create(
        &self,
        dir_handle: u64,
        name: &nfsstring,
        _sattr: sattr3,
    ) -> Result<(u64, fattr3), nfsstat3> {
        let name_str = parse_nfs_name(name)?;
        debug!("NFS CREATE: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(dir_handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let file_path = dir_path.join(&name_str);
        // Clone for spawn_blocking
        let file_path_clone = file_path.clone();

        let metadata = tokio::task::spawn_blocking(move || {
            let file = crypto_fs.create_file(&file_path_clone).map_err(|e| {
                error!("Failed to create file: {:?}", e);
                fs_err_to_nfsstat(&e)
            })?;

            // Explicitly drop the file to ensure it's closed and flushed
            drop(file);

            let mut metadata = crypto_fs
                .metadata(&file_path_clone)
                .map_err(|e| fs_err_to_nfsstat(&e))?;

            // Newly created files have 0 cleartext size even though they have encrypted headers
            metadata.len = 0;
            Ok(metadata)
        })
        .await
        .map_err(|e| {
            error!("NFS create task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })??;

        let handle = self.get_or_create_handle(file_path)?;

        Ok((
            handle,
            NfsServer::<FS>::metadata_to_fattr3(metadata, handle),
        ))
    }

    async fn create_exclusive(&self, dir_handle: u64, name: &nfsstring) -> Result<u64, nfsstat3> {
        let name_str = parse_nfs_name(name)?;
        debug!(
            "NFS CREATE_EXCLUSIVE: dir_handle={}, name={}",
            dir_handle, name_str
        );

        let dir_path = self.get_path_from_handle(dir_handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let file_path = dir_path.join(&name_str);
        // Clone for spawn_blocking
        let file_path_clone = file_path.clone();

        tokio::task::spawn_blocking(move || {
            // Note: this is a best-effort exclusive create.  The underlying
            // filesystem provider does not support O_EXCL (create_new), so
            // there is a small TOCTOU window between the exists() check and
            // the create_file() call.  This is the best we can do without
            // provider-level atomic-create support.
            if crypto_fs.exists(&file_path_clone) {
                return Err(nfsstat3::NFS3ERR_EXIST);
            }
            crypto_fs.create_file(&file_path_clone).map_err(|e| {
                error!("Failed to create file exclusively: {:?}", e);
                fs_err_to_nfsstat(&e)
            })?;
            Ok(())
        })
        .await
        .map_err(|e| {
            error!("NFS create_exclusive task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })??;

        self.get_or_create_handle(file_path)
    }

    async fn mkdir(&self, dir_handle: u64, name: &nfsstring) -> Result<(u64, fattr3), nfsstat3> {
        let name_str = parse_nfs_name(name)?;
        debug!("NFS MKDIR: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(dir_handle)?;

        let new_dir_path = dir_path.join(&name_str);
        let crypto_fs = self.crypto_fs.clone();
        let new_dir_path_clone = new_dir_path.clone();

        let metadata = tokio::task::spawn_blocking(move || {
            crypto_fs.create_dir(&new_dir_path_clone).map_err(|e| {
                error!("Failed to create directory: {:?}", e);
                fs_err_to_nfsstat(&e)
            })?;

            crypto_fs
                .metadata(&new_dir_path_clone)
                .map_err(|e| fs_err_to_nfsstat(&e))
        })
        .await
        .map_err(|e| {
            error!("NFS mkdir task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })??;

        let handle = self.get_or_create_handle(new_dir_path)?;
        Ok((
            handle,
            NfsServer::<FS>::metadata_to_fattr3(metadata, handle),
        ))
    }

    async fn symlink(
        &self,
        _dir_handle: u64,
        _name: &nfsstring,
        _link_data: &nfsstring,
        _sattr: &sattr3,
    ) -> Result<(u64, fattr3), nfsstat3> {
        // We don't support symlinks
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }

    async fn remove(&self, dir_handle: u64, name: &nfsstring) -> Result<(), nfsstat3> {
        let name_str = parse_nfs_name(name)?;
        debug!("NFS REMOVE: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(dir_handle)?;

        let file_path = dir_path.join(&name_str);
        let crypto_fs = self.crypto_fs.clone();
        let file_path_clone = file_path.clone();

        tokio::task::spawn_blocking(move || {
            // Issue #8: distinguish files from directories and call the
            // appropriate removal method.
            let metadata = crypto_fs
                .metadata(&file_path_clone)
                .map_err(|e| fs_err_to_nfsstat(&e))?;

            if metadata.is_dir {
                crypto_fs.remove_dir(&file_path_clone).map_err(|e| {
                    error!("Failed to remove directory: {:?}", e);
                    fs_err_to_nfsstat(&e)
                })
            } else {
                crypto_fs.remove_file(&file_path_clone).map_err(|e| {
                    error!("Failed to remove file: {:?}", e);
                    fs_err_to_nfsstat(&e)
                })
            }
        })
        .await
        .map_err(|e| {
            error!("NFS remove task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })??;

        self.forget_path(&file_path)?;
        Ok(())
    }

    async fn rename(
        &self,
        from_dir: u64,
        from_name: &nfsstring,
        to_dir: u64,
        to_name: &nfsstring,
    ) -> Result<(), nfsstat3> {
        let from_name_str = parse_nfs_name(from_name)?;
        let to_name_str = parse_nfs_name(to_name)?;
        debug!(
            "NFS RENAME: from_dir={}, from_name={}, to_dir={}, to_name={}",
            from_dir, from_name_str, to_dir, to_name_str
        );

        let from_dir_path = self.get_path_from_handle(from_dir)?;
        let to_dir_path = self.get_path_from_handle(to_dir)?;

        let from_path = from_dir_path.join(&from_name_str);
        let to_path = to_dir_path.join(&to_name_str);
        let crypto_fs = self.crypto_fs.clone();
        let from_path_clone = from_path.clone();
        let to_path_clone = to_path.clone();

        tokio::task::spawn_blocking(move || {
            let metadata = crypto_fs
                .metadata(&from_path_clone)
                .map_err(|e| fs_err_to_nfsstat(&e))?;

            if metadata.is_dir {
                crypto_fs.move_dir(&from_path_clone, &to_path_clone)
            } else {
                crypto_fs.move_file(&from_path_clone, &to_path_clone)
            }
            .map_err(|e| {
                error!("Failed to rename: {:?}", e);
                fs_err_to_nfsstat(&e)
            })
        })
        .await
        .map_err(|e| {
            error!("NFS rename task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })??;

        self.update_path(&from_path, to_path)?;
        Ok(())
    }

    async fn readdir(
        &self,
        handle: u64,
        cookie: u64,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        debug!(
            "NFS READDIR: handle={}, cookie={}, max_entries={}",
            handle, cookie, max_entries
        );

        let path = self.get_path_from_handle(handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let path_clone = path.clone();

        let entries = tokio::task::spawn_blocking(move || {
            crypto_fs
                .read_dir(&path_clone)
                .map_err(|e| {
                    error!("Failed to read directory: {:?}", e);
                    fs_err_to_nfsstat(&e)
                })
                .map(|iter| iter.collect::<Vec<_>>())
        })
        .await
        .map_err(|e| {
            error!("NFS readdir task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })??;

        // Issue #13: skip entries where filename_string() fails instead
        // of using unwrap_or_default().
        let mut resolved_entries: Vec<(String, fileid3, Metadata)> = Vec::new();
        for entry in entries {
            let name = match entry.filename_string() {
                Ok(n) => n,
                Err(e) => {
                    warn!("Skipping directory entry with invalid filename: {:?}", e);
                    continue;
                }
            };
            let entry_path = path.join(&name);
            let fileid = self.get_or_create_handle(entry_path)? as fileid3;
            resolved_entries.push((name, fileid, entry.metadata));
        }

        resolved_entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut dirlist_with_meta = Vec::new();
        let mut found_start = cookie == 0;
        let mut has_more = false;

        for (name, fileid, metadata) in resolved_entries {
            if !found_start {
                if fileid == cookie {
                    found_start = true;
                }
                continue;
            }

            if dirlist_with_meta.len() >= max_entries {
                has_more = true;
                break;
            }

            dirlist_with_meta.push(DirEntry {
                fileid,
                name: nfsstring::from(name.into_bytes()),
                attr: NfsServer::<FS>::metadata_to_fattr3(metadata, fileid),
            });
        }

        // Signal EOF when either:
        //   (a) we filled max_entries and there are no more entries after them
        //       (`has_more` is false), or
        //   (b) the cookie fileid was not found in the current listing.
        //
        // Case (b) occurs when the file that the client last saw (identified
        // by `cookie`) was deleted between two READDIR calls.  Without this
        // guard the loop above exhausts all entries with `found_start` still
        // false, returns an empty page with `end: false`, and the NFS client
        // retries indefinitely -- a liveness failure.  Returning `end: true`
        // here tells the client to treat the listing as complete, which is the
        // least-surprising recovery for a stale cursor.
        let end = !has_more || !found_start;
        Ok(ReadDirResult {
            entries: dirlist_with_meta,
            end,
        })
    }

    async fn readlink(&self, _handle: u64) -> Result<nfsstring, nfsstat3> {
        // We don't support symlinks
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }
}
