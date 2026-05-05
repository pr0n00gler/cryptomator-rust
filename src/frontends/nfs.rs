use crate::cryptofs::{
    CryptoFs, CryptoFsFile, File as CryptoFile, FileSystem, FileSystemError, Metadata, OpenOptions,
};
use async_trait::async_trait;
use nfsserve::nfs::{
    fattr3, fileid3, ftype3, nfsstat3, nfsstring, nfstime3, sattr3, set_size3, specdata3,
};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::UNIX_EPOCH;
use tracing::{debug, error, warn};

type CachedFile = (u64, Arc<Mutex<CryptoFsFile>>);

/// Maximum number of file handles the NFS server will track before
/// evicting the least-recently-used entries. The root handle (1)
/// is never evicted.
const DEFAULT_MAX_HANDLES: usize = 10_000;

/// Hard limit on the number of directory entries returned in a single
/// READDIR response.  Prevents malicious or buggy clients from asking
/// for millions of entries at once and forcing unbounded allocations.
const MAX_READDIR_ENTRIES_PER_CALL: usize = 4_096;

/// Maximum bytes returned by a single NFS READ RPC.
const MAX_NFS_READ_BYTES: usize = 1024 * 1024;

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

fn fsync_cached_files(files: Vec<CachedFile>) -> Result<(), nfsstat3> {
    let mut first_error = None;

    for (handle, file) in files {
        match file.lock() {
            Ok(mut guard) => {
                if let Err(e) = guard.fsync() {
                    error!("Failed to fsync cached file handle {}: {:?}", handle, e);
                    first_error.get_or_insert(nfsstat3::NFS3ERR_IO);
                }
            }
            Err(e) => {
                warn!(
                    "File mutex poisoned while closing handle {}, data may be lost: {}",
                    handle, e
                );
                first_error.get_or_insert(nfsstat3::NFS3ERR_IO);
            }
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
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
/// the least-recently-used entry is evicted from both maps.
struct HandleState {
    path_to_handle: HashMap<PathBuf, u64>,
    handle_to_path: HashMap<u64, PathBuf>,
    /// Tracks the last-access order of each handle for LRU eviction.
    /// Maps handle -> access sequence number.
    handle_order: HashMap<u64, u64>,
    /// Reverse mapping: order -> handle for O(log n) min lookup during eviction.
    order_to_handle: BTreeMap<u64, u64>,
    /// Monotonically increasing sequence number for access ordering.
    next_order: u64,
    /// Maximum number of non-root entries.
    max_capacity: usize,
    /// Monotonically increasing counter; starts at 2 (1 is reserved for root).
    next_handle: u64,
    /// Persistent open file handles keyed by handle id.  Each entry is
    /// protected by its own mutex so that concurrent NFS RPCs to the same
    /// file are serialised, while RPCs to different files proceed in
    /// parallel.
    open_files: HashMap<u64, Arc<Mutex<CryptoFsFile>>>,
    /// Per-file locks to coordinate writes and truncation.  WRITE
    /// operations hold a read lock, while setattr truncation holds a
    /// write lock.  This ensures truncation waits for in-flight writes
    /// to complete.
    file_locks: HashMap<u64, Arc<RwLock<()>>>,
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
            handle_order: HashMap::new(),
            order_to_handle: BTreeMap::new(),
            next_order: 0,
            max_capacity,
            next_handle: 2,
            open_files: HashMap::new(),
            file_locks: HashMap::new(),
        }
    }

    /// Evict the least-recently-used non-root entry if at capacity.
    fn evict_if_needed(&mut self) -> Vec<CachedFile> {
        let mut evicted_files = Vec::new();
        // Non-root entry count: subtract 1 for the root entry.
        while self.path_to_handle.len().saturating_sub(1) >= self.max_capacity {
            // Find the handle with the lowest order number (least recently used)
            // via O(log n) BTreeMap lookup instead of O(n) scan.
            let (&oldest_order, &old_handle) = match self.order_to_handle.iter().next() {
                Some(entry) => entry,
                None => break,
            };

            self.handle_order.remove(&old_handle);
            self.order_to_handle.remove(&oldest_order);

            if let Some(file) = self.open_files.remove(&old_handle) {
                evicted_files.push((old_handle, file));
            }
            self.file_locks.remove(&old_handle);
            if let Some(old_path) = self.handle_to_path.remove(&old_handle) {
                self.path_to_handle.remove(&old_path);
            }
        }
        evicted_files
    }

    fn touch(&mut self, handle: u64) {
        if let Some(old_order) = self.handle_order.remove(&handle) {
            self.order_to_handle.remove(&old_order);
            let order = self.next_order;
            self.next_order = self.next_order.wrapping_add(1);
            self.handle_order.insert(handle, order);
            self.order_to_handle.insert(order, handle);
        }
    }

    /// Returns the existing handle for `path`, or allocates a new one.
    ///
    /// Because both the lookup and the insertion happen inside a single
    /// `MutexGuard` scope, there is no window for a concurrent caller to
    /// allocate a second handle for the same path.
    fn get_or_create(&mut self, path: PathBuf) -> Result<(u64, Vec<CachedFile>), nfsstat3> {
        if let Some(&handle) = self.path_to_handle.get(&path) {
            self.touch(handle);
            return Ok((handle, Vec::new()));
        }

        // Evict least-recently-used entries if at capacity.
        let evicted_files = self.evict_if_needed();

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
        let order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        self.handle_order.insert(handle, order);
        self.order_to_handle.insert(order, handle);
        Ok((handle, evicted_files))
    }

    /// Returns the handle for `path` if one already exists, without
    /// allocating a new handle.  Used for read-only lookups (e.g. skipped
    /// entries during NFS pagination).
    fn get(&self, path: &Path) -> Option<u64> {
        self.path_to_handle.get(path).copied()
    }

    fn get_path_and_touch(&mut self, handle: u64) -> Result<PathBuf, nfsstat3> {
        let path = self
            .handle_to_path
            .get(&handle)
            .cloned()
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        self.touch(handle);
        Ok(path)
    }

    fn forget_handle(&mut self, handle: u64) -> Option<CachedFile> {
        if let Some(path) = self.handle_to_path.remove(&handle) {
            self.path_to_handle.remove(&path);
        }
        if let Some(order) = self.handle_order.remove(&handle) {
            self.order_to_handle.remove(&order);
        }
        self.file_locks.remove(&handle);
        self.open_files.remove(&handle).map(|file| (handle, file))
    }

    fn forget_prefix(&mut self, path_prefix: &PathBuf) -> Vec<CachedFile> {
        let handles: Vec<u64> = self
            .path_to_handle
            .iter()
            .filter(|(path, _)| path.starts_with(path_prefix))
            .map(|(_, &handle)| handle)
            .collect();

        handles
            .into_iter()
            .filter_map(|handle| self.forget_handle(handle))
            .collect()
    }

    /// Returns the current number of non-root entries tracked.
    fn len(&self) -> usize {
        // path_to_handle includes the root entry; subtract 1.
        self.path_to_handle.len().saturating_sub(1)
    }

    /// Atomically re-keys every path that starts with `old_path` to be rooted
    /// at `new_path` instead, updating both maps in the same lock scope.
    ///
    /// Also closes any cached open file handles for the affected entries,
    /// since the underlying file paths have changed.
    fn rename_prefix(&mut self, old_path: &PathBuf, new_path: PathBuf) -> Vec<CachedFile> {
        let updates: Vec<(PathBuf, PathBuf, u64)> = self
            .path_to_handle
            .iter()
            .filter(|(path, _)| path.starts_with(old_path))
            .map(|(path, &handle)| {
                let suffix = path.strip_prefix(old_path).unwrap_or(path.as_path());
                (path.clone(), new_path.join(suffix), handle)
            })
            .collect();

        let mut closed_files = Vec::new();
        for (old, new, handle) in updates {
            self.path_to_handle.remove(&old);
            self.path_to_handle.insert(new.clone(), handle);
            self.handle_to_path.insert(handle, new);
            // Close cached file handle since the underlying path changed.
            // Also drop the per-file lock since it's tied to the old path.
            self.file_locks.remove(&handle);
            if let Some(file) = self.open_files.remove(&handle) {
                closed_files.push((handle, file));
            }
        }
        closed_files
    }
}

pub struct NfsServer<FS: FileSystem> {
    crypto_fs: CryptoFs<FS>,
    handles: Arc<Mutex<HandleState>>,
    /// Semaphore that limits the number of concurrent NFS operations.
    conn_semaphore: Arc<tokio::sync::Semaphore>,
}

impl<FS: FileSystem + 'static> NfsServer<FS> {
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

    fn acquire_operation_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, nfsstat3> {
        self.conn_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| nfsstat3::NFS3ERR_JUKEBOX)
    }

    fn get_or_create_handle(&self, path: PathBuf) -> Result<u64, nfsstat3> {
        let (handle, evicted_files) = self
            .handles
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .get_or_create(path)?;
        fsync_cached_files(evicted_files)?;
        Ok(handle)
    }

    fn get_path_from_handle(&self, handle: u64) -> Result<PathBuf, nfsstat3> {
        self.handles
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .get_path_and_touch(handle)
    }

    fn forget_subtree(&self, path: &PathBuf) -> Result<(), nfsstat3> {
        let closed_files = self
            .handles
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .forget_prefix(path);
        fsync_cached_files(closed_files)?;
        Ok(())
    }

    fn update_path(&self, old_path: &PathBuf, new_path: PathBuf) -> Result<(), nfsstat3> {
        let closed_files = self
            .handles
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .rename_prefix(old_path, new_path);
        fsync_cached_files(closed_files)?;
        Ok(())
    }

    /// Returns the per-file RwLock for the given handle, creating one if
    /// it does not exist yet.
    fn get_file_lock(&self, handle: u64) -> Result<Arc<RwLock<()>>, nfsstat3> {
        let mut state = self.handles.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let lock = state
            .file_locks
            .entry(handle)
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone();
        Ok(lock)
    }

    /// Closes the cached file handle for the given path, if one exists.
    fn close_cached_file_by_path(&self, path: &PathBuf) -> Result<(), nfsstat3> {
        let closed_file = {
            let mut state = self.handles.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
            state
                .path_to_handle
                .get(path)
                .copied()
                .and_then(|handle| state.open_files.remove(&handle).map(|file| (handle, file)))
        };
        fsync_cached_files(closed_file.into_iter().collect())?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn handle_count(&self) -> Result<usize, nfsstat3> {
        Ok(self.handles.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?.len())
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
        let _permit = self.acquire_operation_permit()?;
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
        let _permit = self.acquire_operation_permit()?;
        debug!("NFS SETATTR: handle={}, sattr={:?}", handle, sattr);

        let path = self.get_path_from_handle(handle)?;

        // Handle set_size (file truncation or extension).
        if let set_size3::size(new_size) = sattr.size {
            const MAX_TRUNCATE_EXTENSION: u64 = 64 << 20; // 64 MiB

            let file_lock = self.get_file_lock(handle)?;

            let crypto_fs = self.crypto_fs.clone();
            let path_clone = path.clone();
            let handles_clone = Arc::clone(&self.handles);
            let result_metadata = tokio::task::spawn_blocking(move || {
                // Fetch metadata once and reuse it for all checks.
                let metadata = crypto_fs
                    .metadata(&path_clone)
                    .map_err(|e| fs_err_to_nfsstat(&e))?;

                if metadata.is_dir {
                    return Err(nfsstat3::NFS3ERR_ISDIR);
                }

                if new_size > metadata.len && new_size - metadata.len > MAX_TRUNCATE_EXTENSION {
                    return Err(nfsstat3::NFS3ERR_FBIG);
                }

                if new_size == metadata.len {
                    return Ok(Some(metadata));
                }

                let _wguard = file_lock.write().map_err(|_| nfsstat3::NFS3ERR_IO)?;
                let closed_file = {
                    let mut state = handles_clone.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
                    state
                        .open_files
                        .remove(&handle)
                        .map(|file| vec![(handle, file)])
                        .unwrap_or_default()
                };
                fsync_cached_files(closed_file)?;

                crypto_fs
                    .truncate_file(&path_clone, new_size)
                    .map_err(|e| {
                        error!("Failed to resize file via truncate_file: {:?}", e);
                        fs_err_to_nfsstat(&e)
                    })?;

                let fresh_metadata = crypto_fs
                    .metadata(&path_clone)
                    .map_err(|e| fs_err_to_nfsstat(&e))?;
                Ok(Some(fresh_metadata))
            })
            .await
            .map_err(|e| {
                error!("NFS setattr task join error: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })??;

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

            if let Some(m) = result_metadata {
                return Ok(NfsServer::<FS>::metadata_to_fattr3(m, handle));
            }
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

        // No size change requested; fetch metadata once.
        let crypto_fs = self.crypto_fs.clone();
        tokio::task::spawn_blocking(move || {
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
        let _permit = self.acquire_operation_permit()?;
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
        let _permit = self.acquire_operation_permit()?;
        debug!(
            "NFS READ: handle={}, offset={}, count={}",
            handle, offset, count
        );

        let path = self.get_path_from_handle(handle)?;

        let file_lock = self.get_file_lock(handle)?;
        let crypto_fs = self.crypto_fs.clone();
        let handles = Arc::clone(&self.handles);

        tokio::task::spawn_blocking(move || {
            // Check if this is a directory first (directories are never cached).
            let metadata = crypto_fs
                .metadata(&path)
                .map_err(|e| fs_err_to_nfsstat(&e))?;
            if metadata.is_dir {
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }

            // Open or retrieve the persistent file handle inside the blocking
            // context, after confirming the path is not a directory.
            let file = {
                let mut state = handles.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
                if let Some(f) = state.open_files.get(&handle) {
                    Arc::clone(f)
                } else {
                    let f = crypto_fs
                        .open_file(&path, *OpenOptions::new().read(true).write(true))
                        .map_err(|e| {
                            error!("Failed to open persistent file handle: {:?}", e);
                            fs_err_to_nfsstat(&e)
                        })?;
                    let arc = Arc::new(Mutex::new(f));
                    state.open_files.insert(handle, Arc::clone(&arc));
                    arc
                }
            };

            // Acquire shared lock so reads do not proceed during truncation.
            let _rguard = file_lock.read().map_err(|_| nfsstat3::NFS3ERR_IO)?;

            let mut guard = file.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;

            // Get the cleartext file size
            let file_size = guard.seek(SeekFrom::End(0)).map_err(|e| {
                error!("Failed to get file size: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            guard.seek(SeekFrom::Start(offset)).map_err(|e| {
                error!("Failed to seek: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            let read_count = (count as usize).min(MAX_NFS_READ_BYTES);
            let mut buffer = vec![0u8; read_count];
            let bytes_read = guard.read(&mut buffer).map_err(|e| {
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
        let _permit = self.acquire_operation_permit()?;
        debug!(
            "NFS WRITE: handle={}, offset={}, len={}",
            handle,
            offset,
            data.len()
        );

        let path = self.get_path_from_handle(handle)?;

        let file_lock = self.get_file_lock(handle)?;
        let data = data.to_vec(); // Need to own data to move it
        let crypto_fs = self.crypto_fs.clone();
        let handles = Arc::clone(&self.handles);

        tokio::task::spawn_blocking(move || {
            // Check if this is a directory first.
            let metadata = crypto_fs
                .metadata(&path)
                .map_err(|e| fs_err_to_nfsstat(&e))?;
            if metadata.is_dir {
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }

            // Open or retrieve the persistent file handle inside the blocking
            // context, after confirming the path is not a directory.
            let file = {
                let mut state = handles.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
                if let Some(f) = state.open_files.get(&handle) {
                    Arc::clone(f)
                } else {
                    let f = crypto_fs
                        .open_file(&path, *OpenOptions::new().read(true).write(true))
                        .map_err(|e| {
                            error!("Failed to open persistent file handle: {:?}", e);
                            fs_err_to_nfsstat(&e)
                        })?;
                    let arc = Arc::new(Mutex::new(f));
                    state.open_files.insert(handle, Arc::clone(&arc));
                    arc
                }
            };

            // Acquire shared (read) lock so that truncation waits for us
            // to finish before deleting and recreating the file.
            let _rguard = file_lock.read().map_err(|_| nfsstat3::NFS3ERR_IO)?;

            let mut guard = file.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;

            guard.seek(SeekFrom::Start(offset)).map_err(|e| {
                error!("Failed to seek: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            guard.write_all(&data).map_err(|e| {
                error!("Failed to write: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            // Flush userspace buffers and fsync to persistent storage.
            guard.fsync().map_err(|e| {
                error!("Failed to fsync: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            // Get metadata from the open file handle (avoids stale data).
            let metadata = CryptoFile::metadata(&*guard).map_err(|e| {
                error!("Failed to get metadata after write: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

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
        let _permit = self.acquire_operation_permit()?;
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
        let _permit = self.acquire_operation_permit()?;
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
        let _permit = self.acquire_operation_permit()?;
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
        let _permit = self.acquire_operation_permit()?;
        // We don't support symlinks
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }

    async fn remove(&self, dir_handle: u64, name: &nfsstring) -> Result<(), nfsstat3> {
        let _permit = self.acquire_operation_permit()?;
        let name_str = parse_nfs_name(name)?;
        debug!("NFS REMOVE: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(dir_handle)?;

        let file_path = dir_path.join(&name_str);

        // Close any cached file handle before removing the file so that
        // the underlying CryptoFsFile is flushed and dropped first.
        self.close_cached_file_by_path(&file_path)?;

        let crypto_fs = self.crypto_fs.clone();
        let file_path_clone = file_path.clone();

        tokio::task::spawn_blocking(move || {
            let metadata = crypto_fs
                .metadata(&file_path_clone)
                .map_err(|e| fs_err_to_nfsstat(&e))?;

            if metadata.is_dir {
                let mut entries = crypto_fs.read_dir_fallible(&file_path_clone).map_err(|e| {
                    error!("Failed to read directory before remove: {:?}", e);
                    fs_err_to_nfsstat(&e)
                })?;
                if entries
                    .next()
                    .transpose()
                    .map_err(|e| {
                        error!("Failed to decode directory entry before remove: {:?}", e);
                        fs_err_to_nfsstat(&e)
                    })?
                    .is_some()
                {
                    return Err(nfsstat3::NFS3ERR_NOTEMPTY);
                }
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

        self.forget_subtree(&file_path)?;
        Ok(())
    }

    async fn rename(
        &self,
        from_dir: u64,
        from_name: &nfsstring,
        to_dir: u64,
        to_name: &nfsstring,
    ) -> Result<(), nfsstat3> {
        let _permit = self.acquire_operation_permit()?;
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

        // Close cached file handles for both source and destination before
        // renaming so that no stale handle outlives the rename.
        self.close_cached_file_by_path(&from_path)?;
        self.close_cached_file_by_path(&to_path)?;

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

        self.forget_subtree(&to_path)?;
        self.update_path(&from_path, to_path)?;
        Ok(())
    }

    async fn readdir(
        &self,
        handle: u64,
        cookie: u64,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let _permit = self.acquire_operation_permit()?;
        debug!(
            "NFS READDIR: handle={}, cookie={}, max_entries={}",
            handle, cookie, max_entries
        );

        let path = self.get_path_from_handle(handle)?;

        // Issue 2: short-circuit when the client asks for zero entries.
        if max_entries == 0 {
            return Ok(ReadDirResult {
                entries: vec![],
                end: false,
            });
        }

        let crypto_fs = self.crypto_fs.clone();
        let handles = Arc::clone(&self.handles);

        let entry_limit = max_entries.min(MAX_READDIR_ENTRIES_PER_CALL);

        tokio::task::spawn_blocking(move || -> Result<ReadDirResult, nfsstat3> {
            let entries_iter = crypto_fs.read_dir_fallible(&path).map_err(|e| {
                error!("Failed to read directory: {:?}", e);
                fs_err_to_nfsstat(&e)
            })?;

            // Issue 1: Collect and sort entries alphabetically so that NFS
            // pagination cookies yield deterministic results across calls.
            let mut all_entries = Vec::new();
            for entry in entries_iter {
                let entry = entry.map_err(|e| {
                    error!("Failed to decode directory entry: {:?}", e);
                    fs_err_to_nfsstat(&e)
                })?;
                let name = entry.filename_string().map_err(|e| {
                    error!("Failed to decode directory entry filename: {:?}", e);
                    nfsstat3::NFS3ERR_IO
                })?;
                all_entries.push((name, entry.metadata));
            }
            all_entries.sort_by(|(a, _), (b, _)| a.cmp(b));

            let mut collected = Vec::with_capacity(entry_limit);
            let mut start_seen = cookie == 0;
            let mut has_more = false;

            for (name, metadata) in all_entries {
                let full_path = path.join(&name);

                if !start_seen {
                    // Issue 5: For entries before the cookie, use a read-only
                    // lookup to avoid permanently allocating handles for entries
                    // the client already saw.
                    let existing_handle = {
                        let state = handles.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
                        state.get(&full_path)
                    };
                    if let Some(h) = existing_handle {
                        if h == cookie {
                            start_seen = true;
                        }
                    }
                    continue;
                }

                if collected.len() >= entry_limit {
                    has_more = true;
                    break;
                }

                let (handle_id, evicted_files) = {
                    let mut state = handles.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
                    state.get_or_create(full_path)?
                };
                fsync_cached_files(evicted_files)?;

                collected.push(DirEntry {
                    fileid: handle_id as fileid3,
                    name: nfsstring::from(name.into_bytes()),
                    attr: NfsServer::<FS>::metadata_to_fattr3(metadata, handle_id),
                });
            }

            let end = if !start_seen { true } else { !has_more };
            Ok(ReadDirResult {
                entries: collected,
                end,
            })
        })
        .await
        .map_err(|e| {
            error!("NFS readdir task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })?
    }

    async fn readlink(&self, _handle: u64) -> Result<nfsstring, nfsstat3> {
        let _permit = self.acquire_operation_permit()?;
        // We don't support symlinks
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }
}
