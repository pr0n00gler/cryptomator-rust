use crate::cryptofs::{CryptoFs, FileSystem, Metadata, OpenOptions};
use async_trait::async_trait;
use nfsserve::nfs::{fattr3, fileid3, ftype3, nfsstat3, nfsstring, nfstime3, sattr3, specdata3};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;
use tracing::{debug, error};

pub struct NfsServer<FS: FileSystem> {
    crypto_fs: CryptoFs<FS>,
    handle_to_path: Arc<Mutex<HashMap<u64, PathBuf>>>,
    path_to_handle: Arc<Mutex<HashMap<PathBuf, u64>>>,
    next_handle: Arc<Mutex<u64>>,
}

impl<FS: FileSystem> NfsServer<FS> {
    pub fn new(crypto_fs: CryptoFs<FS>) -> Self {
        let mut handle_to_path = HashMap::new();
        let mut path_to_handle = HashMap::new();
        let root = PathBuf::from("/");
        handle_to_path.insert(1, root.clone());
        path_to_handle.insert(root, 1);

        NfsServer {
            crypto_fs,
            handle_to_path: Arc::new(Mutex::new(handle_to_path)),
            path_to_handle: Arc::new(Mutex::new(path_to_handle)),
            next_handle: Arc::new(Mutex::new(2)),
        }
    }

    fn get_or_create_handle(&self, path: PathBuf) -> Result<u64, nfsstat3> {
        let mut path_to_handle = self
            .path_to_handle
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        if let Some(&handle) = path_to_handle.get(&path) {
            return Ok(handle);
        }

        let mut next_handle = self.next_handle.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let mut handle_to_path = self
            .handle_to_path
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;

        let handle = *next_handle;
        *next_handle += 1;
        path_to_handle.insert(path.clone(), handle);
        handle_to_path.insert(handle, path);
        Ok(handle)
    }

    fn get_path_from_handle(&self, handle: &u64) -> Result<PathBuf, nfsstat3> {
        let handle_to_path = self
            .handle_to_path
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        handle_to_path
            .get(handle)
            .cloned()
            .ok_or(nfsstat3::NFS3ERR_STALE)
    }

    fn forget_path(&self, path: &PathBuf) -> Result<(), nfsstat3> {
        let mut path_to_handle = self
            .path_to_handle
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let mut handle_to_path = self
            .handle_to_path
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        if let Some(handle) = path_to_handle.remove(path) {
            handle_to_path.remove(&handle);
        }
        Ok(())
    }

    fn update_path(&self, old_path: &PathBuf, new_path: PathBuf) -> Result<(), nfsstat3> {
        let mut path_to_handle = self
            .path_to_handle
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let mut handle_to_path = self
            .handle_to_path
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;

        let mut updates = Vec::new();
        for (path, handle) in path_to_handle.iter() {
            if path.starts_with(old_path) {
                let suffix = path.strip_prefix(old_path).unwrap_or(path.as_path());
                let updated = new_path.join(suffix);
                updates.push((path.clone(), updated, *handle));
            }
        }

        for (old, new, handle) in updates {
            path_to_handle.remove(&old);
            path_to_handle.insert(new.clone(), handle);
            handle_to_path.insert(handle, new);
        }
        Ok(())
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

        fattr3 {
            ftype: if metadata.is_dir {
                ftype3::NF3DIR
            } else {
                ftype3::NF3REG
            },
            mode,
            nlink: 1,
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
                seconds: atime.as_secs() as u32,
                nseconds: atime.subsec_nanos(),
            },
            mtime: nfstime3 {
                seconds: mtime.as_secs() as u32,
                nseconds: mtime.subsec_nanos(),
            },
            ctime: nfstime3 {
                seconds: ctime.as_secs() as u32,
                nseconds: ctime.subsec_nanos(),
            },
        }
    }

    #[allow(dead_code)]
    fn apply_sattr3(&self, _metadata: &mut Metadata, _sattr: &sattr3) {
        // For now, we ignore attribute changes
        // In a full implementation, we would apply mode, uid, gid, size, and time changes
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

        let path = self.get_path_from_handle(&handle)?;

        let crypto_fs = self.crypto_fs.clone();
        tokio::task::spawn_blocking(move || {
            let metadata = crypto_fs
                .metadata(&path)
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;

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

        let path = self.get_path_from_handle(&handle)?;

        let crypto_fs = self.crypto_fs.clone();
        tokio::task::spawn_blocking(move || {
            match crypto_fs.metadata(&path) {
                Ok(metadata) => {
                    // In a full implementation, we would apply mode, uid, gid, size, and time changes
                    // For now, we ignore attribute changes
                    // self.apply_sattr3(&mut metadata, &sattr);
                    Ok(NfsServer::<FS>::metadata_to_fattr3(metadata, handle))
                }
                Err(_) => Err(nfsstat3::NFS3ERR_IO),
            }
        })
        .await
        .map_err(|e| {
            error!("NFS setattr task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })?
    }

    async fn lookup(&self, dir_handle: u64, name: &nfsstring) -> Result<u64, nfsstat3> {
        let name_str = String::from_utf8_lossy(name).to_string(); // Clone to move into block
        debug!("NFS LOOKUP: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(&dir_handle)?;

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

        let path = self.get_path_from_handle(&handle)?;

        let crypto_fs = self.crypto_fs.clone();
        tokio::task::spawn_blocking(move || {
            let metadata = crypto_fs
                .metadata(&path)
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;

            if metadata.is_dir {
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }

            let mut file = crypto_fs
                .open_file(&path, *OpenOptions::new().read(true))
                .map_err(|e| {
                    error!("Failed to open file for read: {:?}", e);
                    nfsstat3::NFS3ERR_IO
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

        let path = self.get_path_from_handle(&handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let data = data.to_vec(); // Need to own data to move it

        tokio::task::spawn_blocking(move || {
            let mut file = crypto_fs
                .open_file(&path, *OpenOptions::new().write(true).read(true))
                .map_err(|e| {
                    error!("Failed to open file for write: {:?}", e);
                    nfsstat3::NFS3ERR_IO
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
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;

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
        let name_str = String::from_utf8_lossy(name).to_string();
        debug!("NFS CREATE: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(&dir_handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let file_path = dir_path.join(&name_str);
        // Clone for spawn_blocking
        let file_path_clone = file_path.clone();

        let metadata = tokio::task::spawn_blocking(move || {
            let file = crypto_fs.create_file(&file_path_clone).map_err(|e| {
                error!("Failed to create file: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            // Explicitly drop the file to ensure it's closed and flushed
            drop(file);

            let mut metadata = crypto_fs
                .metadata(&file_path_clone)
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;

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
        let name_str = String::from_utf8_lossy(name).to_string();
        debug!(
            "NFS CREATE_EXCLUSIVE: dir_handle={}, name={}",
            dir_handle, name_str
        );

        let dir_path = self.get_path_from_handle(&dir_handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let file_path = dir_path.join(&name_str);
        // Clone for spawn_blocking
        let file_path_clone = file_path.clone();

        tokio::task::spawn_blocking(move || {
            if crypto_fs.exists(&file_path_clone) {
                return Err(nfsstat3::NFS3ERR_EXIST);
            }

            crypto_fs.create_file(&file_path_clone).map_err(|e| {
                error!("Failed to create file exclusively: {:?}", e);
                nfsstat3::NFS3ERR_IO
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
        let name_str = String::from_utf8_lossy(name).to_string();
        debug!("NFS MKDIR: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(&dir_handle)?;

        let new_dir_path = dir_path.join(&name_str);
        let crypto_fs = self.crypto_fs.clone();
        let new_dir_path_clone = new_dir_path.clone();

        let metadata = tokio::task::spawn_blocking(move || {
            crypto_fs.create_dir(&new_dir_path_clone).map_err(|e| {
                error!("Failed to create directory: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })?;

            crypto_fs
                .metadata(&new_dir_path_clone)
                .map_err(|_| nfsstat3::NFS3ERR_IO)
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
        let name_str = String::from_utf8_lossy(name).to_string();
        debug!("NFS REMOVE: dir_handle={}, name={}", dir_handle, name_str);

        let dir_path = self.get_path_from_handle(&dir_handle)?;

        let file_path = dir_path.join(&name_str);
        let crypto_fs = self.crypto_fs.clone();
        let file_path_clone = file_path.clone();

        tokio::task::spawn_blocking(move || {
            crypto_fs.remove_file(&file_path_clone).map_err(|e| {
                error!("Failed to remove file: {:?}", e);
                nfsstat3::NFS3ERR_IO
            })
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
        let from_name_str = String::from_utf8_lossy(from_name).to_string();
        let to_name_str = String::from_utf8_lossy(to_name).to_string();
        debug!(
            "NFS RENAME: from_dir={}, from_name={}, to_dir={}, to_name={}",
            from_dir, from_name_str, to_dir, to_name_str
        );

        let from_dir_path = self.get_path_from_handle(&from_dir)?;
        let to_dir_path = self.get_path_from_handle(&to_dir)?;

        let from_path = from_dir_path.join(&from_name_str);
        let to_path = to_dir_path.join(&to_name_str);
        let crypto_fs = self.crypto_fs.clone();
        let from_path_clone = from_path.clone();
        let to_path_clone = to_path.clone();

        tokio::task::spawn_blocking(move || {
            let metadata = crypto_fs
                .metadata(&from_path_clone)
                .map_err(|_| nfsstat3::NFS3ERR_NOENT)?;

            if metadata.is_dir {
                crypto_fs.move_dir(&from_path_clone, &to_path_clone)
            } else {
                crypto_fs.move_file(&from_path_clone, &to_path_clone)
            }
            .map_err(|e| {
                error!("Failed to rename: {:?}", e);
                nfsstat3::NFS3ERR_IO
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

        let path = self.get_path_from_handle(&handle)?;

        let crypto_fs = self.crypto_fs.clone();
        let path_clone = path.clone();

        let entries = tokio::task::spawn_blocking(move || {
            crypto_fs
                .read_dir(&path_clone)
                .map_err(|e| {
                    error!("Failed to read directory: {:?}", e);
                    nfsstat3::NFS3ERR_IO
                })
                .map(|iter| iter.collect::<Vec<_>>())
        })
        .await
        .map_err(|e| {
            error!("NFS readdir task join error: {:?}", e);
            nfsstat3::NFS3ERR_IO
        })??;

        let mut resolved_entries: Vec<(String, fileid3, Metadata)> = entries
            .into_iter()
            .map(|entry| {
                let name = entry.filename_string().unwrap_or_default();
                let entry_path = path.join(&name);
                let fileid = self.get_or_create_handle(entry_path)? as fileid3;
                Ok((name, fileid, entry.metadata))
            })
            .collect::<Result<Vec<_>, nfsstat3>>()?;

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

        Ok(ReadDirResult {
            entries: dirlist_with_meta,
            end: !has_more,
        })
    }

    async fn readlink(&self, _handle: u64) -> Result<nfsstring, nfsstat3> {
        // We don't support symlinks
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }
}
