use crate::crypto::CryptoError;
use crate::cryptofs::{
    CryptoFs, DirEntry, File, FileSystem, FileSystemError, Metadata,
    OpenOptions as cryptoOpenOptions,
};
use bytes::{Buf, Bytes};
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsResult, FsStream,
    OpenOptions, ReadDirMeta,
};
use futures::{StreamExt, future, future::FutureExt};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{debug, error, info, instrument, warn};

fn map_io_error(e: &std::io::Error) -> FsError {
    match e.kind() {
        ErrorKind::NotFound => FsError::NotFound,
        ErrorKind::AlreadyExists => FsError::Exists,
        ErrorKind::PermissionDenied => FsError::Forbidden,
        _ => FsError::GeneralFailure,
    }
}

impl From<FileSystemError> for FsError {
    fn from(fse: FileSystemError) -> Self {
        match fse {
            FileSystemError::PathDoesNotExist(_) => FsError::NotFound,
            FileSystemError::CryptoError(CryptoError::IoError(ref i)) => {
                let res = map_io_error(i);
                if res == FsError::GeneralFailure {
                    error!("WebDAV IO error (crypto): {:?}", i);
                }
                res
            }
            FileSystemError::IoError(ref s) => {
                let res = map_io_error(s);
                if res == FsError::GeneralFailure {
                    error!("WebDAV IO error: {:?}", s);
                }
                res
            }
            FileSystemError::InvalidPathError(_) => FsError::Forbidden,
            e => {
                error!("WebDAV filesystem error: {:?}", e);
                FsError::GeneralFailure
            }
        }
    }
}

impl DavDirEntry for DirEntry {
    fn name(&self) -> Vec<u8> {
        Vec::from(self.file_name.to_str().unwrap_or_default())
    }

    fn metadata(&self) -> FsFuture<Box<dyn DavMetaData>> {
        Box::pin(future::ok(Box::new(self.metadata) as Box<dyn DavMetaData>))
    }
}

impl DavMetaData for Metadata {
    fn len(&self) -> u64 {
        self.len
    }

    fn modified(&self) -> FsResult<SystemTime> {
        Ok(self.modified)
    }

    fn is_dir(&self) -> bool {
        self.is_dir
    }

    fn accessed(&self) -> FsResult<SystemTime> {
        Ok(self.accessed)
    }

    fn created(&self) -> FsResult<SystemTime> {
        Ok(self.created)
    }
}

#[derive(Debug, Clone)]
struct DFile {
    crypto_fs_file: Arc<Mutex<Box<dyn File>>>,
}

impl DFile {
    fn new(f: Box<dyn File>) -> DFile {
        DFile {
            crypto_fs_file: Arc::new(Mutex::new(f)),
        }
    }
}

impl Drop for DFile {
    fn drop(&mut self) {
        // Try to flush any pending data on drop to prevent data loss.
        // Errors during drop are logged but cannot be propagated.
        if let Ok(mut guard) = self.crypto_fs_file.lock() {
            if let Err(e) = guard.flush() {
                error!("WebDAV DFile drop flush error: {:?}", e);
            }
        }
    }
}

impl DavFile for DFile {
    #[instrument(skip(self))]
    fn metadata(&mut self) -> FsFuture<Box<dyn DavMetaData>> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let guard = crypto_fs_file.lock().map_err(|_| FsError::GeneralFailure)?;
                let metadata = guard.metadata().map_err(|e| {
                    error!("WebDAV metadata error: {:?}", e);
                    FsError::GeneralFailure
                })?;

                Ok(Box::new(metadata) as Box<dyn DavMetaData>)
            })
            .await
            .map_err(|e| {
                error!("WebDAV metadata join error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self, buf))]
    fn write_buf(&mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut guard = crypto_fs_file.lock().map_err(|_| FsError::GeneralFailure)?;
                while buf.has_remaining() {
                    let chunk = buf.chunk();
                    debug!("WebDAV write_buf: {} bytes", chunk.len());
                    guard.write_all(chunk).map_err(|e| {
                        error!("WebDAV write_buf error: {:?}", e);
                        FsError::GeneralFailure
                    })?;
                    let len = chunk.len();
                    buf.advance(len);
                }
                Ok(())
            })
            .await
            .map_err(|e| {
                error!("WebDAV write_buf join error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self, buf), fields(len = buf.len()))]
    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<()> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                debug!("WebDAV write_bytes: {} bytes", buf.len());
                let mut guard = crypto_fs_file.lock().map_err(|_| FsError::GeneralFailure)?;
                guard.write_all(buf.as_ref()).map_err(|e| {
                    error!("WebDAV write_bytes error: {:?}", e);
                    FsError::GeneralFailure
                })?;
                Ok(())
            })
            .await
            .map_err(|e| {
                error!("WebDAV write_bytes join error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self))]
    fn read_bytes(&mut self, count: usize) -> FsFuture<bytes::Bytes> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                debug!("WebDAV read_bytes: {} bytes", count);
                let mut buf = vec![0u8; count];
                let mut guard = crypto_fs_file.lock().map_err(|_| FsError::GeneralFailure)?;
                let n = guard.read(buf.as_mut_slice()).map_err(|e| {
                    error!("WebDAV read_bytes error: {:?}", e);
                    FsError::GeneralFailure
                })?;
                buf.truncate(n);
                Ok(bytes::Bytes::from(buf))
            })
            .await
            .map_err(|e| {
                error!("WebDAV read_bytes join error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self))]
    fn seek(&mut self, pos: SeekFrom) -> FsFuture<u64> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                debug!("WebDAV seek: {:?}", pos);
                let mut guard = crypto_fs_file.lock().map_err(|_| FsError::GeneralFailure)?;
                guard.seek(pos).map_err(|e| {
                    error!("WebDAV seek error: {:?}", e);
                    FsError::GeneralFailure
                })
            })
            .await
            .map_err(|e| {
                error!("WebDAV seek join error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self))]
    fn flush(&mut self) -> FsFuture<()> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                debug!("WebDAV flush");
                let mut guard = crypto_fs_file.lock().map_err(|_| FsError::GeneralFailure)?;
                guard.flush().map_err(|e| {
                    error!("WebDAV flush error: {:?}", e);
                    FsError::GeneralFailure
                })
            })
            .await
            .map_err(|e| {
                error!("WebDAV flush join error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }
}

#[derive(Clone)]
pub struct WebDav<FS: 'static + FileSystem> {
    crypto_fs: CryptoFs<FS>,
}

impl<FS: 'static + FileSystem> WebDav<FS> {
    pub fn new(crypto_fs: CryptoFs<FS>) -> WebDav<FS> {
        WebDav { crypto_fs }
    }
}

impl<FS: FileSystem> DavFileSystem for WebDav<FS> {
    #[instrument(skip(self, options), fields(path = %path.as_url_string()))]
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();
        // Since OpenOptions is not Clone (it's from dav-server), we need to reconstruct or manually pass values.
        // Or we can just extract what we need.
        // Wait, options.create_new etc are bool fields.
        let create_new = options.create_new;
        let create = options.create;
        let read = options.read;
        let append = options.append;
        let truncate = options.truncate;
        let write = options.write;

        async move {
            tokio::task::spawn_blocking(move || {
                debug!("WebDAV open: {:?}", path_buf);
                let exists = crypto_fs.exists(&path_buf);
                if create_new && exists {
                    return Err(FsError::Exists);
                }
                if (create || create_new) && !exists {
                    return Ok(
                        Box::new(DFile::new(Box::new(crypto_fs.create_file(&path_buf)?)))
                            as Box<dyn DavFile>,
                    );
                }
                Ok(Box::new(DFile::new(Box::new(
                    crypto_fs.open_file(
                        &path_buf,
                        *(cryptoOpenOptions::new()
                            .read(read)
                            .create_new(create_new)
                            .create(create)
                            .append(append)
                            .truncate(truncate)
                            .write(write)),
                    )?,
                ))) as Box<dyn DavFile>)
            })
            .await
            .map_err(|e| {
                error!("WebDAV open spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self, _meta), fields(path = %path.as_url_string()))]
    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();

        async move {
            tokio::task::spawn_blocking(move || {
                debug!("WebDAV read_dir: {:?}", path_buf);
                let entries = crypto_fs.read_dir(&path_buf)?;
                // We must collect entires here inside blocking block?
                // entries is Iterator. map creates lazy iterator.
                // We need to collect to Vec to return it safely out of closure.
                // Or construct the stream inside?
                // The return type is Result<FsStream...>.

                let collected_entries: Vec<Box<dyn DavDirEntry>> = entries
                    .map(|e| Box::new(e) as Box<dyn DavDirEntry>)
                    .collect();

                Ok(collected_entries)
            })
            .await
            .map_err(|e| {
                error!("WebDAV read_dir spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
            .map(|collected_entries| {
                let strm = futures::stream::iter(collected_entries).map(Ok::<_, FsError>);
                Box::pin(strm) as FsStream<Box<dyn DavDirEntry>>
            })
        }
        .boxed()
    }

    #[instrument(skip(self), fields(path = %path.as_url_string()))]
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();

        async move {
            tokio::task::spawn_blocking(move || {
                debug!("WebDAV metadata: {:?}", path_buf);
                let metadata = crypto_fs.metadata(&path_buf)?;

                Ok(Box::new(metadata) as Box<dyn DavMetaData>)
            })
            .await
            .map_err(|e| {
                error!("WebDAV metadata spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self), fields(path = %path.as_url_string()))]
    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();
        async move {
            tokio::task::spawn_blocking(move || {
                info!("WebDAV create_dir: {:?}", path_buf);
                Ok(crypto_fs.create_dir(path_buf)?)
            })
            .await
            .map_err(|e| {
                error!("WebDAV create_dir spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self), fields(path = %path.as_url_string()))]
    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();
        async move {
            tokio::task::spawn_blocking(move || {
                info!("WebDAV remove_dir: {:?}", path_buf);
                Ok(crypto_fs.remove_dir(path_buf)?)
            })
            .await
            .map_err(|e| {
                error!("WebDAV remove_dir spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self), fields(path = %path.as_url_string()))]
    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();
        async move {
            tokio::task::spawn_blocking(move || {
                info!("WebDAV remove_file: {:?}", path_buf);
                Ok(crypto_fs.remove_file(path_buf)?)
            })
            .await
            .map_err(|e| {
                error!("WebDAV remove_file spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self), fields(from = %from.as_url_string(), to = %to.as_url_string()))]
    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let from_buf = from.as_pathbuf();
        let to_buf = to.as_pathbuf();

        async move {
            tokio::task::spawn_blocking(move || {
                info!("WebDAV rename: {:?} -> {:?}", from_buf, to_buf);
                Ok(crypto_fs.move_path(&from_buf, &to_buf)?)
            })
            .await
            .map_err(|e| {
                error!("WebDAV rename spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self), fields(from = %from.as_url_string(), to = %to.as_url_string()))]
    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let from_buf = from.as_pathbuf();
        let to_buf = to.as_pathbuf();

        async move {
            tokio::task::spawn_blocking(move || {
                info!("WebDAV copy: {:?} -> {:?}", from_buf, to_buf);
                Ok(crypto_fs.copy_path(&from_buf, &to_buf)?)
            })
            .await
            .map_err(|e| {
                error!("WebDAV copy spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }

    #[instrument(skip(self))]
    fn get_quota(&self) -> FsFuture<(u64, Option<u64>)> {
        let crypto_fs = self.crypto_fs.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                debug!("WebDAV get_quota");
                let stats = crypto_fs.stats(Path::new(&Component::RootDir))?;
                Ok((
                    stats.total_space - stats.free_space,
                    Some(stats.total_space),
                ))
            })
            .await
            .map_err(|e| {
                error!("WebDAV get_quota spawn error: {:?}", e);
                FsError::GeneralFailure
            })?
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error as IoError;
    use std::path::PathBuf;

    #[test]
    fn test_fs_error_from_filesystem_error() {
        assert_eq!(
            FsError::from(FileSystemError::PathDoesNotExist("test".to_string())),
            FsError::NotFound
        );
        assert_eq!(
            FsError::from(FileSystemError::IoError(IoError::new(
                ErrorKind::NotFound,
                "not found"
            ))),
            FsError::NotFound
        );
        assert_eq!(
            FsError::from(FileSystemError::IoError(IoError::new(
                ErrorKind::AlreadyExists,
                "exists"
            ))),
            FsError::Exists
        );
        assert_eq!(
            FsError::from(FileSystemError::IoError(IoError::new(
                ErrorKind::PermissionDenied,
                "forbidden"
            ))),
            FsError::Forbidden
        );
        assert_eq!(
            FsError::from(FileSystemError::IoError(IoError::other("other"))),
            FsError::GeneralFailure
        );
        assert_eq!(
            FsError::from(FileSystemError::InvalidPathError("invalid".to_string())),
            FsError::Forbidden
        );
        assert_eq!(
            FsError::from(FileSystemError::UnknownError("unknown".to_string())),
            FsError::GeneralFailure
        );
    }

    #[test]
    fn test_fs_error_from_crypto_io_error() {
        assert_eq!(
            FsError::from(FileSystemError::CryptoError(CryptoError::IoError(
                IoError::new(ErrorKind::NotFound, "not found")
            ))),
            FsError::NotFound
        );
        assert_eq!(
            FsError::from(FileSystemError::CryptoError(CryptoError::IoError(
                IoError::new(ErrorKind::AlreadyExists, "exists")
            ))),
            FsError::Exists
        );
        assert_eq!(
            FsError::from(FileSystemError::CryptoError(CryptoError::IoError(
                IoError::new(ErrorKind::PermissionDenied, "forbidden")
            ))),
            FsError::Forbidden
        );
        assert_eq!(
            FsError::from(FileSystemError::CryptoError(CryptoError::IoError(
                IoError::other("other")
            ))),
            FsError::GeneralFailure
        );
    }

    #[tokio::test]
    async fn test_dav_dir_entry() {
        let metadata = Metadata {
            is_dir: true,
            is_file: false,
            len: 1024,
            modified: SystemTime::now(),
            accessed: SystemTime::now(),
            created: SystemTime::now(),
            #[cfg(unix)]
            uid: 1000,
            #[cfg(unix)]
            gid: 1000,
        };
        let entry = DirEntry {
            path: PathBuf::from("/test"),
            metadata,
            file_name: "test".into(),
        };

        assert_eq!(entry.name(), b"test");
        let meta = entry.metadata().await.unwrap();
        assert_eq!(meta.len(), 1024);
        assert!(meta.is_dir());
    }

    #[test]
    fn test_dav_metadata() {
        let now = SystemTime::now();
        let metadata = Metadata {
            is_dir: false,
            is_file: true,
            len: 2048,
            modified: now,
            accessed: now,
            created: now,
            #[cfg(unix)]
            uid: 1000,
            #[cfg(unix)]
            gid: 1000,
        };

        assert_eq!(metadata.len(), 2048);
        assert_eq!(metadata.modified().unwrap(), now);
        assert_eq!(metadata.accessed().unwrap(), now);
        assert_eq!(metadata.created().unwrap(), now);
        assert!(!metadata.is_dir());
    }
}
