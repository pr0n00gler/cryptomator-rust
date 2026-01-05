use crate::crypto::CryptoError;
use crate::cryptofs::{
    CryptoFs, DirEntry, File, FileSystem, FileSystemError, Metadata,
    OpenOptions as cryptoOpenOptions,
};
use bytes::{Buf, Bytes};
use futures::{future, future::FutureExt};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use webdav_handler::davpath::DavPath;
use webdav_handler::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsResult, FsStream,
    OpenOptions, ReadDirMeta,
};

impl From<FileSystemError> for FsError {
    fn from(fse: FileSystemError) -> Self {
        match fse {
            FileSystemError::PathDoesNotExist(_) => FsError::NotFound,
            FileSystemError::CryptoError(CryptoError::IoError(i)) => match i.kind() {
                ErrorKind::NotFound => FsError::NotFound,
                _ => FsError::GeneralFailure,
            },
            FileSystemError::IoError(s) => match s.kind() {
                ErrorKind::NotFound => FsError::NotFound,
                _ => FsError::GeneralFailure,
            },
            _ => FsError::GeneralFailure,
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

impl DavFile for DFile {
    fn metadata(&mut self) -> FsFuture<Box<dyn DavMetaData>> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut guard = crypto_fs_file.lock().unwrap();
                let mut metadata = guard.metadata().unwrap();

                // Get the actual cleartext size by seeking to the end
                if !metadata.is_dir {
                    if let Ok(size) = guard.seek(SeekFrom::End(0)) {
                        metadata.len = size;
                    }
                }

                Ok(Box::new(metadata) as Box<dyn DavMetaData>)
            })
            .await
            .unwrap()
        }
        .boxed()
    }

    fn write_buf(&mut self, buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut guard = crypto_fs_file.lock().unwrap();
                Ok(guard.write_all(buf.chunk())?)
            })
            .await
            .unwrap()
        }
        .boxed()
    }

    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<()> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut guard = crypto_fs_file.lock().unwrap();
                Ok(guard.write_all(buf.as_ref())?)
            })
            .await
            .unwrap()
        }
        .boxed()
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<bytes::Bytes> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut buf = vec![0u8; count];
                let mut guard = crypto_fs_file.lock().unwrap();
                guard.read_exact(buf.as_mut_slice())?;
                Ok(bytes::Bytes::from(buf))
            })
            .await
            .unwrap()
        }
        .boxed()
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<u64> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut guard = crypto_fs_file.lock().unwrap();
                Ok(guard.seek(pos)?)
            })
            .await
            .unwrap()
        }
        .boxed()
    }

    fn flush(&mut self) -> FsFuture<()> {
        let crypto_fs_file = self.crypto_fs_file.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut guard = crypto_fs_file.lock().unwrap();
                Ok(guard.flush()?)
            })
            .await
            .unwrap()
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
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();
        // Since OpenOptions is not Clone (it's from webdav-handler), we need to reconstruct or manually pass values.
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
            .unwrap()
        }
        .boxed()
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();

        async move {
            tokio::task::spawn_blocking(move || {
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
            .unwrap()
            .map(|collected_entries| {
                let strm = futures::stream::iter(collected_entries);
                Box::pin(strm) as FsStream<Box<dyn DavDirEntry>>
            })
        }
        .boxed()
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();

        async move {
            tokio::task::spawn_blocking(move || {
                let mut metadata = crypto_fs.metadata(&path_buf)?;

                // For files, get the actual cleartext size by opening and seeking
                if !metadata.is_dir {
                    if let Ok(mut file) =
                        crypto_fs.open_file(&path_buf, *cryptoOpenOptions::new().read(true))
                    {
                        if let Ok(size) = file.seek(SeekFrom::End(0)) {
                            metadata.len = size;
                        }
                    }
                }

                Ok(Box::new(metadata) as Box<dyn DavMetaData>)
            })
            .await
            .unwrap()
        }
        .boxed()
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();
        async move {
            tokio::task::spawn_blocking(move || Ok(crypto_fs.create_dir(path_buf)?))
                .await
                .unwrap()
        }
        .boxed()
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();
        async move {
            tokio::task::spawn_blocking(move || Ok(crypto_fs.remove_dir(path_buf)?))
                .await
                .unwrap()
        }
        .boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let path_buf = path.as_pathbuf();
        async move {
            tokio::task::spawn_blocking(move || Ok(crypto_fs.remove_file(path_buf)?))
                .await
                .unwrap()
        }
        .boxed()
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let from_buf = from.as_pathbuf();
        let to_buf = to.as_pathbuf();

        async move {
            tokio::task::spawn_blocking(move || {
                let from_metadata = crypto_fs.metadata(&from_buf)?;
                if from_metadata.is_dir {
                    return Ok(crypto_fs.move_dir(&from_buf, &to_buf)?);
                }
                Ok(crypto_fs.move_file(&from_buf, &to_buf)?)
            })
            .await
            .unwrap()
        }
        .boxed()
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let crypto_fs = self.crypto_fs.clone();
        let from_buf = from.as_pathbuf();
        let to_buf = to.as_pathbuf();

        async move {
            tokio::task::spawn_blocking(move || Ok(crypto_fs.copy_file(from_buf, to_buf)?))
                .await
                .unwrap()
        }
        .boxed()
    }

    fn get_quota(&self) -> FsFuture<(u64, Option<u64>)> {
        let crypto_fs = self.crypto_fs.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let stats = crypto_fs.stats(Path::new(&Component::RootDir))?;
                Ok((
                    stats.total_space - stats.free_space,
                    Some(stats.total_space),
                ))
            })
            .await
            .unwrap()
        }
        .boxed()
    }
}
