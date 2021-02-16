use crate::crypto::CryptoError;
use crate::cryptofs::{CryptoFS, DirEntry, File, FileSystem, FileSystemError, Metadata};
use failure::AsFail;
use futures::{future, future::FutureExt};
use std::io::{ErrorKind, Read, SeekFrom, Write};
use std::time::SystemTime;
use webdav_handler::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsResult, FsStream,
    OpenOptions, ReadDirMeta,
};
use webdav_handler::webpath::WebPath;

impl From<FileSystemError> for FsError {
    fn from(fse: FileSystemError) -> Self {
        match fse {
            FileSystemError::PathIsNotExist(_) => FsError::NotFound,
            FileSystemError::CryptoError(s) => match s {
                CryptoError::IOError(i) => match i.kind() {
                    ErrorKind::NotFound => FsError::NotFound,
                    _ => FsError::GeneralFailure,
                },
                _ => FsError::GeneralFailure,
            },
            FileSystemError::IOError(s) => match s.kind() {
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

    fn status_changed(&self) -> FsResult<SystemTime> {
        Ok(self.modified)
    }

    fn executable(&self) -> FsResult<bool> {
        Ok(false)
    }
}

#[derive(Debug)]
struct DFile {
    crypto_fs_file: Box<dyn File>,
}

impl DFile {
    fn new(f: Box<dyn File>) -> DFile {
        DFile { crypto_fs_file: f }
    }
}

impl DavFile for DFile {
    fn metadata(&self) -> FsFuture<Box<dyn DavMetaData>> {
        async move {
            debug!("Metadata for a file");
            Ok(Box::new(self.crypto_fs_file.metadata()?) as Box<dyn DavMetaData>)
        }
        .boxed()
    }

    fn write_bytes<'a>(&'a mut self, buf: &'a [u8]) -> FsFuture<'_, usize> {
        async move {
            debug!("Writing bytes to a file");
            Ok(self.crypto_fs_file.write(buf)?)
        }
        .boxed()
    }

    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> FsFuture<'_, ()> {
        async move {
            debug!("Writing all bytes to a file");
            if let Err(e) = self.crypto_fs_file.write_all(buf) {
                debug!("ERROR KEKE!!!!!!!! {}", e.as_fail());
                return Err(FsError::GeneralFailure);
            }
            Ok(())
        }
        .boxed()
    }

    fn read_bytes<'a>(&'a mut self, buf: &'a mut [u8]) -> FsFuture<'_, usize> {
        async move {
            debug!("Reading bytes from a file");
            Ok(self.crypto_fs_file.read(buf)?)
        }
        .boxed()
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<u64> {
        async move {
            debug!("Seeking file");
            Ok(self.crypto_fs_file.seek(pos)?)
        }
        .boxed()
    }

    fn flush(&mut self) -> FsFuture<()> {
        async move {
            debug!("Flushing file");
            Ok(self.crypto_fs_file.flush()?)
        }
        .boxed()
    }
}

#[derive(Clone)]
pub struct WebDav<FS: 'static + FileSystem> {
    crypto_fs: CryptoFS<FS>,
}

impl<FS: 'static + FileSystem> WebDav<FS> {
    pub fn new(crypto_fs: CryptoFS<FS>) -> WebDav<FS> {
        WebDav { crypto_fs }
    }
}

impl<FS: FileSystem> DavFileSystem for WebDav<FS> {
    fn open<'a>(
        &'a self,
        path: &'a WebPath,
        _options: OpenOptions,
    ) -> FsFuture<'_, Box<dyn DavFile>> {
        async move {
            debug!("Opening file");
            let exists = self.crypto_fs.exists(path.as_pathbuf());
            if _options.create_new && exists {
                return Err(FsError::Exists);
            }
            if (_options.create || _options.create_new) && !exists {
                return Ok(
                    Box::new(DFile::new(self.crypto_fs.create_file(path.as_pathbuf())?))
                        as Box<dyn DavFile>,
                );
            }
            Ok(
                Box::new(DFile::new(self.crypto_fs.open_file(path.as_pathbuf())?))
                    as Box<dyn DavFile>,
            )
        }
        .boxed()
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a WebPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'_, FsStream<Box<dyn DavDirEntry>>> {
        async move {
            debug!("Reading dir");
            let entries = self.crypto_fs.read_dir(path.as_pathbuf())?;
            let mut v: Vec<Box<dyn DavDirEntry>> = Vec::new();
            for entry in entries {
                v.push(Box::new(entry));
            }
            let strm = futures::stream::iter(v.into_iter());
            Ok(Box::pin(strm) as FsStream<Box<dyn DavDirEntry>>)
        }
        .boxed()
    }

    fn metadata<'a>(&'a self, path: &'a WebPath) -> FsFuture<'_, Box<dyn DavMetaData>> {
        async move {
            debug!("FS::Metadata");
            let metadata = self.crypto_fs.metadata(path.as_pathbuf())?;
            Ok(Box::new(metadata) as Box<dyn DavMetaData>)
        }
        .boxed()
    }

    fn create_dir<'a>(&'a self, path: &'a WebPath) -> FsFuture<()> {
        async move {
            debug!("Creating dir");
            Ok(self.crypto_fs.create_dir(path.as_pathbuf())?)
        }
        .boxed()
    }

    fn remove_dir<'a>(&'a self, path: &'a WebPath) -> FsFuture<()> {
        async move {
            debug!("Removing dir");
            Ok(self.crypto_fs.remove_dir(path.as_pathbuf())?)
        }
        .boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a WebPath) -> FsFuture<()> {
        async move { Ok(self.crypto_fs.remove_file(path.as_pathbuf())?) }.boxed()
    }

    fn rename<'a>(&'a self, from: &'a WebPath, to: &'a WebPath) -> FsFuture<()> {
        async move {
            let from_metadata = self.crypto_fs.metadata(from.as_pathbuf())?;
            if from_metadata.is_dir {
                return Ok(self
                    .crypto_fs
                    .move_dir(from.as_pathbuf(), to.as_pathbuf())?);
            }
            Ok(self
                .crypto_fs
                .move_file(from.as_pathbuf(), to.as_pathbuf())?)
        }
        .boxed()
    }

    fn copy<'a>(&'a self, from: &'a WebPath, to: &'a WebPath) -> FsFuture<()> {
        async move {
            Ok(self
                .crypto_fs
                .copy_file(from.as_pathbuf(), to.as_pathbuf())?)
        }
        .boxed()
    }

    fn set_accessed<'a>(&'a self, path: &'a WebPath, tm: SystemTime) -> FsFuture<()> {
        async move { Ok(()) }.boxed()
    }

    fn set_modified<'a>(&'a self, path: &'a WebPath, tm: SystemTime) -> FsFuture<()> {
        async move { Ok(()) }.boxed()
    }
}
