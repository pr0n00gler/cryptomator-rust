use crate::cryptofs::{CryptoFS, DirEntry, File, FileSystem, Metadata};
use futures::{future, future::FutureExt};
use std::io::{Read, SeekFrom, Write};
use std::time::SystemTime;
use webdav_handler::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsFuture, FsResult, FsStream, OpenOptions,
    ReadDirMeta,
};
use webdav_handler::webpath::WebPath;

impl DavDirEntry for DirEntry {
    fn name(&self) -> Vec<u8> {
        Vec::from(self.file_name.to_str().unwrap())
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
        async move { Ok(Box::new(self.crypto_fs_file.metadata().unwrap()) as Box<dyn DavMetaData>) }
            .boxed()
    }

    fn write_bytes<'a>(&'a mut self, buf: &'a [u8]) -> FsFuture<'_, usize> {
        async move { Ok(self.crypto_fs_file.write(buf).unwrap()) }.boxed()
    }

    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> FsFuture<'_, ()> {
        async move { Ok(self.crypto_fs_file.write_all(buf).unwrap()) }.boxed()
    }

    fn read_bytes<'a>(&'a mut self, buf: &'a mut [u8]) -> FsFuture<'_, usize> {
        async move { Ok(self.crypto_fs_file.read(buf).unwrap()) }.boxed()
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<u64> {
        async move { Ok(self.crypto_fs_file.seek(pos).unwrap()) }.boxed()
    }

    fn flush(&mut self) -> FsFuture<()> {
        async move { Ok(self.crypto_fs_file.flush().unwrap()) }.boxed()
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
            Ok(Box::new(DFile::new(
                self.crypto_fs.open_file(path.as_pathbuf()).unwrap(),
            )) as Box<dyn DavFile>)
        }
        .boxed()
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a WebPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'_, FsStream<Box<dyn DavDirEntry>>> {
        async move {
            let entries = self.crypto_fs.read_dir(path.as_pathbuf()).unwrap();
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
            let f = self.crypto_fs.open_file(path.as_pathbuf()).unwrap();
            Ok(Box::new(f.metadata().unwrap()) as Box<dyn DavMetaData>)
        }
        .boxed()
    }
}
