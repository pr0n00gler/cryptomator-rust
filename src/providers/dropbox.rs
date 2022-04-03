use crate::cryptofs::{DirEntry, File, FileSystem, FileSystemError, Metadata, Stats};
use bytes::Buf;
use dropbox_sdk::default_client::UserAuthDefaultClient;
use dropbox_sdk::files;
use dropbox_sdk::files::ListFolderContinueArg;
use std::ffi::OsString;
use std::fmt::{Debug, Formatter};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::error;

#[derive(Clone)]
pub struct DropboxClient {
    client: Arc<Mutex<UserAuthDefaultClient>>,
}

impl Debug for DropboxClient {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

#[derive(Clone)]
pub struct DropboxFS {
    client: DropboxClient,
}

impl DropboxFS {
    pub fn new(client: Arc<Mutex<UserAuthDefaultClient>>) -> Self {
        DropboxFS {
            client: DropboxClient { client },
        }
    }
}

// TODO: remove unwraps

impl FileSystem for DropboxFS {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError> {
        let client = self.client.client.lock().unwrap();

        let list_folder_arg =
            files::ListFolderArg::new(String::from(path.as_ref().as_os_str().to_str().unwrap()));

        let mut entries: Vec<DirEntry> = vec![];

        let mut result = files::list_folder(client.deref(), &list_folder_arg)
            .unwrap()
            .unwrap();

        loop {
            for result_entry in result.entries.iter() {
                let dir_entry = match result_entry {
                    files::Metadata::File(f) => DirEntry {
                        path: PathBuf::from(f.path_lower.clone().unwrap()),
                        metadata: *Metadata::default().with_len(f.size).with_is_file(true),
                        file_name: OsString::from(f.name.clone()),
                    },
                    files::Metadata::Folder(f) => DirEntry {
                        path: PathBuf::from(f.path_lower.clone().unwrap()),
                        metadata: *Metadata::default().with_is_dir(true),
                        file_name: OsString::from(f.name.clone()),
                    },
                    _ => continue,
                };

                println!("{:?}", dir_entry.path);
                entries.push(dir_entry);
            }

            if !result.has_more {
                break;
            }

            result = files::list_folder_continue(
                client.deref(),
                &ListFolderContinueArg::new(result.cursor),
            )
            .unwrap()
            .unwrap();
        }

        Ok(Box::new(entries.into_iter()))
    }

    fn create_dir<P: AsRef<Path>>(&self, _path: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn create_dir_all<P: AsRef<Path>>(&self, _path: P) -> Result<(), FileSystemError> {
        Ok(())
    }

    fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, FileSystemError> {
        println!("{:?}", path.as_ref());
        Ok(Box::new(DropboxFile::new(
            self.client.clone(),
            String::from(path.as_ref().to_str().unwrap()),
        )))
    }

    fn create_file<P: AsRef<Path>>(&self, _path: P) -> Result<Box<dyn File>, FileSystemError> {
        todo!()
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        let client = self.client.client.lock().unwrap();

        let get_metadata_arg =
            files::GetMetadataArg::new(String::from(path.as_ref().to_str().unwrap()));
        let result = files::get_metadata(client.deref(), &get_metadata_arg).unwrap();
        result.is_ok()
    }

    fn remove_file<P: AsRef<Path>>(&self, _path: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn remove_dir<P: AsRef<Path>>(&self, _path: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn copy_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn move_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn move_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, FileSystemError> {
        let client = self.client.client.lock().unwrap();

        let get_metadata_arg =
            files::GetMetadataArg::new(String::from(path.as_ref().to_str().unwrap()));
        let result = files::get_metadata(client.deref(), &get_metadata_arg)
            .unwrap()
            .unwrap();

        match result {
            files::Metadata::File(f) => {
                Ok(*Metadata::default().with_is_file(true).with_len(f.size))
            }
            files::Metadata::Folder(_) => Ok(*Metadata::default().with_is_dir(true)),
            _ => Err(FileSystemError::UnknownError("invalid".to_string())),
        }
    }

    fn stats<P: AsRef<Path>>(&self, _path: P) -> Result<Stats, FileSystemError> {
        Ok(Stats::default())
    }
}

#[derive(Debug)]
pub struct DropboxFile {
    pub client: DropboxClient,
    pub path: String,
    pub current_pos: u64,

    // dropbox-sdk doesn't support HTTP range, so we download a whole file
    // and do range work in Cursor
    pub data: Cursor<Vec<u8>>,
}

impl DropboxFile {
    pub fn new(client: DropboxClient, path: String) -> Self {
        DropboxFile {
            client,
            path,
            current_pos: 0,
            data: Cursor::new(vec![0u8; 0]),
        }
    }

    pub fn file_size(&mut self) -> Result<u64, FileSystemError> {
        let client = self.client.client.lock().unwrap();

        let get_metadata_arg = files::GetMetadataArg::new(self.path.clone());
        let result = files::get_metadata(client.deref(), &get_metadata_arg)
            .unwrap()
            .unwrap();

        if let files::Metadata::File(f) = result {
            return Ok(f.size);
        }

        Err(FileSystemError::UnknownError(
            "path is not a file".to_string(),
        ))
    }
}

impl Seek for DropboxFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => self.current_pos = p,
            SeekFrom::Current(p) => self.current_pos = (self.current_pos as i64 + p) as u64,
            SeekFrom::End(p) => match self.file_size() {
                Ok(s) => self.current_pos = (s as i64 + p) as u64,
                Err(e) => {
                    error!("Failed to determine cleartext file size: {:?}", e);
                    return Err(std::io::Error::from(std::io::ErrorKind::Other));
                }
            },
        }
        Ok(self.current_pos)
    }
}

impl Read for DropboxFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.data.get_ref().is_empty() {
            return self.data.read(buf);
        }

        let client = self.client.client.lock().unwrap();

        let download_arg = files::DownloadArg::new(self.path.clone());
        let result = files::download(client.deref(), &download_arg, None, None);

        match result {
            Ok(Ok(download_result)) => {
                let mut body = download_result.body.expect("no body received!");

                let mut data: Vec<u8> = vec![];
                body.read_to_end(&mut data).unwrap();

                self.data = Cursor::new(data);

                self.data.read(buf)
            }
            Ok(Err(download_error)) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                download_error,
            )),
            Err(request_error) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                request_error,
            )),
        }
    }
}

impl Write for DropboxFile {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

impl File for DropboxFile {
    fn metadata(&self) -> Result<Metadata, FileSystemError> {
        let client = self.client.client.lock().unwrap();

        let get_metadata_arg = files::GetMetadataArg::new(self.path.clone());
        let result = files::get_metadata(client.deref(), &get_metadata_arg)
            .unwrap()
            .unwrap();

        match result {
            files::Metadata::File(f) => {
                Ok(*Metadata::default().with_is_file(true).with_len(f.size))
            }
            files::Metadata::Folder(_f) => Ok(*Metadata::default().with_is_dir(true)),
            files::Metadata::Deleted(_d) => Err(FileSystemError::InvalidPathError(
                "path deleted".to_string(),
            )),
        }
    }
}
