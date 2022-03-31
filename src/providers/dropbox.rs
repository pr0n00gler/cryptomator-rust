use crate::cryptofs::{DirEntry, File, FileSystem, FileSystemError, Metadata, Stats};
use dropbox_sdk::default_client::UserAuthDefaultClient;
use dropbox_sdk::files::{ListFolderContinueArg, ListFolderResult};
use dropbox_sdk::{files, UserAuthClient};
use std::ffi::OsString;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Clone)]
pub struct DropboxFS {
    client: Arc<Mutex<UserAuthDefaultClient>>,
}

impl DropboxFS {
    pub fn new(client: Arc<Mutex<UserAuthDefaultClient>>) -> Self {
        DropboxFS { client }
    }
}

impl FileSystem for DropboxFS {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError> {
        let client = self.client.lock().unwrap();

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
                        metadata: Metadata {
                            is_dir: false,
                            is_file: true,
                            len: f.size,
                            modified: SystemTime::UNIX_EPOCH,
                            accessed: SystemTime::UNIX_EPOCH,
                            created: SystemTime::UNIX_EPOCH,
                            uid: 0,
                            gid: 0,
                        },
                        file_name: OsString::from(f.name.clone()),
                    },
                    files::Metadata::Folder(f) => DirEntry {
                        path: PathBuf::from(f.path_lower.clone().unwrap()),
                        metadata: Metadata {
                            is_dir: true,
                            is_file: false,
                            len: 0,
                            modified: SystemTime::UNIX_EPOCH,
                            accessed: SystemTime::UNIX_EPOCH,
                            created: SystemTime::UNIX_EPOCH,
                            uid: 0,
                            gid: 0,
                        },
                        file_name: OsString::from(f.name.clone()),
                    },
                    _ => continue,
                };

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

    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, FileSystemError> {
        todo!()
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, FileSystemError> {
        todo!()
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        let client = self.client.lock().unwrap();

        let get_metadata_arg =
            files::GetMetadataArg::new(String::from(path.as_ref().to_str().unwrap()));
        let result = files::get_metadata(client.deref(), &get_metadata_arg).unwrap();
        result.is_ok()
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        todo!()
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
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
        todo!()
    }

    fn stats<P: AsRef<Path>>(&self, path: P) -> Result<Stats, FileSystemError> {
        todo!()
    }
}
