use crate::cryptofs::{DirEntry, File, FileSystem, FileSystemError, Metadata};
use std::fs;

/// Provides access to a local filesystem
pub struct LocalFS {}

impl LocalFS {
    pub fn new() -> LocalFS {
        LocalFS {}
    }
}

impl Default for LocalFS {
    fn default() -> Self {
        Self::new()
    }
}

impl File for std::fs::File {
    fn metadata(&self) -> Result<Metadata, FileSystemError> {
        Ok(Metadata::from(self.metadata()?))
    }
}

impl FileSystem for LocalFS {
    fn read_dir(&self, path: &str) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError> {
        Ok(Box::new(fs::read_dir(path)?.map(|rd| match rd {
            Ok(de) => DirEntry {
                path: de.path(),
                metadata: match de.metadata() {
                    Ok(m) => Metadata::from(m),
                    Err(_) => Metadata::default(),
                },
                file_name: de.file_name(),
            },
            Err(_) => DirEntry::default(),
        })))
    }

    fn create_dir(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(fs::create_dir(path)?)
    }

    fn create_dir_all(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(fs::create_dir_all(path)?)
    }

    fn open_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError> {
        Ok(Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .open(path)?,
        ))
    }

    fn create_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError> {
        Ok(Box::new(fs::File::create(path)?))
    }

    fn exists(&self, path: &str) -> bool {
        std::path::Path::exists(std::path::Path::new(path))
    }

    fn remove_file(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(fs::remove_file(path)?)
    }

    fn remove_dir(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(fs::remove_dir_all(path)?)
    }

    fn copy_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        fs::copy(_src, _dest)?;
        Ok(())
    }

    fn move_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        self.copy_file(_src, _dest)?;
        Ok(self.remove_file(_src)?)
    }

    fn move_dir(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        // well, there is no call of this method from CryptoFS at this moment and i'm too lazy to
        // implement the method for no reason.
        //TODO: implement this method
        unimplemented!();
    }
}
