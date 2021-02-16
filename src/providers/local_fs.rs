use crate::cryptofs::{DirEntry, File, FileSystem, FileSystemError, Metadata};
use std::fs;
use std::path::Path;

/// Provides access to a local filesystem
#[derive(Clone)]
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
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError> {
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

    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        Ok(fs::create_dir(path)?)
    }

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        Ok(fs::create_dir_all(path)?)
    }

    fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, FileSystemError> {
        Ok(Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .open(path)?,
        ))
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, FileSystemError> {
        Ok(Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .create_new(true)
                .open(path)?,
        ))
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        std::path::Path::exists(std::path::Path::new(path.as_ref()))
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        Ok(fs::remove_file(path)?)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        Ok(fs::remove_dir_all(path)?)
    }

    fn copy_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        fs::copy(_src, _dest)?;
        Ok(())
    }

    fn move_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        self.copy_file(&_src, &_dest)?;
        Ok(self.remove_file(_src)?)
    }

    fn move_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        // well, there is no call of this method from CryptoFS at this moment and i'm too lazy to
        // implement the method for no reason.
        //TODO: implement this method
        unimplemented!();
    }

    fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, FileSystemError> {
        let metadata = fs::metadata(path)?;
        Ok(Metadata::from(metadata))
    }
}
