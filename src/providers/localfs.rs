use crate::cryptofs::{File, FileSystem, FileSystemError};
use std::fs;

pub struct LocalFS {}

impl LocalFS {
    pub fn new() -> LocalFS {
        LocalFS {}
    }
}

impl File for fs::File {}

impl FileSystem for LocalFS {
    fn read_dir(&self, path: &str) -> Result<Box<dyn Iterator<Item = String>>, FileSystemError> {
        let mut filenames: Vec<String> = vec![];
        let entries = fs::read_dir(path)?.map(|rd| rd.map(|e| e.file_name()));
        for entry in entries {
            let e = entry?;
            let filename = e.to_str().unwrap_or_default();
            filenames.extend(vec![String::from(filename)]);
        }
        Ok(Box::new(filenames.into_iter()))
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
        ) as Box<dyn File>)
    }

    fn create_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError> {
        Ok(Box::new(fs::File::create(path)?))
    }

    fn append_file(&self, path: &str) -> Result<Box<dyn std::io::Write>, FileSystemError> {
        Ok(Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .open(path)?,
        ))
    }

    fn exists(&self, path: &str) -> bool {
        std::path::Path::exists(std::path::Path::new(path))
    }

    fn remove_file(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(fs::remove_file(path)?)
    }

    fn remove_dir(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(fs::remove_dir(path)?)
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
        self.copy_file(_src, _dest)?;
        Ok(self.remove_dir(_src)?)
    }
}
