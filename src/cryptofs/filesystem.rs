use crate::cryptofs::FileSystemError;
use std::ffi::OsString;
use std::io::{Read, Seek, Write};
use std::time::SystemTime;

pub trait File: Seek + Read + Write {
    fn metadata(&self) -> Result<Metadata, FileSystemError>;
}

pub trait FileSystem {
    fn read_dir(&self, path: &str) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError>;
    fn create_dir(&self, path: &str) -> Result<(), FileSystemError>;
    fn create_dir_all(&self, path: &str) -> Result<(), FileSystemError>;
    fn open_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError>;
    fn create_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError>;
    fn exists(&self, path: &str) -> bool;
    fn remove_file(&self, path: &str) -> Result<(), FileSystemError>;
    fn remove_dir(&self, path: &str) -> Result<(), FileSystemError>;
    fn copy_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError>;
    fn move_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError>;
    fn move_dir(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError>;
}

#[derive(Copy, Clone)]
pub struct Metadata {
    pub is_dir: bool,
    pub is_file: bool,
    pub len: u64,
    pub modified: SystemTime,
    pub accessed: SystemTime,
    pub created: SystemTime,
}

impl From<std::fs::Metadata> for Metadata {
    fn from(m: std::fs::Metadata) -> Self {
        Metadata {
            is_dir: m.is_dir(),
            is_file: m.is_file(),
            len: m.len(),
            modified: match m.modified() {
                Ok(st) => st,
                Err(_) => SystemTime::UNIX_EPOCH,
            },
            accessed: match m.modified() {
                Ok(st) => st,
                Err(_) => SystemTime::UNIX_EPOCH,
            },
            created: match m.modified() {
                Ok(st) => st,
                Err(_) => SystemTime::UNIX_EPOCH,
            },
        }
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            is_dir: false,
            is_file: false,
            len: 0,
            modified: SystemTime::UNIX_EPOCH,
            accessed: SystemTime::UNIX_EPOCH,
            created: SystemTime::UNIX_EPOCH,
        }
    }
}

pub struct DirEntry {
    pub path: std::path::PathBuf,
    pub metadata: Metadata,
    pub file_name: OsString,
}

impl DirEntry {
    pub fn filename_string(&self) -> Result<String, FileSystemError> {
        match self.file_name.to_str() {
            Some(s) => Ok(s.to_string()),
            None => Err(FileSystemError::UnknownError(format!(
                "failed to convert OsString to String"
            ))),
        }
    }

    pub fn filename_without_extension(&self) -> String {
        match std::path::Path::new(&self.file_name).file_stem() {
            Some(s) => match s.to_str() {
                Some(f) => f.to_string(),
                None => String::new(),
            },
            None => String::new(),
        }
    }
}

impl Default for DirEntry {
    fn default() -> Self {
        DirEntry {
            path: Default::default(),
            metadata: Default::default(),
            file_name: Default::default(),
        }
    }
}
