use crate::cryptofs::FileSystemError;
use std::ffi::OsString;
use std::fmt::Debug;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::time::SystemTime;

/// A File should be readable/writeable/seekable, and be able to return its metadata
pub trait File: Seek + Read + Write + Sync + Send + Debug {
    fn metadata(&self) -> Result<Metadata, FileSystemError>;
}

/// The trait that defines a filesystem.
pub trait FileSystem: Sync + Send + Clone {
    /// Iterates over all entries of this directory path
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError>;

    /// Creates the directory at this path
    /// Note that the parent directory must exist.
    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError>;

    /// Recursively creates the directory at this path
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError>;

    /// Opens the file at this path for reading/writing
    fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, FileSystemError>;

    /// Creates a file at the given path for reading/writing
    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, FileSystemError>;

    /// Returns true if a file or directory at path exists, false otherwise
    fn exists<P: AsRef<Path>>(&self, path: P) -> bool;

    /// Removes the file at the given path
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError>;

    /// Removes dir at the given path
    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError>;

    /// Copies _srs file to _dest
    fn copy_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError>;

    /// Moves file from _src to _dest
    fn move_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError>;

    /// Moves dir from _src to _dest
    fn move_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError>;
}

/// File metadata. Not much more than type, length, and some timestamps
#[derive(Copy, Clone, Debug)]
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

/// Directory entry. Should contain a full path, metadata and name
pub struct DirEntry {
    pub path: std::path::PathBuf,
    pub metadata: Metadata,
    pub file_name: OsString,
}

impl DirEntry {
    pub fn filename_string(&self) -> Result<String, FileSystemError> {
        match self.file_name.to_str() {
            Some(s) => Ok(s.to_string()),
            None => Err(FileSystemError::UnknownError(
                "failed to convert OsString to String".to_string(),
            )),
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
