use crate::cryptofs::FileSystemError;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::Debug;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::time::SystemTime;

#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;

/// A File should be readable/writeable/seekable, and be able to return its metadata
pub trait File: Seek + Read + Write + Sync + Send + Debug {
    fn metadata(&self) -> Result<Metadata, Box<dyn Error>>;
}

/// The trait that defines a filesystem.
pub trait FileSystem: Sync + Send + Clone {
    /// Iterates over all entries of this directory path
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, Box<dyn Error>>;

    /// Creates the directory at this path
    /// Note that the parent directory must exist.
    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>>;

    /// Recursively creates the directory at this path
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>>;

    /// Opens the file at this path for reading/writing
    fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, Box<dyn Error>>;

    /// Creates a file at the given path for reading/writing
    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, Box<dyn Error>>;

    /// Returns true if a file or directory at path exists, false otherwise
    fn exists<P: AsRef<Path>>(&self, path: P) -> bool;

    /// Removes the file at the given path
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>>;

    /// Removes dir at the given path
    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>>;

    /// Copies _srs file to _dest
    fn copy_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>>;

    /// Moves file from _src to _dest
    fn move_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>>;

    /// Moves dir from _src to _dest
    fn move_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>>;

    /// Returns metadata of an entry by the given path
    fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, Box<dyn Error>>;

    /// Returns the stats of the file system containing the provided path
    fn stats<P: AsRef<Path>>(&self, path: P) -> Result<Stats, Box<dyn Error>>;
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

    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
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
            accessed: match m.accessed() {
                Ok(st) => st,
                Err(_) => SystemTime::UNIX_EPOCH,
            },
            created: match m.created() {
                Ok(st) => st,
                Err(_) => SystemTime::UNIX_EPOCH,
            },

            #[cfg(unix)]
            uid: m.st_uid(),
            #[cfg(unix)]
            gid: m.st_gid(),
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

            #[cfg(unix)]
            uid: 0,
            #[cfg(unix)]
            gid: 0,
        }
    }
}

impl Metadata {
    pub fn with_is_dir(&mut self, is_dir: bool) -> &mut Self {
        self.is_dir = is_dir;
        self
    }

    pub fn with_is_file(&mut self, is_file: bool) -> &mut Self {
        self.is_file = is_file;
        self
    }

    pub fn with_len(&mut self, len: u64) -> &mut Self {
        self.len = len;
        self
    }

    pub fn with_modified(&mut self, modified: SystemTime) -> &mut Self {
        self.modified = modified;
        self
    }

    pub fn with_accessed(&mut self, accessed: SystemTime) -> &mut Self {
        self.accessed = accessed;
        self
    }

    pub fn with_created(&mut self, created: SystemTime) -> &mut Self {
        self.created = created;
        self
    }

    #[cfg(unix)]
    pub fn with_uid(&mut self, uid: u32) -> &mut Self {
        self.uid = uid;
        self
    }

    #[cfg(unix)]
    pub fn with_gid(&mut self, gid: u32) -> &mut Self {
        self.gid = gid;
        self
    }
}

/// Directory entry. Should contain a full path, metadata and name
#[derive(Clone, Default)]
pub struct DirEntry {
    pub path: std::path::PathBuf,
    pub metadata: Metadata,
    pub file_name: OsString,
}

impl DirEntry {
    pub fn filename_string(&self) -> Result<String, Box<dyn Error>> {
        match self.file_name.to_str() {
            Some(s) => Ok(s.to_string()),
            None => Err(Box::new(FileSystemError::UnknownError(
                "failed to convert OsString to String".to_string(),
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

#[derive(Copy, Clone, Debug)]
/// Contains some common stats about a file system.
pub struct Stats {
    /// Number of free bytes
    pub free_space: u64,

    /// Available space in bytes to non-priveleged users
    pub available_space: u64,

    /// Total space in bytes
    pub total_space: u64,

    /// Filesystem's disk space allocation granularity in bytes
    pub allocation_granularity: u64,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            free_space: 0,
            available_space: 0,
            total_space: 0,
            allocation_granularity: 512,
        }
    }
}
