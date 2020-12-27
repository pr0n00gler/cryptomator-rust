use crate::cryptofs::FileSystemError;
use std::io::{Read, Seek, Write};

pub trait File: Seek + Read + Write {}

pub trait FileSystem {
    fn read_dir(&self, path: &str) -> Result<Box<dyn Iterator<Item = String>>, FileSystemError>;
    fn create_dir(&self, path: &str) -> Result<(), FileSystemError>;
    fn create_dir_all(&self, path: &str) -> Result<(), FileSystemError>;
    fn open_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError>;
    fn create_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError>;
    fn append_file(&self, path: &str) -> Result<Box<dyn Write>, FileSystemError>;
    fn exists(&self, path: &str) -> bool;
    fn remove_file(&self, path: &str) -> Result<(), FileSystemError>;
    fn remove_dir(&self, path: &str) -> Result<(), FileSystemError>;
    fn copy_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError>;
    fn move_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError>;
    fn move_dir(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError>;
}
