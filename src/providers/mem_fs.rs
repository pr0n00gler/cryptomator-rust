use crate::cryptofs::{
    last_path_component, parent_path, DirEntry, File, FileSystem, FileSystemError, Metadata,
};
use rsfs::mem::FS;
use rsfs::{DirEntry as DE, GenFS, OpenOptions};
use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::SystemTime;

// Simple implementation of in-memory filesystem
// Only for testing purposes
pub struct MemoryFS {
    fs: FS,
}

pub struct VirtualFile<F: rsfs::File> {
    f: F,
}

impl<F: rsfs::File> VirtualFile<F> {
    fn new(f: F) -> Self {
        VirtualFile { f }
    }
}

impl<F: rsfs::File> File for VirtualFile<F> {
    fn metadata(&self) -> Result<Metadata, FileSystemError> {
        Ok(metadata_from_rsfs(self.f.metadata()?))
    }
}

impl<F: rsfs::File> Read for VirtualFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.f.read(buf)
    }
}

impl<F: rsfs::File> Write for VirtualFile<F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.f.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

impl<F: rsfs::File> Seek for VirtualFile<F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.f.seek(pos)
    }
}

fn metadata_from_rsfs<M: rsfs::Metadata>(m: M) -> Metadata {
    Metadata {
        is_dir: m.is_dir(),
        is_file: m.is_file(),
        len: m.len(),
        modified: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        accessed: m.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
        created: m.created().unwrap_or(SystemTime::UNIX_EPOCH),
    }
}

fn dir_entry_from_rsfs<D: rsfs::DirEntry>(d: D) -> DirEntry {
    DirEntry {
        path: d.path(),
        metadata: metadata_from_rsfs(d.metadata().unwrap()),
        file_name: d.file_name(),
    }
}

impl MemoryFS {
    pub fn new() -> Self {
        MemoryFS { fs: FS::new() }
    }
}

impl FileSystem for MemoryFS {
    fn read_dir(&self, path: &str) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError> {
        Ok(Box::new(
            self.fs
                .read_dir(path)
                .unwrap()
                .map(|e| dir_entry_from_rsfs(e.unwrap())),
        ))
    }

    fn create_dir(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(self.fs.create_dir(path)?)
    }

    fn create_dir_all(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(self.fs.create_dir_all(path)?)
    }

    fn open_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError> {
        Ok(Box::new(VirtualFile::new(
            self.fs.new_openopts().read(true).write(true).open(path)?,
        )))
    }

    fn create_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError> {
        Ok(Box::new(VirtualFile::new(self.fs.create_file(path)?)))
    }

    fn exists(&self, path: &str) -> bool {
        let last_element = last_path_component(path).unwrap();
        let entries = self.fs.read_dir(parent_path(path)).unwrap();
        for entry in entries {
            if entry.unwrap().file_name() == OsString::from(last_element.clone()) {
                return true;
            }
        }
        false
    }

    fn remove_file(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(self.fs.remove_file(path)?)
    }

    fn remove_dir(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(self.fs.remove_dir_all(path)?)
    }

    fn copy_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        self.fs.copy(_src, _dest)?;
        Ok(())
    }

    fn move_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        self.copy_file(_src, _dest)?;
        self.remove_file(_src)
    }

    fn move_dir(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        unimplemented!()
    }
}
