use crate::cryptofs::{
    DirEntry, File, FileSystem, Metadata, OpenOptions as cryptoOpenOptions, Stats,
    last_path_component, parent_path,
};
use rsfs::mem::FS;
use rsfs::{DirEntry as DE, GenFS, OpenOptions};
use std::error::Error;
use std::fmt::Debug;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

/// Simple implementation of in-memory filesystem
/// Only for testing purposes
#[derive(Clone)]
pub struct MemoryFs {
    fs: FS,
}

impl Default for MemoryFs {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct VirtualFile<F: rsfs::File> {
    f: F,
}

impl<F: rsfs::File> VirtualFile<F> {
    fn new(f: F) -> Self {
        VirtualFile { f }
    }
}

impl<F: rsfs::File + Send + Sync> File for VirtualFile<F> {
    fn metadata(&self) -> Result<Metadata, Box<dyn Error>> {
        let mut metadata = metadata_from_rsfs(self.f.metadata()?);
        let mut clone = self.f.try_clone()?;
        metadata.len = clone.seek(SeekFrom::End(0))?;
        Ok(metadata)
    }

    fn fsync(&mut self) -> std::io::Result<()> {
        self.flush()
    }

    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        self.f.set_len(len)
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

        #[cfg(unix)]
        uid: 0,
        #[cfg(unix)]
        gid: 0,
    }
}

fn dir_entry_from_rsfs<D: rsfs::DirEntry>(d: D) -> DirEntry {
    DirEntry {
        path: d.path(),
        metadata: metadata_from_rsfs(d.metadata().unwrap()),
        file_name: d.file_name(),
    }
}

impl MemoryFs {
    pub fn new() -> Self {
        MemoryFs { fs: FS::new() }
    }
}

impl FileSystem for MemoryFs {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, Box<dyn Error>> {
        let mut entries = Vec::new();
        for entry in self.fs.read_dir(path)? {
            entries.push(dir_entry_from_rsfs(entry?));
        }
        Ok(Box::new(entries.into_iter()))
    }

    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        Ok(self.fs.create_dir(path)?)
    }

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        Ok(self.fs.create_dir_all(path)?)
    }

    fn open_file<P: AsRef<Path>>(
        &self,
        path: P,
        options: cryptoOpenOptions,
    ) -> Result<Box<dyn File>, Box<dyn Error>> {
        Ok(Box::new(VirtualFile::new(
            self.fs
                .new_openopts()
                .read(options.read)
                .write(options.write)
                .truncate(options.truncate)
                .append(options.append)
                .create(options.create)
                .create_new(options.create_new)
                .open(path)?,
        )))
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, Box<dyn Error>> {
        Ok(Box::new(VirtualFile::new(
            self.fs
                .new_openopts()
                .read(true)
                .write(true)
                .create_new(true)
                .create(true)
                .open(path)?,
        )))
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        let last_element = match last_path_component(&path) {
            Ok(last_element) => last_element,
            Err(_) => return false,
        };
        let Ok(mut entries) = self.fs.read_dir(parent_path(&path)) else {
            return false;
        };
        entries.any(|de| {
            de.map(|entry| entry.file_name() == *last_element)
                .unwrap_or(false)
        })
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        Ok(self.fs.remove_file(path)?)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        Ok(self.fs.remove_dir_all(path)?)
    }

    fn copy_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        self.fs.copy(_src, _dest)?;
        Ok(())
    }

    fn move_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        Ok(self.fs.rename(_src, _dest)?)
    }

    fn move_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        Ok(self.fs.rename(_src, _dest)?)
    }

    fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, Box<dyn Error>> {
        let metadata = self.fs.metadata(&path)?;
        let mut metadata = metadata_from_rsfs(metadata);
        if metadata.is_file {
            let mut file = self.fs.new_openopts().read(true).open(path)?;
            metadata.len = file.seek(SeekFrom::End(0))?;
        }
        Ok(metadata)
    }

    fn stats<P: AsRef<Path>>(&self, _path: P) -> Result<Stats, Box<dyn Error>> {
        Ok(Default::default())
    }
}
