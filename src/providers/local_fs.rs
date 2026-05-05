use crate::cryptofs::{DirEntry, File, FileSystem, FileSystemError, Metadata, OpenOptions, Stats};
use fs2::statvfs;
use std::error::Error;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Provides access to a local filesystem
#[derive(Clone)]
pub struct LocalFs {}

impl LocalFs {
    pub fn new() -> LocalFs {
        LocalFs {}
    }
}

impl Default for LocalFs {
    fn default() -> Self {
        Self::new()
    }
}

impl File for std::fs::File {
    fn metadata(&self) -> Result<Metadata, Box<dyn Error>> {
        Ok(Metadata::from(self.metadata()?))
    }

    fn fsync(&mut self) -> std::io::Result<()> {
        self.sync_all()
    }

    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        std::fs::File::set_len(self, len)
    }
}

fn reject_symlink_components<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn Error>> {
    let path = path.as_ref();
    let mut current = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(Box::new(FileSystemError::InvalidPathError(
                    path.display().to_string(),
                )));
            }
            Component::Normal(part) => {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(Box::new(FileSystemError::SymlinkRejected(
                            current.display().to_string(),
                        )));
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
                    Err(err) => return Err(Box::new(err)),
                }
            }
        }
    }

    Ok(())
}

impl FileSystem for LocalFs {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, Box<dyn Error>> {
        reject_symlink_components(&path)?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            entries.push(DirEntry {
                path: entry.path(),
                metadata: Metadata::from(metadata),
                file_name: entry.file_name(),
            });
        }
        Ok(Box::new(entries.into_iter()))
    }

    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        reject_symlink_components(&path)?;
        Ok(fs::create_dir(path)?)
    }

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        reject_symlink_components(&path)?;
        Ok(fs::create_dir_all(path)?)
    }

    fn open_file<P: AsRef<Path>>(
        &self,
        path: P,
        options: OpenOptions,
    ) -> Result<Box<dyn File>, Box<dyn Error>> {
        reject_symlink_components(&path)?;
        Ok(Box::new(
            fs::OpenOptions::new()
                .create(options.create)
                .write(options.write)
                .read(options.read)
                .truncate(options.truncate)
                .create_new(options.create_new)
                .append(options.append)
                .open(path)?,
        ))
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, Box<dyn Error>> {
        reject_symlink_components(&path)?;
        Ok(Box::new(
            fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .read(true)
                .open(path)?,
        ))
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        if reject_symlink_components(&path).is_err() {
            return false;
        }
        Path::exists(Path::new(path.as_ref()))
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        reject_symlink_components(&path)?;
        Ok(fs::remove_file(path)?)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        reject_symlink_components(&path)?;
        Ok(fs::remove_dir_all(path)?)
    }

    fn copy_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        reject_symlink_components(&_src)?;
        reject_symlink_components(&_dest)?;
        fs::copy(_src, _dest)?;
        Ok(())
    }

    fn move_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        reject_symlink_components(&_src)?;
        reject_symlink_components(&_dest)?;
        Ok(fs::rename(_src, _dest)?)
    }

    fn move_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        reject_symlink_components(&_src)?;
        reject_symlink_components(&_dest)?;
        Ok(fs::rename(_src, _dest)?)
    }

    fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, Box<dyn Error>> {
        reject_symlink_components(&path)?;
        let metadata = fs::metadata(path)?;
        Ok(Metadata::from(metadata))
    }

    fn stats<P: AsRef<Path>>(&self, path: P) -> Result<Stats, Box<dyn Error>> {
        reject_symlink_components(&path)?;
        let stats = statvfs(path)?;
        Ok(Stats {
            free_space: stats.free_space(),
            available_space: stats.available_space(),
            total_space: stats.total_space(),
            allocation_granularity: stats.allocation_granularity(),
        })
    }
}
