use crate::cryptofs::{DirEntry, File, FileSystem, Metadata, OpenOptions, Stats};
use fs2::statvfs;
use std::error::Error;
use std::fs;
use std::path::Path;

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
}

impl FileSystem for LocalFs {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, Box<dyn Error>> {
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

    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        Ok(fs::create_dir(path)?)
    }

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        Ok(fs::create_dir_all(path)?)
    }

    fn open_file<P: AsRef<Path>>(
        &self,
        path: P,
        options: OpenOptions,
    ) -> Result<Box<dyn File>, Box<dyn Error>> {
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
        Ok(Box::new(
            fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .read(true)
                .open(path)?,
        ))
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        Path::exists(Path::new(path.as_ref()))
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        Ok(fs::remove_file(path)?)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        Ok(fs::remove_dir_all(path)?)
    }

    fn copy_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        fs::copy(_src, _dest)?;
        Ok(())
    }

    fn move_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        self.copy_file(&_src, &_dest)?;
        self.remove_file(_src)
    }

    fn move_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), Box<dyn Error>> {
        // well, there is no call of this method from CryptoFS at this moment and i'm too lazy to
        // implement the method for no reason.
        //TODO: implement this method
        unimplemented!();
    }

    fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, Box<dyn Error>> {
        let metadata = fs::metadata(path)?;
        Ok(Metadata::from(metadata))
    }

    fn stats<P: AsRef<Path>>(&self, path: P) -> Result<Stats, Box<dyn Error>> {
        let stats = statvfs(path)?;
        Ok(Stats {
            free_space: stats.free_space(),
            available_space: stats.available_space(),
            total_space: stats.total_space(),
            allocation_granularity: stats.allocation_granularity(),
        })
    }
}
