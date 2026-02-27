use crate::crypto::{
    Cryptor, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH, FILE_CHUNK_LENGTH, FILE_HEADER_LENGTH, FileHeader,
    calculate_cleartext_size, shorten_name,
};
use crate::cryptofs::error::FileSystemError::{InvalidPathError, PathDoesNotExist};
use crate::cryptofs::filesystem::Metadata;
use crate::cryptofs::{
    DirEntry, File, FileSystem, FileSystemError, OpenOptions, Stats, last_path_component,
    parent_path,
};
use lru_cache::LruCache;
use std::collections::hash_map::DefaultHasher;
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::error;
use zeroize::Zeroizing;

/// Extension of encrypted filename
const ENCRYPTED_FILE_EXT: &str = ".c9r";

const SHORTEN_FILENAME_EXT: &str = ".c9s";

/// Name of a file that contains dir_id
const DIR_FILENAME: &str = "dir.c9r";

/// Name of a file that contains full encrypted name
const FULL_NAME_FILENAME: &str = "name.c9s";

/// Name of a file that contains contents of a shorten file
const CONTENTS_FILENAME: &str = "contents.c9r";

struct CacheShard {
    dir_uuids: LruCache<PathBuf, Vec<u8>>,
    dir_entries: LruCache<PathBuf, DirEntry>,
    shortened_names: LruCache<PathBuf, String>,
}

struct CryptoFsCaches {
    shards: Vec<Mutex<CacheShard>>,
    shard_mask: usize,
}

impl CryptoFsCaches {
    fn new(capacity: usize, num_shards: usize) -> Self {
        let num_shards = num_shards.max(1).next_power_of_two();
        let shard_cap = capacity.div_ceil(num_shards);
        let shard_cap = shard_cap.max(1);
        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(Mutex::new(CacheShard {
                dir_uuids: LruCache::new(shard_cap),
                dir_entries: LruCache::new(shard_cap),
                shortened_names: LruCache::new(shard_cap),
            }));
        }
        Self {
            shards,
            shard_mask: num_shards - 1,
        }
    }

    fn get_shard(&self, path: &Path) -> &Mutex<CacheShard> {
        let mut s = DefaultHasher::new();
        path.hash(&mut s);
        let hash = s.finish() as usize;
        &self.shards[hash & self.shard_mask]
    }
}

// TODO: make configurable
/// Chunk cache capacity for per files
const CHUNK_CACHE_CAP: usize = 500;

#[derive(Clone, Debug, Copy)]
pub struct CryptoFsConfig {
    pub chunk_cache_cap: usize,
    pub read_only: bool,
}

impl Default for CryptoFsConfig {
    fn default() -> Self {
        CryptoFsConfig {
            chunk_cache_cap: CHUNK_CACHE_CAP,
            read_only: false,
        }
    }
}

pub struct CryptoPath {
    full_path: PathBuf,
    is_shorten: bool,
}

impl AsRef<Path> for CryptoPath {
    fn as_ref(&self) -> &Path {
        self.full_path.as_ref()
    }
}

/// Provides an access to an encrypted storage
/// In a nutshell, translates all the 'virtual' paths, like '/some_folder/file.txt', to real paths,
/// like /d/DR/RW3L6XRAPFC2UCK5QY37Q2U552IRPE/eZdOa_B9fRqncpYjZmKXfJEz81LgRUbT0yWdE0wyNTMd.c9r
#[derive(Clone)]
pub struct CryptoFs<FS: FileSystem> {
    /// Instance of the Cryptor - does all work with cryptography
    cryptor: Cryptor,

    /// path to an encrypted storage
    root_folder: PathBuf,

    /// Instance of the FileSystem. Should provide access to a real files.
    file_system_provider: FS,

    caches: Arc<CryptoFsCaches>,
    config: CryptoFsConfig,
}

impl<FS: 'static + FileSystem> CryptoFs<FS> {
    /// Returns a new instance of CryptoFS
    pub fn new(
        folder: &str,
        cryptor: Cryptor,
        fs_provider: FS,
    ) -> Result<CryptoFs<FS>, FileSystemError> {
        Self::with_config(folder, cryptor, fs_provider, CryptoFsConfig::default())
    }

    /// Returns a new instance of CryptoFS with read-only mode
    pub fn new_read_only(
        folder: &str,
        cryptor: Cryptor,
        fs_provider: FS,
    ) -> Result<CryptoFs<FS>, FileSystemError> {
        let config = CryptoFsConfig {
            read_only: true,
            ..Default::default()
        };
        Self::with_config(folder, cryptor, fs_provider, config)
    }

    pub fn with_config(
        folder: &str,
        cryptor: Cryptor,
        fs_provider: FS,
        config: CryptoFsConfig,
    ) -> Result<CryptoFs<FS>, FileSystemError> {
        let crypto_fs = CryptoFs {
            cryptor,
            root_folder: PathBuf::from(folder),
            file_system_provider: fs_provider,
            caches: Arc::new(CryptoFsCaches::new(5000, 16)),
            config,
        };
        let root = crypto_fs.real_path_from_dir_id(b"")?;
        if !crypto_fs.config.read_only {
            crypto_fs.file_system_provider.create_dir_all(root)?;
        }
        Ok(crypto_fs)
    }

    /// Returns true if the filesystem is in read-only mode
    pub fn is_read_only(&self) -> bool {
        self.config.read_only
    }

    /// Returns a real path to a dir by dir_id
    pub fn real_path_from_dir_id(&self, dir_id: &[u8]) -> Result<PathBuf, FileSystemError> {
        let dir_hash = self.cryptor.get_dir_id_hash(dir_id)?;
        Ok(self.root_folder.join(&dir_hash[..2]).join(&dir_hash[2..]))
    }

    fn lock_shard(&self, path: &Path) -> Result<MutexGuard<CacheShard>, FileSystemError> {
        self.caches
            .get_shard(path)
            .lock()
            .map_err(|e| FileSystemError::UnknownError(e.to_string()))
    }

    fn shorten_if_needed(&self, encrypted_name: String) -> (String, bool) {
        if encrypted_name.len() > self.cryptor.vault.claims.shorteningThreshold as usize {
            (shorten_name(&encrypted_name) + SHORTEN_FILENAME_EXT, true)
        } else {
            (encrypted_name, false)
        }
    }

    fn os_str_to_utf8<'a>(&self, value: &'a std::ffi::OsStr) -> Result<&'a str, FileSystemError> {
        value
            .to_str()
            .ok_or_else(|| FileSystemError::InvalidPathError(value.to_string_lossy().into_owned()))
    }

    /// Returns a dir_id for a path
    /// There will be an PathIsNotExist error, if path does not exists and CryptoError cause of crypto errors
    pub fn dir_id_from_path<P: AsRef<Path>>(&self, path: P) -> Result<Vec<u8>, FileSystemError> {
        let mut dir_id: Vec<u8> = Vec::new();
        for component in Path::new(path.as_ref()).components() {
            match component {
                std::path::Component::RootDir => dir_id.clear(),
                std::path::Component::Normal(path_name) => {
                    let cleartext_name = self.os_str_to_utf8(path_name)?;
                    dir_id = self.resolve_component(&dir_id, cleartext_name)?;
                }
                other => {
                    let component_str = other.as_os_str().to_string_lossy().to_string();
                    error!("Invalid path component: {:?}", component_str);
                    return Err(InvalidPathError(component_str));
                }
            }
        }
        Ok(dir_id)
    }

    fn resolve_component(
        &self,
        current_dir_id: &[u8],
        component_name: &str,
    ) -> Result<Vec<u8>, FileSystemError> {
        let encrypted_name = self
            .cryptor
            .encrypt_filename(component_name, current_dir_id)?;
        let (full_encrypted_name, _) = self.shorten_if_needed(encrypted_name + ENCRYPTED_FILE_EXT);

        let mut full_path = self.real_path_from_dir_id(current_dir_id)?;
        full_path.push(&full_encrypted_name);

        if let Some(cached_dir_id) = {
            let mut shard = self.lock_shard(&full_path)?;
            shard.dir_uuids.get_mut(&full_path).cloned()
        } {
            return Ok(cached_dir_id);
        }

        let mut dir_uuid = Vec::new();
        if self.file_system_provider.exists(&full_path) {
            let mut reader = self
                .file_system_provider
                .open_file(full_path.join(DIR_FILENAME), OpenOptions::new())?;
            reader.read_to_end(&mut dir_uuid)?;
        }

        if dir_uuid.is_empty() {
            error!("Path {:?} doesn't exist", component_name);
            return Err(PathDoesNotExist(component_name.to_string()));
        }

        {
            let mut shard = self.lock_shard(&full_path)?;
            shard.dir_uuids.insert(full_path, dir_uuid.clone());
        }

        Ok(dir_uuid)
    }

    /// Translates a 'virtual' path to a real path
    pub fn filepath_to_real_path<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<CryptoPath, FileSystemError> {
        // dav-server::parent() method returns an empty path for root paths, like "/file.txt",
        // "/some_folder", so that's a little hack to handle this bug (is it a bug btw?)
        if path.as_ref().eq(Path::new("")) {
            let real_dir_path = self.real_path_from_dir_id(&[])?;
            return Ok(CryptoPath {
                full_path: real_dir_path,
                is_shorten: false,
            });
        }

        let filename = last_path_component(&path)?;
        let parent = parent_path(&path);

        let dir_id = self.dir_id_from_path(&parent)?;
        let real_dir_path = self.real_path_from_dir_id(dir_id.as_slice())?;

        // return only dir path cause the path is not a path to a file
        if filename == parent {
            return Ok(CryptoPath {
                full_path: real_dir_path,
                is_shorten: false,
            });
        }

        let filename_str = self.os_str_to_utf8(filename.as_os_str())?;

        let real_filename = self
            .cryptor
            .encrypt_filename(filename_str, dir_id.as_slice())?;
        let full_encrypted_name = real_filename.clone() + ENCRYPTED_FILE_EXT;
        let (full_name, is_shorten) = self.shorten_if_needed(full_encrypted_name);

        let mut full_path = real_dir_path;
        full_path.push(&full_name);

        if is_shorten {
            let mut shard = self.lock_shard(&full_path)?;
            shard
                .shortened_names
                .insert(full_path.clone(), real_filename);
        }

        Ok(CryptoPath {
            full_path,
            is_shorten,
        })
    }

    /// Returns "virtual" DirEntry with "virtual" metadata by given real DirEntry
    fn virtual_dir_entry_from_real(
        &self,
        de: DirEntry,
        dir_id: &[u8],
        virtual_parent_path: &Path,
    ) -> Result<DirEntry, FileSystemError> {
        let real_path = de.path.clone();
        if let Some(virtual_dir_entry) = {
            let mut shard = self.lock_shard(&real_path)?;
            shard.dir_entries.get_mut(&real_path).cloned()
        } {
            return Ok(virtual_dir_entry);
        }

        let mut metadata = de.metadata;
        let mut ciphertext_filename = de.filename_without_extension();
        if de.filename_string()?.ends_with(SHORTEN_FILENAME_EXT) {
            let cached_name = {
                let mut shard = self.lock_shard(&real_path)?;
                shard.shortened_names.get_mut(&real_path).cloned()
            };

            ciphertext_filename = if let Some(name) = cached_name {
                name
            } else {
                let mut read_name: Vec<u8> = vec![];
                let mut fname_file = self
                    .file_system_provider
                    .open_file(de.path.join(FULL_NAME_FILENAME), OpenOptions::new())?;
                fname_file.read_to_end(&mut read_name)?;
                let full_name = String::from_utf8(read_name)?;
                let name = if let Some(filename) = full_name.strip_suffix(ENCRYPTED_FILE_EXT) {
                    filename.to_string()
                } else {
                    return Err(FileSystemError::UnknownError(String::from(
                        "shorten file consists invalid ciphertext filename",
                    )));
                };
                let mut shard = self.lock_shard(&real_path)?;
                if let Some(existing) = shard.shortened_names.get_mut(&real_path).cloned() {
                    existing
                } else {
                    shard
                        .shortened_names
                        .insert(real_path.clone(), name.clone());
                    name
                }
            };

            if let Ok(m) = self
                .file_system_provider
                .metadata(de.path.join(CONTENTS_FILENAME))
            {
                metadata = m;
            }
        }
        metadata.len = if !metadata.is_dir {
            calculate_cleartext_size(metadata.len)
        } else {
            metadata.len
        };

        let decrypted_filename = self.cryptor.decrypt_filename(ciphertext_filename, dir_id)?;
        let virtual_dir_entry = DirEntry {
            path: virtual_parent_path.join(&decrypted_filename),
            metadata,
            file_name: OsString::from(decrypted_filename),
        };

        let mut shard = self.lock_shard(&real_path)?;
        shard
            .dir_entries
            .insert(real_path, virtual_dir_entry.clone());

        Ok(virtual_dir_entry)
    }

    /// Creates additional filesystem entries (like "name.c9s" and parent folder)
    /// for name shortening support
    fn create_additional_shorten_entries<P: AsRef<Path>>(
        &self,
        real_path: P,
        virtual_path: P,
    ) -> Result<(), FileSystemError> {
        if !self.file_system_provider.exists(&real_path) {
            self.file_system_provider.create_dir(&real_path)?;
        }
        if self
            .file_system_provider
            .exists(real_path.as_ref().join(FULL_NAME_FILENAME))
        {
            self.file_system_provider
                .remove_file(real_path.as_ref().join(FULL_NAME_FILENAME))?;
        }
        let mut full_name_file = self
            .file_system_provider
            .create_file(real_path.as_ref().join(FULL_NAME_FILENAME))?;

        let virtual_filename = last_path_component(&virtual_path)?;
        let virtual_filename_str = self.os_str_to_utf8(virtual_filename.as_os_str())?;

        let full_encrypted_name = self.cryptor.encrypt_filename(
            virtual_filename_str,
            self.dir_id_from_path(parent_path(&virtual_path))?
                .as_slice(),
        )?;
        full_name_file.write_all((full_encrypted_name + ENCRYPTED_FILE_EXT).as_bytes())?;
        Ok(())
    }

    /// Returns an iterator of DirEntries for the given path
    pub fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError> {
        let dir_id = self.dir_id_from_path(&path)?;
        let real_path = self.real_path_from_dir_id(dir_id.as_slice())?;
        let virtual_parent_path = path.as_ref().to_path_buf();
        let dir_entries: Result<Vec<DirEntry>, FileSystemError> = self
            .file_system_provider
            .read_dir(real_path)?
            .map(|de| self.virtual_dir_entry_from_real(de, dir_id.as_slice(), &virtual_parent_path))
            .collect();
        Ok(Box::new(dir_entries?.into_iter()))
    }

    /// Creates the directory at this path
    /// Similar to create_dir_all()
    pub fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let mut current_dir_id: Vec<u8> = vec![];

        for component in path.as_ref().components() {
            match component {
                std::path::Component::RootDir => current_dir_id.clear(),
                std::path::Component::Normal(path_name) => {
                    let component_name = self.os_str_to_utf8(path_name)?;

                    match self.resolve_component(&current_dir_id, component_name) {
                        Ok(id) => current_dir_id = id,
                        Err(FileSystemError::PathDoesNotExist(_)) => {
                            current_dir_id =
                                self.create_dir_entry(&current_dir_id, component_name)?;
                        }
                        Err(e) => return Err(e),
                    }
                }
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    return Err(FileSystemError::InvalidPathError(
                        ".. is not supported".to_string(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Internal helper to create a directory entry (dir.c9r, name.c9s, and sharded content folder)
    fn create_dir_entry(
        &self,
        parent_dir_id: &[u8],
        name: &str,
    ) -> Result<Vec<u8>, FileSystemError> {
        let encrypted_name = self.cryptor.encrypt_filename(name, parent_dir_id)?;
        let full_encrypted_name = encrypted_name + ENCRYPTED_FILE_EXT;
        let (storage_name, is_shorten) = self.shorten_if_needed(full_encrypted_name.clone());

        let mut real_path = self.real_path_from_dir_id(parent_dir_id)?;
        real_path.push(&storage_name);

        self.file_system_provider.create_dir_all(&real_path)?;

        if is_shorten {
            let mut name_writer = self
                .file_system_provider
                .create_file(real_path.join(FULL_NAME_FILENAME))?;
            name_writer.write_all(full_encrypted_name.as_bytes())?;
        }

        let dir_uuid_bytes = uuid::Uuid::new_v4().to_string().into_bytes();
        let mut writer = self
            .file_system_provider
            .create_file(real_path.join(DIR_FILENAME))?;
        writer.write_all(&dir_uuid_bytes)?;

        let real_folder_path = self.real_path_from_dir_id(&dir_uuid_bytes)?;
        self.file_system_provider
            .create_dir_all(&real_folder_path)?;

        {
            let mut shard = self.lock_shard(&real_path)?;
            shard.dir_uuids.insert(real_path, dir_uuid_bytes.clone());
        }

        Ok(dir_uuid_bytes)
    }

    pub fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        self.create_dir(path)
    }

    pub fn open_file<P: AsRef<Path>>(
        &self,
        path: P,
        options: OpenOptions,
    ) -> Result<CryptoFsFile, FileSystemError> {
        let mut real_path = self.filepath_to_real_path(path)?;
        if real_path.is_shorten {
            real_path.full_path = real_path.full_path.join(CONTENTS_FILENAME);
        }
        let crypto_file = CryptoFsFile::open(
            real_path,
            self.cryptor.clone(),
            &self.file_system_provider,
            options,
            self.config.chunk_cache_cap,
            self.config.read_only,
        )?;
        Ok(crypto_file)
    }

    pub fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<CryptoFsFile, FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let mut real_path = self.filepath_to_real_path(&path)?;
        if real_path.is_shorten {
            #[allow(clippy::unnecessary_to_owned)]
            self.create_additional_shorten_entries(
                &real_path.full_path,
                &path.as_ref().to_path_buf(),
            )?;

            real_path.full_path = real_path.full_path.join(CONTENTS_FILENAME);
        }
        let reader = self.file_system_provider.create_file(real_path.full_path)?;
        let crypto_file =
            CryptoFsFile::create_file(self.cryptor.clone(), reader, self.config.chunk_cache_cap)?;
        Ok(crypto_file)
    }

    pub fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        let real_path = match self.filepath_to_real_path(path) {
            Ok(p) => p,
            Err(_) => return false,
        };
        self.file_system_provider.exists(real_path)
    }

    pub fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let real_path = self.filepath_to_real_path(&path)?;
        let key = real_path.full_path.clone();
        let is_shorten = real_path.is_shorten;

        if is_shorten {
            self.file_system_provider.remove_dir(real_path)?;
        } else {
            self.file_system_provider.remove_file(real_path)?;
        }

        self.invalidate_caches(&key)?;
        if is_shorten {
            self.invalidate_caches(key.join(FULL_NAME_FILENAME))?;
            self.invalidate_caches(key.join(CONTENTS_FILENAME))?;
        }

        Ok(())
    }

    pub fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let real_dir_path = self.filepath_to_real_path(&path)?;
        let dir_entries = self.read_dir(&path)?;

        for entry in dir_entries {
            let mut full_path = path.as_ref().to_path_buf();
            full_path.push(&entry.file_name);

            if entry.metadata.is_dir {
                self.remove_dir(&full_path)?;
            } else {
                self.remove_file(&full_path)?;
            }
        }

        self.invalidate_caches(&real_dir_path.full_path)?;

        Ok(self.file_system_provider.remove_dir(real_dir_path)?)
    }

    pub fn copy_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let mut src_real_path = self.filepath_to_real_path(_src)?;
        let mut dst_real_path = self.filepath_to_real_path(&_dest)?;

        if src_real_path.is_shorten {
            src_real_path.full_path = src_real_path.full_path.join(CONTENTS_FILENAME);
        }
        if dst_real_path.is_shorten {
            #[allow(clippy::unnecessary_to_owned)]
            self.create_additional_shorten_entries(
                &dst_real_path.full_path,
                &_dest.as_ref().to_path_buf(),
            )?;

            dst_real_path.full_path = dst_real_path.full_path.join(CONTENTS_FILENAME);
        }

        Ok(self
            .file_system_provider
            .copy_file(src_real_path, dst_real_path)?)
    }

    pub fn copy_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let src_dir_entries = self.read_dir(&_src)?;

        let mut dst_path = _dest.as_ref();
        let mut dst_path_builder = PathBuf::new();
        if !self.exists(&_dest) {
            self.create_dir(&_dest)?;
        } else {
            let src_dir_name = last_path_component(&_src)?;
            dst_path_builder = dst_path_builder.join(_dest).join(src_dir_name);
            dst_path = dst_path_builder.as_path();
            self.create_dir(dst_path)?;
        }

        let src_root = _src.as_ref();
        for entry in src_dir_entries {
            let dst_full_path = dst_path.join(&entry.file_name);
            let src_full_path = src_root.join(&entry.file_name);

            if entry.metadata.is_dir {
                self.copy_dir(src_full_path, dst_full_path)?;
            } else {
                self.copy_file(src_full_path, dst_full_path)?;
            }
        }
        Ok(())
    }

    pub fn copy_path<P: AsRef<Path>>(&self, src: P, dest: P) -> Result<(), FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let metadata = self.metadata(&src)?;
        if metadata.is_dir {
            self.copy_dir(src, dest)
        } else {
            self.copy_file(src, dest)
        }
    }

    pub fn move_path<P: AsRef<Path>>(&self, src: P, dest: P) -> Result<(), FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let metadata = self.metadata(&src)?;
        if metadata.is_dir {
            self.move_dir(src, dest)
        } else {
            self.move_file(src, dest)
        }
    }

    pub fn move_file<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        self.copy_file(&_src, &_dest)?;
        self.remove_file(&_src)
    }

    pub fn move_dir<P: AsRef<Path>>(&self, _src: P, _dest: P) -> Result<(), FileSystemError> {
        if self.config.read_only {
            return Err(FileSystemError::ReadOnly);
        }
        let src_dir_entries = self.read_dir(&_src)?;

        let mut dst_path = _dest.as_ref();
        let mut dst_path_builder = PathBuf::new();
        if !self.exists(&_dest) {
            self.create_dir(&_dest)?;
        } else {
            let src_dir_name = last_path_component(&_src)?;
            dst_path_builder = dst_path_builder.join(_dest).join(src_dir_name);
            dst_path = dst_path_builder.as_path();
            self.create_dir(dst_path)?;
        }

        let src_root = _src.as_ref();
        for entry in src_dir_entries {
            let dst_full_path = dst_path.join(&entry.file_name);
            let src_full_path = src_root.join(&entry.file_name);

            if entry.metadata.is_dir {
                self.move_dir(src_full_path, dst_full_path)?;
            } else {
                self.move_file(src_full_path, dst_full_path)?;
            }
        }
        self.remove_dir(_src)
    }

    pub fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, FileSystemError> {
        let real_path = self.filepath_to_real_path(path)?;
        let mut metadata = if real_path.is_shorten {
            let contents_file = real_path.full_path.join(CONTENTS_FILENAME);
            if self.file_system_provider.exists(&contents_file) {
                self.file_system_provider.metadata(&contents_file)?
            } else {
                self.file_system_provider.metadata(real_path)?
            }
        } else {
            self.file_system_provider.metadata(real_path)?
        };
        if !metadata.is_dir {
            metadata.len = calculate_cleartext_size(metadata.len);
        }
        Ok(metadata)
    }

    pub fn stats<P: AsRef<Path>>(&self, path: P) -> Result<Stats, FileSystemError> {
        let dir_id = self.dir_id_from_path(path)?;
        let real_path = self.real_path_from_dir_id(dir_id.as_slice())?;

        Ok(self.file_system_provider.stats(real_path)?)
    }

    fn invalidate_caches<P: AsRef<Path>>(&self, real_path: P) -> Result<(), FileSystemError> {
        let path = real_path.as_ref();
        let mut shard = self.lock_shard(path)?;
        shard.dir_entries.remove(path);
        shard.dir_uuids.remove(path);
        shard.shortened_names.remove(path);
        Ok(())
    }
}

/// Buffer for filling gaps with zeros
static ZEROS: [u8; FILE_CHUNK_CONTENT_PAYLOAD_LENGTH] = [0u8; FILE_CHUNK_CONTENT_PAYLOAD_LENGTH];

/// 'Virtual' file implementation of the File trait
#[derive(Debug)]
pub struct CryptoFsFile {
    /// A Cryptor instance used to encrypt/decrypt data
    cryptor: Cryptor,

    /// Real filesystem file instance used to perform File(Read, Write, Seek) operations
    rfs_file: Box<dyn File>,

    /// Keeps info about 'virtual' cursor for the 'virtual' file
    current_pos: u64,

    /// FileHeader of the file
    header: FileHeader,

    /// Metadata of the file
    metadata: Metadata,

    /// Real size of the file
    real_len: u64,

    /// Stores the most frequently used chunks of the file to decrease read operations
    chunk_cache: LruCache<u64, Zeroizing<Vec<u8>>>,

    /// Buffer for reading chunks to avoid repeated allocations
    read_buffer: Zeroizing<Vec<u8>>,

    /// Buffer for encrypting chunks to avoid repeated allocations
    write_buffer: Zeroizing<Vec<u8>>,

    /// If true, write operations are blocked
    read_only: bool,
}

impl CryptoFsFile {
    /// Opens a file at the given real path (so the path must be translated from 'virtual' to real before the
    /// function call) for reading/writing.
    /// Read/Write implementations for the traits works with a cleartext data, so CryptoFSFile instance
    /// must contain the Cryptor
    pub fn open<P: AsRef<Path>, FS: FileSystem>(
        real_path: P,
        cryptor: Cryptor,
        real_file_system_provider: &FS,
        options: OpenOptions,
        chunk_cache_cap: usize,
        read_only: bool,
    ) -> Result<CryptoFsFile, FileSystemError> {
        let mut reader = real_file_system_provider.open_file(real_path, options)?;
        let mut encrypted_header: [u8; FILE_HEADER_LENGTH] = [0; FILE_HEADER_LENGTH];

        reader.read_exact(&mut encrypted_header)?;

        let header = cryptor.decrypt_file_header(&encrypted_header)?;
        let mut metadata = reader.metadata()?;
        let real_len = metadata.len;
        if !metadata.is_dir {
            metadata.len = calculate_cleartext_size(metadata.len);
        }
        Ok(CryptoFsFile {
            cryptor,
            rfs_file: reader,
            current_pos: 0,
            header,
            metadata,
            real_len,
            chunk_cache: LruCache::new(chunk_cache_cap),
            read_buffer: Zeroizing::new(Vec::with_capacity(FILE_CHUNK_LENGTH)),
            write_buffer: Zeroizing::new(Vec::with_capacity(FILE_CHUNK_LENGTH)),
            read_only,
        })
    }

    /// Creates a file at the given real path (so the path must be translated from 'virtual' to real before the
    /// function call).
    /// Read/Write implementations for the traits works with a cleartext data, so CryptoFSFile instance
    /// must contain the Cryptor
    pub fn create_file(
        cryptor: Cryptor,
        mut rfs_file: Box<dyn File>,
        chunk_cache_cap: usize,
    ) -> Result<CryptoFsFile, FileSystemError> {
        let header = cryptor.create_file_header();
        let encrypted_header = cryptor.encrypt_file_header(&header)?;
        rfs_file.write_all(encrypted_header.as_slice())?;
        rfs_file.flush()?;
        let mut metadata = rfs_file.metadata()?;
        let real_len = metadata.len;
        if !metadata.is_dir {
            metadata.len = calculate_cleartext_size(metadata.len);
        }
        Ok(CryptoFsFile {
            cryptor,
            rfs_file,
            current_pos: 0,
            header,
            metadata,
            real_len,
            chunk_cache: LruCache::new(chunk_cache_cap),
            read_buffer: Zeroizing::new(Vec::with_capacity(FILE_CHUNK_LENGTH)),
            write_buffer: Zeroizing::new(Vec::with_capacity(FILE_CHUNK_LENGTH)),
            read_only: false,
        })
    }

    /// Returns a cleartext size of the file
    pub fn file_size(&mut self) -> Result<u64, FileSystemError> {
        let current_pos = self.rfs_file.stream_position()?;
        let real_file_size = self.rfs_file.seek(SeekFrom::End(0))?;
        self.rfs_file.seek(SeekFrom::Start(current_pos))?;
        Ok(calculate_cleartext_size(real_file_size))
    }

    /// Return a real size of the file
    pub fn real_file_size(&mut self) -> Result<u64, FileSystemError> {
        let current_pos = self.rfs_file.stream_position()?;
        let real_file_size = self.rfs_file.seek(SeekFrom::End(0))?;
        self.rfs_file.seek(SeekFrom::Start(current_pos))?;
        Ok(real_file_size)
    }

    /// Updates metadata according to a real file
    fn update_metadata(&mut self) -> Result<(), FileSystemError> {
        let current_pos = self.rfs_file.stream_position()?;
        let real_len = self.rfs_file.seek(SeekFrom::End(0))?;
        self.rfs_file.seek(SeekFrom::Start(current_pos))?;

        let real_metadata = self.rfs_file.metadata()?;
        self.real_len = real_len;
        self.metadata = real_metadata;
        self.metadata.len = calculate_cleartext_size(self.real_len);
        Ok(())
    }

    fn refresh_metadata(&mut self) -> Result<(), FileSystemError> {
        let real_metadata = self.rfs_file.metadata()?;
        let new_len = calculate_cleartext_size(real_metadata.len);
        if real_metadata.modified != self.metadata.modified
            || new_len != self.metadata.len
            || real_metadata.len != self.real_len
        {
            self.chunk_cache.clear();
        }
        self.metadata.len = new_len;
        self.metadata.modified = real_metadata.modified;
        self.real_len = real_metadata.len;
        Ok(())
    }

    /// Ensures the cleartext chunk is present in the cache.
    ///
    /// `total_cleartext_size` must reflect the current cleartext file length.
    fn load_chunk(
        &mut self,
        chunk_index: u64,
        mut total_cleartext_size: u64,
    ) -> Result<(), FileSystemError> {
        let payload_len = FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64;
        let chunk_start_clear = chunk_index * payload_len;
        if total_cleartext_size <= chunk_start_clear && self.refresh_metadata().is_ok() {
            total_cleartext_size = self.metadata.len;
        }

        let expected_plain_len = if total_cleartext_size > chunk_start_clear {
            std::cmp::min(payload_len, total_cleartext_size - chunk_start_clear) as usize
        } else {
            0
        };

        if let Some(cached) = self.chunk_cache.get_mut(&chunk_index) {
            if cached.len() < expected_plain_len {
                self.chunk_cache.remove(&chunk_index);
            } else {
                return Ok(());
            }
        }

        self.rfs_file.seek(SeekFrom::Start(
            (chunk_index * FILE_CHUNK_LENGTH as u64) + FILE_HEADER_LENGTH as u64,
        ))?;

        self.read_buffer.resize(FILE_CHUNK_LENGTH, 0);
        let read_bytes = self.rfs_file.read(&mut self.read_buffer)?;

        if read_bytes == 0 {
            if expected_plain_len > 0 {
                if self.refresh_metadata().is_ok() && self.metadata.len <= chunk_start_clear {
                    self.chunk_cache
                        .insert(chunk_index, Zeroizing::new(Vec::new()));
                    return Ok(());
                }
                error!(
                    chunk_index,
                    "Unexpected EOF: expected {} bytes", expected_plain_len
                );
                return Err(FileSystemError::IoError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Physical file is shorter than expected",
                )));
            }
            self.chunk_cache
                .insert(chunk_index, Zeroizing::new(Vec::new()));
            return Ok(());
        }

        let chunk_slice = &self.read_buffer[..read_bytes];

        let mut decrypted_buffer = Zeroizing::new(vec![0u8; FILE_CHUNK_CONTENT_PAYLOAD_LENGTH]);
        let decrypted_len = match self.cryptor.decrypt_chunk(
            &self.header.nonce,
            self.header.payload.content_key.as_ref(),
            chunk_index,
            chunk_slice,
            &mut decrypted_buffer,
        ) {
            Ok(len) => len,
            Err(err) => {
                error!(chunk_index, "Failed to decrypt chunk: {:?}", err);
                return Err(err.into());
            }
        };

        if decrypted_len < expected_plain_len {
            error!(
                chunk_index,
                "Decrypted chunk shorter than expected: {} < {}", decrypted_len, expected_plain_len
            );
            return Err(FileSystemError::IoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Decrypted chunk shorter than expected",
            )));
        }

        decrypted_buffer.truncate(decrypted_len);
        self.chunk_cache.insert(chunk_index, decrypted_buffer);

        Ok(())
    }

    /// Internal helper to handle the Read-Modify-Write cycle for a single chunk.
    fn write_single_chunk(
        &mut self,
        chunk_idx: u64,
        offset: usize,
        data: &[u8],
        known_size: u64,
    ) -> Result<usize, FileSystemError> {
        let payload_len = FILE_CHUNK_CONTENT_PAYLOAD_LENGTH;

        // 1. Load existing data if we are partially overwriting or extending
        let mut chunk_data = if (chunk_idx * payload_len as u64) < known_size {
            self.load_chunk(chunk_idx, known_size)?;
            // Taking ownership from cache to avoid copy
            self.chunk_cache
                .remove(&chunk_idx)
                .unwrap_or_else(|| Zeroizing::new(Vec::new()))
        } else {
            Zeroizing::new(Vec::new())
        };

        // 2. Prepare buffer size
        let required_size = offset + data.len();
        if chunk_data.len() < required_size {
            chunk_data.resize(required_size, 0);
        }

        // 3. Overwrite with new data
        chunk_data[offset..required_size].copy_from_slice(data);

        // 4. Encrypt
        self.write_buffer.resize(FILE_CHUNK_LENGTH, 0);
        let encrypted_len = self.cryptor.encrypt_chunk(
            &self.header.nonce,
            self.header.payload.content_key.as_ref(),
            chunk_idx,
            &chunk_data,
            &mut self.write_buffer,
        )?;

        // 5. Commit to disk
        self.rfs_file.seek(SeekFrom::Start(
            (chunk_idx * FILE_CHUNK_LENGTH as u64) + FILE_HEADER_LENGTH as u64,
        ))?;
        self.rfs_file
            .write_all(&self.write_buffer[..encrypted_len])?;

        // 6. Update Cache
        self.chunk_cache.insert(chunk_idx, chunk_data);

        Ok(data.len())
    }
}

impl Seek for CryptoFsFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => self.current_pos = p,
            SeekFrom::Current(p) => {
                let current = i64::try_from(self.current_pos).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "current position exceeds i64::MAX",
                    )
                })?;
                let new_pos = current.checked_add(p).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek overflow")
                })?;
                if new_pos < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid seek to a negative position",
                    ));
                }
                self.current_pos = new_pos as u64;
            }
            SeekFrom::End(p) => {
                let size = match self.file_size() {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to determine cleartext file size: {:?}", e);
                        return Err(e.into());
                    }
                };
                let size = i64::try_from(size).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "file size exceeds i64::MAX",
                    )
                })?;
                let new_pos = size.checked_add(p).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek overflow")
                })?;
                if new_pos < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid seek to a negative position",
                    ));
                }
                self.current_pos = new_pos as u64;
            }
        }
        Ok(self.current_pos)
    }
}

impl Read for CryptoFsFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let payload_len = FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64;
        self.refresh_metadata().map_err(|e| {
            error!("Failed to read file metadata: {:?}", e);
            std::io::Error::from(e)
        })?;
        let mut total_plain_size = self.metadata.len;
        let mut n: usize = 0;
        while n < buf.len() {
            if self.current_pos >= total_plain_size {
                break;
            }

            let chunk_index = self.current_pos / payload_len;
            let offset = (self.current_pos % payload_len) as usize;
            self.load_chunk(chunk_index, total_plain_size)
                .map_err(|e| {
                    error!(chunk_index, "Failed to read chunk: {:?}", e);
                    std::io::Error::from(e)
                })?;
            total_plain_size = self.metadata.len;
            if self.current_pos >= total_plain_size {
                break;
            }
            let chunk_slice = if let Some(chunk) = self.chunk_cache.get_mut(&chunk_index) {
                chunk.as_slice()
            } else {
                &[]
            };

            let remaining_total = (total_plain_size - self.current_pos) as usize;
            let remaining_buf = buf.len() - n;
            let max_read = remaining_total.min(remaining_buf);
            if max_read == 0 {
                break;
            }

            let available_in_chunk = FILE_CHUNK_CONTENT_PAYLOAD_LENGTH - offset;
            let slice_len = max_read.min(available_in_chunk);

            let data_available = if offset < chunk_slice.len() {
                chunk_slice.len() - offset
            } else {
                0
            };

            let copy_len = slice_len.min(data_available);

            if copy_len > 0 {
                buf[n..n + copy_len].copy_from_slice(&chunk_slice[offset..offset + copy_len]);
                n += copy_len;
                self.current_pos += copy_len as u64;
            }

            if slice_len > copy_len {
                let zero_len = slice_len - copy_len;
                buf[n..n + zero_len].fill(0);
                n += zero_len;
                self.current_pos += zero_len as u64;
            }
        }
        Ok(n)
    }
}

impl Write for CryptoFsFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.read_only {
            return Err(FileSystemError::ReadOnly.into());
        }
        let payload_len = FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64;
        let mut known_size = self.file_size().map_err(std::io::Error::from)?;

        // If we're writing past the end of the file, fill the gap with zeros
        while known_size < self.current_pos {
            let chunk_idx = known_size / payload_len;
            let offset = (known_size % payload_len) as usize;

            let available_in_chunk = FILE_CHUNK_CONTENT_PAYLOAD_LENGTH - offset;
            let remaining_gap = (self.current_pos - known_size) as usize;
            let fill_len = available_in_chunk.min(remaining_gap);

            debug_assert!(fill_len <= ZEROS.len());
            self.write_single_chunk(chunk_idx, offset, &ZEROS[..fill_len], known_size)
                .map_err(std::io::Error::from)?;

            known_size += fill_len as u64;
        }

        let mut n: usize = 0;
        while n < buf.len() {
            let chunk_index = self.current_pos / payload_len;
            let offset_in_chunk = (self.current_pos % payload_len) as usize;
            let slice_len =
                (payload_len - offset_in_chunk as u64).min((buf.len() - n) as u64) as usize;

            self.write_single_chunk(
                chunk_index,
                offset_in_chunk,
                &buf[n..n + slice_len],
                known_size,
            )
            .map_err(std::io::Error::from)?;

            n += slice_len;
            self.current_pos += slice_len as u64;
            known_size = known_size.max(self.current_pos);
        }

        if let Err(e) = self.update_metadata() {
            error!("Failed to update metadata after write");
            return Err(e.into());
        }

        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.rfs_file.flush()
    }
}

impl File for CryptoFsFile {
    fn metadata(&self) -> Result<Metadata, Box<dyn Error>> {
        Ok(self.metadata)
    }
}
