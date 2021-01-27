use crate::crypto::{
    calculate_cleartext_size, Cryptor, FileHeader, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH,
    FILE_CHUNK_LENGTH, FILE_HEADER_LENGTH,
};
use crate::cryptofs::error::FileSystemError::{InvalidPathError, PathIsNotExist, UnknownError};
use crate::cryptofs::filesystem::Metadata;
use crate::cryptofs::{
    component_to_string, last_path_component, parent_path, DirEntry, File, FileSystem,
    FileSystemError,
};
use std::cmp::Ordering;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Extension of encrypted filename
const ENCRYPTED_FILE_EXT: &str = ".c9r";

/// Name of a file that contains dir_id
const DIR_FILENAME: &str = "dir.c9r";

/// Provides an access to an encrypted storage
/// In a nutshell, translates all the 'virtual' paths, like '/some_folder/file.txt', to real paths,
/// like /d/DR/RW3L6XRAPFC2UCK5QY37Q2U552IRPE/eZdOa_B9fRqncpYjZmKXfJEz81LgRUbT0yWdE0wyNTMd.c9r
pub struct CryptoFS<'gc> {
    /// Instance of the Cryptor - does all work with cryptography
    cryptor: Cryptor,

    /// path to an encrypted storage
    root_folder: String,

    /// Instance of the FileSystem. Should provide access to a real files.
    file_system_provider: &'gc dyn FileSystem,
}

impl<'gc> CryptoFS<'gc> {
    /// Returns a new instance of CryptoFS
    pub fn new(
        folder: &str,
        cryptor: Cryptor,
        fs_provider: &'gc dyn FileSystem,
    ) -> Result<CryptoFS<'gc>, FileSystemError> {
        let crypto_fs = CryptoFS {
            cryptor,
            root_folder: String::from(folder),
            file_system_provider: fs_provider,
        };
        let root = crypto_fs.real_path_from_dir_id(b"")?;
        crypto_fs
            .file_system_provider
            .create_dir_all(root.as_str())?;
        Ok(crypto_fs)
    }

    /// Returns a real path to a dir by dir_id
    pub fn real_path_from_dir_id(&self, dir_id: &[u8]) -> Result<String, FileSystemError> {
        let dir_hash = self.cryptor.get_dir_id_hash(dir_id)?;
        let real_path = Path::new(self.root_folder.as_str())
            .join(&dir_hash[..2])
            .join(&dir_hash[2..]);
        match real_path.to_str() {
            Some(p) => Ok(String::from(p)),
            None => Err(UnknownError(String::from(
                "failed to convert PathBuf to str",
            ))),
        }
    }

    /// Returns a dir_id for a path
    /// There will be an PathIsNotExist error, if path does not exists and CryptoError cause of crypto errors
    pub fn dir_id_from_path(&self, path: &str) -> Result<Vec<u8>, FileSystemError> {
        let mut dir_id: Vec<u8> = vec![];
        let components = std::path::Path::new(path).components();
        for c in components {
            dir_id = match c {
                std::path::Component::RootDir => vec![],
                std::path::Component::Normal(p) => {
                    let real_path = self.real_path_from_dir_id(dir_id.as_slice())?;
                    let files = self.file_system_provider.read_dir(real_path.as_str())?;
                    let mut dir_uuid = vec![];
                    for f in files {
                        let decrypted_name = self.cryptor.decrypt_filename(
                            f.filename_without_extension().as_str(),
                            dir_id.as_slice(),
                        )?;
                        if decrypted_name == p.to_str().unwrap_or_default() {
                            let mut reader = self.file_system_provider.open_file(
                                Path::new(real_path.as_str())
                                    .join(f.file_name)
                                    .join(DIR_FILENAME)
                                    .to_str()
                                    .unwrap_or_default(),
                            )?;
                            reader.read_to_end(&mut dir_uuid)?;
                            break;
                        }
                    }
                    if dir_uuid.is_empty() {
                        return Err(PathIsNotExist(String::from(
                            c.as_os_str().to_str().unwrap_or_default(),
                        )));
                    }
                    dir_uuid
                }
                _ => {
                    return Err(InvalidPathError(String::from(
                        c.as_os_str().to_str().unwrap_or_default(),
                    )))
                }
            };
        }
        Ok(dir_id)
    }

    /// Translates a 'virtual' path to a real path
    pub fn filepath_to_real_path(&self, path: &str) -> Result<String, FileSystemError> {
        let filename = last_path_component(path)?;

        let dir_id = self.dir_id_from_path(parent_path(path).as_str())?;
        let real_dir_path = self.real_path_from_dir_id(dir_id.as_slice())?;
        let real_filename = self
            .cryptor
            .encrypt_filename(filename.as_str(), dir_id.as_slice())?;

        let full_path = std::path::PathBuf::new()
            .join(real_dir_path.as_str())
            .join(real_filename.as_str());

        match full_path.to_str() {
            Some(s) => Ok(String::from(s) + ENCRYPTED_FILE_EXT),
            None => Err(UnknownError(String::from(
                "failed to convert PathBuf to str",
            ))),
        }
    }
}

impl<'gc> FileSystem for CryptoFS<'gc> {
    /// Returns an iterator of DirEntries for the given path
    fn read_dir(&self, path: &str) -> Result<Box<dyn Iterator<Item = DirEntry>>, FileSystemError> {
        let dir_id = self.dir_id_from_path(path)?;
        let real_path = self.real_path_from_dir_id(dir_id.as_slice())?;
        Ok(Box::new(
            self.file_system_provider
                .read_dir(real_path.as_str())?
                .map(move |f| DirEntry {
                    path: Default::default(),
                    metadata: f.metadata,
                    file_name: self
                        .cryptor
                        .decrypt_filename(
                            f.filename_without_extension().as_str(),
                            dir_id.as_slice(),
                        )
                        .unwrap_or_default()
                        .parse()
                        .unwrap(),
                })
                .collect::<Vec<DirEntry>>()
                .into_iter(),
        ))
    }

    /// Creates the directory at this path
    /// Similar to create_dir_all()
    fn create_dir(&self, path: &str) -> Result<(), FileSystemError> {
        let mut parent_dir_id: Vec<u8> = vec![];
        let mut path_buf = std::path::PathBuf::new();

        let components = std::path::Path::new(path).components();
        for component in components {
            let path = component_to_string(component)?;
            path_buf = path_buf.join(std::path::Path::new(path.as_str()));
            let dir_id = self.dir_id_from_path(match path_buf.to_str() {
                Some(s) => s,
                None => return Err(UnknownError(String::from("failed to convert OsStr to str"))),
            });

            match dir_id {
                Ok(id) => parent_dir_id = id,
                Err(e) => match e {
                    PathIsNotExist(_) => {
                        let encrypted_folder_name = self
                            .cryptor
                            .encrypt_filename(path.as_str(), parent_dir_id.as_slice())?
                            + ENCRYPTED_FILE_EXT;

                        let parent_folder = self.real_path_from_dir_id(parent_dir_id.as_slice())?;
                        let mut real_path = std::path::Path::new(parent_folder.as_str())
                            .join(encrypted_folder_name.as_str());

                        self.file_system_provider
                            .create_dir_all(real_path.to_str().unwrap_or_default())?;
                        real_path = real_path.join(DIR_FILENAME);

                        let mut writer = self
                            .file_system_provider
                            .create_file(real_path.to_str().unwrap_or_default())?;
                        let dir_uuid = uuid::Uuid::new_v4();
                        writer.write_all(dir_uuid.to_string().as_bytes())?;

                        let dir_id_hash = self
                            .cryptor
                            .get_dir_id_hash(dir_uuid.to_string().as_bytes())?;

                        let real_folder_path = std::path::Path::new(self.root_folder.as_str())
                            .join(&dir_id_hash[..2])
                            .join(&dir_id_hash[2..]);

                        self.file_system_provider.create_dir_all(
                            real_folder_path.as_os_str().to_str().unwrap_or_default(),
                        )?;

                        parent_dir_id = Vec::from(dir_uuid.to_string().as_bytes());
                    }
                    _ => return Err(e),
                },
            }
        }
        Ok(())
    }

    fn create_dir_all(&self, path: &str) -> Result<(), FileSystemError> {
        Ok(self.create_dir(path)?)
    }

    fn open_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError> {
        let real_path = self.filepath_to_real_path(path)?;
        let crypto_file =
            CryptoFSFile::open(real_path.as_str(), self.cryptor, self.file_system_provider)?;
        Ok(Box::new(crypto_file))
    }

    fn create_file(&self, path: &str) -> Result<Box<dyn File>, FileSystemError> {
        let real_path = self.filepath_to_real_path(path)?;
        let rfs_file = self.file_system_provider.create_file(real_path.as_str())?;
        Ok(Box::new(CryptoFSFile::create_file(self.cryptor, rfs_file)?))
    }

    fn exists(&self, path: &str) -> bool {
        let real_path = match self.filepath_to_real_path(path) {
            Ok(p) => p,
            Err(_) => return false,
        };
        self.file_system_provider.exists(real_path.as_str())
    }

    fn remove_file(&self, path: &str) -> Result<(), FileSystemError> {
        let real_path = self.filepath_to_real_path(path)?;
        Ok(self.file_system_provider.remove_file(real_path.as_str())?)
    }

    fn remove_dir(&self, path: &str) -> Result<(), FileSystemError> {
        let dir_entries = self.read_dir(path)?;
        let real_dir_path = self.filepath_to_real_path(path)?;

        for entry in dir_entries {
            let full_path = std::path::PathBuf::new();
            let full_path = full_path.join(path).join(&entry.file_name);
            let full_path = match full_path.as_os_str().to_str() {
                Some(s) => s,
                None => {
                    return Err(UnknownError(String::from(
                        "failed to convert PathBuf to str",
                    )))
                }
            };

            let real_path = self.filepath_to_real_path(full_path)?;
            if entry.metadata.is_dir {
                self.remove_dir(full_path)?;
            } else {
                self.file_system_provider.remove_file(real_path.as_str())?;
            }
        }
        Ok(self
            .file_system_provider
            .remove_dir(real_dir_path.as_str())?)
    }

    fn copy_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        let src_real_path = self.filepath_to_real_path(_src)?;
        let dst_real_path = self.filepath_to_real_path(_dest)?;
        Ok(self
            .file_system_provider
            .copy_file(src_real_path.as_str(), dst_real_path.as_str())?)
    }

    fn move_file(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        let src_real_path = self.filepath_to_real_path(_src)?;
        let dst_real_path = self.filepath_to_real_path(_dest)?;
        Ok(self
            .file_system_provider
            .move_file(src_real_path.as_str(), dst_real_path.as_str())?)
    }

    fn move_dir(&self, _src: &str, _dest: &str) -> Result<(), FileSystemError> {
        let src_dir_entries = self.read_dir(_src)?;

        let mut dst_path = _dest;
        let mut dst_path_builder = std::path::PathBuf::new();
        if !self.exists(_dest) {
            self.create_dir(_dest)?;
        } else {
            let src_dir_name = last_path_component(_src)?;
            dst_path_builder = dst_path_builder.join(_dest).join(src_dir_name);
            dst_path = match dst_path_builder.as_os_str().to_str() {
                Some(s) => s,
                None => {
                    return Err(UnknownError(String::from(
                        "failed to convert PathBuf to str",
                    )))
                }
            };
            self.create_dir(dst_path)?;
        }

        for entry in src_dir_entries {
            let dst_full_path = std::path::PathBuf::new();
            let dst_full_path = dst_full_path.join(dst_path).join(&entry.file_name);
            let dst_full_path = match dst_full_path.as_os_str().to_str() {
                Some(s) => s,
                None => {
                    return Err(UnknownError(String::from(
                        "failed to convert PathBuf to str",
                    )))
                }
            };

            let src_full_path = std::path::PathBuf::new();
            let src_full_path = src_full_path.join(_src).join(&entry.file_name);
            let src_full_path = match src_full_path.as_os_str().to_str() {
                Some(s) => s,
                None => {
                    return Err(UnknownError(String::from(
                        "failed to convert PathBuf to str",
                    )))
                }
            };
            if entry.metadata.is_dir {
                self.move_dir(src_full_path, dst_full_path)?;
            } else {
                self.move_file(src_full_path, dst_full_path)?;
            }
        }
        Ok(self.remove_dir(_src)?)
    }
}

/// 'Virtual' file implementation of the File trait
pub struct CryptoFSFile {
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
}

impl<'gc> CryptoFSFile {
    /// Opens a file at the given real path (so the path must be translated from 'virtual' to real before the
    /// function call) for reading/writing.
    /// Read/Write implementations for the traits works with a cleartext data, so CryptoFSFile instance
    /// must contain the Cryptor
    pub fn open(
        real_path: &str,
        cryptor: Cryptor,
        real_file_system_provider: &'gc dyn FileSystem,
    ) -> Result<CryptoFSFile, FileSystemError> {
        let mut reader = real_file_system_provider.open_file(real_path)?;
        let mut encrypted_header: [u8; FILE_HEADER_LENGTH] = [0; FILE_HEADER_LENGTH];

        reader.read_exact(&mut encrypted_header)?;

        let header = cryptor.decrypt_file_header(&encrypted_header)?;
        let metadata = reader.metadata()?;
        Ok(CryptoFSFile {
            cryptor,
            rfs_file: reader,
            current_pos: 0,
            header,
            metadata: Metadata {
                len: calculate_cleartext_size(metadata.len),
                ..metadata
            },
        })
    }

    /// Creates a file at the given real path (so the path must be translated from 'virtual' to real before the
    /// function call).
    /// Read/Write implementations for the traits works with a cleartext data, so CryptoFSFile instance
    /// must contain the Cryptor
    pub fn create_file(
        cryptor: Cryptor,
        mut rfs_file: Box<dyn File>,
    ) -> Result<CryptoFSFile, FileSystemError> {
        let header = cryptor.create_file_header();
        let encrypted_header = cryptor.encrypt_file_header(&header)?;
        rfs_file.write_all(encrypted_header.as_slice())?;
        rfs_file.flush()?;
        let metadata = rfs_file.metadata()?;
        Ok(CryptoFSFile {
            cryptor,
            rfs_file,
            current_pos: 0,
            header,
            metadata,
        })
    }

    /// Returns a cleartext size of the file
    pub fn get_file_size(&mut self) -> Result<u64, FileSystemError> {
        let current_pos = self.rfs_file.seek(SeekFrom::Current(0))?;
        let real_file_size = self.rfs_file.seek(SeekFrom::End(0))?;
        self.rfs_file.seek(SeekFrom::Start(current_pos))?;
        Ok(calculate_cleartext_size(real_file_size))
    }

    /// Return a real size of the file
    pub fn get_real_file_size(&mut self) -> Result<u64, FileSystemError> {
        let current_pos = self.rfs_file.seek(SeekFrom::Current(0))?;
        let real_file_size = self.rfs_file.seek(SeekFrom::End(0))?;
        self.rfs_file.seek(SeekFrom::Start(current_pos))?;
        Ok(real_file_size)
    }

    /// Reads and returns cleartext chunk of the data.
    fn read_chunk(&mut self, chunk_index: u64) -> Result<Vec<u8>, FileSystemError> {
        self.rfs_file.seek(SeekFrom::Start(
            (chunk_index * FILE_CHUNK_LENGTH as u64) + FILE_HEADER_LENGTH as u64,
        ))?;
        let mut chunk = [0u8; FILE_CHUNK_LENGTH];
        let read_bytes = self.rfs_file.read(&mut chunk)?;
        if read_bytes == 0 {
            return Ok(vec![0; 0]);
        }
        Ok(self.cryptor.decrypt_chunk(
            &self.header.nonce,
            &self.header.payload.content_key,
            chunk_index as usize,
            &chunk[..read_bytes],
        )?)
    }
}

impl Seek for CryptoFSFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => self.current_pos = p,
            SeekFrom::Current(p) => self.current_pos = (self.current_pos as i64 + p) as u64,
            SeekFrom::End(p) => match self.get_file_size() {
                Ok(s) => self.current_pos = (s as i64 + p) as u64,
                Err(_) => return Err(std::io::Error::from(std::io::ErrorKind::Other)),
            },
        }
        Ok(self.current_pos)
    }
}

impl Read for CryptoFSFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut chunk_index = self.current_pos / FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64;
        let mut n: usize = 0;
        while n < buf.len() {
            let offset = if n > 0 {
                0
            } else {
                (self.current_pos % FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64) as usize
            };

            let chunk = match self.read_chunk(chunk_index) {
                Ok(c) => c,
                Err(_) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
            };

            if chunk.is_empty() {
                break;
            }
            if offset == chunk.len() {
                break;
            }

            let slice_len = match (buf.len() - n).cmp(&(chunk.len() - offset)) {
                Ordering::Less => buf.len() - n,
                Ordering::Greater => chunk.len() - offset,
                Ordering::Equal => buf.len() - n,
            };
            buf[n..n + slice_len].copy_from_slice(&chunk[offset..offset + slice_len]);
            n += slice_len;

            self.current_pos += n as u64;
            chunk_index += 1;
        }
        Ok(n)
    }
}

impl Write for CryptoFSFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut encrypted_data: Vec<u8> = vec![];
        let mut chunk_index = self.current_pos / FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64;
        let file_size = match self.get_real_file_size() {
            Ok(s) => s,
            Err(_) => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
        };

        let chunks_count = file_size / FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64;
        let start_chunk_index = chunk_index;
        let mut n: usize = 0;
        while n < buf.len() {
            let offset = if n > 0 {
                0
            } else {
                (self.current_pos % FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64) as usize
            };

            let mut chunk: Vec<u8> = vec![];
            if chunk_index > chunks_count || file_size == FILE_HEADER_LENGTH as u64 {
                let slice_len = if FILE_CHUNK_CONTENT_PAYLOAD_LENGTH <= buf.len() - n {
                    FILE_CHUNK_CONTENT_PAYLOAD_LENGTH
                } else {
                    buf.len() - n
                };
                chunk.extend_from_slice(&buf[n..n + slice_len]);
                n += slice_len;
            } else {
                let mut buf_chunk = match self.read_chunk(chunk_index) {
                    Ok(c) => c,
                    Err(_) => {
                        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                    }
                };
                if buf_chunk.is_empty() {
                    break;
                }

                let slice_len = match (buf.len() - n).cmp(&(buf_chunk.len() - offset)) {
                    Ordering::Less => buf.len() - n,
                    Ordering::Greater => buf_chunk.len() - offset,
                    Ordering::Equal => buf.len() - n,
                };

                buf_chunk[offset..offset + slice_len].copy_from_slice(&buf[n..n + slice_len]);
                n += slice_len;

                chunk = buf_chunk;
            }

            let encrypted_chunk = match self.cryptor.encrypt_chunk(
                &self.header.nonce,
                &self.header.payload.content_key,
                chunk_index as usize,
                chunk.as_slice(),
            ) {
                Ok(c) => c,
                Err(_) => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
            };
            encrypted_data.extend(encrypted_chunk);
            self.current_pos += n as u64;
            chunk_index += 1;
        }
        self.rfs_file.seek(SeekFrom::Start(
            (start_chunk_index * FILE_CHUNK_LENGTH as u64) + FILE_HEADER_LENGTH as u64,
        ))?;
        self.rfs_file.write_all(encrypted_data.as_ref())?;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(self.rfs_file.flush()?)
    }
}

impl File for CryptoFSFile {
    fn metadata(&self) -> Result<Metadata, FileSystemError> {
        Ok(self.metadata)
    }
}
