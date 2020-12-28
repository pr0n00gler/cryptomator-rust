use crate::crypto::{
    calculate_cleartext_size, Cryptor, FileHeader, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH,
    FILE_CHUNK_LENGTH, FILE_HEADER_LENGTH,
};
use crate::cryptofs::error::FileSystemError::{InvalidPathError, PathIsNotExist, UnknownError};
use crate::cryptofs::{File, FileSystem, FileSystemError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const ENCRYPTED_FILE_EXT: &str = ".c9r";
const DIR_FILENAME: &str = "dir.c9r";

pub struct CryptoFS<'gc> {
    cryptor: &'gc Cryptor<'gc>,
    root_folder: String,
    file_system_provider: &'gc dyn FileSystem,
}

impl<'gc> CryptoFS<'gc> {
    pub fn new(
        folder: &str,
        cryptor: &'gc Cryptor,
        fs_provider: &'gc dyn FileSystem,
    ) -> Result<CryptoFS<'gc>, FileSystemError> {
        let crypto_fs = CryptoFS {
            cryptor,
            root_folder: String::from(folder),
            file_system_provider: fs_provider,
        };
        Ok(crypto_fs)
    }

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
                            &f[..f.len() - ENCRYPTED_FILE_EXT.len()],
                            dir_id.as_slice(),
                        )?;
                        if decrypted_name == p.to_str().unwrap_or_default() {
                            let mut reader = self.file_system_provider.open_file(
                                Path::new(real_path.as_str())
                                    .join(f)
                                    .join(DIR_FILENAME)
                                    .to_str()
                                    .unwrap_or_default(),
                            )?;
                            reader.read_to_end(&mut dir_uuid)?;
                            break;
                        }
                    }
                    if dir_uuid.len() == 0 {
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

    pub fn read_dir(
        &self,
        path: &str,
    ) -> Result<Box<dyn Iterator<Item = String>>, FileSystemError> {
        let dir_id = self.dir_id_from_path(path)?;
        let real_path = self.real_path_from_dir_id(dir_id.as_slice())?;
        let files = self
            .file_system_provider
            .read_dir(real_path.as_str())?
            .map(|f| {
                self.cryptor
                    .decrypt_filename(&f[..f.len() - ENCRYPTED_FILE_EXT.len()], dir_id.as_slice())
                    .unwrap_or_default()
            })
            .collect::<Vec<String>>();
        Ok(Box::new(files.into_iter()))
    }

    pub fn create_dir(&self, path: &str) -> Result<(), FileSystemError> {
        let components = std::path::Path::new(path).components();
        let mut parent_dir_id: Vec<u8> = vec![];
        let mut path_buf = std::path::PathBuf::new();
        for component in components {
            let p = match component {
                std::path::Component::RootDir => match component.as_os_str().to_str() {
                    Some(s) => s,
                    None => {
                        return Err(UnknownError(String::from("failed to convert OsStr to str")))
                    }
                },
                std::path::Component::Normal(os) => match os.to_str() {
                    Some(s) => s,
                    None => {
                        return Err(UnknownError(String::from("failed to convert OsStr to str")))
                    }
                },
                _ => {
                    return Err(InvalidPathError(String::from(
                        component.as_os_str().to_str().unwrap_or_default(),
                    )))
                }
            };
            path_buf = path_buf.join(std::path::Path::new(p));
            let dir_id = self.dir_id_from_path(match path_buf.to_str() {
                Some(s) => s,
                None => return Err(UnknownError(String::from("failed to convert OsStr to str"))),
            });
            match dir_id {
                Ok(id) => parent_dir_id = id,
                Err(e) => match e {
                    PathIsNotExist(_) => {
                        let encrypted_folder_name =
                            self.cryptor.encrypt_filename(p, parent_dir_id.as_slice())?
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
                        writer.write(dir_uuid.to_string().as_bytes())?;

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

    fn filepath_to_real_path(&self, path: &str) -> Result<String, FileSystemError> {
        let components = std::path::Path::new(path)
            .components()
            .collect::<Vec<std::path::Component>>();
        let filename = match components.last() {
            Some(c) => match c.as_os_str().to_str() {
                Some(s) => s,
                None => return Err(UnknownError(String::from("failed to convert OsStr to str"))),
            },
            None => {
                return Err(PathIsNotExist(String::from(format!(
                    "invalid path: {}",
                    path
                ))))
            }
        };
        let mut dir_path = std::path::PathBuf::new(); //path without filename
        for (i, c) in components.iter().enumerate() {
            if i > components.len() - 2 {
                break;
            }
            dir_path = dir_path.join(c.as_ref() as &Path);
        }
        let dir_path_str = match dir_path.to_str() {
            Some(s) => s,
            None => {
                return Err(UnknownError(String::from(
                    "failed to convert PathBuf to str",
                )))
            }
        };
        let dir_id = self.dir_id_from_path(dir_path_str)?;
        let real_dir_path = self.real_path_from_dir_id(dir_id.as_slice())?;
        let real_filename = self.cryptor.encrypt_filename(filename, dir_id.as_slice())?;
        let temp = std::path::PathBuf::new();
        let temp = temp.join(std::path::Path::new(real_dir_path.as_str()));
        let temp = temp.join(std::path::Path::new(real_filename.as_str()));
        match temp.to_str() {
            Some(s) => Ok(String::from(s)),
            None => Err(UnknownError(String::from(
                "failed to convert PathBuf to str",
            ))),
        }
    }

    pub fn open_file(&self, path: &str) -> Result<Box<dyn File + 'gc>, FileSystemError> {
        let real_path = self.filepath_to_real_path(path)?;
        let crypto_file = CryptoFSFile::open(
            (String::from(real_path) + ENCRYPTED_FILE_EXT).as_str(),
            self.cryptor,
            self.file_system_provider,
        )?;
        Ok(Box::new(crypto_file))
    }

    pub fn create_file(&self, path: &str) -> Result<Box<dyn File + 'gc>, FileSystemError> {
        let real_path = self.filepath_to_real_path(path)?;
        let real_name = String::from(real_path) + ENCRYPTED_FILE_EXT;
        let rfs_file = self.file_system_provider.create_file(real_name.as_str())?;
        let crypto_file = CryptoFSFile::create_file(&self.cryptor, rfs_file)?;
        Ok(Box::new(crypto_file))
    }

    pub fn remove_file(&self, path: &str) -> Result<(), FileSystemError> {
        let real_path = self.filepath_to_real_path(path)?;
        let real_filepath = String::from(real_path) + ENCRYPTED_FILE_EXT;
        Ok(self
            .file_system_provider
            .remove_file(real_filepath.as_str())?)
    }

    pub fn exists(&self, path: &str) -> bool {
        let real_path = match self.filepath_to_real_path(path) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let real_filepath = String::from(real_path) + ENCRYPTED_FILE_EXT;
        self.file_system_provider.exists(real_filepath.as_str())
    }
}

pub struct CryptoFSFile<'gc> {
    cryptor: &'gc Cryptor<'gc>,
    rfs_file: Box<dyn File>,
    current_pos: u64,
    header: FileHeader,
}

impl<'gc> CryptoFSFile<'gc> {
    pub fn open(
        real_path: &str,
        cryptor: &'gc Cryptor,
        real_file_system_provider: &dyn FileSystem,
    ) -> Result<CryptoFSFile<'gc>, FileSystemError> {
        let mut reader = real_file_system_provider.open_file(real_path)?;
        let mut encrypted_header: [u8; FILE_HEADER_LENGTH] = [0; FILE_HEADER_LENGTH];
        reader.read_exact(&mut encrypted_header)?;
        let header = cryptor.decrypt_file_header(&encrypted_header)?;
        Ok(CryptoFSFile {
            cryptor,
            rfs_file: reader,
            current_pos: 0,
            header,
        })
    }

    pub fn create_file(
        cryptor: &'gc Cryptor,
        mut rfs_file: Box<dyn File>,
    ) -> Result<CryptoFSFile<'gc>, FileSystemError> {
        let header = cryptor.create_file_header();
        let encrypted_header = cryptor.encrypt_file_header(&header)?;
        rfs_file.write(encrypted_header.as_slice())?;
        rfs_file.flush()?;
        Ok(CryptoFSFile {
            cryptor,
            rfs_file,
            current_pos: 0,
            header,
        })
    }

    pub fn get_file_size(&mut self) -> Result<u64, FileSystemError> {
        let current_pos = self.rfs_file.seek(SeekFrom::Current(0))?;
        let real_file_size = self.rfs_file.seek(SeekFrom::End(0))?;
        self.rfs_file.seek(SeekFrom::Start(current_pos))?;
        Ok(calculate_cleartext_size(real_file_size))
    }

    pub fn get_real_file_size(&mut self) -> Result<u64, FileSystemError> {
        let current_pos = self.rfs_file.seek(SeekFrom::Current(0))?;
        let real_file_size = self.rfs_file.seek(SeekFrom::End(0))?;
        self.rfs_file.seek(SeekFrom::Start(current_pos))?;
        Ok(real_file_size)
    }

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

impl Seek for CryptoFSFile<'_> {
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

impl Read for CryptoFSFile<'_> {
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
            if chunk.len() == 0 {
                break;
            }
            for byte in &chunk[offset..] {
                if n >= buf.len() {
                    break;
                }
                buf[n] = *byte;
                n += 1;
            }
            self.current_pos += n as u64;
            chunk_index += 1;
        }
        Ok(n)
    }
}

impl Write for CryptoFSFile<'_> {
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
            let mut offset = if n > 0 {
                0
            } else {
                (self.current_pos % FILE_CHUNK_CONTENT_PAYLOAD_LENGTH as u64) as usize
            };
            let mut chunk: Vec<u8> = vec![];
            if chunk_index > chunks_count || file_size == FILE_HEADER_LENGTH as u64 {
                let mut c = 0;
                while c < FILE_CHUNK_CONTENT_PAYLOAD_LENGTH {
                    if n >= buf.len() {
                        break;
                    }
                    chunk.extend_from_slice(&[buf[n]]);
                    n += 1;
                    c += 1;
                }
            } else {
                let mut buf_chunk = match self.read_chunk(chunk_index) {
                    Ok(c) => c,
                    Err(_) => {
                        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                    }
                };
                if buf_chunk.len() == 0 {
                    break;
                }
                while offset < buf_chunk.len() {
                    if n >= buf.len() {
                        break;
                    }
                    buf_chunk[offset] = buf[n];
                    offset += 1;
                    n += 1;
                }
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

impl File for CryptoFSFile<'_> {}
