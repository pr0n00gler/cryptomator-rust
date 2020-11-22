use crate::crypto::{Cryptor, MasterKey};
use crate::cryptofs::{FileSystem, FileSystemError, SeekAndRead};
use std::path::Path;
use crate::cryptofs::error::FileSystemError::UnknownError;

const ENCRYPTED_FILE_EXT: &str = ".c9r";

pub struct CryptoFS<FSP: FileSystem> {
    cryptor: Cryptor,
    root_folder: String,
    file_system_provider: FSP,
}

impl<FSP: FileSystem> CryptoFS<FSP> {
    pub fn new(
        folder: &str,
        master_key_path: &str,
        master_key_passphrase: &str,
        fs_provider: FSP,
    ) -> Result<CryptoFS<FSP>, FileSystemError> {
        let master_key = MasterKey::from_file(master_key_path, master_key_passphrase)?;
        let cryptor = Cryptor::new(master_key);
        let crypto_fs = CryptoFS {
            cryptor,
            root_folder: String::from(folder),
            file_system_provider: fs_provider,
        };
        Ok(crypto_fs)
    }

    fn real_path_from_dir_id(&self, dir_id: &[u8]) -> Result<String, FileSystemError> {
        let dir_hash = self.cryptor.get_dir_id_hash(dir_id)?;
        let real_path = Path::new(self.root_folder.as_str())
            .join(&dir_hash[..2])
            .join(&dir_hash[2..]);
        match real_path.to_str() {
            Some(p) => Ok(String::from(p)),
            None => Err(UnknownError(String::from("failed to convert PathBuf to str")))
        }
    }

    fn dir_id_from_path(&self, path: &str) -> Result<Vec<u8>, FileSystemError> {
        let mut dir_id: Vec<u8> = vec![];
        let components = std::path::Path::new(path).components().collect::<Vec<_>>();
        for c in components {
            dir_id = match c {
                std::path::Component::RootDir => vec![],
                _ => {
                    let real_path = self.real_path_from_dir_id(dir_id.as_slice())?;
                    let files = self
                        .file_system_provider
                        .read_dir(real_path.as_str())?;
                    let mut dir_uuid = vec![];
                    for f in files {
                        let decrypted_name = self
                            .cryptor
                            .decrypt_filename(&f[..f.len() - ENCRYPTED_FILE_EXT.len()], dir_id.as_slice())?;
                        if decrypted_name == c.as_os_str().to_str().unwrap_or_default() {
                            let mut reader = self.file_system_provider.open_file(
                                Path::new(real_path.as_str())
                                    .join(f)
                                    .join("dir.c9r")
                                    .to_str()
                                    .unwrap_or_default(),
                            )?;
                            reader.read_to_end(&mut dir_uuid)?;
                            break;
                        }
                    }
                    dir_uuid
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
}
