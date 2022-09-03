use crate::crypto::{MasterKey, MasterKeyError, DEFAULT_MASTER_KEY_FILE};
use crate::cryptofs::{parent_path, FileSystem, OpenOptions};
use hmac::digest::KeyInit;
use hmac::Hmac;
use jwt::{AlgorithmType, Header, SignWithKey, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Read;
use std::path::Path;

const DEFAULT_KID: &str = "masterkeyfile:masterkey.cryptomator";
pub const DEFAULT_VAULT_FILENAME: &str = "vault.cryptomator";
pub const DEFAULT_FORMAT: u32 = 8;
pub const DEFAULT_SHORTENING_THRESHOLD: u32 = 220;

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum CipherCombo {
    SIV_CTRMAC,
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
#[allow(non_snake_case)]
pub struct Claims {
    pub jti: uuid::Uuid,
    pub format: u32,
    pub cipherCombo: CipherCombo,
    pub shorteningThreshold: u32,
}

impl Default for Claims {
    fn default() -> Self {
        Claims {
            jti: uuid::Uuid::new_v4(),
            format: 8,
            cipherCombo: CipherCombo::SIV_CTRMAC,
            shorteningThreshold: 220,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Vault {
    pub master_key: MasterKey,
    pub claims: Claims,
}

impl Vault {
    pub fn create_vault(
        key: &[u8],
        format: u32,
        ciphercombo: CipherCombo,
        shortening_threshold: u32,
    ) -> Result<String, MasterKeyError> {
        let header = Header {
            algorithm: AlgorithmType::Hs256,
            key_id: Some(String::from(DEFAULT_KID)),
            ..Default::default()
        };

        let claims = Claims {
            jti: uuid::Uuid::new_v4(),
            format,
            cipherCombo: ciphercombo,
            shorteningThreshold: shortening_threshold,
        };

        let hmac_key: Hmac<Sha256> = Hmac::new_from_slice(key)?;

        Ok(Token::new(header, claims).sign_with_key(&hmac_key)?.into())
    }

    pub fn open<P: AsRef<Path>, S: AsRef<str>, FS: FileSystem>(
        filesystem: &FS,
        vault_path: P,
        password: S,
    ) -> Result<Vault, MasterKeyError> {
        let mut vault_file = filesystem
            .open_file(&vault_path, OpenOptions::new())
            .map_err(|e| {
                MasterKeyError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;
        let mut jwt_bytes: Vec<u8> = vec![];
        vault_file.read_to_end(&mut jwt_bytes)?;
        let jwt_string = String::from_utf8(jwt_bytes)?;

        let unverified_token: Token<Header, Claims, _> = jwt::Token::parse_unverified(&jwt_string)?;

        let master_key = if let Some(kid) = &unverified_token.header().key_id {
            let masterkey_file_path = if kid == DEFAULT_KID {
                let dir_path = parent_path(vault_path);
                dir_path.join(DEFAULT_MASTER_KEY_FILE)
            } else {
                std::path::PathBuf::from(kid)
            };

            let mut masterkey_file = filesystem
                .open_file(masterkey_file_path, OpenOptions::new())
                .map_err(|e| {
                    MasterKeyError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ))
                })?;
            MasterKey::from_reader(&mut masterkey_file, password.as_ref())?
        } else {
            return Err(MasterKeyError::JWTError(jwt::Error::NoKeyId));
        };

        let mut key: Vec<u8> = Vec::with_capacity(64);
        key.extend_from_slice(&master_key.primary_master_key);
        key.extend_from_slice(&master_key.hmac_master_key);

        let hmac_key: Hmac<Sha256> = Hmac::new_from_slice(&key)?;
        let verified_token: Token<Header, Claims, _> =
            VerifyWithKey::verify_with_key(jwt_string.as_str(), &hmac_key)?;

        Ok(Vault {
            master_key,
            claims: *verified_token.claims(),
        })
    }
}
