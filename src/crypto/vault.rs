use crate::crypto::{DEFAULT_MASTER_KEY_FILE, MasterKey, MasterKeyError};
use crate::cryptofs::{FileSystem, OpenOptions, parent_path};
use hmac::Hmac;
use hmac::digest::KeyInit;
use jwt::{AlgorithmType, Header, SignWithKey, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

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

/// `Copy` is intentionally absent: `MasterKey` contains `Zeroizing<[u8; 32]>`
/// fields which are non-`Copy` by design to prevent silent duplication of key
/// material.
///
/// `Debug` is intentionally implemented manually (not derived) because a
/// derived impl would transitively call `MasterKey`'s field debug formatters,
/// which — even with `Zeroizing` wrappers — would print raw key bytes via the
/// `[u8; 32]` `Debug` impl.
#[derive(Clone)]
pub struct Vault {
    pub master_key: MasterKey,
    pub claims: Claims,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Expose only the non-sensitive `claims` field; never the master key.
        f.debug_struct("Vault")
            .field("master_key", &"[REDACTED]")
            .field("claims", &self.claims)
            .finish()
    }
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
            .map_err(|e| MasterKeyError::IoError(std::io::Error::other(e.to_string())))?;
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
                .map_err(|e| MasterKeyError::IoError(std::io::Error::other(e.to_string())))?;
            MasterKey::from_reader(&mut masterkey_file, password.as_ref())?
        } else {
            return Err(MasterKeyError::JWTError(jwt::Error::NoKeyId));
        };

        // Assemble the combined 64-byte key in a Zeroizing buffer so it is
        // wiped from the heap when this scope exits.
        let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
        key.extend_from_slice(master_key.primary_master_key.as_ref());
        key.extend_from_slice(master_key.hmac_master_key.as_ref());

        let hmac_key: Hmac<Sha256> = Hmac::new_from_slice(&key)?;
        let verified_token: Token<Header, Claims, _> =
            VerifyWithKey::verify_with_key(jwt_string.as_str(), &hmac_key)?;

        Ok(Vault {
            master_key,
            claims: *verified_token.claims(),
        })
    }
}
