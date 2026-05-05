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

        let kid = unverified_token
            .header()
            .key_id
            .as_deref()
            .ok_or(MasterKeyError::JWTError(jwt::Error::NoKeyId))?;
        if kid != DEFAULT_KID {
            return Err(MasterKeyError::UnexpectedKeyId(kid.to_owned()));
        }

        let masterkey_file_path = parent_path(vault_path).join(DEFAULT_MASTER_KEY_FILE);
        let mut masterkey_file = filesystem
            .open_file(masterkey_file_path, OpenOptions::new())
            .map_err(|e| MasterKeyError::IoError(std::io::Error::other(e.to_string())))?;
        let master_key = MasterKey::from_reader(&mut masterkey_file, password.as_ref())?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptofs::FileSystem;
    use crate::providers::MemoryFs;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::io::Write;

    fn token_with_kid(kid: &str) -> String {
        let header = serde_json::json!({
            "alg": "HS256",
            "kid": kid,
            "typ": "JWT"
        });
        let claims = serde_json::json!({
            "jti": uuid::Uuid::new_v4(),
            "format": DEFAULT_FORMAT,
            "cipherCombo": "SIV_CTRMAC",
            "shorteningThreshold": DEFAULT_SHORTENING_THRESHOLD
        });
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    fn assert_unexpected_kid(kid: &str) {
        let fs = MemoryFs::new();
        let mut vault_file = fs.create_file("/vault.cryptomator").unwrap();
        vault_file
            .write_all(token_with_kid(kid).as_bytes())
            .unwrap();
        drop(vault_file);

        let err = Vault::open(&fs, "/vault.cryptomator", "password").unwrap_err();
        assert!(matches!(err, MasterKeyError::UnexpectedKeyId(found) if found == kid));
    }

    #[test]
    fn reject_absolute_jwt_kid() {
        assert_unexpected_kid("/tmp/attacker-masterkey.cryptomator");
    }

    #[test]
    fn reject_parent_relative_jwt_kid() {
        assert_unexpected_kid("../../attacker-masterkey.cryptomator");
    }
}
