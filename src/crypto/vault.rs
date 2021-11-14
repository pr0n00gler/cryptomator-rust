use crate::crypto::{MasterKey, MasterKeyError, DEFAULT_MASTER_KEY_FILE};
use crate::cryptofs::parent_path;
use hmac::{Hmac, NewMac};
use jwt::{AlgorithmType, Header, SignWithKey, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Read;

const DEFAULT_KID: &str = "masterkeyfile:masterkey.cryptomator";
pub const DEFAULT_VAULT_FILENAME: &str = "vault.cryptomator";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct Claims {
    pub jti: String,
    pub format: u32,
    pub cipherCombo: String,
    pub shorteningThreshold: u32,
}

pub struct Vault {
    pub masterkey: MasterKey,
    pub claims: Claims,
}

impl Vault {
    pub fn create_vault(
        key: &[u8],
        format: u32,
        ciphercombo: String,
        shortening_threshold: u32,
    ) -> Result<String, MasterKeyError> {
        let header = Header {
            algorithm: AlgorithmType::Hs256,
            key_id: Some(String::from(DEFAULT_KID)),
            ..Default::default()
        };

        let claims = Claims {
            jti: uuid::Uuid::new_v4().to_string(),
            format,
            cipherCombo: ciphercombo,
            shorteningThreshold: shortening_threshold,
        };

        let hmac_key: Hmac<Sha256> = Hmac::new_from_slice(key)?;

        Ok(Token::new(header, claims).sign_with_key(&hmac_key)?.into())
    }

    pub fn open(vault_path: String, password: &str) -> Result<Vault, MasterKeyError> {
        let mut vault_file = std::fs::File::open(&vault_path)?;
        let mut jwt_bytes: Vec<u8> = vec![];
        vault_file.read_to_end(&mut jwt_bytes)?;
        let jwt_string = String::from_utf8(jwt_bytes).unwrap();

        let unverified_token: Token<Header, Claims, _> = jwt::Token::parse_unverified(&jwt_string)?;

        let masterkey = if let Some(kid) = &unverified_token.header().key_id {
            let masterkey_file_path: std::path::PathBuf;
            if kid == DEFAULT_KID {
                let path = std::path::Path::new(&vault_path);
                let dir_path = parent_path(&path);
                masterkey_file_path = dir_path.join(DEFAULT_MASTER_KEY_FILE);
            } else {
                masterkey_file_path = std::path::PathBuf::from(kid)
            }

            let mut masterkey_file = std::fs::File::open(masterkey_file_path)?;
            MasterKey::from_reader(&mut masterkey_file, password)?
        } else {
            return Err(MasterKeyError::JWTError(jwt::Error::NoKeyId));
        };

        let mut key: Vec<u8> = Vec::with_capacity(64);
        key.extend_from_slice(&masterkey.primary_master_key);
        key.extend_from_slice(&masterkey.hmac_master_key);

        let hmac_key: Hmac<Sha256> = Hmac::new_from_slice(&key)?;
        let verified_token: Token<Header, Claims, _> =
            VerifyWithKey::verify_with_key(jwt_string.as_str(), &hmac_key)?;

        Ok(Vault {
            masterkey,
            claims: verified_token.claims().clone(),
        })
    }
}
