use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MasterKeyError {
    #[error("Unsupported vault version")]
    VaultVersion,

    #[error("Input/Output error")]
    IoError(std::io::Error),

    #[error("Json serialize error")]
    SerializationJsonError(serde_json::Error),

    #[error("Base64 decode error")]
    Base64DecodeError(base64::DecodeError),

    #[error("Scrypt invalid params error")]
    ScryptInvalidParams(scrypt::errors::InvalidParams),

    #[error("Scrypt invalid output length")]
    ScryptInvalidOutputLengthError(scrypt::errors::InvalidOutputLen),

    #[error("AES key error")]
    AesKeyError(openssl::aes::KeyError),

    #[error("HMac error")]
    HMacError(hmac::digest::MacError),

    #[error("HMac invalid key length error")]
    HMacInvalidKeyLengthError(hmac::digest::InvalidLength),

    #[error("JWT error")]
    JWTError(jwt::Error),

    #[error("String decoding error")]
    FromUTF8Error(FromUtf8Error),
}

impl From<std::io::Error> for MasterKeyError {
    fn from(err: std::io::Error) -> MasterKeyError {
        MasterKeyError::IoError(err)
    }
}

impl From<serde_json::Error> for MasterKeyError {
    fn from(err: serde_json::Error) -> MasterKeyError {
        MasterKeyError::SerializationJsonError(err)
    }
}

impl From<base64::DecodeError> for MasterKeyError {
    fn from(err: base64::DecodeError) -> MasterKeyError {
        MasterKeyError::Base64DecodeError(err)
    }
}

impl From<scrypt::errors::InvalidParams> for MasterKeyError {
    fn from(err: scrypt::errors::InvalidParams) -> MasterKeyError {
        MasterKeyError::ScryptInvalidParams(err)
    }
}

impl From<scrypt::errors::InvalidOutputLen> for MasterKeyError {
    fn from(err: scrypt::errors::InvalidOutputLen) -> MasterKeyError {
        MasterKeyError::ScryptInvalidOutputLengthError(err)
    }
}

impl From<hmac::digest::MacError> for MasterKeyError {
    fn from(err: hmac::digest::MacError) -> MasterKeyError {
        MasterKeyError::HMacError(err)
    }
}

impl From<hmac::digest::InvalidLength> for MasterKeyError {
    fn from(err: hmac::digest::InvalidLength) -> MasterKeyError {
        MasterKeyError::HMacInvalidKeyLengthError(err)
    }
}

impl From<openssl::aes::KeyError> for MasterKeyError {
    fn from(err: openssl::aes::KeyError) -> MasterKeyError {
        MasterKeyError::AesKeyError(err)
    }
}

impl From<jwt::Error> for MasterKeyError {
    fn from(err: jwt::Error) -> MasterKeyError {
        MasterKeyError::JWTError(err)
    }
}

impl From<FromUtf8Error> for MasterKeyError {
    fn from(err: FromUtf8Error) -> Self {
        MasterKeyError::FromUTF8Error(err)
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Input/Output error")]
    IoError(std::io::Error),

    #[error("Base64 decode error")]
    Base64DecodeError(base64::DecodeError),

    #[error("AEAD error")]
    AeadError(aes_siv::aead::Error),

    #[error("HMac error")]
    HMacError(hmac::digest::MacError),

    #[error("HMac invalid key length error")]
    HMacInvalidKeyLengthError(hmac::digest::InvalidLength),

    #[error("Invalid file header length")]
    InvalidFileHeaderLength(String),

    #[error("Invalid file chunk length")]
    InvalidFileChunkLength(String),

    #[error("String from UTF-8 error")]
    StringFromUtf8Error(std::string::FromUtf8Error),
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> CryptoError {
        CryptoError::IoError(err)
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> CryptoError {
        CryptoError::Base64DecodeError(err)
    }
}

impl From<aes_siv::aead::Error> for CryptoError {
    fn from(err: aes_siv::aead::Error) -> CryptoError {
        CryptoError::AeadError(err)
    }
}

impl From<hmac::digest::MacError> for CryptoError {
    fn from(err: hmac::digest::MacError) -> CryptoError {
        CryptoError::HMacError(err)
    }
}

impl From<hmac::digest::InvalidLength> for CryptoError {
    fn from(err: hmac::digest::InvalidLength) -> CryptoError {
        CryptoError::HMacInvalidKeyLengthError(err)
    }
}

impl From<std::string::FromUtf8Error> for CryptoError {
    fn from(err: std::string::FromUtf8Error) -> CryptoError {
        CryptoError::StringFromUtf8Error(err)
    }
}
