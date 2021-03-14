use failure::Fail;

#[derive(Debug, Fail)]
pub enum MasterKeyError {
    #[fail(display = "Unsupported vault version")]
    VaultVersion,

    #[fail(display = "Input/Output error")]
    IOError(std::io::Error),

    #[fail(display = "Json serialize error")]
    SerializationJsonError(serde_json::Error),

    #[fail(display = "Base64 decode error")]
    Base64DecodeError(base64::DecodeError),

    #[fail(display = "Scrypt invalid params error")]
    ScryptInvalidParams(scrypt::errors::InvalidParams),

    #[fail(display = "Scrypt invalid output length")]
    ScryptInvalidOutputLengthError(scrypt::errors::InvalidOutputLen),

    #[fail(display = "AES key error")]
    AESKeyError(openssl::aes::KeyError),

    #[fail(display = "HMac error")]
    HMacError(hmac::crypto_mac::MacError),

    #[fail(display = "HMac invalid key length error")]
    HMacInvalidKeyLengthError(hmac::crypto_mac::InvalidKeyLength),
}

impl From<std::io::Error> for MasterKeyError {
    fn from(err: std::io::Error) -> MasterKeyError {
        MasterKeyError::IOError(err)
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

impl From<hmac::crypto_mac::MacError> for MasterKeyError {
    fn from(err: hmac::crypto_mac::MacError) -> MasterKeyError {
        MasterKeyError::HMacError(err)
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for MasterKeyError {
    fn from(err: hmac::crypto_mac::InvalidKeyLength) -> MasterKeyError {
        MasterKeyError::HMacInvalidKeyLengthError(err)
    }
}

impl From<openssl::aes::KeyError> for MasterKeyError {
    fn from(err: openssl::aes::KeyError) -> MasterKeyError {
        MasterKeyError::AESKeyError(err)
    }
}

#[derive(Debug, Fail)]
pub enum CryptoError {
    #[fail(display = "Input/Output error")]
    IOError(std::io::Error),

    #[fail(display = "Base64 decode error")]
    Base64DecodeError(base64::DecodeError),

    #[fail(display = "AEAD error")]
    AEADError(aes_siv::aead::Error),

    #[fail(display = "HMac error")]
    HMacError(hmac::crypto_mac::MacError),

    #[fail(display = "HMac invalid key length error")]
    HMacInvalidKeyLengthError(hmac::crypto_mac::InvalidKeyLength),

    #[fail(display = "Invalid file header length")]
    InvalidFileHeaderLength(String),

    #[fail(display = "Invalid file chunk length")]
    InvalidFileChunkLength(String),

    #[fail(display = "String from UTF-8 error")]
    StringFromUTF8Error(std::string::FromUtf8Error),
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> CryptoError {
        CryptoError::IOError(err)
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> CryptoError {
        CryptoError::Base64DecodeError(err)
    }
}

impl From<aes_siv::aead::Error> for CryptoError {
    fn from(err: aes_siv::aead::Error) -> CryptoError {
        CryptoError::AEADError(err)
    }
}

impl From<hmac::crypto_mac::MacError> for CryptoError {
    fn from(err: hmac::crypto_mac::MacError) -> CryptoError {
        CryptoError::HMacError(err)
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for CryptoError {
    fn from(err: hmac::crypto_mac::InvalidKeyLength) -> CryptoError {
        CryptoError::HMacInvalidKeyLengthError(err)
    }
}

impl From<std::string::FromUtf8Error> for CryptoError {
    fn from(err: std::string::FromUtf8Error) -> CryptoError {
        CryptoError::StringFromUTF8Error(err)
    }
}
