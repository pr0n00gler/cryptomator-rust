use failure::Fail;

#[derive(Debug, Fail)]
pub enum MasterKeyError {
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

impl From<openssl::aes::KeyError> for MasterKeyError {
    fn from(err: openssl::aes::KeyError) -> MasterKeyError {
        MasterKeyError::AESKeyError(err)
    }
}