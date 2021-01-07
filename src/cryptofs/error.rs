use crate::crypto::{CryptoError, MasterKeyError};
use failure::Fail;
use failure::_core::fmt::Debug;

#[derive(Debug, Fail)]
pub enum FileSystemError {
    #[fail(display = "Input/Output error")]
    IOError(std::io::Error),

    #[fail(display = "Crypto error")]
    CryptoError(CryptoError),

    #[fail(display = "Master key error")]
    MasterKeyError(MasterKeyError),

    #[fail(display = "Unknown error")]
    UnknownError(String),

    #[fail(display = "Invalid path error")]
    InvalidPathError(String),

    #[fail(display = "Path is not exist error")]
    PathIsNotExist(String),

    #[fail(display = "String from UTF-8 error")]
    StringConvertError(std::string::FromUtf8Error),

    #[fail(display = "UUID parse error")]
    UUIDParseError(uuid::Error),
}

impl From<std::io::Error> for FileSystemError {
    fn from(err: std::io::Error) -> FileSystemError {
        FileSystemError::IOError(err)
    }
}

impl From<CryptoError> for FileSystemError {
    fn from(err: CryptoError) -> FileSystemError {
        FileSystemError::CryptoError(err)
    }
}

impl From<MasterKeyError> for FileSystemError {
    fn from(err: MasterKeyError) -> FileSystemError {
        FileSystemError::MasterKeyError(err)
    }
}

impl From<std::string::FromUtf8Error> for FileSystemError {
    fn from(err: std::string::FromUtf8Error) -> FileSystemError {
        FileSystemError::StringConvertError(err)
    }
}

impl From<uuid::Error> for FileSystemError {
    fn from(err: uuid::Error) -> FileSystemError {
        FileSystemError::UUIDParseError(err)
    }
}
