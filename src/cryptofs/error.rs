use crate::crypto::{CryptoError, MasterKeyError};
use failure::Fail;
use failure::_core::fmt::Debug;
use tracing::error;

#[cfg(unix)]
use libc::{c_int, EIO, ENOENT};

#[derive(Debug, Fail)]
pub enum FileSystemError {
    #[fail(display = "Input/Output error")]
    IoError(std::io::Error),

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
    UuidParseError(uuid::Error),
}

impl From<std::io::Error> for FileSystemError {
    fn from(err: std::io::Error) -> FileSystemError {
        FileSystemError::IoError(err)
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
        FileSystemError::UuidParseError(err)
    }
}

#[cfg(unix)]
pub fn unix_error_code_from_filesystem_error(fs: FileSystemError) -> c_int {
    error!("Error occurred: {:?}", fs);
    match fs {
        FileSystemError::IoError(io) => {
            if let Some(e) = io.raw_os_error() {
                e
            } else {
                EIO
            }
        }
        FileSystemError::CryptoError(CryptoError::IoError(io)) => {
            if let Some(e) = io.raw_os_error() {
                e
            } else {
                EIO
            }
        }
        FileSystemError::MasterKeyError(MasterKeyError::IoError(io)) => {
            if let Some(e) = io.raw_os_error() {
                e
            } else {
                EIO
            }
        }
        FileSystemError::InvalidPathError(_) => ENOENT,
        FileSystemError::PathIsNotExist(_) => ENOENT,
        _ => EIO,
    }
}
