use crate::crypto::{CryptoError, MasterKeyError};
use std::path::PathBuf;
use thiserror::Error;

#[cfg(unix)]
use libc::{c_int, EIO, ENOENT};
use lru_cache::LruCache;

use crate::cryptofs::DirEntry;
#[cfg(unix)]
use tracing::debug;

#[derive(Debug, Error)]
pub enum FileSystemError {
    #[error("Input/Output error")]
    IoError(std::io::Error),

    #[error("Crypto error")]
    CryptoError(CryptoError),

    #[error("Master key error")]
    MasterKeyError(MasterKeyError),

    #[error("Unknown error")]
    UnknownError(String),

    #[error("Invalid path error")]
    InvalidPathError(String),

    #[error("Path does not exist error")]
    PathDoesNotExist(String),

    #[error("String from UTF-8 error")]
    StringConvertError(std::string::FromUtf8Error),

    #[error("UUID parse error")]
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

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, LruCache<PathBuf, Vec<u8>>>>>
    for FileSystemError
{
    fn from(
        err: std::sync::PoisonError<std::sync::MutexGuard<LruCache<PathBuf, Vec<u8>>>>,
    ) -> FileSystemError {
        FileSystemError::UnknownError(err.to_string())
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, LruCache<PathBuf, DirEntry>>>>
    for FileSystemError
{
    fn from(
        err: std::sync::PoisonError<std::sync::MutexGuard<LruCache<PathBuf, DirEntry>>>,
    ) -> FileSystemError {
        FileSystemError::UnknownError(err.to_string())
    }
}

#[cfg(unix)]
pub fn unix_error_code_from_filesystem_error(fs: FileSystemError) -> c_int {
    debug!("Error occurred: {:?}", fs);
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
        FileSystemError::PathDoesNotExist(_) => ENOENT,
        _ => EIO,
    }
}
