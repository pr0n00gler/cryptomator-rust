use failure::Fail;
use std::io;

#[derive(Debug, Fail)]
pub enum MasterKeyError {
    #[fail(display = "Input/Output error")]
    IOError(io::Error),
    #[fail(display = "Json serialize error")]
    SerializationJsonError(serde_json::error::Error),
}

impl From<io::Error> for MasterKeyError {
    fn from(err: io::Error) -> MasterKeyError {
        MasterKeyError::IOError(err)
    }
}

impl From<serde_json::Error> for MasterKeyError {
    fn from(err: serde_json::Error) -> MasterKeyError {
        MasterKeyError::SerializationJsonError(err)
    }
}