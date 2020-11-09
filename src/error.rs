use failure::Fail;

#[derive(Debug, Fail)]
pub enum MasterKeyError {
    #[fail(display = "Input/Output error")]
    IOError(std::io::Error),
    #[fail(display = "Json serialize error")]
    SerializationJsonError(serde_json::Error),
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
