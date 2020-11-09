use std::fs;
use std::io;

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum MasterKeyError {
    IO(io::Error),
    JSON(serde_json::Error)
}

impl From<io::Error> for MasterKeyError {
    fn from(err: io::Error) -> MasterKeyError {
        MasterKeyError::IO(err)
    }
}

impl From<serde_json::Error> for MasterKeyError {
    fn from(err: serde_json::Error) -> MasterKeyError {
        MasterKeyError::JSON(err)
    }
}

#[derive(Deserialize, Serialize)]
pub struct MasterKey {
    version: u8,
    scryptSalt: String,
    scryptCostParam: u32,
    scryptBlockSize: u32,
    pub primaryMasterKey: String,
    hmacMasterKey: String,
    versionMac: String
}

impl MasterKey {
    pub fn from_file(filename: String) -> Result<MasterKey, MasterKeyError> {
        let file = fs::File::open(filename)?;
        let m: MasterKey = serde_json::from_reader(file)?;
        Ok(m)
    }
}