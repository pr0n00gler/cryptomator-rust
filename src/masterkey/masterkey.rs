use serde::{Deserialize, Serialize};
use std::fs;

use crate::error::MasterKeyError;

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct MasterKey {
    version: u8,
    scryptSalt: String,
    scryptCostParam: u32,
    scryptBlockSize: u32,
    pub primaryMasterKey: String,
    hmacMasterKey: String,
    versionMac: String,
}

impl MasterKey {
    pub fn from_file(filename: String) -> Result<MasterKey, MasterKeyError> {
        let file = fs::File::open(filename)?;
        let m: MasterKey = serde_json::from_reader(file)?;
        Ok(m)
    }
}
