use std::io::Read;

use base64::DecodeError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PTYMetadata {
    pub term: Option<String>,
    pub width: u32,
    pub height: u32,
    pub modes: Vec<(String, u32)>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ExitData {
    pub timestamp: u64,
    pub status: Option<u32>,
    pub signal: Option<String>,
    #[serde(default)]
    pub core_dumped: bool,
    pub error_msg: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Metadata {
    pub started_at: u64,
    pub data_size: u64,
    pub encapsulated_key: String,
    pub pty: Option<PTYMetadata>,
    pub exit_data: Option<ExitData>,
}

#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("could not read metadata")]
    ReadError(std::io::Error),
    #[error("invalid base64 metadata")]
    DecodeB64Meta(DecodeError),
    #[error("invalid metadata json")]
    DecodeJsonMeta(serde_json::Error),
}

impl Metadata {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, MetadataError> {
        let mut b64len: [u8; 4] = [0; 4];
        reader
            .read_exact(&mut b64len)
            .map_err(MetadataError::ReadError)?;
        let b64len = u32::from_be_bytes(b64len) as usize;
        let mut b64meta: Vec<u8> = vec![0; b64len];
        reader
            .read_exact(&mut b64meta)
            .map_err(MetadataError::ReadError)?;

        let metadata = base64::decode(&b64meta).map_err(MetadataError::DecodeB64Meta)?;
        serde_json::from_slice(&metadata).map_err(MetadataError::DecodeJsonMeta)
    }
}
