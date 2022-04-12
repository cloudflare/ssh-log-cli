use std::{
    fmt::Debug,
    io::{Read, Write},
    time::Duration,
};

use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

#[derive(Copy, Clone)]
pub enum DataSource {
    Client,
    Origin,
}

pub struct DataPacket {
    pub source: DataSource,
    pub code: u32,
    pub elapsed: Duration,
    pub data: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum DataError {
    #[error("read error")]
    ReadError(std::io::Error),
    #[error("write error")]
    WriteError(std::io::Error),
    #[error("data packet too small")]
    DataPacketTooSmall,
    #[error("unexpected data source")]
    UnexpectedDataSource,
}

pub struct DataDecoder<R: Read>(pub R);

impl<R: Read> DataDecoder<R> {
    pub fn next(&mut self) -> Result<Option<DataPacket>, DataError> {
        let mut total_len: [u8; 4] = [0; 4];
        let read = self.0.read(&mut total_len).map_err(DataError::ReadError)?;
        if read == 0 {
            return Ok(None);
        }
        let total_len = u32::from_be_bytes(total_len) as usize;
        if total_len < 13 {
            return Err(DataError::DataPacketTooSmall);
        }

        let mut buf: Vec<u8> = vec![0; total_len];
        self.0.read_exact(&mut buf).map_err(DataError::ReadError)?;

        let source = match buf[0] {
            0 => DataSource::Client,
            1 => DataSource::Origin,
            _ => return Err(DataError::UnexpectedDataSource),
        };

        Ok(Some(DataPacket {
            source,
            code: BigEndian::read_u32(&buf[1..5]),
            elapsed: Duration::from_micros(BigEndian::read_u64(&buf[5..13])),
            data: Vec::from(&buf[13..]),
        }))
    }
}

pub fn generate_data_file<R: Read, W: Write>(
    mut decoder: DataDecoder<R>,
    mut client_data_writer: W,
    mut origin_data_writer: W,
) -> Result<(), DataError> {
    loop {
        let data_packet = match decoder.next()? {
            Some(packet) => packet,
            None => return Ok(()),
        };
        let writer = match data_packet.source {
            DataSource::Client => &mut client_data_writer,
            DataSource::Origin => &mut origin_data_writer,
        };
        writer
            .write(&data_packet.data)
            .map_err(DataError::WriteError)?;
    }
}
