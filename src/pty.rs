use std::{
    io::{Read, Write},
    time::{Duration, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::{
    data::{DataDecoder, DataError, DataSource},
    metadata::{ExitData, Metadata},
};

const PTY_MODE_ECHO: &str = "ECHO";

#[derive(Error, Debug)]
pub enum PTYParserError {
    #[error("data decoding error")]
    ReadError(DataError),
    #[error("could not write data")]
    WriteError(std::io::Error),
    #[error("ssh session has no PTY allocated")]
    PTYNotFound,
}

pub fn generate_replay<R: Read, W: Write>(
    meta: &Metadata,
    mut decoder: DataDecoder<R>,
    mut data_writer: W,
    mut times_writer: W,
) -> Result<(), PTYParserError> {
    let pty = match &meta.pty {
        Some(pty_meta) => pty_meta,
        None => return Err(PTYParserError::PTYNotFound),
    };

    let echo_enabled = pty
        .modes
        .iter()
        .any(|(mode, value)| mode == PTY_MODE_ECHO && *value != 0);

    write!(
        data_writer,
        "Session started on {} [TERM=\"{}\" COLUMNS=\"{}\" LINES=\"{}\"]\n",
        format_date(meta.started_at),
        pty.term.clone().unwrap_or("unknown".to_string()),
        pty.width,
        pty.height
    )
    .map_err(PTYParserError::WriteError)?;

    let mut latest_elapsed = 0;
    loop {
        let data_packet = match decoder.next().map_err(PTYParserError::ReadError)? {
            Some(packet) => packet,
            None => break,
        };

        if matches!(data_packet.source, DataSource::Client) {
            // the server playsback the client input
            continue;
        }

        data_writer
            .write(&data_packet.data)
            .map_err(PTYParserError::WriteError)?;
        let elapsed_micros = data_packet.elapsed.as_micros();
        let elapsed = (elapsed_micros - latest_elapsed) as f32 / 1000000 as f32;
        write!(times_writer, "{:.6} {}\n", elapsed, data_packet.data.len())
            .map_err(PTYParserError::WriteError)?;
        latest_elapsed = elapsed_micros;
    }

    write_exit_data(data_writer, &meta.exit_data)
}

fn write_exit_data<W: Write>(mut writer: W, data: &Option<ExitData>) -> Result<(), PTYParserError> {
    let exit_str = match data {
        Some(exit_data) => {
            let end = format_date(exit_data.timestamp);

            if let Some(ref e) = exit_data.error_msg {
                format!("\nScript done on {} [ERROR=\"{}\"]\n", end, e)
            } else if exit_data.core_dumped {
                format!("\nScript done on {} [CORE DUMPED]\n", end)
            } else {
                let code = exit_data.status.unwrap_or(0);
                format!(
                    "\nScript done on {} [COMMAND_EXIT_CODE=\"{}\"]\n",
                    end, code
                )
            }
        }
        None => format!("\nSession has no termination data\n"),
    };
    writer
        .write_all(exit_str.as_bytes())
        .map_err(PTYParserError::WriteError)?;
    Ok(())
}

fn format_date(unix_timestamp: u64) -> String {
    let d = UNIX_EPOCH + Duration::from_secs(unix_timestamp);
    let datetime = DateTime::<Utc>::from(d);
    datetime.format("%Y-%m-%d %H:%M:%S+00").to_string()
}
