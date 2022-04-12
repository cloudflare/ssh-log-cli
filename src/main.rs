#![warn(rust_2018_idioms)]
mod data;
mod hpke;
mod metadata;
mod pty;
mod zip;

use crate::metadata::Metadata;
use clap::Parser;
use data::{generate_data_file, DataDecoder};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::{fs, str};
use tempfile::tempdir;
use walkdir::WalkDir;

const CLIENT_DATA_FILE_NAME: &str = "data_from_client.txt";
const SERVER_DATA_FILE_NAME: &str = "data_from_server.txt";
const REPLAY_DATA_FILE_NAME: &str = "term_data.txt";
const REPLAY_TIMES_FILE_NAME: &str = "term_times.txt";

#[derive(Parser)]
#[clap(about, author, version)]
struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
struct DecryptOptions {
    #[clap(
        short = 'i',
        long,
        help = "File containing the base64 encoded encrypted matched data"
    )]
    input_filename: String,

    #[clap(
        short = 'k',
        long,
        help = "File containing the base64 encoded private key"
    )]
    private_key_filename: String,

    #[clap(
        short = 'r',
        long,
        help = "Replay this session, only works if PTY was allocated for the session"
    )]
    replay: bool,

    #[clap(
        short = 'o',
        long,
        conflicts_with = "replay",
        help = "Output ZIP file name for the decrypted session data"
    )]
    output_file_name: Option<String>,
}

#[derive(Parser)]
struct GenerateKeyPairOptions {
    #[clap(short = 'o', long, help = "Output file name for the private key")]
    output_file_name: String,
}

#[derive(Parser)]
enum Command {
    Decrypt(DecryptOptions),
    GenerateKeyPair(GenerateKeyPairOptions),
}

fn run_pty_decode<R: Read>(
    metadata: &Metadata,
    decoder: DataDecoder<R>,
    base_path: &Path,
) -> Result<(String, String), String> {
    let replay_data_fname = base_path.join(REPLAY_DATA_FILE_NAME);
    let replay_times_fname = base_path.join(REPLAY_TIMES_FILE_NAME);

    let replay_data_fp =
        File::create(&replay_data_fname).map_err(|_| "Could not create output replay data file")?;
    let replay_times_fp = File::create(&replay_times_fname)
        .map_err(|_| "Could not create output replay time series file")?;

    pty::generate_replay(&metadata, decoder, replay_data_fp, replay_times_fp)
        .map_err(|_| "Could not parse pty data")?;

    Ok((
        replay_data_fname.to_str().unwrap().into(),
        replay_times_fname.to_str().unwrap().into(),
    ))
}

fn run_raw_decode<R: Read>(decoder: DataDecoder<R>, base_path: &Path) -> Result<(), String> {
    let client_data_fp = File::create(base_path.join(CLIENT_DATA_FILE_NAME))
        .map_err(|_| "Could not create client data file")?;
    let server_data_fp = File::create(base_path.join(SERVER_DATA_FILE_NAME))
        .map_err(|_| "Could not create server data file")?;

    generate_data_file(decoder, client_data_fp, server_data_fp)
        .map_err(|_| "Could parse write raw data".into())
}

fn replay_pty_session(data_fname: &str, times_fname: &str) -> Result<(), String> {
    std::process::Command::new("scriptreplay")
        .args(["--timing", times_fname, data_fname])
        .spawn()
        .map_err(|_| "Could not launch scriptreplay, make sure you have it in your PATH.")?
        .wait()
        .map_err(|_| "scriptreplay error")?;
    Ok(())
}

fn create_zip_output(fname: &str, path: &Path) -> Result<(), String> {
    let output = File::create(fname).unwrap();
    let walkdir = WalkDir::new(path);
    let it = walkdir.into_iter();

    zip::zip(
        &mut it.filter_map(|e| e.ok()),
        path.to_str().unwrap(),
        output,
    )
    .map_err(|_| "Could not zip output")?;
    Ok(())
}

fn run_decrypt(opts: DecryptOptions) -> Result<(), String> {
    let mut input_file =
        File::open(&opts.input_filename).map_err(|_| "Could not open input file")?;
    let private_key_base64 = fs::read_to_string(&opts.private_key_filename)
        .map_err(|_| "Failed to read private key from file")?;

    let metadata = Metadata::read(&mut input_file).map_err(|_| "Could not read metadata")?;
    let reader = hpke::Ctx::new(&metadata, private_key_base64, input_file)
        .map_err(|_| "Could not create decryption context")?;
    let decoder = DataDecoder(reader);

    let temp_dir = tempdir().map_err(|_| "Could not create temporary directory")?;
    let base_path = temp_dir.path();
    match metadata.pty {
        Some(_) => {
            let (data_fname, times_fname) = run_pty_decode(&metadata, decoder, base_path)?;
            if opts.replay {
                return replay_pty_session(&data_fname, &times_fname);
            }
        }
        None => {
            run_raw_decode(decoder, base_path)?;
        }
    }

    let out_file_name = opts
        .output_file_name
        .unwrap_or(format!("{}-decrypted.zip", opts.input_filename));
    if !out_file_name.ends_with(".zip") {
        return Err("Output file name must have a .zip extension".into());
    }

    create_zip_output(&out_file_name, &base_path)
}

fn run_generate_key_pair(opts: GenerateKeyPairOptions) -> Result<(), String> {
    let public_fname = format!("{}.pub", opts.output_file_name);
    let mut private_fp =
        File::create(opts.output_file_name).map_err(|_| "Could not create private key file")?;
    let mut public_fp =
        File::create(public_fname).map_err(|_| "Could not create public key file")?;

    let key_pair = hpke::KeyPair::new();
    private_fp
        .write_all(key_pair.0.as_bytes())
        .map_err(|_| "Could not write private key")?;
    public_fp
        .write_all(key_pair.1.as_bytes())
        .map_err(|_| "Could not write public key")?;
    Ok(())
}

fn run(options: Options) -> Result<(), String> {
    match options.command {
        Command::GenerateKeyPair(opts) => run_generate_key_pair(opts),
        Command::Decrypt(opts) => run_decrypt(opts),
    }
}

fn main() -> Result<(), String> {
    run(Options::parse())
}
