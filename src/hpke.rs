use std::{
    cmp::min,
    io::{self, Cursor, Read, Write},
};

use base64::DecodeError;
use hex::FromHexError;
use hpke::{
    aead::{AeadCtxR, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, HpkeError, Kem as KemTrait, OpModeR, Serializable,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;

use crate::metadata::Metadata;

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

type PrivateKey = <Kem as KemTrait>::PrivateKey;
type EncappedKey = <Kem as KemTrait>::EncappedKey;

#[derive(Error, Debug)]
pub enum HPKEDecryptionError {
    #[error("invalid base64 private key")]
    PrivateKeyInvalidB64(DecodeError),
    #[error("invalid private key")]
    PrivateKeyInvalid(HpkeError),
    #[error("invalid hex encapsulated key")]
    EncappedKeyInvalidHex(FromHexError),
    #[error("invalid encapsulated key")]
    EncappedKeyInvalid(HpkeError),
    #[error("error reading from reader")]
    BuffRead(std::io::Error),
    #[error("context creation error")]
    ContextCreation(HpkeError),
    #[error("error decrypting buffer")]
    Decrypt(HpkeError),
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    private_key: String,
    public_key: String,
}

impl KeyPair {
    // Generates a public-private key pair
    pub fn new() -> (String, String) {
        let mut csprng = StdRng::from_entropy();
        let (private, public) = Kem::gen_keypair(&mut csprng);
        let private = base64::encode(private.to_bytes());
        let public = base64::encode(public.to_bytes());
        (private, public)
    }
}

pub struct Ctx<R> {
    inner: AeadCtxR<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>,
    reader: R,
    pending: Vec<u8>,
}

impl<R: Read> Ctx<R> {
    pub fn new(
        meta: &Metadata,
        private_key: String,
        reader: R,
    ) -> Result<Self, HPKEDecryptionError> {
        let private_key =
            base64::decode(private_key).map_err(HPKEDecryptionError::PrivateKeyInvalidB64)?;
        let private_key =
            PrivateKey::from_bytes(&private_key).map_err(HPKEDecryptionError::PrivateKeyInvalid)?;

        let encapped_key = hex::decode(meta.encapsulated_key.as_bytes())
            .map_err(HPKEDecryptionError::EncappedKeyInvalidHex)?;
        let encapped_key = EncappedKey::from_bytes(&encapped_key)
            .map_err(HPKEDecryptionError::EncappedKeyInvalid)?;

        let inner = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private_key,
            &encapped_key,
            &[],
        )
        .map_err(HPKEDecryptionError::ContextCreation)?;

        Ok(Ctx {
            inner,
            reader,
            pending: Vec::new(),
        })
    }

    pub fn decrypt_block(&mut self) -> Result<Vec<u8>, HPKEDecryptionError> {
        let mut len: [u8; 4] = [0; 4];
        let read = self
            .reader
            .read(&mut len)
            .map_err(HPKEDecryptionError::BuffRead)?;
        if read == 0 {
            return Ok(Vec::new());
        }

        let len = u32::from_be_bytes(len) as usize;
        let mut buf = vec![0; len];
        self.reader
            .read_exact(&mut buf)
            .map_err(HPKEDecryptionError::BuffRead)?;
        self.inner
            .open(&buf, &[])
            .map_err(HPKEDecryptionError::Decrypt)
    }
}

fn write_buf(buf: &[u8], cursor: &mut Cursor<&mut [u8]>, n: usize) -> Result<Vec<u8>, io::Error> {
    let n = min(buf.len(), n);
    let (to_write, remaining) = buf.split_at(n);
    cursor.write_all(to_write)?;
    Ok(Vec::from(remaining))
}

impl<R: Read> Read for Ctx<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let buf_len = buf.len();
        let mut c = Cursor::new(buf);

        // read first from the pending buffer
        self.pending = write_buf(&self.pending, &mut c, buf_len)?;

        let buf_remaining = buf_len - c.position() as usize;
        if buf_remaining > 0 {
            // grab some more bytes from the underlying reader
            let decrypted = self
                .decrypt_block()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.pending = write_buf(&decrypted, &mut c, buf_remaining)?;
        }

        Ok(c.position() as usize)
    }
}
