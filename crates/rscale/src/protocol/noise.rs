use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use blake2::Blake2s256;
use blake2::digest::Digest;
use graviola::aead::ChaCha20Poly1305;
use graviola::key_agreement::x25519::{PublicKey as X25519PublicKey, StaticPrivateKey};
use hkdf::{InvalidLength, SimpleHkdf};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{AppError, AppResult};

use super::keys::machine_public_key_from_raw;
use super::types::{EarlyNoise, MapResponse, wants_zstd};

const NOISE_PROTOCOL: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROTOCOL_VERSION_PREFIX: &str = "Tailscale Control Protocol v";
const INITIATION_MESSAGE_TYPE: u8 = 1;
const RESPONSE_MESSAGE_TYPE: u8 = 2;
const RECORD_MESSAGE_TYPE: u8 = 4;
const INITIATION_HEADER_LEN: usize = 5;
const RECORD_HEADER_LEN: usize = 3;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const INITIATION_PAYLOAD_LEN: usize = 96;
const RESPONSE_PAYLOAD_LEN: usize = 48;
const MAX_MESSAGE_SIZE: usize = 4096;
const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE - RECORD_HEADER_LEN;
const MAX_PLAINTEXT_SIZE: usize = MAX_CIPHERTEXT_SIZE - TAG_LEN;
const INITIATION_MESSAGE_LEN: usize = INITIATION_HEADER_LEN + INITIATION_PAYLOAD_LEN;
const INITIATION_EPHEMERAL_OFFSET: usize = INITIATION_HEADER_LEN;
const INITIATION_MACHINE_KEY_OFFSET: usize = INITIATION_EPHEMERAL_OFFSET + KEY_LEN;
const INITIATION_TAG_OFFSET: usize = INITIATION_MACHINE_KEY_OFFSET + KEY_LEN + TAG_LEN;
const RESPONSE_EPHEMERAL_OFFSET: usize = RECORD_HEADER_LEN;
const RESPONSE_TAG_OFFSET: usize = RESPONSE_EPHEMERAL_OFFSET + KEY_LEN;
const EARLY_PAYLOAD_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";

pub struct AcceptedControlConn<T> {
    pub transport: NoiseTransport<T>,
    pub machine_public_key: String,
    pub protocol_version: u16,
}

pub async fn accept<T>(
    io: T,
    control_private_key: &[u8; 32],
    initial_handshake: &[u8],
) -> AppResult<AcceptedControlConn<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let protocol_version = parse_protocol_version(initial_handshake)?;
    let control_private = StaticPrivateKey::from_array(control_private_key);
    let control_public = control_private.public_key().as_bytes();

    let mut symmetric = SymmetricState::initialize();
    symmetric.mix_hash(&protocol_version_prologue(protocol_version));
    symmetric.mix_hash(&control_public);

    let client_ephemeral = parse_public_key(
        &initial_handshake[INITIATION_EPHEMERAL_OFFSET..INITIATION_MACHINE_KEY_OFFSET],
        "client ephemeral public key",
    )?;
    symmetric.mix_hash(&client_ephemeral.as_bytes());

    let es_cipher = symmetric.mix_dh(&control_private, &client_ephemeral)?;
    let mut machine_public_key_raw = [0_u8; KEY_LEN];
    symmetric.decrypt_and_hash(
        &es_cipher,
        &mut machine_public_key_raw,
        &initial_handshake[INITIATION_MACHINE_KEY_OFFSET..INITIATION_TAG_OFFSET],
    )?;
    let machine_public_key = machine_public_key_from_raw(&machine_public_key_raw);
    let machine_public = X25519PublicKey::from_array(&machine_public_key_raw);

    let ss_cipher = symmetric.mix_dh(&control_private, &machine_public)?;
    symmetric.decrypt_and_hash(
        &ss_cipher,
        &mut [],
        &initial_handshake[INITIATION_TAG_OFFSET..INITIATION_MESSAGE_LEN],
    )?;

    let control_ephemeral = StaticPrivateKey::new_random().map_err(|err| {
        AppError::Bootstrap(format!("failed to generate control ephemeral key: {err}"))
    })?;
    let control_ephemeral_public = control_ephemeral.public_key().as_bytes();

    let mut response = [0_u8; RECORD_HEADER_LEN + RESPONSE_PAYLOAD_LEN];
    response[0] = RESPONSE_MESSAGE_TYPE;
    response[1..RECORD_HEADER_LEN].copy_from_slice(&(RESPONSE_PAYLOAD_LEN as u16).to_be_bytes());
    response[RESPONSE_EPHEMERAL_OFFSET..RESPONSE_TAG_OFFSET]
        .copy_from_slice(&control_ephemeral_public);

    symmetric.mix_hash(&control_ephemeral_public);
    let _ = symmetric.mix_dh(&control_ephemeral, &client_ephemeral)?;
    let se_cipher = symmetric.mix_dh(&control_ephemeral, &machine_public)?;
    symmetric.encrypt_and_hash(&se_cipher, &mut response[RESPONSE_TAG_OFFSET..], &[])?;

    let (rx, tx) = symmetric.split()?;
    let mut transport = NoiseTransport::new(io, rx, tx);
    transport
        .write_handshake_response(&response[RECORD_HEADER_LEN..])
        .await?;

    Ok(AcceptedControlConn {
        transport,
        machine_public_key,
        protocol_version,
    })
}

pub async fn write_early_payload<T>(
    transport: &mut NoiseTransport<T>,
    early_noise: &EarlyNoise,
) -> AppResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(early_noise)?;
    let length = u32::try_from(payload.len()).map_err(|_| {
        AppError::Bootstrap("early noise payload is too large to frame".to_string())
    })?;

    transport.write_all(EARLY_PAYLOAD_MAGIC).await?;
    transport.write_all(&length.to_be_bytes()).await?;
    transport.write_all(&payload).await?;
    transport.flush().await?;
    Ok(())
}

pub fn encode_map_response_frame(response: &MapResponse, compress: &str) -> AppResult<Vec<u8>> {
    let body = serde_json::to_vec(response)?;
    let payload = if wants_zstd(compress) {
        zstd::stream::encode_all(body.as_slice(), 3).map_err(|err| {
            AppError::Bootstrap(format!("failed to zstd-encode map response: {err}"))
        })?
    } else {
        body
    };

    let payload_len = u32::try_from(payload.len()).map_err(|_| {
        AppError::Bootstrap("map response payload is too large to frame".to_string())
    })?;

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn parse_protocol_version(initial_handshake: &[u8]) -> AppResult<u16> {
    if initial_handshake.len() != INITIATION_MESSAGE_LEN {
        return Err(AppError::InvalidRequest(format!(
            "unexpected TS2021 handshake size: {}",
            initial_handshake.len()
        )));
    }

    let protocol_version = u16::from_be_bytes([initial_handshake[0], initial_handshake[1]]);
    if initial_handshake[2] != INITIATION_MESSAGE_TYPE {
        return Err(AppError::InvalidRequest(format!(
            "unexpected TS2021 message type: {}",
            initial_handshake[2]
        )));
    }

    let payload_len = u16::from_be_bytes([initial_handshake[3], initial_handshake[4]]) as usize;
    if payload_len != INITIATION_PAYLOAD_LEN {
        return Err(AppError::InvalidRequest(format!(
            "unexpected TS2021 payload length: {payload_len}"
        )));
    }

    Ok(protocol_version)
}

fn protocol_version_prologue(version: u16) -> Vec<u8> {
    let mut value = PROTOCOL_VERSION_PREFIX.as_bytes().to_vec();
    value.extend_from_slice(version.to_string().as_bytes());
    value
}

fn parse_public_key(bytes: &[u8], label: &str) -> AppResult<X25519PublicKey> {
    X25519PublicKey::try_from_slice(bytes)
        .map_err(|err| AppError::Unauthorized(format!("invalid {label}: {err}")))
}

pub struct NoiseTransport<T> {
    io: T,
    rx: CipherState,
    tx: CipherState,
    read_header: [u8; RECORD_HEADER_LEN],
    read_header_filled: usize,
    read_ciphertext: Vec<u8>,
    read_ciphertext_len: usize,
    read_ciphertext_filled: usize,
    read_plaintext: Vec<u8>,
    read_plaintext_offset: usize,
    write_pending: Vec<u8>,
    write_pending_offset: usize,
}

impl<T> NoiseTransport<T> {
    fn new(io: T, rx: CipherState, tx: CipherState) -> Self {
        Self {
            io,
            rx,
            tx,
            read_header: [0; RECORD_HEADER_LEN],
            read_header_filled: 0,
            read_ciphertext: Vec::new(),
            read_ciphertext_len: 0,
            read_ciphertext_filled: 0,
            read_plaintext: Vec::new(),
            read_plaintext_offset: 0,
            write_pending: Vec::new(),
            write_pending_offset: 0,
        }
    }
}

impl<T> NoiseTransport<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    async fn write_handshake_response(&mut self, payload: &[u8]) -> AppResult<()> {
        let mut frame = [0_u8; RECORD_HEADER_LEN + RESPONSE_PAYLOAD_LEN];
        frame[0] = RESPONSE_MESSAGE_TYPE;
        frame[1..RECORD_HEADER_LEN].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        frame[RECORD_HEADER_LEN..].copy_from_slice(payload);
        self.io.write_all(&frame).await?;
        self.io.flush().await?;
        Ok(())
    }

    fn poll_flush_pending(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.write_pending_offset < this.write_pending.len() {
            let offset = this.write_pending_offset;
            let chunk = this.write_pending[offset..].to_vec();
            let written = match Pin::new(&mut this.io).poll_write(cx, &chunk) {
                Poll::Ready(Ok(written)) => written,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            };

            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to flush pending Noise frame",
                )));
            }

            this.write_pending_offset += written;
        }

        this.write_pending.clear();
        this.write_pending_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn ensure_plaintext(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.read_plaintext_offset < this.read_plaintext.len() {
                return Poll::Ready(Ok(()));
            }

            if this.read_header_filled < RECORD_HEADER_LEN {
                let start = this.read_header_filled;
                let mut read_buf = ReadBuf::new(&mut this.read_header[start..RECORD_HEADER_LEN]);
                match Pin::new(&mut this.io).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let filled = read_buf.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF while reading Noise frame header",
                            )));
                        }
                        this.read_header_filled += filled;
                        continue;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if this.read_ciphertext_len == 0 {
                if this.read_header[0] != RECORD_MESSAGE_TYPE {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected Noise frame type {}", this.read_header[0]),
                    )));
                }

                this.read_ciphertext_len =
                    u16::from_be_bytes([this.read_header[1], this.read_header[2]]) as usize;
                if this.read_ciphertext_len > MAX_CIPHERTEXT_SIZE {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Noise frame too large: {}", this.read_ciphertext_len),
                    )));
                }

                let read_ciphertext_len = this.read_ciphertext_len;
                this.read_ciphertext.clear();
                this.read_ciphertext.resize(read_ciphertext_len, 0);
                this.read_ciphertext_filled = 0;
            }

            if this.read_ciphertext_filled < this.read_ciphertext_len {
                let start = this.read_ciphertext_filled;
                let end = this.read_ciphertext_len;
                let mut read_buf = ReadBuf::new(&mut this.read_ciphertext[start..end]);
                match Pin::new(&mut this.io).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let filled = read_buf.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF while reading Noise frame body",
                            )));
                        }
                        this.read_ciphertext_filled += filled;
                        continue;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let mut plaintext = this.read_ciphertext.clone();
            let plain_len = this.rx.decrypt_in_place(&mut plaintext)?;
            plaintext.truncate(plain_len);

            this.read_header_filled = 0;
            this.read_ciphertext_len = 0;
            this.read_ciphertext_filled = 0;
            this.read_plaintext = plaintext;
            this.read_plaintext_offset = 0;
        }
    }
}

impl<T> AsyncRead for NoiseTransport<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().ensure_plaintext(cx) {
            Poll::Ready(Ok(())) => {
                let remaining = &self.read_plaintext[self.read_plaintext_offset..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                self.read_plaintext_offset += to_copy;
                if self.read_plaintext_offset == self.read_plaintext.len() {
                    self.read_plaintext.clear();
                    self.read_plaintext_offset = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> AsyncWrite for NoiseTransport<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let plaintext_len = buf.len().min(MAX_PLAINTEXT_SIZE);
        let this = self.as_mut().get_mut();
        this.tx
            .encode_frame(&buf[..plaintext_len], &mut this.write_pending)?;

        match self.as_mut().poll_flush_pending(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(plaintext_len)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.io).poll_flush(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.io).poll_shutdown(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct CipherState {
    cipher: ChaCha20Poly1305,
    nonce: ControlNonce,
}

impl CipherState {
    fn new(key: [u8; KEY_LEN]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key),
            nonce: ControlNonce::default(),
        }
    }

    fn encode_frame(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.nonce.current()?;
        let mut ciphertext = plaintext.to_vec();
        let mut tag = [0_u8; TAG_LEN];
        self.cipher.encrypt(&nonce, &[], &mut ciphertext, &mut tag);
        self.nonce.increment()?;

        out.reserve(RECORD_HEADER_LEN + ciphertext.len() + TAG_LEN);
        out.push(RECORD_MESSAGE_TYPE);
        out.extend_from_slice(&((ciphertext.len() + TAG_LEN) as u16).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn decrypt_in_place(&mut self, ciphertext_and_tag: &mut [u8]) -> io::Result<usize> {
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Noise frame is too short to contain an authentication tag",
            ));
        }

        let plaintext_len = ciphertext_and_tag.len() - TAG_LEN;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(plaintext_len);
        let nonce = self.nonce.current()?;
        self.cipher
            .decrypt(&nonce, &[], ciphertext, &tag[..])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypt error"))?;
        self.nonce.increment()?;
        Ok(plaintext_len)
    }
}

#[derive(Clone, Copy, Default)]
struct ControlNonce(u64);

impl ControlNonce {
    fn current(&self) -> io::Result<[u8; NONCE_LEN]> {
        if self.0 == u64::MAX {
            return Err(io::Error::other(
                "cipher exhausted, no more nonces available for current key",
            ));
        }

        let mut nonce = [0_u8; NONCE_LEN];
        nonce[4..].copy_from_slice(&self.0.to_be_bytes());
        Ok(nonce)
    }

    fn increment(&mut self) -> io::Result<()> {
        if self.0 == u64::MAX {
            return Err(io::Error::other(
                "cipher exhausted, no more nonces available for current key",
            ));
        }
        self.0 += 1;
        Ok(())
    }
}

struct SymmetricState {
    h: [u8; KEY_LEN],
    ck: [u8; KEY_LEN],
    finished: bool,
}

impl SymmetricState {
    fn initialize() -> Self {
        let hash = blake2s(NOISE_PROTOCOL);
        Self {
            h: hash,
            ck: hash,
            finished: false,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.ensure_active();
        let mut hasher = Blake2s256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    fn mix_dh(
        &mut self,
        private_key: &StaticPrivateKey,
        public_key: &X25519PublicKey,
    ) -> AppResult<SingleUseCipher> {
        self.ensure_active();
        let shared_secret = private_key.diffie_hellman(public_key).map_err(|err| {
            AppError::Unauthorized(format!("failed to compute Noise shared secret: {err}"))
        })?;

        let mut output = [0_u8; KEY_LEN * 2];
        hkdf_expand(&self.ck, &shared_secret.0, &mut output).map_err(|err| {
            AppError::Bootstrap(format!("failed to derive Noise chaining key: {err}"))
        })?;
        self.ck.copy_from_slice(&output[..KEY_LEN]);
        let mut cipher_key = [0_u8; KEY_LEN];
        cipher_key.copy_from_slice(&output[KEY_LEN..]);
        Ok(SingleUseCipher::new(cipher_key))
    }

    fn encrypt_and_hash(
        &mut self,
        cipher: &SingleUseCipher,
        ciphertext: &mut [u8],
        plaintext: &[u8],
    ) -> AppResult<()> {
        self.ensure_active();
        if ciphertext.len() != plaintext.len() + TAG_LEN {
            return Err(AppError::Bootstrap(
                "invalid Noise handshake ciphertext buffer length".to_string(),
            ));
        }
        cipher.encrypt(ciphertext, plaintext, &self.h);
        self.mix_hash(ciphertext);
        Ok(())
    }

    fn decrypt_and_hash(
        &mut self,
        cipher: &SingleUseCipher,
        plaintext: &mut [u8],
        ciphertext: &[u8],
    ) -> AppResult<()> {
        self.ensure_active();
        if ciphertext.len() != plaintext.len() + TAG_LEN {
            return Err(AppError::Unauthorized(
                "invalid Noise handshake ciphertext length".to_string(),
            ));
        }
        cipher
            .decrypt(plaintext, ciphertext, &self.h)
            .map_err(|err| {
                AppError::Unauthorized(format!("failed to decrypt Noise handshake payload: {err}"))
            })?;
        self.mix_hash(ciphertext);
        Ok(())
    }

    fn split(&mut self) -> AppResult<(CipherState, CipherState)> {
        self.ensure_active();
        self.finished = true;

        let mut output = [0_u8; KEY_LEN * 2];
        hkdf_expand(&self.ck, &[], &mut output)
            .map_err(|err| AppError::Bootstrap(format!("failed to split Noise session: {err}")))?;

        let mut key_one = [0_u8; KEY_LEN];
        let mut key_two = [0_u8; KEY_LEN];
        key_one.copy_from_slice(&output[..KEY_LEN]);
        key_two.copy_from_slice(&output[KEY_LEN..]);
        Ok((CipherState::new(key_one), CipherState::new(key_two)))
    }

    fn ensure_active(&self) {
        assert!(!self.finished, "attempted to reuse completed Noise state");
    }
}

struct SingleUseCipher {
    key: [u8; KEY_LEN],
}

impl SingleUseCipher {
    fn new(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }

    fn encrypt(&self, ciphertext: &mut [u8], plaintext: &[u8], aad: &[u8]) {
        let mut body = plaintext.to_vec();
        let mut tag = [0_u8; TAG_LEN];
        ChaCha20Poly1305::new(self.key).encrypt(&[0_u8; NONCE_LEN], aad, &mut body, &mut tag);
        ciphertext[..plaintext.len()].copy_from_slice(&body);
        ciphertext[plaintext.len()..].copy_from_slice(&tag);
    }

    fn decrypt(&self, plaintext: &mut [u8], ciphertext: &[u8], aad: &[u8]) -> Result<(), String> {
        let body_len = ciphertext.len() - TAG_LEN;
        let mut body = ciphertext[..body_len].to_vec();
        ChaCha20Poly1305::new(self.key)
            .decrypt(&[0_u8; NONCE_LEN], aad, &mut body, &ciphertext[body_len..])
            .map_err(|err| err.to_string())?;
        plaintext.copy_from_slice(&body);
        Ok(())
    }
}

fn hkdf_expand(
    salt: &[u8],
    input_key_material: &[u8],
    output: &mut [u8],
) -> Result<(), InvalidLength> {
    SimpleHkdf::<Blake2s256>::new(Some(salt), input_key_material).expand(&[], output)
}

fn blake2s(data: &[u8]) -> [u8; KEY_LEN] {
    Blake2s256::digest(data).into()
}

pub fn encode_json_body<T: Serialize>(value: &T) -> AppResult<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    const CONTROL_PRIVATE_KEY: [u8; 32] = [0x11; 32];
    const CLIENT_PRIVATE_KEY: [u8; 32] = [0x22; 32];
    const CLIENT_EPHEMERAL_PRIVATE_KEY: [u8; 32] = [0x33; 32];
    const PROTOCOL_VERSION: u16 = 57;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn parse_protocol_version_accepts_valid_frame() -> TestResult {
        let (frame, _) = build_client_initiation(PROTOCOL_VERSION)?;
        let version = parse_protocol_version(&frame)?;
        assert_eq!(version, PROTOCOL_VERSION);
        Ok(())
    }

    #[test]
    fn parse_protocol_version_rejects_bad_type_and_length() -> TestResult {
        let (mut frame, _) = build_client_initiation(PROTOCOL_VERSION)?;
        frame[2] = 9;
        let wrong_type = match parse_protocol_version(&frame) {
            Ok(_) => return Err(std::io::Error::other("unexpected type should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(wrong_type, AppError::InvalidRequest(message) if message.contains("message type"))
        );

        let mut short = frame;
        short.truncate(short.len() - 1);
        let short_err = match parse_protocol_version(&short) {
            Ok(_) => return Err(std::io::Error::other("short handshake should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(short_err, AppError::InvalidRequest(message) if message.contains("handshake size"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn accept_completes_handshake_and_exposes_machine_key() -> TestResult {
        let (accepted, _client_io, _client_session, client_public_key) =
            complete_handshake().await?;
        assert_eq!(accepted.protocol_version, PROTOCOL_VERSION);
        assert_eq!(
            accepted.machine_public_key,
            machine_public_key_from_raw(&client_public_key)
        );
        Ok(())
    }

    #[tokio::test]
    async fn accept_rejects_corrupted_initiation_payload() -> TestResult {
        let (server_io, _client_io) = duplex(4096);
        let (mut initiation, _) = build_client_initiation(PROTOCOL_VERSION)?;
        let last = initiation.len() - 1;
        initiation[last] ^= 0xff;

        let err = match accept(server_io, &CONTROL_PRIVATE_KEY, &initiation).await {
            Ok(_) => return Err(std::io::Error::other("corrupted initiation should fail").into()),
            Err(err) => err,
        };
        assert!(
            matches!(err, AppError::Unauthorized(message) if message.contains("Noise handshake"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn noise_transport_reads_multiple_client_records() -> TestResult {
        let (mut accepted, mut client_io, mut client_session, _) = complete_handshake().await?;
        let first = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let second = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
        client_io
            .write_all(&encode_client_record(&mut client_session, first)?)
            .await?;
        client_io
            .write_all(&encode_client_record(&mut client_session, second)?)
            .await?;

        let mut received = vec![0_u8; first.len() + second.len()];
        accepted.transport.read_exact(&mut received).await?;
        assert_eq!(&received[..first.len()], first);
        assert_eq!(&received[first.len()..], second);
        Ok(())
    }

    #[tokio::test]
    async fn noise_transport_rejects_invalid_record_type() -> TestResult {
        let (mut accepted, mut client_io, _client_session, _) = complete_handshake().await?;
        client_io.write_all(&[0x09, 0x00, 0x01, 0x00]).await?;

        let err = match accepted.transport.read_u8().await {
            Ok(_) => return Err(std::io::Error::other("invalid frame type should fail").into()),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        Ok(())
    }

    #[tokio::test]
    async fn write_early_payload_emits_magic_and_json_over_noise() -> TestResult {
        let (mut accepted, mut client_io, mut client_session, _) = complete_handshake().await?;
        let early_noise = EarlyNoise {
            node_key_challenge: "chalpub:abcdef".to_string(),
        };

        write_early_payload(&mut accepted.transport, &early_noise).await?;
        let magic = decode_client_record(&mut client_io, &mut client_session).await?;
        let length = decode_client_record(&mut client_io, &mut client_session).await?;
        let payload = decode_client_record(&mut client_io, &mut client_session).await?;

        assert_eq!(magic, EARLY_PAYLOAD_MAGIC);
        let payload_len = u32::from_be_bytes(length.as_slice().try_into()?) as usize;
        assert_eq!(payload.len(), payload_len);
        let decoded: EarlyNoise = serde_json::from_slice(&payload)?;
        assert_eq!(decoded, early_noise);
        Ok(())
    }

    #[test]
    fn encode_map_response_frame_supports_plain_and_zstd() -> TestResult {
        let response = MapResponse {
            keep_alive: true,
            pop_browser_url: "https://login.example.com/device".to_string(),
            ..MapResponse::default()
        };

        let plain = encode_map_response_frame(&response, "")?;
        let plain_len = u32::from_le_bytes(plain[..4].try_into()?) as usize;
        let plain_body = &plain[4..];
        assert_eq!(plain_body.len(), plain_len);
        let decoded_plain: MapResponse = serde_json::from_slice(plain_body)?;
        assert_eq!(decoded_plain, response);

        let compressed = encode_map_response_frame(&response, "zstd")?;
        let compressed_len = u32::from_le_bytes(compressed[..4].try_into()?) as usize;
        let compressed_body = &compressed[4..];
        assert_eq!(compressed_body.len(), compressed_len);
        let decompressed = zstd::stream::decode_all(compressed_body)?;
        let decoded_compressed: MapResponse = serde_json::from_slice(&decompressed)?;
        assert_eq!(decoded_compressed, response);
        Ok(())
    }

    #[test]
    fn encode_json_body_serializes_structs() -> TestResult {
        let payload = encode_json_body(&EarlyNoise {
            node_key_challenge: "chalpub:test".to_string(),
        })?;
        let decoded: EarlyNoise = serde_json::from_slice(&payload)?;
        assert_eq!(decoded.node_key_challenge, "chalpub:test");
        Ok(())
    }

    async fn complete_handshake() -> TestResult<(
        AcceptedControlConn<DuplexStream>,
        DuplexStream,
        TestClientSession,
        [u8; 32],
    )> {
        let (server_io, mut client_io) = duplex(4096);
        let (initiation, continuation) = build_client_initiation(PROTOCOL_VERSION)?;
        let client_public_key = public_key_raw(&CLIENT_PRIVATE_KEY);

        let accepted = accept(server_io, &CONTROL_PRIVATE_KEY, &initiation).await?;

        let mut response = [0_u8; RECORD_HEADER_LEN + RESPONSE_PAYLOAD_LEN];
        client_io.read_exact(&mut response).await?;
        assert_eq!(response[0], RESPONSE_MESSAGE_TYPE);
        let response_len = u16::from_be_bytes([response[1], response[2]]) as usize;
        assert_eq!(response_len, RESPONSE_PAYLOAD_LEN);

        let client_session = continue_client_handshake(continuation, &response)?;

        Ok((accepted, client_io, client_session, client_public_key))
    }

    fn build_client_initiation(version: u16) -> TestResult<(Vec<u8>, ClientContinuation)> {
        let machine_private = StaticPrivateKey::from_array(&CLIENT_PRIVATE_KEY);
        let machine_ephemeral = StaticPrivateKey::from_array(&CLIENT_EPHEMERAL_PRIVATE_KEY);
        let control_public = StaticPrivateKey::from_array(&CONTROL_PRIVATE_KEY)
            .public_key()
            .as_bytes();
        let control_public = X25519PublicKey::from_array(&control_public);

        let mut symmetric = SymmetricState::initialize();
        symmetric.mix_hash(&protocol_version_prologue(version));
        symmetric.mix_hash(&control_public.as_bytes());

        let machine_ephemeral_public = machine_ephemeral.public_key().as_bytes();
        let machine_public = machine_private.public_key().as_bytes();
        let mut frame = vec![0_u8; INITIATION_MESSAGE_LEN];
        frame[..2].copy_from_slice(&version.to_be_bytes());
        frame[2] = INITIATION_MESSAGE_TYPE;
        frame[3..INITIATION_HEADER_LEN]
            .copy_from_slice(&(INITIATION_PAYLOAD_LEN as u16).to_be_bytes());
        frame[INITIATION_EPHEMERAL_OFFSET..INITIATION_MACHINE_KEY_OFFSET]
            .copy_from_slice(&machine_ephemeral_public);

        symmetric.mix_hash(&machine_ephemeral_public);
        let es_cipher = symmetric.mix_dh(&machine_ephemeral, &control_public)?;
        symmetric.encrypt_and_hash(
            &es_cipher,
            &mut frame[INITIATION_MACHINE_KEY_OFFSET..INITIATION_TAG_OFFSET],
            &machine_public,
        )?;
        let ss_cipher = symmetric.mix_dh(&machine_private, &control_public)?;
        symmetric.encrypt_and_hash(
            &ss_cipher,
            &mut frame[INITIATION_TAG_OFFSET..INITIATION_MESSAGE_LEN],
            &[],
        )?;

        Ok((
            frame,
            ClientContinuation {
                machine_private,
                machine_ephemeral,
                symmetric,
            },
        ))
    }

    fn continue_client_handshake(
        continuation: ClientContinuation,
        response: &[u8; RECORD_HEADER_LEN + RESPONSE_PAYLOAD_LEN],
    ) -> TestResult<TestClientSession> {
        let mut symmetric = continuation.symmetric;
        let control_ephemeral = parse_public_key(
            &response[RESPONSE_EPHEMERAL_OFFSET..RESPONSE_TAG_OFFSET],
            "control ephemeral public key",
        )?;

        symmetric.mix_hash(&control_ephemeral.as_bytes());
        let _ = symmetric.mix_dh(&continuation.machine_ephemeral, &control_ephemeral)?;
        let se_cipher = symmetric.mix_dh(&continuation.machine_private, &control_ephemeral)?;
        symmetric.decrypt_and_hash(&se_cipher, &mut [], &response[RESPONSE_TAG_OFFSET..])?;

        let (tx, rx) = symmetric.split()?;
        Ok(TestClientSession { rx, tx })
    }

    fn public_key_raw(private_key: &[u8; 32]) -> [u8; 32] {
        StaticPrivateKey::from_array(private_key)
            .public_key()
            .as_bytes()
    }

    fn encode_client_record(
        session: &mut TestClientSession,
        plaintext: &[u8],
    ) -> TestResult<Vec<u8>> {
        let mut frame = Vec::new();
        session.tx.encode_frame(plaintext, &mut frame)?;
        Ok(frame)
    }

    async fn decode_client_record(
        client_io: &mut DuplexStream,
        session: &mut TestClientSession,
    ) -> TestResult<Vec<u8>> {
        let mut header = [0_u8; RECORD_HEADER_LEN];
        client_io.read_exact(&mut header).await?;
        assert_eq!(header[0], RECORD_MESSAGE_TYPE);

        let ciphertext_len = u16::from_be_bytes([header[1], header[2]]) as usize;
        let mut ciphertext = vec![0_u8; ciphertext_len];
        client_io.read_exact(&mut ciphertext).await?;

        let plain_len = session.rx.decrypt_in_place(&mut ciphertext)?;
        ciphertext.truncate(plain_len);
        Ok(ciphertext)
    }

    struct ClientContinuation {
        machine_private: StaticPrivateKey,
        machine_ephemeral: StaticPrivateKey,
        symmetric: SymmetricState,
    }

    struct TestClientSession {
        rx: CipherState,
        tx: CipherState,
    }
}
