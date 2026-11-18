use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use concord_common::sync::lock;
use concord_common::{BoxStream, Stream};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::conn::{HmacSha1, new_hmac};
use super::frames::{APPLICATION_DATA, FrameReader, HANDSHAKE, HEADER};
use crate::http1::invalid;

const SERVER_HELLO: u8 = 2;
const SERVER_RANDOM_INDEX: usize = HEADER + 1 + 3 + 2;
const RANDOM_SIZE: usize = 32;
const SESSION_ID_LENGTH_INDEX: usize = SERVER_RANDOM_INDEX + RANDOM_SIZE;
const HMAC_HEADER: usize = HEADER + super::conn::HMAC_SIZE;

/// Lets the handshake own a `BoxStream` while the caller keeps a way to take
/// the transport back once the handshake is over.
#[derive(Clone)]
pub(super) struct Lent(Arc<Mutex<Option<BoxStream>>>);

impl Lent {
    pub fn new(io: BoxStream) -> Self {
        Lent(Arc::new(Mutex::new(Some(io))))
    }

    pub fn take(&self) -> io::Result<BoxStream> {
        lock(&self.0)
            .take()
            .ok_or_else(|| invalid("shadow-tls: transport already taken"))
    }

    fn with<R>(
        &self,
        f: impl FnOnce(&mut BoxStream) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        match lock(&self.0).as_mut() {
            Some(inner) => f(inner),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
}

impl AsyncRead for Lent {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with(|inner| Pin::new(inner).poll_read(cx, buf))
    }
}

impl AsyncWrite for Lent {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with(|inner| Pin::new(inner).poll_write(cx, data))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with(|inner| Pin::new(inner).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with(|inner| Pin::new(inner).poll_shutdown(cx))
    }
}

impl Stream for Lent {}

pub(super) struct HashingRead {
    lent: Lent,
    mac: Arc<Mutex<HmacSha1>>,
}

impl HashingRead {
    pub fn new(lent: Lent, mac: Arc<Mutex<HmacSha1>>) -> Self {
        HashingRead { lent, mac }
    }
}

impl AsyncRead for HashingRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.lent).poll_read(cx, buf))?;
        if let Some(fresh) = buf.filled().get(before..) {
            lock(&this.mac).update(fresh);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for HashingRead {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().lent).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().lent).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().lent).poll_shutdown(cx)
    }
}

impl Stream for HashingRead {}

#[derive(Default)]
pub(super) struct V3State {
    pub server_random: Option<[u8; RANDOM_SIZE]>,
    pub read_mac: Option<HmacSha1>,
    pub is_tls13: bool,
    pub authorized: bool,
    pub leftover: usize,
}

pub(super) struct V3Tap {
    lent: Lent,
    password: Vec<u8>,
    state: Arc<Mutex<V3State>>,
    frames: FrameReader,
    key: [u8; 32],
    pending: Vec<u8>,
    pos: usize,
}

impl V3Tap {
    pub fn new(lent: Lent, password: &str, state: Arc<Mutex<V3State>>) -> Self {
        V3Tap {
            lent,
            password: password.as_bytes().to_vec(),
            state,
            frames: FrameReader::new(),
            key: [0; 32],
            pending: Vec::new(),
            pos: 0,
        }
    }

    fn process(&mut self, mut frame: Vec<u8>) -> io::Result<Vec<u8>> {
        let mut state = lock(&self.state);
        match frame.first().copied() {
            Some(HANDSHAKE) => {
                let hello = frame.get(HEADER) == Some(&SERVER_HELLO);
                if hello
                    && state.read_mac.is_none()
                    && let Some(random) =
                        frame.get(SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + RANDOM_SIZE)
                    && let Ok(random) = <[u8; RANDOM_SIZE]>::try_from(random)
                {
                    let mut mac = new_hmac(&self.password);
                    mac.update(&random);
                    self.key = kdf(&self.password, &random);
                    state.read_mac = Some(mac);
                    state.server_random = Some(random);
                    state.is_tls13 = server_hello_is_tls13(&frame);
                    state.authorized = !state.is_tls13;
                }
            }
            Some(APPLICATION_DATA) => {
                state.authorized = false;
                if frame.len() > HMAC_HEADER
                    && let Some(mac) = state.read_mac.as_mut()
                {
                    let payload = frame.get(HMAC_HEADER..).unwrap_or_default();
                    mac.update(payload);
                    let expected = mac.sum();
                    let wire = frame.get(HEADER..HMAC_HEADER).unwrap_or_default();
                    if expected.get(..wire.len()) != Some(wire) {
                        return Err(invalid(
                            "shadow-tls v3: HMAC mismatch, possible data corruption",
                        ));
                    }
                    frame.drain(HEADER..HMAC_HEADER);
                    for (byte, key) in frame.iter_mut().skip(HEADER).zip(self.key.iter().cycle()) {
                        *byte ^= key;
                    }
                    let [hi, lo] = u16::try_from(frame.len() - HEADER)
                        .map_err(|_| invalid("shadow-tls v3: record too large"))?
                        .to_be_bytes();
                    if let Some(len) = frame.get_mut(3..5) {
                        len.copy_from_slice(&[hi, lo]);
                    }
                    state.authorized = true;
                }
            }
            _ => {}
        }
        Ok(frame)
    }
}

pub(super) fn kdf(password: &[u8], server_random: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(server_random);
    hasher.finalize().into()
}

fn server_hello_is_tls13(frame: &[u8]) -> bool {
    let Some(&id_len) = frame.get(SESSION_ID_LENGTH_INDEX) else {
        return false;
    };
    let ext_len_at = SESSION_ID_LENGTH_INDEX + 1 + usize::from(id_len) + 3;
    let Some(ext_len) = frame
        .get(ext_len_at..ext_len_at + 2)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_be_bytes)
    else {
        return false;
    };
    let Some(mut extensions) = frame.get(ext_len_at + 2..ext_len_at + 2 + usize::from(ext_len))
    else {
        return false;
    };
    while extensions.len() >= 4 {
        let (Some(kind), Some(len)) = (
            extensions
                .get(..2)
                .and_then(|b| <[u8; 2]>::try_from(b).ok()),
            extensions
                .get(2..4)
                .and_then(|b| <[u8; 2]>::try_from(b).ok()),
        ) else {
            return false;
        };
        let len = usize::from(u16::from_be_bytes(len));
        let Some(body) = extensions.get(4..4 + len) else {
            return false;
        };
        if u16::from_be_bytes(kind) == 43 {
            return body == [0x03, 0x04];
        }
        extensions = extensions.get(4 + len..).unwrap_or_default();
    }
    false
}

impl AsyncRead for V3Tap {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(rest) = this.pending.get(this.pos..).filter(|rest| !rest.is_empty()) {
                let take = rest.len().min(buf.remaining());
                if let Some(chunk) = rest.get(..take) {
                    buf.put_slice(chunk);
                }
                this.pos += take;
                lock(&this.state).leftover = this.pending.len() - this.pos;
                return Poll::Ready(Ok(()));
            }
            let frame = match ready!(this.frames.poll_frame(&mut this.lent, cx))? {
                Some(frame) => frame,
                None => return Poll::Ready(Ok(())),
            };
            this.pending = this.process(frame)?;
            this.pos = 0;
        }
    }
}

impl AsyncWrite for V3Tap {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().lent).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().lent).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().lent).poll_shutdown(cx)
    }
}

impl Stream for V3Tap {}
