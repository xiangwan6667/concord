use std::io;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, ready};

use concord_common::{BoxRead, BoxStream, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Client;
use super::crypto::{Aead, Ctr, ctr};
use super::mask::{MaskedRead, MaskedWrite};

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid VLESS Encryption record header",
    )
}

pub(super) fn record_length(header: &[u8; 5]) -> io::Result<usize> {
    let [kind, major, minor, hi, lo] = *header;
    let length = usize::from(u16::from_be_bytes([hi, lo]));
    if [kind, major, minor] != [23, 3, 3] || !(17..=16640).contains(&length) {
        return Err(invalid());
    }
    Ok(length)
}

fn fill(
    io: &mut MaskedRead,
    bytes: &mut [u8],
    have: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<bool>> {
    while *have < bytes.len() {
        let mut buf = ReadBuf::new(bytes.get_mut(*have..).unwrap_or_default());
        ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
        let count = buf.filled().len();
        if count == 0 {
            return Poll::Ready(Ok(false));
        }
        *have += count;
    }
    Poll::Ready(Ok(true))
}

pub(crate) struct EncryptionRead {
    io: MaskedRead,
    key: Option<Aead>,
    united: Arc<Vec<u8>>,
    aes: bool,
    random: bool,
    initial: [u8; 16],
    initial_have: usize,
    padding: Vec<u8>,
    padding_have: usize,
    header: [u8; 5],
    header_have: usize,
    decoded: bool,
    body: Vec<u8>,
    body_have: usize,
    plain: std::ops::Range<usize>,
    resumption: Option<(Weak<Client>, Vec<u8>)>,
    failed: bool,
}

pub(crate) struct EncryptionWrite {
    io: MaskedWrite,
    key: Aead,
    united: Arc<Vec<u8>>,
    aes: bool,
    prefix: Vec<u8>,
    pending: Vec<u8>,
    sent: usize,
    failed: bool,
}

pub(super) struct State {
    pub(super) write: Aead,
    pub(super) read: Option<Aead>,
    pub(super) united: Vec<u8>,
    pub(super) aes: bool,
    pub(super) prefix: Vec<u8>,
    pub(super) padding: usize,
    pub(super) write_xor: Option<Ctr>,
    pub(super) read_xor: Option<Ctr>,
    pub(super) random: bool,
    pub(super) resumption: Option<(Weak<Client>, Vec<u8>)>,
}

pub(crate) struct EncryptionStream {
    read: EncryptionRead,
    write: EncryptionWrite,
}

impl EncryptionStream {
    pub(super) fn new(io: BoxStream, state: State) -> Self {
        let (read, write) = io.into_split();
        let united = Arc::new(state.united);
        Self {
            read: EncryptionRead {
                io: MaskedRead::new(
                    read,
                    state.read_xor,
                    if state.read.is_none() {
                        16
                    } else {
                        state.padding
                    },
                ),
                key: state.read,
                united: united.clone(),
                aes: state.aes,
                random: state.random,
                initial: [0; 16],
                initial_have: 0,
                padding: vec![0; state.padding],
                padding_have: 0,
                header: [0; 5],
                header_have: 0,
                decoded: false,
                body: Vec::new(),
                body_have: 0,
                plain: 0..0,
                resumption: state.resumption,
                failed: false,
            },
            write: EncryptionWrite {
                io: MaskedWrite::new(write, state.write_xor, state.prefix.len()),
                key: state.write,
                united,
                aes: state.aes,
                prefix: state.prefix,
                pending: Vec::new(),
                sent: 0,
                failed: false,
            },
        }
    }

    pub(crate) fn into_halves(self) -> (EncryptionRead, EncryptionWrite) {
        (self.read, self.write)
    }
}

impl EncryptionRead {
    pub(crate) fn raw_mut(&mut self) -> &mut (dyn AsyncRead + Send + Unpin) {
        &mut self.io
    }

    pub(crate) fn at_record_boundary(&self) -> bool {
        self.key.is_some()
            && self.padding.is_empty()
            && self.header_have == 0
            && self.body_have == 0
    }

    pub(crate) fn has_pending_plaintext(&self) -> bool {
        !self.plain.is_empty()
    }

    pub(crate) fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.body.get(self.plain.clone()).unwrap_or_default());
        self.finish_record();
    }

    fn finish_record(&mut self) {
        self.plain = 0..0;
        self.header_have = 0;
        self.decoded = false;
        self.body_have = 0;
        self.body.clear();
    }

    fn key(&mut self) -> io::Result<&mut Aead> {
        self.key.as_mut().ok_or_else(invalid)
    }

    fn poll_prelude(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.key.is_none() {
            if !ready!(fill(
                &mut self.io,
                &mut self.initial,
                &mut self.initial_have,
                cx
            ))? {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.key = Some(Aead::new(&self.initial, &self.united, self.aes)?);
            if self.random {
                self.io.mask.cipher = Some(ctr(&self.united, &self.initial));
            }
        }
        if !self.padding.is_empty() {
            if !ready!(fill(
                &mut self.io,
                &mut self.padding,
                &mut self.padding_have,
                cx
            ))? {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            let mut padding = std::mem::take(&mut self.padding);
            self.key()?.open(&mut padding, &[])?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if !ready!(fill(
            &mut self.io,
            &mut self.header,
            &mut self.header_have,
            cx
        ))? {
            if self.header_have != 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            return Poll::Ready(Ok(false));
        }
        if !self.decoded {
            let length = match record_length(&self.header) {
                Ok(length) => length,
                Err(error) => {
                    if let Some((client, pfs)) = self.resumption.take()
                        && let Some(client) = client.upgrade()
                    {
                        client.expire(&pfs);
                    }
                    return Poll::Ready(Err(error));
                }
            };
            self.resumption = None;
            self.body.resize(length, 0);
            self.decoded = true;
        }
        if !ready!(fill(&mut self.io, &mut self.body, &mut self.body_have, cx))? {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        let replacement = if self.key()?.at_max() {
            let mut context = self.header.to_vec();
            context.extend_from_slice(&self.body);
            Some(Aead::new(&context, &self.united, self.aes)?)
        } else {
            None
        };
        let mut body = std::mem::take(&mut self.body);
        let header = self.header;
        let length = self.key()?.open(&mut body, &header)?;
        self.body = body;
        self.plain = 0..length;
        if let Some(key) = replacement {
            self.key = Some(key);
        }
        Poll::Ready(Ok(true))
    }
}

impl AsyncRead for EncryptionRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let result = (|| {
            ready!(this.poll_prelude(cx))?;
            if this.plain.is_empty() && !ready!(this.poll_record(cx))? {
                return Poll::Ready(Ok(()));
            }
            let count = this.plain.len().min(output.remaining());
            output.put_slice(
                this.body
                    .get(this.plain.start..this.plain.start + count)
                    .unwrap_or_default(),
            );
            this.plain.start += count;
            if this.plain.is_empty() {
                this.finish_record();
            }
            Poll::Ready(Ok(()))
        })();
        if matches!(&result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
}

impl EncryptionWrite {
    pub(crate) fn raw_mut(&mut self) -> &mut (dyn AsyncWrite + Send + Unpin) {
        &mut self.io
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(bytes) = self
            .pending
            .get(self.sent..)
            .filter(|bytes| !bytes.is_empty())
        {
            let count = ready!(Pin::new(&mut self.io).poll_write(cx, bytes))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += count;
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }

    fn stage(&mut self, data: &[u8]) -> io::Result<()> {
        let length = (data.len() + 16) as u16;
        let [hi, lo] = length.to_be_bytes();
        let header = [23, 3, 3, hi, lo];
        let renew = self.key.at_max();
        let body = self.key.seal(data, &header)?;
        if renew {
            let mut context = header.to_vec();
            context.extend_from_slice(&body);
            self.key = Aead::new(&context, &self.united, self.aes)?;
        }
        self.pending.append(&mut self.prefix);
        self.pending.extend_from_slice(&header);
        self.pending.extend_from_slice(&body);
        Ok(())
    }
}

impl AsyncWrite for EncryptionWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let result = (|| {
            ready!(this.drain(cx))?;
            let count = data.len().min(8192);
            this.stage(data.get(..count).unwrap_or_default())?;
            if let Poll::Ready(Err(error)) = this.drain(cx) {
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(count))
        })();
        if matches!(&result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl AsyncRead for EncryptionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for EncryptionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl Stream for EncryptionStream {
    concord_common::stream_policy!(own: into_split; default: read_requirements, write_requirements,
        poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let (read, write) = self.into_halves();
        (Box::new(read), Box::new(write))
    }
}
