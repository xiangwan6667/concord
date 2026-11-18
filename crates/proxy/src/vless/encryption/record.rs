use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use concord_common::{BoxRead, BoxStream, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::crypto::Aead;
use super::mask::{HeaderMask, MaskedRead, MaskedWrite};
use super::{Client, invalid};

const MAX_PLAINTEXT: usize = 8192;

pub(super) struct Session {
    pub(super) united: Arc<[u8]>,
    pub(super) send: Aead,
    pub(super) recv: Option<Aead>,
    pub(super) aes: bool,
    pub(super) iv: [u8; 16],
    pub(super) recv_iv: Option<[u8; 16]>,
    pub(super) padding: usize,
    pub(super) prewrite: Vec<u8>,
    pub(super) resume: Option<(Arc<Client>, [u8; 64])>,
    pub(super) random: bool,
}

pub(crate) struct Encrypted {
    reader: EncryptedRead,
    writer: EncryptedWrite,
}

pub(crate) struct EncryptedRead {
    io: MaskedRead,
    aead: Option<Aead>,
    united: Arc<[u8]>,
    aes: bool,
    random: bool,
    resume: Option<(Arc<Client>, [u8; 64])>,
    state: ReadState,
    wire: Vec<u8>,
    needed: usize,
    plain_len: usize,
    have: usize,
    header: [u8; 5],
    position: usize,
    failed: bool,
}

enum ReadState {
    Random,
    Padding,
    Header,
    Body,
    Plain,
}

pub(crate) struct EncryptedWrite {
    io: MaskedWrite,
    aead: Aead,
    united: Arc<[u8]>,
    prewrite: Vec<u8>,
    pending: Vec<u8>,
    position: usize,
    accepted: Option<usize>,
    failed: bool,
}

impl Encrypted {
    pub(super) fn new(io: BoxStream, session: Session) -> Self {
        let (read, write) = io.into_split();
        let mask_out = session
            .random
            .then(|| HeaderMask::new(&session.united, session.iv, session.prewrite.len()));
        let mask_in = session
            .recv_iv
            .filter(|_| session.random)
            .map(|iv| HeaderMask::new(&session.united, iv, session.padding));
        let (state, needed) = if session.recv.is_none() {
            (ReadState::Random, 16)
        } else {
            (ReadState::Padding, session.padding)
        };
        Self {
            reader: EncryptedRead {
                io: MaskedRead {
                    inner: read,
                    mask: mask_in,
                },
                aead: session.recv,
                united: session.united.clone(),
                aes: session.aes,
                random: session.random,
                resume: session.resume,
                state,
                wire: vec![0; needed],
                needed,
                plain_len: 0,
                have: 0,
                header: [0; 5],
                position: 0,
                failed: false,
            },
            writer: EncryptedWrite {
                io: MaskedWrite::new(write, mask_out),
                aead: session.send,
                united: session.united,
                prewrite: session.prewrite,
                pending: Vec::new(),
                position: 0,
                accepted: None,
                failed: false,
            },
        }
    }

    pub(crate) fn into_halves(self) -> (EncryptedRead, EncryptedWrite) {
        (self.reader, self.writer)
    }
}

impl EncryptedRead {
    pub(crate) fn raw_mut(&mut self) -> &mut (dyn AsyncRead + Send + Unpin + 'static) {
        &mut self.io
    }
    pub(crate) fn has_pending_plaintext(&self) -> bool {
        matches!(self.state, ReadState::Plain) && self.position < self.plain_len
    }
    pub(crate) fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        if matches!(self.state, ReadState::Plain) {
            let (plain, _) = self.wire.split_at(self.plain_len);
            let (_, remaining) = plain.split_at(self.position);
            out.extend_from_slice(remaining);
            self.next_state(ReadState::Header, 5);
            self.position = 0;
        }
    }
    pub(crate) fn at_record_boundary(&self) -> bool {
        matches!(self.state, ReadState::Plain)
            || (matches!(self.state, ReadState::Header) && self.have == 0)
    }

    fn next_state(&mut self, state: ReadState, len: usize) {
        self.state = state;
        if len > self.wire.len() {
            self.wire.resize(len, 0);
        }
        self.needed = len;
        self.have = 0;
    }

    fn finish_block(&mut self) -> io::Result<()> {
        let wire = self
            .wire
            .get_mut(..self.needed)
            .ok_or_else(|| invalid("invalid record length"))?;
        if matches!(self.state, ReadState::Random) {
            let iv: [u8; 16] = (&*wire).try_into().map_err(invalid)?;
            self.aead = Some(Aead::new(&iv, &self.united, self.aes)?);
            if self.random {
                self.io.mask = Some(HeaderMask::new(&self.united, iv, 0));
            }
            self.next_state(ReadState::Header, 5);
            return Ok(());
        }
        if matches!(self.state, ReadState::Header) {
            self.header = (&*wire).try_into().map_err(invalid)?;
            let length = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
            if self.header[..3] != [23, 3, 3] || !(17..=17000).contains(&length) {
                self.invalidate();
                return Err(invalid("invalid record header; new handshake needed"));
            }
            self.next_state(ReadState::Body, length);
            return Ok(());
        }
        let aead = self
            .aead
            .as_mut()
            .ok_or_else(|| invalid("missing read key"))?;
        if matches!(self.state, ReadState::Padding) {
            aead.open_slice(wire, &[])?;
        } else {
            let rekey = if aead.needs_rekey() {
                let mut record = self.header.to_vec();
                record.extend_from_slice(wire);
                Some(Aead::new(&record, &self.united, self.aes)?)
            } else {
                None
            };
            self.plain_len = aead.open_slice(wire, &self.header)?;
            if let Some(key) = rekey {
                *aead = key;
            }
            self.resume = None;
            self.state = ReadState::Plain;
            self.position = 0;
            return Ok(());
        }
        self.next_state(ReadState::Header, 5);
        Ok(())
    }

    fn invalidate(&mut self) {
        if let Some((client, pfs)) = self.resume.take() {
            client.invalidate(&pfs);
        }
    }
}

impl AsyncRead for EncryptedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(invalid("read after authentication failure")));
        }
        loop {
            if matches!(this.state, ReadState::Plain) {
                if this.position < this.plain_len {
                    let plain = this
                        .wire
                        .get(this.position..this.plain_len)
                        .ok_or_else(|| invalid("invalid plaintext cursor"))?;
                    let take = out.remaining().min(plain.len());
                    out.put_slice(plain.split_at(take).0);
                    this.position += take;
                    return Poll::Ready(Ok(()));
                }
                this.next_state(ReadState::Header, 5);
            }
            while this.have < this.needed {
                let tail = this
                    .wire
                    .get_mut(this.have..this.needed)
                    .ok_or_else(|| invalid("invalid record cursor"))?;
                let mut read = ReadBuf::new(tail);
                ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    if matches!(this.state, ReadState::Header) && this.have == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.have += count;
            }
            if let Err(error) = this.finish_block() {
                this.failed = true;
                return Poll::Ready(Err(error));
            }
        }
    }
}

impl EncryptedWrite {
    pub(crate) fn raw_mut(&mut self) -> &mut (dyn AsyncWrite + Send + Unpin + 'static) {
        &mut self.io
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(rest) = self
            .pending
            .get(self.position..)
            .filter(|rest| !rest.is_empty())
        {
            let result = ready!(Pin::new(&mut self.io).poll_write(cx, rest));
            let written = match result {
                Ok(0) => {
                    self.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(written) => written,
                Err(error) => {
                    self.failed = true;
                    return Poll::Ready(Err(error));
                }
            };
            self.position += written;
        }
        self.pending.clear();
        self.position = 0;
        Poll::Ready(Ok(()))
    }

    fn stage(&mut self, data: &[u8]) -> io::Result<usize> {
        let take = data.len().min(MAX_PLAINTEXT);
        let length = u16::try_from(take + 16).map_err(invalid)?.to_be_bytes();
        let header = [23, 3, 3, length[0], length[1]];
        self.pending.append(&mut self.prewrite);
        let record_start = self.pending.len();
        self.pending.extend_from_slice(&header);
        let body_start = self.pending.len();
        self.pending.extend_from_slice(data.split_at(take).0);
        let tag = self
            .aead
            .seal_slice(self.pending.split_at_mut(body_start).1, &header)?;
        self.pending.extend_from_slice(tag.as_ref());
        if self.aead.nonce_wrapped() {
            self.aead = Aead::new(
                self.pending.split_at(record_start).1,
                &self.united,
                self.aead.uses_aes(),
            )?;
        }
        Ok(take)
    }
}

impl AsyncWrite for EncryptedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("write after transport failure")));
        }
        if let Some(accepted) = this.accepted {
            ready!(this.drain(cx))?;
            this.accepted = None;
            return Poll::Ready(Ok(accepted));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let accepted = this.stage(data)?;
        this.accepted = Some(accepted);
        ready!(this.drain(cx))?;
        this.accepted = None;
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

impl AsyncRead for Encrypted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, out)
    }
}

impl AsyncWrite for Encrypted {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

impl Stream for Encrypted {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        (Box::new(self.reader), Box::new(self.writer))
    }
}
