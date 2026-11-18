use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, BytesMut};
use concord_common::stream_buffer::BufferRequirements;
use concord_common::{BoxRead, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::codec::{Decode, Encode};
use super::frame::{Chunk, MAX_CHUNK, Opener, Scheme, Sealer};

const READ_CHUNK: usize = 17 * 1024;
const REPLY_TUNNEL: u8 = 0;
const REPLY_ERROR: u8 = 2;

#[derive(Default)]
pub(super) enum Reply {
    #[default]
    Start,
    Code,
    Length(u8),
    Message(u8, usize, Vec<u8>),
    Done,
}

impl Reply {
    /// Consumes reply bytes from `plain`; `Ok(true)` once the tunnel is open.
    pub(super) fn feed(&mut self, plain: &mut BytesMut) -> io::Result<bool> {
        while !plain.is_empty() && !matches!(self, Reply::Done) {
            let byte = plain.first().copied().unwrap_or(0);
            plain.advance(1);
            *self = match std::mem::take(self) {
                Reply::Start => match byte {
                    REPLY_TUNNEL => Reply::Done,
                    REPLY_ERROR => Reply::Code,
                    _ => return Err(io::Error::other("command not support")),
                },
                Reply::Code => Reply::Length(byte),
                Reply::Length(code) if byte == 0 => return Err(server_error(code, &[])),
                Reply::Length(code) => Reply::Message(code, usize::from(byte), Vec::new()),
                Reply::Message(code, len, mut message) => {
                    message.push(byte);
                    if message.len() == len {
                        return Err(server_error(code, &message));
                    }
                    Reply::Message(code, len, message)
                }
                Reply::Done => Reply::Done,
            };
        }
        Ok(matches!(self, Reply::Done))
    }
}

struct Incoming<D> {
    opener: D,
    input: BytesMut,
    plain: BytesMut,
    reply: Reply,
    awaiting_reply: bool,
    peer_zero: bool,
}

struct Outgoing<E> {
    sealer: E,
    out: Vec<u8>,
    sent: usize,
    sent_zero: bool,
}

pub(super) struct SnellStream<S, E = Sealer, D = Opener> {
    inner: S,
    incoming: Incoming<D>,
    outgoing: Outgoing<E>,
}

impl<S> SnellStream<S> {
    pub(super) fn new(inner: S, scheme: Scheme, psk: &[u8]) -> Self {
        Self::with_codecs(inner, Sealer::new(scheme, psk), Opener::new(scheme, psk))
    }
}

impl<S, E: Encode, D: Decode> SnellStream<S, E, D> {
    pub(super) fn with_codecs(inner: S, sealer: E, opener: D) -> Self {
        SnellStream {
            inner,
            incoming: Incoming {
                opener,
                input: BytesMut::new(),
                plain: BytesMut::new(),
                reply: Reply::Start,
                awaiting_reply: true,
                peer_zero: false,
            },
            outgoing: Outgoing {
                sealer,
                out: Vec::new(),
                sent: 0,
                sent_zero: false,
            },
        }
    }

    pub(super) fn queue(&mut self, data: &[u8]) -> io::Result<()> {
        self.outgoing.queue(data)
    }

    /// mihomo ends a stream with the zero chunk only for a CONNECT_V2 request; a plain
    /// CONNECT half-closes the TCP connection and nothing more.
    pub(super) fn without_end_chunk(&mut self) {
        self.outgoing.sent_zero = true;
    }
}

impl<E: Encode> Outgoing<E> {
    fn queue(&mut self, data: &[u8]) -> io::Result<()> {
        self.sealer.seal_stream(&mut self.out, data)
    }

    fn drain<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
    ) -> Poll<io::Result<()>> {
        while let Some(rest) = self.out.get(self.sent..).filter(|rest| !rest.is_empty()) {
            let n = ready!(Pin::new(&mut *io).poll_write(cx, rest))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.out.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_write<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx, io))?;
        let take = data.len().min(4 * MAX_CHUNK);
        self.queue(data.get(..take).unwrap_or_default())?;
        if let Poll::Ready(Err(err)) = self.drain(cx, io) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
    ) -> Poll<io::Result<()>> {
        ready!(self.drain(cx, io))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
    ) -> Poll<io::Result<()>> {
        if !self.sent_zero {
            self.sealer.seal_zero(&mut self.out)?;
            self.sent_zero = true;
        }
        ready!(self.drain(cx, io))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

impl<D: Decode> Incoming<D> {
    fn poll_fill<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut R,
    ) -> Poll<io::Result<bool>> {
        loop {
            if !self.plain.is_empty() {
                return Poll::Ready(Ok(true));
            }
            match self.opener.open(&mut self.input, &mut self.plain)? {
                Some(Chunk::Data) => continue,
                Some(Chunk::Zero) => {
                    self.peer_zero = true;
                    return Poll::Ready(Ok(false));
                }
                None => {}
            }
            let mut chunk = [0u8; READ_CHUNK];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                // mihomo's server closes without a zero chunk when the target does.
                if self.input.is_empty() && self.opener.at_chunk_boundary() {
                    self.peer_zero = true;
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.input.extend_from_slice(read.filled());
        }
    }

    fn poll_reply<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut R,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.reply.feed(&mut self.plain)? {
                return Poll::Ready(Ok(()));
            }
            if !ready!(self.poll_fill(cx, io))? {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
    }

    fn poll_read<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut R,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.awaiting_reply {
            ready!(self.poll_reply(cx, io))?;
            self.awaiting_reply = false;
        }
        if self.peer_zero {
            return Poll::Ready(Ok(()));
        }
        if !ready!(self.poll_fill(cx, io))? {
            return Poll::Ready(Ok(()));
        }
        let take = self.plain.len().min(buf.remaining());
        buf.put_slice(self.plain.get(..take).unwrap_or_default());
        self.plain.advance(take);
        Poll::Ready(Ok(()))
    }
}

fn server_error(code: u8, message: &[u8]) -> io::Error {
    io::Error::other(format!(
        "server reported code: {code}, message: {}",
        String::from_utf8_lossy(message)
    ))
}

impl<S: AsyncRead + AsyncWrite + Unpin, E: Encode, D: Decode> AsyncRead for SnellStream<S, E, D> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.incoming.poll_read(cx, &mut this.inner, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, E: Encode, D: Decode> AsyncWrite for SnellStream<S, E, D> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.outgoing.poll_write(cx, &mut this.inner, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.outgoing.poll_flush(cx, &mut this.inner)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.outgoing.poll_shutdown(cx, &mut this.inner)
    }
}

struct ReadHalf<D> {
    io: BoxRead,
    incoming: Incoming<D>,
}

impl<D: Decode> AsyncRead for ReadHalf<D> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.incoming.poll_read(cx, &mut this.io, buf)
    }
}

struct WriteHalf<E> {
    io: BoxWrite,
    outgoing: Outgoing<E>,
}

impl<E: Encode> AsyncWrite for WriteHalf<E> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.outgoing.poll_write(cx, &mut this.io, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.outgoing.poll_flush(cx, &mut this.io)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.outgoing.poll_shutdown(cx, &mut this.io)
    }
}

impl<S: Stream, E: Encode, D: Decode> Stream for SnellStream<S, E, D> {
    concord_common::stream_policy!(inner;
        forward: peer_addr;
        own: into_split, write_requirements;
        default: read_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp,
            needs_handshake, direct, into_tcp);

    fn write_requirements(&self) -> BufferRequirements {
        self.outgoing
            .sealer
            .write_requirements()
            .compose_writer(self.inner.write_requirements())
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let SnellStream {
            inner,
            incoming,
            outgoing,
        } = *self;
        let (io_read, io_write) = Box::new(inner).into_split();
        (
            Box::new(ReadHalf {
                io: io_read,
                incoming,
            }),
            Box::new(WriteHalf {
                io: io_write,
                outgoing,
            }),
        )
    }
}
