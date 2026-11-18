use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use aes_cfb::Aes128;
use concord_common::stream_buffer::{self, BufferRequirements, OwnedDrain, StreamBuffer};
use concord_common::{Address, BoxRead, BoxStream, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::crypto::{
    BodyDecoder, BodyEncoder, CHUNK, Chunk, Frame, Request, ResponseOpener, Security, alter_key,
    command_key, legacy_response_decryptor, user_id,
};
use crate::ctx::Clock;

const MIN_BUFFER: usize = 16 * 1024;

pub(crate) struct VmessCfg {
    pub(crate) user: [u8; 16],
    pub(crate) alter: Option<[u8; 16]>,
    pub(crate) security: Security,
    pub(crate) global_padding: bool,
    pub(crate) authenticated_length: bool,
    pub(crate) clock: Clock,
}

impl VmessCfg {
    pub(crate) fn new(
        uuid: &str,
        alter_id: u32,
        security: Security,
        global_padding: bool,
        authenticated_length: bool,
        clock: Clock,
    ) -> Self {
        let id = user_id(uuid);
        VmessCfg {
            user: command_key(&id),
            alter: (alter_id > 0).then(|| alter_key(&id)),
            security,
            global_padding,
            authenticated_length,
            clock,
        }
    }

    fn seconds(&self) -> u64 {
        (self.clock)()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }

    fn handshake(&self, request: &Request, dst: &Address) -> io::Result<Vec<u8>> {
        let now = self.seconds();
        match &self.alter {
            Some(alter) => request.seal_legacy(&self.user, alter, now, dst),
            None => request.seal_aead(&self.user, i64::try_from(now).unwrap_or(0), dst),
        }
    }
}

fn eof() -> io::Error {
    io::ErrorKind::UnexpectedEof.into()
}

enum ReadStage {
    Header,
    HeaderBody(usize),
    Len,
    Body(Frame),
    Raw,
    Done,
}

struct Reader {
    stage: ReadStage,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    deciphered: usize,
    cfb: Option<cfb_mode::BufDecryptor<Aes128>>,
    decoder: Option<BodyDecoder>,
    pending: usize,
    serve: Option<Range<usize>>,
}

impl Reader {
    fn new() -> Self {
        Reader {
            stage: ReadStage::Header,
            buf: Vec::new(),
            start: 0,
            end: 0,
            deciphered: 0,
            cfb: None,
            decoder: None,
            pending: 0,
            serve: None,
        }
    }

    fn release(&mut self) {
        self.start += std::mem::take(&mut self.pending);
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
            self.deciphered = 0;
        }
    }

    /// Waits until `need` bytes are buffered. `Ok(false)` is a clean end of
    /// stream, allowed only when nothing is buffered and `eof_ok` is set.
    fn poll_fill<S: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut S,
        need: usize,
        eof_ok: bool,
    ) -> Poll<io::Result<bool>> {
        while self.end - self.start < need {
            if self.buf.len() - self.end < need - (self.end - self.start) {
                if self.start > 0 {
                    self.buf.copy_within(self.start..self.end, 0);
                    self.end -= self.start;
                    self.deciphered = self.deciphered.saturating_sub(self.start);
                    self.start = 0;
                }
                let wanted = (self.start + need).max(MIN_BUFFER);
                if self.buf.len() < wanted {
                    self.buf.resize(wanted, 0);
                }
            }
            let tail = self.buf.get_mut(self.end..).unwrap_or_default();
            let mut read = ReadBuf::new(tail);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut read))?;
            let n = read.filled().len();
            if n == 0 {
                if eof_ok && self.end == self.start {
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(eof()));
            }
            self.end += n;
        }
        let upto = self.start + need;
        if let Some(cfb) = self.cfb.as_mut()
            && self.deciphered < upto
            && let Some(region) = self.buf.get_mut(self.deciphered..upto)
        {
            cfb.decrypt(region);
            self.deciphered = upto;
        }
        Poll::Ready(Ok(true))
    }

    fn poll_header<S: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut S,
        request: &Request,
        legacy_header: bool,
    ) -> Poll<io::Result<()>> {
        let (key, nonce);
        if legacy_header {
            (key, nonce) = request.response_legacy_keys();
            if self.cfb.is_none() {
                self.cfb = Some(legacy_response_decryptor(&key, &nonce)?);
            }
            ready!(self.poll_fill(cx, io, 4, false))?;
            let command_len = self
                .buf
                .get(self.start..self.start + 4)
                .and_then(|head| head.first_chunk::<4>().copied())
                .ok_or_else(eof)?;
            if command_len.first() != Some(&request.response_header) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad response header",
                )));
            }
            let total = 4 + usize::from(command_len[3]);
            ready!(self.poll_fill(cx, io, total, false))?;
            self.pending = total;
            self.release();
            if request.security != Security::Legacy {
                self.cfb = None;
            }
        } else {
            (key, nonce) = request.response_aead_keys();
            let opener = ResponseOpener::new(key, nonce);
            let total = if let ReadStage::HeaderBody(total) = self.stage {
                total
            } else {
                ready!(self.poll_fill(cx, io, 18, false))?;
                let region = self
                    .buf
                    .get_mut(self.start..self.start + 18)
                    .ok_or_else(eof)?;
                let total = opener.open_length(region)? + 16;
                self.pending = 18;
                self.release();
                self.stage = ReadStage::HeaderBody(total);
                total
            };
            ready!(self.poll_fill(cx, io, total, false))?;
            let region = self
                .buf
                .get_mut(self.start..self.start + total)
                .ok_or_else(eof)?;
            opener.open_header(region)?;
            self.pending = total;
            self.release();
            if request.security == Security::Legacy {
                self.cfb = Some(legacy_response_decryptor(&key, &nonce)?);
                self.deciphered = self.start;
            }
        }
        let decoder = BodyDecoder::new(request, &key, &nonce)?;
        self.stage = if decoder.chunked() {
            ReadStage::Len
        } else {
            ReadStage::Raw
        };
        self.decoder = Some(decoder);
        Poll::Ready(Ok(()))
    }

    /// The next chunk's plaintext as a range of `self.buf`, or `None` at the end.
    fn poll_chunk<S: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut S,
        request: &Request,
        legacy_header: bool,
    ) -> Poll<io::Result<Option<Range<usize>>>> {
        self.release();
        loop {
            match std::mem::replace(&mut self.stage, ReadStage::Done) {
                stage @ (ReadStage::Header | ReadStage::HeaderBody(_)) => {
                    self.stage = stage;
                    ready!(self.poll_header(cx, io, request, legacy_header))?;
                }
                ReadStage::Len => {
                    self.stage = ReadStage::Len;
                    let head = self.decoder.as_ref().map_or(2, BodyDecoder::length_bytes);
                    if !ready!(self.poll_fill(cx, io, head, true))? {
                        return Poll::Ready(Ok(None));
                    }
                    let field = self
                        .buf
                        .get_mut(self.start..self.start + head)
                        .ok_or_else(eof)?;
                    let decoder = self.decoder.as_mut().ok_or_else(eof)?;
                    let frame = decoder.parse_length(field)?;
                    self.stage = ReadStage::Body(frame);
                }
                ReadStage::Body(frame) => {
                    let head = self.decoder.as_ref().map_or(2, BodyDecoder::length_bytes);
                    let total = head + frame.sealed + frame.padding;
                    let sealed = frame.sealed;
                    self.stage = ReadStage::Body(frame);
                    ready!(self.poll_fill(cx, io, total, false))?;
                    let begin = self.start + head;
                    let region = self.buf.get_mut(begin..begin + sealed).ok_or_else(eof)?;
                    let decoder = self.decoder.as_mut().ok_or_else(eof)?;
                    let chunk = decoder.open(region)?;
                    self.pending = total;
                    match chunk {
                        Chunk::Data(range) => {
                            self.stage = ReadStage::Len;
                            return Poll::Ready(Ok(Some(begin + range.start..begin + range.end)));
                        }
                        Chunk::End => {
                            self.stage = ReadStage::Done;
                            return Poll::Ready(Ok(None));
                        }
                    }
                }
                ReadStage::Raw => {
                    self.stage = ReadStage::Raw;
                    return Poll::Ready(Ok(None));
                }
                ReadStage::Done => {
                    self.stage = ReadStage::Done;
                    return Poll::Ready(Ok(None));
                }
            }
        }
    }
}

struct Writer {
    handshake: Option<Address>,
    encoder: BodyEncoder,
    out: Vec<u8>,
    pos: usize,
    staged: Option<usize>,
    ended: bool,
    owned: OwnedDrain,
}

impl Writer {
    fn poll_owned_plain<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
    ) -> Poll<io::Result<()>> {
        self.owned
            .poll_drain(|buffer| stream_buffer::poll_write_buffer(&mut *io, cx, buffer))
    }

    fn drain<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
    ) -> Poll<io::Result<()>> {
        while let Some(rest) = self.out.get(self.pos..).filter(|r| !r.is_empty()) {
            match ready!(Pin::new(&mut *io).poll_write(cx, rest)) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(n) => self.pos += n,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        self.out.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }

    fn stage_handshake(&mut self, cfg: &VmessCfg, request: &Request) -> io::Result<()> {
        if let Some(dst) = self.handshake.take() {
            let head = cfg.handshake(request, &dst)?;
            self.out.extend_from_slice(&head);
        }
        Ok(())
    }

    fn poll_send<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
        cfg: &VmessCfg,
        request: &Request,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx, io))?;
        if let Some(accepted) = self.staged.take() {
            return Poll::Ready(Ok(accepted));
        }
        let take = data.len().min(CHUNK);
        self.stage_handshake(cfg, request)?;
        if take > 0 {
            let payload = data.get(..take).unwrap_or_default();
            if self.encoder.chunked() {
                let mut out = std::mem::take(&mut self.out);
                let sealed = self.encoder.seal(payload, &mut out);
                self.out = out;
                sealed?;
            } else {
                self.out.extend_from_slice(payload);
            }
        }
        self.staged = Some(take);
        ready!(self.drain(cx, io))?;
        self.staged = None;
        Poll::Ready(Ok(take))
    }

    fn poll_flush<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
        cfg: &VmessCfg,
        request: &Request,
    ) -> Poll<io::Result<()>> {
        if self.handshake.is_some() {
            ready!(self.poll_send(cx, io, cfg, request, &[]))?;
        }
        ready!(self.drain(cx, io))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut W,
        cfg: &VmessCfg,
        request: &Request,
    ) -> Poll<io::Result<()>> {
        ready!(self.drain(cx, io))?;
        if !self.ended {
            self.ended = true;
            self.stage_handshake(cfg, request)?;
            if self.encoder.chunked() {
                let mut out = std::mem::take(&mut self.out);
                let sealed = self.encoder.seal(&[], &mut out);
                self.out = out;
                sealed?;
            }
        }
        ready!(self.drain(cx, io))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

impl Reader {
    fn poll_data<S: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut S,
        request: &Request,
        legacy: bool,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(range) = self.serve.clone() {
                let data = self.buf.get(range.clone()).unwrap_or_default();
                let take = data.len().min(out.remaining());
                out.put_slice(data.get(..take).unwrap_or_default());
                self.serve = (take < data.len()).then(|| range.start + take..range.end);
                return Poll::Ready(Ok(()));
            }
            if matches!(self.stage, ReadStage::Raw) {
                if self.end > self.start {
                    let data = self.buf.get(self.start..self.end).unwrap_or_default();
                    let take = data.len().min(out.remaining());
                    out.put_slice(data.get(..take).unwrap_or_default());
                    self.start += take;
                    if self.start == self.end {
                        self.start = 0;
                        self.end = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(io).poll_read(cx, out);
            }
            match ready!(self.poll_chunk(cx, io, request, legacy))? {
                Some(range) => self.serve = Some(range),
                None => {
                    if matches!(self.stage, ReadStage::Raw) {
                        continue;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

pub(crate) struct VmessStream<S> {
    io: S,
    cfg: Arc<VmessCfg>,
    request: Arc<Request>,
    reader: Reader,
    writer: Writer,
}

impl<S> VmessStream<S> {
    pub(crate) fn new(
        io: S,
        cfg: Arc<VmessCfg>,
        request: Request,
        dst: Address,
    ) -> io::Result<Self> {
        let encoder = BodyEncoder::new(&request)?;
        Ok(VmessStream {
            io,
            cfg,
            request: Arc::new(request),
            reader: Reader::new(),
            writer: Writer {
                handshake: Some(dst),
                encoder,
                out: Vec::new(),
                pos: 0,
                staged: None,
                ended: false,
                owned: OwnedDrain::default(),
            },
        })
    }

    fn legacy_header(&self) -> bool {
        self.cfg.alter.is_some()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VmessStream<S> {
    /// One call writes at most one chunk, so a datagram is never split.
    pub(crate) fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writer
            .poll_send(cx, &mut self.io, &self.cfg, &self.request, data)
    }

    pub(crate) fn poll_recv_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Range<usize>>>> {
        let legacy = self.legacy_header();
        self.reader
            .poll_chunk(cx, &mut self.io, &self.request, legacy)
    }

    pub(crate) fn chunk(&self, range: Range<usize>) -> &[u8] {
        self.reader.buf.get(range).unwrap_or_default()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let legacy = this.legacy_header();
        this.reader
            .poll_data(cx, &mut this.io, &this.request, legacy, out)
    }
}

impl<S: Stream> VmessStream<S> {
    fn poll_owned(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.writer
            .owned
            .poll_drain(|buffer| self.io.poll_write_buffer(cx, buffer))
    }
}

impl<S: Stream> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_owned(cx))?;
        this.poll_send(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_owned(cx))?;
        this.writer
            .poll_flush(cx, &mut this.io, &this.cfg, &this.request)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_owned(cx))?;
        this.writer
            .poll_shutdown(cx, &mut this.io, &this.cfg, &this.request)
    }
}

struct ReadHalf {
    io: BoxRead,
    request: Arc<Request>,
    legacy: bool,
    reader: Reader,
}

impl AsyncRead for ReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reader
            .poll_data(cx, &mut this.io, &this.request, this.legacy, out)
    }
}

struct WriteHalf {
    io: BoxWrite,
    cfg: Arc<VmessCfg>,
    request: Arc<Request>,
    writer: Writer,
}

impl AsyncWrite for WriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.writer.poll_owned_plain(cx, &mut this.io))?;
        this.writer
            .poll_send(cx, &mut this.io, &this.cfg, &this.request, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.writer.poll_owned_plain(cx, &mut this.io))?;
        this.writer
            .poll_flush(cx, &mut this.io, &this.cfg, &this.request)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.writer.poll_owned_plain(cx, &mut this.io))?;
        this.writer
            .poll_shutdown(cx, &mut this.io, &this.cfg, &this.request)
    }
}

impl<S: Stream> Stream for VmessStream<S> {
    concord_common::stream_policy!(io;
        forward: peer_addr;
        own: into_split, write_requirements, poll_write_buffer;
        default: read_requirements, poll_read_buffer, raw_socket, tcp, needs_handshake, direct,
            into_tcp);

    fn write_requirements(&self) -> BufferRequirements {
        self.writer
            .encoder
            .owned_requirements()
            .map(|requirements| requirements.compose_writer(self.io.write_requirements()))
            .unwrap_or_default()
    }

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_owned(cx))?;
        ready!(self.writer.drain(cx, &mut self.io))?;
        let length = buffer.len();
        let requirements = self.write_requirements();
        if self.writer.handshake.is_some()
            || self.writer.staged.is_some()
            || self.writer.encoder.owned_requirements().is_none()
            || length == 0
            || length > CHUNK
            || buffer.headroom() < requirements.front
            || buffer.tailroom() < requirements.rear
        {
            return stream_buffer::poll_write_buffer(self, cx, buffer);
        }
        self.writer.encoder.seal_owned(buffer)?;
        self.writer.owned.start(buffer);
        if let Poll::Ready(Err(error)) = self.poll_owned(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(length))
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let legacy = self.legacy_header();
        let VmessStream {
            io,
            cfg,
            request,
            reader,
            writer,
        } = *self;
        let (io_read, io_write) = Box::new(io).into_split();
        (
            Box::new(ReadHalf {
                io: io_read,
                request: request.clone(),
                legacy,
                reader,
            }),
            Box::new(WriteHalf {
                io: io_write,
                cfg,
                request,
                writer,
            }),
        )
    }
}

pub(crate) type BoxedVmess = VmessStream<BoxStream>;

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use concord_common::stream_buffer::ReadBufferOptions;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::vmess::crypto::{CMD_TCP, CMD_UDP, kdf, one_shot_seal};

    fn body_writer(
        security: Security,
        authenticated: bool,
        near: tokio::io::DuplexStream,
    ) -> (VmessStream<tokio::io::DuplexStream>, BodyEncoder) {
        let request = Request::new(security, CMD_TCP, false, authenticated);
        let expected = BodyEncoder::new(&request).unwrap();
        let cfg = Arc::new(VmessCfg::new(
            "00000000-0000-0000-0000-000000000001",
            0,
            security,
            false,
            authenticated,
            Arc::new(SystemTime::now),
        ));
        let mut writer =
            VmessStream::new(near, cfg, request, Address::new("example.com", 443)).unwrap();
        writer.writer.handshake = None;
        (writer, expected)
    }

    fn filled(requirements: BufferRequirements, payload: &[u8]) -> StreamBuffer {
        let mut buffer = ReadBufferOptions::for_copy(Default::default(), requirements)
            .unwrap()
            .take();
        buffer.spare_mut()[..payload.len()].copy_from_slice(payload);
        buffer.advance(payload.len()).unwrap();
        buffer
    }

    #[tokio::test]
    async fn owned_and_scalar_writes_keep_order_through_partial_pending_sinks() {
        for security in [Security::Aes128Gcm, Security::Chacha20Poly1305] {
            for authenticated in [false, true] {
                let (near, mut far) = tokio::io::duplex(7);
                let received = tokio::spawn(async move {
                    let mut wire = Vec::new();
                    far.read_to_end(&mut wire).await.unwrap();
                    wire
                });
                let (mut writer, mut expected_encoder) = body_writer(security, authenticated, near);
                let requirements = writer.write_requirements();
                assert_eq!(requirements.mtu, CHUNK);
                let mut expected = Vec::new();
                for (index, length) in [1, CHUNK, 128].into_iter().enumerate() {
                    let payload: Vec<_> = (0..length).map(|n| (n % 251) as u8).collect();
                    expected_encoder.seal(&payload, &mut expected).unwrap();
                    let room = if index == 1 {
                        Default::default()
                    } else {
                        requirements
                    };
                    let mut buffer = filled(room, &payload);
                    assert_eq!(
                        std::future::poll_fn(|cx| writer.poll_write_buffer(cx, &mut buffer))
                            .await
                            .unwrap(),
                        length
                    );
                    assert!(buffer.is_empty());
                    if index == 0 {
                        assert!(writer.writer.owned.is_pending());
                    }
                    writer.write_all(b"tail").await.unwrap();
                    expected_encoder.seal(b"tail", &mut expected).unwrap();
                }
                writer.shutdown().await.unwrap();
                expected_encoder.seal(&[], &mut expected).unwrap();
                assert_eq!(received.await.unwrap(), expected);
            }
        }
    }

    #[tokio::test]
    async fn the_write_half_finishes_an_owned_chunk_accepted_before_the_split() {
        let (near, mut far) = tokio::io::duplex(7);
        let received = tokio::spawn(async move {
            let mut wire = Vec::new();
            far.read_to_end(&mut wire).await.unwrap();
            wire
        });
        let (mut writer, mut expected_encoder) = body_writer(Security::Aes128Gcm, true, near);
        let payload: Vec<_> = (0..300).map(|n| (n % 251) as u8).collect();
        let mut buffer = filled(writer.write_requirements(), &payload);
        let accepted = std::future::poll_fn(|cx| writer.poll_write_buffer(cx, &mut buffer))
            .await
            .unwrap();
        assert_eq!(accepted, payload.len());
        assert!(writer.writer.owned.is_pending());
        let (_read, mut write) = Box::new(writer).into_split();
        write.write_all(b"tail").await.unwrap();
        write.shutdown().await.unwrap();
        let mut expected = Vec::new();
        expected_encoder.seal(&payload, &mut expected).unwrap();
        expected_encoder.seal(b"tail", &mut expected).unwrap();
        expected_encoder.seal(&[], &mut expected).unwrap();
        assert_eq!(received.await.unwrap(), expected);
    }

    fn response_head(request: &Request) -> Vec<u8> {
        let (key, nonce) = request.response_aead_keys();
        let len_key = kdf(&key, "AEAD Resp Header Len Key", &[]);
        let len_nonce = kdf(&nonce, "AEAD Resp Header Len IV", &[]);
        let head_key = kdf(&key, "AEAD Resp Header Key", &[]);
        let head_nonce = kdf(&nonce, "AEAD Resp Header IV", &[]);
        let mut wire =
            one_shot_seal(&len_key[..16], &len_nonce[..12], &[], &4u16.to_be_bytes()).unwrap();
        let head = [request.response_header, 0, 0, 0];
        wire.extend(one_shot_seal(&head_key[..16], &head_nonce[..12], &[], &head).unwrap());
        wire
    }

    #[tokio::test]
    async fn a_response_header_body_survives_pending_after_its_length() {
        for command in [CMD_TCP, CMD_UDP] {
            for security in [
                Security::None,
                Security::Aes128Gcm,
                Security::Chacha20Poly1305,
            ] {
                let request = Request::new(security, command, false, false);
                let head = response_head(&request);
                let (key, nonce) = request.response_aead_keys();
                let response = Request {
                    key,
                    nonce,
                    response_header: request.response_header,
                    security,
                    option: request.option,
                    command,
                };
                let mut body = Vec::new();
                if security == Security::None && command == CMD_TCP {
                    body.extend_from_slice(b"hello");
                } else {
                    let mut encoder = BodyEncoder::new(&response).unwrap();
                    encoder.seal(b"hello", &mut body).unwrap();
                    encoder.seal(&[], &mut body).unwrap();
                }
                let (mut near, mut far) = tokio::io::duplex(head.len() + body.len());
                let mut reader = Reader::new();
                let mut cx = Context::from_waker(std::task::Waker::noop());
                for part in [&head[..17], &head[17..18], &head[18..19]] {
                    far.write_all(part).await.unwrap();
                    assert!(
                        reader
                            .poll_chunk(&mut cx, &mut near, &request, false)
                            .is_pending()
                    );
                }
                far.write_all(&head[19..]).await.unwrap();
                far.write_all(&body).await.unwrap();
                match reader.poll_chunk(&mut cx, &mut near, &request, false) {
                    Poll::Ready(Ok(Some(range))) => assert_eq!(&reader.buf[range], b"hello"),
                    Poll::Ready(Ok(None)) if matches!(reader.stage, ReadStage::Raw) => {
                        assert_eq!(&reader.buf[reader.start..reader.end], b"hello");
                        continue;
                    }
                    other => panic!("response body lost its saved header state: {other:?}"),
                }
                assert!(matches!(
                    reader.poll_chunk(&mut cx, &mut near, &request, false),
                    Poll::Ready(Ok(None))
                ));
            }
        }
    }

    #[tokio::test]
    async fn the_halves_move_data_both_ways_and_shutdown_keeps_reading() {
        let cfg = Arc::new(VmessCfg::new(
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            Security::None,
            false,
            false,
            Arc::new(SystemTime::now),
        ));
        let request = Request::new(Security::None, CMD_TCP, false, false);
        let head = response_head(&request);
        let (near, mut far) = tokio::io::duplex(4096);
        let stream: concord_common::BoxStream =
            Box::new(VmessStream::new(near, cfg, request, Address::new("1.2.3.4", 80)).unwrap());
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        far.write_all(&head).await.unwrap();
        far.write_all(b"down").await.unwrap();
        write.write_all(b"up").await.unwrap();
        write.shutdown().await.unwrap();
        let (mut far_read, mut far_write) = tokio::io::split(far);
        let mut sent = Vec::new();
        far_read.read_to_end(&mut sent).await.unwrap();
        assert!(sent.ends_with(b"up"));
        far_write.write_all(b"more").await.unwrap();
        far_write.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"downmore");
    }
}
