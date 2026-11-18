use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, ready};

use concord_common::{Address, BoxRead, BoxWrite, Stream};
use concord_tls::{TlsConn, TlsRead, TlsWrite};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::vision_io::{VisionRead, VisionWrite};
use crate::addr_codec::VMESS;
use crate::lazy::HeadFirst;

pub(crate) const FLOW_VISION: &str = "xtls-rprx-vision";
pub(crate) const CMD_TCP: u8 = 1;
pub(crate) const CMD_UDP: u8 = 2;
pub(crate) const CMD_MUX: u8 = 3;

pub(crate) fn request_header(
    user: &[u8; 16],
    flow: Option<&str>,
    command: u8,
    dst: &Address,
) -> io::Result<Vec<u8>> {
    let mut addons = Vec::new();
    if let Some(flow) = flow {
        addons.push(0x0a);
        addons.push(u8::try_from(flow.len()).map_err(|_| io::Error::other("flow too long"))?);
        addons.extend_from_slice(flow.as_bytes());
    }
    let mut out = Vec::with_capacity(32 + addons.len());
    out.push(0);
    out.extend_from_slice(user);
    out.push(u8::try_from(addons.len()).map_err(|_| io::Error::other("addons too long"))?);
    out.extend_from_slice(&addons);
    out.push(command);
    if command != CMD_MUX {
        VMESS.write(dst, &mut out)?;
    }
    Ok(out)
}

enum Response {
    Head { buf: [u8; 2], have: usize },
    Skip(usize),
    Done,
}

/// Reads and drops the `[version][addons length][addons]` that a VLESS server
/// sends before the first payload byte.
pub(crate) struct ResponseSkip<S> {
    inner: S,
    state: Response,
}

impl<S> ResponseSkip<S> {
    pub(crate) fn new(inner: S) -> Self {
        ResponseSkip {
            inner,
            state: Response::Head {
                buf: [0; 2],
                have: 0,
            },
        }
    }

    fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponseSkip<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                Response::Head { buf, have } => {
                    let tail = buf.get_mut(*have..).unwrap_or_default();
                    let mut read = ReadBuf::new(tail);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                    let n = read.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *have += n;
                    if *have == 2 {
                        let [version, addons] = *buf;
                        if version != 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unexpected response version",
                            )));
                        }
                        this.state = if addons == 0 {
                            Response::Done
                        } else {
                            Response::Skip(usize::from(addons))
                        };
                    }
                }
                Response::Skip(left) => {
                    let mut scratch = [0u8; 256];
                    let take = (*left).min(scratch.len());
                    let mut read = ReadBuf::new(scratch.get_mut(..take).unwrap_or_default());
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                    let n = read.filled().len();
                    if n == 0 || n >= *left {
                        this.state = Response::Done;
                    } else {
                        *left -= n;
                    }
                }
                Response::Done => return Pin::new(&mut this.inner).poll_read(cx, out),
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseSkip<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: Stream> Stream for ResponseSkip<S> {
    concord_common::stream_policy!(inner;
        forward: peer_addr;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            raw_socket, tcp, needs_handshake, direct, into_tcp;
        own: into_split);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let ResponseSkip { inner, state } = *self;
        let (read, write) = Box::new(inner).into_split();
        (Box::new(ResponseSkip { inner: read, state }), write)
    }
}

const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const SERVER_HANDSHAKE: [u8; 3] = [0x16, 0x03, 0x03];
const CLIENT_HANDSHAKE: [u8; 2] = [0x16, 0x03];
const APPLICATION_DATA: [u8; 3] = [0x17, 0x03, 0x03];
const PADDING_HEADER: usize = 16 + 1 + 2 + 2;
const BUFFER_LIMIT: usize = 8192 - PADDING_HEADER;
const COMMAND_CONTINUE: u8 = 0;
const COMMAND_END: u8 = 1;
const COMMAND_DIRECT: u8 = 2;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    let pair = data.get(at..at + 2)?;
    Some(u16::from_be_bytes([*pair.first()?, *pair.get(1)?]))
}

/// Xray's TLS sniffing on the first few packets, which decides whether the
/// inner connection is TLS 1.3 and may go direct.
struct Filter {
    packets_to_filter: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    cipher: u16,
    remaining_server_hello: u16,
}

impl Filter {
    fn new() -> Self {
        Filter {
            packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: 0,
            remaining_server_hello: 0,
        }
    }

    fn run(&mut self, buffer: &[u8]) {
        if self.packets_to_filter <= 0 {
            return;
        }
        let len = buffer.len();
        self.packets_to_filter -= 1;
        let mut index = find(buffer, &SERVER_HANDSHAKE);
        if let Some(at) = index {
            if len > at + 5 && buffer.starts_with(&SERVER_HANDSHAKE) {
                self.is_tls = true;
                if buffer.get(5) == Some(&2) {
                    self.remaining_server_hello = be16(buffer, at + 3).unwrap_or(0).wrapping_add(5);
                    self.is_tls12_or_above = true;
                    if len - at >= 79 && self.remaining_server_hello >= 79 {
                        let session_id_len = usize::from(buffer.get(at + 43).copied().unwrap_or(0));
                        let cipher_offset = at + 43 + session_id_len + 1;
                        if cipher_offset + 2 <= len {
                            self.cipher = be16(buffer, cipher_offset).unwrap_or(0);
                        }
                    }
                }
            }
        } else if let Some(at) = find(buffer, &CLIENT_HANDSHAKE) {
            index = Some(at);
            if len > at + 5 && buffer.get(at + 5) == Some(&1) {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let mut end = usize::from(self.remaining_server_hello);
            let start = index.unwrap_or(0);
            if start + end > len {
                end = len;
                self.remaining_server_hello -=
                    u16::try_from(end.saturating_sub(start)).unwrap_or(0);
            } else {
                self.remaining_server_hello -= u16::try_from(end).unwrap_or(0);
                end += start;
            }
            let window = buffer.get(start..end).unwrap_or_default();
            if find(window, &TLS13_SUPPORTED_VERSIONS).is_some() {
                if matches!(self.cipher, 0x1301..=0x1304) {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello == 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

fn apply_padding(
    out: &mut Vec<u8>,
    content: &[u8],
    command: u8,
    user: &mut Option<[u8; 16]>,
    padding_tls: bool,
) {
    let content_len = content.len();
    let mut rng = rand::rng();
    let padding = if content_len < 900 {
        if padding_tls {
            rng.random_range(0..500usize) + 900 - content_len
        } else {
            rng.random_range(0..256usize)
        }
    } else {
        0
    };
    if let Some(id) = user.take() {
        out.extend_from_slice(&id);
    }
    out.push(command);
    out.extend_from_slice(&u16::try_from(content_len).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&u16::try_from(padding).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding, 0);
}

fn reshape(data: &[u8]) -> Vec<Range<usize>> {
    let mut pieces = Vec::new();
    if data.len() < BUFFER_LIMIT {
        pieces.push(0..data.len());
        return pieces;
    }
    let mut offset = 0;
    while data.len() - offset >= BUFFER_LIMIT {
        let rest = data.get(offset..).unwrap_or_default();
        let cut = rfind(rest, &APPLICATION_DATA)
            .filter(|cut| (21..=BUFFER_LIMIT).contains(cut))
            .unwrap_or(8192 / 2);
        pieces.push(offset..offset + cut);
        offset += cut;
    }
    pieces.push(offset..data.len());
    pieces
}

fn lock(filter: &Mutex<Filter>) -> MutexGuard<'_, Filter> {
    concord_common::sync::lock(filter)
}

/// VLESS `xtls-rprx-vision` over a concrete TLS connection: padded frames
/// while the inner handshake runs, then the raw socket once the inner
/// connection is TLS 1.3 application data. Each direction switches to the raw
/// socket on its own; they share only the filter, which both run on the first
/// packets.
pub(crate) struct Vision<R = TlsRead, W = TlsWrite> {
    reader: VisionReader<R>,
    writer: VisionWriter<W>,
}

struct VisionReader<R> {
    io: ResponseSkip<R>,
    user: [u8; 16],
    filter: Arc<Mutex<Filter>>,
    read_process: bool,
    first_header: bool,
    last_command: u8,
    header: [u8; PADDING_HEADER],
    header_have: usize,
    remaining_content: usize,
    remaining_padding: usize,
    plain: Vec<u8>,
    plain_pos: usize,
    direct_read: bool,
}

struct VisionWriter<W> {
    io: HeadFirst<W>,
    filter: Arc<Mutex<Filter>>,
    write_filter: bool,
    write_direct: bool,
    user_once: Option<[u8; 16]>,
    tls_out: Vec<u8>,
    tls_pos: usize,
    raw_out: Vec<u8>,
    raw_pos: usize,
    switch_pending: bool,
    staged: Option<usize>,
}

impl Vision {
    pub(crate) fn new(tls: TlsConn, header: Vec<u8>, user: [u8; 16]) -> io::Result<Self> {
        if !tls.is_tls13() {
            return Err(io::Error::other(
                "XTLS Vision based on TLS 1.3 outer connection",
            ));
        }
        let (read, write) = tls
            .into_halves()
            .map_err(|_| io::Error::other("XTLS Vision needs the TLS record layer"))?;
        Ok(Self::from_halves(read, write, header, user))
    }
}

impl<R, W> Vision<R, W> {
    pub(super) fn from_halves(read: R, write: W, header: Vec<u8>, user: [u8; 16]) -> Self {
        let filter = Arc::new(Mutex::new(Filter::new()));
        Vision {
            reader: VisionReader {
                io: ResponseSkip::new(read),
                user,
                filter: filter.clone(),
                read_process: true,
                first_header: true,
                last_command: COMMAND_CONTINUE,
                header: [0; PADDING_HEADER],
                header_have: 0,
                remaining_content: 0,
                remaining_padding: 0,
                plain: Vec::new(),
                plain_pos: 0,
                direct_read: false,
            },
            writer: VisionWriter {
                io: HeadFirst::new(write, header),
                filter,
                write_filter: true,
                write_direct: false,
                user_once: Some(user),
                tls_out: Vec::new(),
                tls_pos: 0,
                raw_out: Vec::new(),
                raw_pos: 0,
                switch_pending: false,
                staged: None,
            },
        }
    }
}

impl<R: VisionRead> VisionReader<R> {
    fn tls(&mut self) -> &mut R {
        self.io.get_mut()
    }

    fn switch_to_direct_read(&mut self) -> io::Result<()> {
        let mut plain = std::mem::take(&mut self.plain);
        plain.drain(..self.plain_pos);
        self.plain_pos = 0;
        let tls = self.tls();
        if tls.has_pending_plaintext() {
            tls.drain_plaintext(&mut plain);
        }
        let boundary = tls.at_record_boundary();
        self.plain = plain;
        if !boundary {
            return Err(io::Error::other("vision: direct read inside a TLS record"));
        }
        self.read_process = false;
        self.direct_read = true;
        Ok(())
    }
}

impl<W: VisionWrite> VisionWriter<W> {
    fn stage_filtered(&mut self, data: &[u8]) {
        if data.is_empty() {
            apply_padding(
                &mut self.tls_out,
                &[],
                COMMAND_CONTINUE,
                &mut self.user_once,
                true,
            );
            return;
        }
        let mut filter = lock(&self.filter);
        filter.run(data);
        let mut padding = true;
        for piece in reshape(data) {
            let content = data.get(piece).unwrap_or_default();
            if !padding {
                let target = if self.write_direct || self.switch_pending {
                    &mut self.raw_out
                } else {
                    &mut self.tls_out
                };
                target.extend_from_slice(content);
                continue;
            }
            let mut command = COMMAND_CONTINUE;
            if filter.is_tls && content.len() > 6 && content.starts_with(&APPLICATION_DATA) {
                command = COMMAND_END;
                if filter.enable_xtls {
                    command = COMMAND_DIRECT;
                    self.switch_pending = true;
                }
                self.write_filter = false;
                padding = false;
            } else if !filter.is_tls12_or_above && filter.packets_to_filter <= 1 {
                command = COMMAND_END;
                self.write_filter = false;
                padding = false;
            }
            apply_padding(
                &mut self.tls_out,
                content,
                command,
                &mut self.user_once,
                filter.is_tls,
            );
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(rest) = self.tls_out.get(self.tls_pos..).filter(|r| !r.is_empty()) {
            match ready!(Pin::new(&mut self.io).poll_write(cx, rest)) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(n) => self.tls_pos += n,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        self.tls_out.clear();
        self.tls_pos = 0;
        if self.switch_pending {
            ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.switch_pending = false;
            self.write_direct = true;
        }
        while let Some(rest) = self.raw_out.get(self.raw_pos..).filter(|r| !r.is_empty()) {
            let raw = self.io.get_mut().raw_write();
            match ready!(Pin::new(&mut *raw).poll_write(cx, rest)) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(n) => self.raw_pos += n,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        self.raw_out.clear();
        self.raw_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<R: VisionRead> AsyncRead for VisionReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_pos < this.plain.len() {
                let data = this.plain.get(this.plain_pos..).unwrap_or_default();
                let take = data.len().min(out.remaining());
                out.put_slice(data.get(..take).unwrap_or_default());
                this.plain_pos += take;
                if this.plain_pos == this.plain.len() {
                    this.plain.clear();
                    this.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.direct_read {
                let raw = this.tls().raw_read();
                return Pin::new(&mut *raw).poll_read(cx, out);
            }
            if this.remaining_content > 0 {
                let limit = this.remaining_content.min(out.remaining());
                if limit == 0 {
                    return Poll::Ready(Ok(()));
                }
                let mut sub = ReadBuf::new(out.initialize_unfilled_to(limit));
                ready!(Pin::new(&mut this.io).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                lock(&this.filter).run(sub.filled());
                out.advance(n);
                this.remaining_content -= n;
                return Poll::Ready(Ok(()));
            }
            if this.remaining_padding > 0 {
                let mut scratch = [0u8; 512];
                let take = this.remaining_padding.min(scratch.len());
                let mut read = ReadBuf::new(scratch.get_mut(..take).unwrap_or_default());
                ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
                let n = read.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                this.remaining_padding -= n;
                continue;
            }
            if this.read_process {
                match this.last_command {
                    COMMAND_CONTINUE => {
                        let need = if this.first_header {
                            PADDING_HEADER
                        } else {
                            PADDING_HEADER - 16
                        };
                        let tail = this
                            .header
                            .get_mut(this.header_have..need)
                            .unwrap_or_default();
                        let mut read = ReadBuf::new(tail);
                        ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
                        let n = read.filled().len();
                        if n == 0 {
                            if this.header_have == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        this.header_have += n;
                        if this.header_have < need {
                            continue;
                        }
                        this.header_have = 0;
                        let mut head = this.header.get(..need).unwrap_or_default();
                        if this.first_header {
                            this.first_header = false;
                            if head.get(..16) != Some(&this.user[..]) {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "XTLS Vision server responded unknown UUID",
                                )));
                            }
                            head = head.get(16..).unwrap_or_default();
                        }
                        this.last_command = head.first().copied().unwrap_or(COMMAND_END);
                        this.remaining_content = usize::from(be16(head, 1).unwrap_or(0));
                        this.remaining_padding = usize::from(be16(head, 3).unwrap_or(0));
                    }
                    COMMAND_END => this.read_process = false,
                    COMMAND_DIRECT => this.switch_to_direct_read()?,
                    other => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("XTLS Vision read unknown command: {other}"),
                        )));
                    }
                }
                continue;
            }
            return Pin::new(&mut this.io).poll_read(cx, out);
        }
    }
}

impl<W: VisionWrite> AsyncWrite for VisionWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if let Some(accepted) = this.staged.take() {
            return Poll::Ready(Ok(accepted));
        }
        if this.write_filter {
            this.stage_filtered(data);
            this.staged = Some(data.len());
            ready!(this.drain(cx))?;
            this.staged = None;
            return Poll::Ready(Ok(data.len()));
        }
        if this.write_direct {
            let raw = this.io.get_mut().raw_write();
            return Pin::new(&mut *raw).poll_write(cx, data);
        }
        Pin::new(&mut this.io).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_filter && this.user_once.is_some() && this.staged.is_none() {
            ready!(Pin::new(&mut *this).poll_write(cx, &[]))?;
        }
        ready!(this.drain(cx))?;
        if this.write_direct {
            let raw = this.io.get_mut().raw_write();
            return Pin::new(&mut *raw).poll_flush(cx);
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if this.write_direct {
            let raw = this.io.get_mut().raw_write();
            return Pin::new(&mut *raw).poll_shutdown(cx);
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

impl<R: VisionRead, W: VisionWrite> AsyncRead for Vision<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, out)
    }
}

impl<R: VisionRead, W: VisionWrite> AsyncWrite for Vision<R, W> {
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

impl<R: VisionRead, W: VisionWrite> Stream for Vision<R, W> {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let Vision { reader, writer } = *self;
        (Box::new(reader), Box::new(writer))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn the_response_skip_splits_without_sharing_state() {
        let (near, mut far) = tokio::io::duplex(64);
        let skip: concord_common::BoxStream = Box::new(ResponseSkip::new(near));
        let (mut read, mut write) = skip.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        far.write_all(&[0, 2, 9, 9, b'h', b'i']).await.unwrap();
        write.write_all(b"out").await.unwrap();
        write.shutdown().await.unwrap();
        let mut sent = [0u8; 3];
        far.read_exact(&mut sent).await.unwrap();
        assert_eq!(&sent, b"out");
        far.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"hi");
    }

    #[test]
    fn the_request_header_carries_flow_and_destination() {
        let user = [7u8; 16];
        let head = request_header(
            &user,
            Some(FLOW_VISION),
            CMD_TCP,
            &Address::new("1.2.3.4", 80),
        )
        .unwrap();
        assert_eq!(head[0], 0);
        assert_eq!(&head[1..17], &user);
        assert_eq!(head[17], 18);
        assert_eq!(&head[18..20], &[0x0a, 16]);
        assert_eq!(&head[20..36], FLOW_VISION.as_bytes());
        assert_eq!(&head[36..], &[1, 0, 80, 1, 1, 2, 3, 4]);
    }

    #[test]
    fn a_mux_header_has_no_address() {
        let head = request_header(&[0; 16], None, CMD_MUX, &Address::new("1.2.3.4", 80)).unwrap();
        assert_eq!(head.len(), 1 + 16 + 1 + 1);
    }

    #[test]
    fn padded_frames_hold_the_content() {
        let mut out = Vec::new();
        let mut user = Some([9u8; 16]);
        apply_padding(&mut out, b"hello", COMMAND_CONTINUE, &mut user, true);
        assert_eq!(&out[..16], &[9u8; 16]);
        assert_eq!(out[16], COMMAND_CONTINUE);
        assert_eq!(u16::from_be_bytes([out[17], out[18]]), 5);
        let padding = usize::from(u16::from_be_bytes([out[19], out[20]]));
        assert!((900 - 5..900 - 5 + 500).contains(&padding));
        assert_eq!(&out[21..26], b"hello");
        assert_eq!(out.len(), 26 + padding);
        assert!(user.is_none());
    }

    #[test]
    fn large_writes_are_cut_at_application_data_records() {
        let mut data = vec![0u8; 9000];
        data[5000..5003].copy_from_slice(&APPLICATION_DATA);
        let pieces = reshape(&data);
        assert_eq!(pieces[0], 0..5000);
        assert_eq!(pieces.last().map(|r| r.end), Some(9000));
    }

    #[test]
    fn the_filter_recognises_a_tls13_server_hello() {
        let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x7a, 0x02];
        hello.resize(5 + 0x7a, 0);
        hello[43] = 0;
        hello[44] = 0x13;
        hello[45] = 0x01;
        let at = hello.len() - 10;
        hello[at..at + 6].copy_from_slice(&TLS13_SUPPORTED_VERSIONS);
        let mut filter = Filter::new();
        filter.run(&hello);
        assert!(filter.is_tls && filter.is_tls12_or_above);
        assert!(filter.enable_xtls);
    }
}
