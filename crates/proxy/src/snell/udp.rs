use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use bytes::BytesMut;
use concord_common::{Address, BoxRead, BoxStream, BoxWrite, PacketBuf, PacketSession};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::codec::{Decode, Encode};
use super::frame::{Chunk, MAX_CHUNK, Opener, Scheme, Sealer};
use super::stream::Reply;
use crate::util::{invalid_data, lock};

const FORWARD: u8 = 1;
const READ_CHUNK: usize = 17 * 1024;

struct Writer<E> {
    io: BoxWrite,
    sealer: E,
    scratch: Vec<u8>,
    out: Vec<u8>,
    sent: usize,
    inflight: bool,
}

struct Reader<D> {
    io: BoxRead,
    opener: D,
    input: BytesMut,
    plain: BytesMut,
    reply: Reply,
}

pub(super) struct SnellPackets<E = Sealer, D = Opener> {
    writer: Mutex<Writer<E>>,
    reader: Mutex<Reader<D>>,
    closed: AtomicBool,
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "session closed")
}

impl SnellPackets {
    pub(super) fn new(io: BoxStream, scheme: Scheme, psk: &[u8], sealer: Sealer) -> Self {
        Self::with_codecs(io, sealer, Opener::new(scheme, psk))
    }
}

impl<E: Encode, D: Decode> SnellPackets<E, D> {
    pub(super) fn with_codecs(io: BoxStream, sealer: E, opener: D) -> Self {
        let (read, write) = io.into_split();
        SnellPackets {
            writer: Mutex::new(Writer {
                io: write,
                sealer,
                scratch: Vec::new(),
                out: Vec::new(),
                sent: 0,
                inflight: false,
            }),
            reader: Mutex::new(Reader {
                io: read,
                opener,
                input: BytesMut::new(),
                plain: BytesMut::new(),
                reply: Reply::Start,
            }),
            closed: AtomicBool::new(false),
        }
    }

    /// Reads the server's reply to the UDP request; v4 servers answer before any packet flows.
    pub(super) async fn read_reply(&self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut guard = lock(&self.reader);
            let reader = &mut *guard;
            loop {
                if reader.reply.feed(&mut reader.plain)? {
                    return Poll::Ready(Ok(()));
                }
                ready!(fill(reader, cx))?;
            }
        })
        .await
    }
}

fn fill<D: Decode>(reader: &mut Reader<D>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    loop {
        match reader.opener.open(&mut reader.input, &mut reader.plain)? {
            Some(Chunk::Data) => return Poll::Ready(Ok(())),
            Some(Chunk::Zero) => return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
            None => {}
        }
        let mut chunk = [0u8; READ_CHUNK];
        let mut read = ReadBuf::new(&mut chunk);
        ready!(Pin::new(&mut reader.io).poll_read(cx, &mut read))?;
        if read.filled().is_empty() {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        reader.input.extend_from_slice(read.filled());
    }
}

fn put_destination(out: &mut Vec<u8>, dst: &Address) -> io::Result<()> {
    out.push(FORWARD);
    match dst {
        Address::Domain(host, port) => {
            out.push(
                u8::try_from(host.len())
                    .map_err(|_| invalid_data("snell UDP address too large"))?,
            );
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Address::Socket(addr) => {
            out.push(0);
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(0x04);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(0x06);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    Ok(())
}

fn parse_source(packet: &[u8]) -> io::Result<(SocketAddr, &[u8])> {
    let (ip, rest): (IpAddr, &[u8]) = match packet.first() {
        Some(0x04) => {
            let octets: [u8; 4] = packet
                .get(1..5)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| invalid_data("insufficient UDP length"))?;
            (
                Ipv4Addr::from(octets).into(),
                packet.get(5..).unwrap_or_default(),
            )
        }
        Some(0x06) => {
            let octets: [u8; 16] = packet
                .get(1..17)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| invalid_data("insufficient UDP length"))?;
            (
                Ipv6Addr::from(octets).into(),
                packet.get(17..).unwrap_or_default(),
            )
        }
        _ => return Err(invalid_data("ip version invalid")),
    };
    let port = rest
        .get(..2)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| invalid_data("insufficient UDP length"))?;
    Ok((SocketAddr::new(ip, port), rest.get(2..).unwrap_or_default()))
}

impl<E: Encode, D: Decode> PacketSession for SnellPackets<E, D> {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(closed()));
        }
        let mut guard = lock(&self.writer);
        let writer = &mut *guard;
        if !writer.inflight {
            writer.scratch.clear();
            put_destination(&mut writer.scratch, dst)?;
            if writer.scratch.len() + pkt.len() > MAX_CHUNK {
                return Poll::Ready(Err(invalid_data("snell UDP payload too large")));
            }
            writer.scratch.extend_from_slice(pkt.as_slice());
            writer.out.clear();
            writer.sent = 0;
            writer.sealer.seal_chunk(&mut writer.out, &writer.scratch)?;
            writer.inflight = true;
        }
        while let Some(rest) = writer
            .out
            .get(writer.sent..)
            .filter(|rest| !rest.is_empty())
        {
            match Pin::new(&mut writer.io).poll_write(cx, rest) {
                Poll::Ready(Ok(0)) => {
                    writer.inflight = false;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => writer.sent += n,
                Poll::Ready(Err(err)) => {
                    writer.inflight = false;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        writer.inflight = false;
        Poll::Ready(Ok(()))
    }

    fn poll_recv(&self, cx: &mut Context<'_>, out: &mut PacketBuf) -> Poll<io::Result<Address>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(closed()));
        }
        let mut guard = lock(&self.reader);
        let reader = &mut *guard;
        loop {
            if !reader.reply.feed(&mut reader.plain)? {
                ready!(fill(reader, cx))?;
                continue;
            }
            if reader.plain.is_empty() {
                ready!(fill(reader, cx))?;
            }
            let (from, payload) = parse_source(&reader.plain)?;
            out.extend_from_slice(payload);
            reader.plain.clear();
            return Poll::Ready(Ok(Address::from(from)));
        }
    }

    fn headroom(&self) -> usize {
        0
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}
