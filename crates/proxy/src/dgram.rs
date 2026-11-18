use std::future::poll_fn;
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};

use concord_common::{Address, BoxRead, BoxStream, BoxWrite, PacketBuf, PacketSession, Tasks};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use crate::util::lock;

const INITIAL_READ_BUFFER: usize = 16 * 1024;
const MAX_READ_BUFFER: usize = 2 * 65_536;

pub(crate) enum Decoded {
    NeedMore,
    Skip(usize),
    Packet {
        /// `None` is the session's fixed remote.
        addr: Option<Address>,
        payload: Range<usize>,
        consumed: usize,
    },
}

/// Frames one datagram in front of its payload, in place.
pub(crate) trait Encoder: Send + 'static {
    fn headroom(&self) -> usize;
    fn encode(&mut self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()>;

    /// Appends the framed datagram to `out`; a protocol that splits one overrides this.
    fn encode_into(
        &mut self,
        pkt: &mut PacketBuf,
        dst: &Address,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        self.encode(pkt, dst)?;
        out.extend_from_slice(pkt.as_slice());
        Ok(())
    }
}

pub(crate) trait Decoder: Send + 'static {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded>;
}

/// Frames a send handed over that the writer task has not taken yet.
struct Outbox<E> {
    encoder: E,
    frames: Vec<u8>,
    error: Option<(io::ErrorKind, String)>,
    closed: bool,
    sender: Option<Waker>,
    writer: Option<Waker>,
}

struct Reader<D> {
    io: BoxRead,
    decoder: D,
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

/// Datagrams over a byte stream (trojan, VLESS, VMess, UDP-over-TCP). A packet is
/// copied out of the session's read buffer once.
///
/// A send only queues its frame and wakes the session's writer task. Woken from a
/// runtime worker, the writer waits in that worker's LIFO slot until the sending task
/// yields, which an inbound does once it has drained the datagrams it was woken for;
/// the writer then puts the whole burst on the stream in one write. The writer is the
/// only one writing, so a frame never waits on the reader and the two halves seldom
/// meet on the socket.
pub(crate) struct StreamSession<E, D> {
    outbox: Arc<Mutex<Outbox<E>>>,
    reader: Mutex<Reader<D>>,
    remote: Address,
    headroom: usize,
    closed: AtomicBool,
}

/// Queued frames past this make a send wait for the writer.
const MAX_QUEUED: usize = 64 * 1024;

impl<E: Encoder, D: Decoder> StreamSession<E, D> {
    pub(crate) fn new(
        io: BoxStream,
        encoder: E,
        decoder: D,
        remote: Address,
        tasks: &Tasks,
    ) -> Self {
        let (read, write) = io.into_split();
        let headroom = encoder.headroom();
        let outbox = Arc::new(Mutex::new(Outbox {
            encoder,
            frames: Vec::new(),
            error: None,
            closed: false,
            sender: None,
            writer: None,
        }));
        tasks.spawn(write_out(outbox.clone(), write));
        StreamSession {
            headroom,
            outbox,
            reader: Mutex::new(Reader {
                io: read,
                decoder,
                buf: vec![0; INITIAL_READ_BUFFER],
                start: 0,
                end: 0,
            }),
            remote,
            closed: AtomicBool::new(false),
        }
    }
}

impl<E, D> Drop for StreamSession<E, D> {
    fn drop(&mut self) {
        let writer = {
            let mut outbox = lock(&self.outbox);
            outbox.closed = true;
            outbox.writer.take()
        };
        if let Some(writer) = writer {
            writer.wake();
        }
    }
}

/// Takes everything queued, writes it, and flushes; ends once the session is closed or
/// dropped and the outbox drained, or on the first error, which the next send reports.
async fn write_out<E: Encoder>(outbox: Arc<Mutex<Outbox<E>>>, mut io: BoxWrite) {
    loop {
        let batch = poll_fn(|cx| {
            let mut outbox = lock(&outbox);
            if !outbox.frames.is_empty() {
                let batch = std::mem::take(&mut outbox.frames);
                if let Some(sender) = outbox.sender.take() {
                    sender.wake();
                }
                return Poll::Ready(Some(batch));
            }
            if outbox.closed {
                return Poll::Ready(None);
            }
            outbox.writer = Some(cx.waker().clone());
            Poll::Pending
        })
        .await;
        let Some(batch) = batch else {
            return;
        };
        let written = match io.write_all(&batch).await {
            Ok(()) => io.flush().await,
            Err(err) => Err(err),
        };
        if let Err(err) = written {
            let mut outbox = lock(&outbox);
            outbox.error = Some((err.kind(), err.to_string()));
            if let Some(sender) = outbox.sender.take() {
                sender.wake();
            }
            return;
        }
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "session closed")
}

impl<E: Encoder, D: Decoder> PacketSession for StreamSession<E, D> {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(closed_error()));
        }
        let writer = {
            let mut outbox = lock(&self.outbox);
            if let Some((kind, message)) = &outbox.error {
                return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
            }
            if outbox.frames.len() >= MAX_QUEUED {
                outbox.sender = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let Outbox {
                encoder, frames, ..
            } = &mut *outbox;
            encoder.encode_into(pkt, dst, frames)?;
            outbox.writer.take()
        };
        if let Some(writer) = writer {
            writer.wake();
        }
        Poll::Ready(Ok(()))
    }

    fn poll_recv(&self, cx: &mut Context<'_>, out: &mut PacketBuf) -> Poll<io::Result<Address>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(closed_error()));
        }
        let mut guard = lock(&self.reader);
        let reader = &mut *guard;
        loop {
            if reader.end > reader.start {
                let input = reader
                    .buf
                    .get_mut(reader.start..reader.end)
                    .unwrap_or_default();
                match reader.decoder.decode(input)? {
                    Decoded::NeedMore => {}
                    Decoded::Skip(consumed) => {
                        reader.start += consumed;
                        continue;
                    }
                    Decoded::Packet {
                        addr,
                        payload,
                        consumed,
                    } => {
                        if let Some(data) = input.get(payload) {
                            out.extend_from_slice(data);
                        }
                        reader.start += consumed;
                        return Poll::Ready(Ok(addr.unwrap_or_else(|| self.remote.clone())));
                    }
                }
            }
            if reader.start == reader.end {
                reader.start = 0;
                reader.end = 0;
            } else if reader.end == reader.buf.len() {
                if reader.start > 0 {
                    reader.buf.copy_within(reader.start..reader.end, 0);
                    reader.end -= reader.start;
                    reader.start = 0;
                } else if reader.buf.len() < MAX_READ_BUFFER {
                    let grown = reader.buf.len() * 2;
                    reader.buf.resize(grown, 0);
                } else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "datagram larger than the read buffer",
                    )));
                }
            }
            let end = reader.end;
            let space = reader.buf.get_mut(end..).unwrap_or_default();
            let mut read = ReadBuf::new(space);
            ready!(Pin::new(&mut reader.io).poll_read(cx, &mut read))?;
            let n = read.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            reader.end += n;
        }
    }

    fn headroom(&self) -> usize {
        self.headroom
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let writer = {
            let mut outbox = lock(&self.outbox);
            outbox.closed = true;
            outbox.writer.take()
        };
        if let Some(writer) = writer {
            writer.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use concord_common::{recv_packet, send_packet};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    struct LenPrefix;

    impl Encoder for LenPrefix {
        fn headroom(&self) -> usize {
            2
        }

        fn encode(&mut self, pkt: &mut PacketBuf, _dst: &Address) -> io::Result<()> {
            let len = u16::try_from(pkt.len()).map_err(|_| io::Error::other("too long"))?;
            pkt.prepend(2).copy_from_slice(&len.to_be_bytes());
            Ok(())
        }
    }

    impl Decoder for LenPrefix {
        fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded> {
            let Some(head) = input.get(..2) else {
                return Ok(Decoded::NeedMore);
            };
            let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
            if input.len() < 2 + len {
                return Ok(Decoded::NeedMore);
            }
            Ok(Decoded::Packet {
                addr: None,
                payload: 2..2 + len,
                consumed: 2 + len,
            })
        }
    }

    fn remote() -> Address {
        Address::new("203.0.113.9", 53)
    }

    #[tokio::test]
    async fn packets_round_trip_over_a_stream() {
        let (near, mut far) = duplex(64 * 1024);
        let session = StreamSession::new(
            Box::new(near),
            LenPrefix,
            LenPrefix,
            remote(),
            &Default::default(),
        );
        let mut packet = PacketBuf::with_headroom(session.headroom());
        packet.extend_from_slice(b"hello");
        send_packet(&session, &mut packet, &remote()).await.unwrap();
        let mut wire = [0u8; 7];
        far.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire, b"\0\x05hello");

        let big = vec![7u8; 5000];
        far.write_all(&[0x13, 0x88]).await.unwrap();
        far.write_all(&big).await.unwrap();
        far.write_all(b"\0\x02ok").await.unwrap();
        let (first, from) = recv_packet(&session).await.unwrap();
        assert_eq!(first.as_slice(), &big[..]);
        assert_eq!(from, remote());
        let (second, _) = recv_packet(&session).await.unwrap();
        assert_eq!(second.as_slice(), b"ok");
    }

    #[tokio::test]
    async fn a_stalled_stream_holds_sends_back_and_keeps_their_order() {
        let (near, mut far) = duplex(1024);
        let session = StreamSession::new(
            Box::new(near),
            LenPrefix,
            LenPrefix,
            remote(),
            &Default::default(),
        );
        let target = remote();
        let mut sent = 0u32;
        loop {
            let mut packet = PacketBuf::with_headroom(2);
            packet.extend_from_slice(&sent.to_be_bytes());
            packet.extend_from_slice(&[0u8; 996]);
            let sending = send_packet(&session, &mut packet, &target);
            match tokio::time::timeout(std::time::Duration::from_millis(50), sending).await {
                Ok(result) => {
                    result.unwrap();
                    sent += 1;
                }
                Err(_) => break,
            }
            assert!(sent < 1000, "sends never waited for the stream");
        }
        assert!(sent as usize * 1002 >= MAX_QUEUED);
        for expected in 0..sent {
            let mut frame = [0u8; 1002];
            far.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame[..2], &1000u16.to_be_bytes());
            assert_eq!(frame[2..6], expected.to_be_bytes());
        }
    }

    #[tokio::test]
    async fn the_writer_task_ends_with_its_session() {
        for close_first in [false, true] {
            let (near, mut far) = duplex(1024);
            let session = StreamSession::new(
                Box::new(near),
                LenPrefix,
                LenPrefix,
                remote(),
                &Default::default(),
            );
            let mut packet = PacketBuf::with_headroom(2);
            packet.extend_from_slice(b"last");
            send_packet(&session, &mut packet, &remote()).await.unwrap();
            let mut frame = [0u8; 6];
            far.read_exact(&mut frame).await.unwrap();
            tokio::task::yield_now().await;
            if close_first {
                session.close();
            }
            drop(session);
            let mut rest = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                far.read_to_end(&mut rest),
            )
            .await
            .expect("the writer task kept the stream after its session went away")
            .unwrap();
        }
    }

    #[tokio::test]
    async fn a_send_still_leaves_when_its_session_drops_right_after() {
        let (near, mut far) = duplex(1024);
        let session = StreamSession::new(
            Box::new(near),
            LenPrefix,
            LenPrefix,
            remote(),
            &Default::default(),
        );
        for payload in [&b"one"[..], b"two"] {
            let mut packet = PacketBuf::with_headroom(2);
            packet.extend_from_slice(payload);
            send_packet(&session, &mut packet, &remote()).await.unwrap();
        }
        drop(session);
        let mut rest = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            far.read_to_end(&mut rest),
        )
        .await
        .expect("the writer task kept the stream after its session went away")
        .unwrap();
        assert_eq!(rest, b"\0\x03one\0\x03two");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burst_across_many_sessions_reaches_every_stream() {
        const SESSIONS: usize = 64;
        const PACKETS: u32 = 50;
        let mut sessions = Vec::new();
        let mut fars = Vec::new();
        for _ in 0..SESSIONS {
            let (near, far) = duplex(64 * 1024);
            sessions.push(StreamSession::new(
                Box::new(near),
                LenPrefix,
                LenPrefix,
                remote(),
                &Default::default(),
            ));
            fars.push(far);
        }
        let target = remote();
        for round in 0..PACKETS {
            for session in &sessions {
                let mut packet = PacketBuf::with_headroom(2);
                packet.extend_from_slice(&round.to_be_bytes());
                send_packet(session, &mut packet, &target).await.unwrap();
            }
        }
        let reads = fars.into_iter().map(|mut far| {
            tokio::spawn(async move {
                for round in 0..PACKETS {
                    let mut frame = [0u8; 6];
                    far.read_exact(&mut frame).await.unwrap();
                    assert_eq!(frame[2..], round.to_be_bytes());
                }
            })
        });
        let all = futures_util::future::join_all(reads);
        for read in tokio::time::timeout(std::time::Duration::from_secs(5), all)
            .await
            .expect("a session's frames never left")
        {
            read.unwrap();
        }
    }

    #[tokio::test]
    async fn a_datagram_over_a_shadowsocks_stream_leaves_whole() {
        use shadowsocks::config::ServerType;
        use shadowsocks::context::Context as SsContext;
        use shadowsocks::relay::tcprelay::ProxyServerStream;

        use crate::ss::crypto::{ClientStream, SsKey, new_context, parse_method};

        let kind = parse_method("aes-128-gcm").unwrap();
        let key = SsKey::new(kind, "secret").unwrap();
        let (near, far) = duplex(1 << 20);
        let carrier: BoxStream = Box::new(ClientStream::new(near, new_context(), &key, &remote()));
        let session =
            StreamSession::new(carrier, LenPrefix, LenPrefix, remote(), &Default::default());
        let mut server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            far,
            kind,
            key.key(),
        );
        for len in [10, 20_000] {
            let mut packet = PacketBuf::with_headroom(2);
            packet.extend_from_slice(&vec![3u8; len]);
            send_packet(&session, &mut packet, &remote()).await.unwrap();
        }
        let arrival = async {
            server.handshake().await.unwrap();
            let mut wire = vec![0u8; 12 + 20_002];
            server.read_exact(&mut wire).await.map(|_| wire)
        };
        let wire = tokio::time::timeout(std::time::Duration::from_secs(5), arrival)
            .await
            .expect("the end of the datagram waited for more data")
            .unwrap();
        assert_eq!(&wire[12..14], &20_000u16.to_be_bytes());
    }

    #[tokio::test]
    async fn a_frame_a_writer_only_buffered_still_reaches_the_transport() {
        let (near, mut far) = duplex(64 * 1024);
        let session = StreamSession::new(
            Box::new(tokio::io::BufStream::new(near)),
            LenPrefix,
            LenPrefix,
            remote(),
            &Default::default(),
        );
        let mut packet = PacketBuf::with_headroom(session.headroom());
        packet.extend_from_slice(b"query");
        send_packet(&session, &mut packet, &remote()).await.unwrap();
        let mut wire = [0u8; 7];
        tokio::time::timeout(std::time::Duration::from_secs(5), far.read_exact(&mut wire))
            .await
            .expect("the frame stayed in the writer's buffer")
            .unwrap();
        assert_eq!(&wire, b"\0\x05query");
    }
}
