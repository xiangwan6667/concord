use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use concord_common::{Address, PacketBuf, PacketSession, Tasks};
use rand::Rng;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::wire::{Defrag, UdpHeader, parse_udp, put_udp_header, udp_header_len};
use crate::quic::{DatagramHub, QuicStream};
use crate::util::lock;

const QUEUE: usize = 64;

type Inbox = mpsc::Sender<(Address, Vec<u8>)>;

/// Hands the datagrams of one connection to the session they belong to.
#[derive(Default)]
pub(super) struct Hub {
    sessions: Mutex<HashMap<u32, Inbox>>,
    defrag: Mutex<Defrag>,
}

impl Hub {
    pub(super) fn register(&self, id: u32) -> mpsc::Receiver<(Address, Vec<u8>)> {
        let (inbox, rx) = mpsc::channel(QUEUE);
        lock(&self.sessions).insert(id, inbox);
        rx
    }

    pub(super) fn remove(&self, id: u32) {
        lock(&self.sessions).remove(&id);
    }
}

impl DatagramHub for Hub {
    fn close_all(&self) {
        lock(&self.sessions).clear();
    }

    fn dispatch(&self, datagram: &Bytes) {
        let Ok(message) = parse_udp(datagram) else {
            return;
        };
        let Some(data) = lock(&self.defrag).feed(&message) else {
            return;
        };
        let Some(inbox) = lock(&self.sessions).get(&message.session).cloned() else {
            return;
        };
        let _ = inbox.try_send((Address::new(message.host, message.port), data));
    }
}

/// The datagrams of one `associate`; the server relays them to any destination.
pub(super) struct Hy1Packets {
    id: u32,
    conn: quinn::Connection,
    hub: Arc<Hub>,
    incoming: Mutex<mpsc::Receiver<(Address, Vec<u8>)>>,
    closed: Arc<AtomicBool>,
    hold: JoinHandle<()>,
    _conn_hold: Arc<dyn Send + Sync>,
}

impl Hy1Packets {
    /// `control` is the stream the session was requested on; the server ends the
    /// session when it closes, and so does this side when the server closes it.
    pub(super) fn new(
        conn: quinn::Connection,
        hub: Arc<Hub>,
        id: u32,
        control: QuicStream,
        conn_hold: Arc<dyn Send + Sync>,
        tasks: &Tasks,
    ) -> Self {
        let incoming = hub.register(id);
        let closed = Arc::new(AtomicBool::new(false));
        let hold = {
            let (hub, closed) = (hub.clone(), closed.clone());
            tasks.spawn(async move {
                let mut control = control;
                let mut sink = [0u8; 1024];
                while matches!(control.read(&mut sink).await, Ok(n) if n > 0) {}
                closed.store(true, Ordering::Relaxed);
                hub.remove(id);
            })
        };
        Hy1Packets {
            id,
            conn,
            hub,
            incoming: Mutex::new(incoming),
            closed,
            hold,
            _conn_hold: conn_hold,
        }
    }

    fn send_datagram(&self, datagram: Vec<u8>) -> io::Result<()> {
        self.conn
            .send_datagram(Bytes::from(datagram))
            .map_err(|err| match err {
                quinn::SendDatagramError::TooLarge => {
                    io::Error::new(io::ErrorKind::InvalidInput, "datagram too large")
                }
                other => io::Error::other(other),
            })
    }

    fn send(&self, payload: &[u8], dst: &Address) -> io::Result<()> {
        let data_len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?;
        let host = dst.host_string();
        let head = udp_header_len(&host);
        let limit = self
            .conn
            .max_datagram_size()
            .ok_or_else(|| io::Error::other("datagrams are not supported by the server"))?;
        let header = |message, fragment, fragments, data_len| UdpHeader {
            session: self.id,
            host: &host,
            port: dst.port(),
            message,
            fragment,
            fragments,
            data_len,
        };
        if head + payload.len() <= limit {
            let mut out = Vec::with_capacity(head + payload.len());
            put_udp_header(&mut out, &header(0, 0, 1, data_len));
            out.extend_from_slice(payload);
            return self.send_datagram(out);
        }
        let room = limit.saturating_sub(head);
        let pieces = payload.len().div_ceil(room.max(1));
        let fragments = u8::try_from(pieces)
            .ok()
            .filter(|_| room > 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?;
        let message = rand::rng().random_range(1..=u16::MAX);
        for (index, piece) in payload.chunks(room).enumerate() {
            let mut out = Vec::with_capacity(head + piece.len());
            let piece_len = u16::try_from(piece.len()).unwrap_or(u16::MAX);
            put_udp_header(
                &mut out,
                &header(
                    message,
                    u8::try_from(index).unwrap_or(0),
                    fragments,
                    piece_len,
                ),
            );
            out.extend_from_slice(piece);
            self.send_datagram(out)?;
        }
        Ok(())
    }
}

impl PacketSession for Hy1Packets {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Ready(self.send(pkt.as_slice(), dst))
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        match lock(&self.incoming).poll_recv(cx) {
            Poll::Ready(Some((from, data))) => {
                buf.extend_from_slice(&data);
                Poll::Ready(Ok(from))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.hub.remove(self.id);
    }
}

impl Drop for Hy1Packets {
    fn drop(&mut self) {
        self.hold.abort();
        self.hub.remove(self.id);
    }
}
