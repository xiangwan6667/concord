use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use concord_common::{Address, PacketBuf, PacketSession};
use tokio::sync::mpsc;

use super::wire::{Defrag, MAX_UDP, UdpHeader, parse_udp, put_udp_header, udp_header_len};
use crate::quic::DatagramHub;
use crate::util::lock;

const QUEUE: usize = 64;
/// A domain of 255 bytes with `:65535`, a two-byte length and the fixed header.
const HEADROOM: usize = 8 + 2 + 255 + 6;

struct Entry {
    queue: mpsc::Sender<(Address, Bytes)>,
    defrag: Mutex<Defrag>,
}

/// Hands the datagrams of one connection to the session they belong to.
#[derive(Default)]
pub(crate) struct Hub {
    sessions: Mutex<HashMap<u32, Arc<Entry>>>,
    next: Mutex<u32>,
}

impl Hub {
    pub(crate) fn register(&self) -> (u32, mpsc::Receiver<(Address, Bytes)>) {
        let (queue, rx) = mpsc::channel(QUEUE);
        let mut next = lock(&self.next);
        let id = *next;
        *next = next.wrapping_add(1);
        lock(&self.sessions).insert(
            id,
            Arc::new(Entry {
                queue,
                defrag: Mutex::new(Defrag::default()),
            }),
        );
        (id, rx)
    }

    pub(crate) fn remove(&self, id: u32) {
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
        let Some(entry) = lock(&self.sessions).get(&message.session).cloned() else {
            return;
        };
        let Some((addr, data)) = lock(&entry.defrag).feed(message) else {
            return;
        };
        let Some(addr) = Address::parse(&addr) else {
            return;
        };
        let _ = entry.queue.try_send((addr, data));
    }
}

/// The datagrams of one `associate`, which the server relays to any destination.
pub(crate) struct Hy2Packets {
    id: u32,
    conn: quinn::Connection,
    hub: Arc<Hub>,
    incoming: Mutex<mpsc::Receiver<(Address, Bytes)>>,
    packet_id: AtomicU16,
    udp_mtu: usize,
    closed: AtomicBool,
    _hold: Arc<dyn Send + Sync>,
}

impl Hy2Packets {
    pub(crate) fn new(
        conn: quinn::Connection,
        hub: Arc<Hub>,
        udp_mtu: usize,
        hold: Arc<dyn Send + Sync>,
    ) -> Self {
        let (id, incoming) = hub.register();
        Hy2Packets {
            id,
            conn,
            hub,
            incoming: Mutex::new(incoming),
            packet_id: AtomicU16::new(0),
            udp_mtu,
            closed: AtomicBool::new(false),
            _hold: hold,
        }
    }

    fn send_pieces(&self, payload: &[u8], addr: &str, limit: usize) -> io::Result<()> {
        let room = limit.saturating_sub(udp_header_len(addr)).max(1);
        let pieces: Vec<&[u8]> = payload.chunks(room).collect();
        let total = u8::try_from(pieces.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?;
        let packet = self.packet_id.fetch_add(1, Ordering::Relaxed);
        for (index, piece) in pieces.into_iter().enumerate() {
            let mut out = Vec::with_capacity(udp_header_len(addr) + piece.len());
            put_udp_header(
                &mut out,
                &UdpHeader {
                    session: self.id,
                    packet,
                    fragment: index as u8,
                    fragments: total,
                    addr,
                },
            );
            out.extend_from_slice(piece);
            self.conn
                .send_datagram(Bytes::from(out))
                .map_err(send_error)?;
        }
        Ok(())
    }
}

fn send_error(err: quinn::SendDatagramError) -> io::Error {
    match err {
        quinn::SendDatagramError::TooLarge => {
            io::Error::new(io::ErrorKind::InvalidInput, "datagram too large")
        }
        other => io::Error::other(other),
    }
}

impl PacketSession for Hy2Packets {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if pkt.len() > MAX_UDP {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram too large",
            )));
        }
        let addr = dst.to_string();
        let header = udp_header_len(&addr);
        if pkt.len() + header <= self.udp_mtu {
            let packet = self.packet_id.fetch_add(1, Ordering::Relaxed);
            let mut head = Vec::with_capacity(header);
            put_udp_header(
                &mut head,
                &UdpHeader {
                    session: self.id,
                    packet,
                    fragment: 0,
                    fragments: 1,
                    addr: &addr,
                },
            );
            pkt.prepend(head.len()).copy_from_slice(&head);
            let sent = self
                .conn
                .send_datagram(Bytes::copy_from_slice(pkt.as_slice()));
            pkt.consume(head.len());
            match sent {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(quinn::SendDatagramError::TooLarge) => {}
                Err(err) => return Poll::Ready(Err(send_error(err))),
            }
        }
        let limit = self
            .conn
            .max_datagram_size()
            .map_or(self.udp_mtu, |size| size.min(self.udp_mtu));
        Poll::Ready(self.send_pieces(pkt.as_slice(), &addr, limit))
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        match lock(&self.incoming).poll_recv(cx) {
            Poll::Ready(Some((from, data))) => {
                buf.extend_from_slice(&data);
                Poll::Ready(Ok(from))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn headroom(&self) -> usize {
        HEADROOM
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.hub.remove(self.id);
    }
}

impl Drop for Hy2Packets {
    fn drop(&mut self) {
        self.hub.remove(self.id);
    }
}
