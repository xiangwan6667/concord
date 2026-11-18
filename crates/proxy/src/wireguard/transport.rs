use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use arc_swap::ArcSwap;
use concord_common::{Address, Datagram, PacketBuf, PacketSession, recv_packet, send_packet};
use concord_platform::{UDP_BATCH, UdpBatch};
use gotatun::packet::{Packet, PacketBufPool};
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::task::AbortHandle;

use super::amnezia::Amnezia;

/// Cloudflare's reserved bytes sit in header bytes 1 to 3, which plain WireGuard keeps zero.
pub(super) type Reserved = ArcSwap<HashMap<SocketAddr, [u8; 3]>>;

const HEADER_LEN: usize = 4;

/// Set once the wire fails: gotatun's receive task ends on its first error and is not
/// restarted, so the tunnel cannot recover. Tripping it also ends the stack over the tunnel,
/// which fails the flows parked there.
#[derive(Default)]
pub(super) struct Breaker {
    tripped: AtomicBool,
    stack: Option<AbortHandle>,
}

impl Breaker {
    pub(super) fn new(stack: AbortHandle) -> Self {
        Breaker {
            tripped: AtomicBool::new(false),
            stack: Some(stack),
        }
    }

    fn trip(&self) {
        self.tripped.store(true, Ordering::Relaxed);
        if let Some(stack) = &self.stack {
            stack.abort();
        }
    }

    pub(super) fn tripped(&self) -> bool {
        self.tripped.load(Ordering::Relaxed)
    }
}

pub(super) enum Carrier {
    Sockets(Vec<Arc<UdpSocket>>),
    Session(Arc<dyn PacketSession>),
}

pub(super) struct Wire {
    carrier: Carrier,
    reserved: Arc<Reserved>,
    amnezia: Option<Arc<Amnezia>>,
    broken: Arc<Breaker>,
}

pub(super) struct WireFactory(Option<Wire>);

impl WireFactory {
    pub(super) fn new(
        carrier: Carrier,
        reserved: Arc<Reserved>,
        amnezia: Option<Arc<Amnezia>>,
        broken: Arc<Breaker>,
    ) -> Self {
        WireFactory(Some(Wire {
            carrier,
            reserved,
            amnezia,
            broken,
        }))
    }
}

#[derive(Clone)]
pub(super) struct WireSend {
    carrier: Arc<SendHalf>,
    reserved: Arc<Reserved>,
    amnezia: Option<Arc<Amnezia>>,
    broken: Arc<Breaker>,
}

const SEND_BATCH: usize = if UdpBatch::SENDS { UDP_BATCH } else { 1 };

struct OutSocket {
    socket: Arc<UdpSocket>,
    v4: bool,
    batch: UdpBatch,
}

enum SendHalf {
    Sockets(Vec<OutSocket>),
    Session(Arc<dyn PacketSession>),
}

pub(super) struct WireRecv {
    carrier: Carrier,
    amnezia: Option<Arc<Amnezia>>,
    broken: Arc<Breaker>,
}

impl UdpTransportFactory for WireFactory {
    type Send = WireSend;
    type Recv = WireRecv;

    async fn bind(
        &mut self,
        _params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let wire = self
            .0
            .take()
            .ok_or_else(|| io::Error::other("the wireguard transport is already bound"))?;
        Ok(wire.split())
    }
}

impl Wire {
    fn split(self) -> (WireSend, WireRecv) {
        let half = match &self.carrier {
            Carrier::Sockets(sockets) => SendHalf::Sockets(
                sockets
                    .iter()
                    .map(|socket| OutSocket {
                        v4: socket.local_addr().is_ok_and(|local| local.is_ipv4()),
                        socket: socket.clone(),
                        batch: UdpBatch::default(),
                    })
                    .collect(),
            ),
            Carrier::Session(session) => SendHalf::Session(session.clone()),
        };
        (
            WireSend {
                carrier: Arc::new(half),
                reserved: self.reserved,
                amnezia: self.amnezia.clone(),
                broken: self.broken.clone(),
            },
            WireRecv {
                carrier: self.carrier,
                amnezia: self.amnezia,
                broken: self.broken,
            },
        )
    }
}

impl WireSend {
    fn fail(&self, err: io::Error) -> io::Error {
        self.broken.trip();
        err
    }

    fn socket_for(sockets: &[OutSocket], destination: SocketAddr) -> io::Result<&OutSocket> {
        sockets
            .iter()
            .find(|out| out.v4 == destination.is_ipv4())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no wireguard socket for this address family",
                )
            })
    }

    fn batches(&self) -> bool {
        SEND_BATCH > 1 && self.amnezia.is_none() && matches!(&*self.carrier, SendHalf::Sockets(_))
    }

    async fn emit(&self, datagram: &[u8], destination: SocketAddr) -> io::Result<()> {
        match &*self.carrier {
            SendHalf::Sockets(sockets) => {
                let out = Self::socket_for(sockets, destination)?;
                out.socket.send_to(datagram, destination).await.map(|_| ())
            }
            SendHalf::Session(session) => {
                let mut out = PacketBuf::with_headroom(session.headroom());
                out.extend_from_slice(datagram);
                send_packet(&**session, &mut out, &Address::from(destination))
                    .await
                    .map_err(|err| self.fail(err))
            }
        }
    }
}

impl WireSend {
    async fn send_batch(&self, packets: &mut Vec<(Packet, SocketAddr)>) -> io::Result<()> {
        let SendHalf::Sockets(sockets) = &*self.carrier else {
            return Ok(());
        };
        let Some(first) = packets.first().map(|(_, destination)| *destination) else {
            return Ok(());
        };
        let out = Self::socket_for(sockets, first)?;
        {
            let reserved = self.reserved.load();
            for (packet, destination) in packets.iter_mut() {
                apply_reserved(packet, *destination, &reserved);
            }
        }
        loop {
            out.socket.writable().await?;
            match drain(packets, SEND_BATCH, |batch| {
                out.batch.send(&out.socket, batch)
            }) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
    }
}

fn apply_reserved(
    packet: &mut Packet,
    destination: SocketAddr,
    reserved: &HashMap<SocketAddr, [u8; 3]>,
) {
    if packet.len() >= HEADER_LEN
        && let Some(reserved) = reserved.get(&destination)
        && let Some(slot) = packet.get_mut(1..HEADER_LEN)
    {
        slot.copy_from_slice(reserved);
    }
}

/// Hands `packets` to `send` a batch at a time until none is left, dropping each batch as it
/// reports it sent. An error leaves the unsent packets in place.
fn drain(
    packets: &mut Vec<(Packet, SocketAddr)>,
    limit: usize,
    mut send: impl FnMut(&[Datagram<'_>]) -> io::Result<usize>,
) -> io::Result<()> {
    while !packets.is_empty() {
        let batch: Vec<Datagram<'_>> = packets
            .iter()
            .take(limit)
            .map(|(packet, dst)| Datagram {
                payload: packet,
                dst: *dst,
            })
            .collect();
        let sent = send(&batch)?;
        packets.drain(..sent.min(packets.len()));
    }
    Ok(())
}

impl UdpSend for WireSend {
    type SendManyBuf = ();

    fn max_number_of_packets_to_send(&self) -> usize {
        if self.batches() { SEND_BATCH } else { 1 }
    }

    async fn send_many_to(
        &self,
        _buf: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if self.batches() {
            return self.send_batch(packets).await;
        }
        for (packet, destination) in std::mem::take(packets) {
            self.send_to(packet, destination).await?;
        }
        Ok(())
    }

    async fn send_to(&self, mut packet: Packet, destination: SocketAddr) -> io::Result<()> {
        if let Some(amnezia) = &self.amnezia {
            for datagram in amnezia.frame(&packet, destination).await {
                self.emit(&datagram, destination).await?;
            }
            return Ok(());
        }
        apply_reserved(&mut packet, destination, &self.reserved.load());
        self.emit(&packet, destination).await
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        match &*self.carrier {
            SendHalf::Sockets(sockets) => match sockets.first() {
                Some(out) => out.socket.local_addr().map(Some),
                None => Ok(None),
            },
            SendHalf::Session(_) => Ok(None),
        }
    }
}

impl UdpRecv for WireRecv {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        loop {
            let mut packet = pool.get();
            let received = match &self.carrier {
                Carrier::Sockets(sockets) => loop {
                    let result = poll_fn(|cx| {
                        let mut buf = ReadBuf::new(&mut packet);
                        for socket in sockets {
                            if let Poll::Ready(result) = socket.poll_recv_from(cx, &mut buf) {
                                return Poll::Ready(result.map(|from| (buf.filled().len(), from)));
                            }
                        }
                        Poll::Pending
                    })
                    .await;
                    // Windows reports an ICMP port unreachable for an earlier datagram as a read error.
                    if result
                        .as_ref()
                        .is_err_and(|err| err.kind() == io::ErrorKind::ConnectionReset)
                    {
                        continue;
                    }
                    break result;
                },
                Carrier::Session(session) => {
                    recv_packet(&**session)
                        .await
                        .and_then(|(data, from)| match from {
                            Address::Socket(from) if data.len() <= packet.len() => {
                                if let Some(slot) = packet.get_mut(..data.len()) {
                                    slot.copy_from_slice(data.as_slice());
                                }
                                Ok((data.len(), from))
                            }
                            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
                        })
                }
            };
            let (len, from) = received.inspect_err(|_| {
                self.broken.trip();
            })?;
            packet.truncate(len);
            if let Some(amnezia) = &self.amnezia {
                match amnezia.unframe(&mut packet, from) {
                    Some(kept) => {
                        packet.truncate(kept);
                        return Ok((packet, from));
                    }
                    None => continue,
                }
            }
            if len >= HEADER_LEN
                && let Some(slot) = packet.get_mut(1..HEADER_LEN)
            {
                slot.fill(0);
            }
            return Ok((packet, from));
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "the test talks to loopback sockets directly"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reserved_bytes_are_written_to_a_peer_and_cleared_on_receipt() {
        let ours = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let theirs = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reserved = Arc::new(ArcSwap::from_pointee(HashMap::from([(
            theirs.local_addr().unwrap(),
            [1, 2, 3],
        )])));
        let wire = Wire {
            carrier: Carrier::Sockets(vec![ours.clone()]),
            reserved,
            amnezia: None,
            broken: Arc::default(),
        };
        let (send, mut recv) = wire.split();

        send.send_to(
            Packet::copy_from(&[1u8, 0, 0, 0, 9, 9][..]),
            theirs.local_addr().unwrap(),
        )
        .await
        .unwrap();
        let mut seen = [0u8; 16];
        let (n, from) = theirs.recv_from(&mut seen).await.unwrap();
        assert_eq!(&seen[..n], &[1, 1, 2, 3, 9, 9]);

        theirs.send_to(&[2, 7, 8, 9, 5], from).await.unwrap();
        let pool = PacketBufPool::new(1);
        let (packet, _) = recv.recv_from(&mut { pool }).await.unwrap();
        assert_eq!(&packet[..], &[2, 0, 0, 0, 5]);
    }
    fn queued(count: usize, destination: SocketAddr) -> Vec<(Packet, SocketAddr)> {
        (0..count)
            .map(|i| {
                let tag = u8::try_from(i).unwrap();
                (Packet::copy_from(&[1u8, 0, 0, 0, tag][..]), destination)
            })
            .collect()
    }

    #[test]
    fn several_queued_packets_leave_in_one_call_to_the_sender() {
        let destination: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut packets = queued(10, destination);
        let mut calls = Vec::new();

        drain(&mut packets, 64, |batch| {
            calls.push(batch.len());
            Ok(batch.len())
        })
        .unwrap();

        assert_eq!(calls, [10], "a batch of 10 reached the sender in one call");
        assert!(packets.is_empty());
    }

    #[test]
    fn a_partial_send_resumes_after_the_packets_that_left() {
        let destination: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut packets = queued(5, destination);
        let mut seen = Vec::new();

        drain(&mut packets, 64, |batch| {
            seen.push(batch.iter().map(|d| d.payload[4]).collect::<Vec<_>>());
            Ok(batch.len().min(2))
        })
        .unwrap();

        assert_eq!(seen, [vec![0, 1, 2, 3, 4], vec![2, 3, 4], vec![4]]);
    }

    #[test]
    fn a_batch_is_cut_at_the_limit_and_an_error_keeps_the_unsent() {
        let destination: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut packets = queued(5, destination);
        let mut calls = 0;

        let err = drain(&mut packets, 3, |batch| {
            calls += 1;
            assert!(batch.len() <= 3);
            if calls == 1 {
                Ok(batch.len())
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(packets.len(), 2);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn the_socket_adapter_reports_the_batch_capacity_and_delivers_a_batch() {
        let ours = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let theirs = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire = Wire {
            carrier: Carrier::Sockets(vec![ours]),
            reserved: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            amnezia: None,
            broken: Arc::default(),
        };
        let (send, _recv) = wire.split();
        assert_eq!(send.max_number_of_packets_to_send(), SEND_BATCH);

        let mut packets = queued(8, theirs.local_addr().unwrap());
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send.send_many_to(&mut (), &mut packets),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(packets.is_empty());

        let mut seen = [0u8; 64];
        for i in 0..8u8 {
            let (n, _) = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                theirs.recv_from(&mut seen),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&seen[..n], &[1, 0, 0, 0, i]);
        }
    }
}
