use std::io;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use concord_common::{Address, PacketBuf, PacketSession};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::conn::{Counted, Hub, Live};
use super::wire::{self, Fragment, V4_OVERHEAD, V5_OVERHEAD, Version};
use crate::util::lock;

const WRITER_QUEUE: usize = 64;

pub(super) struct Relay {
    pub(super) version: Version,
    pub(super) native: bool,
    pub(super) max_packet: usize,
}

/// One UDP association: native mode sends datagrams, quic mode a unidirectional
/// stream per packet through a writer task so that `poll_send` never waits.
pub(super) struct TuicPackets {
    id: u32,
    relay: Relay,
    live: Arc<Live>,
    hub: Arc<Hub>,
    incoming: Mutex<mpsc::Receiver<(Address, Bytes)>>,
    packet_id: AtomicU16,
    streams: Option<(mpsc::Sender<Vec<u8>>, JoinHandle<()>)>,
    closed: AtomicBool,
    _count: Counted,
}

impl TuicPackets {
    pub(super) fn new(live: Arc<Live>, relay: Relay, count: Counted) -> io::Result<Self> {
        let (id, incoming) = live
            .hub
            .register(relay.version)
            .ok_or_else(|| io::Error::other("tuic: no free association id"))?;
        let streams = (!relay.native).then(|| {
            let (queue, mut jobs) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
            let conn = live.quic.conn.clone();
            let task = live.quic.tasks.spawn(async move {
                while let Some(frame) = jobs.recv().await {
                    let Ok(mut stream) = conn.open_uni().await else {
                        break;
                    };
                    if stream.write_all(&frame).await.is_err() {
                        break;
                    }
                    let _ = stream.finish();
                }
            });
            (queue, task)
        });
        Ok(TuicPackets {
            id,
            hub: live.hub.clone(),
            relay,
            live,
            incoming: Mutex::new(incoming),
            packet_id: AtomicU16::new(rand::random()),
            streams,
            closed: AtomicBool::new(false),
            _count: count,
        })
    }

    fn overhead(&self) -> usize {
        match self.relay.version {
            Version::V5 => V5_OVERHEAD,
            Version::V4 => V4_OVERHEAD,
        }
    }

    fn send_native(&self, data: &[u8], dst: &Address) -> io::Result<()> {
        let conn = &self.live.quic.conn;
        let packet = self.packet_id.fetch_add(1, Ordering::Relaxed);
        let whole = |addr: Option<&Address>| {
            wire::packet(
                self.relay.version,
                &Fragment {
                    assoc: self.id,
                    packet,
                    total: 1,
                    id: 0,
                    addr,
                    data,
                },
            )
        };
        if self.relay.version == Version::V4 {
            if data.len() > self.relay.max_packet {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "datagram larger than max-udp-relay-packet-size",
                ));
            }
            return conn
                .send_datagram(Bytes::from(whole(Some(dst))?))
                .map_err(send_error);
        }
        if data.len() <= self.relay.max_packet {
            match conn.send_datagram(Bytes::from(whole(Some(dst))?)) {
                Ok(()) => return Ok(()),
                Err(quinn::SendDatagramError::TooLarge) => {}
                Err(err) => return Err(send_error(err)),
            }
        }
        let room = conn
            .max_datagram_size()
            .map_or(self.relay.max_packet, |size| {
                size.saturating_sub(self.overhead())
            })
            .min(self.relay.max_packet)
            .max(1);
        let pieces: Vec<&[u8]> = data.chunks(room).collect();
        let total = u8::try_from(pieces.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?;
        for (index, piece) in pieces.into_iter().enumerate() {
            let frame = wire::packet(
                self.relay.version,
                &Fragment {
                    assoc: self.id,
                    packet,
                    total,
                    id: index as u8,
                    addr: (index == 0).then_some(dst),
                    data: piece,
                },
            )?;
            conn.send_datagram(Bytes::from(frame)).map_err(send_error)?;
        }
        Ok(())
    }

    fn send_stream(&self, data: &[u8], dst: &Address) -> io::Result<()> {
        let Some((queue, _)) = &self.streams else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        let frame = wire::packet(
            self.relay.version,
            &Fragment {
                assoc: self.id,
                packet: self.packet_id.fetch_add(1, Ordering::Relaxed),
                total: 1,
                id: 0,
                addr: Some(dst),
                data,
            },
        )?;
        let _ = queue.try_send(frame);
        Ok(())
    }

    fn dissociate(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.hub.remove(self.id);
        if let Some((_, task)) = &self.streams {
            task.abort();
        }
        let frame = wire::dissociate(self.relay.version, self.id);
        let conn = self.live.quic.conn.clone();
        self.live.quic.tasks.spawn_detached(async move {
            if let Ok(mut stream) = conn.open_uni().await
                && stream.write_all(&frame).await.is_ok()
            {
                let _ = stream.finish();
            }
        });
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

impl PacketSession for TuicPackets {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let data = pkt.as_slice();
        let sent = if self.relay.native {
            self.send_native(data, dst)
        } else {
            self.send_stream(data, dst)
        };
        Poll::Ready(sent)
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

    fn close(&self) {
        self.dissociate();
    }
}

impl Drop for TuicPackets {
    fn drop(&mut self) {
        self.dissociate();
    }
}
