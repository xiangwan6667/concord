use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};

use concord_common::sync::lock;
use concord_common::{Address, PacketBuf, PacketSession, Tasks, recv_packet, send_packet};
use futures_util::future::BoxFuture;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const SESSION_QUEUE: usize = 256;

/// A quinn socket over a `PacketSession`, which is how a `dialer-proxy` carries
/// QUIC. The two queues copy each datagram once.
pub struct SessionSocket {
    local: SocketAddr,
    remote: SocketAddr,
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    session: Arc<dyn PacketSession>,
    pumps: [JoinHandle<()>; 2],
}

impl fmt::Debug for SessionSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSocket")
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

impl Drop for SessionSocket {
    fn drop(&mut self) {
        for pump in &self.pumps {
            pump.abort();
        }
        self.session.close();
    }
}

impl SessionSocket {
    pub fn new(session: Arc<dyn PacketSession>, remote: SocketAddr, tasks: &Tasks) -> Arc<Self> {
        let (outgoing, mut queued) = mpsc::channel::<Vec<u8>>(SESSION_QUEUE);
        let (deliver, incoming) = mpsc::channel::<(Vec<u8>, SocketAddr)>(SESSION_QUEUE);
        let sender = session.clone();
        let target = Address::Socket(remote);
        let send_pump = tasks.spawn(async move {
            while let Some(data) = queued.recv().await {
                let mut pkt = PacketBuf::with_headroom(sender.headroom());
                pkt.extend_from_slice(&data);
                if send_packet(&*sender, &mut pkt, &target).await.is_err() {
                    break;
                }
            }
        });
        let receiver = session.clone();
        let recv_pump = tasks.spawn(async move {
            while let Ok((pkt, from)) = recv_packet(&*receiver).await {
                let from = match from {
                    Address::Socket(addr) => addr,
                    Address::Domain(..) => remote,
                };
                let _ = deliver.try_send((pkt.as_slice().to_vec(), from));
            }
        });
        let local = match remote.ip() {
            IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        Arc::new(SessionSocket {
            local,
            remote,
            outgoing,
            incoming: Mutex::new(incoming),
            session,
            pumps: [send_pump, recv_pump],
        })
    }
}

struct SessionPoller {
    outgoing: mpsc::Sender<Vec<u8>>,
    waiting: Mutex<Option<BoxFuture<'static, io::Result<()>>>>,
}

impl fmt::Debug for SessionPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for SessionPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let waiting = this
            .waiting
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let future = waiting.get_or_insert_with(|| {
            let outgoing = this.outgoing.clone();
            Box::pin(async move {
                outgoing
                    .reserve_owned()
                    .await
                    .map(drop)
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
            })
        });
        let result = ready!(future.as_mut().poll(cx));
        *waiting = None;
        Poll::Ready(result)
    }
}

impl AsyncUdpSocket for SessionSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SessionPoller {
            outgoing: self.outgoing.clone(),
            waiting: Mutex::new(None),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        match self.outgoing.try_send(transmit.contents.to_vec()) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::ErrorKind::WouldBlock.into()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let next = ready!(lock(&self.incoming).poll_recv(cx));
        let Some((data, from)) = next else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let (Some(buf), Some(slot)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        let len = data.len().min(buf.len());
        if let (Some(target), Some(source)) = (buf.get_mut(..len), data.get(..len)) {
            target.copy_from_slice(source);
        }
        *slot = RecvMeta {
            addr: from,
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}
