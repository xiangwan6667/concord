use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use concord_common::Tasks;
use concord_common::sync::lock;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::Rng;
use tokio::task::JoinHandle;

use super::obfs::{Gecko, Opened, Seal};

pub(crate) enum Obfs {
    None,
    Seal(Box<dyn Seal>),
    Gecko(Mutex<Gecko>),
}

/// The port-hopping schedule. The connection keeps its first server address
/// while datagrams leave for whichever port the schedule picked last.
#[derive(Clone)]
pub(crate) struct Hop {
    pub(crate) ports: Vec<u16>,
    pub(crate) min: Duration,
    pub(crate) max: Duration,
}

struct HopState {
    base_port: u16,
    current: Arc<AtomicU16>,
    task: JoinHandle<()>,
}

impl Drop for HopState {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl HopState {
    fn start(base_port: u16, hop: Hop, tasks: &Tasks) -> Self {
        let current = Arc::new(AtomicU16::new(base_port));
        let task = tasks.spawn(hop_loop(Arc::downgrade(&current), hop));
        HopState {
            base_port,
            current,
            task,
        }
    }
}

async fn hop_loop(current: Weak<AtomicU16>, hop: Hop) {
    loop {
        let wait = if hop.max > hop.min {
            let span = u64::try_from((hop.max - hop.min).as_millis()).unwrap_or(0);
            hop.min + Duration::from_millis(rand::rng().random_range(0..=span))
        } else {
            hop.min
        };
        tokio::time::sleep(wait).await;
        let Some(current) = current.upgrade() else {
            return;
        };
        let pick = rand::rng().random_range(0..hop.ports.len().max(1));
        if let Some(port) = hop.ports.get(pick) {
            current.store(*port, Ordering::Relaxed);
        }
    }
}

/// Obfuscates datagrams and hops the server port over whatever socket the
/// factory produced, so quinn sees one peer address throughout.
pub(crate) struct WrappedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Obfs,
    hop: Option<HopState>,
    scratch: Mutex<Vec<u8>>,
}

impl fmt::Debug for WrappedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedSocket").finish_non_exhaustive()
    }
}

impl WrappedSocket {
    pub(crate) fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        obfs: Obfs,
        hop: Option<(u16, Hop)>,
        tasks: &Tasks,
    ) -> Arc<Self> {
        let hop = hop
            .filter(|(_, hop)| !hop.ports.is_empty())
            .map(|(base, hop)| HopState::start(base, hop, tasks));
        Arc::new(WrappedSocket {
            inner,
            obfs,
            hop,
            scratch: Mutex::new(Vec::new()),
        })
    }

    fn obfuscating(&self) -> bool {
        !matches!(self.obfs, Obfs::None)
    }

    fn destination(&self, wanted: SocketAddr) -> SocketAddr {
        let mut to = wanted;
        if let Some(hop) = &self.hop {
            to.set_port(hop.current.load(Ordering::Relaxed));
        }
        to
    }

    fn send_raw(
        &self,
        original: &Transmit<'_>,
        destination: SocketAddr,
        data: &[u8],
        segment_size: Option<usize>,
    ) -> io::Result<()> {
        self.inner.try_send(&Transmit {
            destination,
            ecn: original.ecn,
            contents: data,
            segment_size,
            src_ip: original.src_ip,
        })
    }

    fn open_received(&self, buf: &mut [u8], meta: &mut RecvMeta) -> bool {
        let len = meta.len.min(buf.len());
        let stride = if meta.stride == 0 || meta.stride > len {
            len
        } else {
            meta.stride
        };
        let Some(data) = buf.get_mut(..len) else {
            return false;
        };
        let from = meta.addr;
        match &self.obfs {
            Obfs::None => true,
            Obfs::Seal(seal) => {
                let (mut read, mut write) = (0, 0);
                while read < len {
                    let end = (read + stride).min(len);
                    let Some(opened) = data
                        .get_mut(read..end)
                        .and_then(|segment| seal.open(segment))
                    else {
                        break;
                    };
                    data.copy_within(read..read + opened, write);
                    write += opened;
                    read = end;
                }
                if write == 0 {
                    return false;
                }
                meta.len = write;
                meta.stride = if len > stride {
                    stride - seal.overhead()
                } else {
                    write
                };
                true
            }
            Obfs::Gecko(gecko) => {
                let mut gecko = lock(gecko);
                let (mut read, mut write) = (0, 0);
                while read < len {
                    let end = (read + stride).min(len);
                    let opened = match data.get_mut(read..end) {
                        Some(segment) => gecko.open(segment, from),
                        None => Opened::Dropped,
                    };
                    match opened {
                        Opened::Whole(opened) => {
                            data.copy_within(read..read + opened, write);
                            write += opened;
                        }
                        Opened::Joined(joined) if len == stride => {
                            drop(gecko);
                            let Some(target) = buf.get_mut(..joined.len()) else {
                                return false;
                            };
                            target.copy_from_slice(&joined);
                            meta.len = joined.len();
                            meta.stride = joined.len();
                            return true;
                        }
                        Opened::Joined(_) => return false,
                        Opened::Dropped if len > stride => return false,
                        Opened::Dropped => {}
                    }
                    read = end;
                }
                if write == 0 {
                    return false;
                }
                meta.len = write;
                meta.stride = if len > stride { stride - 8 } else { write };
                true
            }
        }
    }
}

/// quinn-udp keeps URO off on Windows yet sizes every receive for 64 coalesced datagrams,
/// so each `WSARecvMsg` would be handed about 94 KB for a single packet.
#[cfg(windows)]
#[derive(Debug)]
pub(super) struct SingleReceive(pub(super) Arc<dyn AsyncUdpSocket>);

#[cfg(windows)]
impl AsyncUdpSocket for SingleReceive {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.0.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.0.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.0.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.0.may_fragment()
    }
}

impl AsyncUdpSocket for WrappedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let to = self.destination(transmit.destination);
        match &self.obfs {
            Obfs::None => self.send_raw(transmit, to, transmit.contents, transmit.segment_size),
            Obfs::Seal(seal) => {
                let mut scratch = lock(&self.scratch);
                scratch.clear();
                seal.seal(transmit.contents, &mut scratch);
                self.send_raw(transmit, to, &scratch, None)
            }
            Obfs::Gecko(gecko) => {
                let mut datagrams = Vec::new();
                lock(gecko).seal(transmit.contents, &mut datagrams);
                for (index, datagram) in datagrams.iter().enumerate() {
                    match self.send_raw(transmit, to, datagram, None) {
                        Ok(()) => {}
                        Err(err) if index == 0 => return Err(err),
                        Err(_) => break,
                    }
                }
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let received = ready!(self.inner.poll_recv(cx, bufs, meta))?;
            if !self.obfuscating() && self.hop.is_none() {
                return Poll::Ready(Ok(received));
            }
            let mut kept = 0;
            for index in 0..received {
                let (Some(buf), Some(mut info)) = (bufs.get_mut(index), meta.get(index).copied())
                else {
                    break;
                };
                if !self.open_received(buf, &mut info) {
                    continue;
                }
                if let Some(hop) = &self.hop {
                    info.addr.set_port(hop.base_port);
                }
                if let Some(slot) = meta.get_mut(kept) {
                    *slot = info;
                }
                if kept != index {
                    bufs.swap(kept, index);
                }
                kept += 1;
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        if self.obfuscating() {
            1
        } else {
            self.inner.max_transmit_segments()
        }
    }

    fn max_receive_segments(&self) -> usize {
        if cfg!(windows) {
            1
        } else {
            self.inner.max_receive_segments()
        }
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "the tests talk to loopback sockets directly"
)]
mod tests {
    use quinn::{Runtime, TokioRuntime};

    use super::super::obfs::Salamander;
    use super::*;

    fn wrap(
        socket: tokio::net::UdpSocket,
        obfs: Obfs,
        hop: Option<(u16, Hop)>,
    ) -> Arc<WrappedSocket> {
        let inner = TokioRuntime
            .wrap_udp_socket(socket.into_std().unwrap())
            .unwrap();
        WrappedSocket::new(inner, obfs, hop, &Default::default())
    }

    async fn send(socket: &Arc<WrappedSocket>, to: SocketAddr, data: &[u8]) {
        let mut poller = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        socket
            .try_send(&Transmit {
                destination: to,
                ecn: None,
                contents: data,
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
    }

    async fn receive(socket: &Arc<WrappedSocket>) -> (Vec<u8>, SocketAddr) {
        std::future::poll_fn(|cx| {
            let mut buf = vec![0u8; 2048];
            let mut meta = [RecvMeta::default()];
            let mut bufs = [IoSliceMut::new(&mut buf)];
            let count = ready!(socket.poll_recv(cx, &mut bufs, &mut meta))?;
            assert_eq!(count, 1);
            let got = meta.first().copied().unwrap_or_default();
            Poll::Ready(io::Result::Ok((
                buf.get(..got.len).unwrap_or_default().to_vec(),
                got.addr,
            )))
        })
        .await
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn datagrams_follow_the_hop_schedule_but_replies_keep_the_base_port() {
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let base = first.local_addr().unwrap();
        let other = second.local_addr().unwrap();
        let hop = Hop {
            ports: vec![other.port()],
            min: Duration::from_secs(5),
            max: Duration::from_secs(5),
        };
        let socket = wrap(client, Obfs::None, Some((base.port(), hop)));
        send(&socket, base, b"one").await;
        let mut buf = [0u8; 16];
        let (len, from) = first.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf.get(..len), Some(&b"one"[..]));

        tokio::time::sleep(Duration::from_secs(6)).await;
        send(&socket, base, b"two").await;
        let (len, _) = second.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf.get(..len), Some(&b"two"[..]));

        second.send_to(b"back", from).await.unwrap();
        let (data, source) = receive(&socket).await;
        assert_eq!(data, b"back");
        assert_eq!(source.port(), base.port());
    }

    #[tokio::test]
    async fn salamander_datagrams_cross_the_wire_sealed() {
        let near = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far_addr = far.local_addr().unwrap();
        let socket = wrap(near, Obfs::Seal(Box::new(Salamander::new(b"pw"))), None);
        send(&socket, far_addr, b"hello salamander").await;
        let mut buf = [0u8; 64];
        let (len, from) = far.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, b"hello salamander".len() + 8);
        assert_ne!(buf.get(8..len), Some(&b"hello salamander"[..]));
        let mut sealed = buf.get(..len).unwrap_or_default().to_vec();
        let opened = Salamander::new(b"pw").open(&mut sealed).unwrap();
        assert_eq!(sealed.get(..opened), Some(&b"hello salamander"[..]));

        let mut sealed = Vec::new();
        Salamander::new(b"pw").seal(b"reply", &mut sealed);
        far.send_to(&sealed, from).await.unwrap();
        let (data, _) = receive(&socket).await;
        assert_eq!(data, b"reply");
    }
}
