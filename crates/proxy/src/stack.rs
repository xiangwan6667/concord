mod session;
mod stream;
pub(crate) use session::{SessionTunnel, StackSession};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
pub(crate) use stream::IpStream;

use concord_common::{Stream, Tasks};
use concord_netstack::frag::Reassembler;
use concord_netstack::wire::{
    BuildError, IpView, L4Checksum, L4Kind, Parsed, build_udp, parse_packet, parse_udp,
};
use concord_netstack::{Admit, Egress, NetReadHalf, NetStream, NetWriteHalf, TcpConfig, TcpStack};
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};

use crate::util::lock;

pub(crate) use concord_netstack::Congestion;

#[cfg(test)]
mod serve;

const UDP_RECEIVE_CAPACITY: usize = 212_992;
const OUTBOUND_QUEUE: usize = 1024;
const MAX_TX_BACKLOG: usize = 256;
const RX_BATCH: usize = 64;
const EPHEMERAL_START: u16 = 32768;
const EPHEMERAL_END: u16 = 60999;

pub(crate) struct StackConfig {
    pub(crate) addrs: Vec<IpAddr>,
    pub(crate) mtu: usize,
}

/// Builds the stack's packets into buffers from gotatun's pool, at most one MTU each.
struct Out<'a> {
    queue: &'a mut VecDeque<Packet>,
    pool: &'a mut PacketBufPool,
    mtu: usize,
}

impl Egress for Out<'_> {
    fn send(&mut self, build: &mut dyn FnMut(&mut [u8]) -> Option<usize>) -> bool {
        if self.queue.len() >= MAX_TX_BACKLOG {
            return false;
        }
        let mut packet = self.pool.get();
        packet.buf_mut().resize(self.mtu, 0);
        let room = self.mtu;
        if let Some(len) = packet.get_mut(..room).and_then(build) {
            packet.truncate(len);
            self.queue.push_back(packet);
        }
        true
    }
}

#[derive(Default)]
struct UdpSlot {
    queue: VecDeque<(SocketAddr, Vec<u8>)>,
    queued_bytes: usize,
    waker: Option<Waker>,
}

fn datagram_cost(data: &[u8]) -> usize {
    data.len() + size_of::<(SocketAddr, Vec<u8>)>()
}

struct Inner {
    tcp: TcpStack,
    udp: HashMap<u16, UdpSlot>,
    listeners: HashMap<u16, mpsc::UnboundedSender<NetStream>>,
    fragments: Reassembler,
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    rx: VecDeque<Packet>,
    tx: VecDeque<Packet>,
    pool: PacketBufPool,
    mtu: usize,
    next_port: u16,
    send_wakers: Vec<Waker>,
}

impl Inner {
    fn local_for(&self, remote: IpAddr) -> io::Result<IpAddr> {
        let local = if remote.is_ipv4() { self.v4 } else { self.v6 };
        local.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no route inside the tunnel",
            )
        })
    }

    fn port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if port >= EPHEMERAL_END {
            EPHEMERAL_START
        } else {
            port + 1
        };
        port
    }

    fn handle_rx(&mut self) {
        let mut whole = Vec::new();
        while let Some(packet) = self.rx.pop_front() {
            match parse_packet(&packet) {
                Ok(Parsed::Packet(view)) => self.dispatch(&view),
                Ok(Parsed::Fragment(frag)) => {
                    if self.fragments.push(&frag, self.tcp.now(), &mut whole)
                        && let Ok(Parsed::Packet(view)) = parse_packet(&whole)
                    {
                        self.dispatch(&view);
                    }
                }
                Err(_) => {}
            }
        }
    }

    fn dispatch(&mut self, view: &IpView<'_>) {
        match view.kind {
            L4Kind::Tcp => {
                let listeners = &self.listeners;
                let mut out = Out {
                    queue: &mut self.tx,
                    pool: &mut self.pool,
                    mtu: self.mtu,
                };
                self.tcp
                    .input(view.src, view.dst, view.l4, &mut out, |_, local| {
                        if listeners.contains_key(&local.port()) {
                            Admit::Accept(u32::from(local.port()))
                        } else {
                            Admit::Reject
                        }
                    });
            }
            L4Kind::Udp => {
                if let Ok(udp) = parse_udp(view)
                    && let Some(slot) = self.udp.get_mut(&udp.dst_port)
                    && slot.queued_bytes < UDP_RECEIVE_CAPACITY
                {
                    let from = SocketAddr::new(view.src, udp.src_port);
                    slot.queued_bytes += datagram_cost(udp.payload);
                    slot.queue.push_back((from, udp.payload.to_vec()));
                    if let Some(waker) = slot.waker.take() {
                        waker.wake();
                    }
                }
            }
            L4Kind::Icmp => {}
        }
    }

    fn poll_tcp(&mut self) -> Option<Instant> {
        let mut out = Out {
            queue: &mut self.tx,
            pool: &mut self.pool,
            mtu: self.mtu,
        };
        let next = self.tcp.poll(&mut out);
        while let Some(accepted) = self.tcp.take_accepted() {
            let port = u16::try_from(accepted.tag).unwrap_or_default();
            if let Some(listener) = self.listeners.get(&port) {
                let _ = listener.send(accepted.stream);
            }
        }
        next.map(|at| self.tcp.instant_at(at))
    }

    fn drain(&mut self, out: &mpsc::Sender<Packet>) {
        while let Some(packet) = self.tx.pop_front() {
            if let Err(err) = out.try_send(packet) {
                if let mpsc::error::TrySendError::Full(packet) = err {
                    self.tx.push_front(packet);
                }
                break;
            }
        }
        if self.tx.len() < MAX_TX_BACKLOG {
            for waker in self.send_wakers.drain(..) {
                waker.wake();
            }
        }
    }
}

pub(crate) struct Stack {
    inner: Mutex<Inner>,
    wake: Arc<Notify>,
    active: AtomicUsize,
}

struct NotifyWake(Arc<Notify>);

impl Wake for NotifyWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

/// The two halves gotatun talks to, and the handle the application side uses.
pub(crate) struct Wired {
    pub(crate) stack: Arc<Stack>,
    pub(crate) send: StackSend,
    pub(crate) recv: StackRecv,
    pub(crate) driver: JoinHandle<()>,
}

pub(crate) struct StackSend {
    tx: mpsc::Sender<Packet>,
}

pub(crate) struct StackRecv {
    rx: mpsc::Receiver<Packet>,
    mtu: MtuWatcher,
}

impl IpSend for StackSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tx
            .send(packet.into_bytes())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl IpRecv for StackRecv {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            let Some(packet) = self.rx.recv().await else {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            };
            if let Ok(ip) = packet.try_into_ip() {
                return Ok(std::iter::once(ip));
            }
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

impl Stack {
    pub(crate) fn start(config: &StackConfig, tasks: &Tasks) -> Wired {
        let (to_wg, from_stack) = mpsc::channel(OUTBOUND_QUEUE);
        let (to_stack, from_wg) = mpsc::channel(OUTBOUND_QUEUE);
        let tcp = TcpStack::new(concord_netstack::StackConfig {
            tcp: TcpConfig {
                mtu: config.mtu,
                ..TcpConfig::default()
            },
            ..concord_netstack::StackConfig::default()
        });
        let stack = Arc::new(Stack {
            inner: Mutex::new(Inner {
                tcp,
                udp: HashMap::new(),
                listeners: HashMap::new(),
                fragments: Reassembler::default(),
                v4: config.addrs.iter().copied().find(IpAddr::is_ipv4),
                v6: config.addrs.iter().copied().find(IpAddr::is_ipv6),
                rx: VecDeque::new(),
                tx: VecDeque::new(),
                pool: PacketBufPool::new(0),
                mtu: config.mtu,
                next_port: rand::random_range(EPHEMERAL_START..=EPHEMERAL_END),
                send_wakers: Vec::new(),
            }),
            wake: Arc::new(Notify::new()),
            active: AtomicUsize::new(0),
        });
        let driver = tasks.spawn(drive(stack.clone(), to_wg, from_wg));
        Wired {
            stack,
            send: StackSend { tx: to_stack },
            recv: StackRecv {
                rx: from_stack,
                mtu: MtuWatcher::new(u16::try_from(config.mtu).unwrap_or(u16::MAX)),
            },
            driver,
        }
    }

    pub(crate) fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    fn poke(&self) {
        self.wake.notify_one();
    }

    pub(crate) fn connect_tcp(
        self: &Arc<Self>,
        remote: SocketAddr,
        congestion: Congestion,
    ) -> io::Result<TcpConn> {
        let mut inner = lock(&self.inner);
        let ip = inner.local_for(remote.ip())?;
        let mut local = SocketAddr::new(ip, inner.port());
        while inner.tcp.is_bound(local, remote) {
            local.set_port(inner.port());
        }
        let stream = inner.tcp.connect(local, remote, congestion)?;
        drop(inner);
        self.poke();
        self.active.fetch_add(1, Ordering::Relaxed);
        Ok(TcpConn {
            stream,
            active: Active(self.clone()),
        })
    }

    pub(crate) fn bind_udp(self: &Arc<Self>) -> io::Result<UdpPort> {
        let mut inner = lock(&self.inner);
        let mut port = inner.port();
        while inner.udp.contains_key(&port) {
            port = inner.port();
        }
        drop(inner);
        self.bind_udp_at(port)
    }

    fn bind_udp_at(self: &Arc<Self>, port: u16) -> io::Result<UdpPort> {
        let mut inner = lock(&self.inner);
        if inner.udp.contains_key(&port) {
            return Err(io::Error::from(io::ErrorKind::AddrInUse));
        }
        inner.udp.insert(port, UdpSlot::default());
        drop(inner);
        self.active.fetch_add(1, Ordering::Relaxed);
        Ok(UdpPort {
            stack: self.clone(),
            port,
        })
    }
}

/// Fails every connection and wakes every parked receive when the driver ends, whether its
/// loop returned or its task was aborted.
struct Stopped<'a>(&'a Stack);

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        let mut inner = lock(&self.0.inner);
        inner.tcp.shutdown();
        for slot in inner.udp.values_mut() {
            if let Some(waker) = slot.waker.take() {
                waker.wake();
            }
        }
    }
}

async fn drive(stack: Arc<Stack>, out: mpsc::Sender<Packet>, mut from_wg: mpsc::Receiver<Packet>) {
    let _stopped = Stopped(&stack);
    let waker = Waker::from(Arc::new(NotifyWake(stack.wake.clone())));
    loop {
        let (deadline, backlog) = {
            let mut inner = lock(&stack.inner);
            inner.tcp.register_waker(&waker);
            inner.handle_rx();
            let deadline = inner.poll_tcp();
            inner.drain(&out);
            (deadline, !inner.tx.is_empty())
        };
        let deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        tokio::select! {
            packet = from_wg.recv() => {
                let Some(packet) = packet else { break };
                let mut inner = lock(&stack.inner);
                inner.rx.push_back(packet);
                while inner.rx.len() < RX_BATCH {
                    match from_wg.try_recv() {
                        Ok(more) => inner.rx.push_back(more),
                        Err(_) => break,
                    }
                }
            }
            permit = out.reserve(), if backlog => {
                let Ok(permit) = permit else { break };
                if let Some(packet) = lock(&stack.inner).tx.pop_front() {
                    permit.send(packet);
                }
            }
            () = stack.wake.notified() => {}
            () = sleep_until(deadline) => {}
        }
    }
}

pub(crate) struct TcpConn {
    stream: NetStream,
    active: Active,
}

/// Keeps the stack's count of live connections.
pub(crate) struct Active(Arc<Stack>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl TcpConn {
    pub(crate) fn into_split(self) -> (NetReadHalf, NetWriteHalf, Active) {
        let (read, write) = self.stream.into_split();
        (read, write, self.active)
    }

    pub(crate) fn poll_established(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_established(cx)
    }
}

impl AsyncRead for TcpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Stream for TcpConn {
    concord_common::stream_policy!(stream;
        forward: direct;
        default: into_split, read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            raw_socket, tcp, peer_addr, needs_handshake, into_tcp);
}

pub(crate) struct UdpPort {
    stack: Arc<Stack>,
    port: u16,
}

impl UdpPort {
    pub(crate) fn close(&self) {
        let mut inner = lock(&self.stack.inner);
        if let Some(mut slot) = inner.udp.remove(&self.port)
            && let Some(waker) = slot.waker.take()
        {
            waker.wake();
        }
        for waker in inner.send_wakers.drain(..) {
            waker.wake();
        }
    }

    pub(crate) fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        data: &[u8],
        dst: SocketAddr,
    ) -> Poll<io::Result<()>> {
        let mut guard = lock(&self.stack.inner);
        let inner = &mut *guard;
        let src = SocketAddr::new(inner.local_for(dst.ip())?, self.port);
        if inner.tx.len() >= MAX_TX_BACKLOG {
            inner.send_wakers.push(cx.waker().clone());
            return Poll::Pending;
        }
        let mut result = Ok(());
        Out {
            queue: &mut inner.tx,
            pool: &mut inner.pool,
            mtu: inner.mtu,
        }
        .send(
            &mut |buf| match build_udp(buf, src, dst, data, L4Checksum::Full) {
                Ok(len) => Some(len),
                Err(BuildError::TooLarge | BuildError::Family) => {
                    result = Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "datagram larger than the tunnel MTU",
                    ));
                    None
                }
            },
        );
        drop(guard);
        self.stack.poke();
        Poll::Ready(result)
    }

    pub(crate) fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut inner = lock(&self.stack.inner);
        let Some(slot) = inner.udp.get_mut(&self.port) else {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected)));
        };
        let Some((from, data)) = slot.queue.pop_front() else {
            slot.waker = Some(cx.waker().clone());
            return Poll::Pending;
        };
        slot.queued_bytes -= datagram_cost(&data);
        let Some(dst) = buf.get_mut(..data.len()) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram larger than the buffer",
            )));
        };
        dst.copy_from_slice(&data);
        Poll::Ready(Ok((data.len(), from)))
    }
}

impl Drop for UdpPort {
    fn drop(&mut self) {
        lock(&self.stack.inner).udp.remove(&self.port);
        self.stack.active.fetch_sub(1, Ordering::Relaxed);
    }
}
