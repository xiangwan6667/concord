use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use std::task::{Context, Poll, Waker};

use concord_common::sync::{lock, read, write};
use concord_common::{
    Address, CoreError, Datagram, DialCx, HostResolver, Initiator, IpVersion, LookupIps, PacketBuf,
    PacketSession, RecvBatch, SockOpts, SocketWatch, SocketWatcher, Tasks,
};
use concord_platform::UdpBatch;
use futures_util::task::AtomicWaker;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout_at;

use crate::dial::resolve;
use crate::loopback::{LoopbackGuard, UdpTicket};

struct Resolving {
    task: JoinHandle<()>,
}

#[derive(Default)]
struct Names {
    known: HashMap<concord_common::Host, IpAddr>,
    resolving: Option<Resolving>,
    failed: Option<(concord_common::Host, io::Error)>,
    waker: Option<Waker>,
}

/// A UDP socket that sends to any destination, and resolves a domain destination
/// once per name in a background task so the packet path never blocks or allocates.
pub struct DirectPacketSession {
    socket: RwLock<Io>,
    v6: bool,
    resolver: Arc<dyn HostResolver>,
    initiator: Initiator,
    version: IpVersion,
    ipv6: bool,
    names: Arc<Mutex<Names>>,
    closed: AtomicBool,
    /// Datagrams a full watched socket did not take.
    dropped: AtomicU64,
    /// The one sender that may wait on a full socket. Tokio drops a waker left on a socket
    /// that leaves its reactor without waking it, so `watch` wakes this one.
    sender: AtomicWaker,
    batch: UdpBatch,
    _ticket: Option<UdpTicket>,
    tasks: Tasks,
}

/// Where the socket's read readiness comes from.
enum Io {
    Tokio(UdpSocket),
    /// Watched by the writer that adopted the session's replies. Nothing waits on such a
    /// socket's writes: a send goes straight to the descriptor.
    Watched {
        socket: Arc<std::net::UdpSocket>,
        watch: Arc<dyn SocketWatch>,
    },
    /// The socket could not be handed over or back.
    Closed,
}

fn gone() -> io::Error {
    io::Error::from(io::ErrorKind::BrokenPipe)
}

fn pick(ips: &LookupIps, v6: bool, ipv6_enabled: bool) -> Option<IpAddr> {
    if v6 {
        ipv6_enabled.then(|| ips.v6.first().copied()).flatten()
    } else {
        ips.v4.first().copied()
    }
}

impl DirectPacketSession {
    pub fn new(
        socket: UdpSocket,
        resolver: Arc<dyn HostResolver>,
        initiator: Initiator,
        version: IpVersion,
        ipv6: bool,
        tasks: Tasks,
    ) -> Self {
        let v6 = socket.local_addr().is_ok_and(|addr| addr.is_ipv6());
        DirectPacketSession {
            socket: RwLock::new(Io::Tokio(socket)),
            v6,
            resolver,
            initiator,
            version,
            ipv6,
            names: Arc::new(Mutex::new(Names::default())),
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            sender: AtomicWaker::new(),
            batch: UdpBatch::default(),
            _ticket: None,
            tasks,
        }
    }

    /// The socket's family comes from `hint`, the first destination the caller expects.
    pub async fn associate(
        cx: &DialCx<'_>,
        hint: &Address,
        version: IpVersion,
        opts: &SockOpts,
        loopback: Option<&Arc<LoopbackGuard>>,
        tasks: &Tasks,
    ) -> io::Result<Self> {
        let resolving = resolve(cx, hint, version);
        let resolved = match cx.deadline {
            Some(deadline) => timeout_at(deadline, resolving)
                .await
                .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)))?,
            None => resolving.await?,
        };
        let ips = LookupIps {
            v4: resolved.v4,
            v6: resolved.v6,
        };
        let peer = ips
            .first(version)
            .ok_or_else(|| CoreError::IpNotFound(hint.host_string()))?;
        let socket = cx.env.sockets.bind_udp(peer, opts)?;
        let ticket = loopback.map(|guard| guard.track_udp(&socket));
        let mut session = Self::new(
            socket,
            Arc::clone(&cx.env.resolver),
            cx.initiator,
            version,
            cx.env.ipv6,
            tasks.clone(),
        );
        session._ticket = ticket;
        if let Some(host) = hint.domain()
            && let Some(ip) = pick(&ips, session.v6, session.ipv6)
        {
            lock(&session.names).known.insert(host.into(), ip);
        }
        Ok(session)
    }

    fn io(&self) -> RwLockReadGuard<'_, Io> {
        read(&self.socket)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match &*self.io() {
            Io::Tokio(socket) => socket.local_addr(),
            Io::Watched { socket, .. } => socket.local_addr(),
            Io::Closed => Err(gone()),
        }
    }

    fn poll_name(&self, cx: &mut Context<'_>, host: &str) -> Poll<io::Result<IpAddr>> {
        let mut names = lock(&self.names);
        if let Some(ip) = names.known.get(host) {
            return Poll::Ready(Ok(*ip));
        }
        if names
            .failed
            .as_ref()
            .is_some_and(|(failed, _)| failed.as_str() == host)
            && let Some((_, err)) = names.failed.take()
        {
            return Poll::Ready(Err(err));
        }
        if names
            .waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(cx.waker()))
        {
            names.waker = Some(cx.waker().clone());
        }
        if names.resolving.is_none() {
            let key: concord_common::Host = host.into();
            let task = self.tasks.spawn(resolve_name(
                Arc::clone(&self.names),
                Arc::clone(&self.resolver),
                key,
                self.version,
                self.initiator,
                (self.v6, self.ipv6),
            ));
            names.resolving = Some(Resolving { task });
        }
        Poll::Pending
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        addr: SocketAddr,
    ) -> Poll<io::Result<()>> {
        if addr.is_ipv6() != self.v6 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination address family differs from the socket's",
            )));
        }
        match &*self.io() {
            Io::Tokio(socket) => {
                let sent = socket.poll_send_to(cx, payload, addr).map_ok(|_| ());
                self.waiting(cx, sent)
            }
            Io::Watched { socket, .. } => Poll::Ready(
                self.or_dropped(socket.send_to(payload, addr), 1)
                    .map(|_| ()),
            ),
            Io::Closed => Poll::Ready(Err(gone())),
        }
    }

    fn waiting<T>(&self, cx: &Context<'_>, sent: Poll<T>) -> Poll<T> {
        if sent.is_pending() {
            self.sender.register(cx.waker());
        }
        sent
    }

    /// A full watched socket loses what it was offered, and the session counts it: sing-tun's
    /// engine sends a flow's uploads once and takes `EAGAIN` for sent (`flushPacketUploads`,
    /// `stack_go_splice.go:911-939`).
    fn or_dropped(&self, sent: io::Result<usize>, offered: usize) -> io::Result<usize> {
        match sent {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                self.dropped.fetch_add(offered as u64, Ordering::Relaxed);
                Ok(offered)
            }
            sent => sent,
        }
    }
}

async fn resolve_name(
    names: Arc<Mutex<Names>>,
    resolver: Arc<dyn HostResolver>,
    host: concord_common::Host,
    version: IpVersion,
    initiator: Initiator,
    (v6, ipv6): (bool, bool),
) {
    let found = resolver
        .lookup(&host, version, initiator)
        .await
        .and_then(|ips| {
            pick(&ips, v6, ipv6).ok_or_else(|| {
                let error = if v6 && !ipv6 {
                    CoreError::Ipv6Disabled
                } else {
                    CoreError::IpNotFound(host.to_string())
                };
                error.into()
            })
        });
    let mut names = lock(&names);
    names.resolving = None;
    match found {
        Ok(ip) => {
            names.known.insert(host, ip);
        }
        Err(err) => names.failed = Some((host, err)),
    }
    if let Some(waker) = names.waker.take() {
        waker.wake();
    }
}

impl Drop for DirectPacketSession {
    fn drop(&mut self) {
        if let Some(resolving) = lock(&self.names).resolving.take() {
            resolving.task.abort();
        }
        match *self.dropped.get_mut() {
            0 => {}
            dropped => tracing::debug!("[UDP] a full socket dropped {dropped} datagrams"),
        }
    }
}

impl PacketSession for DirectPacketSession {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        match dst {
            Address::Socket(addr) => self.poll_send_to(cx, pkt.as_slice(), *addr),
            Address::Domain(host, port) => match self.poll_name(cx, host) {
                Poll::Ready(Ok(ip)) => {
                    self.poll_send_to(cx, pkt.as_slice(), SocketAddr::new(ip, *port))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        let mut read = ReadBuf::new(buf.spare_mut());
        let from = match &*self.io() {
            Io::Tokio(socket) => std::task::ready!(socket.poll_recv_from(cx, &mut read))?,
            Io::Watched { socket, watch } => loop {
                std::task::ready!(watch.poll_read_ready(cx))?;
                let mut from = None;
                let received = watch.try_read(&mut || {
                    let (len, addr) = socket.recv_from(read.initialize_unfilled())?;
                    from = Some(addr);
                    Ok(len)
                });
                match (received, from) {
                    (Ok(len), Some(from)) => {
                        read.advance(len);
                        break from;
                    }
                    (Err(err), _) if err.kind() != io::ErrorKind::WouldBlock => {
                        return Poll::Ready(Err(err));
                    }
                    _ => {}
                }
            },
            Io::Closed => return Poll::Ready(Err(gone())),
        };
        let received = read.filled().len();
        buf.advance(received);
        Poll::Ready(Ok(Address::from(from)))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        if let Some(resolving) = lock(&self.names).resolving.take() {
            resolving.task.abort();
        }
    }

    fn batches(&self) -> bool {
        UdpBatch::SENDS
    }

    fn poll_send_batch(
        &self,
        cx: &mut Context<'_>,
        batch: &[Datagram<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if UdpBatch::SENDS {
            let same = batch
                .iter()
                .take_while(|datagram| datagram.dst.is_ipv6() == self.v6)
                .count();
            if same > 1 {
                let batch = batch.get(..same).unwrap_or(batch);
                match &*self.io() {
                    Io::Tokio(socket) => loop {
                        let ready = socket.poll_send_ready(cx);
                        if let Err(err) = std::task::ready!(self.waiting(cx, ready)) {
                            return Poll::Ready(Err(err));
                        }
                        match self.batch.send(socket, batch) {
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                            sent => return Poll::Ready(sent),
                        }
                    },
                    Io::Watched { socket, .. } => {
                        let sent = self.batch.send_std(socket, batch);
                        return Poll::Ready(self.or_dropped(sent, batch.len()));
                    }
                    Io::Closed => return Poll::Ready(Err(gone())),
                }
            }
        }
        let mut sent = 0;
        for datagram in batch {
            match self.poll_send_to(cx, datagram.payload, datagram.dst) {
                Poll::Ready(Ok(())) => sent += 1,
                Poll::Ready(Err(err)) if sent == 0 => return Poll::Ready(Err(err)),
                Poll::Pending if sent == 0 => return Poll::Pending,
                Poll::Ready(Err(_)) | Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(sent))
    }

    fn recv_batches(&self) -> bool {
        UdpBatch::RECEIVES
    }

    fn poll_recv_batch(&self, cx: &mut Context<'_>, batch: &mut RecvBatch) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        match &*self.io() {
            Io::Tokio(socket) => loop {
                std::task::ready!(socket.poll_recv_ready(cx))?;
                match UdpBatch::recv(socket, batch) {
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    received => return Poll::Ready(received),
                }
            },
            Io::Watched { socket, watch } => loop {
                std::task::ready!(watch.poll_read_ready(cx))?;
                let received =
                    watch.try_read(&mut || UdpBatch::recv_std(socket, batch).map(|()| 0));
                match received {
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    received => return Poll::Ready(received.map(|_| ())),
                }
            },
            Io::Closed => Poll::Ready(Err(gone())),
        }
    }

    /// Moves the socket from Tokio's reactor to `watcher`. The write lock is held across the
    /// move, so no send or receive sees the socket while nothing watches it; a socket that can
    /// be neither watched nor handed back closes the session.
    fn watch(&self, watcher: &dyn SocketWatcher) {
        let mut io = write(&self.socket);
        let socket = match std::mem::replace(&mut *io, Io::Closed) {
            Io::Tokio(socket) => socket.into_std(),
            other => {
                *io = other;
                return;
            }
        };
        let watched = socket.and_then(|socket| {
            let socket = Arc::new(socket);
            match watcher.watch(Arc::clone(&socket)) {
                Ok(watch) => Ok(Io::Watched { socket, watch }),
                Err(err) => {
                    tracing::debug!("[UDP] the reply writer could not watch the socket: {err}");
                    let socket = Arc::into_inner(socket).ok_or(err)?;
                    UdpSocket::from_std(socket).map(Io::Tokio)
                }
            }
        });
        match watched {
            Ok(watched) => *io = watched,
            Err(err) => {
                tracing::debug!("[UDP] closing a session whose socket was lost in a move: {err}");
                self.closed.store(true, Ordering::Relaxed);
            }
        }
        drop(io);
        self.sender.wake();
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::sync::atomic::Ordering;

    use concord_common::{SocketFactory, recv_packet, send_packet};
    use concord_platform::Platform;

    use super::*;
    use crate::Sockets;
    use crate::test_support::{FakePlatform, MapResolver, env, loopback_udp};

    async fn session_to(
        resolver: Arc<MapResolver>,
    ) -> (DirectPacketSession, Arc<FakePlatform>, UdpSocket) {
        let platform = Arc::new(FakePlatform::default());
        let sockets: Arc<dyn SocketFactory> =
            Arc::new(Sockets::new(Arc::clone(&platform) as Arc<dyn Platform>));
        let socket = sockets
            .bind_udp("127.0.0.1".parse().unwrap(), &SockOpts::default())
            .unwrap();
        let session = DirectPacketSession::new(
            socket,
            resolver as Arc<dyn HostResolver>,
            Initiator::Direct,
            IpVersion::Dual,
            true,
            Default::default(),
        );
        (session, platform, loopback_udp().await)
    }

    #[tokio::test]
    async fn packets_flow_both_ways_through_a_protected_socket() {
        let (session, platform, peer) = session_to(Arc::new(MapResolver::default())).await;
        let peer_addr = peer.local_addr().unwrap();
        assert_eq!(lock(&platform.protected).len(), 1);

        let mut packet = PacketBuf::from_slice(b"hello");
        send_packet(&session, &mut packet, &Address::Socket(peer_addr))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        peer.send_to(b"reply", from).await.unwrap();
        let (packet, source) = recv_packet(&session).await.unwrap();
        assert_eq!(packet.as_slice(), b"reply");
        assert_eq!(source, Address::Socket(peer_addr));
        assert_eq!(session.headroom(), 0);
    }

    #[tokio::test]
    async fn a_batch_leaves_in_order_as_separate_datagrams() {
        let (session, _platform, peer) = session_to(Arc::new(MapResolver::default())).await;
        let dst = peer.local_addr().unwrap();
        let payloads: [&[u8]; 4] = [b"one", b"two", b"three", b"4"];
        let batch: Vec<_> = payloads
            .iter()
            .map(|&payload| Datagram { payload, dst })
            .collect();

        let mut rest = batch.as_slice();
        while !rest.is_empty() {
            let sent = poll_fn(|cx| session.poll_send_batch(cx, rest))
                .await
                .unwrap();
            assert!(sent > 0);
            rest = &rest[sent..];
        }

        for payload in payloads {
            let mut buf = [0u8; 16];
            let (n, _) = peer.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], payload);
        }
    }

    #[tokio::test]
    async fn a_batch_that_starts_with_a_bad_destination_reports_it_first() {
        let (session, _platform, peer) = session_to(Arc::new(MapResolver::default())).await;
        let batch = [
            Datagram {
                payload: b"x",
                dst: "[2001:db8::1]:53".parse().unwrap(),
            },
            Datagram {
                payload: b"y",
                dst: peer.local_addr().unwrap(),
            },
        ];

        let err = poll_fn(|cx| session.poll_send_batch(cx, &batch))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let sent = poll_fn(|cx| session.poll_send_batch(cx, &batch[1..]))
            .await
            .unwrap();
        assert_eq!(sent, 1);
    }

    #[tokio::test]
    async fn a_domain_is_resolved_once_per_session() {
        let resolver = MapResolver::with("example.test", &["127.0.0.1"], &[]);
        let (session, _platform, peer) = session_to(Arc::clone(&resolver)).await;
        let port = peer.local_addr().unwrap().port();
        let dst = Address::Domain("example.test".into(), port);

        for round in 0..3u8 {
            let mut packet = PacketBuf::from_slice(&[round]);
            send_packet(&session, &mut packet, &dst).await.unwrap();
            let mut buf = [0u8; 4];
            let (n, _) = peer.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &[round]);
        }
        assert_eq!(resolver.lookups.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_failed_packet_does_not_poison_the_session() {
        let resolver = MapResolver::with("v6only.test", &[], &["2001:db8::1"]);
        let (session, _platform, peer) = session_to(Arc::clone(&resolver)).await;
        let peer_addr = peer.local_addr().unwrap();

        let mut packet = PacketBuf::from_slice(b"x");
        let v6 = Address::Socket("[2001:db8::1]:53".parse().unwrap());
        let err = send_packet(&session, &mut packet, &v6).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let err = send_packet(
            &session,
            &mut packet,
            &Address::Domain("v6only.test".into(), 53),
        )
        .await
        .unwrap_err();
        assert_eq!(
            CoreError::of(&err),
            Some(&CoreError::IpNotFound("v6only.test".into()))
        );
        let err = send_packet(
            &session,
            &mut packet,
            &Address::Domain("unknown.test".into(), 53),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unknown.test"));

        send_packet(&session, &mut packet, &Address::Socket(peer_addr))
            .await
            .unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(peer.recv_from(&mut buf).await.unwrap().0, 1);
    }

    #[tokio::test]
    async fn associate_picks_the_family_from_the_hint_and_tracks_the_port() {
        let platform = Arc::new(FakePlatform::default());
        let sockets: Arc<dyn SocketFactory> =
            Arc::new(Sockets::new(Arc::clone(&platform) as Arc<dyn Platform>));
        let resolver = MapResolver::with("example.test", &["127.0.0.1"], &[]);
        let env = env(sockets, resolver.clone(), false, true);
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let guard = LoopbackGuard::new(true);

        let hint = Address::Domain("example.test".into(), 53);
        let session = DirectPacketSession::associate(
            &cx,
            &hint,
            IpVersion::Dual,
            &SockOpts::default(),
            Some(&guard),
            &Default::default(),
        )
        .await
        .unwrap();
        let local = session.local_addr().unwrap();
        assert!(local.is_ipv4());
        let source: SocketAddr = format!("127.0.0.1:{}", local.port()).parse().unwrap();
        assert!(guard.check_udp_source(source, |_| false).is_err());

        let mut packet = PacketBuf::from_slice(b"x");
        let peer = loopback_udp().await;
        send_packet(
            &session,
            &mut packet,
            &Address::Domain("example.test".into(), peer.local_addr().unwrap().port()),
        )
        .await
        .unwrap();
        assert_eq!(resolver.lookups.load(Ordering::Relaxed), 1);

        session.close();
        let err = send_packet(
            &session,
            &mut packet,
            &Address::Socket(peer.local_addr().unwrap()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        drop(session);
        assert!(guard.check_udp_source(source, |_| false).is_ok());
    }

    #[cfg(target_os = "linux")]
    mod watched {
        use std::sync::atomic::AtomicUsize;
        use std::task::Wake;

        use concord_common::{SocketWatch, SocketWatcher};

        use super::*;

        /// Holds the socket as a poller's registration does, and asks for another poll
        /// after a read that found nothing.
        struct Watch {
            _socket: Arc<std::net::UdpSocket>,
            empty: AtomicBool,
            live: Arc<AtomicUsize>,
        }

        impl SocketWatch for Watch {
            fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.empty.swap(false, Ordering::SeqCst) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Ok(()))
            }

            fn try_read(&self, read: &mut dyn FnMut() -> io::Result<usize>) -> io::Result<usize> {
                let received = read();
                if matches!(&received, Err(err) if err.kind() == io::ErrorKind::WouldBlock) {
                    self.empty.store(true, Ordering::SeqCst);
                }
                received
            }
        }

        impl Drop for Watch {
            fn drop(&mut self) {
                self.live.fetch_sub(1, Ordering::SeqCst);
            }
        }

        #[derive(Default)]
        struct Watcher {
            live: Arc<AtomicUsize>,
            refuses: bool,
        }

        impl SocketWatcher for Watcher {
            fn watch(&self, socket: Arc<std::net::UdpSocket>) -> io::Result<Arc<dyn SocketWatch>> {
                if self.refuses {
                    return Err(io::Error::other("refused"));
                }
                self.live.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::new(Watch {
                    _socket: socket,
                    empty: AtomicBool::new(false),
                    live: Arc::clone(&self.live),
                }))
            }
        }

        struct Wakes(AtomicUsize);

        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        async fn round_trip(session: &DirectPacketSession, peer: &UdpSocket) {
            let dst = peer.local_addr().unwrap();
            let mut packet = PacketBuf::from_slice(b"single");
            send_packet(session, &mut packet, &Address::Socket(dst))
                .await
                .unwrap();
            let batch = [b"one".as_slice(), b"two"].map(|payload| Datagram { payload, dst });
            let sent = poll_fn(|cx| session.poll_send_batch(cx, &batch))
                .await
                .unwrap();
            assert_eq!(sent, 2);
            let mut from = None;
            for payload in [b"single".as_slice(), b"one", b"two"] {
                let mut buf = [0u8; 16];
                let (n, addr) = peer.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], payload);
                from = Some(addr);
            }

            peer.send_to(b"reply", from.unwrap()).await.unwrap();
            let (packet, source) = recv_packet(session).await.unwrap();
            assert_eq!(packet.as_slice(), b"reply");
            assert_eq!(source, Address::Socket(dst));
        }

        #[tokio::test]
        async fn a_watched_socket_sends_and_receives() {
            let (session, _platform, peer) = session_to(Arc::new(MapResolver::default())).await;
            let watcher = Watcher::default();
            let local = session.local_addr().unwrap();

            session.watch(&watcher);

            assert_eq!(watcher.live.load(Ordering::SeqCst), 1);
            assert_eq!(session.local_addr().unwrap(), local);
            round_trip(&session, &peer).await;
        }

        #[tokio::test]
        async fn a_second_watch_keeps_the_first() {
            let (session, _platform, peer) = session_to(Arc::new(MapResolver::default())).await;
            let watcher = Watcher::default();

            session.watch(&watcher);
            session.watch(&watcher);

            assert_eq!(watcher.live.load(Ordering::SeqCst), 1);
            round_trip(&session, &peer).await;
        }

        #[tokio::test]
        async fn a_refused_watch_leaves_the_socket_with_tokio() {
            let (session, _platform, peer) = session_to(Arc::new(MapResolver::default())).await;
            let watcher = Watcher {
                refuses: true,
                ..Watcher::default()
            };

            session.watch(&watcher);

            assert_eq!(watcher.live.load(Ordering::SeqCst), 0);
            assert!(matches!(&*session.io(), Io::Tokio(_)));
            round_trip(&session, &peer).await;
        }

        #[tokio::test]
        async fn a_socket_lost_in_the_move_closes_the_session() {
            #[derive(Default)]
            struct Keeps(Mutex<Option<Arc<std::net::UdpSocket>>>);

            impl SocketWatcher for Keeps {
                fn watch(
                    &self,
                    socket: Arc<std::net::UdpSocket>,
                ) -> io::Result<Arc<dyn SocketWatch>> {
                    *lock(&self.0) = Some(socket);
                    Err(io::Error::other("refused"))
                }
            }

            let (session, _platform, peer) = session_to(Arc::new(MapResolver::default())).await;

            session.watch(&Keeps::default());

            let mut packet = PacketBuf::from_slice(b"x");
            let dst = Address::Socket(peer.local_addr().unwrap());
            let err = send_packet(&session, &mut packet, &dst).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
            let err = recv_packet(&session).await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }

        #[tokio::test]
        async fn dropping_a_watched_session_ends_the_watch_and_closes_the_socket() {
            let (session, _platform, _peer) = session_to(Arc::new(MapResolver::default())).await;
            let watcher = Watcher::default();
            session.watch(&watcher);
            let local = session.local_addr().unwrap();
            assert!(!is_free(local));

            drop(session);

            assert_eq!(watcher.live.load(Ordering::SeqCst), 0);
            assert!(is_free(local));
        }

        #[allow(
            clippy::disallowed_methods,
            reason = "binding the session's address shows whether its socket is closed"
        )]
        fn is_free(local: SocketAddr) -> bool {
            std::net::UdpSocket::bind(local).is_ok()
        }

        #[tokio::test]
        async fn a_sender_waiting_on_tokio_is_woken_when_the_socket_moves() {
            let (session, _platform, _peer) = session_to(Arc::new(MapResolver::default())).await;
            let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&wakes));
            let waited = session.waiting(&Context::from_waker(&waker), Poll::<()>::Pending);
            assert!(waited.is_pending());

            session.watch(&Watcher::default());

            assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn a_full_watched_socket_drops_what_it_was_offered_and_counts_it() {
            let (session, _platform, _peer) = session_to(Arc::new(MapResolver::default())).await;

            let full = session.or_dropped(Err(io::ErrorKind::WouldBlock.into()), 3);
            assert_eq!(full.unwrap(), 3);
            assert_eq!(session.dropped.load(Ordering::Relaxed), 3);

            assert_eq!(session.or_dropped(Ok(2), 3).unwrap(), 2);
            let refused = session.or_dropped(Err(io::ErrorKind::ConnectionRefused.into()), 3);
            assert_eq!(
                refused.unwrap_err().kind(),
                io::ErrorKind::ConnectionRefused
            );
            assert_eq!(session.dropped.load(Ordering::Relaxed), 3);
        }
    }
}
