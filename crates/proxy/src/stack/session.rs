use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use concord_common::sync::lock;
use concord_common::{Address, PacketBuf, PacketSession};

use super::UdpPort;

type Lookup = Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send>>;

struct Resolving {
    host: String,
    lookup: Lookup,
}

/// What a tunnel over the userspace stack lends each UDP session it carries.
pub(crate) trait SessionTunnel: Send + Sync + 'static {
    fn resolve(&self, host: String) -> impl Future<Output = io::Result<IpAddr>> + Send + 'static;

    fn usable(&self) -> bool;
}

/// UDP through the tunnel. A destination given by name is resolved once per name,
/// the way Go resolves it before it hands the packet to the tunnel.
pub(crate) struct StackSession<T> {
    port: UdpPort,
    tunnel: T,
    names: Mutex<HashMap<String, IpAddr>>,
    pending: Mutex<Option<Resolving>>,
    closed: AtomicBool,
}

impl<T: SessionTunnel> StackSession<T> {
    pub(crate) fn new(port: UdpPort, tunnel: T) -> Self {
        StackSession {
            port,
            tunnel,
            names: Mutex::new(HashMap::new()),
            pending: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) async fn seed(&self, host: &str) -> io::Result<()> {
        let ip = self.tunnel.resolve(host.to_string()).await?;
        lock(&self.names).insert(host.to_string(), ip);
        Ok(())
    }

    fn poll_target(&self, cx: &mut Context<'_>, dst: &Address) -> Poll<io::Result<SocketAddr>> {
        let (host, port) = match dst {
            Address::Socket(addr) => return Poll::Ready(Ok(*addr)),
            Address::Domain(host, port) => (host.as_str(), *port),
        };
        if let Some(ip) = lock(&self.names).get(host) {
            return Poll::Ready(Ok(SocketAddr::new(*ip, port)));
        }
        let mut pending = lock(&self.pending);
        if pending.as_ref().is_none_or(|current| current.host != host) {
            *pending = Some(Resolving {
                host: host.to_string(),
                lookup: Box::pin(self.tunnel.resolve(host.to_string())),
            });
        }
        let Some(current) = pending.as_mut() else {
            return Poll::Pending;
        };
        let result = ready!(current.lookup.as_mut().poll(cx));
        *pending = None;
        let ip = result?;
        lock(&self.names).insert(host.to_string(), ip);
        Poll::Ready(Ok(SocketAddr::new(ip, port)))
    }

    fn broken(&self) -> bool {
        self.closed.load(Ordering::Relaxed) || !self.tunnel.usable()
    }
}

impl<T: SessionTunnel> PacketSession for StackSession<T> {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.broken() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let target = ready!(self.poll_target(cx, dst))?;
        self.port.poll_send_to(cx, pkt.as_slice(), target)
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        if self.broken() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let (n, from) = ready!(self.port.poll_recv_from(cx, buf.spare_mut()))?;
        buf.advance(n);
        Poll::Ready(Ok(Address::from(from)))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.port.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "tests drive a loopback stack and assert on fixed shapes"
    )]

    use std::future::poll_fn;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::task::Waker;
    use std::time::Duration;

    use gotatun::packet::PacketBufPool;
    use gotatun::tun::{IpRecv, IpSend};
    use tokio::sync::Notify;
    use tokio::time::timeout;

    use super::super::{Stack, StackConfig};
    use super::*;

    const ADDR: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
    const ECHO: u16 = 7001;
    const NAME: &str = "echo.test";

    #[derive(Default)]
    struct Probe {
        lookups: AtomicUsize,
        unusable: AtomicBool,
        gate: Option<Notify>,
    }

    struct Fake(Arc<Probe>);

    impl SessionTunnel for Fake {
        fn resolve(
            &self,
            _host: String,
        ) -> impl Future<Output = io::Result<IpAddr>> + Send + 'static {
            self.0.lookups.fetch_add(1, Ordering::Relaxed);
            let probe = self.0.clone();
            async move {
                if let Some(gate) = &probe.gate {
                    gate.notified().await;
                }
                Ok(IpAddr::V4(ADDR))
            }
        }

        fn usable(&self) -> bool {
            !self.0.unusable.load(Ordering::Relaxed)
        }
    }

    /// A stack whose outgoing packets come straight back in, with a UDP echo on its own address.
    fn looped() -> Arc<Stack> {
        let wired = Stack::start(
            &StackConfig {
                addrs: vec![ADDR.into()],
                mtu: 1400,
            },
            &Default::default(),
        );
        wired.stack.serve_udp(ECHO, |data| Some(data.to_vec()));
        let (mut send, mut recv) = (wired.send, wired.recv);
        tokio::spawn(async move {
            let mut pool = PacketBufPool::new(0);
            while let Ok(packets) = recv.recv(&mut pool).await {
                let packets: Vec<_> = packets.collect();
                for packet in packets {
                    if send.send(packet).await.is_err() {
                        return;
                    }
                }
            }
        });
        wired.stack
    }

    fn session(stack: &Arc<Stack>, probe: &Arc<Probe>) -> StackSession<Fake> {
        StackSession::new(stack.bind_udp().unwrap(), Fake(probe.clone()))
    }

    async fn send<T: SessionTunnel>(
        session: &StackSession<T>,
        data: &[u8],
        dst: &Address,
    ) -> io::Result<()> {
        let mut pkt = PacketBuf::from_slice(data);
        poll_fn(|cx| session.poll_send(cx, &mut pkt, dst)).await
    }

    async fn recv<T: SessionTunnel>(session: &StackSession<T>) -> io::Result<(Vec<u8>, Address)> {
        let mut buf = PacketBuf::take();
        let from = timeout(
            Duration::from_secs(5),
            poll_fn(|cx| session.poll_recv(cx, &mut buf)),
        )
        .await
        .unwrap()?;
        Ok((buf.as_slice().to_vec(), from))
    }

    fn echo() -> SocketAddr {
        SocketAddr::new(ADDR.into(), ECHO)
    }

    #[tokio::test]
    async fn a_socket_address_goes_out_without_a_lookup() {
        let stack = looped();
        let probe = Arc::new(Probe::default());
        let session = session(&stack, &probe);
        send(&session, b"ping", &Address::Socket(echo()))
            .await
            .unwrap();
        let (data, from) = recv(&session).await.unwrap();
        assert_eq!(data, b"ping");
        assert_eq!(from, Address::Socket(echo()));
        assert_eq!(probe.lookups.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_name_is_resolved_once_and_kept() {
        let stack = looped();
        let probe = Arc::new(Probe::default());
        let session = session(&stack, &probe);
        session.seed(NAME).await.unwrap();
        let dst = Address::Domain(NAME.into(), ECHO);
        for round in 0..3u8 {
            send(&session, &[round], &dst).await.unwrap();
            let (data, from) = recv(&session).await.unwrap();
            assert_eq!(data, [round]);
            assert_eq!(from, Address::Socket(echo()));
        }
        assert_eq!(probe.lookups.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn sends_waiting_on_one_name_share_its_lookup() {
        let stack = looped();
        let probe = Arc::new(Probe {
            gate: Some(Notify::new()),
            ..Probe::default()
        });
        let session = session(&stack, &probe);
        let dst = Address::Domain(NAME.into(), ECHO);
        let mut cx = Context::from_waker(Waker::noop());
        let mut pkt = PacketBuf::from_slice(b"held");
        assert!(session.poll_send(&mut cx, &mut pkt, &dst).is_pending());
        assert!(session.poll_send(&mut cx, &mut pkt, &dst).is_pending());
        assert_eq!(probe.lookups.load(Ordering::Relaxed), 1);
        probe.gate.as_ref().unwrap().notify_one();
        send(&session, b"held", &dst).await.unwrap();
        assert_eq!(recv(&session).await.unwrap().0, b"held");
        assert_eq!(probe.lookups.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_closed_session_refuses_both_ways() {
        let stack = looped();
        let probe = Arc::new(Probe::default());
        let session = session(&stack, &probe);
        session.close();
        let err = send(&session, b"x", &Address::Socket(echo()))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let err = recv(&session).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn closing_a_session_wakes_a_parked_receive() {
        let stack = looped();
        let probe = Arc::new(Probe::default());
        let session = Arc::new(session(&stack, &probe));
        let parked = tokio::spawn({
            let session = session.clone();
            async move {
                let mut buf = PacketBuf::take();
                poll_fn(|cx| session.poll_recv(cx, &mut buf)).await
            }
        });
        tokio::task::yield_now().await;
        assert!(!parked.is_finished());
        session.close();
        let err = timeout(Duration::from_secs(5), parked)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn a_stopped_stack_wakes_a_parked_receive() {
        let wired = Stack::start(
            &StackConfig {
                addrs: vec![ADDR.into()],
                mtu: 1400,
            },
            &Default::default(),
        );
        let probe = Arc::new(Probe::default());
        let session = Arc::new(session(&wired.stack, &probe));
        let parked = tokio::spawn({
            let session = session.clone();
            async move {
                let mut buf = PacketBuf::take();
                poll_fn(|cx| session.poll_recv(cx, &mut buf)).await
            }
        });
        tokio::task::yield_now().await;
        assert!(!parked.is_finished());
        probe.unusable.store(true, Ordering::Relaxed);
        wired.driver.abort();
        let err = timeout(Duration::from_secs(5), parked)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn an_unusable_tunnel_breaks_the_session() {
        let stack = looped();
        let probe = Arc::new(Probe::default());
        let session = session(&stack, &probe);
        probe.unusable.store(true, Ordering::Relaxed);
        let err = send(&session, b"x", &Address::Socket(echo()))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let err = recv(&session).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
