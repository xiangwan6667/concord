use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{CoreError, SockOpts, SocketFactory, io_error, ip4p_target};
use concord_platform::{
    IcmpSocket, Platform, bind_to_interface, enable_tfo, grow_udp_buffers, icmp_echo_socket,
    is_global_unicast, mptcp_protocol, prepare_udp_socket, raw_socket_of, set_routing_mark,
};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::held::Held;

const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(15);

/// The one place an outbound socket is created, so no path can skip the
/// descriptor-pressure gate, `protect`, or the interface binding. A socket the platform cannot
/// protect yet is held until `protect_held`.
pub struct Sockets {
    platform: Arc<dyn Platform>,
    held: Arc<Held>,
    auto_detect_interface: AtomicBool,
    ip4p: AtomicBool,
}

fn domain_of(ip: IpAddr) -> Domain {
    match ip {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    }
}

fn keep_alive(secs: u32) -> Duration {
    if secs == 0 {
        DEFAULT_KEEP_ALIVE
    } else {
        Duration::from_secs(u64::from(secs))
    }
}

impl Sockets {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        Sockets {
            platform,
            held: Arc::default(),
            auto_detect_interface: AtomicBool::new(false),
            ip4p: AtomicBool::new(false),
        }
    }

    pub fn platform(&self) -> &Arc<dyn Platform> {
        &self.platform
    }

    pub fn set_auto_detect_interface(&self, enabled: bool) {
        self.auto_detect_interface.store(enabled, Ordering::Relaxed);
    }

    pub fn auto_detect_interface(&self) -> bool {
        self.auto_detect_interface.load(Ordering::Relaxed)
    }

    pub fn set_ip4p(&self, enabled: bool) {
        self.ip4p.store(enabled, Ordering::Relaxed);
    }

    /// Protects every socket created while the host's VPN was not established, or refused, and
    /// still open. Called once the VPN is.
    pub async fn protect_held(&self) {
        let (held, platform) = (Arc::clone(&self.held), Arc::clone(&self.platform));
        if let Err(err) = tokio::task::spawn_blocking(move || held.activate(&*platform)).await {
            tracing::warn!("protect: held sockets task failed: {err}");
        }
    }

    /// Sends one ICMP echo request to `dst` from a direct socket and waits for its reply. The
    /// request is `message`: an ICMP echo request without its IP header.
    pub async fn ping(
        &self,
        dst: IpAddr,
        message: &[u8],
        opts: &SockOpts,
        wait: Duration,
    ) -> io::Result<()> {
        let echo = EchoRequest::parse(message, dst.is_ipv6())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.check_pressure()?;
        let protocol = if dst.is_ipv6() {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        };
        let IcmpSocket {
            socket,
            keeps_identifier,
        } = icmp_echo_socket(domain_of(dst), protocol)?;
        self.route(&socket, opts, dst)?;
        let any = match dst {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        socket.bind(&any.into())?;
        socket.connect(&SocketAddr::new(dst, 0).into())?;
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket.into())?;
        socket.send(message).await?;
        let mut buf = [0u8; 2048];
        tokio::time::timeout(wait, async {
            loop {
                let len = socket.recv(&mut buf).await?;
                if buf
                    .get(..len)
                    .is_some_and(|reply| echo.is_answered_by(reply, keeps_identifier))
                {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    fn check_pressure(&self) -> io::Result<()> {
        if self.platform.fd_pressure() {
            return Err(CoreError::FdPressure.into());
        }
        Ok(())
    }

    fn resolve_interface(
        &self,
        opts: &SockOpts,
        dest: IpAddr,
    ) -> io::Result<Option<(Arc<str>, u32)>> {
        if !is_global_unicast(dest) {
            return Ok(None);
        }
        match opts.interface.as_ref().filter(|name| !name.is_empty()) {
            Some(name) => {
                let info = self
                    .platform
                    .interface_by_name(name)
                    .ok_or_else(|| io_error(format!("interface {name} not found")))?;
                Ok(Some((Arc::clone(name), info.index)))
            }
            // mihomo fails the dial too: an unbound socket would follow the TUN's routes.
            None if self.auto_detect_interface() => self
                .platform
                .interface_for(dest)
                .map(|info| Some((info.name, info.index)))
                .ok_or_else(|| io_error(format!("no interface outside TUN reaches {dest}"))),
            None => Ok(None),
        }
    }

    fn route(&self, socket: &Socket, opts: &SockOpts, dest: IpAddr) -> io::Result<()> {
        self.held.guard(&*self.platform, raw_socket_of(socket));
        if let Some((name, index)) = self.resolve_interface(opts, dest)? {
            bind_to_interface(socket, &name, index, dest.is_ipv6())?;
        }
        if let Some(mark) = opts.routing_mark.filter(|mark| *mark != 0)
            && is_global_unicast(dest)
        {
            set_routing_mark(socket, mark)?;
        }
        Ok(())
    }

    fn new_tcp_socket(opts: &SockOpts, domain: Domain) -> io::Result<Socket> {
        if opts.mptcp
            && let Some(protocol) = mptcp_protocol()
            && let Ok(socket) = Socket::new(domain, Type::STREAM, Some(protocol))
        {
            return Ok(socket);
        }
        Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
    }

    fn configure_tcp(socket: &Socket, opts: &SockOpts) -> io::Result<()> {
        socket.set_tcp_nodelay(true)?;
        if opts.disable_keep_alive {
            socket.set_keepalive(false)?;
        } else {
            let params = TcpKeepalive::new()
                .with_time(keep_alive(opts.keep_alive_idle_secs))
                .with_interval(keep_alive(opts.keep_alive_interval_secs));
            socket.set_tcp_keepalive(&params)?;
        }
        if opts.tfo
            && let Err(err) = enable_tfo(socket)
        {
            tracing::debug!("TCP Fast Open is not available: {err}");
        }
        Ok(())
    }
}

struct EchoRequest {
    v6: bool,
    identifier: u16,
    sequence: u16,
}

impl EchoRequest {
    fn parse(message: &[u8], v6: bool) -> Option<Self> {
        let [kind, 0, _, _, id0, id1, seq0, seq1, ..] = *message else {
            return None;
        };
        (kind == if v6 { 128 } else { 8 }).then_some(EchoRequest {
            v6,
            identifier: u16::from_be_bytes([id0, id1]),
            sequence: u16::from_be_bytes([seq0, seq1]),
        })
    }

    /// An IPv4 reply may arrive with its IP header, as on macOS or from a raw socket.
    fn is_answered_by(&self, reply: &[u8], identifier_kept: bool) -> bool {
        let message = match reply.first() {
            Some(first) if !self.v6 && first >> 4 == 4 => {
                reply.get(usize::from(first & 0x0f) * 4..)
            }
            _ => Some(reply),
        };
        let Some(&[kind, 0, _, _, id0, id1, seq0, seq1, ..]) = message else {
            return false;
        };
        kind == if self.v6 { 129 } else { 0 }
            && u16::from_be_bytes([seq0, seq1]) == self.sequence
            && (!identifier_kept || u16::from_be_bytes([id0, id1]) == self.identifier)
    }
}

#[async_trait]
impl SocketFactory for Sockets {
    async fn connect_tcp(&self, target: SocketAddr, opts: &SockOpts) -> io::Result<TcpStream> {
        let target = self.ip4p(target);
        self.check_pressure()?;
        let socket = Self::new_tcp_socket(opts, domain_of(target.ip()))?;
        self.route(&socket, opts, target.ip())?;
        Self::configure_tcp(&socket, opts)?;
        socket.set_nonblocking(true)?;
        TcpSocket::from_std_stream(socket.into())
            .connect(target)
            .await
    }

    fn bind_udp(&self, peer: IpAddr, opts: &SockOpts) -> io::Result<UdpSocket> {
        self.check_pressure()?;
        let socket = Socket::new(domain_of(peer), Type::DGRAM, Some(Protocol::UDP))?;
        self.route(&socket, opts, peer)?;
        prepare_udp_socket(&socket)?;
        if opts.tunnel_udp_buffers {
            grow_udp_buffers(&socket);
        }
        let any = match peer {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        socket.bind(&any.into())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }

    fn ip4p(&self, addr: SocketAddr) -> SocketAddr {
        if !self.ip4p.load(Ordering::Relaxed) {
            return addr;
        }
        match ip4p_target(addr) {
            Some(converted) => {
                tracing::debug!("Convert IP4P address {} to {converted}", addr.ip());
                converted
            }
            None => addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::*;

    use crate::test_support::{FakePlatform, loopback_listener};
    use concord_common::sync::lock;

    fn sockets(platform: &Arc<FakePlatform>) -> Sockets {
        Sockets::new(Arc::clone(platform) as Arc<dyn Platform>)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn protect_runs_once_and_before_the_connection_exists() {
        let platform = Arc::new(FakePlatform::default());
        platform.protect_delay_ms.store(150, Ordering::Relaxed);
        let (listener, addr) = loopback_listener().await;
        let accepted = tokio::spawn({
            let platform = Arc::clone(&platform);
            async move {
                listener.accept().await.unwrap();
                lock(&platform.protected).len()
            }
        });

        let stream = sockets(&platform)
            .connect_tcp(addr, &SockOpts::default())
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), addr);
        assert_eq!(
            accepted.await.unwrap(),
            1,
            "the peer saw the connection before protect finished"
        );
        assert_eq!(lock(&platform.protected).len(), 1);
    }

    fn ip4p_of(addr: SocketAddr) -> SocketAddr {
        let IpAddr::V4(v4) = addr.ip() else {
            unreachable!("loopback listeners are IPv4")
        };
        let [a, b, c, d] = v4.octets();
        let [p0, p1] = addr.port().to_be_bytes();
        let octets = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, p0, p1, a, b, c, d];
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), 9)
    }

    #[tokio::test]
    async fn an_ip4p_target_is_converted_only_when_enabled() {
        let platform = Arc::new(FakePlatform::default());
        let factory = sockets(&platform);
        let (listener, addr) = loopback_listener().await;
        let record = ip4p_of(addr);

        assert_eq!(factory.ip4p(record), record);
        factory.set_ip4p(true);
        assert_eq!(factory.ip4p(record), addr);
        assert_eq!(
            factory.ip4p("[2001:db8::1]:9".parse().unwrap()),
            "[2001:db8::1]:9".parse().unwrap()
        );

        let opts = SockOpts::default();
        let (stream, accepted) =
            tokio::join!(factory.connect_tcp(record, &opts), listener.accept());
        assert_eq!(stream.unwrap().peer_addr().unwrap(), addr);
        accepted.unwrap();
    }

    #[cfg(any(unix, windows))]
    fn echo_request(kind: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut message = vec![kind, 0, 0, 0];
        message.extend_from_slice(&id.to_be_bytes());
        message.extend_from_slice(&seq.to_be_bytes());
        message.extend_from_slice(b"concord");
        let mut sum: u32 = message
            .chunks(2)
            .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let checksum = (!sum as u16).to_be_bytes();
        if kind == 8 {
            message[2..4].copy_from_slice(&checksum);
        }
        message
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn a_loopback_ping_is_answered() {
        let platform = Arc::new(FakePlatform::default());
        let factory = sockets(&platform);
        let wait = Duration::from_secs(5);
        let mut answered = false;
        let kinds = [("127.0.0.1", 8), ("::1", 128)];
        for (host, kind) in kinds {
            let request = echo_request(kind, 0x1234, 7);
            match factory
                .ping(host.parse().unwrap(), &request, &SockOpts::default(), wait)
                .await
            {
                Ok(()) => answered = true,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::PermissionDenied
                            | io::ErrorKind::AddrNotAvailable
                            | io::ErrorKind::Unsupported
                    ) => {}
                Err(err) => panic!("{host}: {err}"),
            }
        }
        assert!(!answered || !lock(&platform.protected).is_empty());
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn a_well_formed_request_to_a_silent_destination_is_not_invalid() {
        let platform = Arc::new(FakePlatform::default());
        // A TUN on the machine running the test may answer for any address.
        let result = sockets(&platform)
            .ping(
                "192.0.2.1".parse().unwrap(),
                &echo_request(8, 0x1234, 7),
                &SockOpts::default(),
                Duration::from_millis(1500),
            )
            .await;
        if let Err(err) = result {
            assert!(!matches!(err.kind(), io::ErrorKind::InvalidInput));
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn a_reply_must_answer_this_request() {
        let v4 = EchoRequest::parse(&echo_request(8, 9, 3), false).unwrap();
        let reply = [0u8, 0, 0, 0, 0, 9, 0, 3, 1];
        assert!(v4.is_answered_by(&reply, true));
        let mut other_seq = reply;
        other_seq[7] = 4;
        assert!(!v4.is_answered_by(&other_seq, true));
        let mut other_id = reply;
        other_id[5] = 8;
        assert!(!v4.is_answered_by(&other_id, true));
        assert!(v4.is_answered_by(&other_id, false));
        let mut with_header = vec![0x45u8, 0, 0, 29, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1];
        with_header.extend_from_slice(&[127, 0, 0, 1]);
        with_header.extend_from_slice(&reply);
        assert!(v4.is_answered_by(&with_header, true));
        let request_itself = echo_request(8, 9, 3);
        assert!(!v4.is_answered_by(&request_itself, true));
        assert!(EchoRequest::parse(&echo_request(128, 9, 3), false).is_none());
        assert!(EchoRequest::parse(&[8, 0, 0], false).is_none());
    }

    #[tokio::test]
    async fn udp_sockets_are_protected_and_family_matched() {
        let platform = Arc::new(FakePlatform::default());
        let factory = sockets(&platform);
        let v4 = factory
            .bind_udp("203.0.113.1".parse().unwrap(), &SockOpts::default())
            .unwrap();
        assert!(v4.local_addr().unwrap().is_ipv4());
        if let Ok(v6) = factory.bind_udp("2001:db8::1".parse().unwrap(), &SockOpts::default()) {
            assert!(v6.local_addr().unwrap().is_ipv6());
        }
        assert!(!lock(&platform.protected).is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_socket_refused_before_the_vpn_is_protected_when_it_comes_up() {
        let platform = Arc::new(FakePlatform::default());
        platform.refuse.store(true, Ordering::SeqCst);
        let factory = sockets(&platform);
        let socket = factory
            .bind_udp("203.0.113.1".parse().unwrap(), &SockOpts::default())
            .unwrap();
        assert!(lock(&platform.protected).is_empty());

        platform.refuse.store(false, Ordering::SeqCst);
        factory.protect_held().await;
        let inode = concord_platform::SocketIdentity::Inode.of(raw_socket_of(&socket));
        assert_eq!(*lock(&platform.protected_inodes), [inode]);
        factory.protect_held().await;
        assert_eq!(lock(&platform.protected).len(), 1);
    }

    #[tokio::test]
    async fn fd_pressure_refuses_before_a_socket_exists() {
        let platform = Arc::new(FakePlatform::default());
        platform.pressure.store(true, Ordering::Relaxed);
        let factory = sockets(&platform);
        let (_listener, addr) = loopback_listener().await;

        let err = factory
            .connect_tcp(addr, &SockOpts::default())
            .await
            .unwrap_err();
        assert_eq!(CoreError::of(&err), Some(&CoreError::FdPressure));
        let err = factory
            .bind_udp(addr.ip(), &SockOpts::default())
            .unwrap_err();
        assert_eq!(CoreError::of(&err), Some(&CoreError::FdPressure));
        assert!(lock(&platform.protected).is_empty());

        platform.pressure.store(false, Ordering::Relaxed);
        factory
            .connect_tcp(addr, &SockOpts::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_default_interface_is_bound_only_when_auto_detect_is_on() {
        let platform = Arc::new(FakePlatform::default());
        let factory = sockets(&platform);
        let (_listener, addr) = loopback_listener().await;
        assert!(
            factory
                .resolve_interface(&SockOpts::default(), "8.8.8.8".parse().unwrap())
                .unwrap()
                .is_none()
        );

        *lock(&platform.default_if) = Some(concord_platform::InterfaceInfo {
            name: "en9".into(),
            index: 9,
            addrs: vec![],
        });
        assert!(
            factory
                .resolve_interface(&SockOpts::default(), "8.8.8.8".parse().unwrap())
                .unwrap()
                .is_none()
        );
        factory.set_auto_detect_interface(true);
        *lock(&platform.default_if) = None;
        assert!(
            factory
                .resolve_interface(&SockOpts::default(), "8.8.8.8".parse().unwrap())
                .is_err()
        );
        *lock(&platform.default_if) = Some(concord_platform::InterfaceInfo {
            name: "en9".into(),
            index: 9,
            addrs: vec![],
        });
        let found = factory
            .resolve_interface(&SockOpts::default(), "8.8.8.8".parse().unwrap())
            .unwrap();
        assert_eq!(found, Some(("en9".into(), 9)));
        assert!(
            factory
                .resolve_interface(&SockOpts::default(), addr.ip())
                .unwrap()
                .is_none()
        );

        let opts = SockOpts {
            interface: Some("no-such-if0".into()),
            ..SockOpts::default()
        };
        assert!(
            factory
                .resolve_interface(&opts, "8.8.8.8".parse().unwrap())
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    #[tokio::test]
    async fn tcp_options_apply_to_a_real_connection() {
        let platform = Arc::new(FakePlatform::default());
        let (_listener, addr) = loopback_listener().await;
        let opts = SockOpts {
            keep_alive_idle_secs: 30,
            keep_alive_interval_secs: 10,
            tfo: true,
            mptcp: true,
            routing_mark: Some(0),
            ..SockOpts::default()
        };
        let stream = sockets(&platform).connect_tcp(addr, &opts).await.unwrap();
        assert!(stream.nodelay().unwrap());
        let quiet = SockOpts {
            disable_keep_alive: true,
            ..SockOpts::default()
        };
        sockets(&platform).connect_tcp(addr, &quiet).await.unwrap();
    }
}
