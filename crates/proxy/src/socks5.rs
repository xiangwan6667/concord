use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Initiator, IpVersion, Outbound, OutboundInfo, OutboundKind,
    PacketBuf, PacketSession,
};
use concord_config::proxy::{ProxyDef, Socks5Opts};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::addr_codec::SOCKS;
use crate::ctx::{BuildCtx, BuildError};
use crate::link::simple_link;
use crate::node::{Link, info_for};
use crate::udprelay::{UdpCodec, UdpRelay, Watch};

const VERSION: u8 = 5;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const AUTH_NONE: u8 = 0;
const AUTH_PASSWORD: u8 = 2;

fn fail(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

pub(crate) async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    command: u8,
    target: &Address,
    user: Option<(&str, &str)>,
) -> io::Result<Address> {
    let methods: &[u8] = if user.is_some() {
        &[VERSION, 2, AUTH_NONE, AUTH_PASSWORD]
    } else {
        &[VERSION, 1, AUTH_NONE]
    };
    io.write_all(methods).await?;
    let mut choice = [0u8; 2];
    io.read_exact(&mut choice).await?;
    if choice[0] != VERSION {
        return Err(fail("SOCKS version error"));
    }
    match (choice[1], user) {
        (AUTH_NONE, _) => {}
        (AUTH_PASSWORD, Some((name, pass))) => {
            let (name, pass) = (name.as_bytes(), pass.as_bytes());
            let name_len = u8::try_from(name.len()).map_err(|_| fail("username too long"))?;
            let pass_len = u8::try_from(pass.len()).map_err(|_| fail("password too long"))?;
            let mut auth = vec![1, name_len];
            auth.extend_from_slice(name);
            auth.push(pass_len);
            auth.extend_from_slice(pass);
            io.write_all(&auth).await?;
            let mut reply = [0u8; 2];
            io.read_exact(&mut reply).await?;
            if reply[1] != 0 {
                return Err(fail("SOCKS5 authentication failed"));
            }
        }
        _ => return Err(fail("SOCKS5 no acceptable authentication method")),
    }
    let mut request = vec![VERSION, command, 0];
    SOCKS.write(target, &mut request)?;
    io.write_all(&request).await?;
    let mut reply = [0u8; 3];
    io.read_exact(&mut reply).await?;
    if reply[0] != VERSION {
        return Err(fail("SOCKS version error"));
    }
    if reply[1] != 0 {
        return Err(fail(format!(
            "SOCKS5 request failed, reply code {}",
            reply[1]
        )));
    }
    SOCKS.read(io).await
}

struct Socks5 {
    info: OutboundInfo,
    link: Link,
    auth: Option<(String, String)>,
}

impl Socks5 {
    fn user(&self) -> Option<(&str, &str)> {
        self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()))
    }
}

#[async_trait]
impl Outbound for Socks5 {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let mut stream = self.link.open(cx).await?;
        client_handshake(&mut stream, CMD_CONNECT, dst, self.user()).await?;
        Ok(stream)
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let mut control = self.link.open(cx).await?;
        let unspecified = Address::Socket(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
        let bound = client_handshake(&mut control, CMD_UDP_ASSOCIATE, &unspecified, self.user())
            .await
            .map_err(|err| fail(format!("client handshake error: {err}")))?;
        let Address::Socket(mut relay) = bound else {
            return Err(fail("invalid UDP bind address"));
        };
        if relay.ip().is_unspecified() {
            relay.set_ip(self.server_ip(cx, control.peer_addr()).await?);
        }
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        let task = self.link.tasks().spawn(async move {
            let mut sink = [0u8; 256];
            while matches!(control.read(&mut sink).await, Ok(n) if n > 0) {}
            flag.store(true, Ordering::Relaxed);
        });
        let watch = Watch::new(closed, task);
        let session = UdpRelay::open(&self.link.egress, cx, relay, Socks5Udp, Some(watch)).await?;
        Ok(Arc::new(session))
    }
}

impl Socks5 {
    async fn server_ip(&self, cx: &DialCx<'_>, peer: Option<SocketAddr>) -> io::Result<IpAddr> {
        if let Some(peer) = peer.filter(|_| !self.link.egress.is_via()) {
            return Ok(peer.ip());
        }
        match &self.link.server {
            Address::Socket(addr) => Ok(addr.ip()),
            Address::Domain(host, _) => {
                let found = cx
                    .env
                    .resolver
                    .lookup(host, IpVersion::Ipv4Prefer, Initiator::Proxy)
                    .await?;
                found
                    .first(IpVersion::Ipv4Prefer)
                    .ok_or_else(|| concord_common::CoreError::IpNotFound(host.to_string()).into())
            }
        }
    }
}

struct Socks5Udp;

impl UdpCodec for Socks5Udp {
    fn headroom(&self) -> usize {
        3 + crate::addr_codec::MAX_ADDR_LEN
    }

    fn seal(&self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        let len = 3 + SOCKS.len(dst);
        let head = pkt.prepend(len);
        head.get_mut(..3)
            .ok_or_else(|| fail("short header"))?
            .fill(0);
        SOCKS.write_into(dst, head.get_mut(3..).unwrap_or_default())?;
        Ok(())
    }

    fn open(&self, pkt: &mut PacketBuf) -> io::Result<Address> {
        let data = pkt.as_slice();
        if data.len() < 5 {
            return Err(fail("short socks5 udp packet"));
        }
        if data.get(2) != Some(&0) {
            return Err(fail("discarding fragmented payload"));
        }
        let (addr, used) = SOCKS
            .parse(data.get(3..).unwrap_or_default())?
            .ok_or_else(|| fail("short socks5 udp packet"))?;
        pkt.consume(3 + used);
        Ok(addr)
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &Socks5Opts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let mut tls = opts.tls.clone();
    if tls.server_name.is_empty() {
        tls.server_name.clone_from(&opts.server);
    }
    let link = simple_link(def, &opts.server, opts.port, &tls, ctx)?;
    let auth = (!opts.username.is_empty()).then(|| (opts.username.clone(), opts.password.clone()));
    Ok(Arc::new(Socks5 {
        info: info_for(
            def,
            OutboundKind::Socks5,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        auth,
    }))
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    async fn fake_server(mut io: tokio::io::DuplexStream, expect_auth: bool) -> Vec<u8> {
        let mut head = [0u8; 2];
        io.read_exact(&mut head).await.unwrap();
        let mut methods = vec![0u8; usize::from(head[1])];
        io.read_exact(&mut methods).await.unwrap();
        if expect_auth {
            assert_eq!(methods, [0, 2]);
            io.write_all(&[5, 2]).await.unwrap();
            let mut ver_len = [0u8; 2];
            io.read_exact(&mut ver_len).await.unwrap();
            let mut name = vec![0u8; usize::from(ver_len[1])];
            io.read_exact(&mut name).await.unwrap();
            let mut plen = [0u8; 1];
            io.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; usize::from(plen[0])];
            io.read_exact(&mut pass).await.unwrap();
            assert_eq!((&name[..], &pass[..]), (&b"user"[..], &b"pw"[..]));
            io.write_all(&[1, 0]).await.unwrap();
        } else {
            assert_eq!(methods, [0]);
            io.write_all(&[5, 0]).await.unwrap();
        }
        let mut req = [0u8; 3];
        io.read_exact(&mut req).await.unwrap();
        let addr = SOCKS.read(&mut io).await.unwrap();
        io.write_all(&[5, 0, 0, 1, 10, 0, 0, 1, 0x1f, 0x90])
            .await
            .unwrap();
        assert_eq!(addr, Address::new("example.com", 443));
        req.to_vec()
    }

    #[tokio::test]
    async fn connect_without_auth() {
        let (mut near, far) = duplex(1024);
        let server = tokio::spawn(fake_server(far, false));
        let bound = client_handshake(
            &mut near,
            CMD_CONNECT,
            &Address::new("example.com", 443),
            None,
        )
        .await
        .unwrap();
        assert_eq!(bound, Address::new("10.0.0.1", 8080));
        assert_eq!(server.await.unwrap(), [5, 1, 0]);
    }

    #[tokio::test]
    async fn connect_with_password_auth() {
        let (mut near, far) = duplex(1024);
        let server = tokio::spawn(fake_server(far, true));
        client_handshake(
            &mut near,
            CMD_CONNECT,
            &Address::new("example.com", 443),
            Some(("user", "pw")),
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_failed_reply_is_an_error() {
        let (mut near, mut far) = duplex(1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let _ = far.read(&mut buf).await;
            far.write_all(&[5, 0]).await.unwrap();
            let _ = far.read(&mut buf).await;
            far.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = client_handshake(&mut near, CMD_CONNECT, &Address::new("a.test", 1), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("reply code 5"));
    }

    #[test]
    fn udp_packets_carry_the_destination() {
        let codec = Socks5Udp;
        let mut pkt = PacketBuf::with_headroom(codec.headroom());
        pkt.extend_from_slice(b"data");
        codec.seal(&mut pkt, &Address::new("1.2.3.4", 53)).unwrap();
        assert_eq!(
            pkt.as_slice(),
            [0, 0, 0, 1, 1, 2, 3, 4, 0, 53, b'd', b'a', b't', b'a']
        );
        let from = codec.open(&mut pkt).unwrap();
        assert_eq!(from, Address::new("1.2.3.4", 53));
        assert_eq!(pkt.as_slice(), b"data");
        let mut frag = PacketBuf::from_slice(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 53, 1]);
        assert!(codec.open(&mut frag).is_err());
    }

    #[test]
    fn the_largest_datagram_to_a_255_byte_domain_keeps_its_payload() {
        let codec = Socks5Udp;
        let host = "a".repeat(255);
        let payload: Vec<u8> = (0..65_507u32).map(|i| i.to_le_bytes()[0]).collect();
        let mut pkt = PacketBuf::take();
        pkt.extend_from_slice(&payload);
        let in_place = pkt.as_slice().as_ptr();
        codec.seal(&mut pkt, &Address::new(&host, 53)).unwrap();
        let header = 3 + 1 + 1 + 255 + 2;
        assert_eq!(pkt.len(), header + payload.len());
        assert_eq!(pkt.as_slice()[header..].as_ptr(), in_place);
        assert_eq!(codec.open(&mut pkt).unwrap(), Address::new(&host, 53));
        assert_eq!(pkt.as_slice(), payload);
    }
}
