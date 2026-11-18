#![allow(
    clippy::disallowed_methods,
    reason = "the harness talks to loopback listeners and sockets directly"
)]

//! Every outbound against a standalone mihomo. Run with
//! `CONCORD_MIHOMO=<path to the mihomo binary> cargo test -p concord-proxy --test interop -- --ignored`.
//! `CONCORD_QUIET_CLOSE=1` also checks that a server closing after one reply reads as a clean
//! end. The h2mux cases skip it: sing-mux's h2mux server ends a stream only once the client
//! ends its side, so mihomo's own client never sees that end either.

use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, DialEnv, HostResolver, Initiator, IpVersion, LookupIps,
    NodeDialer, NullSink, PacketBuf, PacketSession, SockOpts, recv_packet, send_packet,
};
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_net::Sockets;
use concord_platform::NativePlatform;
use concord_proxy::{BuildCtx, build_outbound};
use concord_tls::TrustStore;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[path = "interop/ech_dns.rs"]
mod ech_dns;
#[path = "interop/gost.rs"]
mod gost;
#[path = "interop/gost_relay.rs"]
mod gost_relay;
#[path = "interop/jls.rs"]
mod jls;
#[path = "interop/realm.rs"]
mod realm;
#[path = "interop/t1.rs"]
mod t1;
#[path = "interop/vless_encryption.rs"]
mod vless_encryption;
#[path = "interop/xray.rs"]
mod xray;
#[path = "interop/xray_front.rs"]
mod xray_front;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const KEY16: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";
const KEY32: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const REALITY_PRIVATE: &str = "4FPB64XuuLf_4rH6cRUelA49KX6LfpmlVNKDKuionHo";
const REALITY_PUBLIC: &str = "gnP8rteYQcQdsEDGFqm53nwdrL6HcBB6tZ4hd1c7nh4";

struct IpOnly;

#[async_trait]
impl HostResolver for IpOnly {
    async fn lookup(
        &self,
        host: &str,
        _version: IpVersion,
        _initiator: Initiator,
    ) -> io::Result<LookupIps> {
        let ip: IpAddr = if host == "localhost" {
            IpAddr::from([127, 0, 0, 1])
        } else {
            host.parse()
                .map_err(|_| CoreError::IpNotFound(host.into()))?
        };
        let mut found = LookupIps::default();
        if ip.is_ipv4() {
            found.v4.push(ip);
        } else {
            found.v6.push(ip);
        }
        Ok(found)
    }
}

const HOP: &str = "hop";

struct LoopbackNodes;

static HOP_DATAGRAMS: AtomicUsize = AtomicUsize::new(0);
const DATAGRAM_HOPS: [&str; 4] = [
    "ss-dialer-proxy",
    "socks-dialer-proxy",
    "hy2-dialer-proxy",
    "tuic5-dialer-proxy",
];

struct UdpHop(UdpSocket);

impl PacketSession for UdpHop {
    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> std::task::Poll<io::Result<()>> {
        let Ok(to) = dst.to_string().parse::<SocketAddr>() else {
            return std::task::Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        };
        self.0.poll_send_to(cx, pkt.as_slice(), to).map(|sent| {
            HOP_DATAGRAMS.fetch_add(1, Ordering::Relaxed);
            sent.map(|_| ())
        })
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut PacketBuf,
    ) -> std::task::Poll<io::Result<Address>> {
        let mut bytes = vec![0u8; 65535];
        let mut read = tokio::io::ReadBuf::new(&mut bytes);
        match self.0.poll_recv_from(cx, &mut read) {
            std::task::Poll::Ready(Ok(from)) => {
                buf.extend_from_slice(read.filled());
                std::task::Poll::Ready(Ok(Address::Socket(from)))
            }
            std::task::Poll::Ready(Err(err)) => std::task::Poll::Ready(Err(err)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[async_trait]
impl NodeDialer for LoopbackNodes {
    async fn dial_via(&self, name: &str, _cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        if name != HOP {
            return Err(CoreError::UnknownNode(name.to_string()).into());
        }
        let target: SocketAddr = dst
            .to_string()
            .parse()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(Box::new(tokio::net::TcpStream::connect(target).await?))
    }

    async fn associate_via(
        &self,
        name: &str,
        _cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if name != HOP {
            return Err(CoreError::UnknownNode(name.to_string()).into());
        }
        Ok(Arc::new(UdpHop(UdpSocket::bind("127.0.0.1:0").await?)))
    }
}

fn env() -> DialEnv {
    DialEnv {
        sockets: Arc::new(Sockets::new(Arc::new(NativePlatform::new()))),
        resolver: Arc::new(IpOnly),
        nodes: Arc::new(LoopbackNodes),
        events: Arc::new(NullSink),
        sock_opts: SockOpts::default(),
        tcp_concurrent: false,
        ipv6: true,
    }
}

// Below the ephemeral range: a wildcard DIRECT socket in mihomo can share a port with a listener.
// Multiplied because runs started together have close pids, and each takes a few hundred ports
// that it only binds later, through mihomo.
fn free_port() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let offset = (u64::from(std::process::id()) * 397) % 12_000;
    let base = 20_000 + u16::try_from(offset).unwrap_or(0);
    loop {
        let port = base + NEXT.fetch_add(1, Ordering::Relaxed);
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
            && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
    }
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = conn.read(&mut buf).await {
                    if n == 0 || conn.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            if socket.send_to(&buf[..n], from).await.is_err() {
                break;
            }
        }
    });
    addr
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Udp {
    No,
    OneDestination,
    Many,
}

struct Case {
    name: String,
    listener: String,
    proxy: Value,
    udp: Udp,
}

struct Certs {
    cert: PathBuf,
    key: PathBuf,
}

fn certs(dir: &Path) -> Certs {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, made.cert.pem()).unwrap();
    std::fs::write(&key, made.signing_key.serialize_pem()).unwrap();
    Certs { cert, key }
}

fn tls_lines(certs: &Certs) -> String {
    format!(
        "    certificate: {}\n    private-key: {}\n",
        certs.cert.display(),
        certs.key.display()
    )
}

fn listener(name: &str, kind: &str, port: u16, body: &str) -> String {
    format!("  - name: {name}\n    type: {kind}\n    listen: 127.0.0.1\n    port: {port}\n{body}")
}

fn proxy(name: &str, kind: &str, port: u16, extra: Value) -> Value {
    let mut base =
        json!({"name": name, "type": kind, "server": "127.0.0.1", "port": port, "udp": true});
    if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}

fn case(
    name: &str,
    kind: &str,
    listener_kind: &str,
    listener_body: &str,
    extra: Value,
    udp: Udp,
) -> Case {
    let port = free_port();
    Case {
        name: name.to_string(),
        listener: listener(name, listener_kind, port, listener_body),
        proxy: proxy(name, kind, port, extra),
        udp,
    }
}

fn ss_case(
    name: &str,
    cipher: &str,
    password: &str,
    listener_extra: &str,
    proxy_extra: Value,
    udp: Udp,
) -> Case {
    let body =
        format!("    password: {password}\n    cipher: {cipher}\n    udp: true\n{listener_extra}");
    let mut extra = json!({"cipher": cipher, "password": password});
    if let (Some(extra), Some(more)) = (extra.as_object_mut(), proxy_extra.as_object()) {
        for (key, value) in more {
            extra.insert(key.clone(), value.clone());
        }
    }
    case(name, "ss", "shadowsocks", &body, extra, udp)
}

fn vmess_users(alter: u32) -> String {
    format!("    users:\n      - username: a\n        uuid: {UUID}\n        alterId: {alter}\n")
}

fn vmess_case(name: &str, extra: Value, udp: Udp, alter: u32, listener_extra: &str) -> Case {
    let body = format!("{}{listener_extra}", vmess_users(alter));
    let mut merged = json!({"uuid": UUID, "alterId": alter, "cipher": "aes-128-gcm"});
    if let (Some(merged), Some(extra)) = (merged.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            merged.insert(key.clone(), value.clone());
        }
    }
    case(name, "vmess", "vmess", &body, merged, udp)
}

fn vless_case(name: &str, extra: Value, udp: Udp, flow: &str, listener_extra: &str) -> Case {
    let flow_line = if flow.is_empty() {
        String::new()
    } else {
        format!("        flow: {flow}\n")
    };
    let body = format!(
        "    users:\n      - username: a\n        uuid: {UUID}\n{flow_line}{listener_extra}"
    );
    let mut merged = json!({"uuid": UUID, "flow": flow});
    if let (Some(merged), Some(extra)) = (merged.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            merged.insert(key.clone(), value.clone());
        }
    }
    case(name, "vless", "vless", &body, merged, udp)
}

fn trojan_case(name: &str, extra: Value, udp: Udp, listener_extra: &str, certs: &Certs) -> Case {
    let body = format!(
        "    users:\n      - username: a\n        password: trojan-pw\n{}{listener_extra}",
        tls_lines(certs)
    );
    let mut merged = json!({"password": "trojan-pw", "sni": "localhost", "skip-cert-verify": true});
    if let (Some(merged), Some(extra)) = (merged.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            merged.insert(key.clone(), value.clone());
        }
    }
    case(name, "trojan", "trojan", &body, merged, udp)
}

fn tls_client() -> Value {
    json!({"tls": true, "servername": "localhost", "skip-cert-verify": true})
}

fn merge(mut base: Value, more: Value) -> Value {
    if let (Some(base), Some(more)) = (base.as_object_mut(), more.as_object()) {
        for (key, value) in more {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}

fn cases(certs: &Certs) -> Vec<Case> {
    let tls = tls_lines(certs);
    let mut all = vec![
        ss_case("ss-aes128", "aes-128-gcm", "pw", "", json!({}), Udp::Many),
        ss_case(
            "ss-dialer-proxy",
            "aes-128-gcm",
            "pw",
            "",
            json!({"dialer-proxy": HOP}),
            Udp::Many,
        ),
        ss_case("ss-aes256", "aes-256-gcm", "pw", "", json!({}), Udp::Many),
        ss_case(
            "ss-chacha",
            "chacha20-ietf-poly1305",
            "pw",
            "",
            json!({}),
            Udp::Many,
        ),
        ss_case(
            "ss-xchacha",
            "xchacha20-ietf-poly1305",
            "pw",
            "",
            json!({}),
            Udp::Many,
        ),
        ss_case("ss-cfb", "aes-256-cfb", "pw", "", json!({}), Udp::Many),
        ss_case("ss-chacha20", "chacha20", "pw", "", json!({}), Udp::Many),
        ss_case("ss-xchacha20", "xchacha20", "pw", "", json!({}), Udp::Many),
        ss_case("ss-ccm", "aes-128-ccm", "pw", "", json!({}), Udp::Many),
        ss_case(
            "ss-gcm-siv",
            "aes-256-gcm-siv",
            "pw",
            "",
            json!({}),
            Udp::Many,
        ),
        ss_case("ss-ctr", "aes-128-ctr", "pw", "", json!({}), Udp::Many),
        ss_case(
            "ss-2022-aes128",
            "2022-blake3-aes-128-gcm",
            KEY16,
            "",
            json!({}),
            Udp::Many,
        ),
        ss_case(
            "ss-2022-aes256",
            "2022-blake3-aes-256-gcm",
            KEY32,
            "",
            json!({}),
            Udp::Many,
        ),
        ss_case(
            "ss-2022-chacha",
            "2022-blake3-chacha20-poly1305",
            KEY32,
            "",
            json!({}),
            Udp::Many,
        ),
        ss_case(
            "ss-2022-chacha8",
            "2022-blake3-chacha8-poly1305",
            KEY32,
            "",
            json!({}),
            Udp::Many,
        ),
        ss_case(
            "ss-uot2",
            "aes-128-gcm",
            "pw",
            "",
            json!({"udp-over-tcp": true, "udp-over-tcp-version": 2}),
            Udp::Many,
        ),
        ss_case(
            "ss-uot1",
            "aes-128-gcm",
            "pw",
            "",
            json!({"udp-over-tcp": true, "udp-over-tcp-version": 1}),
            Udp::Many,
        ),
        ss_case(
            "ss-obfs-http",
            "aes-128-gcm",
            "pw",
            "    simple-obfs:\n      enable: true\n      mode: http\n",
            json!({"plugin": "obfs", "plugin-opts": {"mode": "http", "host": "bing.com"}}),
            Udp::No,
        ),
        ss_case(
            "ss-obfs-tls",
            "aes-128-gcm",
            "pw",
            "    simple-obfs:\n      enable: true\n      mode: tls\n",
            json!({"plugin": "obfs", "plugin-opts": {"mode": "tls", "host": "bing.com"}}),
            Udp::No,
        ),
        vmess_case("vmess-gcm", json!({}), Udp::OneDestination, 0, ""),
        vmess_case(
            "vmess-chacha",
            json!({"cipher": "chacha20-poly1305"}),
            Udp::OneDestination,
            0,
            "",
        ),
        vmess_case(
            "vmess-none",
            json!({"cipher": "none"}),
            Udp::OneDestination,
            0,
            "",
        ),
        vmess_case(
            "vmess-zero",
            json!({"cipher": "zero"}),
            Udp::OneDestination,
            0,
            "",
        ),
        vmess_case(
            "vmess-auto",
            json!({"cipher": "auto"}),
            Udp::OneDestination,
            0,
            "",
        ),
        vmess_case(
            "vmess-cfb",
            json!({"cipher": "aes-128-cfb"}),
            Udp::OneDestination,
            0,
            "",
        ),
        vmess_case(
            "vmess-padding",
            json!({"global-padding": true, "authenticated-length": true, "cipher": "chacha20-poly1305"}),
            Udp::OneDestination,
            0,
            "",
        ),
        vmess_case(
            "vmess-padding-gcm",
            json!({"global-padding": true}),
            Udp::OneDestination,
            0,
            "",
        ),
        vmess_case(
            "vmess-authlen",
            json!({"authenticated-length": true}),
            Udp::OneDestination,
            0,
            "",
        ),
        vmess_case("vmess-alter", json!({}), Udp::OneDestination, 1, ""),
        vmess_case(
            "vmess-alter-cfb",
            json!({"cipher": "aes-128-cfb"}),
            Udp::OneDestination,
            1,
            "",
        ),
        vmess_case("vmess-xudp", json!({"xudp": true}), Udp::Many, 0, ""),
        vmess_case(
            "vmess-packetaddr",
            json!({"packet-addr": true}),
            Udp::Many,
            0,
            "",
        ),
        vmess_case(
            "vmess-ws-tls",
            merge(
                tls_client(),
                json!({"network": "ws", "ws-opts": {"path": "/vm"}}),
            ),
            Udp::OneDestination,
            0,
            &format!("    ws-path: /vm\n{tls}"),
        ),
        vmess_case(
            "vmess-grpc-tls",
            merge(
                tls_client(),
                json!({"network": "grpc", "grpc-opts": {"grpc-service-name": "gun"}}),
            ),
            Udp::OneDestination,
            0,
            &format!("    grpc-service-name: gun\n{tls}"),
        ),
        vless_case(
            "vless-plain",
            json!({}),
            Udp::Many,
            "",
            "    allow-insecure: true\n",
        ),
        vless_case(
            "vless-packetaddr",
            json!({"packet-encoding": "packetaddr"}),
            Udp::Many,
            "",
            "    allow-insecure: true\n",
        ),
        vless_case(
            "vless-ws-tls",
            merge(
                tls_client(),
                json!({"network": "ws", "ws-opts": {"path": "/vl"}}),
            ),
            Udp::Many,
            "",
            &format!("    ws-path: /vl\n{tls}"),
        ),
        vless_case(
            "vless-vision",
            tls_client(),
            Udp::Many,
            "xtls-rprx-vision",
            &tls,
        ),
        trojan_case("trojan-tls", json!({}), Udp::Many, "", certs),
        trojan_case(
            "trojan-ws",
            json!({"network": "ws", "ws-opts": {"path": "/tj"}}),
            Udp::Many,
            "    ws-path: /tj\n",
            certs,
        ),
        trojan_case(
            "trojan-ss",
            json!({"ss-opts": {"enabled": true, "method": "AES-256-GCM", "password": "ss-pw"}}),
            Udp::Many,
            "    ss-option:\n      enabled: true\n      method: AES-256-GCM\n      password: ss-pw\n",
            certs,
        ),
        trojan_case(
            "trojan-ss-ccm",
            json!({"ss-opts": {"enabled": true, "method": "AES-128-CCM", "password": "ss-pw"}}),
            Udp::Many,
            "    ss-option:\n      enabled: true\n      method: AES-128-CCM\n      password: ss-pw\n",
            certs,
        ),
        trojan_case(
            "trojan-ss-cfb",
            json!({"ss-opts": {"enabled": true, "method": "AES-128-CFB", "password": "ss-pw"}}),
            Udp::Many,
            "    ss-option:\n      enabled: true\n      method: AES-128-CFB\n      password: ss-pw\n",
            certs,
        ),
        trojan_case(
            "trojan-ss-chacha20",
            json!({"ss-opts": {"enabled": true, "method": "CHACHA20", "password": "ss-pw"}}),
            Udp::Many,
            "    ss-option:\n      enabled: true\n      method: CHACHA20\n      password: ss-pw\n",
            certs,
        ),
        trojan_case(
            "trojan-ss-xchacha20",
            json!({"ss-opts": {"enabled": true, "method": "XCHACHA20", "password": "ss-pw"}}),
            Udp::Many,
            "    ss-option:\n      enabled: true\n      method: XCHACHA20\n      password: ss-pw\n",
            certs,
        ),
    ];
    all.extend(quic_cases(certs));
    all.extend(t1::cases(certs));
    all.extend(jls::cases(certs));
    all.extend(realm::cases(certs));
    all.push(case(
        "socks-open",
        "socks5",
        "socks",
        "    udp: true\n",
        json!({}),
        Udp::Many,
    ));
    all.push(case(
        "socks-dialer-proxy",
        "socks5",
        "socks",
        "    udp: true\n",
        json!({"dialer-proxy": HOP}),
        Udp::Many,
    ));
    all.push(case(
        "socks-auth",
        "socks5",
        "socks",
        "    udp: true\n    users:\n      - username: u\n        password: p\n",
        json!({"username": "u", "password": "p"}),
        Udp::Many,
    ));
    all.push(case("http-open", "http", "http", "", json!({}), Udp::No));
    all.push(reality_case(&all));
    all.push(case(
        "http-auth",
        "http",
        "http",
        "    users:\n      - username: u\n        password: p\n",
        json!({"username": "u", "password": "p"}),
        Udp::No,
    ));
    all
}

/// REALITY's cover site is the trojan-tls listener, a Go TLS 1.3 server.
fn reality_case(all: &[Case]) -> Case {
    let dest = all
        .iter()
        .find(|case| case.name == "trojan-tls")
        .and_then(|case| case.proxy.get("port"))
        .and_then(Value::as_u64)
        .unwrap();
    let listener = format!(
        "    reality-config:\n      dest: 127.0.0.1:{dest}\n      private-key: {REALITY_PRIVATE}\n      \
         short-id:\n        - 0123456789abcdef\n      server-names:\n        - localhost\n"
    );
    vless_case(
        "vless-reality-vision",
        json!({
            "tls": true,
            "servername": "localhost",
            "client-fingerprint": "chrome",
            "reality-opts": {"public-key": REALITY_PUBLIC, "short-id": "0123456789abcdef"},
        }),
        Udp::Many,
        "xtls-rprx-vision",
        &listener,
    )
}

fn hy2_case(name: &str, listener_extra: &str, extra: Value, certs: &Certs) -> Case {
    let body = format!(
        "    users:\n      user: hy2-pw\n{}{listener_extra}",
        tls_lines(certs)
    );
    let base = json!({"password": "hy2-pw", "sni": "localhost", "skip-cert-verify": true});
    case(
        name,
        "hysteria2",
        "hysteria2",
        &body,
        merge(base, extra),
        Udp::Many,
    )
}

const TUIC_UUID: &str = "b3f1a6d2-5c0e-4a11-9c43-7e2d8f6a0b15";

fn tuic_case(name: &str, v5: bool, listener_extra: &str, extra: Value, certs: &Certs) -> Case {
    let (auth, base) = if v5 {
        (
            format!("    users:\n      {TUIC_UUID}: tuic-pw\n"),
            json!({"uuid": TUIC_UUID, "password": "tuic-pw"}),
        )
    } else {
        (
            "    token:\n      - tuic-token\n".to_string(),
            json!({"token": "tuic-token"}),
        )
    };
    let body = format!("{auth}{}{listener_extra}", tls_lines(certs));
    let base = merge(base, json!({"sni": "localhost", "skip-cert-verify": true}));
    case(name, "tuic", "tuic", &body, merge(base, extra), Udp::Many)
}

fn shadowtls_case(name: &str, version: u8, certs: &Certs) -> Case {
    let decoy_port = free_port();
    let decoy = listener(
        &format!("{name}-decoy"),
        "http",
        decoy_port,
        &tls_lines(certs),
    );
    let extra = format!(
        "    shadow-tls:\n      enable: true\n      version: {version}\n      password: st-pw\n      users:\n        - name: u\n          password: st-pw\n      handshake:\n        dest: 127.0.0.1:{decoy_port}\n"
    );
    let plugin = json!({"plugin": "shadow-tls", "plugin-opts": {
        "host": "localhost", "password": "st-pw", "version": version, "skip-cert-verify": true}});
    let mut made = ss_case(name, "aes-128-gcm", "pw", &extra, plugin, Udp::Many);
    made.listener = format!("{decoy}{}", made.listener);
    made
}

/// A node with `shadow-tls-opts` against a listener whose `shadow-tls` takes the place of its TLS:
/// the listener's ShadowTLS block, the node's TLS keys and the decoy listener to prepend.
fn shadowtls_layer(name: &str, version: u8, certs: &Certs) -> (String, Value, String) {
    let decoy_port = free_port();
    let decoy = listener(
        &format!("{name}-decoy"),
        "http",
        decoy_port,
        &tls_lines(certs),
    );
    let listener_extra = format!(
        "    shadow-tls:\n      enable: true\n      version: {version}\n      password: st-pw\n      users:\n        - name: u\n          password: st-pw\n      handshake:\n        dest: 127.0.0.1:{decoy_port}\n"
    );
    let client = json!({"tls": true, "servername": "localhost", "sni": "localhost",
        "skip-cert-verify": true, "shadow-tls-opts": {"password": "st-pw", "version": version}});
    (listener_extra, client, decoy)
}

fn shadowtls_layer_cases(certs: &Certs) -> Vec<Case> {
    let with_decoy = |mut made: Case, decoy: String| {
        made.listener = format!("{decoy}{}", made.listener);
        made
    };
    let (extra, client, decoy) = shadowtls_layer("vmess-shadowtls-v3", 3, certs);
    let vmess = vmess_case("vmess-shadowtls-v3", client, Udp::OneDestination, 0, &extra);
    let mut all = vec![with_decoy(vmess, decoy)];
    let (extra, client, decoy) = shadowtls_layer("vmess-shadowtls-v2", 2, certs);
    let vmess = vmess_case("vmess-shadowtls-v2", client, Udp::OneDestination, 0, &extra);
    all.push(with_decoy(vmess, decoy));

    let (extra, client, decoy) = shadowtls_layer("vless-ws-shadowtls-v3", 3, certs);
    let client = merge(client, json!({"network": "ws", "ws-opts": {"path": "/vl"}}));
    let listener = format!("    ws-path: /vl\n{extra}");
    let vless = vless_case("vless-ws-shadowtls-v3", client, Udp::Many, "", &listener);
    all.push(with_decoy(vless, decoy));

    let (extra, client, decoy) = shadowtls_layer("vless-ws-shadowtls-v2", 2, certs);
    let client = merge(client, json!({"network": "ws", "ws-opts": {"path": "/vl"}}));
    let vless = vless_case(
        "vless-ws-shadowtls-v2",
        client,
        Udp::Many,
        "",
        &format!("    ws-path: /vl\n{extra}"),
    );
    all.push(with_decoy(vless, decoy));

    let (extra, client, decoy) = shadowtls_layer("vless-xhttp-shadowtls-v3", 3, certs);
    let client = merge(
        client,
        json!({"network": "xhttp", "xhttp-opts": {"path": "/xh", "mode": "stream-one"}}),
    );
    let vless = vless_case(
        "vless-xhttp-shadowtls-v3",
        client,
        Udp::Many,
        "",
        &format!("    xhttp-config:\n      path: /xh\n      mode: stream-one\n{extra}"),
    );
    all.push(with_decoy(vless, decoy));

    // mihomo refuses a listener with both a certificate and shadow-tls.
    let trojan = |name: &str, extra: &str, client: Value| {
        let body = format!("    users:\n      - username: a\n        password: trojan-pw\n{extra}");
        let client = merge(json!({"password": "trojan-pw"}), client);
        case(name, "trojan", "trojan", &body, client, Udp::Many)
    };
    let (extra, client, decoy) = shadowtls_layer("trojan-shadowtls-v1", 1, certs);
    all.push(with_decoy(
        trojan("trojan-shadowtls-v1", &extra, client),
        decoy,
    ));

    let (extra, client, decoy) = shadowtls_layer("trojan-grpc-shadowtls-v3", 3, certs);
    let client = merge(
        client,
        json!({"network": "grpc", "grpc-opts": {"grpc-service-name": "gun"}}),
    );
    let extra = format!("    grpc-service-name: gun\n{extra}");
    let made = trojan("trojan-grpc-shadowtls-v3", &extra, client);
    all.push(with_decoy(made, decoy));

    let (extra, client, decoy) = shadowtls_layer("anytls-shadowtls-v3", 3, certs);
    let body = format!("    users:\n      user: anytls-pw\n{extra}");
    let client = merge(json!({"password": "anytls-pw"}), client);
    let anytls = case(
        "anytls-shadowtls-v3",
        "anytls",
        "anytls",
        &body,
        client,
        Udp::Many,
    );
    all.push(with_decoy(anytls, decoy));
    all
}

fn anytls_case(name: &str, extra: Value, listener_extra: &str, certs: &Certs) -> Case {
    let body = format!(
        "    users:\n      user: anytls-pw\n{}{listener_extra}",
        tls_lines(certs)
    );
    let base = json!({"password": "anytls-pw", "sni": "localhost", "skip-cert-verify": true});
    case(
        name,
        "anytls",
        "anytls",
        &body,
        merge(base, extra),
        Udp::Many,
    )
}

fn quic_cases(certs: &Certs) -> Vec<Case> {
    let tls = tls_lines(certs);
    let xhttp = |name: &str, mode: &str, alpn: Value| {
        let client = merge(
            tls_client(),
            json!({"network": "xhttp", "alpn": alpn, "xhttp-opts": {"path": "/xh", "mode": mode}}),
        );
        vless_case(
            name,
            client,
            Udp::Many,
            "",
            &format!("    xhttp-config:\n      path: /xh\n      mode: {mode}\n{tls}"),
        )
    };
    let mut all = shadowtls_layer_cases(certs);
    all.extend([
        shadowtls_case("ss-shadowtls-v3", 3, certs),
        shadowtls_case("ss-shadowtls-v2", 2, certs),
        shadowtls_case("ss-shadowtls-v1", 1, certs),
        ss_case(
            "ss-smux-h2mux",
            "aes-128-gcm",
            "pw",
            "",
            json!({"smux": {"enabled": true}}),
            Udp::Many,
        ),
        ss_case(
            "ss-smux-smux",
            "aes-128-gcm",
            "pw",
            "",
            json!({"smux": {"enabled": true, "protocol": "smux"}}),
            Udp::Many,
        ),
        ss_case(
            "ss-smux-yamux-padding",
            "aes-128-gcm",
            "pw",
            "",
            json!({"smux": {"enabled": true, "protocol": "yamux", "padding": true}}),
            Udp::Many,
        ),
        ss_case(
            "ss-smux-only-tcp",
            "aes-128-gcm",
            "pw",
            "",
            json!({"smux": {"enabled": true, "only-tcp": true}}),
            Udp::Many,
        ),
        xhttp("vless-xhttp-packet-up", "packet-up", json!(["h2"])),
        xhttp("vless-xhttp-stream-up", "stream-up", json!(["h2"])),
        xhttp("vless-xhttp-stream-one", "stream-one", json!(["h2"])),
        xhttp("vless-xhttp-h1", "packet-up", json!(["http/1.1"])),
        anytls_case("anytls-plain", json!({}), "", certs),
        anytls_case(
            "anytls-noreuse",
            json!({"disable-reuse": true, "client-metadata": "probe"}),
            "",
            certs,
        ),
        tuic_case("tuic5-native", true, "", json!({}), certs),
        tuic_case(
            "tuic5-quic",
            true,
            "",
            json!({"udp-relay-mode": "quic"}),
            certs,
        ),
        tuic_case(
            "tuic5-bbr",
            true,
            "    congestion-controller: bbr\n",
            json!({"congestion-controller": "bbr", "cwnd": 64}),
            certs,
        ),
        tuic_case(
            "tuic5-bbr-conservative",
            true,
            "    congestion-controller: bbr\n    bbr-profile: conservative\n",
            json!({"congestion-controller": "bbr", "bbr-profile": "conservative"}),
            certs,
        ),
        tuic_case(
            "tuic5-bbr-aggressive",
            true,
            "    congestion-controller: bbr\n    bbr-profile: aggressive\n",
            json!({"congestion-controller": "bbr", "bbr-profile": "aggressive"}),
            certs,
        ),
        tuic_case(
            "tuic5-cubic",
            true,
            "",
            json!({"congestion-controller": "cubic"}),
            certs,
        ),
        tuic_case(
            "tuic5-uos",
            true,
            "",
            json!({"udp-over-stream": true, "udp-over-stream-version": 2}),
            certs,
        ),
        tuic_case(
            "tuic5-dialer-proxy",
            true,
            "",
            json!({"dialer-proxy": HOP}),
            certs,
        ),
        tuic_case("tuic4-native", false, "", json!({}), certs),
        tuic_case(
            "tuic4-quic",
            false,
            "",
            json!({"udp-relay-mode": "quic", "fast-open": true}),
            certs,
        ),
        hy2_case("hy2-plain", "", json!({}), certs),
        hy2_case(
            "hy2-salamander",
            "    obfs: salamander\n    obfs-password: salt-pw\n",
            json!({"obfs": "salamander", "obfs-password": "salt-pw"}),
            certs,
        ),
        hy2_case(
            "hy2-gecko",
            "    obfs: gecko\n    obfs-password: gecko-pw\n",
            json!({"obfs": "gecko", "obfs-password": "gecko-pw"}),
            certs,
        ),
        hy2_case(
            "hy2-brutal",
            "    up: 200 Mbps\n    down: 200 Mbps\n",
            json!({"up": "100 Mbps", "down": "100 Mbps"}),
            certs,
        ),
        hy2_case("hy2-bbr-cwnd", "", json!({"cwnd": 64}), certs),
        hy2_case("hy2-dialer-proxy", "", json!({"dialer-proxy": HOP}), certs),
    ]);
    all
}

struct Mihomo {
    child: Child,
    log: PathBuf,
}

impl Drop for Mihomo {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(binary: &Path, dir: &Path, cases: &[Case]) -> Mihomo {
    let level = std::env::var("CONCORD_MIHOMO_LOG").unwrap_or_else(|_| "info".to_string());
    let mut config = format!("log-level: {level}\nmode: direct\nipv6: false\nlisteners:\n");
    for case in cases {
        let _ = write!(config, "{}", case.listener);
    }
    std::fs::write(dir.join("config.yaml"), config).unwrap();
    let log = dir.join("mihomo.log");
    let out = std::fs::File::create(&log).unwrap();
    let child = Command::new(binary)
        .env("DISABLE_LOOPBACK_DETECTOR", "true")
        .arg("-d")
        .arg(dir)
        .arg("-f")
        .arg(dir.join("config.yaml"))
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .unwrap();
    Mihomo { child, log }
}

async fn wait_ready(mihomo: &mut Mihomo, cases: &[Case]) {
    let last = cases
        .last()
        .and_then(|case| case.proxy.get("port"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    for _ in 0..100 {
        if let Ok(Some(status)) = mihomo.child.try_wait() {
            let log = std::fs::read_to_string(&mihomo.log).unwrap_or_default();
            panic!("mihomo exited early ({status}):\n{log}");
        }
        if std::net::TcpStream::connect(("127.0.0.1", u16::try_from(last).unwrap_or(0))).is_ok() {
            // Listeners accept before the tunnel runs, and it closes whatever arrives until then.
            tokio::time::sleep(Duration::from_secs(1)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let log = std::fs::read_to_string(&mihomo.log).unwrap_or_default();
    let config = mihomo
        .log
        .parent()
        .and_then(|dir| std::fs::read_to_string(dir.join("config.yaml")).ok())
        .unwrap_or_default();
    panic!("mihomo never listened:\n{log}\n--- config ---\n{config}");
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 7 % 251).unwrap_or(0))
        .collect()
}

/// A TLS 1.3 echo server: through Vision its application data makes both directions leave
/// the outer TLS for the raw socket.
async fn tls_echo() -> SocketAddr {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(made.signing_key.serialize_der()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![made.cert.der().clone()], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(conn).await else {
                    return;
                };
                let (mut read, mut write) = tokio::io::split(tls);
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

async fn inner_tls_round_trip(
    outbound: &dyn concord_common::Outbound,
    env: &DialEnv,
    target: SocketAddr,
) -> Result<(), String> {
    let cx = DialCx::new(env, Initiator::Direct, None);
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        outbound.connect(&cx, &Address::new(&target.ip().to_string(), target.port())),
    )
    .await
    .map_err(|_| "connect timed out".to_string())?
    .map_err(|err| format!("connect: {err}"))?;
    let options = concord_tls::TlsOptions {
        server_name: Some("localhost".into()),
        skip_cert_verify: true,
        ..concord_tls::TlsOptions::default()
    };
    let connector = concord_tls::TlsConnector::new(options, TrustStore::new(b"", Vec::new()))
        .map_err(|err| format!("inner tls config: {err}"))?;
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect_unaligned(stream, "localhost"),
    )
    .await
    .map_err(|_| "inner tls handshake timed out".to_string())?
    .map_err(|err| format!("inner tls handshake: {err}"))?;
    let (mut read, mut write) = tokio::io::split(tls);
    for size in [5usize, 200_000, 3000] {
        let data = pattern(size);
        let writer = async {
            write.write_all(&data).await?;
            write.flush().await
        };
        let reader = async {
            let mut got = vec![0u8; size];
            read.read_exact(&mut got).await?;
            Ok::<_, io::Error>(got)
        };
        let (written, got) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(writer, reader)
        })
        .await
        .map_err(|_| format!("inner tls {size} byte echo timed out"))?;
        written.map_err(|err| format!("inner tls write {size}: {err}"))?;
        let got = got.map_err(|err| format!("inner tls read {size}: {err}"))?;
        if got != data {
            return Err(format!("inner tls {size} byte echo came back different"));
        }
    }
    Ok(())
}

async fn tcp_round_trip(
    outbound: &dyn concord_common::Outbound,
    env: &DialEnv,
    echo: SocketAddr,
) -> Result<(), String> {
    let cx = DialCx::new(env, Initiator::Direct, None);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        outbound.connect(&cx, &Address::new(&echo.ip().to_string(), echo.port())),
    )
    .await
    .map_err(|_| "connect timed out".to_string())?
    .map_err(|err| format!("connect: {err}"))?;
    for size in [5usize, 3000, 200_000] {
        let data = pattern(size);
        let (mut read, mut write) = tokio::io::split(&mut stream);
        let writer = async {
            write.write_all(&data).await?;
            write.flush().await
        };
        let reader = async {
            let mut got = vec![0u8; size];
            read.read_exact(&mut got).await?;
            Ok::<_, io::Error>(got)
        };
        let (written, got) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(writer, reader)
        })
        .await
        .map_err(|_| format!("{size} byte echo timed out"))?;
        written.map_err(|err| format!("write {size}: {err}"))?;
        let got = got.map_err(|err| format!("read {size}: {err}"))?;
        if got != data {
            return Err(format!(
                "{size} byte echo came back different: got {:?}, wanted {:?}",
                got.get(..got.len().min(16)),
                data.get(..data.len().min(16))
            ));
        }
    }
    Ok(())
}

async fn tcp_closer() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 5];
                if conn.read_exact(&mut buf).await.is_ok() {
                    let _ = conn.write_all(b"hi").await;
                }
            });
        }
    });
    addr
}

/// One byte back, then the origin closes first, as the bench's CRR origin does.
async fn tcp_one_byte_back() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut byte = [0u8; 1];
                if conn.read_exact(&mut byte).await.is_ok() {
                    let _ = conn.write_all(&byte).await;
                }
            });
        }
    });
    addr
}

/// `total` short connections, 16 at a time, each one byte each way against
/// `tcp_one_byte_back`.
async fn tcp_crr(
    outbound: Arc<dyn concord_common::Outbound>,
    env: &DialEnv,
    origin: SocketAddr,
    total: usize,
) -> Result<(), String> {
    let next = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let (outbound, env, next) = (outbound.clone(), env.clone(), next.clone());
            tokio::spawn(async move {
                let mut failures = Vec::new();
                while next.fetch_add(1, Ordering::Relaxed) < total {
                    if let Err(err) = crr_once(&*outbound, &env, origin).await {
                        failures.push(err);
                    }
                }
                failures
            })
        })
        .collect();
    let mut kinds = std::collections::BTreeMap::<String, usize>::new();
    for worker in workers {
        for failure in worker.await.map_err(|err| err.to_string())? {
            *kinds.entry(failure).or_default() += 1;
        }
    }
    let failed: usize = kinds.values().sum();
    if failed == 0 {
        return Ok(());
    }
    Err(format!("{failed}/{total} failed: {kinds:?}"))
}

async fn crr_once(
    outbound: &dyn concord_common::Outbound,
    env: &DialEnv,
    origin: SocketAddr,
) -> Result<(), String> {
    let cx = DialCx::new(env, Initiator::Direct, None);
    let work = async {
        let mut stream = outbound
            .connect(&cx, &Address::new(&origin.ip().to_string(), origin.port()))
            .await
            .map_err(|err| format!("connect: {err}"))?;
        stream
            .write_all(b"c")
            .await
            .map_err(|err| format!("write: {err}"))?;
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|err| format!("read: {err}"))?;
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .map_err(|_| "timed out".to_string())?
}

const H2MUX_CASES: [&str; 2] = ["ss-smux-h2mux", "ss-smux-only-tcp"];

/// Answers each connection with a banner before reading, as SMTP and SSH servers do.
async fn tcp_greeter() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                if conn.write_all(b"220 ready").await.is_err() {
                    return;
                }
                let mut buf = [0u8; 4];
                if conn.read_exact(&mut buf).await.is_ok() {
                    let _ = conn.write_all(&buf).await;
                }
            });
        }
    });
    addr
}

/// A connection the client only reads from first: a lazy header has to go out without data.
async fn tcp_server_first(
    outbound: &dyn concord_common::Outbound,
    env: &DialEnv,
    greeter: SocketAddr,
) -> Result<(), String> {
    let cx = DialCx::new(env, Initiator::Direct, None);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        outbound.connect(
            &cx,
            &Address::new(&greeter.ip().to_string(), greeter.port()),
        ),
    )
    .await
    .map_err(|_| "connect timed out".to_string())?
    .map_err(|err| format!("connect: {err}"))?;
    let mut banner = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut banner))
        .await
        .map_err(|_| "banner timed out".to_string())?
        .map_err(|err| format!("banner: {err}"))?;
    if &banner != b"220 ready" {
        return Err(format!("banner came back as {banner:?}"));
    }
    stream
        .write_all(b"EHLO")
        .await
        .map_err(|err| format!("write: {err}"))?;
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echo))
        .await
        .map_err(|_| "reply timed out".to_string())?
        .map_err(|err| format!("reply: {err}"))?;
    if &echo != b"EHLO" {
        return Err(format!("reply came back as {echo:?}"));
    }
    Ok(())
}

async fn tcp_quiet_close(
    outbound: &dyn concord_common::Outbound,
    env: &DialEnv,
    closer: SocketAddr,
) -> Result<(), String> {
    let cx = DialCx::new(env, Initiator::Direct, None);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        outbound.connect(&cx, &Address::new(&closer.ip().to_string(), closer.port())),
    )
    .await
    .map_err(|_| "connect timed out".to_string())?
    .map_err(|err| format!("connect: {err}"))?;
    stream
        .write_all(b"hello")
        .await
        .map_err(|err| format!("write: {err}"))?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush: {err}"))?;
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest))
        .await
        .map_err(|_| "close timed out".to_string())?
        .map_err(|err| format!("close: {err}"))?;
    if rest != b"hi" {
        return Err(format!("close: read {rest:?} before the end"));
    }
    Ok(())
}

async fn udp_round_trip(
    outbound: &dyn concord_common::Outbound,
    env: &DialEnv,
    targets: &[SocketAddr],
) -> Result<(), String> {
    let cx = DialCx::new(env, Initiator::Direct, None);
    let first = Address::new(&targets[0].ip().to_string(), targets[0].port());
    let session = tokio::time::timeout(Duration::from_secs(10), outbound.associate(&cx, &first))
        .await
        .map_err(|_| "associate timed out".to_string())?
        .map_err(|err| format!("associate: {err}"))?;
    for (round, target) in targets.iter().enumerate() {
        let dst = Address::new(&target.ip().to_string(), target.port());
        for size in [4usize, 700] {
            let data = pattern(size + round);
            let mut packet = PacketBuf::with_headroom(session.headroom());
            packet.extend_from_slice(&data);
            tokio::time::timeout(
                Duration::from_secs(10),
                send_packet(&*session, &mut packet, &dst),
            )
            .await
            .map_err(|_| "send timed out".to_string())?
            .map_err(|err| format!("send: {err}"))?;
            let (got, from) = tokio::time::timeout(Duration::from_secs(10), recv_packet(&*session))
                .await
                .map_err(|_| format!("no udp answer from {target}"))?
                .map_err(|err| format!("recv: {err}"))?;
            if got.as_slice() != data {
                let at = got.as_slice().iter().zip(&data).position(|(a, b)| a != b);
                return Err(format!(
                    "udp payload from {from:?} differs: got {} bytes, wanted {}, first difference at {at:?}: {:?} vs {:?}",
                    got.len(),
                    data.len(),
                    at.and_then(|i| got.as_slice().get(i..i + 8)),
                    at.and_then(|i| data.get(i..i + 8)),
                ));
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs CONCORD_MIHOMO"]
async fn every_outbound_talks_to_mihomo() {
    let binary = concord_test_support::peer("CONCORD_MIHOMO");
    let dir = tempfile::tempdir().unwrap();
    let certs = certs(dir.path());
    let cases = cases(&certs);
    let filter = std::env::var("CONCORD_CASE").ok();
    let wants_realm = filter
        .as_deref()
        .is_none_or(|only| "hy2-realm".contains(only) || only.contains("realm"));
    let _stun = realm::stun_server().await;
    let mut mihomo = start(Path::new(&binary), dir.path(), &cases);
    wait_ready(&mut mihomo, &cases).await;
    if wants_realm {
        realm::wait_registered(&mihomo.log, 2).await;
    }

    let echo = tcp_echo().await;
    let tls_target = tls_echo().await;
    let closer = tcp_closer().await;
    let one_byte = tcp_one_byte_back().await;
    let greeter = tcp_greeter().await;
    let udp_a = udp_echo().await;
    let udp_b = udp_echo().await;
    let mut env = env();
    if let Some(list) = t1::ech_list() {
        env.resolver = ech_dns::start(list, &["ech.example.com", "localhost"]).await;
    }
    let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));

    let mut failures = Vec::new();
    for case in &cases {
        if filter
            .as_deref()
            .is_some_and(|only| !case.name.contains(only))
        {
            continue;
        }
        let Some(map) = case.proxy.as_object() else {
            continue;
        };
        let def = match parse_proxy(map, &Capabilities::full()) {
            Ok(ProxyParse::Ok(def)) => def,
            Ok(ProxyParse::Quarantined { reason, .. }) => {
                failures.push(format!("{}: quarantined: {reason}", case.name));
                continue;
            }
            Err(err) => {
                failures.push(format!("{}: config: {err}", case.name));
                continue;
            }
        };
        let outbound = match build_outbound(&def, &ctx) {
            Ok(outbound) => outbound,
            Err(err) => {
                failures.push(format!("{}: build: {err}", case.name));
                continue;
            }
        };
        let mut notes = Vec::new();
        let mut tcp = tcp_round_trip(&*outbound, &env, echo).await;
        // mihomo's Snell reader takes a frame in two reads, and its tunnel's peek deadline can
        // land between them; the frame is lost and the listener drops or stalls the connection.
        if let (true, Err(err)) = (case.name.starts_with("snell"), &tcp) {
            println!("{:<20} retrying tcp: {err}", case.name);
            tcp = tcp_round_trip(&*outbound, &env, echo).await;
        }
        if let Err(err) = tcp {
            notes.push(format!("tcp {err}"));
        }
        if case.name.contains("vision")
            && let Err(err) = inner_tls_round_trip(&*outbound, &env, tls_target).await
        {
            notes.push(err);
        }
        if case.name.starts_with("ss-smux")
            && let Err(err) = tcp_server_first(&*outbound, &env, greeter).await
        {
            notes.push(format!("server first {err}"));
        }
        if std::env::var_os("CONCORD_QUIET_CLOSE").is_some()
            && !H2MUX_CASES.contains(&case.name.as_str())
            && let Err(err) = tcp_quiet_close(&*outbound, &env, closer).await
        {
            notes.push(format!("quiet close {err}"));
        }
        if let Some(total) = std::env::var("CONCORD_CRR")
            .ok()
            .and_then(|total| total.parse().ok())
            && let Err(err) = tcp_crr(outbound.clone(), &env, one_byte, total).await
        {
            notes.push(format!("crr {err}"));
        }
        if case.udp != Udp::No {
            let targets: Vec<SocketAddr> = if case.udp == Udp::Many {
                vec![udp_a, udp_b]
            } else {
                vec![udp_a]
            };
            let hopped = HOP_DATAGRAMS.load(Ordering::Relaxed);
            // The same port sharing can hit a client socket; a new session gets new ports.
            let first = udp_round_trip(&*outbound, &env, &targets).await;
            let result = match first {
                Err(err) if err.starts_with("no udp answer") => {
                    println!("{:<20} retrying udp: {err}", case.name);
                    udp_round_trip(&*outbound, &env, &targets).await
                }
                other => other,
            };
            if let Err(err) = result {
                notes.push(format!("udp {err}"));
            } else if DATAGRAM_HOPS.contains(&case.name.as_str())
                && HOP_DATAGRAMS.load(Ordering::Relaxed) == hopped
            {
                notes.push("udp left this host instead of the dialer-proxy".to_string());
            }
        }
        if case.name.starts_with("hy2-realm") {
            outbound.reset_sessions();
            if let Err(err) = tcp_round_trip(&*outbound, &env, echo).await {
                notes.push(format!("tcp after a new punch {err}"));
            }
        }
        println!(
            "{:<20} {}",
            case.name,
            if notes.is_empty() {
                "ok".to_string()
            } else {
                notes.join("; ")
            }
        );
        if !notes.is_empty() {
            failures.push(format!("{}: {}", case.name, notes.join("; ")));
        }
    }
    if wants_realm {
        for (what, proxy, expected) in realm::failures() {
            let Some(map) = proxy.as_object() else {
                continue;
            };
            let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
                failures.push(format!("realm {what}: config"));
                continue;
            };
            let outcome = match build_outbound(&def, &ctx) {
                Ok(outbound) => tcp_round_trip(&*outbound, &env, echo).await,
                Err(err) => Err(format!("build: {err}")),
            };
            match outcome {
                Err(err) if err.contains(expected) => println!("realm {what:<28} ok ({err})"),
                other => failures.push(format!("realm {what}: wanted {expected:?}, got {other:?}")),
            }
        }
    }
    if !failures.is_empty() {
        let log = std::fs::read_to_string(&mihomo.log).unwrap_or_default();
        let tail: Vec<&str> = log
            .lines()
            .filter(|line| !line.contains("using DIRECT"))
            .collect();
        panic!(
            "{} cases failed:\n{}\n--- mihomo log tail ---\n{}",
            failures.len(),
            failures.join("\n"),
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        );
    }
}
