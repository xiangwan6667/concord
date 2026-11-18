use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::{BoxRead, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Counts(Arc<AtomicUsize>);

struct Counted {
    inner: BoxStream,
    sent: Arc<AtomicUsize>,
}

#[async_trait]
impl NodeDialer for Counts {
    async fn dial_via(&self, _: &str, _: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let target: SocketAddr = dst
            .to_string()
            .parse()
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        Ok(Box::new(Counted {
            inner: Box::new(tokio::net::TcpStream::connect(target).await?),
            sent: self.0.clone(),
        }))
    }

    async fn associate_via(
        &self,
        _: &str,
        _: &DialCx<'_>,
        _: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, out)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_write(cx, bytes)
            .map(|result| {
                result.inspect(|&n| {
                    this.sent.fetch_add(n, Ordering::Relaxed);
                })
            })
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for Counted {
    concord_common::stream_policy!(inner;
        forward: peer_addr;
        own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            raw_socket, tcp, needs_handshake, direct, into_tcp);
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let (read, write) = tokio::io::split(*self);
        (Box::new(read), Box::new(write))
    }
}

fn mlkem_keys(binary: &str) -> (String, String) {
    let output = Command::new(binary)
        .args(["generate", "vless-mlkem768"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim()
            .to_string()
    };
    (field("Seed:"), field("Client:"))
}

#[tokio::test]
#[ignore = "needs CONCORD_MIHOMO"]
async fn vless_encryption_1rtt_and_0rtt_interoperate_with_mihomo() {
    let binary = concord_test_support::peer("CONCORD_MIHOMO");
    let (seed, mlkem) = mlkem_keys(&binary);
    let mut cases = Vec::new();
    for mode in ["native", "xorpub", "random"] {
        for rtt in ["1rtt", "0rtt"] {
            let encryption =
                format!("mlkem768x25519plus.{mode}.{rtt}.100-35-35.{REALITY_PUBLIC}.{mlkem}");
            let decryption = format!(
                "    decryption: mlkem768x25519plus.{mode}.600s.100-35-35.{REALITY_PRIVATE}.{seed}\n"
            );
            for flow in ["", "xtls-rprx-vision"] {
                let name = format!("vless-encryption-{mode}-{rtt}-{flow}");
                cases.push(vless_case(
                    &name,
                    json!({"encryption": encryption, "dialer-proxy": HOP}),
                    Udp::Many,
                    flow,
                    &decryption,
                ));
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut peer = start(Path::new(&binary), dir.path(), &cases);
    wait_ready(&mut peer, &cases).await;
    let echo = tcp_echo().await;
    let tls = tls_echo().await;
    let udp = udp_echo().await;
    let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
    for case in cases {
        let sent = Arc::new(AtomicUsize::new(0));
        let mut env = env();
        env.nodes = Arc::new(Counts(sent.clone()));
        let Ok(ProxyParse::Ok(def)) =
            parse_proxy(case.proxy.as_object().unwrap(), &Capabilities::full())
        else {
            panic!("{} parse failed", case.name);
        };
        let outbound = build_outbound(&def, &ctx).unwrap();
        // Identical one-byte sessions make the 1235-byte hello difference observable below the encryption layer.
        crr_once(&*outbound, &env, echo)
            .await
            .unwrap_or_else(|e| panic!("{} initial: {e}", case.name));
        let initial = sent.swap(0, Ordering::Relaxed);
        crr_once(&*outbound, &env, echo)
            .await
            .unwrap_or_else(|e| panic!("{} repeated: {e}", case.name));
        let repeated = sent.swap(0, Ordering::Relaxed);
        let padding_variance = if case.name.contains("vision") { 255 } else { 0 };
        if case.name.contains("0rtt") {
            // 1250-byte PFS + 35-byte padding replaces the 50-byte resumed exchange.
            assert!(
                initial.abs_diff(repeated + 1235) <= padding_variance,
                "{} did not resume: {initial} vs {repeated}",
                case.name
            );
        } else {
            assert!(
                initial.abs_diff(repeated) <= padding_variance,
                "{} unexpectedly resumed",
                case.name
            );
        }
        tcp_round_trip(&*outbound, &env, echo)
            .await
            .unwrap_or_else(|e| panic!("{} TCP: {e}", case.name));
        if case.name.contains("vision") {
            inner_tls_round_trip(&*outbound, &env, tls)
                .await
                .unwrap_or_else(|e| panic!("{} direct: {e}", case.name));
        }
        udp_round_trip(&*outbound, &env, &[udp])
            .await
            .unwrap_or_else(|e| panic!("{} UDP: {e}", case.name));
        println!("{} ok; initial {initial}, repeated {repeated}", case.name);
    }
}

#[tokio::test]
#[ignore = "needs CONCORD_MIHOMO"]
async fn rejected_vless_ticket_is_dropped_and_next_connection_uses_1rtt() {
    let binary = concord_test_support::peer("CONCORD_MIHOMO");
    let dir = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
    for mode in ["native", "xorpub", "random"] {
        let encryption = format!("mlkem768x25519plus.{mode}.0rtt.100-35-35.{REALITY_PUBLIC}");
        let decryption =
            format!("    decryption: mlkem768x25519plus.{mode}.600s.100-35-35.{REALITY_PRIVATE}\n");
        let cases = [vless_case(
            &format!("ticket-restart-{mode}"),
            json!({"encryption": encryption, "dialer-proxy": HOP}),
            Udp::No,
            "",
            &decryption,
        )];
        let sent = Arc::new(AtomicUsize::new(0));
        let mut env = env();
        env.nodes = Arc::new(Counts(sent.clone()));
        let Ok(ProxyParse::Ok(def)) =
            parse_proxy(cases[0].proxy.as_object().unwrap(), &Capabilities::full())
        else {
            panic!("parse failed");
        };
        let outbound = build_outbound(&def, &ctx).unwrap();
        let mut peer = start(Path::new(&binary), dir.path(), &cases);
        wait_ready(&mut peer, &cases).await;
        crr_once(&*outbound, &env, echo).await.unwrap();
        let full = sent.swap(0, Ordering::Relaxed);
        crr_once(&*outbound, &env, echo).await.unwrap();
        let resumed = sent.swap(0, Ordering::Relaxed);
        assert_eq!(full, resumed + 1235);
        drop(peer);
        let mut peer = start(Path::new(&binary), dir.path(), &cases);
        wait_ready(&mut peer, &cases).await;
        assert!(
            crr_once(&*outbound, &env, echo).await.is_err(),
            "{mode}: restarted server accepted old ticket"
        );
        let rejected = sent.swap(0, Ordering::Relaxed);
        assert_eq!(rejected, resumed);
        crr_once(&*outbound, &env, echo)
            .await
            .unwrap_or_else(|e| panic!("{mode}: full handshake after rejection: {e}"));
        assert_eq!(sent.swap(0, Ordering::Relaxed), full);
        crr_once(&*outbound, &env, echo).await.unwrap();
        assert_eq!(sent.swap(0, Ordering::Relaxed), resumed);
        println!("{mode}: old ticket rejected, full handshake and new ticket work");
    }
}
