use super::*;

pub(super) struct Peer {
    child: Child,
    log: PathBuf,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(super) async fn start_peer(binary: &Path, listen: &str, port: u16, dir: &Path) -> Peer {
    let log = dir.join(format!("gost-{port}.log"));
    let output = std::fs::File::create(&log).unwrap();
    let child = Command::new(binary)
        .args(["-L", listen])
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .unwrap();
    let mut peer = Peer { child, log };
    for _ in 0..100 {
        if let Some(status) = peer.child.try_wait().unwrap() {
            panic!(
                "gost exited ({status}): {}",
                std::fs::read_to_string(&peer.log).unwrap_or_default()
            );
        }
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return peer;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "gost never listened: {}",
        std::fs::read_to_string(&peer.log).unwrap_or_default()
    );
}

pub(super) fn outbound(value: Value) -> Arc<dyn concord_common::Outbound> {
    let ProxyParse::Ok(def) =
        parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("quarantined")
    };
    build_outbound(&def, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap()
}

#[tokio::test]
#[ignore = "needs CONCORD_GOST2 (gost v2) and CONCORD_MIHOMO"]
async fn gost_plugin_round_trips_with_upstream_gost_and_mihomo() {
    let gost = concord_test_support::peer("CONCORD_GOST2");
    let mihomo = concord_test_support::peer("CONCORD_MIHOMO");
    let dir = tempfile::tempdir().unwrap();
    let certs = certs(dir.path());
    let base = ss_case("ss-gost-peer", "aes-128-gcm", "pw", "", json!({}), Udp::No);
    let base_port = base.proxy["port"].as_u64().unwrap();
    let mut peer = start(Path::new(&mihomo), dir.path(), std::slice::from_ref(&base));
    wait_ready(&mut peer, std::slice::from_ref(&base)).await;
    let echo = tcp_echo().await;
    for (mux, tls, transport) in [
        (false, false, "ws"),
        (true, false, "mws"),
        (false, true, "wss"),
        (true, true, "mwss"),
    ] {
        let port = free_port();
        let listen = format!(
            "{transport}://127.0.0.1:{port}/127.0.0.1:{base_port}?path=/gost&cert={}&key={}",
            certs.cert.display(),
            certs.key.display()
        );
        let _gost = start_peer(Path::new(&gost), &listen, port, dir.path()).await;
        let node = outbound(proxy(
            "ss-gost",
            "ss",
            port,
            json!({"cipher":"aes-128-gcm", "password":"pw",
            "plugin":"gost-plugin", "plugin-opts":{"mode":"websocket", "host":"localhost", "path":"/gost", "mux":mux, "tls":tls, "skip-cert-verify":true}}),
        ));
        tcp_round_trip(node.as_ref(), &env(), echo)
            .await
            .unwrap_or_else(|error| panic!("{transport}: {error}"));
        println!("gost-plugin {transport}: TCP 5/3000/200000 bytes passed");
    }
}
