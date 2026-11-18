use super::*;

struct Xray {
    child: Child,
    log: PathBuf,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(binary: &Path, dir: &Path, certs: &Certs, port: u16) -> Xray {
    let config = json!({
        "log": {"loglevel": "info"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"},
            "streamSettings": {
                "network": "xhttp", "security": "tls",
                "tlsSettings": {"alpn": ["h3"], "certificates": [{
                    "certificateFile": certs.cert, "keyFile": certs.key
                }]},
                "xhttpSettings": {"path": "/xh", "mode": "auto"}
            }
        }],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
    });
    let path = dir.join("xray.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let log = dir.join("xray.log");
    let out = std::fs::File::create(&log).unwrap();
    let child = Command::new(binary)
        .arg("run")
        .arg("-config")
        .arg(path)
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .unwrap();
    Xray { child, log }
}

async fn wait(peer: &mut Xray) {
    for _ in 0..100 {
        let log = std::fs::read_to_string(&peer.log).unwrap_or_default();
        if let Some(status) = peer.child.try_wait().unwrap() {
            panic!("Xray exited {status}: {log}");
        }
        if log.contains("listening QUIC for XHTTP/3") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "Xray did not listen: {}",
        std::fs::read_to_string(&peer.log).unwrap()
    );
}

#[tokio::test]
#[ignore = "needs CONCORD_XRAY"]
async fn xhttp_h3_talks_to_xray_in_all_three_modes() {
    let binary = concord_test_support::peer("CONCORD_XRAY");
    let dir = tempfile::tempdir().unwrap();
    let certs = certs(dir.path());
    let port = free_port();
    let mut peer = start(Path::new(&binary), dir.path(), &certs, port);
    wait(&mut peer).await;
    let echo = tcp_echo().await;
    let front = super::xray_front::start(port).await;
    for (mode, mixed) in [
        ("stream-one", false),
        ("stream-up", false),
        ("packet-up", false),
        ("stream-up", true),
        ("packet-up", true),
    ] {
        let mut node = proxy(
            "xray-h3",
            "vless",
            port,
            json!({
                "uuid": UUID, "tls": true, "servername": "localhost", "skip-cert-verify": true,
                "alpn": ["h3"], "network": "xhttp", "xhttp-opts": {"path": "/xh", "mode": mode}
            }),
        );
        if mixed {
            node["xhttp-opts"]["download-settings"] = json!({
                "server": "127.0.0.1", "port": front.port, "tls": false, "alpn": ["h2"]
            });
        }
        let ProxyParse::Ok(def) =
            parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap()
        else {
            panic!("quarantined");
        };
        let outbound = build_outbound(&def, &BuildCtx::new(TrustStore::new(b"", vec![]))).unwrap();
        let result = tcp_round_trip(&*outbound, &env(), echo).await;
        assert!(
            result.is_ok(),
            "{mode} mixed_h2={mixed}: {result:?}\n{}",
            std::fs::read_to_string(&peer.log).unwrap()
        );
        println!("xray-h3 {mode} mixed_h2={mixed}: ok");
        outbound.reset_sessions();
    }
}
