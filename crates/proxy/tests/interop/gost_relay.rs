use super::gost::{outbound, start_peer};
use super::*;

#[tokio::test]
#[ignore = "needs CONCORD_GOST3 (gost v3)"]
async fn gost_relay_round_trips_with_upstream_gost() {
    let gost = concord_test_support::peer("CONCORD_GOST3");
    let dir = tempfile::tempdir().unwrap();
    let certs = certs(dir.path());
    let echo = tcp_echo().await;
    let udp_echo = udp_echo().await;
    for (mux, tls, transport) in [
        (false, false, "tcp"),
        (true, false, "mtcp"),
        (false, true, "tls"),
        (true, true, "mtls"),
    ] {
        for forward in [false, true] {
            for udp in [false, true] {
                let port = free_port();
                let target = if udp { udp_echo } else { echo };
                let remote = if forward {
                    format!("/{target}")
                } else {
                    String::new()
                };
                let listen = format!(
                    "relay+{transport}://user:password@127.0.0.1:{port}{remote}?nodelay=true&mux.version=1&certFile={}&keyFile={}",
                    certs.cert.display(),
                    certs.key.display()
                );
                let _gost = start_peer(Path::new(&gost), &listen, port, dir.path()).await;
                let node = outbound(proxy(
                    "relay",
                    "gost-relay",
                    port,
                    json!({"username":"user", "password":"password",
                    "forward":forward, "tls":tls, "mux":mux, "sni":"localhost", "skip-cert-verify":true}),
                ));
                let env = env();
                let result = if udp {
                    udp_round_trip(node.as_ref(), &env, &[target]).await
                } else {
                    tcp_round_trip(node.as_ref(), &env, target).await
                };
                result.unwrap_or_else(|error| {
                    panic!("gost relay {transport} forward={forward} udp={udp}: {error}")
                });
                println!("gost-relay {transport} forward={forward} udp={udp}: passed");
            }
        }
    }
}
