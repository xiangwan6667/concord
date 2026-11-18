use std::time::Duration;

use serde_json::json;

use super::{Case, Certs, Udp, case};

fn snell_case(
    name: &str,
    version: u32,
    udp: bool,
    listener_extra: &str,
    extra: serde_json::Value,
) -> Case {
    let psk = if version == 6 {
        "snell-v6-test-psk-0123456789"
    } else {
        "snell-psk"
    };
    let body = format!("    psk: {psk}\n    version: {version}\n    udp: {udp}\n{listener_extra}");
    let mut proxy = json!({"psk": psk, "version": version, "udp": udp});
    if let (Some(base), Some(more)) = (proxy.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    case(
        name,
        "snell",
        "snell",
        &body,
        proxy,
        if udp { Udp::Many } else { Udp::No },
    )
}

fn snell_shadowtls_case(name: &str, snell: u32, version: u8, certs: &Certs) -> Case {
    let decoy_port = super::free_port();
    let decoy = super::listener(
        &format!("{name}-decoy"),
        "http",
        decoy_port,
        &super::tls_lines(certs),
    );
    let listener_extra = format!(
        "    shadow-tls:\n      enable: true\n      version: {version}\n      password: st-pw\n      users:\n        - name: u\n          password: st-pw\n      handshake:\n        dest: 127.0.0.1:{decoy_port}\n"
    );
    let obfs = json!({"obfs-opts": {
        "mode": "shadow-tls", "host": "localhost", "password": "st-pw", "version": version,
        "skip-cert-verify": true}});
    let mut made = snell_case(name, snell, snell >= 3, &listener_extra, obfs);
    made.listener = format!("{decoy}{}", made.listener);
    made
}

fn shadowquic_case(name: &str, listener_extra: &str, client_extra: serde_json::Value) -> Case {
    let body = format!(
        "    users:\n      - username: sq-user\n        password: sq-pass\n    jls-upstream:\n      addr: 127.0.0.1:9\n      sni: localhost\n{listener_extra}"
    );
    let client = super::merge(
        json!({"username": "sq-user", "password": "sq-pass", "sni": "localhost"}),
        client_extra,
    );
    case(name, "shadowquic", "shadowquic", &body, client, Udp::Many)
}

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn field(number: u64, value: u64, out: &mut Vec<u8>) {
    varint(number << 3, out);
    varint(value, out);
}

fn message(number: u64, inner: &[u8], out: &mut Vec<u8>) {
    varint(number << 3 | 2, out);
    varint(inner.len() as u64, out);
    out.extend_from_slice(inner);
}

fn traffic_pattern(low_mode: u64, rotation: u64, fragment: bool, nonce: u64) -> String {
    use base64::Engine;
    let mut pattern = Vec::new();
    field(1, 77, &mut pattern);
    let mut sub = Vec::new();
    field(1, u64::from(fragment), &mut sub);
    field(2, 3, &mut sub);
    message(3, &sub, &mut pattern);
    let mut sub = Vec::new();
    field(1, nonce, &mut sub);
    field(3, 4, &mut sub);
    field(4, 9, &mut sub);
    message(4, &sub, &mut pattern);
    let mut sub = Vec::new();
    field(1, 120, &mut sub);
    field(2, 200, &mut sub);
    message(5, &sub, &mut pattern);
    let mut sub = Vec::new();
    field(1, low_mode, &mut sub);
    field(2, rotation, &mut sub);
    message(6, &sub, &mut pattern);
    base64::engine::general_purpose::STANDARD.encode(pattern)
}

fn mieru_case(
    name: &str,
    listener_extra: &str,
    client_extra: serde_json::Value,
    ports: Option<(u16, u16)>,
) -> Case {
    mieru_case_on("TCP", name, listener_extra, client_extra, ports)
}

fn mieru_case_on(
    transport: &str,
    name: &str,
    listener_extra: &str,
    client_extra: serde_json::Value,
    ports: Option<(u16, u16)>,
) -> Case {
    let body = format!(
        "    transport: {transport}\n    users:\n      mieru-user: mieru-pass\n{listener_extra}"
    );
    let client = super::merge(
        json!({"transport": transport, "username": "mieru-user", "password": "mieru-pass"}),
        client_extra,
    );
    let Some((first, last)) = ports else {
        return case(name, "mieru", "mieru", &body, client, Udp::Many);
    };
    let mut made = case(name, "mieru", "mieru", &body, client, Udp::Many);
    made.listener = super::listener(name, "mieru", 0, &body)
        .replace("port: 0\n", &format!("port: {first}-{last}\n"));
    if let Some(proxy) = made.proxy.as_object_mut() {
        proxy.remove("port");
        proxy.insert("port-range".into(), json!(format!("{first}-{last}")));
    }
    made
}

fn nonce_every_packet(kind: u64, every: bool) -> String {
    use base64::Engine;
    let mut pattern = Vec::new();
    field(1, 91, &mut pattern);
    let mut sub = Vec::new();
    field(1, kind, &mut sub);
    field(2, u64::from(every), &mut sub);
    field(3, 5, &mut sub);
    field(4, 11, &mut sub);
    message(4, &sub, &mut pattern);
    let mut sub = Vec::new();
    field(1, 40, &mut sub);
    field(2, 60, &mut sub);
    message(5, &sub, &mut pattern);
    base64::engine::general_purpose::STANDARD.encode(pattern)
}

fn mieru_udp_cases() -> Vec<Case> {
    let udp = |name: &str, listener_extra: &str, client: serde_json::Value| {
        mieru_case_on("UDP", name, listener_extra, client, None)
    };
    let low = traffic_pattern(1, 0, false, 1);
    let low_wide = traffic_pattern(4, 15, false, 2);
    let every = nonce_every_packet(2, true);
    let first = nonce_every_packet(1, false);
    let range = loop {
        let first = super::free_port();
        let middle = super::free_port();
        let last = super::free_port();
        if middle == first + 1 && last == middle + 1 {
            break (first, last);
        }
    };
    vec![
        udp("mieru-udp-default", "", json!({})),
        udp(
            "mieru-udp-off",
            "",
            json!({"multiplexing": "MULTIPLEXING_OFF"}),
        ),
        udp(
            "mieru-udp-nowait",
            "",
            json!({"handshake-mode": "HANDSHAKE_NO_WAIT"}),
        ),
        udp(
            "mieru-udp-hint",
            "    user-hint-is-mandatory: true\n",
            json!({}),
        ),
        udp(
            "mieru-udp-low-32",
            &format!("    traffic-pattern: {low}\n"),
            json!({"traffic-pattern": low}),
        ),
        udp(
            "mieru-udp-low-56",
            &format!("    traffic-pattern: {low_wide}\n"),
            json!({"traffic-pattern": low_wide}),
        ),
        udp(
            "mieru-udp-nonce-all",
            &format!("    traffic-pattern: {every}\n"),
            json!({"traffic-pattern": every}),
        ),
        udp(
            "mieru-udp-nonce-first",
            &format!("    traffic-pattern: {first}\n"),
            json!({"traffic-pattern": first}),
        ),
        mieru_case_on("UDP", "mieru-udp-range", "", json!({}), Some(range)),
    ]
}

fn mieru_cases() -> Vec<Case> {
    let pattern = |mode, rotation, fragment, nonce| {
        let encoded = traffic_pattern(mode, rotation, fragment, nonce);
        (
            format!("    traffic-pattern: {encoded}\n"),
            json!({"traffic-pattern": encoded}),
        )
    };
    let (listener_1, client_1) = pattern(1, 0, false, 1);
    let (listener_2, client_2) = pattern(2, 5, true, 2);
    let (listener_3, client_3) = pattern(3, 32, false, 0);
    let (listener_4, client_4) = pattern(4, 15, false, 1);
    let range = loop {
        let first = super::free_port();
        let middle = super::free_port();
        let last = super::free_port();
        if middle == first + 1 && last == middle + 1 {
            break (first, last);
        }
    };
    vec![
        mieru_case("mieru-default", "", json!({}), None),
        mieru_case(
            "mieru-off",
            "",
            json!({"multiplexing": "MULTIPLEXING_OFF"}),
            None,
        ),
        mieru_case(
            "mieru-high",
            "",
            json!({"multiplexing": "MULTIPLEXING_HIGH"}),
            None,
        ),
        mieru_case(
            "mieru-nowait",
            "",
            json!({"handshake-mode": "HANDSHAKE_NO_WAIT"}),
            None,
        ),
        mieru_case(
            "mieru-hint",
            "    user-hint-is-mandatory: true\n",
            json!({}),
            None,
        ),
        mieru_case("mieru-low-32", &listener_1, client_1, None),
        mieru_case("mieru-low-40-fragment", &listener_2, client_2, None),
        mieru_case("mieru-low-48", &listener_3, client_3, None),
        mieru_case("mieru-low-56", &listener_4, client_4, None),
        mieru_case(
            "mieru-dialer-proxy",
            "",
            json!({"dialer-proxy": super::HOP}),
            None,
        ),
        mieru_case("mieru-range", "", json!({}), Some(range)),
    ]
    .into_iter()
    .chain(mieru_udp_cases())
    .collect()
}

// The server refuses to start with brutal on unless it is a Linux build with the tcp-brutal
// module or a `-tags debug` build, which only logs the failed setsockopt.
fn smux_brutal_cases() -> Vec<Case> {
    if std::env::var_os("CONCORD_BRUTAL_PEER").is_none() {
        return Vec::new();
    }
    let server = "    mux-option:\n      brutal:\n        enabled: true\n        up: 80 Mbps\n        down: 40 Mbps\n";
    ["h2mux", "smux", "yamux"]
        .into_iter()
        .map(|protocol| {
            super::ss_case(
                &format!("ss-smux-brutal-{protocol}"),
                "aes-128-gcm",
                "pw",
                server,
                json!({"smux": {"enabled": true, "protocol": protocol,
                    "brutal-opts": {"enabled": true, "up": "20 Mbps", "down": "100 Mbps"}}}),
                Udp::Many,
            )
        })
        .collect()
}

static ECH_LIST: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

pub(super) fn ech_list() -> Option<Vec<u8>> {
    ECH_LIST.get().cloned()
}

fn ech_keypair(certs: &Certs) -> Option<(String, String)> {
    let binary = std::env::var_os("CONCORD_MIHOMO")?;
    let out = std::process::Command::new(binary)
        .args(["generate", "ech-keypair", "ech.example.com"])
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let config = text
        .lines()
        .find_map(|line| line.strip_prefix("Config: "))?
        .to_string();
    let key = format!("{}\n", text.split_once("Key: ")?.1.trim_end());
    let list = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&config)
            .ok()?
    };
    let _ = ECH_LIST.set(list);
    let path = certs.cert.with_file_name("ech-key.pem");
    std::fs::write(&path, key).ok()?;
    Some((config, path.display().to_string()))
}

fn ech_cases(certs: &Certs) -> Vec<Case> {
    let Some((config, key)) = ech_keypair(certs) else {
        return Vec::new();
    };
    let ech = json!({"ech-opts": {"enable": true, "config": config}});
    let listener = format!("    ech-key: {key}\n");
    let by_name = json!({"ech-opts": {"enable": true, "query-server-name": "ech.example.com"}});
    let by_sni = json!({"ech-opts": {"enable": true}});
    vec![
        super::trojan_case(
            "ech-dns-trojan",
            by_name.clone(),
            Udp::Many,
            &listener,
            certs,
        ),
        super::trojan_case(
            "ech-dns-trojan-sni",
            by_sni.clone(),
            Udp::Many,
            &listener,
            certs,
        ),
        super::trojan_case(
            "ech-dns-trojan-chrome",
            super::merge(by_name.clone(), json!({"client-fingerprint": "chrome"})),
            Udp::Many,
            &listener,
            certs,
        ),
        super::anytls_case("ech-dns-anytls", by_name.clone(), &listener, certs),
        super::vless_case(
            "ech-dns-vless",
            super::merge(super::tls_client(), by_name.clone()),
            Udp::Many,
            "",
            &format!("{}{listener}", super::tls_lines(certs)),
        ),
        super::hy2_case("ech-dns-hy2", &listener, by_name.clone(), certs),
        super::hy2_case("ech-hy2", &listener, ech.clone(), certs),
        super::tuic_case("ech-dns-tuic", true, &listener, by_name, certs),
        super::tuic_case("ech-dns-tuic-sni", true, &listener, by_sni, certs),
        super::trojan_case("ech-trojan", ech.clone(), Udp::Many, &listener, certs),
        super::trojan_case(
            "ech-trojan-chrome",
            super::merge(ech.clone(), json!({"client-fingerprint": "chrome"})),
            Udp::Many,
            &listener,
            certs,
        ),
        super::anytls_case("ech-anytls", ech.clone(), &listener, certs),
        super::vless_case(
            "ech-vless",
            super::merge(super::tls_client(), ech.clone()),
            Udp::Many,
            "",
            &format!("{}{listener}", super::tls_lines(certs)),
        ),
        super::tuic_case("ech-tuic", true, &listener, ech, certs),
    ]
}

pub(super) fn cases(certs: &Certs) -> Vec<Case> {
    let obfs =
        |mode: &str| format!("    obfs-opts:\n      mode: {mode}\n      host: example.com\n");
    let mut all = mieru_cases();
    all.extend(ech_cases(certs));
    all.extend(smux_brutal_cases());
    all.extend(vec![
        shadowquic_case("sq-datagram", "", json!({})),
        shadowquic_case("sq-udp-over-stream", "", json!({"udp-over-stream": true})),
        shadowquic_case(
            "sq-bbr",
            "    congestion-controller: bbr\n",
            json!({"congestion-controller": "bbr", "cwnd": 16}),
        ),
        shadowquic_case(
            "sq-cubic",
            "",
            json!({"congestion-controller": "cubic", "disable-mtu-discovery": true}),
        ),
        shadowquic_case(
            "sq-new-reno-v1",
            "",
            json!({"congestion-controller": "new_reno", "quic-versions": ["v1", "v2"]}),
        ),
        shadowquic_case(
            "sq-brutal",
            "    up: 200 Mbps\n    down: 200 Mbps\n",
            json!({"up": "100 Mbps", "down": "100 Mbps"}),
        ),
        shadowquic_case(
            "sq-windows",
            "",
            json!({"recv-window-conn": 3_000_000, "recv-window": 9_000_000, "max-open-streams": 64,
                "max-datagram-frame-size": 1300, "keep-alive-interval": 2000, "zero-rtt": true}),
        ),
        shadowquic_case("sq-dialer-proxy", "", json!({"dialer-proxy": super::HOP})),
        snell_case("snell-v1", 1, false, "", json!({})),
        snell_case("snell-v2", 2, false, "", json!({})),
        snell_case("snell-v3", 3, true, "", json!({})),
        snell_case("snell-v4", 4, true, "", json!({})),
        snell_case("snell-v5", 5, true, "", json!({})),
        snell_case("snell-v6", 6, true, "", json!({"userkey":"alice-key"})),
        snell_case(
            "snell-v6-unshaped",
            6,
            true,
            "    mode: unshaped\n",
            json!({"mode":"unshaped","userkey":"alice-key"}),
        ),
        snell_case(
            "snell-v6-unsafe-raw",
            6,
            true,
            "    mode: unsafe-raw\n",
            json!({"mode":"unsafe-raw","userkey":"alice-key"}),
        ),
        snell_case(
            "snell-v6-reuse",
            6,
            true,
            "",
            json!({"reuse":true,"userkey":"alice-key"}),
        ),
        snell_case(
            "snell-v6-long-userkey",
            6,
            true,
            "",
            json!({"userkey":"a".repeat(255)}),
        ),
        snell_shadowtls_case("snell-v6-shadowtls-v2", 6, 2, certs),
        snell_shadowtls_case("snell-v6-shadowtls-v3", 6, 3, certs),
        snell_case("snell-v4-reuse", 4, true, "", json!({"reuse": true})),
        snell_case(
            "snell-v1-obfs-tls",
            1,
            false,
            &obfs("tls"),
            json!({"obfs-opts": {"mode": "tls", "host": "example.com"}}),
        ),
        snell_case(
            "snell-v3-obfs-http",
            3,
            true,
            &obfs("http"),
            json!({"obfs-opts": {"mode": "http", "host": "example.com"}}),
        ),
        snell_case(
            "snell-v4-obfs-tls",
            4,
            true,
            &obfs("tls"),
            json!({"obfs-opts": {"mode": "tls", "host": "example.com"}}),
        ),
        snell_shadowtls_case("snell-v4-shadowtls-v2", 4, 2, certs),
        snell_shadowtls_case("snell-v3-shadowtls-v3", 3, 3, certs),
        snell_shadowtls_case("snell-v2-shadowtls-v3", 2, 3, certs),
    ]);
    all
}

struct Reference {
    child: std::process::Child,
    port: u16,
}

impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_reference(binary: &str, certs: &super::Certs, args: &[&str]) -> Reference {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let mut child = Command::new(binary)
        .arg("-cert")
        .arg(&certs.cert)
        .arg("-key")
        .arg(&certs.key)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let port = line
        .trim()
        .strip_prefix("listening ")
        .and_then(|port| port.parse().ok())
        .unwrap_or_else(|| panic!("the reference server said {line:?}"));
    Reference { child, port }
}

async fn fragmented_udp(
    outbound: &dyn concord_common::Outbound,
    env: &concord_common::DialEnv,
    target: std::net::SocketAddr,
) -> Result<(), String> {
    use concord_common::{Address, DialCx, Initiator, PacketBuf, recv_packet, send_packet};

    let cx = DialCx::new(env, Initiator::Direct, None);
    let dst = Address::new(&target.ip().to_string(), target.port());
    let session = outbound
        .associate(&cx, &dst)
        .await
        .map_err(|err| format!("associate: {err}"))?;
    for size in [1100usize, 1300, 2500, 4000] {
        let data = super::pattern(size);
        let mut packet = PacketBuf::with_headroom(session.headroom());
        packet.extend_from_slice(&data);
        send_packet(&*session, &mut packet, &dst)
            .await
            .map_err(|err| format!("send {size}: {err}"))?;
        let (got, _) = tokio::time::timeout(Duration::from_secs(10), recv_packet(&*session))
            .await
            .map_err(|_| format!("no answer to {size} bytes"))?
            .map_err(|err| format!("recv {size}: {err}"))?;
        if got.as_slice() != data {
            return Err(format!("{size} byte datagram came back different"));
        }
    }
    Ok(())
}

/// The original hysteria 1 server (`apernet/hysteria` core v1.3.5), built into a
/// small program, is the peer: `CONCORD_HY1_SERVER=<path>`.
#[tokio::test]
#[ignore = "needs CONCORD_HY1_SERVER"]
async fn hysteria_talks_to_the_reference_server() {
    let binary = concord_test_support::peer("CONCORD_HY1_SERVER");
    let dir = tempfile::tempdir().unwrap();
    let certs = super::certs(dir.path());
    let echo = super::tcp_echo().await;
    let (udp_a, udp_b) = (super::udp_echo().await, super::udp_echo().await);
    let env = super::env();
    let ctx = concord_proxy::BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new()));
    let filter = std::env::var("CONCORD_CASE").ok();

    let variants: Vec<(&str, Vec<&str>, serde_json::Value)> = vec![
        ("hy1-plain", vec![], json!({})),
        ("hy1-fast-open", vec![], json!({"fast-open": true})),
        (
            "hy1-obfs",
            vec!["-obfs", "xplus-pw"],
            json!({"obfs": "xplus-pw"}),
        ),
        (
            "hy1-wechat",
            vec!["-protocol", "wechat-video"],
            json!({"protocol": "wechat-video"}),
        ),
        (
            "hy1-wechat-obfs",
            vec!["-protocol", "wechat-video", "-obfs", "xplus-pw"],
            json!({"obfs-protocol": "wechat-video", "obfs": "xplus-pw"}),
        ),
        (
            "hy1-auth-base64",
            vec!["-auth", "base64-secret"],
            json!({"auth": "YmFzZTY0LXNlY3JldA=="}),
        ),
        (
            "hy1-speed-override",
            vec![],
            json!({"up-speed": 20, "down-speed": 20, "recv-window": 8_000_000, "recv-window-conn": 2_000_000}),
        ),
        (
            "hy1-no-mtu-discovery",
            vec![],
            json!({"disable-mtu-discovery": true}),
        ),
        (
            "hy1-dialer-proxy",
            vec![],
            json!({"dialer-proxy": super::HOP}),
        ),
    ];
    let mut failures = Vec::new();
    for (name, args, extra) in variants {
        if filter.as_deref().is_some_and(|only| !name.contains(only)) {
            continue;
        }
        let server = spawn_reference(&binary, &certs, &args);
        let mut proxy = json!({
            "name": name, "type": "hysteria", "server": "127.0.0.1", "port": server.port,
            "up": "100", "down": "100", "auth-str": "hy1-auth", "sni": "localhost",
            "skip-cert-verify": true, "udp": true,
        });
        proxy = super::merge(proxy, extra);
        let Some(map) = proxy.as_object() else {
            continue;
        };
        let def = match concord_config::parse_proxy(map, &concord_config::Capabilities::full()) {
            Ok(concord_config::ProxyParse::Ok(def)) => def,
            other => {
                failures.push(format!("{name}: config: {}", other.is_ok()));
                continue;
            }
        };
        let outbound = match concord_proxy::build_outbound(&def, &ctx) {
            Ok(outbound) => outbound,
            Err(err) => {
                failures.push(format!("{name}: build: {err}"));
                continue;
            }
        };
        let mut notes = Vec::new();
        if let Err(err) = super::tcp_round_trip(&*outbound, &env, echo).await {
            notes.push(format!("tcp {err}"));
        }
        if let Err(err) = super::udp_round_trip(&*outbound, &env, &[udp_a, udp_b]).await {
            notes.push(format!("udp {err}"));
        }
        if let Err(err) = fragmented_udp(&*outbound, &env, udp_a).await {
            notes.push(format!("fragmented udp {err}"));
        }
        println!(
            "{name:<22} {}",
            if notes.is_empty() {
                "ok".to_string()
            } else {
                notes.join("; ")
            }
        );
        if !notes.is_empty() {
            failures.push(format!("{name}: {}", notes.join("; ")));
        }
    }
    let server = spawn_reference(&binary, &certs, &[]);
    let wrong = json!({
        "name": "hy1-wrong-auth", "type": "hysteria", "server": "127.0.0.1", "port": server.port,
        "up": "100", "down": "100", "auth-str": "nope", "sni": "localhost", "skip-cert-verify": true,
    });
    if let Some(map) = wrong.as_object()
        && let Ok(concord_config::ProxyParse::Ok(def)) =
            concord_config::parse_proxy(map, &concord_config::Capabilities::full())
        && let Ok(outbound) = concord_proxy::build_outbound(&def, &ctx)
    {
        let cx = concord_common::DialCx::new(&env, concord_common::Initiator::Direct, None);
        let dst = concord_common::Address::new("127.0.0.1", echo.port());
        match outbound.connect(&cx, &dst).await {
            Err(err) if format!("{err:?}").contains("auth error") => {}
            other => failures.push(format!("wrong auth: {:?}", other.err())),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A wrong password gets no answer from the JLS server, so the dial never completes.
#[tokio::test]
#[ignore = "needs CONCORD_MIHOMO"]
async fn shadowquic_with_a_wrong_password_does_not_connect() {
    let binary = std::env::var("CONCORD_MIHOMO").expect("CONCORD_MIHOMO is not set");
    let dir = tempfile::tempdir().unwrap();
    let cases = vec![
        shadowquic_case("sq-good", "", json!({"password": "wrong"})),
        super::case("http-open", "http", "http", "", json!({}), Udp::No),
    ];
    let mut mihomo = super::start(std::path::Path::new(&binary), dir.path(), &cases);
    super::wait_ready(&mut mihomo, &cases).await;
    let env = super::env();
    let ctx = concord_proxy::BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new()));
    let map = cases[0].proxy.as_object().unwrap();
    let Ok(concord_config::ProxyParse::Ok(def)) =
        concord_config::parse_proxy(map, &concord_config::Capabilities::full())
    else {
        panic!("the proxy did not parse");
    };
    let outbound = concord_proxy::build_outbound(&def, &ctx).unwrap();
    let cx = concord_common::DialCx::new(&env, concord_common::Initiator::Direct, None);
    let dialed = tokio::time::timeout(
        Duration::from_secs(4),
        outbound.connect(&cx, &concord_common::Address::new("127.0.0.1", 9)),
    )
    .await;
    assert!(!matches!(dialed, Ok(Ok(_))), "a wrong password connected");
}

#[tokio::test]
#[ignore = "needs CONCORD_MIHOMO"]
async fn mieru_transports_move_bulk_data() {
    use std::path::Path;
    use std::time::Instant;

    use concord_common::{Address, DialCx, Initiator};
    use concord_config::{Capabilities, ProxyParse, parse_proxy};
    use concord_proxy::{BuildCtx, build_outbound};
    use concord_tls::TrustStore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let binary = std::env::var("CONCORD_MIHOMO").expect("CONCORD_MIHOMO is not set");
    let megabytes: usize = std::env::var("CONCORD_BULK_MB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(32);
    let dir = tempfile::tempdir().unwrap();
    let cases = vec![
        mieru_case_on("UDP", "bulk-udp", "", json!({}), None),
        mieru_case("bulk-tcp", "", json!({}), None),
    ];
    let mut mihomo = super::start(Path::new(&binary), dir.path(), &cases);
    super::wait_ready(&mut mihomo, &cases).await;
    let echo = super::tcp_echo().await;
    let env = super::env();
    let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
    let data = super::pattern(megabytes << 20);
    let sink = bulk_sink(data.len()).await;
    let source = bulk_source(data.clone()).await;
    for case in &cases {
        let map = case.proxy.as_object().unwrap();
        let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
            panic!("{} does not parse", case.name);
        };
        let outbound = build_outbound(&def, &ctx).unwrap();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let mut stream = outbound
            .connect(&cx, &Address::new(&echo.ip().to_string(), echo.port()))
            .await
            .unwrap();
        let started = Instant::now();
        let (mut read, mut write) = tokio::io::split(&mut stream);
        let writer = async {
            write.write_all(&data).await?;
            write.flush().await
        };
        let reader = async {
            let mut got = vec![0u8; data.len()];
            read.read_exact(&mut got).await?;
            Ok::<_, std::io::Error>(got)
        };
        let (written, got) = tokio::time::timeout(Duration::from_secs(120), async {
            tokio::join!(writer, reader)
        })
        .await
        .unwrap_or_else(|_| panic!("{} timed out", case.name));
        written.unwrap();
        assert!(got.unwrap() == data, "{} echoed different bytes", case.name);
        let secs = started.elapsed().as_secs_f64();
        println!(
            "{:<10} {megabytes} MiB each way in {secs:.2} s: {:.1} MiB/s per direction",
            case.name,
            megabytes as f64 / secs
        );
        drop(stream);

        let mut upload = outbound
            .connect(&cx, &Address::new(&sink.ip().to_string(), sink.port()))
            .await
            .unwrap();
        let started = Instant::now();
        upload.write_all(&data).await.unwrap();
        upload.flush().await.unwrap();
        let mut done = [0u8; 1];
        upload.read_exact(&mut done).await.unwrap();
        let secs = started.elapsed().as_secs_f64();
        println!(
            "{:<10} upload   {megabytes} MiB in {secs:.2} s: {:.1} MiB/s",
            case.name,
            megabytes as f64 / secs
        );
        drop(upload);

        let mut download = outbound
            .connect(&cx, &Address::new(&source.ip().to_string(), source.port()))
            .await
            .unwrap();
        let started = Instant::now();
        let mut got = vec![0u8; data.len()];
        download.read_exact(&mut got).await.unwrap();
        let secs = started.elapsed().as_secs_f64();
        assert!(got == data, "{} sent different bytes", case.name);
        println!(
            "{:<10} download {megabytes} MiB in {secs:.2} s: {:.1} MiB/s",
            case.name,
            megabytes as f64 / secs
        );
    }
}

async fn bulk_sink(size: usize) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut left = size;
                let mut buf = vec![0u8; 64 * 1024];
                while left > 0 {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => left -= n.min(left),
                    }
                }
                let _ = conn.write_all(&[1]).await;
            });
        }
    });
    addr
}

async fn bulk_source(data: Vec<u8>) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let data = std::sync::Arc::new(data);
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let data = data.clone();
            tokio::spawn(async move {
                let _ = conn.write_all(&data).await;
                let _ = conn.flush().await;
                let mut hold = [0u8; 1];
                let _ = conn.read(&mut hold).await;
            });
        }
    });
    addr
}
