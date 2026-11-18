//! One outbound per protocol and the listener that serves it. Listener and
//! client fields follow `crates/proxy/tests/interop.rs`.

use std::path::Path;

use serde_json::{Value, json};

#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub name: &'static str,
    pub udp: bool,
    pub about: &'static str,
}

pub const ALL: &[Spec] = &[
    spec(
        "direct",
        true,
        "no outbound protocol: the inbound, router and relay alone",
    ),
    spec(
        "rematch",
        true,
        "rematch name and sub-rule routing before DIRECT",
    ),
    spec("ss-aes128", true, "shadowsocks aes-128-gcm"),
    spec("gost-relay", true, "gost relay with authentication"),
    spec(
        "ss-gost",
        false,
        "shadowsocks aes-128-gcm over gost WebSocket and smux v1",
    ),
    spec("ss-chacha", true, "shadowsocks chacha20-ietf-poly1305"),
    spec("ss-chacha20", true, "shadowsocks djb chacha20"),
    spec("ss-xchacha20", true, "shadowsocks xchacha20 stream"),
    spec(
        "trojan-ss-chacha20",
        true,
        "trojan with djb chacha20 ss-opts",
    ),
    spec("trojan-ss-xchacha20", true, "trojan with xchacha20 ss-opts"),
    spec("ss2022", true, "shadowsocks 2022-blake3-aes-128-gcm"),
    spec(
        "ss2022-chacha8",
        true,
        "shadowsocks 2022-blake3-chacha8-poly1305",
    ),
    spec("vmess", true, "vmess aes-128-gcm, alterId 0"),
    spec("vmess-cfb", true, "vmess aes-128-cfb, alterId 0"),
    spec("vmess-chacha", true, "vmess chacha20-poly1305, alterId 0"),
    spec("vmess-none", true, "vmess unencrypted body, alterId 0"),
    spec(
        "vmess-ws-tls",
        false,
        "vmess aes-128-gcm over WebSocket and TLS",
    ),
    spec(
        "vmess-grpc-tls",
        false,
        "vmess aes-128-gcm over gRPC and TLS",
    ),
    spec("vless-tls", true, "vless over TLS"),
    spec("vless-jls", true, "vless over TCP JLS"),
    spec(
        "vless-encryption",
        true,
        "VLESS ML-KEM-768 + X25519 encryption, 1-RTT",
    ),
    spec(
        "vless-encryption-0rtt",
        true,
        "VLESS ML-KEM-768 + X25519 encryption, ticket resumption",
    ),
    spec(
        "vless-xhttp-packet-up",
        false,
        "vless XHTTP packet-up over HTTP/2",
    ),
    spec(
        "vless-xhttp-stream-up",
        false,
        "vless XHTTP stream-up over HTTP/2",
    ),
    spec(
        "vless-xhttp-stream-one",
        false,
        "vless XHTTP stream-one over HTTP/2",
    ),
    spec(
        "vless-xhttp-h3-stream-one",
        false,
        "vless XHTTP stream-one over HTTP/3 (CONCORD_XRAY server)",
    ),
    spec(
        "vless-xhttp-h3-stream-up",
        false,
        "vless XHTTP stream-up over HTTP/3 (CONCORD_XRAY server)",
    ),
    spec(
        "vless-xhttp-h3-packet-up",
        false,
        "vless XHTTP packet-up over HTTP/3 (CONCORD_XRAY server)",
    ),
    spec(
        "ss-smux-h2mux",
        true,
        "shadowsocks aes-128-gcm with sing h2mux",
    ),
    spec("trojan-tls", true, "trojan over TLS"),
    spec(
        "trojan-shadowtls",
        true,
        "trojan with ShadowTLS v3 in place of TLS",
    ),
    spec(
        "trojan-chrome",
        false,
        "trojan over TLS with the chrome client fingerprint (BoringSSL)",
    ),
    spec("anytls", true, "anytls"),
    spec("hysteria2", true, "hysteria2 over QUIC"),
    spec(
        "hysteria-brutal",
        true,
        "hysteria v1, Brutal at 100 Mbit/s (needs --sing-box)",
    ),
    spec("hysteria2-brutal", true, "hysteria2, Brutal at 100 Mbit/s"),
    spec(
        "shadowquic-brutal",
        true,
        "shadowquic, Brutal at 100 Mbit/s",
    ),
    spec("tuic", true, "tuic v5 over QUIC"),
    spec(
        "masque-l4",
        false,
        "MASQUE H3 L4 proxy over a local QUIC peer",
    ),
    spec(
        "snell",
        false,
        "snell v4; mihomo's listener stalls some flows",
    ),
    spec("snell-v6", true, "snell v6 with the default profile"),
    spec(
        "snell-v6-unshaped",
        true,
        "snell v6 without traffic shaping",
    ),
    spec(
        "snell-v6-unsafe-raw",
        true,
        "snell v6 without encryption or shaping",
    ),
    spec("mieru-tcp", false, "mieru over TCP"),
];

pub const QUICK: &[&str] = &[
    "direct",
    "ss-aes128",
    "trojan-tls",
    "vmess-grpc-tls",
    "hysteria2",
];

const fn spec(name: &'static str, udp: bool, about: &'static str) -> Spec {
    Spec { name, udp, about }
}

pub fn find(name: &str) -> Option<Spec> {
    ALL.iter().copied().find(|s| s.name == name)
}

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const TUIC_UUID: &str = "b3f1a6d2-5c0e-4a11-9c43-7e2d8f6a0b15";
const KEY16: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";
const KEY32: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

pub struct Case {
    pub spec: Spec,
    /// The mihomo `listeners:` entry; absent for DIRECT, rematch and sing-box-served Hysteria v1.
    pub listener: Option<String>,
    pub singbox_listener: Option<Value>,
    pub xray_listener: Option<Value>,
    pub proxy: Option<Value>,
    pub gost: Option<(&'static str, String)>,
}

impl Case {
    pub fn name(&self) -> &'static str {
        self.spec.name
    }

    pub fn rule_target(&self) -> &str {
        if self.proxy.is_some() {
            self.spec.name
        } else {
            "DIRECT"
        }
    }
}

/// The case needs a second listener: the TLS server its handshake is relayed to.
pub fn needs_decoy(spec: Spec) -> bool {
    spec.name == "trojan-shadowtls"
}

pub fn build(spec: Spec, host: &str, port: u16, decoy: u16, certs: &Path) -> Case {
    let tls = format!(
        "    certificate: {}\n    private-key: {}\n",
        certs.join("cert.pem").display(),
        certs.join("key.pem").display()
    );
    let insecure = json!({"sni": "localhost", "skip-cert-verify": true});
    if let Some(mode) = spec.name.strip_prefix("vless-xhttp-h3-") {
        return Case {
            spec,
            listener: None,
            gost: None,
            singbox_listener: None,
            xray_listener: Some(json!({
                "listen": host, "port": port, "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": {"network": "xhttp", "security": "tls",
                    "tlsSettings": {"alpn": ["h3"], "certificates": [{"certificateFile": certs.join("cert.pem"), "keyFile": certs.join("key.pem")}]},
                    "xhttpSettings": {"path": "/xh", "mode": "auto"}}
            })),
            proxy: Some(
                json!({"name": spec.name, "type": "vless", "server": host, "port": port,
                "uuid": UUID, "tls": true, "servername": "localhost", "skip-cert-verify": true,
                "network": "xhttp", "alpn": ["h3"], "xhttp-opts": {"path": "/xh", "mode": mode}}),
            ),
        };
    }
    if spec.name == "rematch" {
        return Case {
            spec,
            listener: None,
            gost: None,
            singbox_listener: None,
            xray_listener: None,
            proxy: Some(
                json!({"name": spec.name, "type": "rematch", "target-rematch-name": "bench", "target-sub-rule": "bench-rematch"}),
            ),
        };
    }
    if spec.name == "masque-l4" {
        // Public test keys; the local benchmark peer does not request client authentication.
        return Case {
            spec,
            listener: None,
            gost: None,
            singbox_listener: None,
            xray_listener: None,
            proxy: Some(
                json!({"name":spec.name,"type":"masque","server":host,"port":port,
                "network":"h3-l4proxy", "private-key":"MHcCAQEEIIv8E335vR4FW1LFLLzFZYMueRGUm5fHUPlx0KCzPu23oAoGCCqGSM49AwEHoUQDQgAEd3X4sHYlzsLE8QDt31G5xCXnaY4+1L7dHARLSuUbcuFTRwyFFmwAnH5A2jwjs1A/HHd1yP28nuFTMXWKdgQh2A==",
                "public-key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd3X4sHYlzsLE8QDt31G5xCXnaY4+1L7dHARLSuUbcuFTRwyFFmwAnH5A2jwjs1A/HHd1yP28nuFTMXWKdgQh2A==", "skip-cert-verify":true, "sni":"localhost"}),
            ),
        };
    }
    if spec.name == "hysteria-brutal" {
        return Case {
            spec,
            listener: None,
            xray_listener: None,
            gost: None,
            singbox_listener: Some(json!({
                "type": "hysteria", "tag": spec.name, "listen": host, "listen_port": port,
                "up_mbps": 100, "down_mbps": 100,
                "users": [{"name": "bench", "auth_str": "hy1-pw"}],
                "tls": {"enabled": true, "alpn": ["hysteria"],
                    "certificate_path": certs.join("cert.pem"), "key_path": certs.join("key.pem")}
            })),
            proxy: Some(json!({
                "name": spec.name, "type": "hysteria", "server": host, "port": port,
                "udp": true, "auth-str": "hy1-pw", "up": "100", "down": "100",
                "sni": "localhost", "skip-cert-verify": true
            })),
        };
    }
    if spec.name == "gost-relay" {
        return Case {
            spec,
            listener: None,
            xray_listener: None,
            singbox_listener: None,
            gost: Some((
                "CONCORD_GOST3",
                format!("relay://user:password@{host}:{port}?nodelay=true"),
            )),
            proxy: Some(
                json!({"name":spec.name, "type":"gost-relay", "server":host, "port":port,
                "username":"user", "password":"password", "udp":true}),
            ),
        };
    }
    if spec.name == "ss-gost" {
        return Case {
            spec,
            listener: None,
            xray_listener: None,
            singbox_listener: None,
            gost: Some((
                "CONCORD_GOST2",
                format!("ss+mws://aes-128-gcm:pw@{host}:{port}?path=/gost"),
            )),
            proxy: Some(
                json!({"name":spec.name, "type":"ss", "server":host, "port":port,
                "cipher":"aes-128-gcm", "password":"pw", "plugin":"gost-plugin",
                "plugin-opts":{"mode":"websocket", "host":"localhost", "path":"/gost"}}),
            ),
        };
    }
    let ss = |cipher: &str, password: &str| {
        (
            "ss",
            "shadowsocks",
            format!("    password: {password}\n    cipher: {cipher}\n    udp: true\n"),
            json!({"cipher": cipher, "password": password}),
        )
    };
    let trojan = |extra: Value| {
        (
            "trojan",
            "trojan",
            format!("    users:\n      - username: a\n        password: trojan-pw\n{tls}"),
            merge(merge(json!({"password": "trojan-pw"}), &insecure), &extra),
        )
    };
    let (kind, listener_kind, body, extra) = match spec.name {
        "ss-aes128" => ss("aes-128-gcm", "pw"),
        "ss-chacha" => ss("chacha20-ietf-poly1305", "pw"),
        "ss-chacha20" => ss("chacha20", "pw"),
        "ss-xchacha20" => ss("xchacha20", "pw"),
        "ss2022" => ss("2022-blake3-aes-128-gcm", KEY16),
        "ss2022-chacha8" => ss("2022-blake3-chacha8-poly1305", KEY32),
        "vmess" | "vmess-cfb" | "vmess-chacha" | "vmess-none" => (
            "vmess",
            "vmess",
            format!("    users:\n      - username: a\n        uuid: {UUID}\n        alterId: 0\n"),
            json!({"uuid": UUID, "alterId": 0, "cipher": match spec.name {
                "vmess-cfb" => "aes-128-cfb",
                "vmess-chacha" => "chacha20-poly1305",
                "vmess-none" => "none",
                _ => "aes-128-gcm",
            }}),
        ),
        "vmess-ws-tls" => (
            "vmess",
            "vmess",
            format!(
                "    users:\n      - username: a\n        uuid: {UUID}\n        alterId: 0\n    ws-path: /vm\n{tls}"
            ),
            json!({"uuid": UUID, "alterId": 0, "cipher": "aes-128-gcm", "tls": true, "servername": "localhost", "skip-cert-verify": true, "network": "ws", "ws-opts": {"path": "/vm"}}),
        ),
        "vmess-grpc-tls" => (
            "vmess",
            "vmess",
            format!(
                "    users:\n      - username: a\n        uuid: {UUID}\n        alterId: 0\n    grpc-service-name: gun\n{tls}"
            ),
            json!({"uuid": UUID, "alterId": 0, "cipher": "aes-128-gcm", "tls": true, "servername": "localhost", "skip-cert-verify": true, "network": "grpc", "grpc-opts": {"grpc-service-name": "gun"}}),
        ),
        "vless-jls" => (
            "vless",
            "vless",
            format!(
                "    users:\n      - username: a\n        uuid: {UUID}\n    jls-config:\n      enable: true\n      sni: localhost\n      dest: 127.0.0.1:9\n      users:\n        - username: name\n          password: secret\n"
            ),
            json!({"uuid": UUID, "tls": true, "servername": "localhost", "jls-opts": {"username": "name", "password": "secret"}}),
        ),
        "vless-tls" => (
            "vless",
            "vless",
            format!("    users:\n      - username: a\n        uuid: {UUID}\n{tls}"),
            json!({"uuid": UUID, "tls": true, "servername": "localhost", "skip-cert-verify": true}),
        ),
        "vless-encryption" | "vless-encryption-0rtt" => {
            let rtt = if spec.name.ends_with("0rtt") {
                "0rtt"
            } else {
                "1rtt"
            };
            (
                "vless",
                "vless",
                format!(
                    "    users:\n      - username: a\n        uuid: {UUID}\n    decryption: mlkem768x25519plus.native.600s.4FPB64XuuLf_4rH6cRUelA49KX6LfpmlVNKDKuionHo\n"
                ),
                json!({"uuid": UUID, "encryption": format!("mlkem768x25519plus.native.{rtt}.gnP8rteYQcQdsEDGFqm53nwdrL6HcBB6tZ4hd1c7nh4")}),
            )
        }
        "vless-xhttp-packet-up" | "vless-xhttp-stream-up" | "vless-xhttp-stream-one" => {
            let mode = spec.name.strip_prefix("vless-xhttp-").unwrap();
            (
                "vless",
                "vless",
                format!(
                    "    users:\n      - username: a\n        uuid: {UUID}\n    xhttp-config:\n      path: /xh\n      mode: {mode}\n{tls}"
                ),
                json!({"uuid": UUID, "tls": true, "servername": "localhost", "skip-cert-verify": true, "network": "xhttp", "alpn": ["h2"], "xhttp-opts": {"path": "/xh", "mode": mode}}),
            )
        }
        "ss-smux-h2mux" => {
            let (kind, listener_kind, body, extra) = ss("aes-128-gcm", "pw");
            (
                kind,
                listener_kind,
                body,
                merge(extra, &json!({"smux": {"enabled": true}})),
            )
        }
        "trojan-tls" => trojan(json!({})),
        "trojan-ss-chacha20" | "trojan-ss-xchacha20" => {
            let method = if spec.name == "trojan-ss-chacha20" {
                "CHACHA20"
            } else {
                "XCHACHA20"
            };
            let (kind, listener, mut body, extra) = trojan(json!({"ss-opts": {
                "enabled": true, "method": method, "password": "ss-pw"
            }}));
            body.push_str(&format!("    ss-option:\n      enabled: true\n      method: {method}\n      password: ss-pw\n"));
            (kind, listener, body, extra)
        }
        "trojan-chrome" => trojan(json!({"client-fingerprint": "chrome"})),
        "trojan-shadowtls" => (
            "trojan",
            "trojan",
            format!(
                "    users:\n      - username: a\n        password: trojan-pw\n    shadow-tls:\n      enable: true\n      version: 3\n      users:\n        - name: u\n          password: st-pw\n      handshake:\n        dest: {host}:{decoy}\n  - name: trojan-shadowtls-decoy\n    type: http\n    listen: {host}\n    port: {decoy}\n{tls}"
            ),
            merge(
                json!({"password": "trojan-pw", "shadow-tls-opts": {"password": "st-pw", "version": 3}}),
                &insecure,
            ),
        ),
        "anytls" => (
            "anytls",
            "anytls",
            format!("    users:\n      user: anytls-pw\n{tls}"),
            merge(json!({"password": "anytls-pw"}), &insecure),
        ),
        "hysteria2" => (
            "hysteria2",
            "hysteria2",
            format!("    users:\n      user: hy2-pw\n{tls}"),
            merge(json!({"password": "hy2-pw"}), &insecure),
        ),
        "hysteria2-brutal" => (
            "hysteria2",
            "hysteria2",
            format!("    users:\n      user: hy2-pw\n    up: 100\n    down: 100\n{tls}"),
            merge(
                json!({"password": "hy2-pw", "up": "100", "down": "100"}),
                &insecure,
            ),
        ),
        "shadowquic-brutal" => (
            "shadowquic",
            "shadowquic",
            format!(
                "    users:\n      - username: bench\n        password: sq-pw\n    up: 100\n    down: 100\n    jls-upstream:\n      addr: {host}:{port}\n      sni: localhost\n  - name: shadowquic-tls\n    type: trojan\n    listen: {host}\n    port: {port}\n    users:\n      - username: bench\n        password: unused\n{tls}"
            ),
            merge(
                json!({"username": "bench", "password": "sq-pw", "up": "100", "down": "100"}),
                &insecure,
            ),
        ),
        "tuic" => (
            "tuic",
            "tuic",
            format!("    users:\n      {TUIC_UUID}: tuic-pw\n    alpn: [h3]\n{tls}"),
            merge(
                json!({"uuid": TUIC_UUID, "password": "tuic-pw", "alpn": ["h3"]}),
                &insecure,
            ),
        ),
        "snell" => (
            "snell",
            "snell",
            "    psk: snell-psk\n    version: 4\n".to_string(),
            json!({"psk": "snell-psk", "version": 4}),
        ),
        "snell-v6" | "snell-v6-unshaped" | "snell-v6-unsafe-raw" => {
            let mode = match spec.name {
                "snell-v6-unshaped" => "unshaped",
                "snell-v6-unsafe-raw" => "unsafe-raw",
                _ => "default",
            };
            (
                "snell",
                "snell",
                format!(
                    "    psk: snell-v6-bench-psk\n    version: 6\n    mode: {mode}\n    udp: true\n"
                ),
                json!({"psk":"snell-v6-bench-psk","version":6,"mode":mode,"udp":true,"userkey":"bench"}),
            )
        }
        "mieru-tcp" => (
            "mieru",
            "mieru",
            "    transport: TCP\n    users:\n      mu: mp\n".to_string(),
            json!({"transport": "TCP", "username": "mu", "password": "mp"}),
        ),
        _ => {
            return Case {
                spec,
                listener: None,
                singbox_listener: None,
                xray_listener: None,
                gost: None,
                proxy: None,
            };
        }
    };
    let listener = format!(
        "  - name: {}\n    type: {listener_kind}\n    listen: {host}\n    port: {port}\n{body}",
        spec.name
    );
    let base =
        json!({"name": spec.name, "type": kind, "server": host, "port": port, "udp": spec.udp});
    Case {
        spec,
        listener: Some(listener),
        singbox_listener: None,
        xray_listener: None,
        gost: None,
        proxy: Some(merge(base, &extra)),
    }
}

fn merge(mut base: Value, more: &Value) -> Value {
    if let (Some(base), Some(more)) = (base.as_object_mut(), more.as_object()) {
        for (key, value) in more {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}

pub fn write_certs(dir: &Path) -> std::io::Result<()> {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(std::io::Error::other)?;
    std::fs::write(dir.join("cert.pem"), made.cert.pem())?;
    std::fs::write(dir.join("key.pem"), made.signing_key.serialize_pem())
}

/// Both clients get the same profile, including rematch's second rule walk.
pub fn client_profile(case: &Case, mixed: u16, tun: Option<&Value>) -> String {
    let proxies = match &case.proxy {
        Some(proxy) => format!("proxies:\n  - {proxy}\n"),
        None => String::new(),
    };
    let tun = tun.map(|t| format!("tun: {t}\n")).unwrap_or_default();
    let sub_rules = if case.spec.name == "rematch" {
        "sub-rules:\n  bench-rematch:\n    - REMATCH-NAME,bench,DIRECT\n    - MATCH,REJECT\n"
    } else {
        ""
    };
    format!(
        "mixed-port: {mixed}\nallow-lan: false\nmode: rule\nlog-level: error\nipv6: false\n\
         find-process-mode: off\ngeo-auto-update: false\nunified-delay: false\n\
         dns:\n  enable: false\n{tun}{proxies}rules:\n  - MATCH,{}\n{sub_rules}",
        case.rule_target()
    )
}

pub fn server_config(cases: &[Case]) -> String {
    let mut config = "log-level: error\nmode: direct\nipv6: false\nfind-process-mode: off\n\
                      geo-auto-update: false\nlisteners:\n"
        .to_string();
    for listener in cases.iter().filter_map(|case| case.listener.as_deref()) {
        config.push_str(listener);
    }
    if cases.iter().all(|c| c.listener.is_none()) {
        config = config.replace("listeners:\n", "");
    }
    config
}

pub fn singbox_config(cases: &[Case]) -> Value {
    json!({
        "log": {"level": "error"},
        "inbounds": cases.iter().filter_map(|c| c.singbox_listener.clone()).collect::<Vec<_>>(),
        "outbounds": [{"type": "direct", "tag": "direct"}]
    })
}

/// A profile shaped like a large subscription: `proxies` shadowsocks nodes in one
/// select group and `rules` domain rules with an IP tail, all unreachable, so only
/// parse, compile and resident cost are measured.
pub fn large_profile(mixed: u16, proxies: usize, rules: usize) -> String {
    use std::fmt::Write;
    let mut out = format!(
        "mixed-port: {mixed}\nallow-lan: false\nmode: rule\nlog-level: error\nipv6: false\n\
         find-process-mode: off\ngeo-auto-update: false\ndns:\n  enable: false\nproxies:\n"
    );
    for i in 0..proxies {
        let _ = writeln!(
            out,
            "  - {{name: n{i}, type: ss, server: 10.{}.{}.{}, port: {}, cipher: aes-128-gcm, password: p{i}}}",
            (i >> 16) & 255,
            (i >> 8) & 255,
            i & 255,
            10_000 + i % 50_000
        );
    }
    out.push_str("proxy-groups:\n  - name: all\n    type: select\n    proxies:\n");
    for i in 0..proxies {
        let _ = writeln!(out, "      - n{i}");
    }
    out.push_str("rules:\n");
    for i in 0..rules {
        let _ = match i % 10 {
            0..=5 => writeln!(out, "  - DOMAIN-SUFFIX,s{i}.example{}.com,all", i % 97),
            6 | 7 => writeln!(out, "  - DOMAIN,h{i}.example.net,DIRECT"),
            8 => writeln!(out, "  - DOMAIN-KEYWORD,kw{i},all"),
            _ => writeln!(
                out,
                "  - IP-CIDR,{}.{}.{}.0/24,DIRECT,no-resolve",
                1 + (i >> 16) % 220,
                (i >> 8) & 255,
                i & 255
            ),
        };
    }
    out.push_str("  - MATCH,DIRECT\n");
    out
}

pub fn xray_config(cases: &[Case]) -> Value {
    json!({"log": {"loglevel": "warning"},
        "inbounds": cases.iter().filter_map(|case| case.xray_listener.clone()).collect::<Vec<_>>(),
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]})
}
