use serde_json::{Value, json};

use super::*;
use crate::lenient::scalar_text;

fn go_sprint(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "<nil>".to_string(),
        Some(Value::Array(items)) => {
            let parts: Vec<String> = items.iter().map(|item| go_sprint(Some(item))).collect();
            format!("[{}]", parts.join(" "))
        }
        Some(other) => scalar_text(other).unwrap_or_default(),
    }
}

fn lookup<'a>(proxy: &'a Map, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut current = proxy.get(parts.next()?)?;
    for part in parts {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

fn object(value: Value) -> Map {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn check(proxy: Value, prefix: &str, want: &[(&str, &str)]) {
    let proxy = object(proxy);
    let link = encode_link(&proxy);
    assert!(
        link.starts_with(prefix),
        "link {link:?} does not start with {prefix:?}"
    );
    let read = decode_subscription(&link).unwrap_or_default();
    assert_eq!(read.len(), 1, "link {link:?} read back as {read:?}");
    for (path, expected) in want {
        let got = go_sprint(lookup(&read[0], path));
        assert_eq!(&got, expected, "{path} from {link:?}");
    }
}

#[test]
fn shadowsocks_links_read_back() {
    check(
        json!({"name": "ss node", "type": "ss", "server": "a.example", "port": 8388,
            "cipher": "aes-256-gcm", "password": "p@ss:word", "udp-over-tcp": true,
            "plugin": "obfs", "plugin-opts": {"mode": "tls", "host": "cdn.example"}}),
        "ss://aes-256-gcm:p%40ss%3Aword@a.example:8388",
        &[
            ("name", "ss node"),
            ("server", "a.example"),
            ("port", "8388"),
            ("cipher", "aes-256-gcm"),
            ("password", "p@ss:word"),
            ("udp-over-tcp", "true"),
            ("plugin", "obfs"),
            ("plugin-opts.mode", "tls"),
            ("plugin-opts.host", "cdn.example"),
        ],
    );
    check(
        json!({"name": "ss 2022", "type": "ss", "server": "2001:db8::1", "port": 443,
            "cipher": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}),
        "",
        &[
            ("server", "2001:db8::1"),
            ("cipher", "2022-blake3-aes-128-gcm"),
            ("password", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ],
    );
    check(
        json!({"name": "ssr", "type": "ssr", "server": "b.example", "port": 443, "cipher": "chacha20-ietf",
            "password": "secret", "obfs": "tls1.2_ticket_auth", "protocol": "auth_aes128_md5",
            "obfs-param": "obfs.example", "protocol-param": "1:p"}),
        "",
        &[
            ("name", "ssr"),
            ("server", "b.example"),
            ("port", "443"),
            ("cipher", "chacha20-ietf"),
            ("password", "secret"),
            ("obfs", "tls1.2_ticket_auth"),
            ("protocol", "auth_aes128_md5"),
            ("obfs-param", "obfs.example"),
            ("protocol-param", "1:p"),
        ],
    );
}

#[test]
fn vmess_links_read_back() {
    check(
        json!({"name": "vmess ws", "type": "vmess", "server": "c.example", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 64, "cipher": "auto", "tls": true,
            "servername": "sni.example", "network": "ws",
            "ws-opts": {"path": "/ray", "headers": {"Host": "host.example"}, "max-early-data": 2048}}),
        "vmess://eyJ",
        &[
            ("name", "vmess ws"),
            ("server", "c.example"),
            ("port", "443"),
            ("uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("alterId", "64"),
            ("cipher", "auto"),
            ("tls", "true"),
            ("servername", "sni.example"),
            ("network", "ws"),
            ("ws-opts.path", "/ray"),
            ("ws-opts.headers.Host", "host.example"),
            ("ws-opts.max-early-data", "2048"),
        ],
    );
    check(
        json!({"name": "vmess grpc", "type": "vmess", "server": "c.example", "port": "443", "uuid": "u",
            "cipher": "aes-128-gcm", "network": "grpc", "grpc-opts": {"grpc-service-name": "svc"}}),
        "vmess://u@c.example:443?",
        &[
            ("network", "grpc"),
            ("grpc-opts.grpc-service-name", "svc"),
            ("tls", "<nil>"),
            ("alterId", "0"),
            ("cipher", "aes-128-gcm"),
        ],
    );
    check(
        json!({"name": "vmess aead ws", "type": "vmess", "server": "c.example", "port": 443, "uuid": "u",
            "alterId": 0, "cipher": "auto", "tls": true, "servername": "sni.example",
            "client-fingerprint": "chrome", "network": "ws",
            "ws-opts": {"path": "/ray", "headers": {"Host": "host.example"}}}),
        "vmess://u@c.example:443?",
        &[
            ("name", "vmess aead ws"),
            ("cipher", "auto"),
            ("tls", "true"),
            ("servername", "sni.example"),
            ("client-fingerprint", "chrome"),
            ("network", "ws"),
            ("ws-opts.path", "/ray"),
            ("ws-opts.headers.Host", "host.example"),
        ],
    );
}

#[test]
fn vless_links_read_back() {
    check(
        json!({"name": "vless reality", "type": "vless", "server": "d.example", "port": 443, "uuid": "u-1",
            "flow": "xtls-rprx-vision", "tls": true, "servername": "www.example",
            "client-fingerprint": "firefox", "network": "tcp",
            "reality-opts": {"public-key": "pk", "short-id": "ab"}}),
        "",
        &[
            ("name", "vless reality"),
            ("uuid", "u-1"),
            ("flow", "xtls-rprx-vision"),
            ("tls", "true"),
            ("servername", "www.example"),
            ("client-fingerprint", "firefox"),
            ("network", "tcp"),
            ("reality-opts.public-key", "pk"),
            ("reality-opts.short-id", "ab"),
            ("xudp", "<nil>"),
        ],
    );
    check(
        json!({"name": "vless h2", "type": "vless", "server": "d.example", "port": 443, "uuid": "u-2",
            "xudp": true, "network": "h2", "h2-opts": {"path": "/h2", "host": ["h2.example"]}}),
        "",
        &[
            ("network", "h2"),
            ("h2-opts.path", "/h2"),
            ("h2-opts.host", "[h2.example]"),
            ("xudp", "true"),
        ],
    );
}

#[test]
fn trojan_and_quic_links_read_back() {
    check(
        json!({"name": "trojan", "type": "trojan", "server": "e.example", "port": 443,
            "password": "pass word", "sni": "sni.example", "skip-cert-verify": true,
            "alpn": ["h2", "http/1.1"], "network": "grpc", "grpc-opts": {"grpc-service-name": "g"}}),
        "",
        &[
            ("name", "trojan"),
            ("password", "pass word"),
            ("sni", "sni.example"),
            ("skip-cert-verify", "true"),
            ("alpn", "[h2 http/1.1]"),
            ("network", "grpc"),
            ("grpc-opts.grpc-service-name", "g"),
        ],
    );
    check(
        json!({"name": "trojan ws", "type": "trojan", "server": "e.example", "port": 443, "password": "p",
            "network": "ws", "ws-opts": {"path": "/ws"}}),
        "",
        &[("network", "ws"), ("ws-opts.path", "/ws")],
    );
    check(
        json!({"name": "hy", "type": "hysteria", "server": "f.example", "port": 443, "auth-str": "token",
            "up": "30 Mbps", "down": "200 Mbps", "sni": "hy.example", "protocol": "udp", "obfs": "o"}),
        "",
        &[
            ("auth_str", "token"),
            ("up", "30 Mbps"),
            ("down", "200 Mbps"),
            ("sni", "hy.example"),
            ("protocol", "udp"),
            ("obfs", "o"),
        ],
    );
    check(
        json!({"name": "hy2", "type": "hysteria2", "server": "g.example", "port": 443,
            "ports": "443,20000-30000", "password": "pw", "obfs": "salamander", "obfs-password": "op",
            "sni": "hy2.example", "skip-cert-verify": true}),
        "",
        &[
            ("name", "hy2"),
            ("port", "443"),
            ("ports", "443,20000-30000"),
            ("password", "pw"),
            ("obfs", "salamander"),
            ("obfs-password", "op"),
            ("sni", "hy2.example"),
            ("skip-cert-verify", "true"),
        ],
    );
    check(
        json!({"name": "tuic", "type": "tuic", "server": "h.example", "port": 443, "uuid": "u-3",
            "password": "pw", "congestion-controller": "bbr", "udp-relay-mode": "quic", "alpn": ["h3"]}),
        "",
        &[
            ("uuid", "u-3"),
            ("password", "pw"),
            ("congestion-controller", "bbr"),
            ("udp-relay-mode", "quic"),
            ("alpn", "[h3]"),
        ],
    );
}

#[test]
fn proxy_links_read_back() {
    check(
        json!({"name": "socks", "type": "socks5", "server": "i.example", "port": 1080,
            "username": "me", "password": "secret"}),
        "",
        &[
            ("name", "socks"),
            ("type", "socks5"),
            ("username", "me"),
            ("password", "secret"),
        ],
    );
    check(
        json!({"name": "https", "type": "http", "server": "j.example", "port": 443, "username": "test", "tls": true}),
        "",
        &[
            ("type", "http"),
            ("username", "test"),
            ("password", ""),
            ("tls", "true"),
        ],
    );
    check(
        json!({"name": "anytls", "type": "anytls", "server": "k.example", "port": 443, "password": "pw",
            "sni": "a.example", "skip-cert-verify": true}),
        "",
        &[
            ("name", "anytls"),
            ("password", "pw"),
            ("sni", "a.example"),
            ("skip-cert-verify", "true"),
        ],
    );
    check(
        json!({"name": "mieru", "type": "mieru", "server": "l.example", "port": 2999, "transport": "TCP",
            "username": "u", "password": "p", "multiplexing": "MULTIPLEXING_LOW"}),
        "",
        &[
            ("name", "mieru:2999/TCP"),
            ("port", "2999"),
            ("transport", "TCP"),
            ("username", "u"),
            ("password", "p"),
            ("multiplexing", "MULTIPLEXING_LOW"),
        ],
    );
}

#[test]
fn an_httpupgrade_proxy_in_mihomo_shape_reads_back_as_httpupgrade() {
    let opts = json!({"path": "/up", "headers": {"Host": "host.example"},
        "v2ray-http-upgrade": true, "v2ray-http-upgrade-fast-open": true});
    let upgraded = [
        ("network", "httpupgrade"),
        ("ws-opts.path", "/up"),
        ("ws-opts.headers.Host", "host.example"),
        ("ws-opts.v2ray-http-upgrade-fast-open", "true"),
        ("ws-opts.max-early-data", "<nil>"),
    ];
    check(
        json!({"name": "vmess httpupgrade", "type": "vmess", "server": "c.example", "port": 443,
            "uuid": "u", "alterId": 64, "cipher": "auto", "network": "ws", "ws-opts": opts}),
        "vmess://",
        &upgraded,
    );
    check(
        json!({"name": "vless httpupgrade", "type": "vless", "server": "d.example", "port": 443,
            "uuid": "u", "tls": true, "network": "ws", "ws-opts": opts}),
        "vless://u@d.example:443?",
        &upgraded,
    );
    check(
        json!({"name": "trojan httpupgrade", "type": "trojan", "server": "e.example", "port": 443,
            "password": "p", "network": "ws", "ws-opts": {"path": "/up", "v2ray-http-upgrade": true}}),
        "trojan://",
        &[("network", "httpupgrade"), ("ws-opts.path", "/up")],
    );
}

#[test]
fn links_leave_out_what_no_link_carries() {
    let proxies = [
        json!({"name": "wg", "type": "wireguard", "server": "a.example", "port": 51820}),
        json!({"name": "no server", "type": "ss", "cipher": "aes-128-gcm", "password": "p"}),
        json!({"name": "ssr v6", "type": "ssr", "server": "2001:db8::1", "port": 443}),
        json!({"name": "realm", "type": "hysteria2", "server": "a.example", "port": 443,
            "realm-opts": {"enable": true}}),
        json!({"name": "shadow-tls", "type": "ss", "server": "a.example", "port": 443, "cipher": "aes-128-gcm",
            "password": "p", "plugin": "shadow-tls", "plugin-opts": {"host": "cdn.example", "password": "x"}}),
        json!({"name": "trojan ws host", "type": "trojan", "server": "a.example", "port": 443, "password": "p",
            "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example"}}}),
        json!({"name": "trojan httpupgrade fast open", "type": "trojan", "server": "a.example", "port": 443,
            "password": "p", "network": "ws",
            "ws-opts": {"path": "/up", "v2ray-http-upgrade": true, "v2ray-http-upgrade-fast-open": true}}),
    ];
    for (index, proxy) in proxies.into_iter().enumerate() {
        assert_eq!(encode_link(&object(proxy)), "", "mapping {index}");
    }
}

#[test]
fn decoding_answers_each_line_on_its_own() {
    assert_eq!(
        decode_link("trojan://pw@a.example:443#one")[0]["name"],
        "one"
    );
    assert!(decode_link("not a link").is_empty());
    assert_eq!(decode_link("socks5://b.example:1080#two")[0]["name"], "two");
}

#[test]
fn subscriptions_dedupe_names_and_accept_base64() {
    let text = "trojan://a@x.example:443#n\ntrojan://b@y.example:443#n\n";
    let proxies = decode_subscription(text).unwrap();
    assert_eq!(proxies[0]["name"], "n");
    assert_eq!(proxies[1]["name"], "n-01");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    assert_eq!(decode_subscription(&encoded).unwrap().len(), 2);
    assert!(decode_subscription("nothing here").is_err());
}

#[test]
fn hysteria2_port_hopping_links() {
    let proxies =
        decode_subscription("hysteria2://pw@h.example:443,20000-30000/?sni=s#hop").unwrap();
    assert_eq!(proxies[0]["port"], "443");
    assert_eq!(proxies[0]["ports"], "443,20000-30000");
    assert_eq!(proxies[0]["password"], "pw");
}

#[test]
fn reality_share_links_preserve_mldsa_verification() {
    check(
        json!({"name":"r","type":"vless","server":"a.example","port":443,"uuid":"u",
            "tls":true,"reality-opts":{"public-key":"public-key","mldsa65-verify":"verification-key"}}),
        "vless://",
        &[("reality-opts.mldsa65-verify", "verification-key")],
    );
    assert!(decode_link("vless://u@a.example:443?security=reality&pqv=key").is_empty());
}

#[test]
fn xhttp_download_reality_keeps_aliases_and_independent_tls_settings() {
    for (public_key, expected) in [(Some("primary"), "primary"), (None, "alias")] {
        let extra = object(json!({"downloadSettings":{"security":"reality",
            "realitySettings":{"publicKey":public_key,"password":"alias","shortId":"abcd",
            "mldsa65Verify":"verify","serverName":"download.example","fingerprint":"firefox"}}}));
        let mut options = Map::new();
        super::xhttp::apply_extra(&extra, &mut options);
        let download = &options["download-settings"];
        assert_eq!(download["tls"], true);
        assert_eq!(download["reality-opts"]["public-key"], expected);
        assert_eq!(download["reality-opts"]["mldsa65-verify"], "verify");
        assert_eq!(download["reality-opts"]["short-id"], "abcd");
        assert_eq!(download["servername"], "download.example");
        assert_eq!(download["client-fingerprint"], "firefox");
    }
}
