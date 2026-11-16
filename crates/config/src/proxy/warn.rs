use super::types::*;

/// The modern fingerprint that stands in for a name mihomo still accepts but marks deprecated.
pub fn deprecated_fingerprint(name: &str) -> Option<&'static str> {
    match name {
        "chrome_psk"
        | "chrome_psk_shuffle"
        | "chrome_padding_psk_shuffle"
        | "chrome_pq"
        | "chrome_pq_psk" => Some("chrome"),
        "randomized" => Some("random"),
        _ => None,
    }
}

fn tls_of(kind: &ProxyKind) -> Option<&TlsOpts> {
    match kind {
        ProxyKind::Vmess(o) => Some(&o.tls),
        ProxyKind::Vless(o) => Some(&o.tls),
        ProxyKind::Trojan(o) => Some(&o.tls),
        ProxyKind::Hysteria2(o) => Some(&o.tls),
        ProxyKind::Tuic(o) => Some(&o.tls),
        ProxyKind::AnyTls(o) => Some(&o.tls),
        ProxyKind::Miu(o) => Some(&o.tls),
        ProxyKind::Socks5(o) => Some(&o.tls),
        ProxyKind::Http(o) => Some(&o.tls),
        ProxyKind::Hysteria(o) => Some(&o.tls),
        _ => None,
    }
}

fn transport_of(kind: &ProxyKind) -> Option<&Transport> {
    match kind {
        ProxyKind::Vmess(o) => Some(&o.transport),
        ProxyKind::Vless(o) => Some(&o.transport),
        ProxyKind::Trojan(o) => Some(&o.transport),
        _ => None,
    }
}

fn fingerprints(kind: &ProxyKind) -> Vec<(&'static str, &str)> {
    let mut found = Vec::new();
    if let Some(tls) = tls_of(kind) {
        found.push(("client-fingerprint", tls.client_fingerprint.as_str()));
    }
    match kind {
        ProxyKind::Ss(o) => found.push(("client-fingerprint", o.client_fingerprint.as_str())),
        ProxyKind::Snell(o) => found.push(("client-fingerprint", o.client_fingerprint.as_str())),
        _ => {}
    }
    if let Some(Transport::Xhttp(xhttp)) = transport_of(kind)
        && let Some(download) = xhttp.download.as_deref()
        && let Some(value) = download.client_fingerprint.as_deref()
    {
        found.push(("download-settings.client-fingerprint", value));
    }
    found
}

/// What the node's options say that the app should show, beyond what makes it unsupported.
pub fn proxy_warnings(def: &ProxyDef) -> Vec<String> {
    let mut out = Vec::new();
    for (key, value) in fingerprints(&def.kind) {
        if let Some(modern) = deprecated_fingerprint(value) {
            out.push(format!(
                "{key} `{value}` is deprecated and is treated as `{modern}`"
            ));
        }
    }
    if let ProxyKind::WireGuard(wg) = &def.kind
        && let Some(amnezia) = wg.amnezia.as_ref().filter(|a| a.version == 3)
    {
        let cookies = amnezia.disable_cookies.then_some("disable-cookies");
        let unapplied: Vec<&str> = [
            (
                "content-padding-addition",
                &amnezia.content_padding_addition,
            ),
            ("rekey-after-time", &amnezia.rekey_after_time),
            ("rekey-timeout", &amnezia.rekey_timeout),
            ("reject-after-time", &amnezia.reject_after_time),
            ("keepalive-timeout", &amnezia.keepalive_timeout),
            ("max-handshake-attempts", &amnezia.max_handshake_attempts),
        ]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, _)| key)
        .chain(cookies)
        .collect();
        if !unapplied.is_empty() {
            out.push(format!(
                "amnezia-wg-option {} are not applied",
                unapplied.join(", ")
            ));
        }
        if amnezia.random_trailers {
            out.push(
                "amnezia-wg-option random-trailers is applied to handshake messages only, \
                 not to transport messages"
                    .to_string(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::proxy::{Capabilities, ProxyParse, parse_proxy};

    fn warnings(value: Value) -> Vec<String> {
        let Value::Object(map) = value else {
            panic!("not a map")
        };
        match parse_proxy(&map, &Capabilities::full()).unwrap() {
            ProxyParse::Ok(def) => proxy_warnings(&def),
            ProxyParse::Quarantined { reason, .. } => panic!("{reason}"),
        }
    }

    #[test]
    fn the_deprecated_names_map_to_modern_ones() {
        for name in [
            "chrome_psk",
            "chrome_psk_shuffle",
            "chrome_padding_psk_shuffle",
            "chrome_pq",
            "chrome_pq_psk",
        ] {
            assert_eq!(deprecated_fingerprint(name), Some("chrome"), "{name}");
        }
        assert_eq!(deprecated_fingerprint("randomized"), Some("random"));
        assert_eq!(deprecated_fingerprint("chrome"), None);
        assert_eq!(deprecated_fingerprint("nonsense"), None);
    }

    #[test]
    fn a_deprecated_fingerprint_is_warned_on_every_kind_that_takes_it() {
        let base = |extra: Value| {
            let mut map = json!({"name": "n", "server": "h.test", "port": 443});
            map.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            map
        };
        let cases = [
            json!({"type": "vless", "uuid": "6a4f3bc1-2c44-4a43-a5a3-3f1a2b0e6a11", "tls": true,
                   "client-fingerprint": "chrome_psk"}),
            json!({"type": "trojan", "password": "p", "client-fingerprint": "chrome_psk"}),
            json!({"type": "ss", "cipher": "aes-128-gcm", "password": "p",
                   "client-fingerprint": "chrome_psk"}),
            json!({"type": "snell", "psk": "p", "client-fingerprint": "chrome_psk"}),
            json!({"type": "vless", "uuid": "6a4f3bc1-2c44-4a43-a5a3-3f1a2b0e6a11", "tls": true,
                   "flow": "xtls-rprx-vision", "servername": "example.test",
                   "client-fingerprint": "chrome_psk",
                   "reality-opts": {"public-key": "A".repeat(43), "short-id": "ab"}}),
        ];
        for case in cases {
            let found = warnings(base(case.clone()));
            assert_eq!(
                found,
                ["client-fingerprint `chrome_psk` is deprecated and is treated as `chrome`"],
                "{case}"
            );
        }
    }

    #[test]
    fn the_xhttp_download_side_is_checked_too() {
        let found = warnings(json!({
            "name": "n", "type": "vless", "server": "h.test", "port": 443,
            "uuid": "6a4f3bc1-2c44-4a43-a5a3-3f1a2b0e6a11", "tls": true, "network": "xhttp",
            "xhttp-opts": {"path": "/", "download-settings": {"client-fingerprint": "randomized"}},
        }));
        assert_eq!(
            found,
            [
                "download-settings.client-fingerprint `randomized` is deprecated and is treated as `random`"
            ]
        );
    }

    #[test]
    fn current_and_unknown_fingerprints_are_not_deprecations() {
        for value in ["chrome", "random", "none", "nonsense", ""] {
            let found = warnings(json!({
                "name": "n", "type": "trojan", "server": "h.test", "port": 443,
                "password": "p", "client-fingerprint": value,
            }));
            assert!(found.is_empty(), "{value}");
        }
    }

    #[test]
    fn amnezia_v3_options_that_do_nothing_are_named() {
        let found = warnings(json!({
            "name": "n", "type": "wireguard", "server": "h.test", "port": 51820,
            "private-key": "AAAA", "public-key": "BBBB", "ip": "10.0.0.2",
            "amnezia-wg-option": {"version": 3, "rekey-timeout": "5", "keepalive-timeout": "10",
                                  "random-trailers": true},
        }));
        assert_eq!(
            found,
            [
                "amnezia-wg-option rekey-timeout, keepalive-timeout are not applied",
                "amnezia-wg-option random-trailers is applied to handshake messages only, \
                 not to transport messages",
            ]
        );
    }
}
