use concord_config::Capabilities;

const TRANSPORTS: &[&str] = &["ws", "grpc", "h2", "http", "xhttp", "httpupgrade"];
const SS_PLUGINS: &[&str] = &["obfs", "v2ray-plugin", "shadow-tls"];

/// `proxy_types` and `rule_types` are the config crate's full lists: `build_outbound` matches
/// every `ProxyKind`, and the rules crate decides the rule types.
pub fn capabilities() -> Capabilities {
    let full = Capabilities::full();
    let keep = |names: Vec<&'static str>, built: &[&str]| -> Vec<&'static str> {
        names
            .into_iter()
            .filter(|name| built.contains(name))
            .collect()
    };
    Capabilities {
        proxy_types: full.proxy_types,
        transports: keep(full.transports, TRANSPORTS),
        rule_types: full.rule_types,
        ss_plugins: keep(full.ss_plugins, SS_PLUGINS),
        ech: true,
        smux: true,
    }
}

#[cfg(test)]
mod tests {
    use concord_config::{ProxyParse, parse_proxy};
    use concord_tls::TrustStore;
    use serde_json::{Value, json};

    use super::*;
    use crate::{BuildCtx, build_outbound};

    fn minimal(kind: &str) -> Value {
        let base = json!({"name": "n", "type": kind, "server": "127.0.0.1", "port": 1});
        let extra = match kind {
            "ss" => json!({"cipher": "aes-128-gcm", "password": "p"}),
            "vmess" => {
                json!({"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "cipher": "auto", "alterId": 0})
            }
            "vless" => json!({"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}),
            "trojan" | "anytls" => json!({"password": "p"}),
            "hysteria" => json!({"up": "10", "down": "10"}),
            "hysteria2" => json!({"password": "p"}),
            "tuic" => json!({"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "p"}),
            "wireguard" => json!({
                "private-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "ip": "10.0.0.2"
            }),
            "ssr" => json!({
                "cipher": "aes-128-cfb", "password": "p", "obfs": "plain", "protocol": "origin"
            }),
            "snell" => json!({"psk": "p"}),
            "ssh" => json!({"username": "u", "password": "p"}),
            "miu" => json!({"psk": "0123456789abcdef"}),
            "mieru" => json!({"transport": "TCP", "username": "u", "password": "p"}),
            _ => json!({}),
        };
        let mut merged = base;
        if let (Some(merged), Some(extra)) = (merged.as_object_mut(), extra.as_object()) {
            merged.extend(extra.clone());
        }
        merged
    }

    #[test]
    fn every_advertised_type_gets_past_unsupported() {
        let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
        for kind in capabilities().proxy_types {
            let value = minimal(kind);
            let Some(map) = value.as_object() else {
                continue;
            };
            let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
                panic!("{kind}: the minimal config does not parse");
            };
            assert_eq!(def.kind.type_name(), kind);
            if let Err(err) = build_outbound(&def, &ctx) {
                assert!(!err.is_unsupported(), "{kind}: {err}");
            }
        }
    }

    #[test]
    fn every_type_that_builds_is_advertised() {
        let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
        let advertised = capabilities().proxy_types;
        for kind in Capabilities::full().proxy_types {
            let value = minimal(kind);
            let Some(map) = value.as_object() else {
                continue;
            };
            let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
                continue;
            };
            let builds = !matches!(build_outbound(&def, &ctx), Err(err) if err.is_unsupported());
            assert_eq!(builds, advertised.contains(&kind), "{kind}");
        }
    }

    #[test]
    fn the_list_never_claims_more_than_the_config_knows() {
        let caps = capabilities();
        let full = Capabilities::full();
        assert!(
            caps.proxy_types
                .iter()
                .all(|t| full.proxy_types.contains(t))
        );
        assert!(caps.ss_plugins.iter().all(|t| full.ss_plugins.contains(t)));
    }

    #[test]
    fn smux_shadow_tls_and_ech_are_advertised() {
        let caps = capabilities();
        assert!(caps.smux);
        assert!(caps.ss_plugins.contains(&"shadow-tls"));
        assert!(caps.transports.contains(&"xhttp"));
        assert!(caps.ech);
    }
}
