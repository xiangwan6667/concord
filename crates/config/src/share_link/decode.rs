use std::collections::HashMap;

use serde_json::{Value, json};

use super::urlx::{
    Link, decode_base64_std, decode_base64_url, parse_query, try_decode_base64, unique_name,
};
use crate::Map;
use crate::error::{ConfigError, Result};

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36";

const SS_CIPHERS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
    "none",
    "plain",
    "dummy",
];

fn valid_ss_method(cipher: &str) -> bool {
    SS_CIPHERS.contains(&cipher.to_ascii_lowercase().as_str())
}

pub fn decode_subscription_text(text: &str) -> Result<Vec<Map>> {
    let data = match decode_base64_std(text.trim_matches(['\r', '\n', ' '])) {
        Some(bytes) if !text.contains("://") => {
            String::from_utf8(bytes).unwrap_or_else(|_| text.to_string())
        }
        _ => text.to_string(),
    };
    let mut proxies = Vec::new();
    let mut names: HashMap<String, u32> = HashMap::new();
    for raw in data.split('\n') {
        let line = raw.trim_end_matches([' ', '\r']);
        if line.is_empty() {
            continue;
        }
        let Some((scheme, body)) = line.split_once("://") else {
            continue;
        };
        decode_line(
            &scheme.to_ascii_lowercase(),
            body,
            line,
            &mut names,
            &mut proxies,
        );
    }
    if proxies.is_empty() {
        return Err(ConfigError::new(
            "convert v2ray subscribe error: format invalid",
        ));
    }
    Ok(proxies)
}

pub fn decode_link_line(line: &str) -> Result<Vec<Map>> {
    decode_subscription_text(line)
}

fn text(value: &str) -> Value {
    Value::String(value.to_string())
}

fn truthy(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

fn split_alpn(value: &str) -> Value {
    Value::Array(value.split(',').map(text).collect())
}

fn into_map(value: Value) -> Map {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn decode_line(
    scheme: &str,
    body: &str,
    line: &str,
    names: &mut HashMap<String, u32>,
    out: &mut Vec<Map>,
) {
    match scheme {
        "hysteria" => {
            let Some(link) = Link::parse(line) else {
                return;
            };
            let up = if link.get("up").is_empty() {
                link.get("upmbps")
            } else {
                link.get("up")
            };
            let down = if link.get("down").is_empty() {
                link.get("downmbps")
            } else {
                link.get("down")
            };
            let mut map = into_map(json!({
                "name": unique_name(names, &link.fragment),
                "type": scheme,
                "server": link.host,
                "port": link.port,
                "sni": link.get("peer"),
                "obfs": link.get("obfs"),
            }));
            if !link.get("alpn").is_empty() {
                map.insert("alpn".into(), split_alpn(link.get("alpn")));
            }
            map.insert("auth_str".into(), text(link.get("auth")));
            map.insert("protocol".into(), text(link.get("protocol")));
            map.insert("down".into(), text(down));
            map.insert("up".into(), text(up));
            map.insert(
                "skip-cert-verify".into(),
                Value::Bool(truthy(link.get("insecure"))),
            );
            out.push(map);
        }
        "hysteria2" | "hy2" | "hysteria2+realm" | "hy2+realm" => {
            let realm = scheme.ends_with("+realm");
            let (hop_line, ports) = split_hysteria2_ports(line);
            let Some(link) = Link::parse(&hop_line) else {
                return;
            };
            let mut map = into_map(json!({
                "name": unique_name(names, &link.fragment),
                "type": "hysteria2",
                "server": link.host,
                "port": if link.port.is_empty() { "443".to_string() } else { link.port.clone() },
            }));
            if !ports.is_empty() {
                map.insert("ports".into(), text(&ports));
            }
            map.insert("obfs".into(), text(link.get("obfs")));
            map.insert("obfs-password".into(), text(link.get("obfs-password")));
            map.insert("sni".into(), text(link.get("sni")));
            map.insert(
                "skip-cert-verify".into(),
                Value::Bool(truthy(link.get("insecure"))),
            );
            if !link.get("alpn").is_empty() {
                map.insert("alpn".into(), split_alpn(link.get("alpn")));
            }
            map.insert("fingerprint".into(), text(link.get("pinSHA256")));
            map.insert("down".into(), text(link.get("down")));
            map.insert("up".into(), text(link.get("up")));
            if realm {
                let token = link.user.clone().unwrap_or_default();
                let realm_id = super::urlx::unescape(link.path.trim_start_matches('/'));
                let host = if link.port.is_empty() {
                    link.host.clone()
                } else {
                    format!("{}:{}", link.host, link.port)
                };
                let stun: Vec<Value> = link.all("stun").into_iter().map(text).collect();
                let mut opts =
                    into_map(json!({"enable": true, "server-url": format!("https://{host}")}));
                if !token.is_empty() {
                    opts.insert("token".into(), text(&token));
                }
                if !realm_id.is_empty() {
                    opts.insert("realm-id".into(), text(&realm_id));
                }
                if !stun.is_empty() {
                    opts.insert("stun-servers".into(), Value::Array(stun));
                }
                map.insert("realm-opts".into(), Value::Object(opts));
                if !link.get("auth").is_empty() {
                    map.insert("password".into(), text(link.get("auth")));
                }
            } else if let Some(auth) = link.user.as_deref().filter(|a| !a.is_empty()) {
                let auth = match &link.password {
                    Some(password) => format!("{auth}:{password}"),
                    None => auth.to_string(),
                };
                map.insert("password".into(), text(&auth));
            }
            out.push(map);
        }
        "tuic" => {
            let Some(link) = Link::parse(line) else {
                return;
            };
            let mut map = into_map(json!({
                "name": unique_name(names, &link.fragment),
                "type": scheme,
                "server": link.host,
                "port": link.port,
                "udp": true,
            }));
            match &link.password {
                Some(password) => {
                    map.insert("uuid".into(), text(link.username()));
                    map.insert("password".into(), text(password));
                }
                None => {
                    map.insert("token".into(), text(link.username()));
                }
            }
            if !link.get("congestion_control").is_empty() {
                map.insert(
                    "congestion-controller".into(),
                    text(link.get("congestion_control")),
                );
            }
            if !link.get("alpn").is_empty() {
                map.insert("alpn".into(), split_alpn(link.get("alpn")));
            }
            if !link.get("sni").is_empty() {
                map.insert("sni".into(), text(link.get("sni")));
            }
            if link.get("disable_sni") == "1" {
                map.insert("disable-sni".into(), Value::Bool(true));
            }
            if !link.get("udp_relay_mode").is_empty() {
                map.insert("udp-relay-mode".into(), text(link.get("udp_relay_mode")));
            }
            out.push(map);
        }
        "trojan" => {
            let Some(link) = Link::parse(line) else {
                return;
            };
            let mut map = into_map(json!({
                "name": unique_name(names, &link.fragment),
                "type": scheme,
                "server": link.host,
                "port": link.port,
                "password": link.username(),
                "udp": true,
                "skip-cert-verify": truthy(link.get("allowInsecure")),
            }));
            if !link.get("sni").is_empty() {
                map.insert("sni".into(), text(link.get("sni")));
            }
            if !link.get("alpn").is_empty() {
                map.insert("alpn".into(), split_alpn(link.get("alpn")));
            }
            let network = link.get("type").to_lowercase();
            if !network.is_empty() {
                map.insert("network".into(), text(&network));
            }
            match network.as_str() {
                "ws" | "httpupgrade" => {
                    map.insert(
                        "ws-opts".into(),
                        json!({"path": link.get("path"), "headers": {"User-Agent": USER_AGENT}}),
                    );
                }
                "grpc" => {
                    map.insert(
                        "grpc-opts".into(),
                        json!({"grpc-service-name": link.get("serviceName")}),
                    );
                }
                _ => {}
            }
            let fingerprint = if link.get("fp").is_empty() {
                "chrome"
            } else {
                link.get("fp")
            };
            map.insert("client-fingerprint".into(), text(fingerprint));
            if !link.get("pcs").is_empty() {
                map.insert("fingerprint".into(), text(link.get("pcs")));
            }
            out.push(map);
        }
        "vless" => {
            let Some(mut link) = Link::parse(line) else {
                return;
            };
            if let Some(decoded) =
                try_decode_base64(&link.host).and_then(|b| String::from_utf8(b).ok())
            {
                link.host = decoded;
            }
            let mut map = Map::new();
            if v_share_link(names, &link, scheme, &mut map).is_err() {
                return;
            }
            if !link.get("flow").is_empty() {
                map.insert("flow".into(), text(&link.get("flow").to_lowercase()));
            }
            if !link.get("encryption").is_empty() {
                map.insert("encryption".into(), text(link.get("encryption")));
            }
            out.push(map);
        }
        "vmess" => decode_vmess(scheme, body, line, names, out),
        "ss" => decode_ss(scheme, line, names, out),
        "ssr" => decode_ssr(scheme, body, names, out),
        "socks" | "socks5" | "socks5h" | "http" | "https" => {
            let Some(link) = Link::parse(line) else {
                return;
            };
            if link.host.is_empty() || link.port.is_empty() {
                return;
            }
            let remarks = if link.fragment.is_empty() {
                format!("{}:{}", link.host, link.port)
            } else {
                link.fragment.clone()
            };
            let (mut username, mut password) = (String::new(), String::new());
            if let Some(user) = &link.user {
                let encoded = match &link.password {
                    Some(pass) => format!("{user}:{pass}"),
                    None => user.clone(),
                };
                let decoded = decode_base64_std(&encoded)
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or(encoded);
                let parts: Vec<&str> = decoded.split(':').collect();
                username = parts.first().copied().unwrap_or_default().to_string();
                if parts.len() == 2 {
                    password = parts.get(1).copied().unwrap_or_default().to_string();
                }
            }
            let kind = if matches!(scheme, "http" | "https") {
                "http"
            } else {
                "socks5"
            };
            let mut map = into_map(json!({
                "name": unique_name(names, &remarks),
                "type": kind,
                "server": link.host,
                "port": link.port,
                "username": username,
                "password": password,
                "skip-cert-verify": true,
            }));
            if scheme == "https" {
                map.insert("tls".into(), Value::Bool(true));
            }
            out.push(map);
        }
        "anytls" => {
            let Some(link) = Link::parse(line) else {
                return;
            };
            if link.host.is_empty() || link.port.is_empty() {
                return;
            }
            let username = link.username().to_string();
            let password = link.password.clone().unwrap_or_else(|| username.clone());
            let remarks = if link.fragment.is_empty() {
                format!("{}:{}", link.host, link.port)
            } else {
                link.fragment.clone()
            };
            out.push(into_map(json!({
                "name": unique_name(names, &remarks),
                "type": "anytls",
                "server": link.host,
                "port": link.port,
                "username": username,
                "password": password,
                "sni": link.get("sni"),
                "fingerprint": link.get("hpkp"),
                "skip-cert-verify": link.get("insecure") == "1",
                "udp": true,
            })));
        }
        "mierus" => decode_mieru(line, names, out),
        _ => {}
    }
}

fn split_hysteria2_ports(line: &str) -> (String, String) {
    let Some(at) = line.find("://") else {
        return (line.to_string(), String::new());
    };
    let (head, rest) = line.split_at(at + 3);
    let (auth, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let (userinfo, auth) = match auth.rfind('@') {
        Some(i) => auth.split_at(i + 1),
        None => ("", auth),
    };
    if auth.contains(']') {
        return (line.to_string(), String::new());
    }
    let Some(colon) = auth.rfind(':') else {
        return (line.to_string(), String::new());
    };
    let (host, ports) = auth.split_at(colon);
    let ports = ports.trim_start_matches(':');
    if !ports.contains([',', '-']) {
        return (line.to_string(), String::new());
    }
    let first = ports.split([',', '-']).next().unwrap_or_default();
    if first.is_empty() {
        return (line.to_string(), String::new());
    }
    (
        format!("{head}{userinfo}{host}:{first}{tail}"),
        ports.to_string(),
    )
}

fn v_share_link(
    names: &mut HashMap<String, u32>,
    link: &Link,
    scheme: &str,
    proxy: &mut Map,
) -> Result<()> {
    proxy.insert("name".into(), text(&unique_name(names, &link.fragment)));
    if link.host.is_empty() {
        return Err(ConfigError::new("url.Hostname() is empty"));
    }
    if link.port.is_empty() {
        return Err(ConfigError::new("url.Port() is empty"));
    }
    proxy.insert("type".into(), text(scheme));
    proxy.insert("server".into(), text(&link.host));
    proxy.insert("port".into(), text(&link.port));
    proxy.insert("uuid".into(), text(link.username()));
    proxy.insert("udp".into(), Value::Bool(true));
    let security = link.get("security").to_lowercase();
    if security.ends_with("tls") || security == "reality" {
        proxy.insert("tls".into(), Value::Bool(true));
        let fingerprint = if link.get("fp").is_empty() {
            "chrome"
        } else {
            link.get("fp")
        };
        proxy.insert("client-fingerprint".into(), text(fingerprint));
        if !link.get("alpn").is_empty() {
            proxy.insert("alpn".into(), split_alpn(link.get("alpn")));
        }
        if !link.get("pcs").is_empty() {
            proxy.insert("fingerprint".into(), text(link.get("pcs")));
        }
    }
    if !link.get("sni").is_empty() {
        proxy.insert("servername".into(), text(link.get("sni")));
    }
    if !link.get("pbk").is_empty() {
        let mut reality =
            into_map(json!({"public-key": link.get("pbk"), "short-id": link.get("sid")}));
        match link.get("support-x25519mlkem768") {
            "" => {}
            value => {
                let enabled = match value {
                    "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
                    "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
                    _ => None,
                };
                if let Some(enabled) = enabled {
                    reality.insert("support-x25519mlkem768".into(), Value::Bool(enabled));
                }
            }
        }
        if !link.get("pqv").is_empty() {
            reality.insert("mldsa65-verify".into(), text(link.get("pqv")));
        }
        proxy.insert("reality-opts".into(), Value::Object(reality));
    } else if !link.get("pqv").is_empty() {
        return Err(ConfigError::new("REALITY pqv requires pbk"));
    }
    match link.get("packetEncoding") {
        "none" => {}
        "packet" => {
            proxy.insert("packet-addr".into(), Value::Bool(true));
        }
        _ => {
            proxy.insert("xudp".into(), Value::Bool(true));
        }
    }
    let mut network = link.get("type").to_lowercase();
    if network.is_empty() {
        network = "tcp".into();
    }
    if network == "tcp" && link.get("headerType").to_lowercase() == "http" {
        network = "http".into();
    } else if network == "http" {
        network = "h2".into();
    }
    proxy.insert("network".into(), text(&network));
    match network.as_str() {
        "http" => {
            let mut headers = Map::new();
            let mut opts = Map::new();
            opts.insert("path".into(), json!(["/"]));
            if !link.get("host").is_empty() {
                headers.insert("Host".into(), json!([link.get("host")]));
            }
            if !link.get("method").is_empty() {
                opts.insert("method".into(), text(link.get("method")));
            }
            if !link.get("path").is_empty() {
                opts.insert("path".into(), json!([link.get("path")]));
            }
            opts.insert("headers".into(), Value::Object(headers));
            proxy.insert("http-opts".into(), Value::Object(opts));
        }
        "h2" => {
            let mut opts = into_map(json!({"path": "/"}));
            if !link.get("path").is_empty() {
                opts.insert("path".into(), text(link.get("path")));
            }
            if !link.get("host").is_empty() {
                opts.insert("host".into(), json!([link.get("host")]));
            }
            proxy.insert("h2-opts".into(), Value::Object(opts));
        }
        "ws" | "httpupgrade" => {
            let mut opts = into_map(json!({
                "path": link.get("path"),
                "headers": {"User-Agent": USER_AGENT, "Host": link.get("host")},
            }));
            if !link.get("ed").is_empty() {
                let early: i64 = link
                    .get("ed")
                    .parse()
                    .map_err(|_| ConfigError::new("bad WebSocket max early data size"))?;
                if network == "ws" {
                    opts.insert("max-early-data".into(), json!(early));
                    opts.insert(
                        "early-data-header-name".into(),
                        text("Sec-WebSocket-Protocol"),
                    );
                } else {
                    opts.insert("v2ray-http-upgrade-fast-open".into(), Value::Bool(true));
                }
            }
            if !link.get("eh").is_empty() {
                opts.insert("early-data-header-name".into(), text(link.get("eh")));
            }
            proxy.insert("ws-opts".into(), Value::Object(opts));
        }
        "grpc" => {
            proxy.insert(
                "grpc-opts".into(),
                json!({"grpc-service-name": link.get("serviceName")}),
            );
        }
        "xhttp" => {
            let mut opts = Map::new();
            for (key, query) in [("path", "path"), ("host", "host"), ("mode", "mode")] {
                if !link.get(query).is_empty() {
                    opts.insert(key.into(), text(link.get(query)));
                }
            }
            if let Ok(Value::Object(extra)) = serde_json::from_str::<Value>(link.get("extra")) {
                super::xhttp::apply_extra(&extra, &mut opts);
            }
            proxy.insert("xhttp-opts".into(), Value::Object(opts));
        }
        _ => {}
    }
    Ok(())
}

fn decode_vmess(
    scheme: &str,
    body: &str,
    line: &str,
    names: &mut HashMap<String, u32>,
    out: &mut Vec<Map>,
) {
    let Some(decoded) = try_decode_base64(body) else {
        let Some(link) = Link::parse(line) else {
            return;
        };
        let mut map = Map::new();
        if v_share_link(names, &link, scheme, &mut map).is_err() {
            return;
        }
        map.insert("alterId".into(), json!(0));
        let cipher = if link.get("encryption").is_empty() {
            "auto"
        } else {
            link.get("encryption")
        };
        map.insert("cipher".into(), text(cipher));
        out.push(map);
        return;
    };
    let Ok(Value::Object(values)) = serde_json::from_slice::<Value>(&decoded) else {
        return;
    };
    let Some(Value::String(ps)) = values.get("ps") else {
        return;
    };
    let mut vmess = Map::new();
    vmess.insert("name".into(), text(&unique_name(names, ps)));
    vmess.insert("type".into(), text(scheme));
    vmess.insert(
        "server".into(),
        values.get("add").cloned().unwrap_or(Value::Null),
    );
    vmess.insert(
        "port".into(),
        values.get("port").cloned().unwrap_or(Value::Null),
    );
    vmess.insert(
        "uuid".into(),
        values.get("id").cloned().unwrap_or(Value::Null),
    );
    vmess.insert(
        "alterId".into(),
        values.get("aid").cloned().unwrap_or(json!(0)),
    );
    vmess.insert("udp".into(), Value::Bool(true));
    vmess.insert("xudp".into(), Value::Bool(true));
    vmess.insert("tls".into(), Value::Bool(false));
    vmess.insert("skip-cert-verify".into(), Value::Bool(false));
    let str_of = |key: &str| {
        values
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let cipher = str_of("scy");
    vmess.insert(
        "cipher".into(),
        text(if cipher.is_empty() { "auto" } else { &cipher }),
    );
    if !str_of("sni").is_empty() {
        vmess.insert("servername".into(), text(&str_of("sni")));
    }
    let mut network = String::new();
    if let Some(Value::String(net)) = values.get("net") {
        network = net.to_lowercase();
        if values.get("type").and_then(Value::as_str) == Some("http") {
            network = "http".into();
        } else if network == "http" {
            network = "h2".into();
        }
        vmess.insert("network".into(), text(&network));
    }
    if let Some(Value::String(tls)) = values.get("tls") {
        if tls.to_lowercase().ends_with("tls") {
            vmess.insert("tls".into(), Value::Bool(true));
        }
        if let Some(Value::String(alpn)) = values.get("alpn") {
            vmess.insert("alpn".into(), split_alpn(alpn));
        }
    }
    let host = str_of("host");
    let path = str_of("path");
    match network.as_str() {
        "http" => {
            let mut headers = Map::new();
            if !host.is_empty() {
                headers.insert("Host".into(), json!([host]));
            }
            let paths = if path.is_empty() {
                json!(["/"])
            } else {
                json!([path])
            };
            vmess.insert(
                "http-opts".into(),
                json!({"path": paths, "headers": headers}),
            );
        }
        "h2" => {
            let mut opts =
                into_map(json!({"path": if path.is_empty() { "/" } else { path.as_str() }}));
            if !host.is_empty() {
                opts.insert("host".into(), json!([host]));
            }
            vmess.insert("h2-opts".into(), Value::Object(opts));
        }
        "ws" | "httpupgrade" => {
            let mut headers = Map::new();
            let mut opts = into_map(json!({"path": "/"}));
            if !host.is_empty() {
                headers.insert("Host".into(), text(&host));
            }
            if !path.is_empty() {
                let mut final_path = path.clone();
                if let Some((base, query)) = path.split_once('?')
                    && let Some(pairs) = parse_query(query)
                {
                    let early = pairs
                        .iter()
                        .find(|(k, _)| k == "ed")
                        .map(|(_, v)| v.clone());
                    if let Some(early) = early.filter(|e| !e.is_empty())
                        && let Ok(size) = early.parse::<i64>()
                    {
                        if network == "ws" {
                            opts.insert("max-early-data".into(), json!(size));
                            opts.insert(
                                "early-data-header-name".into(),
                                text("Sec-WebSocket-Protocol"),
                            );
                        } else {
                            opts.insert("v2ray-http-upgrade-fast-open".into(), Value::Bool(true));
                        }
                        let rest: Vec<String> = pairs
                            .iter()
                            .filter(|(k, _)| k != "ed")
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect();
                        final_path = if rest.is_empty() {
                            base.to_string()
                        } else {
                            format!("{base}?{}", rest.join("&"))
                        };
                    }
                    if let Some((_, header)) =
                        pairs.iter().find(|(k, v)| k == "eh" && !v.is_empty())
                    {
                        opts.insert("early-data-header-name".into(), text(header));
                    }
                }
                opts.insert("path".into(), text(&final_path));
            }
            opts.insert("headers".into(), Value::Object(headers));
            vmess.insert("ws-opts".into(), Value::Object(opts));
        }
        "grpc" => {
            vmess.insert(
                "grpc-opts".into(),
                json!({"grpc-service-name": values.get("path").cloned().unwrap_or(Value::Null)}),
            );
        }
        _ => {}
    }
    out.push(vmess);
}

fn decode_ss(scheme: &str, line: &str, names: &mut HashMap<String, u32>, out: &mut Vec<Map>) {
    let Some(mut link) = Link::parse(line) else {
        return;
    };
    let name = unique_name(names, &link.fragment);
    if link.port.is_empty() {
        let Some(decoded) = decode_base64_std(link.host.trim_end_matches('='))
            .and_then(|b| String::from_utf8(b).ok())
        else {
            return;
        };
        let Some(reparsed) = Link::parse(&format!("ss://{decoded}")) else {
            return;
        };
        link = reparsed;
    }
    let cipher_raw = link.username().to_string();
    let (mut cipher, mut password) = (cipher_raw.clone(), String::new());
    match &link.password {
        Some(pass) => password.clone_from(pass),
        None => {
            let decoded = decode_base64_url(&cipher_raw)
                .or_else(|| decode_base64_std(&cipher_raw))
                .unwrap_or_default();
            let decoded = String::from_utf8_lossy(&decoded).into_owned();
            let Some((c, p)) = decoded.split_once(':') else {
                return;
            };
            cipher = c.to_string();
            password = p.to_string();
            if !valid_ss_method(&cipher) {
                let alt = decode_base64_std(&cipher_raw).unwrap_or_default();
                let alt = String::from_utf8_lossy(&alt).into_owned();
                if let Some((c, p)) = alt.split_once(':') {
                    cipher = c.to_string();
                    password = p.to_string();
                }
            }
        }
    }
    let mut map = into_map(json!({
        "name": name,
        "type": scheme,
        "server": link.host,
        "port": link.port,
        "cipher": cipher,
        "password": password,
        "udp": true,
    }));
    if link.get("udp-over-tcp") == "true" || link.get("uot") == "1" {
        map.insert("udp-over-tcp".into(), Value::Bool(true));
    }
    let plugin = link.get("plugin");
    if plugin.contains(';') {
        let pairs =
            parse_query(&format!("pluginName={}", plugin.replace(';', "&"))).unwrap_or_default();
        let get = |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let plugin_name = get("pluginName");
        if plugin_name.contains("obfs") {
            map.insert("plugin".into(), text("obfs"));
            map.insert(
                "plugin-opts".into(),
                json!({"mode": get("obfs"), "host": get("obfs-host")}),
            );
        } else if plugin_name.contains("v2ray-plugin") {
            let mode = if get("mode").is_empty() {
                get("obfs")
            } else {
                get("mode")
            };
            let host = if get("host").is_empty() {
                get("obfs-host")
            } else {
                get("host")
            };
            map.insert("plugin".into(), text("v2ray-plugin"));
            map.insert(
                "plugin-opts".into(),
                json!({"mode": mode, "host": host, "path": get("path"), "tls": plugin.contains("tls")}),
            );
        }
    }
    out.push(map);
}

fn url_safe(data: &str) -> String {
    data.replace('+', "-").replace('/', "_")
}

fn decode_url_safe(data: &str) -> String {
    decode_base64_url(data)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

fn decode_ssr(scheme: &str, body: &str, names: &mut HashMap<String, u32>, out: &mut Vec<Map>) {
    let Some(decoded) = try_decode_base64(body).and_then(|b| String::from_utf8(b).ok()) else {
        return;
    };
    let Some((before, after)) = decoded.split_once("/?") else {
        return;
    };
    let parts: Vec<&str> = before.split(':').collect();
    if parts.len() != 6 {
        return;
    }
    let field = |i: usize| parts.get(i).copied().unwrap_or_default();
    let Some(query) = parse_query(&url_safe(after)) else {
        return;
    };
    let get = |key: &str| {
        query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| decode_url_safe(v))
            .unwrap_or_default()
    };
    let mut map = into_map(json!({
        "name": unique_name(names, &get("remarks")),
        "type": scheme,
        "server": field(0),
        "port": field(1),
        "cipher": field(3),
        "password": decode_url_safe(&url_safe(field(5))),
        "obfs": field(4),
        "protocol": field(2),
        "udp": true,
    }));
    if !get("obfsparam").is_empty() {
        map.insert("obfs-param".into(), text(&get("obfsparam")));
    }
    if !get("protoparam").is_empty() {
        map.insert("protocol-param".into(), text(&get("protoparam")));
    }
    out.push(map);
}

fn decode_mieru(line: &str, names: &mut HashMap<String, u32>, out: &mut Vec<Map>) {
    let Some(link) = Link::parse(line) else {
        return;
    };
    if link.host.is_empty() {
        return;
    }
    let mut base = link.fragment.clone();
    if base.is_empty() {
        base = link.get("profile").to_string();
    }
    if base.is_empty() {
        base = link.host.clone();
    }
    let ports = link.all("port");
    let protocols = link.all("protocol");
    if ports.is_empty() || ports.len() != protocols.len() {
        return;
    }
    for (port, protocol) in ports.iter().zip(&protocols) {
        let mut map = into_map(json!({
            "name": unique_name(names, &format!("{base}:{port}/{protocol}")),
            "type": "mieru",
            "server": link.host,
            "transport": protocol,
            "udp": true,
            "username": link.username(),
            "password": link.password.clone().unwrap_or_default(),
        }));
        if port.contains('-') {
            map.insert("port-range".into(), text(port));
        } else {
            match port.parse::<i64>() {
                Ok(number) => {
                    map.insert("port".into(), json!(number));
                }
                Err(_) => continue,
            }
        }
        for (key, query) in [
            ("multiplexing", "multiplexing"),
            ("handshake-mode", "handshake-mode"),
            ("traffic-pattern", "traffic-pattern"),
        ] {
            if !link.get(query).is_empty() {
                map.insert(key.into(), text(link.get(query)));
            }
        }
        out.push(map);
    }
}
