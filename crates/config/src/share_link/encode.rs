use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use super::urlx::{EscapeMode, escape, parse_query};
use crate::Map;
use crate::lenient::scalar_text;

#[derive(Clone, Copy)]
struct Fields<'a>(Option<&'a Map>);

impl<'a> Fields<'a> {
    fn str(self, key: &str) -> String {
        self.0
            .and_then(|map| map.get(key))
            .and_then(scalar_text)
            .unwrap_or_default()
    }

    fn flag(self, key: &str) -> bool {
        match self.0.and_then(|map| map.get(key)) {
            Some(Value::Bool(flag)) => *flag,
            Some(Value::String(text)) => text == "true",
            _ => false,
        }
    }

    fn sub(self, key: &str) -> Fields<'a> {
        match self.0.and_then(|map| map.get(key)) {
            Some(Value::Object(map)) => Fields(Some(map)),
            _ => Fields(None),
        }
    }

    fn list(self, key: &str) -> Vec<String> {
        match self.0.and_then(|map| map.get(key)) {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| scalar_text(item).unwrap_or_else(|| item.to_string()))
                .collect(),
            Some(Value::String(text)) if !text.is_empty() => vec![text.clone()],
            _ => Vec::new(),
        }
    }

    fn first(self, key: &str) -> String {
        self.list(key).into_iter().next().unwrap_or_default()
    }
}

type Query = BTreeMap<String, String>;

fn set_if(query: &mut Query, key: &str, value: String) {
    if !value.is_empty() {
        query.insert(key.to_string(), value);
    }
}

fn set(query: &mut Query, key: &str, value: &str) {
    query.insert(key.to_string(), value.to_string());
}

fn user_text(user: &str, password: Option<&str>) -> String {
    let user = escape(user, EscapeMode::UserPassword);
    match password {
        Some(password) => format!("{user}:{}", escape(password, EscapeMode::UserPassword)),
        None => user,
    }
}

fn share_url(scheme: &str, user: Option<String>, host: &str, query: &Query, name: &str) -> String {
    let mut out = format!("{scheme}://");
    if let Some(user) = user {
        out.push_str(&user);
        out.push('@');
    }
    out.push_str(host);
    if !query.is_empty() {
        out.push('?');
        out.push_str(&super::urlx::encode_query(query));
    }
    if !name.is_empty() {
        out.push('#');
        out.push_str(&escape(name, EscapeMode::Fragment));
    }
    out
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn host_port(f: Fields<'_>) -> String {
    join_host_port(&f.str("server"), &f.str("port"))
}

pub fn encode_share_link(proxy: &Map) -> String {
    let f = Fields(Some(proxy));
    if f.str("server").is_empty() {
        return String::new();
    }
    match f.str("type").as_str() {
        "ss" => ss(f),
        "ssr" => ssr(f),
        "vmess" => vmess(f),
        "vless" => vless(f),
        "trojan" => trojan(f),
        "hysteria" => hysteria(f),
        "hysteria2" => hysteria2(f),
        "tuic" => tuic(f),
        "socks5" => socks(f, "socks5"),
        "http" => socks(f, if f.flag("tls") { "https" } else { "http" }),
        "anytls" => anytls(f),
        "mieru" => mieru(f),
        _ => String::new(),
    }
}

fn ss(f: Fields<'_>) -> String {
    let user = user_text(&f.str("cipher"), Some(&f.str("password")));
    let mut query = Query::new();
    if f.flag("udp-over-tcp") {
        set(&mut query, "uot", "1");
    }
    let opts = f.sub("plugin-opts");
    match f.str("plugin").as_str() {
        "" => {}
        "obfs" => {
            let plugin = format!(
                "obfs-local;obfs={};obfs-host={}",
                opts.str("mode"),
                opts.str("host")
            );
            set(&mut query, "plugin", &plugin);
        }
        "v2ray-plugin" => {
            let mut plugin = format!(
                "v2ray-plugin;mode={};host={};path={}",
                opts.str("mode"),
                opts.str("host"),
                opts.str("path")
            );
            if opts.flag("tls") {
                plugin.push_str(";tls");
            }
            set(&mut query, "plugin", &plugin);
        }
        _ => return String::new(),
    }
    share_url("ss", Some(user), &host_port(f), &query, &f.str("name"))
}

fn ssr(f: Fields<'_>) -> String {
    if f.str("server").contains(':') {
        return String::new();
    }
    let enc = |value: String| URL_SAFE_NO_PAD.encode(value.as_bytes());
    let body = format!(
        "{}/?obfsparam={}&protoparam={}&remarks={}",
        [
            f.str("server"),
            f.str("port"),
            f.str("protocol"),
            f.str("cipher"),
            f.str("obfs"),
            enc(f.str("password")),
        ]
        .join(":"),
        enc(f.str("obfs-param")),
        enc(f.str("protocol-param")),
        enc(f.str("name")),
    );
    format!("ssr://{}", enc(body))
}

/// mihomo reads a `type=httpupgrade` link back as HTTPUpgrade; its own configs spell that
/// `network: ws` with `ws-opts.v2ray-http-upgrade`.
fn share_network(f: Fields<'_>) -> String {
    let network = f.str("network");
    if network == "ws" && f.sub("ws-opts").flag("v2ray-http-upgrade") {
        return "httpupgrade".to_string();
    }
    network
}

fn ws_early_data_path(network: &str, opts: Fields<'_>) -> String {
    let path = opts.str("path");
    let early = if network == "httpupgrade" {
        if opts.flag("v2ray-http-upgrade-fast-open") {
            "0".to_string()
        } else {
            String::new()
        }
    } else {
        opts.str("max-early-data")
    };
    if early.is_empty() || (network != "httpupgrade" && early == "0") {
        return path;
    }
    let path = path.as_str();
    let (base, query) = path.split_once('?').unwrap_or((path, ""));
    let Some(mut pairs) = parse_query(query) else {
        return path.to_string();
    };
    pairs.retain(|(key, _)| key != "ed");
    pairs.push(("ed".to_string(), early));
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let encoded: Vec<String> = pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                escape(k, EscapeMode::Query),
                escape(v, EscapeMode::Query)
            )
        })
        .collect();
    format!("{base}?{}", encoded.join("&"))
}

fn vmess(f: Fields<'_>) -> String {
    let alter = f.str("alterId");
    if alter.is_empty() || alter == "0" {
        let mut query = v_share_query(f);
        let cipher = f.str("cipher");
        if !cipher.is_empty() && cipher != "auto" {
            set(&mut query, "encryption", &cipher);
        }
        return share_url(
            "vmess",
            Some(user_text(&f.str("uuid"), None)),
            &host_port(f),
            &query,
            &f.str("name"),
        );
    }
    let mut values: BTreeMap<&str, Value> = BTreeMap::new();
    for (key, value) in [
        ("v", "2".to_string()),
        ("ps", f.str("name")),
        ("add", f.str("server")),
        ("port", f.str("port")),
        ("id", f.str("uuid")),
        ("aid", alter),
        ("scy", f.str("cipher")),
        ("net", "tcp".to_string()),
        ("type", "none".to_string()),
        ("host", String::new()),
        ("path", String::new()),
        ("tls", String::new()),
    ] {
        values.insert(key, json!(value));
    }
    let network = share_network(f);
    match network.as_str() {
        "ws" | "httpupgrade" => {
            let opts = f.sub("ws-opts");
            values.insert("net", json!(network));
            values.insert("host", json!(opts.sub("headers").str("Host")));
            values.insert("path", json!(ws_early_data_path(&network, opts)));
        }
        "http" => {
            let opts = f.sub("http-opts");
            values.insert("type", json!("http"));
            values.insert("host", json!(opts.sub("headers").first("Host")));
            values.insert("path", json!(opts.first("path")));
        }
        "h2" => {
            let opts = f.sub("h2-opts");
            values.insert("net", json!("h2"));
            values.insert("host", json!(opts.first("host")));
            values.insert("path", json!(opts.str("path")));
        }
        "grpc" => {
            values.insert("net", json!("grpc"));
            values.insert("path", json!(f.sub("grpc-opts").str("grpc-service-name")));
        }
        _ => {}
    }
    if f.flag("tls") {
        values.insert("tls", json!("tls"));
        values.insert("sni", json!(f.str("servername")));
        values.insert("alpn", json!(f.list("alpn").join(",")));
        values.insert("fp", json!(f.str("client-fingerprint")));
    }
    let data = serde_json::to_string(&values).unwrap_or_default();
    format!("vmess://{}", STANDARD.encode(data.as_bytes()))
}

fn vless(f: Fields<'_>) -> String {
    let mut query = v_share_query(f);
    set_if(&mut query, "flow", f.str("flow"));
    set_if(&mut query, "encryption", f.str("encryption"));
    share_url(
        "vless",
        Some(user_text(&f.str("uuid"), None)),
        &host_port(f),
        &query,
        &f.str("name"),
    )
}

fn v_share_query(f: Fields<'_>) -> Query {
    let mut query = Query::new();
    if f.flag("tls") {
        let reality = f.sub("reality-opts");
        let public_key = reality.str("public-key");
        if public_key.is_empty() {
            set(&mut query, "security", "tls");
        } else {
            set(&mut query, "security", "reality");
            set(&mut query, "pbk", &public_key);
            set_if(&mut query, "sid", reality.str("short-id"));
            set_if(&mut query, "pqv", reality.str("mldsa65-verify"));
            set_if(
                &mut query,
                "support-x25519mlkem768",
                reality.str("support-x25519mlkem768"),
            );
        }
        set_if(&mut query, "fp", f.str("client-fingerprint"));
        set_if(&mut query, "alpn", f.list("alpn").join(","));
        set_if(&mut query, "pcs", f.str("fingerprint"));
    }
    set_if(&mut query, "sni", f.str("servername"));
    if f.flag("packet-addr") {
        set(&mut query, "packetEncoding", "packet");
    } else if !f.flag("xudp") {
        set(&mut query, "packetEncoding", "none");
    }
    let network = share_network(f);
    match network.as_str() {
        "" | "tcp" => {}
        "http" => {
            let opts = f.sub("http-opts");
            set(&mut query, "type", "tcp");
            set(&mut query, "headerType", "http");
            set_if(&mut query, "path", opts.first("path"));
            set_if(&mut query, "host", opts.sub("headers").first("Host"));
            set_if(&mut query, "method", opts.str("method"));
        }
        "h2" => {
            let opts = f.sub("h2-opts");
            set(&mut query, "type", "http");
            set_if(&mut query, "path", opts.str("path"));
            set_if(&mut query, "host", opts.first("host"));
        }
        "ws" | "httpupgrade" => {
            let opts = f.sub("ws-opts");
            set(&mut query, "type", &network);
            set_if(&mut query, "path", opts.str("path"));
            set_if(&mut query, "host", opts.sub("headers").str("Host"));
            if network == "ws" {
                let early = opts.str("max-early-data");
                if !early.is_empty() && early != "0" {
                    set(&mut query, "ed", &early);
                }
                let header = opts.str("early-data-header-name");
                if !header.is_empty() && header != "Sec-WebSocket-Protocol" {
                    set(&mut query, "eh", &header);
                }
            } else if opts.flag("v2ray-http-upgrade-fast-open") {
                set(&mut query, "ed", "0");
            }
        }
        "grpc" => {
            set(&mut query, "type", "grpc");
            set_if(
                &mut query,
                "serviceName",
                f.sub("grpc-opts").str("grpc-service-name"),
            );
        }
        "xhttp" => {
            let opts = f.sub("xhttp-opts");
            set(&mut query, "type", "xhttp");
            set_if(&mut query, "path", opts.str("path"));
            set_if(&mut query, "host", opts.str("host"));
            set_if(&mut query, "mode", opts.str("mode"));
        }
        other => set(&mut query, "type", other),
    }
    query
}

fn trojan(f: Fields<'_>) -> String {
    let mut query = Query::new();
    if f.flag("skip-cert-verify") {
        set(&mut query, "allowInsecure", "1");
    }
    set_if(&mut query, "sni", f.str("sni"));
    set_if(&mut query, "alpn", f.list("alpn").join(","));
    let network = share_network(f);
    match network.as_str() {
        "ws" | "httpupgrade" => {
            let opts = f.sub("ws-opts");
            if !opts.sub("headers").str("Host").is_empty()
                || (network == "httpupgrade" && opts.flag("v2ray-http-upgrade-fast-open"))
            {
                return String::new();
            }
            set(&mut query, "type", &network);
            set_if(&mut query, "path", opts.str("path"));
        }
        "grpc" => {
            set(&mut query, "type", "grpc");
            set_if(
                &mut query,
                "serviceName",
                f.sub("grpc-opts").str("grpc-service-name"),
            );
        }
        _ => {}
    }
    set_if(&mut query, "fp", f.str("client-fingerprint"));
    set_if(&mut query, "pcs", f.str("fingerprint"));
    share_url(
        "trojan",
        Some(user_text(&f.str("password"), None)),
        &host_port(f),
        &query,
        &f.str("name"),
    )
}

fn hysteria(f: Fields<'_>) -> String {
    let mut query = Query::new();
    set_if(&mut query, "peer", f.str("sni"));
    set_if(&mut query, "obfs", f.str("obfs"));
    set_if(&mut query, "alpn", f.list("alpn").join(","));
    let mut auth = f.str("auth-str");
    if auth.is_empty() {
        auth = f.str("auth_str");
    }
    set_if(&mut query, "auth", auth);
    set_if(&mut query, "protocol", f.str("protocol"));
    set_if(&mut query, "up", f.str("up"));
    set_if(&mut query, "down", f.str("down"));
    if f.flag("skip-cert-verify") {
        set(&mut query, "insecure", "1");
    }
    share_url("hysteria", None, &host_port(f), &query, &f.str("name"))
}

fn hysteria2(f: Fields<'_>) -> String {
    if f.sub("realm-opts").flag("enable") {
        return String::new();
    }
    let mut host = host_port(f);
    let ports = f.str("ports");
    if !ports.is_empty() && !f.str("server").contains(':') {
        host = format!("{}:{ports}", f.str("server"));
    }
    let password = f.str("password");
    let user = (!password.is_empty()).then(|| user_text(&password, None));
    let mut query = Query::new();
    set_if(&mut query, "sni", f.str("sni"));
    set_if(&mut query, "obfs", f.str("obfs"));
    set_if(&mut query, "obfs-password", f.str("obfs-password"));
    if f.flag("skip-cert-verify") {
        set(&mut query, "insecure", "1");
    }
    set_if(&mut query, "alpn", f.list("alpn").join(","));
    set_if(&mut query, "pinSHA256", f.str("fingerprint"));
    set_if(&mut query, "up", f.str("up"));
    set_if(&mut query, "down", f.str("down"));
    share_url("hysteria2", user, &host, &query, &f.str("name"))
}

fn tuic(f: Fields<'_>) -> String {
    let user = if f.str("uuid").is_empty() {
        user_text(&f.str("token"), None)
    } else {
        user_text(&f.str("uuid"), Some(&f.str("password")))
    };
    let mut query = Query::new();
    set_if(
        &mut query,
        "congestion_control",
        f.str("congestion-controller"),
    );
    set_if(&mut query, "alpn", f.list("alpn").join(","));
    set_if(&mut query, "sni", f.str("sni"));
    if f.flag("disable-sni") {
        set(&mut query, "disable_sni", "1");
    }
    set_if(&mut query, "udp_relay_mode", f.str("udp-relay-mode"));
    share_url("tuic", Some(user), &host_port(f), &query, &f.str("name"))
}

fn socks(f: Fields<'_>, scheme: &str) -> String {
    let (username, password) = (f.str("username"), f.str("password"));
    let user = (!username.is_empty() || !password.is_empty())
        .then(|| user_text(&username, Some(&password)));
    share_url(scheme, user, &host_port(f), &Query::new(), &f.str("name"))
}

fn anytls(f: Fields<'_>) -> String {
    let mut query = Query::new();
    set_if(&mut query, "sni", f.str("sni"));
    if f.flag("skip-cert-verify") {
        set(&mut query, "insecure", "1");
    }
    set_if(&mut query, "hpkp", f.str("fingerprint"));
    share_url(
        "anytls",
        Some(user_text(&f.str("password"), None)),
        &host_port(f),
        &query,
        &f.str("name"),
    )
}

fn mieru(f: Fields<'_>) -> String {
    let mut port = f.str("port-range");
    if port.is_empty() {
        port = f.str("port");
    }
    let mut protocol = f.str("transport");
    if protocol.is_empty() {
        protocol = "TCP".to_string();
    }
    let mut query = Query::new();
    set(&mut query, "port", &port);
    set(&mut query, "protocol", &protocol);
    set_if(&mut query, "multiplexing", f.str("multiplexing"));
    set_if(&mut query, "handshake-mode", f.str("handshake-mode"));
    set_if(&mut query, "traffic-pattern", f.str("traffic-pattern"));
    let mut host = f.str("server");
    if host.contains(':') {
        host = format!("[{host}]");
    }
    let user = user_text(&f.str("username"), Some(&f.str("password")));
    share_url("mierus", Some(user), &host, &query, &f.str("name"))
}
