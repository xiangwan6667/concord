mod gost_relay;
use self::gost_relay::gost_relay_opts;
mod ss;
use self::ss::parse_ss;
mod masque;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use indexmap::IndexMap;
use serde_json::Value;

use super::types::*;
use crate::Map;
use crate::error::{ConfigError, Result};
use crate::lenient::Fields;

pub const T0_PROXY_TYPES: &[&str] = &[
    "direct",
    "reject",
    "ss",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "tuic",
    "anytls",
    "socks5",
    "http",
];
pub const T1_PROXY_TYPES: &[&str] = &[
    "wireguard",
    "masque",
    "hysteria",
    "ssr",
    "snell",
    "mieru",
    "miu",
    "ssh",
    "shadowquic",
    "dns",
    "rematch",
    "gost-relay",
];
pub const T2_PROXY_TYPES: &[&str] = &[
    "tailscale",
    "easytier",
    "zerotier",
    "openvpn",
    "sudoku",
    "trusttunnel",
];

const T2_NETWORKS: &[&str] = &["mkcp", "kcp", "mekya"];
const T2_TLS_KEYS: &[&str] = &["restls-opts", "tlsmirror-opts"];
const T2_SS_PLUGINS: &[&str] = &["restls", "kcptun"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub proxy_types: Vec<&'static str>,
    pub transports: Vec<&'static str>,
    pub rule_types: Vec<&'static str>,
    pub ss_plugins: Vec<&'static str>,
    pub ech: bool,
    pub smux: bool,
}

impl Capabilities {
    pub fn full() -> Capabilities {
        Capabilities {
            proxy_types: T0_PROXY_TYPES
                .iter()
                .chain(T1_PROXY_TYPES)
                .copied()
                .collect(),
            transports: vec!["ws", "grpc", "h2", "http", "xhttp", "httpupgrade"],
            rule_types: crate::rule::rule_type_names().collect(),
            ss_plugins: vec!["obfs", "v2ray-plugin", "shadow-tls", "jls", "gost-plugin"],
            ech: true,
            smux: true,
        }
    }

    pub fn tier0() -> Capabilities {
        Capabilities {
            proxy_types: T0_PROXY_TYPES.to_vec(),
            transports: vec!["ws", "grpc", "h2", "http"],
            rule_types: crate::rule::T0_RULE_TYPES.to_vec(),
            ss_plugins: vec!["obfs", "v2ray-plugin"],
            ech: false,
            smux: false,
        }
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Capabilities::full()
    }
}

enum Fail {
    Hard(ConfigError),
    Quarantine(String),
}

impl From<ConfigError> for Fail {
    fn from(err: ConfigError) -> Self {
        Fail::Hard(err)
    }
}

type R<T> = std::result::Result<T, Fail>;

fn quarantine<T>(reason: impl Into<String>) -> R<T> {
    Err(Fail::Quarantine(reason.into()))
}

pub fn parse_proxy(map: &Map, caps: &Capabilities) -> Result<ProxyParse> {
    let Some(Value::String(type_name)) = map.get("type") else {
        return Err(ConfigError::new("missing type"));
    };
    let mut f = Fields::new(map, "", true);
    f.require("name");
    let name = f.string("name")?;
    match parse_typed(&mut f, type_name, caps) {
        Ok((kind, common, smux)) => {
            let ignored = f.take_ignored().iter().map(ToString::to_string).collect();
            f.finish()?;
            Ok(ProxyParse::Ok(Box::new(ProxyDef {
                name,
                common,
                kind,
                smux,
                ignored,
            })))
        }
        Err(Fail::Quarantine(reason)) => Ok(ProxyParse::Quarantined {
            name,
            kind: type_name.clone(),
            reason,
        }),
        Err(Fail::Hard(err)) => Err(err),
    }
}

fn parse_typed(
    f: &mut Fields<'_>,
    type_name: &str,
    caps: &Capabilities,
) -> R<(ProxyKind, CommonOpts, Option<SmuxOpts>)> {
    if T2_PROXY_TYPES.contains(&type_name) {
        return quarantine(format!(
            "proxy type '{type_name}' is not supported by this core"
        ));
    }
    if !T0_PROXY_TYPES.contains(&type_name) && !T1_PROXY_TYPES.contains(&type_name) {
        return quarantine(format!("unknown proxy type '{type_name}'"));
    }
    if !caps.proxy_types.contains(&type_name) {
        return quarantine(format!("proxy type '{type_name}' is not implemented yet"));
    }
    for key in T2_TLS_KEYS {
        if f.has(key) {
            return quarantine(format!("option '{key}' is not supported by this core"));
        }
    }
    if !matches!(type_name, "vmess" | "vless" | "trojan" | "anytls") {
        f.ignore("shadow-tls-opts", "this type does not use ShadowTLS");
        f.ignore("jls-opts", "this type does not use JLS");
    }
    let common = common_opts(f)?;
    let smux = smux_opts(f, caps)?;
    let kind = match type_name {
        "direct" => ProxyKind::Direct(DirectOpts),
        "reject" => ProxyKind::Reject(RejectOpts),
        "dns" => ProxyKind::Dns(DnsOpts),
        "rematch" => ProxyKind::Rematch(super::rematch::parse(f)?),
        "ss" => ProxyKind::Ss(parse_ss(f, caps)?),
        "vmess" => ProxyKind::Vmess(Box::new(parse_vmess(f, caps)?)),
        "vless" => ProxyKind::Vless(Box::new(parse_vless(f, caps)?)),
        "trojan" => ProxyKind::Trojan(Box::new(parse_trojan(f, caps)?)),
        "hysteria2" => ProxyKind::Hysteria2(Box::new(parse_hysteria2(f, caps)?)),
        "tuic" => ProxyKind::Tuic(Box::new(parse_tuic(f, caps)?)),
        "anytls" => ProxyKind::AnyTls(Box::new(parse_anytls(f, caps)?)),
        "miu" => ProxyKind::Miu(Box::new(parse_miu(f, caps)?)),
        "socks5" => ProxyKind::Socks5(parse_socks5(f)?),
        "gost-relay" => ProxyKind::GostRelay(Box::new(gost_relay_opts(f)?)),
        "http" => ProxyKind::Http(parse_http(f)?),
        "wireguard" => ProxyKind::WireGuard(Box::new(parse_wireguard(f)?)),
        "masque" => ProxyKind::Masque(Box::new(masque::parse(f)?)),
        "hysteria" => ProxyKind::Hysteria(Box::new(parse_hysteria(f, caps)?)),
        "ssr" => ProxyKind::Ssr(parse_ssr(f)?),
        "snell" => ProxyKind::Snell(parse_snell(f)?),
        "mieru" => ProxyKind::Mieru(parse_mieru(f)?),
        "ssh" => ProxyKind::Ssh(parse_ssh(f)?),
        "shadowquic" => ProxyKind::ShadowQuic(Box::new(parse_shadowquic(f)?)),
        _ => return quarantine(format!("unknown proxy type '{type_name}'")),
    };
    Ok((kind, common, smux))
}

fn common_opts(f: &mut Fields<'_>) -> R<CommonOpts> {
    Ok(CommonOpts {
        tfo: f.boolean("tfo")?,
        mptcp: f.boolean("mptcp")?,
        interface_name: f.string("interface-name")?,
        routing_mark: f.mark("routing-mark")?,
        ip_version: IpVersionPref::parse(&f.string("ip-version")?),
        dialer_proxy: f.string("dialer-proxy")?,
        udp: f.boolean("udp")?,
    })
}

fn smux_opts(f: &mut Fields<'_>, caps: &Capabilities) -> R<Option<SmuxOpts>> {
    if f.raw("smux").is_some_and(|smux| !smux.is_object()) {
        f.ignore("smux", "it is not a map");
        return Ok(None);
    }
    let Some(mut s) = f.sub("smux")? else {
        return Ok(None);
    };
    let mut out = SmuxOpts {
        enabled: s.boolean("enabled")?,
        protocol: s.string("protocol")?,
        max_connections: s.loose("max-connections", 0)?,
        min_streams: s.loose("min-streams", 0)?,
        max_streams: s.loose("max-streams", 0)?,
        padding: s.boolean("padding")?,
        statistic: s.boolean("statistic")?,
        only_tcp: s.boolean("only-tcp")?,
        brutal: None,
    };
    if let Some(mut b) = s.sub("brutal-opts")? {
        out.brutal = Some(BrutalOpts {
            enabled: b.boolean("enabled")?,
            up: b.string("up")?,
            down: b.string("down")?,
        });
    }
    if out.enabled {
        if !caps.smux {
            return quarantine("option 'smux' is not implemented yet");
        }
        if !matches!(out.protocol.as_str(), "" | "smux" | "yamux" | "h2mux") {
            return Err(Fail::Hard(ConfigError::new(format!(
                "unknown smux protocol: {}",
                out.protocol
            ))));
        }
    }
    Ok(Some(out))
}

fn ech_opts(f: &mut Fields<'_>, caps: &Capabilities) -> R<Option<EchOpts>> {
    let Some(mut e) = f.sub("ech-opts")? else {
        return Ok(None);
    };
    let out = EchOpts {
        enable: e.boolean("enable")?,
        config: e.string("config")?,
        query_server_name: e.string("query-server-name")?,
    };
    if out.enable {
        if !caps.ech {
            return quarantine("option 'ech-opts' is not implemented yet");
        }
        if !out.config.is_empty() && STANDARD.decode(out.config.as_bytes()).is_err() {
            return Err(Fail::Hard(ConfigError::new(
                "base64 decode ech config string failed",
            )));
        }
    }
    Ok(Some(out))
}

fn reality_opts(f: &mut Fields<'_>) -> R<Option<RealityOpts>> {
    let Some(mut r) = f.sub("reality-opts")? else {
        return Ok(None);
    };
    let version = r.string("client-version")?;
    let client_version = if version.is_empty() {
        None
    } else {
        let parts = version
            .split('.')
            .map(str::parse::<u8>)
            .collect::<Result<Vec<_>, _>>()
            .ok()
            .and_then(|parts| <[u8; 3]>::try_from(parts).ok())
            .ok_or_else(|| Fail::Hard(ConfigError::new("invalid REALITY client version")))?;
        Some(parts)
    };
    let verify = r.string("mldsa65-verify")?;
    let mldsa65_verify = if verify.is_empty() {
        None
    } else {
        let key = URL_SAFE_NO_PAD
            .decode(verify)
            .ok()
            .filter(|key| key.len() == 1952)
            .ok_or_else(|| {
                Fail::Hard(ConfigError::new(
                    "invalid REALITY ML-DSA-65 verification key",
                ))
            })?;
        Some(key)
    };
    let out = RealityOpts {
        public_key: r.req_string("public-key")?,
        short_id: r.string("short-id")?,
        support_x25519_mlkem768: !r.has("support-x25519mlkem768")
            || r.boolean("support-x25519mlkem768")?,
        client_version,
        mldsa65_verify,
    };
    r.finish()?;
    if out.public_key.is_empty() && (out.client_version.is_some() || out.mldsa65_verify.is_some()) {
        return Err(Fail::Hard(ConfigError::new(
            "REALITY authentication options require a public key",
        )));
    }
    if !out.public_key.is_empty() {
        let key = URL_SAFE_NO_PAD.decode(out.public_key.as_bytes());
        if key.map(|k| k.len()) != Ok(32) {
            return Err(Fail::Hard(ConfigError::new("invalid REALITY public key")));
        }
        let hex_ok = out.short_id.len().is_multiple_of(2)
            && out.short_id.len() <= 16
            && out.short_id.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex_ok {
            return Err(Fail::Hard(ConfigError::new("invalid REALITY short ID")));
        }
    }
    Ok(Some(out))
}

fn jls_auth(mut f: Fields<'_>) -> R<JlsOpts> {
    let auth = JlsOpts {
        username: f.string("username")?,
        password: f.string("password")?,
    };
    if auth.username.is_empty() != auth.password.is_empty() {
        return Err(Fail::Hard(ConfigError::new(
            "jls: username and password are required",
        )));
    }
    Ok(auth)
}

fn jls_opts(f: &mut Fields<'_>) -> R<Option<JlsOpts>> {
    let Some(o) = f.sub("jls-opts")? else {
        return Ok(None);
    };
    let auth = jls_auth(o)?;
    Ok((!auth.username.is_empty()).then_some(auth))
}

fn jls_plugin(mut f: Fields<'_>) -> R<JlsPlugin> {
    let host = f.req_string("host")?;
    let alpn = if f.has("alpn") {
        f.strings("alpn")?
    } else {
        vec!["h2".into(), "http/1.1".into()]
    };
    let auth = JlsOpts {
        username: f.req_string("username")?,
        password: f.req_string("password")?,
    };
    if host.is_empty() || auth.username.is_empty() || auth.password.is_empty() {
        return Err(Fail::Hard(ConfigError::new(
            "jls: host, username and password are required",
        )));
    }
    Ok(JlsPlugin { host, auth, alpn })
}

fn tls_opts(f: &mut Fields<'_>, name_key: &str, caps: &Capabilities) -> R<TlsOpts> {
    let mut tls = tls_fields(f, name_key, caps)?;
    tls.reality = reality_opts(f)?;
    tls.shadow_tls = shadow_tls_layer(f)?.flatten();
    tls.jls = jls_opts(f)?;
    Ok(tls)
}

/// mihomo `ShadowTLSOptions.Parse` (`adapter/outbound/shadowtls.go:10-15`): written with neither
/// a password nor a version it is off, and version 0 means 2.
fn shadow_tls_layer(f: &mut Fields<'_>) -> R<Option<Option<ShadowTlsLayer>>> {
    let Some(mut o) = f.sub("shadow-tls-opts")? else {
        return Ok(None);
    };
    let password = o.string("password")?;
    let version = o.i64("version")?;
    if password.is_empty() && version == 0 {
        return Ok(Some(None));
    }
    let version = if version == 0 { 2 } else { version };
    let Some(version) = u8::try_from(version).ok().filter(|v| (1..=3).contains(v)) else {
        return quarantine(format!("shadow-tls: unknown protocol version: {version}"));
    };
    Ok(Some(Some(ShadowTlsLayer { password, version })))
}

/// mihomo reads `reality-opts` on vmess, vless and trojan only.
fn tls_without_reality(f: &mut Fields<'_>, name_key: &str, caps: &Capabilities) -> R<TlsOpts> {
    f.ignore("reality-opts", "this type does not use REALITY");
    tls_fields(f, name_key, caps)
}

fn tls_fields(f: &mut Fields<'_>, name_key: &str, caps: &Capabilities) -> R<TlsOpts> {
    Ok(TlsOpts {
        enabled: false,
        server_name: f.string(name_key)?,
        alpn: f.strings("alpn")?,
        alpn_set: f.has("alpn"),
        skip_cert_verify: f.boolean("skip-cert-verify")?,
        fingerprint: f.string("fingerprint")?,
        certificate: f.string("certificate")?,
        private_key: f.string("private-key")?,
        name_cert_verify: f.string("name-cert-verify")?,
        client_fingerprint: f.string("client-fingerprint")?,
        reality: None,
        jls: None,
        ech: ech_opts(f, caps)?,
        shadow_tls: None,
    })
}

fn headers(f: &mut Fields<'_>, key: &str) -> R<IndexMap<String, String>> {
    Ok(f.string_map(key)?)
}

fn ws_opts(f: &mut Fields<'_>, upgrade: bool) -> R<WsOpts> {
    let mut out = WsOpts::default();
    if let Some(mut o) = f.sub("ws-opts")? {
        out.path = o.string("path")?;
        out.headers = headers(&mut o, "headers")?;
        out.max_early_data = o.loose("max-early-data", 0)?;
        out.early_data_header_name = o.string("early-data-header-name")?;
        out.v2ray_http_upgrade = o.boolean("v2ray-http-upgrade")?;
        out.v2ray_http_upgrade_fast_open = o.boolean("v2ray-http-upgrade-fast-open")?;
    }
    out.v2ray_http_upgrade |= upgrade;
    Ok(out)
}

fn reuse_settings(f: &mut Fields<'_>, key: &str) -> R<Option<XhttpReuse>> {
    let Some(mut r) = f.sub(key)? else {
        return Ok(None);
    };
    Ok(Some(XhttpReuse {
        max_concurrency: r.string("max-concurrency")?,
        max_connections: r.string("max-connections")?,
        c_max_reuse_times: r.string("c-max-reuse-times")?,
        h_max_request_times: r.string("h-max-request-times")?,
        h_max_reusable_secs: r.string("h-max-reusable-secs")?,
        h_keep_alive_period: r.loose("h-keep-alive-period", 0)?,
    }))
}

fn opt_text(f: &mut Fields<'_>, key: &str) -> R<Option<String>> {
    Ok(f.opt_string(key)?)
}

fn xhttp_download(mut d: Fields<'_>, caps: &Capabilities) -> R<XhttpDownload> {
    for key in T2_TLS_KEYS {
        if d.has(key) {
            return quarantine(format!(
                "option 'download-settings.{key}' is not supported by this core"
            ));
        }
    }
    let headers = if d.has("headers") {
        Some(headers(&mut d, "headers")?)
    } else {
        None
    };
    let alpn = if d.has("alpn") {
        Some(d.strings("alpn")?)
    } else {
        None
    };
    Ok(XhttpDownload {
        path: opt_text(&mut d, "path")?,
        host: opt_text(&mut d, "host")?,
        headers,
        reuse: reuse_settings(&mut d, "reuse-settings")?,
        server: opt_text(&mut d, "server")?,
        port: d.opt_u16("port")?,
        tls: d.opt_bool("tls")?,
        alpn,
        reality: reality_opts(&mut d)?,
        jls: d.sub("jls-opts")?.map(jls_auth).transpose()?,
        skip_cert_verify: d.opt_bool("skip-cert-verify")?,
        name_cert_verify: opt_text(&mut d, "name-cert-verify")?,
        fingerprint: opt_text(&mut d, "fingerprint")?,
        certificate: opt_text(&mut d, "certificate")?,
        private_key: opt_text(&mut d, "private-key")?,
        server_name: opt_text(&mut d, "servername")?,
        client_fingerprint: opt_text(&mut d, "client-fingerprint")?,
        ech: ech_opts(&mut d, caps)?,
        shadow_tls: shadow_tls_layer(&mut d)?,
    })
}

fn xhttp_opts(f: &mut Fields<'_>, caps: &Capabilities) -> R<XhttpOpts> {
    let Some(mut o) = f.sub("xhttp-opts")? else {
        return Ok(XhttpOpts::default());
    };
    let out = XhttpOpts {
        path: o.string("path")?,
        host: o.string("host")?,
        mode: o.string("mode")?,
        headers: headers(&mut o, "headers")?,
        no_grpc_header: o.boolean("no-grpc-header")?,
        x_padding_bytes: o.string("x-padding-bytes")?,
        x_padding_obfs_mode: o.boolean("x-padding-obfs-mode")?,
        x_padding_key: o.string("x-padding-key")?,
        x_padding_header: o.string("x-padding-header")?,
        x_padding_placement: o.string("x-padding-placement")?,
        x_padding_method: o.string("x-padding-method")?,
        uplink_http_method: o.string("uplink-http-method")?,
        session_placement: o.string("session-placement")?,
        session_key: o.string("session-key")?,
        session_table: o.string("session-table")?,
        session_length: o.string("session-length")?,
        seq_placement: o.string("seq-placement")?,
        seq_key: o.string("seq-key")?,
        uplink_data_placement: o.string("uplink-data-placement")?,
        uplink_data_key: o.string("uplink-data-key")?,
        uplink_chunk_size: o.string("uplink-chunk-size")?,
        sc_max_each_post_bytes: o.string("sc-max-each-post-bytes")?,
        sc_min_posts_interval_ms: o.string("sc-min-posts-interval-ms")?,
        reuse: reuse_settings(&mut o, "reuse-settings")?,
        download: match o.sub("download-settings")? {
            Some(d) => Some(Box::new(xhttp_download(d, caps)?)),
            None => None,
        },
    };
    Ok(out)
}

fn transport(f: &mut Fields<'_>, network: &str, caps: &Capabilities) -> R<Transport> {
    f.ignore("ws-path", "it was removed; write ws-opts.path");
    f.ignore("ws-headers", "it was removed; write ws-opts.headers");
    let network = network.to_ascii_lowercase();
    if T2_NETWORKS.contains(&network.as_str()) {
        return quarantine(format!("network '{network}' is not supported by this core"));
    }
    let known = matches!(
        network.as_str(),
        "ws" | "httpupgrade" | "grpc" | "h2" | "http" | "xhttp"
    );
    if known && !caps.transports.contains(&network.as_str()) {
        return quarantine(format!("network '{network}' is not implemented yet"));
    }
    Ok(match network.as_str() {
        "ws" => Transport::Ws(ws_opts(f, false)?),
        "httpupgrade" => Transport::Ws(ws_opts(f, true)?),
        "grpc" => {
            let mut out = GrpcOpts::default();
            if let Some(mut o) = f.sub("grpc-opts")? {
                out.service_name = o.string("grpc-service-name")?;
                out.user_agent = o.string("grpc-user-agent")?;
                out.ping_interval = o.loose("ping-interval", 0)?;
                out.max_connections = o.loose("max-connections", 0)?;
                out.min_streams = o.loose("min-streams", 0)?;
                out.max_streams = o.loose("max-streams", 0)?;
            }
            Transport::Grpc(out)
        }
        "h2" => {
            let mut out = H2Opts::default();
            if let Some(mut o) = f.sub("h2-opts")? {
                out.host = o.strings("host")?;
                out.path = o.string("path")?;
            }
            Transport::H2(out)
        }
        "http" => {
            let mut out = HttpOpts::default();
            if let Some(mut o) = f.sub("http-opts")? {
                out.method = o.string("method")?;
                out.path = o.strings("path")?;
                out.headers = o.list_map("headers")?;
            }
            Transport::Http(out)
        }
        "xhttp" => Transport::Xhttp(Box::new(xhttp_opts(f, caps)?)),
        _ => Transport::Tcp,
    })
}

fn server_port(f: &mut Fields<'_>) -> R<(String, u16)> {
    Ok((f.req_string("server")?, f.req_u16("port")?))
}

struct PluginOpts(Map);

fn plugin_fields(map: &PluginOpts) -> Fields<'_> {
    Fields::new(&map.0, "plugin-opts", false)
}

fn shadow_tls_opts(mut o: Fields<'_>, node: &str) -> R<ShadowTlsOpts> {
    let host = o.req_string("host")?;
    let version = o.opt_u16("version")?.unwrap_or(2);
    let version = u8::try_from(version).unwrap_or(0);
    if !(1..=3).contains(&version) {
        return quarantine(format!("{node} shadow-tls version error: {version}"));
    }
    let alpn = if o.has("alpn") {
        o.strings("alpn")?
    } else {
        vec!["h2".into(), "http/1.1".into()]
    };
    let opts = ShadowTlsOpts {
        host,
        password: o.string("password")?,
        version,
        fingerprint: o.string("fingerprint")?,
        skip_cert_verify: o.boolean("skip-cert-verify")?,
        alpn,
        certificate: o.string("certificate")?,
        private_key: o.string("private-key")?,
        name_cert_verify: o.string("name-cert-verify")?,
    };
    o.finish()?;
    Ok(opts)
}

fn packet_fields(f: &mut Fields<'_>) -> R<(bool, bool, String)> {
    Ok((
        f.boolean("packet-addr")?,
        f.boolean("xudp")?,
        f.string("packet-encoding")?,
    ))
}

fn parse_vmess(f: &mut Fields<'_>, caps: &Capabilities) -> R<VmessOpts> {
    let (server, port) = server_port(f)?;
    let uuid = f.req_string("uuid")?;
    let cipher = f.req_string("cipher")?;
    let mut tls = tls_opts(f, "servername", caps)?;
    tls.enabled = f.boolean("tls")?;
    let network = f.string("network")?;
    let transport = transport(f, &network, caps)?;
    let (packet_addr, xudp, packet_encoding) = packet_fields(f)?;
    Ok(VmessOpts {
        server,
        port,
        uuid,
        alter_id: f.loose("alterid", 0)?,
        cipher,
        tls,
        transport,
        packet_addr,
        xudp,
        packet_encoding,
        global_padding: f.boolean("global-padding")?,
        authenticated_length: f.boolean("authenticated-length")?,
    })
}

fn parse_vless(f: &mut Fields<'_>, caps: &Capabilities) -> R<VlessOpts> {
    let (server, port) = server_port(f)?;
    let uuid = f.req_string("uuid")?;
    let mut tls = tls_opts(f, "servername", caps)?;
    tls.enabled = f.boolean("tls")?;
    let network = f.string("network")?;
    let transport = transport(f, &network, caps)?;
    let (packet_addr, xudp, packet_encoding) = packet_fields(f)?;
    Ok(VlessOpts {
        server,
        port,
        uuid,
        flow: f.string("flow")?,
        encryption: f.string("encryption")?,
        tls,
        transport,
        packet_addr,
        xudp,
        packet_encoding,
    })
}

fn parse_trojan(f: &mut Fields<'_>, caps: &Capabilities) -> R<TrojanOpts> {
    let (server, port) = server_port(f)?;
    let password = f.req_string("password")?;
    let mut tls = tls_opts(f, "sni", caps)?;
    tls.enabled = true;
    let network = f.string("network")?;
    // mihomo's trojan speaks only ws and grpc; any other network is plain TCP.
    let transport = match transport(f, &network, caps)? {
        Transport::H2(_) | Transport::Http(_) => Transport::Tcp,
        other => other,
    };
    let ss = match f.sub("ss-opts")? {
        Some(mut o) => Some(TrojanSsOpts {
            enabled: o.boolean("enabled")?,
            method: o.string("method")?,
            password: o.string("password")?,
        }),
        None => None,
    };
    Ok(TrojanOpts {
        server,
        port,
        password,
        tls,
        transport,
        ss,
    })
}

fn port_or_ports(f: &mut Fields<'_>, port: u16, ports_key: &str, what: &str) -> R<String> {
    let ports = f.string(ports_key)?;
    if port == 0 && ports.is_empty() {
        return Err(Fail::Hard(ConfigError::new(format!(
            "{what}: either 'port' or '{ports_key}' must be set"
        ))));
    }
    Ok(ports)
}

fn parse_hysteria2(f: &mut Fields<'_>, caps: &Capabilities) -> R<Hysteria2Opts> {
    let server = f.req_string("server")?;
    let port = f.u16("port")?;
    let ports = port_or_ports(f, port, "ports", "hysteria2")?;
    let mut tls = tls_without_reality(f, "sni", caps)?;
    tls.enabled = true;
    let realm = match f.sub("realm-opts")? {
        Some(mut r) => {
            let mut realm = Hysteria2Realm {
                enable: r.boolean("enable")?,
                server_url: r.string("server-url")?,
                token: r.string("token")?,
                realm_id: r.string("realm-id")?,
                stun_servers: r.strings("stun-servers")?,
                sni: r.string("sni")?,
                skip_cert_verify: r.boolean("skip-cert-verify")?,
                name_cert_verify: r.string("name-cert-verify")?,
                fingerprint: r.string("fingerprint")?,
                certificate: r.string("certificate")?,
                private_key: r.string("private-key")?,
                alpn: r.strings("alpn")?,
            };
            if realm.enable && realm.server_url.is_empty() {
                return Err(Fail::Hard(ConfigError::new(
                    "realm-opts: server-url is required",
                )));
            }
            if !realm.enable {
                realm.stun_servers.clear();
            }
            Some(realm)
        }
        None => None,
    };
    Ok(Hysteria2Opts {
        server,
        port,
        ports,
        hop_interval: f.string("hop-interval")?,
        up: f.string("up")?,
        down: f.string("down")?,
        password: f.string("password")?,
        obfs: f.string("obfs")?,
        obfs_password: f.string("obfs-password")?,
        obfs_min_packet_size: f.loose("obfs-min-packet-size", 0)?,
        obfs_max_packet_size: f.loose("obfs-max-packet-size", 0)?,
        tls,
        cwnd: f.loose("cwnd", 0)?,
        bbr_profile: f.string("bbr-profile")?,
        udp_mtu: f.loose("udp-mtu", 0)?,
        handshake_timeout: f.loose("handshake-timeout", 0)?,
        realm,
        initial_stream_receive_window: f.u64("initial-stream-receive-window")?,
        max_stream_receive_window: f.u64("max-stream-receive-window")?,
        initial_connection_receive_window: f.u64("initial-connection-receive-window")?,
        max_connection_receive_window: f.u64("max-connection-receive-window")?,
    })
}

fn parse_tuic(f: &mut Fields<'_>, caps: &Capabilities) -> R<TuicOpts> {
    let (server, port) = server_port(f)?;
    let mut tls = tls_without_reality(f, "sni", caps)?;
    tls.enabled = true;
    let out = TuicOpts {
        server,
        port,
        token: f.string("token")?,
        uuid: f.string("uuid")?,
        password: f.string("password")?,
        ip: f.string("ip")?,
        heartbeat_interval: f.loose("heartbeat-interval", 0)?,
        tls,
        reduce_rtt: f.boolean("reduce-rtt")?,
        request_timeout: f.loose("request-timeout", 0)?,
        udp_relay_mode: f.string("udp-relay-mode")?,
        congestion_controller: f.string("congestion-controller")?,
        disable_sni: f.boolean("disable-sni")?,
        max_udp_relay_packet_size: f.loose("max-udp-relay-packet-size", 0)?,
        fast_open: f.boolean("fast-open")?,
        max_open_streams: f.loose("max-open-streams", 0)?,
        cwnd: f.loose("cwnd", 0)?,
        bbr_profile: f.string("bbr-profile")?,
        recv_window_conn: f.loose("recv-window-conn", 0)?,
        recv_window: f.loose("recv-window", 0)?,
        disable_mtu_discovery: f.boolean("disable-mtu-discovery")?,
        max_datagram_frame_size: f.loose("max-datagram-frame-size", 0)?,
        udp_over_stream: f.boolean("udp-over-stream")?,
        udp_over_stream_version: u8::try_from(f.u32("udp-over-stream-version")?).unwrap_or(0),
    };
    if out.token.is_empty() && (out.uuid.is_empty() || out.password.is_empty()) {
        return quarantine("tuic: either 'token' or both 'uuid' and 'password' must be set");
    }
    Ok(out)
}

fn parse_miu(f: &mut Fields<'_>, caps: &Capabilities) -> R<MiuOpts> {
    let (server, port) = server_port(f)?;
    let psk = f.req_string("psk")?.trim().to_string();
    if psk.len() < 16 {
        return Err(ConfigError::new("miu: psk must contain at least 16 bytes").into());
    }
    let mut tls = tls_opts(f, "sni", caps)?;
    if tls.server_name.is_empty() {
        tls.server_name = f.string("servername")?;
    } else {
        f.string("servername")?;
    }
    f.boolean("tls")?;
    tls.enabled = true;
    let idle = f.i64("idle-session-timeout")?;
    let min_idle = f.i64("min-idle-session")?;
    if !(0..=9_223_372_035).contains(&idle) || !(0..=32).contains(&min_idle) {
        return Err(ConfigError::new("miu: invalid idle session settings").into());
    }
    Ok(MiuOpts {
        server,
        port,
        psk,
        tls,
        idle_session_timeout: idle as u64,
        min_idle_session: min_idle as u8,
    })
}

fn parse_anytls(f: &mut Fields<'_>, caps: &Capabilities) -> R<AnyTlsOpts> {
    let (server, port) = server_port(f)?;
    let password = f.req_string("password")?;
    let mut tls = tls_without_reality(f, "sni", caps)?;
    tls.jls = jls_opts(f)?;
    tls.enabled = true;
    tls.shadow_tls = shadow_tls_layer(f)?.flatten();
    // mihomo reads these as int; a negative one acts as unset.
    let mut non_negative =
        |key: &str| -> R<u32> { Ok(u32::try_from(f.i64(key)?.max(0)).unwrap_or(u32::MAX)) };
    Ok(AnyTlsOpts {
        idle_session_check_interval: non_negative("idle-session-check-interval")?,
        idle_session_timeout: non_negative("idle-session-timeout")?,
        min_idle_session: non_negative("min-idle-session")?,
        server,
        port,
        password,
        tls,
        client_metadata: f.string("client-metadata")?,
        disable_reuse: f.boolean("disable-reuse")?,
    })
}

/// mihomo's socks5 and http nodes dial plain Go TLS: no ALPN, uTLS, REALITY or ECH.
fn plain_tls(f: &mut Fields<'_>) -> R<TlsOpts> {
    for key in ["alpn", "client-fingerprint", "reality-opts", "ech-opts"] {
        f.ignore(key, "socks5 and http nodes dial plain TLS");
    }
    Ok(TlsOpts {
        enabled: f.boolean("tls")?,
        server_name: f.string("sni")?,
        skip_cert_verify: f.boolean("skip-cert-verify")?,
        fingerprint: f.string("fingerprint")?,
        certificate: f.string("certificate")?,
        private_key: f.string("private-key")?,
        name_cert_verify: f.string("name-cert-verify")?,
        ..TlsOpts::default()
    })
}

fn parse_socks5(f: &mut Fields<'_>) -> R<Socks5Opts> {
    let (server, port) = server_port(f)?;
    let tls = TlsOpts {
        server_name: String::new(),
        ..plain_tls(f)?
    };
    Ok(Socks5Opts {
        server,
        port,
        username: f.string("username")?,
        password: f.string("password")?,
        tls,
    })
}

fn parse_http(f: &mut Fields<'_>) -> R<HttpProxyOpts> {
    let (server, port) = server_port(f)?;
    let tls = plain_tls(f)?;
    Ok(HttpProxyOpts {
        server,
        port,
        username: f.string("username")?,
        password: f.string("password")?,
        tls,
        headers: headers(f, "headers")?,
    })
}

fn parse_wireguard(f: &mut Fields<'_>) -> R<WireGuardOpts> {
    let private_key = f.req_string("private-key")?;
    let mut out = WireGuardOpts {
        ip: f.string("ip")?,
        ipv6: f.string("ipv6")?,
        private_key,
        workers: f.loose("workers", 0)?,
        mtu: f.loose("mtu", 0)?,
        persistent_keepalive: f.loose("persistent-keepalive", 0)?,
        remote_dns_resolve: f.boolean("remote-dns-resolve")?,
        dns: f.strings("dns")?,
        refresh_server_ip_interval: f.loose("refresh-server-ip-interval", 0)?,
        ..WireGuardOpts::default()
    };
    if let Some(mut stack) = f.sub("ip-stack")? {
        out.ip_stack_mode = stack.string("mode")?;
        out.ip_stack_congestion_controller = stack.string("congestion-controller")?;
    }
    if let Some(mut a) = f.sub("amnezia-wg-option")? {
        out.amnezia = Some(AmneziaWgOpts {
            version: a.u32("version")?,
            jc: a.loose("jc", 0)?,
            jmin: a.loose("jmin", 0)?,
            jmax: a.loose("jmax", 0)?,
            s1: a.loose("s1", 0)?,
            s2: a.loose("s2", 0)?,
            s3: a.loose("s3", 0)?,
            s4: a.loose("s4", 0)?,
            h: [
                a.string("h1")?,
                a.string("h2")?,
                a.string("h3")?,
                a.string("h4")?,
            ],
            i: [
                a.string("i1")?,
                a.string("i2")?,
                a.string("i3")?,
                a.string("i4")?,
                a.string("i5")?,
            ],
            j: [a.string("j1")?, a.string("j2")?, a.string("j3")?],
            itime: a.i64("itime")?,
            header_protection_key: a.string("header-protection-key")?,
            content_padding_addition: a.string("content-padding-addition")?,
            rekey_after_time: a.string("rekey-after-time")?,
            rekey_timeout: a.string("rekey-timeout")?,
            reject_after_time: a.string("reject-after-time")?,
            keepalive_timeout: a.string("keepalive-timeout")?,
            max_handshake_attempts: a.string("max-handshake-attempts")?,
            random_trailers: a.boolean("random-trailers")?,
            disable_cookies: a.boolean("disable-cookies")?,
        });
    }
    let reserved = f.u8_list("reserved")?;
    if let Some(Value::Array(peers)) = f.raw("peers") {
        for (index, peer) in peers.iter().enumerate() {
            let Value::Object(peer) = peer else {
                return Err(Fail::Hard(ConfigError::new(format!(
                    "'peers[{index}]' expected a map"
                ))));
            };
            let mut p = Fields::new(peer, &format!("peers[{index}]"), true);
            let allowed_ips = p.strings("allowed-ips")?;
            if allowed_ips.is_empty() {
                return Err(Fail::Hard(ConfigError::new(format!(
                    "missing allowed_ips for peer {index}"
                ))));
            }
            let own = p.u8_list("reserved")?;
            out.peers.push(WgPeer {
                server: p.string("server")?,
                port: p.u16("port")?,
                public_key: p.string("public-key")?,
                pre_shared_key: p.string("pre-shared-key")?,
                reserved: if own.is_empty() {
                    reserved.clone()
                } else {
                    own
                },
                allowed_ips,
            });
        }
    }
    if out.peers.is_empty() {
        let server = f.string("server")?;
        if server.is_empty() {
            return quarantine("wireguard: server or peers must be set");
        }
        out.peers.push(WgPeer {
            server,
            port: f.u16("port")?,
            public_key: f.string("public-key")?,
            pre_shared_key: f.string("pre-shared-key")?,
            reserved,
            allowed_ips: Vec::new(),
        });
    }
    Ok(out)
}

fn parse_hysteria(f: &mut Fields<'_>, caps: &Capabilities) -> R<HysteriaOpts> {
    let server = f.req_string("server")?;
    let port = f.u16("port")?;
    let ports = f.string("ports")?;
    if port == 0 && ports.is_empty() {
        return quarantine("hysteria: either 'port' or 'ports' must be set");
    }
    let mut tls = tls_without_reality(f, "sni", caps)?;
    tls.enabled = true;
    Ok(HysteriaOpts {
        server,
        port,
        ports,
        protocol: f.string("protocol")?,
        obfs_protocol: f.string("obfs-protocol")?,
        up: f.req_string("up")?,
        up_speed: f.loose("up-speed", 0)?,
        down: f.req_string("down")?,
        down_speed: f.loose("down-speed", 0)?,
        auth: f.string("auth")?,
        auth_str: f.string("auth-str")?,
        obfs: f.string("obfs")?,
        tls,
        recv_window_conn: f.loose("recv-window-conn", 0)?,
        recv_window: f.loose("recv-window", 0)?,
        disable_mtu_discovery: f.boolean("disable-mtu-discovery")?,
        fast_open: f.boolean("fast-open")?,
        hop_interval: f.loose("hop-interval", 0)?,
    })
}

fn parse_ssr(f: &mut Fields<'_>) -> R<SsrOpts> {
    let (server, port) = server_port(f)?;
    Ok(SsrOpts {
        server,
        port,
        password: f.req_string("password")?,
        cipher: f.req_string("cipher")?,
        obfs: f.req_string("obfs")?,
        obfs_param: f.string("obfs-param")?,
        protocol: f.req_string("protocol")?,
        protocol_param: f.string("protocol-param")?,
    })
}

fn parse_snell(f: &mut Fields<'_>) -> R<SnellOpts> {
    let (server, port) = server_port(f)?;
    let psk = f.req_string("psk")?;
    let mut out = SnellOpts {
        server,
        port,
        psk,
        version: f.u32("version")?,
        reuse: f.boolean("reuse")?,
        client_fingerprint: f.string("client-fingerprint")?,
        ..SnellOpts::default()
    };
    if out.version == 6 {
        out.mode = f.string("mode")?;
        out.userkey = f.string("userkey")?;
        if out.userkey.len() > 255 {
            return quarantine("snell userkey must be at most 255 bytes");
        }
    } else {
        f.ignore("userkey", "only snell version 6 reads it");
        f.ignore("mode", "only snell version 6 reads it");
    }
    if let Some(mut o) = f.sub("obfs-opts")? {
        out.obfs_mode = o.string("mode")?;
        if out.obfs_mode == "shadow-tls" {
            let node = format!("snell {}:{}", out.server, out.port);
            out.shadow_tls = Some(shadow_tls_opts(o, &node)?);
        } else if out.obfs_mode == "jls" {
            out.jls = Some(jls_plugin(o)?);
        } else {
            out.obfs_host = o
                .opt_string("host")?
                .unwrap_or_else(|| "bing.com".to_string());
        }
    }
    Ok(out)
}

fn parse_mieru(f: &mut Fields<'_>) -> R<MieruOpts> {
    let server = f.req_string("server")?;
    let port = f.u16("port")?;
    let port_range = port_or_ports(f, port, "port-range", "mieru")?;
    Ok(MieruOpts {
        server,
        port,
        port_range,
        transport: f.req_string("transport")?,
        username: f.req_string("username")?,
        password: f.req_string("password")?,
        multiplexing: f.string("multiplexing")?,
        handshake_mode: f.string("handshake-mode")?,
        traffic_pattern: f.string("traffic-pattern")?,
    })
}

fn parse_ssh(f: &mut Fields<'_>) -> R<SshOpts> {
    let (server, port) = server_port(f)?;
    Ok(SshOpts {
        server,
        port,
        username: f.req_string("username")?,
        password: f.string("password")?,
        private_key: f.string("private-key")?,
        private_key_passphrase: f.string("private-key-passphrase")?,
        host_key: f.strings("host-key")?,
        host_key_algorithms: f.strings("host-key-algorithms")?,
    })
}

fn parse_shadowquic(f: &mut Fields<'_>) -> R<ShadowQuicOpts> {
    let (server, port) = server_port(f)?;
    Ok(ShadowQuicOpts {
        server,
        port,
        username: f.string("username")?,
        password: f.string("password")?,
        sni: f.string("sni")?,
        alpn: f.strings("alpn")?,
        quic_versions: f.strings("quic-versions")?,
        udp_over_stream: f.boolean("udp-over-stream")?,
        zero_rtt: f.boolean("zero-rtt")?,
        keep_alive_interval: f.loose("keep-alive-interval", 0)?,
        congestion_controller: f.string("congestion-controller")?,
        up: f.string("up")?,
        down: f.string("down")?,
        cwnd: f.loose("cwnd", 0)?,
        bbr_profile: f.string("bbr-profile")?,
        recv_window_conn: f.loose("recv-window-conn", 0)?,
        recv_window: f.loose("recv-window", 0)?,
        disable_mtu_discovery: f.boolean("disable-mtu-discovery")?,
        max_datagram_frame_size: f.loose("max-datagram-frame-size", 0)?,
        max_open_streams: f.loose("max-open-streams", 0)?,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(value: Value) -> Result<ProxyParse> {
        match value {
            Value::Object(map) => parse_proxy(&map, &Capabilities::full()),
            _ => Err(ConfigError::new("not a map")),
        }
    }

    fn def(value: Value) -> ProxyDef {
        match parse(value) {
            Ok(ProxyParse::Ok(def)) => *def,
            other => panic!("expected a proxy, got {other:?}"),
        }
    }

    fn quarantined(value: Value) -> String {
        match parse(value) {
            Ok(ProxyParse::Quarantined { reason, .. }) => reason,
            other => panic!("expected quarantine, got {other:?}"),
        }
    }

    fn error(value: Value) -> String {
        parse(value).unwrap_err().message
    }

    #[test]
    fn rematch_preserves_absent_and_empty_targets() {
        for (field, opts) in [
            (
                "target-rematch-name",
                RematchOpts {
                    target_rematch_name: Some(String::new()),
                    target_sub_rule: None,
                },
            ),
            (
                "target-sub-rule",
                RematchOpts {
                    target_rematch_name: None,
                    target_sub_rule: Some(String::new()),
                },
            ),
        ] {
            let mut value = json!({"name": "r", "type": "rematch"});
            value[field] = json!("");
            assert_eq!(def(value).kind, ProxyKind::Rematch(opts));
        }
        assert_eq!(
            error(json!({"name": "r", "type": "rematch"})),
            "rematch requires at least one of target-rematch-name or target-sub-rule"
        );
        let proxy = def(
            json!({"name":"r", "type":"rematch", "target-rematch-name":"Next", "target-sub-rule":"inner"}),
        );
        assert_eq!(
            proxy.kind,
            ProxyKind::Rematch(RematchOpts {
                target_rematch_name: Some("Next".into()),
                target_sub_rule: Some("inner".into())
            })
        );
    }

    #[test]
    fn supported_types_parse_with_weak_typing() {
        let p = def(
            json!({"name": "a", "type": "ss", "server": "x", "port": "8388", "cipher": "aes-128-gcm",
            "password": 123, "UDP": "true", "plugin": "obfs", "plugin-opts": {"mode": "tls"}}),
        );
        let ProxyKind::Ss(ss) = &p.kind else {
            panic!("not ss")
        };
        assert_eq!((ss.port, ss.password.as_str()), (8388, "123"));
        assert!(p.common.udp);
        assert_eq!(
            ss.plugin,
            Some(SsPlugin::Obfs {
                mode: "tls".into(),
                host: "bing.com".into()
            })
        );
        let p = def(
            json!({"name": "v", "type": "vmess", "server": "x", "port": 443, "uuid": "u", "cipher": "auto",
            "tls": true, "servername": "s", "network": "ws", "ws_opts": {"path": "/p", "headers": {"Host": "h"}},
            "alterId": 2}),
        );
        let ProxyKind::Vmess(v) = &p.kind else {
            panic!("not vmess")
        };
        assert_eq!(v.alter_id, 2);
        assert!(v.tls.enabled);
        assert!(
            matches!(&v.transport, Transport::Ws(ws) if ws.path == "/p" && ws.headers["Host"] == "h")
        );
    }

    #[test]
    fn a_routing_mark_is_read_as_the_low_32_bits_of_an_int() {
        for (mark, expected) in [
            (json!(2_147_483_648_u64), 0x8000_0000),
            (json!(-1), u32::MAX),
        ] {
            let node = def(json!({"name": "d", "type": "direct", "routing-mark": mark}));
            assert_eq!(node.common.routing_mark, expected);
        }
    }

    #[test]
    fn download_settings_with_a_tls_layer_this_core_lacks_set_the_node_aside() {
        for key in ["restls-opts", "tlsmirror-opts"] {
            let node = json!({"name": "e", "type": "vless", "server": "x", "port": 1, "uuid": "u", "network": "xhttp",
                "xhttp-opts": {"download-settings": {key: {"password": "p"}}}});
            assert!(quarantined(node).contains(&format!("download-settings.{key}")));
        }
    }

    #[test]
    fn jls_download_settings_validate_credentials_and_keep_explicit_disable() {
        let mut node = json!({"name": "e", "type": "vless", "server": "x", "port": 1, "uuid": "u", "tls": true, "network": "xhttp",
            "jls-opts": {"username": "parent", "password": "parent"},
            "xhttp-opts": {"download-settings": {"jls-opts": {"password": "p"}}}});
        assert_eq!(
            error(node.clone()),
            "jls: username and password are required"
        );
        for (value, username) in [
            (json!({"username": "child", "password": "p"}), "child"),
            (json!({}), ""),
        ] {
            node["xhttp-opts"]["download-settings"]["jls-opts"] = value;
            let parsed = def(node.clone());
            let ProxyKind::Vless(opts) = &parsed.kind else {
                panic!("expected vless")
            };
            let Transport::Xhttp(xhttp) = &opts.transport else {
                panic!("expected xhttp")
            };
            let auth = xhttp.download.as_ref().unwrap().jls.as_ref().unwrap();
            assert_eq!(auth.username, username);
        }
    }

    #[test]
    fn missing_required_fields_are_hard_errors() {
        let message = error(json!({"name": "a", "type": "trojan", "server": "x"}));
        assert_eq!(message, "'' has unset fields: password, port");
        assert!(
            error(json!({"name": "a", "type": "vless", "server": "x", "port": 1})).contains("uuid")
        );
        assert_eq!(error(json!({"name": "a"})), "missing type");
        assert!(error(json!({"type": "direct"})).contains("name"));
        assert!(error(json!({"name": "a", "type": "hysteria2", "server": "x"})).contains("ports"));
        let message = error(
            json!({"name": "a", "type": "vless", "server": "x", "port": 1, "uuid": "u",
            "tls": true, "reality-opts": {"short-id": "ab"}}),
        );
        assert!(
            message.contains("reality-opts") && message.contains("public-key"),
            "{message}"
        );
        assert!(error(json!({"name": "a", "type": "ss", "server": "x", "port": "abc", "cipher": "c", "password": "p"}))
            .contains("port"));
    }

    #[test]
    fn a_negative_tuning_number_reads_as_unset_with_a_warning() {
        let tuic = def(
            json!({"name": "t", "type": "tuic", "server": "x", "port": 1, "token": "k",
                              "heartbeat-interval": -1, "cwnd": 4294967296_u64}),
        );
        let ProxyKind::Tuic(opts) = &tuic.kind else {
            panic!()
        };
        assert_eq!((opts.heartbeat_interval, opts.cwnd), (0, 0));
        assert_eq!(
            crate::proxy::proxy_warnings(&tuic),
            [
                "heartbeat-interval is ignored: -1 is out of range",
                "cwnd is ignored: 4294967296 is out of range"
            ]
        );
        let vmess = def(
            json!({"name": "v", "type": "vmess", "server": "x", "port": 1, "uuid": "u",
                               "cipher": "auto", "alterId": -1, "network": "grpc",
                               "grpc-opts": {"ping-interval": -5}, "smux": {"enabled": true, "max-streams": -1}}),
        );
        assert_eq!(
            crate::proxy::proxy_warnings(&vmess),
            [
                "smux.max-streams is ignored: -1 is out of range",
                "grpc-opts.ping-interval is ignored: -5 is out of range",
                "alterid is ignored: -1 is out of range"
            ]
        );
        let snell = json!({"name": "s", "type": "snell", "server": "x", "port": 1, "psk": "k", "version": -1});
        assert!(
            parse(snell).is_err(),
            "a version picks the protocol, so it is not read past"
        );
    }

    #[test]
    fn keys_a_type_does_not_have_are_ignored_with_a_warning() {
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let cases = [
            (
                json!({"name": "a", "type": "vmess", "server": "x", "port": 1, "uuid": "u", "cipher": "auto", "smux": true}),
                vec!["smux is ignored: it is not a map"],
            ),
            (
                json!({"name": "b", "type": "hysteria2", "server": "x", "port": 1, "password": "p",
                       "reality-opts": {"public-key": key}}),
                vec!["reality-opts is ignored: this type does not use REALITY"],
            ),
            (
                json!({"name": "c", "type": "socks5", "server": "x", "port": 1, "alpn": ["h2"],
                       "ech-opts": {"enable": true, "config": "%"}}),
                vec![
                    "alpn is ignored: socks5 and http nodes dial plain TLS",
                    "ech-opts is ignored: socks5 and http nodes dial plain TLS",
                ],
            ),
        ];
        for (node, expected) in cases {
            let parsed = def(node);
            assert_eq!(crate::proxy::proxy_warnings(&parsed), expected);
        }
        let removed = [
            (
                json!({"name": "w", "type": "vmess", "server": "x", "port": 1, "uuid": "u", "cipher": "auto",
                       "network": "ws", "ws-path": "/p", "ws-headers": {"Host": "h"}}),
                vec![
                    "ws-path is ignored: it was removed; write ws-opts.path",
                    "ws-headers is ignored: it was removed; write ws-opts.headers",
                ],
            ),
            (
                json!({"name": "s", "type": "snell", "server": "x", "port": 1, "psk": "k", "version": 4,
                       "userkey": "u", "mode": "unshaped"}),
                vec![
                    "userkey is ignored: only snell version 6 reads it",
                    "mode is ignored: only snell version 6 reads it",
                ],
            ),
        ];
        for (node, expected) in removed {
            assert_eq!(crate::proxy::proxy_warnings(&def(node)), expected);
        }
        let reality_kept = def(
            json!({"name": "d", "type": "vless", "server": "x", "port": 1, "uuid": "u",
            "tls": true, "reality-opts": {"public-key": key}}),
        );
        assert!(crate::proxy::proxy_warnings(&reality_kept).is_empty());
    }

    #[test]
    fn unsupported_things_are_quarantined_not_rejected() {
        for kind in [
            "tailscale",
            "easytier",
            "zerotier",
            "openvpn",
            "sudoku",
            "trusttunnel",
        ] {
            let reason = quarantined(json!({"name": "n", "type": kind}));
            assert!(reason.contains(kind), "{reason}");
        }
        assert!(
            quarantined(json!({"name": "n", "type": "mystery"})).contains("unknown proxy type")
        );
        let base = json!({"name": "n", "type": "vmess", "server": "x", "port": 1, "uuid": "u", "cipher": "auto"});
        for (key, value) in [
            ("network", json!("mkcp")),
            ("network", json!("kcp")),
            ("restls-opts", json!({})),
            ("tlsmirror-opts", json!({})),
        ] {
            let mut proxy = base.clone();
            proxy[key] = value;
            quarantined(proxy);
        }
        for plugin in ["restls", "kcptun"] {
            quarantined(
                json!({"name": "n", "type": "ss", "server": "x", "port": 1, "cipher": "c", "password": "p", "plugin": plugin}),
            );
        }
    }

    #[test]
    fn capabilities_gate_tier_one_features() {
        let caps = Capabilities::tier0();
        let wg =
            json!({"name": "w", "type": "wireguard", "server": "x", "port": 1, "private-key": "k"});
        let Value::Object(map) = wg.clone() else {
            return;
        };
        assert!(matches!(
            parse_proxy(&map, &caps),
            Ok(ProxyParse::Quarantined { .. })
        ));
        assert!(matches!(parse(wg), Ok(ProxyParse::Ok(_))));
        let Value::Object(map) = json!({"name": "n", "type": "ss", "server": "x", "port": 1, "cipher": "c", "password": "p",
            "smux": {"enabled": true}})
        else {
            return;
        };
        assert!(matches!(
            parse_proxy(&map, &caps),
            Ok(ProxyParse::Quarantined { .. })
        ));
        assert!(matches!(
            parse_proxy(&map, &Capabilities::full()),
            Ok(ProxyParse::Ok(_))
        ));
    }

    #[test]
    fn reality_keys_are_validated() {
        let key = "A".repeat(43);
        let ok = json!({"name": "r", "type": "vless", "server": "x", "port": 1, "uuid": "u", "tls": true,
            "reality-opts": {"public-key": key, "short-id": "0123abcd"}});
        let ProxyKind::Vless(v) = def(ok).kind else {
            panic!("not vless")
        };
        assert_eq!(
            v.tls.reality.map(|r| r.short_id),
            Some("0123abcd".to_string())
        );
        assert!(
            error(
                json!({"name": "r", "type": "vless", "server": "x", "port": 1, "uuid": "u",
            "reality-opts": {"public-key": "short"}})
            )
            .contains("public key")
        );
        assert!(
            error(
                json!({"name": "r", "type": "vless", "server": "x", "port": 1, "uuid": "u",
            "reality-opts": {"public-key": key, "short-id": "xyz"}})
            )
            .contains("short ID")
        );
    }

    #[test]
    fn reality_authentication_options_are_validated_and_retained() {
        let verify = URL_SAFE_NO_PAD.encode([9; 1952]);
        let node = json!({"name":"r","type":"vless","server":"x","port":443,"uuid":"u","tls":true,
            "client-fingerprint":"chrome", "reality-opts":{"public-key":"A".repeat(43),
            "client-version":"26.3.27", "mldsa65-verify":verify}});
        let ProxyKind::Vless(vless) = def(node.clone()).kind else {
            panic!("not vless")
        };
        let reality = vless.tls.reality.unwrap();
        assert_eq!(reality.client_version, Some([26, 3, 27]));
        assert_eq!(reality.mldsa65_verify, Some(vec![9; 1952]));
        for version in ["1.2", "1.2.3.4", "256.1.2", "one.2.3"] {
            let mut invalid = node.clone();
            invalid["reality-opts"]["client-version"] = version.into();
            assert!(error(invalid).contains("client version"));
        }
        let mut invalid = node;
        invalid["reality-opts"]["mldsa65-verify"] = "short".into();
        assert!(error(invalid).contains("ML-DSA-65"));
    }

    #[test]
    fn amnezia_wg_options_keep_their_numbers_and_texts() {
        let ProxyKind::WireGuard(w) = def(
            json!({"name": "w", "type": "wireguard", "server": "x", "port": 51820,
            "private-key": "k", "public-key": "p", "ip": "10.0.0.2",
            "amnezia-wg-option": {"version": 3, "jc": 4, "s1": 30, "h1": 1234567,
            "h2": "100-200", "i1": "<r 8>", "header-protection-key": "a2V5",
            "random-trailers": true, "rekey-timeout": "5-10"}}),
        )
        .kind
        else {
            panic!()
        };
        let a = w.amnezia.unwrap();
        assert_eq!((a.version, a.jc, a.s1), (3, 4, 30));
        assert_eq!((a.h[0].as_str(), a.h[1].as_str()), ("1234567", "100-200"));
        assert_eq!(a.i[0], "<r 8>");
        assert_eq!(a.header_protection_key, "a2V5");
        assert!(a.random_trailers && !a.disable_cookies);
        assert_eq!(a.rekey_timeout, "5-10");
    }

    #[test]
    fn wireguard_and_hysteria_shapes() {
        let ProxyKind::WireGuard(w) = def(
            json!({"name": "w", "type": "wireguard", "server": "x", "port": 51820,
            "private-key": "k", "public-key": "p", "ip": "10.0.0.2", "reserved": [1, 2, 3]}),
        )
        .kind
        else {
            panic!()
        };
        assert_eq!(w.peers.len(), 1);
        assert_eq!(w.peers[0].reserved, [1, 2, 3]);
        let ProxyKind::Hysteria(h) = def(
            json!({"name": "h", "type": "hysteria", "server": "x", "ports": "1000-2000",
            "up": "10", "down": "20"}),
        )
        .kind
        else {
            panic!()
        };
        assert_eq!(h.ports, "1000-2000");
        assert!(
            error(json!({"name": "h", "type": "hysteria", "server": "x", "port": 1}))
                .contains("down, up")
        );
    }

    #[test]
    fn wireguard_reserved_and_allowed_ips_follow_mihomo() {
        let wg = |extra: serde_json::Value| {
            let mut node = json!({"name": "w", "type": "wireguard", "server": "x", "port": 1,
                "private-key": "k", "public-key": "p", "ip": "10.0.0.2"});
            node.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            node
        };
        let ProxyKind::WireGuard(w) = def(wg(
            json!({"reserved": "U4An", "allowed-ips": ["10.0.0.0/8"]}),
        ))
        .kind
        else {
            panic!()
        };
        assert_eq!(w.peers[0].reserved, [0x53, 0x80, 0x27]);
        assert!(w.peers[0].allowed_ips.is_empty());

        let ProxyKind::WireGuard(w) = def(wg(json!({"reserved": [1, 2, 3], "peers": [
            {"server": "a", "port": 1, "public-key": "p", "allowed-ips": ["0.0.0.0/0"]},
            {"server": "b", "port": 1, "public-key": "p", "allowed-ips": ["0.0.0.0/0"],
             "reserved": [4, 5, 6]},
        ]})))
        .kind
        else {
            panic!()
        };
        assert_eq!(w.peers[0].reserved, [1, 2, 3]);
        assert_eq!(w.peers[1].reserved, [4, 5, 6]);

        assert!(
            error(wg(
                json!({"peers": [{"server": "a", "port": 1, "public-key": "p"}]})
            ))
            .contains("missing allowed_ips for peer 0")
        );
    }

    #[test]
    fn an_empty_alpn_is_told_apart_from_none() {
        let tls = |extra: serde_json::Value| {
            let mut node = json!({"name": "t", "type": "trojan", "server": "x", "port": 1,
                "password": "p"});
            node.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let ProxyKind::Trojan(t) = def(node).kind else {
                panic!("not trojan")
            };
            t.tls
        };
        assert!(tls(json!({"alpn": []})).alpn_set);
        assert!(!tls(json!({})).alpn_set);
    }

    #[test]
    fn shadow_tls_opts_are_read_on_the_types_mihomo_reads_them_on() {
        let layer = |password: &str, version| {
            Some(ShadowTlsLayer {
                password: password.to_string(),
                version,
            })
        };
        let opts = |kind: &str, extra: Value| {
            let mut node = json!({"name": "n", "type": kind, "server": "x", "port": 1, "uuid": "u",
                "cipher": "auto", "password": "p", "tls": true});
            node["shadow-tls-opts"] = extra;
            def(node)
        };
        let tls_of = |def: ProxyDef| match def.kind {
            ProxyKind::Vmess(o) => o.tls,
            ProxyKind::Vless(o) => o.tls,
            ProxyKind::Trojan(o) => o.tls,
            ProxyKind::AnyTls(o) => o.tls,
            _ => panic!("not a TLS node"),
        };
        for kind in ["vmess", "vless", "trojan", "anytls"] {
            let tls = tls_of(opts(kind, json!({"password": "s", "version": 3})));
            assert_eq!(tls.shadow_tls, layer("s", 3), "{kind}");
        }
        assert_eq!(
            tls_of(opts("vmess", json!({"password": "s"}))).shadow_tls,
            layer("s", 2)
        );
        assert_eq!(tls_of(opts("vmess", json!({}))).shadow_tls, None);
        assert!(
            quarantined(
                json!({"name": "n", "type": "trojan", "server": "x", "port": 1,
            "password": "p", "shadow-tls-opts": {"password": "s", "version": 4}})
            )
            .contains("unknown protocol version: 4")
        );

        let ss = def(
            json!({"name": "n", "type": "ss", "server": "x", "port": 1, "cipher": "aes-128-gcm",
            "password": "p", "shadow-tls-opts": {"password": "s", "version": 3}}),
        );
        assert_eq!(ss.ignored.len(), 1, "{:?}", ss.ignored);

        let xhttp = |ds: Value| {
            let node = def(
                json!({"name": "n", "type": "vless", "server": "x", "port": 1, "uuid": "u",
                "tls": true, "network": "xhttp", "xhttp-opts": {"download-settings": ds}}),
            );
            let ProxyKind::Vless(o) = node.kind else {
                panic!("not vless")
            };
            let Transport::Xhttp(x) = o.transport else {
                panic!("not xhttp")
            };
            x.download.map(|d| d.shadow_tls)
        };
        assert_eq!(xhttp(json!({})), Some(None));
        assert_eq!(xhttp(json!({"shadow-tls-opts": {}})), Some(Some(None)));
        assert_eq!(
            xhttp(json!({"shadow-tls-opts": {"password": "d", "version": 1}})),
            Some(Some(layer("d", 1)))
        );
    }

    #[test]
    fn what_mihomo_checks_only_when_dialing_sets_the_node_aside() {
        let cases = [
            (
                json!({"name": "t", "type": "tuic", "server": "x", "port": 1, "uuid": "6a4f3bc1-2c44-4a43-a5a3-3f1a2b0e6a11"}),
                "either 'token'",
            ),
            (
                json!({"name": "h", "type": "hysteria", "server": "x", "up": "10", "down": "50"}),
                "either 'port' or 'ports'",
            ),
            (
                json!({"name": "w", "type": "wireguard", "private-key": "k", "ip": "10.0.0.2"}),
                "server or peers",
            ),
            (
                json!({"name": "s", "type": "ss", "server": "x", "port": 1, "cipher": "aes-128-gcm", "password": "p",
                       "plugin": "shadow-tls", "plugin-opts": {"host": "a.test", "password": "x", "version": 0}}),
                "shadow-tls version error: 0",
            ),
        ];
        for (node, reason) in cases {
            let got = quarantined(node);
            assert!(got.contains(reason), "{got}");
        }
    }
    #[test]
    fn masque_options_preserve_the_warp_modes_and_reject_negative_timeouts() {
        let base = json!({"name":"warp","type":"masque","server":"peer.test","port":443,
            "private-key":"sec1","public-key":"spki","ip":"10.0.0.2","ipv6":"fd00::2",
            "uri":"https://cloudflareaccess.com/","sni":"warp.test","mtu":1280,
            "handshake-timeout":7,"skip-cert-verify":true,"remote-dns-resolve":true,
            "dns":["tcp://10.0.0.1"],"ip-stack":{"mode":"mips","congestion-controller":"reno"}});
        for mode in ["", "h2", "h3-l4proxy"] {
            let mut raw = base.clone();
            raw["network"] = json!(mode);
            let ProxyKind::Masque(opts) = def(raw).kind else {
                panic!("MASQUE was not parsed");
            };
            assert_eq!(opts.network, mode);
            assert_eq!(opts.handshake_timeout, 7);
            assert_eq!(opts.ip_stack_congestion_controller, "reno");
            assert_eq!(opts.dns, ["tcp://10.0.0.1"]);
            assert!(opts.skip_cert_verify);
        }
        let mut raw = base;
        raw["handshake-timeout"] = json!(-1);
        assert_eq!(
            parse(raw).unwrap_err().to_string(),
            "masque handshake timeout must be non-negative"
        );
    }
}

#[cfg(test)]
mod jls_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jls_options_parse_for_tls_protocols_ss_and_snell() {
        for kind in ["vmess", "vless", "trojan", "anytls"] {
            let node = json!({"name": "n", "type": kind, "server": "a.test", "port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "pw", "cipher": "auto", "tls": true,
                "jls-opts": {"username": "name", "password": "secret"}});
            let result = parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap();
            let ProxyParse::Ok(def) = result else {
                panic!("{kind}: {result:?}");
            };
            let tls = match &def.kind {
                ProxyKind::Vmess(o) => &o.tls,
                ProxyKind::Vless(o) => &o.tls,
                ProxyKind::Trojan(o) => &o.tls,
                ProxyKind::AnyTls(o) => &o.tls,
                _ => panic!("unexpected kind"),
            };
            assert_eq!(tls.jls.as_ref().unwrap().username, "name");
        }
        for kind in ["ss", "snell"] {
            let mut node = json!({"name": "n", "type": kind, "server": "a.test", "port": 443,
                "cipher": "aes-128-gcm", "password": "pw", "psk": "psk", "version": 4});
            let auth = json!({"host": "cover.test", "username": "name", "password": "secret", "mode": "jls"});
            if kind == "ss" {
                node["plugin"] = json!("jls");
                node["plugin-opts"] = auth;
            } else {
                node["obfs-opts"] = auth;
            }
            assert!(matches!(
                parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap(),
                ProxyParse::Ok(_)
            ));
        }
    }

    #[test]
    fn jls_opts_do_not_replace_a_quic_protocols_tls() {
        let node = json!({"name": "n", "type": "hysteria2", "server": "a.test", "port": 443,
            "password": "pw", "jls-opts": {"username": "name", "password": "secret"}});
        let ProxyParse::Ok(def) =
            parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap()
        else {
            panic!("quarantined");
        };
        let ProxyKind::Hysteria2(opts) = &def.kind else {
            panic!("wrong kind");
        };
        assert!(opts.tls.jls.is_none());
    }

    #[test]
    fn jls_empty_opts_disable_auth_but_partial_credentials_fail() {
        let mut node = json!({"name": "n", "type": "trojan", "server": "a.test", "port": 443, "password": "pw", "jls-opts": {}});
        assert!(matches!(
            parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap(),
            ProxyParse::Ok(_)
        ));
        node["jls-opts"] = json!({"username": "name"});
        assert!(parse_proxy(node.as_object().unwrap(), &Capabilities::full()).is_err());
    }
}
