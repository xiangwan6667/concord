use std::io;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use concord_common::{Address, DialCx, DialEnv, Initiator};
use concord_config::proxy::{
    GrpcOpts, H2Opts, HttpOpts, ProxyDef, ShadowTlsLayer, ShadowTlsOpts, TlsOpts, Transport,
    WsOpts, XhttpOpts, XhttpReuse,
};
use concord_tls::TlsConnector;
use concord_transport::{
    DialFn, GrpcOptions, GunClient, H2Options, HttpOptions, Layer, ShadowTlsClient,
    ShadowTlsOptions, TransportStack, WS_ALPN, WsOptions, XhttpClient, XhttpDial, XhttpDownload,
    XhttpOptions, shadow_tls_dial, tls_dial,
};

mod xhttp_quic;

use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Egress, Link};
use crate::tlsmap::{TlsSpec, connector, looks_up_ech, tls_options};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    Vmess,
    Vless,
    Trojan,
}

pub(crate) struct LinkSpec<'a> {
    pub(crate) def: &'a ProxyDef,
    pub(crate) server: &'a str,
    pub(crate) port: u16,
    pub(crate) tls: &'a TlsOpts,
    pub(crate) transport: &'a Transport,
    pub(crate) flavor: Flavor,
}

tokio::task_local! {
    /// The nodes whose pools this task is dialing for. A pool dial starts a fresh
    /// `DialCx`, so a `dialer-proxy` loop back through the node shows here instead. This
    /// holds only while pool dials run on the calling task; a pool that spawns its dial
    /// must carry the chain into the task.
    static POOL_DIALS: Vec<Arc<str>>;
}

/// Whether this task is inside a pool dial for `node`: a pool that holds a lock across
/// its dial is entered again only by a loop.
pub(crate) fn pool_dialing(node: &str) -> bool {
    POOL_DIALS
        .try_with(|dialing| dialing.iter().any(|name| &**name == node))
        .unwrap_or(false)
}

/// A gRPC connection is dialed from inside the client's pool, which has no
/// `DialCx` of its own, so each `open` leaves the environment here first.
pub(crate) type EnvSlot = Arc<ArcSwapOption<DialEnv>>;

fn http_obfs_options(opts: &HttpOpts) -> HttpOptions {
    HttpOptions {
        method: opts.method.clone(),
        paths: opts.path.clone(),
        headers: opts
            .headers
            .iter()
            .map(|(key, values)| (key.clone(), values.clone()))
            .collect(),
    }
}

fn ws_options(opts: &WsOpts) -> WsOptions {
    WsOptions {
        path: opts.path.clone(),
        headers: opts
            .headers
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        max_early_data: usize::try_from(opts.max_early_data).unwrap_or(0),
        early_data_header_name: opts.early_data_header_name.clone(),
        v2ray_http_upgrade: opts.v2ray_http_upgrade,
        v2ray_http_upgrade_fast_open: opts.v2ray_http_upgrade_fast_open,
        random_host: false,
    }
}

fn host_header(opts: &WsOpts) -> Option<&str> {
    opts.headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
}

fn grpc_options(opts: &GrpcOpts, authority: String) -> GrpcOptions {
    GrpcOptions {
        service_name: opts.service_name.clone(),
        user_agent: opts.user_agent.clone(),
        authority,
        ping_interval: opts.ping_interval,
        max_connections: opts.max_connections as usize,
        min_streams: opts.min_streams as usize,
        max_streams: opts.max_streams as usize,
    }
}

fn h2_options(opts: &H2Opts) -> H2Options {
    let hosts = if opts.host.is_empty() {
        vec!["www.example.com".to_string()]
    } else {
        opts.host.clone()
    };
    H2Options {
        hosts,
        path: opts.path.clone(),
    }
}

fn user_alpn(tls: &TlsOpts) -> Vec<String> {
    tls.alpn.clone()
}

/// The ShadowTLS layer of `shadow-tls` plugin options; the node's `client-fingerprint` shapes
/// its handshake as it does a plain TLS node's.
pub(crate) fn shadow_tls_layer(
    opts: &ShadowTlsOpts,
    client_fingerprint: &str,
    ctx: &BuildCtx,
) -> Result<Layer, BuildError> {
    let node_tls = TlsOpts {
        enabled: true,
        server_name: opts.host.clone(),
        skip_cert_verify: opts.skip_cert_verify,
        fingerprint: opts.fingerprint.clone(),
        certificate: opts.certificate.clone(),
        private_key: opts.private_key.clone(),
        name_cert_verify: opts.name_cert_verify.clone(),
        client_fingerprint: client_fingerprint.to_string(),
        ..TlsOpts::default()
    };
    let layer = ShadowTlsLayer {
        password: opts.password.clone(),
        version: opts.version,
    };
    let spec = TlsSpec {
        sni: opts.host.clone(),
        alpn: opts.alpn.clone(),
    };
    Ok(Layer::ShadowTls(shadow_tls_client(
        &layer, &node_tls, spec, ctx,
    )?))
}

/// mihomo `vmess.StreamTLSConn` (`transport/vmess/tls.go:52-68`): ShadowTLS takes the place of
/// the node's TLS and keeps its name, certificate checks and fingerprint, but not ECH.
fn shadow_tls_client(
    layer: &ShadowTlsLayer,
    tls: &TlsOpts,
    spec: TlsSpec,
    ctx: &BuildCtx,
) -> Result<Arc<ShadowTlsClient>, BuildError> {
    let decoy = TlsOpts {
        enabled: true,
        reality: None,
        ech: None,
        shadow_tls: None,
        jls: None,
        ..tls.clone()
    };
    let client = ShadowTlsClient::new(
        ShadowTlsOptions {
            password: layer.password.clone(),
            version: layer.version,
            tls: tls_options(&decoy, spec, ctx, None)?,
        },
        ctx.trust.clone(),
    )
    .map_err(|err| BuildError::invalid(err.to_string()))?;
    Ok(Arc::new(client))
}

/// What secures a connection the node dials: its TLS, or ShadowTLS in TLS's place.
enum Secure {
    Tls(Box<TlsConnector>),
    ShadowTls(Arc<ShadowTlsClient>),
}

impl Secure {
    fn new(
        tls: &TlsOpts,
        spec: TlsSpec,
        ctx: &BuildCtx,
        env: &EnvSlot,
    ) -> Result<Secure, BuildError> {
        match &tls.shadow_tls {
            Some(layer) => shadow_tls_client(layer, tls, spec, ctx).map(Secure::ShadowTls),
            None => connector(tls, spec, ctx, Some(env)).map(|tls| Secure::Tls(Box::new(tls))),
        }
    }

    /// The node's TLS, or its stack with ShadowTLS beneath the other layers.
    fn place(
        secure: Option<Secure>,
        stack: TransportStack,
    ) -> (Option<TlsConnector>, TransportStack) {
        match secure {
            Some(Secure::Tls(tls)) => (Some(*tls), stack),
            Some(Secure::ShadowTls(client)) => (None, stack.under(Layer::ShadowTls(client))),
            None => (None, stack),
        }
    }

    fn wrap(self, raw: DialFn, sni: String, required_alpn: Option<&'static str>) -> DialFn {
        match self {
            Secure::Tls(tls) => tls_dial(raw, Arc::new(*tls), sni, required_alpn),
            Secure::ShadowTls(client) => shadow_tls_dial(raw, client, sni),
        }
    }
}

/// mihomo checks a node's security modes when it builds the node (`adapter/outbound/vless.go:536-555`,
/// `:770-788` for xhttp's download side).
fn check_security(tls: &TlsOpts, tls_on: bool, download: bool) -> Result<(), BuildError> {
    let mut modes = Vec::new();
    if tls.shadow_tls.is_some() {
        modes.push("ShadowTLS");
    }
    if tls.jls.is_some() {
        modes.push("JLS");
    }
    if tls
        .reality
        .as_ref()
        .is_some_and(|r| !r.public_key.is_empty())
    {
        modes.push("REALITY");
    }
    let side = if download {
        "xhttp download-settings"
    } else {
        ""
    };
    if modes.len() > 1 {
        let sep = if download { " " } else { "" };
        return Err(BuildError::invalid(format!(
            "{side}{sep}security modes are mutually exclusive: {}",
            modes.join(", ")
        )));
    }
    if !tls_on && let Some(mode) = modes.first() {
        let sep = if download { ": " } else { "" };
        return Err(BuildError::invalid(format!(
            "{side}{sep}{mode} requires TLS"
        )));
    }
    Ok(())
}

pub(crate) fn jls_layer(
    opts: &concord_config::proxy::JlsPlugin,
    fingerprint: &str,
    ctx: &BuildCtx,
) -> Result<Layer, BuildError> {
    let tls = TlsOpts {
        enabled: true,
        server_name: opts.host.clone(),
        alpn: opts.alpn.clone(),
        alpn_set: true,
        client_fingerprint: fingerprint.to_string(),
        jls: Some(opts.auth.clone()),
        ..TlsOpts::default()
    };
    let spec = TlsSpec {
        sni: opts.host.clone(),
        alpn: opts.alpn.clone(),
    };
    Ok(Layer::Tls(Arc::new(connector(&tls, spec, ctx, None)?)))
}

pub(crate) fn build_link(spec: LinkSpec<'_>, ctx: &BuildCtx) -> Result<Link, BuildError> {
    let LinkSpec {
        def,
        server,
        port,
        tls,
        transport,
        flavor,
    } = spec;
    let trojan = flavor == Flavor::Trojan;
    let tls_on = tls.enabled || trojan;
    let egress = Egress::new(&def.name, &def.common);
    let server_addr = Address::new(server, port);
    check_security(tls, tls_on, false)?;

    let reality = tls
        .reality
        .as_ref()
        .is_some_and(|r| !r.public_key.is_empty());
    if reality
        && !matches!(
            transport,
            Transport::Tcp
                | Transport::Grpc(_)
                | Transport::H2(_)
                | Transport::Http(_)
                | Transport::Xhttp(_)
        )
    {
        return Err(BuildError::invalid(format!(
            "REALITY is not supported over the {} network",
            transport.name()
        )));
    }

    let alpn_given = tls.alpn_set || !tls.alpn.is_empty();
    let plain_sni = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    let (sni, alpn, transport_host) = match transport {
        Transport::Ws(ws) => {
            let sni = if !tls.server_name.is_empty() || trojan {
                plain_sni.clone()
            } else {
                host_header(ws).map_or_else(|| server.to_string(), str::to_string)
            };
            let alpn = if trojan && alpn_given && tls.shadow_tls.is_none() {
                tls.alpn.clone()
            } else {
                WS_ALPN.map(str::to_string).to_vec()
            };
            let host = if trojan {
                plain_sni.clone()
            } else {
                server.to_string()
            };
            (sni, alpn, host)
        }
        Transport::Grpc(_) | Transport::H2(_) => (
            plain_sni.clone(),
            vec!["h2".to_string()],
            server.to_string(),
        ),
        _ => {
            let alpn = if (trojan || tls.jls.is_some()) && !alpn_given {
                vec!["h2".to_string(), "http/1.1".to_string()]
            } else {
                user_alpn(tls)
            };
            (plain_sni.clone(), alpn, server.to_string())
        }
    };

    let env_slot: EnvSlot = Arc::new(ArcSwapOption::empty());
    let secure_for = |alpn: Vec<String>, sni: &str| -> Result<Option<Secure>, BuildError> {
        if !tls_on {
            return Ok(None);
        }
        let spec = TlsSpec {
            sni: sni.to_string(),
            alpn,
        };
        let mut tls = tls.clone();
        tls.enabled = true;
        Secure::new(&tls, spec, ctx, &env_slot).map(Some)
    };

    let mut slot = None;
    let layer = match transport {
        Transport::Tcp => None,
        Transport::Ws(ws) => Some(Layer::Ws(WsOptions {
            random_host: flavor == Flavor::Vless && !tls_on,
            ..ws_options(ws)
        })),
        Transport::Http(http) => Some(Layer::Http(http_obfs_options(http))),
        Transport::H2(h2) => {
            if !tls_on {
                return Err(BuildError::invalid("the h2 network requires tls"));
            }
            Some(Layer::H2(h2_options(h2)))
        }
        Transport::Grpc(grpc) => {
            let authority = if tls.server_name.is_empty() && !trojan {
                format!("{server}:{port}")
            } else {
                plain_sni.clone()
            };
            let dial = grpc_dial(
                egress.clone(),
                server_addr.clone(),
                secure_for(alpn.clone(), &sni)?,
                sni.clone(),
                env_slot.clone(),
                (!reality).then_some("h2"),
            );
            slot = Some(env_slot.clone());
            let client = GunClient::new(grpc_options(grpc, authority), dial, ctx.tasks.clone());
            Some(Layer::Grpc(client))
        }
        Transport::Xhttp(xhttp) => {
            let layer = xhttp_layer(xhttp, tls, &egress, (server, port), &env_slot, ctx)?;
            slot = Some(env_slot.clone());
            Some(layer)
        }
    };
    let stack = TransportStack::new(layer.into_iter().collect(), ctx.tasks.clone());

    let ech_lookup = tls_on && tls.shadow_tls.is_none() && looks_up_ech(tls);
    let secure = if matches!(transport, Transport::Grpc(_) | Transport::Xhttp(_)) {
        None
    } else {
        secure_for(alpn, &sni)?
    };
    let (tls, stack) = Secure::place(secure, stack);
    if slot.is_none() && ech_lookup {
        slot = Some(env_slot);
    }
    let link = Link {
        egress,
        server: server_addr,
        tls,
        sni_fallback: sni,
        stack,
        transport_host,
        env_slot: slot,
    };
    Ok(link)
}

pub(crate) fn simple_link(
    def: &ProxyDef,
    server: &str,
    port: u16,
    tls: &TlsOpts,
    ctx: &BuildCtx,
) -> Result<Link, BuildError> {
    let sni = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    check_security(tls, tls.enabled, false)?;
    let env_slot: EnvSlot = Arc::new(ArcSwapOption::empty());
    let secured = if tls.enabled {
        let spec = TlsSpec {
            sni: sni.clone(),
            alpn: if tls.jls.is_some() && !tls.alpn_set {
                vec!["h2".into(), "http/1.1".into()]
            } else {
                tls.alpn.clone()
            },
        };
        Some(Secure::new(tls, spec, ctx, &env_slot)?)
    } else {
        None
    };
    let stack = TransportStack::new(Vec::new(), ctx.tasks.clone());
    let (secured, stack) = Secure::place(secured, stack);
    Ok(Link {
        tls: secured,
        sni_fallback: sni,
        stack,
        env_slot: (tls.enabled && tls.shadow_tls.is_none() && looks_up_ech(tls))
            .then_some(env_slot),
        ..Link::plain(def, server, port, &ctx.tasks)
    })
}

fn grpc_dial(
    egress: Egress,
    server: Address,
    secure: Option<Secure>,
    sni: String,
    slot: EnvSlot,
    required_alpn: Option<&'static str>,
) -> DialFn {
    let raw = dial_server(egress, server, slot);
    match secure {
        Some(secure) => secure.wrap(raw, sni, required_alpn),
        None => raw,
    }
}

/// A fresh connection to `server` for a client that dials from inside its own pool.
fn dial_server(egress: Egress, server: Address, slot: EnvSlot) -> DialFn {
    Arc::new(move || {
        let (egress, server, slot) = (egress.clone(), server.clone(), slot.clone());
        Box::pin(async move {
            let dialing = pool_chain(egress.name())?;
            let env = slot
                .load_full()
                .ok_or_else(|| io::Error::other("grpc dial without an environment"))?;
            POOL_DIALS
                .scope(dialing, async {
                    let cx = DialCx::new(&env, Initiator::Proxy, None);
                    egress.dial(&cx, &server).await
                })
                .await
        })
    })
}

fn pool_chain(node: &Arc<str>) -> io::Result<Vec<Arc<str>>> {
    let mut chain = POOL_DIALS.try_with(Clone::clone).unwrap_or_default();
    if chain.contains(node) {
        return Err(concord_common::CoreError::DialerLoop(node.to_string()).into());
    }
    chain.push(node.clone());
    Ok(chain)
}

fn request_host(explicit: &str, server_name: &str, server: &str) -> String {
    if !explicit.is_empty() {
        return explicit.to_string();
    }
    let host = if server_name.is_empty() {
        server
    } else {
        server_name
    };
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn xhttp_reuse(reuse: &XhttpReuse) -> concord_transport::XhttpReuse {
    concord_transport::XhttpReuse {
        max_concurrency: reuse.max_concurrency.clone(),
        max_connections: reuse.max_connections.clone(),
        c_max_reuse_times: reuse.c_max_reuse_times.clone(),
        h_max_request_times: reuse.h_max_request_times.clone(),
        h_max_reusable_secs: reuse.h_max_reusable_secs.clone(),
    }
}

fn headers(map: &indexmap::IndexMap<String, String>) -> Vec<(String, String)> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// A dial function for one side of an xhttp client and whether it speaks HTTP/1.1.
fn xhttp_dial(
    egress: &Egress,
    tls: &TlsOpts,
    (server, port): (&str, u16),
    slot: &EnvSlot,
    ctx: &BuildCtx,
    period: i64,
) -> Result<(XhttpDial, bool), BuildError> {
    if tls.alpn.len() == 1 && tls.alpn.first().is_some_and(|alpn| alpn == "h3") {
        return Ok((
            XhttpDial::Quic(xhttp_quic::dial(
                egress,
                tls,
                (server, port),
                slot,
                ctx,
                period,
            )?),
            false,
        ));
    }
    let http1 = tls.alpn.len() == 1 && tls.alpn.first().is_some_and(|alpn| alpn == "http/1.1");
    let raw = dial_server(egress.clone(), Address::new(server, port), slot.clone());
    if !tls.enabled {
        return Ok((XhttpDial::Tcp(raw), http1));
    }
    let sni = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    let wire = if http1 { "http/1.1" } else { "h2" };
    let spec = TlsSpec {
        sni: sni.clone(),
        alpn: vec![wire.to_string()],
    };
    if let Some(layer) = &tls.shadow_tls {
        let client = shadow_tls_client(layer, tls, spec, ctx)?;
        return Ok((XhttpDial::Tcp(shadow_tls_dial(raw, client, sni)), http1));
    }
    let connector = Arc::new(connector(tls, spec, ctx, Some(slot))?);
    let reality = tls
        .reality
        .as_ref()
        .is_some_and(|r| !r.public_key.is_empty());
    Ok((
        XhttpDial::Tcp(tls_dial(
            raw,
            connector,
            sni,
            (!http1 && !reality).then_some("h2"),
        )),
        http1,
    ))
}

fn reuse_keep_alive(reuse: &Option<XhttpReuse>) -> i64 {
    reuse
        .as_ref()
        .map_or(0, |reuse| i64::from(reuse.h_keep_alive_period))
}

fn xhttp_layer(
    opts: &XhttpOpts,
    tls: &TlsOpts,
    egress: &Egress,
    (server, port): (&str, u16),
    slot: &EnvSlot,
    ctx: &BuildCtx,
) -> Result<Layer, BuildError> {
    let (dial, http1) = xhttp_dial(
        egress,
        tls,
        (server, port),
        slot,
        ctx,
        reuse_keep_alive(&opts.reuse),
    )?;
    let has_reality = tls
        .reality
        .as_ref()
        .is_some_and(|reality| !reality.public_key.is_empty());
    let download = opts
        .download
        .as_deref()
        .map(|ds| {
            let mut side = tls.clone();
            if let Some(enabled) = ds.tls {
                side.enabled = enabled;
            }
            if let Some(alpn) = &ds.alpn {
                side.alpn = alpn.clone();
            }
            if let Some(value) = ds.skip_cert_verify {
                side.skip_cert_verify = value;
            }
            if let Some(value) = &ds.name_cert_verify {
                side.name_cert_verify = value.clone();
            }
            if let Some(value) = &ds.fingerprint {
                side.fingerprint = value.clone();
            }
            if let Some(value) = &ds.certificate {
                side.certificate = value.clone();
            }
            if let Some(value) = &ds.private_key {
                side.private_key = value.clone();
            }
            if let Some(value) = &ds.server_name {
                side.server_name = value.clone();
            }
            if let Some(value) = &ds.client_fingerprint {
                side.client_fingerprint = value.clone();
            }
            if let Some(reality) = &ds.reality {
                side.reality = Some(reality.clone());
            }
            if let Some(jls) = &ds.jls {
                side.jls = (!jls.username.is_empty()).then(|| jls.clone());
            }
            if let Some(ech) = &ds.ech {
                side.ech = Some(ech.clone());
            }
            if let Some(shadow_tls) = &ds.shadow_tls {
                side.shadow_tls = shadow_tls.clone();
            }
            check_security(&side, side.enabled, true)?;
            let host = ds.server.as_deref().unwrap_or(server);
            let reuse = ds.reuse.clone().or_else(|| opts.reuse.clone());
            let (dial, http1) = xhttp_dial(
                egress,
                &side,
                (host, ds.port.unwrap_or(port)),
                slot,
                ctx,
                reuse_keep_alive(&reuse),
            )?;
            let explicit = ds.host.as_deref().unwrap_or(&opts.host);
            Ok::<_, BuildError>(XhttpDownload {
                host: request_host(explicit, &side.server_name, host),
                path: ds.path.clone().unwrap_or_else(|| opts.path.clone()),
                headers: headers(ds.headers.as_ref().unwrap_or(&opts.headers)),
                keep_alive_period: reuse_keep_alive(&reuse),
                reuse: reuse.as_ref().map(xhttp_reuse),
                http1,
                dial,
            })
        })
        .transpose()?;
    let options = XhttpOptions {
        host: request_host(&opts.host, &tls.server_name, server),
        path: opts.path.clone(),
        mode: opts.mode.clone(),
        headers: headers(&opts.headers),
        no_grpc_header: opts.no_grpc_header,
        x_padding_bytes: opts.x_padding_bytes.clone(),
        x_padding_obfs_mode: opts.x_padding_obfs_mode,
        x_padding_key: opts.x_padding_key.clone(),
        x_padding_header: opts.x_padding_header.clone(),
        x_padding_placement: opts.x_padding_placement.clone(),
        x_padding_method: opts.x_padding_method.clone(),
        uplink_http_method: opts.uplink_http_method.clone(),
        session_placement: opts.session_placement.clone(),
        session_key: opts.session_key.clone(),
        session_table: opts.session_table.clone(),
        session_length: opts.session_length.clone(),
        seq_placement: opts.seq_placement.clone(),
        seq_key: opts.seq_key.clone(),
        uplink_data_placement: opts.uplink_data_placement.clone(),
        uplink_data_key: opts.uplink_data_key.clone(),
        uplink_chunk_size: opts.uplink_chunk_size.clone(),
        sc_max_each_post_bytes: opts.sc_max_each_post_bytes.clone(),
        sc_min_posts_interval_ms: opts.sc_min_posts_interval_ms.clone(),
        reuse: opts.reuse.as_ref().map(xhttp_reuse),
        keep_alive_period: reuse_keep_alive(&opts.reuse),
        http1,
        has_reality,
    };
    let client = XhttpClient::new(options, dial, download, ctx.tasks.clone())
        .map_err(|err| BuildError::invalid(err.to_string()))?;
    Ok(Layer::Xhttp(client))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use async_trait::async_trait;
    use concord_common::{
        Address, BoxStream, CoreError, DialCx, Initiator, NodeDialer, Outbound, PacketSession,
    };
    use concord_config::proxy::{ProxyDef, ProxyKind};
    use concord_config::{Capabilities, ProxyParse, parse_proxy};
    use concord_tls::TrustStore;
    use concord_transport::Layer;
    use serde_json::{Value, json};
    use tokio::sync::Barrier;

    use super::{Flavor, LinkSpec, build_link};
    use crate::node::Link;
    use crate::testing::test_env_with;
    use crate::{BuildCtx, build_outbound};

    fn build(extra: Value) -> Result<(), String> {
        let node = json!({
            "name": "n", "type": "vless", "server": "127.0.0.1", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "reality-opts": {"public-key": "SHbG8EvyDdqrc-BMXJTMtSwVPS7mVZGHN0SjL1yYa1I"}
        });
        build_node(node, extra)
    }

    fn def_of(mut node: Value, extra: Value) -> Result<ProxyDef, String> {
        if let (Some(node), Some(extra)) = (node.as_object_mut(), extra.as_object()) {
            node.extend(extra.clone());
        }
        let Some(map) = node.as_object() else {
            return Err("not an object".into());
        };
        let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
            return Err("does not parse".into());
        };
        Ok(*def)
    }

    fn build_node(node: Value, extra: Value) -> Result<(), String> {
        let def = def_of(node, extra)?;
        let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
        build_outbound(&def, &ctx)
            .map(drop)
            .map_err(|err| err.to_string())
    }

    fn vmess_link(extra: Value) -> Link {
        let node = json!({"name": "n", "type": "vmess", "server": "127.0.0.1", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "cipher": "auto", "tls": true,
            "shadow-tls-opts": {"password": "p", "version": 3}});
        let def = def_of(node, extra).unwrap();
        let ProxyKind::Vmess(opts) = &def.kind else {
            panic!("not vmess");
        };
        let spec = LinkSpec {
            def: &def,
            server: &opts.server,
            port: opts.port,
            tls: &opts.tls,
            transport: &opts.transport,
            flavor: Flavor::Vmess,
        };
        build_link(spec, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap()
    }

    #[test]
    fn shadow_tls_takes_the_place_of_tls_under_the_transport() {
        let layers = |link: &Link| {
            assert!(link.tls.is_none());
            link.stack
                .layers()
                .iter()
                .map(|layer| match layer {
                    Layer::ShadowTls(_) => "shadow-tls",
                    Layer::Ws(_) => "ws",
                    Layer::H2(_) => "h2",
                    Layer::Grpc(_) => "grpc",
                    _ => "other",
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(layers(&vmess_link(json!({}))), ["shadow-tls"]);
        assert_eq!(
            layers(&vmess_link(json!({"network": "ws"}))),
            ["shadow-tls", "ws"]
        );
        assert_eq!(
            layers(&vmess_link(json!({"network": "h2"}))),
            ["shadow-tls", "h2"]
        );
        let grpc = vmess_link(json!({"network": "grpc"}));
        assert_eq!(layers(&grpc), ["grpc"]);
    }

    #[test]
    fn shadow_tls_is_refused_where_mihomo_refuses_it() {
        let shadow = json!({"shadow-tls-opts": {"password": "p", "version": 3}});
        let err = build(merge(
            shadow.clone(),
            json!({"tls": true, "client-fingerprint": "chrome"}),
        ))
        .unwrap_err();
        assert!(
            err.contains("mutually exclusive: ShadowTLS, REALITY"),
            "{err}"
        );

        let vmess = json!({"name": "n", "type": "vmess", "server": "127.0.0.1", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "cipher": "auto"});
        let err = build_node(vmess.clone(), shadow.clone()).unwrap_err();
        assert!(err.contains("ShadowTLS requires TLS"), "{err}");
        build_node(vmess, merge(shadow.clone(), json!({"tls": true}))).unwrap();

        let xhttp = |download: Value| {
            let vless = json!({"name": "n", "type": "vless", "server": "127.0.0.1", "port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tls": true, "network": "xhttp",
                "xhttp-opts": {"path": "/x", "download-settings": download}});
            build_node(vless, json!({}))
        };
        let err = xhttp(json!({"tls": false, "shadow-tls-opts": {"password": "p"}})).unwrap_err();
        assert!(
            err.contains("xhttp download-settings: ShadowTLS requires TLS"),
            "{err}"
        );
        let err = xhttp(
            json!({"shadow-tls-opts": {"password": "p"}, "client-fingerprint": "chrome",
            "reality-opts": {"public-key": "SHbG8EvyDdqrc-BMXJTMtSwVPS7mVZGHN0SjL1yYa1I"}}),
        )
        .unwrap_err();
        assert!(
            err.contains("xhttp download-settings security modes are mutually exclusive"),
            "{err}"
        );
        xhttp(json!({"shadow-tls-opts": {"password": "p", "version": 2}})).unwrap();
    }

    fn merge(mut base: Value, more: Value) -> Value {
        if let (Some(base), Some(more)) = (base.as_object_mut(), more.as_object()) {
            base.extend(more.clone());
        }
        base
    }

    #[test]
    fn reality_without_tls_is_refused_as_mihomo_does() {
        let err = build(json!({"tls": false})).unwrap_err();
        assert!(err.contains("REALITY requires TLS"), "{err}");
    }

    #[test]
    fn reality_runs_over_xhttp() {
        build(json!({
            "tls": true, "client-fingerprint": "chrome",
            "network": "xhttp", "xhttp-opts": {"path": "/x"}
        }))
        .unwrap();
    }

    /// The `dialer-proxy` `hop`: it holds `wait` dials until all are in flight and
    /// fails them, or with no `wait` dials back through `back`.
    struct Hop {
        wait: Option<Barrier>,
        back: OnceLock<Arc<dyn Outbound>>,
    }

    #[async_trait]
    impl NodeDialer for Hop {
        async fn dial_via(
            &self,
            _name: &str,
            cx: &DialCx<'_>,
            dst: &Address,
        ) -> io::Result<BoxStream> {
            if let Some(wait) = &self.wait {
                wait.wait().await;
                return Err(io::Error::other("hop down"));
            }
            let back = self.back.get().ok_or_else(|| io::Error::other("no node"))?;
            back.connect(cx, dst).await
        }

        async fn associate_via(
            &self,
            name: &str,
            _cx: &DialCx<'_>,
            _hint: &Address,
        ) -> io::Result<Arc<dyn PacketSession>> {
            Err(CoreError::UnknownNode(name.to_string()).into())
        }
    }

    fn pooled(network: Value) -> Arc<dyn Outbound> {
        let mut node = json!({
            "name": "pooled", "type": "vless", "server": "127.0.0.1", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "dialer-proxy": "hop"
        });
        if let (Some(node), Some(network)) = (node.as_object_mut(), network.as_object()) {
            node.extend(network.clone());
        }
        let map = node.as_object().unwrap();
        let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
            panic!("does not parse");
        };
        build_outbound(&def, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap()
    }

    #[tokio::test]
    async fn pool_dials_through_a_dialer_proxy_run_side_by_side() {
        const DIALS: usize = 32;
        let hop = Arc::new(Hop {
            wait: Some(Barrier::new(DIALS)),
            back: OnceLock::new(),
        });
        let env = test_env_with(hop);
        // XHTTP without reuse dials a connection per logical connection.
        let outbound = pooled(json!({"network": "xhttp", "xhttp-opts": {"path": "/x"}}));
        let dials: Vec<_> = (0..DIALS)
            .map(|_| {
                let (outbound, env) = (outbound.clone(), env.clone());
                tokio::spawn(async move {
                    let cx = DialCx::new(&env, Initiator::Direct, None);
                    outbound
                        .connect(&cx, &Address::new("127.0.0.1", 9))
                        .await
                        .map(drop)
                })
            })
            .collect();
        for dial in dials {
            let err = tokio::time::timeout(Duration::from_secs(5), dial)
                .await
                .expect("dials did not run side by side")
                .unwrap()
                .unwrap_err();
            assert!(err.to_string().contains("hop down"), "{err}");
        }
    }

    /// Gun holds its connection's lock across the dial, so the loop must fail before
    /// it reaches the pool again.
    #[tokio::test]
    async fn a_dialer_proxy_loop_through_the_pool_fails() {
        for network in [
            json!({"network": "xhttp", "xhttp-opts": {"path": "/x"}}),
            json!({"network": "grpc", "grpc-opts": {"grpc-service-name": "x"}}),
        ] {
            let hop = Arc::new(Hop {
                wait: None,
                back: OnceLock::new(),
            });
            let env = test_env_with(hop.clone());
            let outbound = pooled(network.clone());
            let _ = hop.back.set(outbound.clone());
            let cx = DialCx::new(&env, Initiator::Direct, None);
            let err = tokio::time::timeout(
                Duration::from_secs(5),
                outbound.connect(&cx, &Address::new("127.0.0.1", 9)),
            )
            .await
            .unwrap_or_else(|_| panic!("{network}: the loop did not end"))
            .map(drop)
            .unwrap_err();
            assert!(
                matches!(CoreError::of(&err), Some(CoreError::DialerLoop(name)) if name == "pooled"),
                "{network}: {err}"
            );
        }
    }
}

#[cfg(test)]
mod jls_tests {
    use crate::{BuildCtx, build_outbound};
    use concord_config::{Capabilities, ProxyParse, parse_proxy};
    use concord_tls::TrustStore;
    use serde_json::json;

    #[test]
    fn jls_security_modes_use_the_shared_validation_for_both_sides() {
        use concord_config::proxy::{JlsOpts, RealityOpts, ShadowTlsLayer, TlsOpts};
        let auth = JlsOpts {
            username: "name".into(),
            password: "secret".into(),
        };
        for download in [false, true] {
            let mut tls = TlsOpts {
                jls: Some(auth.clone()),
                ..Default::default()
            };
            let err = super::check_security(&tls, false, download)
                .err()
                .unwrap()
                .to_string();
            assert!(err.ends_with("JLS requires TLS"), "{err}");
            tls.shadow_tls = Some(ShadowTlsLayer {
                password: "pw".into(),
                version: 3,
            });
            let err = super::check_security(&tls, true, download)
                .err()
                .unwrap()
                .to_string();
            assert!(
                err.ends_with("security modes are mutually exclusive: ShadowTLS, JLS"),
                "{err}"
            );
            tls.shadow_tls = None;
            tls.reality = Some(RealityOpts {
                public_key: "A".repeat(43),
                ..Default::default()
            });
            let err = super::check_security(&tls, true, download)
                .err()
                .unwrap()
                .to_string();
            assert!(
                err.ends_with("security modes are mutually exclusive: JLS, REALITY"),
                "{err}"
            );
            if download {
                assert!(err.starts_with("xhttp download-settings "));
            }
        }
    }

    #[test]
    fn jls_nodes_build_for_all_six_tcp_entries() {
        for kind in ["vmess", "vless", "trojan", "anytls", "ss", "snell"] {
            let mut value = json!({"name": "jls", "type": kind, "server": "cover.test", "port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "cipher": "aes-128-gcm", "password": "pw",
                "psk": "psk", "version": 4, "tls": true, "client-fingerprint": "chrome"});
            let auth = json!({"username": "name", "password": "secret", "host": "cover.test", "mode": "jls"});
            match kind {
                "ss" => {
                    value["plugin"] = json!("jls");
                    value["plugin-opts"] = auth;
                }
                "snell" => value["obfs-opts"] = auth,
                _ => value["jls-opts"] = auth,
            }
            let ProxyParse::Ok(def) =
                parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap()
            else {
                panic!("quarantined {kind}");
            };
            assert!(
                build_outbound(&def, &BuildCtx::new(TrustStore::new(b"", vec![]))).is_ok(),
                "{kind}"
            );
        }
    }
}
