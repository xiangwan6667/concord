use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use concord_common::{
    Address, BoxStream, DialCx, DialEnv, Initiator, IpVersion, OutboundInfo, OutboundKind,
    SockOpts, Tasks,
};
use concord_config::proxy::{CommonOpts, IpVersionPref, ProxyDef};
use concord_net::dial_tcp;
use concord_tls::{TlsConn, TlsConnector};
use concord_transport::TransportStack;

use crate::link::EnvSlot;

pub(crate) fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn ip_version(pref: IpVersionPref) -> IpVersion {
    match pref {
        IpVersionPref::Dual => IpVersion::Dual,
        IpVersionPref::V4 => IpVersion::Ipv4,
        IpVersionPref::V6 => IpVersion::Ipv6,
        IpVersionPref::V4Prefer => IpVersion::Ipv4Prefer,
        IpVersionPref::V6Prefer => IpVersion::Ipv6Prefer,
    }
}

/// How a node reaches its own server: directly, or through another node by name.
#[derive(Clone)]
pub(crate) struct Egress {
    name: Arc<str>,
    via: Option<Arc<str>>,
    version: IpVersion,
    interface: Option<Arc<str>>,
    routing_mark: Option<u32>,
    tfo: bool,
    mptcp: bool,
}

impl Egress {
    pub(crate) fn new(name: &str, common: &CommonOpts) -> Self {
        Egress {
            name: Arc::from(name),
            via: Some(common.dialer_proxy.as_str())
                .filter(|via| !via.is_empty())
                .map(Arc::from),
            version: ip_version(common.ip_version),
            interface: Some(common.interface_name.as_str())
                .filter(|name| !name.is_empty())
                .map(Arc::from),
            routing_mark: Some(common.routing_mark).filter(|mark| *mark != 0),
            tfo: common.tfo,
            mptcp: common.mptcp,
        }
    }

    pub(crate) fn name(&self) -> &Arc<str> {
        &self.name
    }

    pub(crate) fn version(&self) -> IpVersion {
        self.version
    }

    pub(crate) fn is_via(&self) -> bool {
        self.via.is_some()
    }

    pub(crate) fn via(&self) -> Option<&str> {
        self.via.as_deref()
    }

    pub(crate) fn sock_opts(&self, env: &DialEnv) -> SockOpts {
        let mut opts = env.sock_opts.clone();
        if self.interface.is_some() {
            opts.interface.clone_from(&self.interface);
        }
        if self.routing_mark.is_some() {
            opts.routing_mark = self.routing_mark;
        }
        opts.tfo |= self.tfo;
        opts.mptcp |= self.mptcp;
        opts
    }

    /// A server name goes to `proxy-server-nameserver`, so the dial is tagged as a proxy dial.
    pub(crate) async fn dial(&self, cx: &DialCx<'_>, server: &Address) -> io::Result<BoxStream> {
        if let Some(via) = &self.via {
            let inner = cx.enter(&self.name)?;
            return cx.env.nodes.dial_via(via, &inner, server).await;
        }
        let proxy_cx = DialCx::new(cx.env, Initiator::Proxy, cx.deadline);
        let stream = dial_tcp(&proxy_cx, server, self.version, &self.sock_opts(cx.env)).await?;
        Ok(Box::new(stream))
    }
}

/// A server name goes to `proxy-server-nameserver`.
pub(crate) async fn resolve_server(
    cx: &DialCx<'_>,
    server: &Address,
    version: IpVersion,
) -> io::Result<SocketAddr> {
    let resolved = match server {
        Address::Socket(addr) => *addr,
        Address::Domain(host, port) => {
            let found = cx
                .env
                .resolver
                .lookup(host, version, Initiator::Proxy)
                .await?;
            let ip = found
                .first(version)
                .ok_or_else(|| concord_common::CoreError::IpNotFound(host.to_string()))?;
            SocketAddr::new(ip, *port)
        }
    };
    Ok(cx.env.sockets.ip4p(resolved))
}

pub(crate) fn info(
    name: &str,
    kind: OutboundKind,
    server: &str,
    port: u16,
    udp: bool,
) -> OutboundInfo {
    OutboundInfo {
        name: Arc::from(name),
        kind,
        addr: Arc::from(join_host_port(server, port)),
        udp,
        provider: None,
        ip_version: IpVersion::Dual,
    }
}

pub(crate) fn info_for(
    def: &ProxyDef,
    kind: OutboundKind,
    server: &str,
    port: u16,
    udp: bool,
) -> OutboundInfo {
    OutboundInfo {
        ip_version: ip_version(def.common.ip_version),
        ..info(&def.name, kind, server, port, udp)
    }
}

/// The server connection of a node: dial, TLS, then the transport layers.
pub(crate) struct Link {
    pub(crate) egress: Egress,
    pub(crate) server: Address,
    pub(crate) tls: Option<TlsConnector>,
    pub(crate) sni_fallback: String,
    pub(crate) stack: TransportStack,
    pub(crate) transport_host: String,
    pub(crate) env_slot: Option<EnvSlot>,
}

impl Link {
    /// A bare TCP connection to the server, for callers to add TLS and layers to.
    pub(crate) fn plain(def: &ProxyDef, server: &str, port: u16, tasks: &Tasks) -> Link {
        Link {
            egress: Egress::new(&def.name, &def.common),
            server: Address::new(server, port),
            tls: None,
            sni_fallback: server.to_string(),
            stack: TransportStack::new(Vec::new(), tasks.clone()),
            transport_host: server.to_string(),
            env_slot: None,
        }
    }

    pub(crate) fn tasks(&self) -> &Tasks {
        self.stack.tasks()
    }

    pub(crate) async fn open(&self, cx: &DialCx<'_>) -> io::Result<BoxStream> {
        if let Some(slot) = &self.env_slot {
            slot.store(Some(Arc::new(cx.env.clone())));
        }
        if self.stack.owns_dial() {
            if crate::link::pool_dialing(self.egress.name()) {
                return Err(
                    concord_common::CoreError::DialerLoop(self.egress.name().to_string()).into(),
                );
            }
            return self.stack.apply_owned(&self.transport_host).await;
        }
        let dial = || self.egress.dial(cx, &self.server);
        let secured: BoxStream = match &self.tls {
            Some(tls) => Box::new(self.secure(tls, dial).await?),
            None => dial().await?,
        };
        self.stack.apply(secured, &self.transport_host).await
    }

    /// The link keeps this connection for good, so a rustls handshake goes on to the native record engine, whose
    /// reads take the rest of a record and up to a copy buffer of the next off the socket.
    async fn secure<D, F>(&self, tls: &TlsConnector, dial: D) -> io::Result<TlsConn>
    where
        D: FnMut() -> F,
        F: Future<Output = io::Result<BoxStream>>,
    {
        tls.connect_whole_dialing(dial, &self.sni_fallback).await
    }

    pub(crate) async fn server_socket(&self, cx: &DialCx<'_>) -> io::Result<SocketAddr> {
        resolve_server(cx, &self.server, self.egress.version()).await
    }

    /// Vision needs the concrete TLS connection, so no transport layer may sit on it.
    pub(crate) async fn open_tls(&self, cx: &DialCx<'_>) -> io::Result<TlsConn> {
        let tls = self
            .tls
            .as_ref()
            .ok_or_else(|| io::Error::other("this node has no TLS"))?;
        if let Some(slot) = &self.env_slot {
            slot.store(Some(Arc::new(cx.env.clone())));
        }
        tls.connect_dialing(|| self.egress.dial(cx, &self.server), &self.sni_fallback)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use concord_common::BoxStream;
    use concord_config::proxy::TlsOpts;
    use concord_config::{Capabilities, ProxyParse, parse_proxy};
    use concord_tls::{TlsConn, TrustStore};
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::Link;
    use crate::BuildCtx;
    use crate::tlsmap::{TlsSpec, connector};

    #[allow(clippy::unwrap_used, reason = "test helper")]
    async fn secured(client_fingerprint: &str) -> TlsConn {
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(made.signing_key.serialize_der());
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![made.cert.der().clone()], key.into())
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let node = json!({"name": "n", "type": "http", "server": "127.0.0.1", "port": port});
        let Ok(ProxyParse::Ok(def)) = parse_proxy(node.as_object().unwrap(), &Capabilities::full())
        else {
            panic!("the node does not parse");
        };
        let options = TlsOpts {
            enabled: true,
            skip_cert_verify: true,
            client_fingerprint: client_fingerprint.to_string(),
            ..TlsOpts::default()
        };
        let spec = TlsSpec {
            sni: "localhost".to_string(),
            alpn: Vec::new(),
        };
        let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
        let tls = connector(&options, spec, &ctx, None).unwrap();
        let link = Link {
            tls: Some(tls),
            sni_fallback: "localhost".to_string(),
            ..Link::plain(&def, "127.0.0.1", port, &ctx.tasks)
        };

        let accept = async {
            let (io, _) = listener.accept().await.unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(server))
                .accept(io)
                .await
                .unwrap()
        };
        let connect = async {
            let tls = link.tls.as_ref().unwrap();
            let dial = || async {
                let io = concord_test_support::tcp_connect(([127, 0, 0, 1], port).into()).await;
                Ok(Box::new(io) as BoxStream)
            };
            link.secure(tls, dial).await.unwrap()
        };
        let (_server, client) = tokio::join!(accept, connect);
        client
    }

    #[tokio::test]
    async fn a_rustls_node_reads_its_tls_on_the_native_record_engine() {
        assert!(matches!(secured("").await, TlsConn::Record(_)));
    }

    #[tokio::test]
    async fn a_fingerprinted_node_keeps_boringssl_for_its_tls() {
        assert!(matches!(secured("chrome").await, TlsConn::Buffered(_)));
    }
}
