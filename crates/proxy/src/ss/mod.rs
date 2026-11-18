mod chunk;
pub(crate) mod crypto;
mod legacy;
mod udp;
mod window;

use std::io;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{ProxyDef, SsOpts, SsPlugin, TlsOpts};
use concord_transport::{
    Layer, ObfsMode, ObfsOptions, TransportStack, V2rayPluginOptions, WsOptions,
};
use shadowsocks::context::SharedContext;
use shadowsocks::crypto::CipherKind;

use self::crypto::{ClientStream, SsKey, new_context, parse_method};
use self::udp::SsUdp;
use crate::ctx::{BuildCtx, BuildError, Clock};
use crate::lazy::Kick;
use crate::link::{EnvSlot, shadow_tls_layer};
use crate::node::{Link, info_for};
use crate::tlsmap::{TlsSpec, connector, looks_up_ech};
use crate::udprelay::UdpRelay;
use crate::uot;

struct Shadowsocks {
    info: OutboundInfo,
    link: Link,
    key: SsKey,
    context: SharedContext,
    uot: Option<u8>,
    clock: Clock,
}

impl Shadowsocks {
    async fn open(&self, cx: &DialCx<'_>, target: &Address) -> io::Result<ClientStream<BoxStream>> {
        let stream = self.link.open(cx).await?;
        Ok(ClientStream::new(
            stream,
            self.context.clone(),
            &self.key,
            target,
        ))
    }
}

#[async_trait]
impl Outbound for Shadowsocks {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        Ok(Box::new(Kick::new(self.open(cx, dst).await?)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if let Some(version) = self.uot {
            let stream = self.open(cx, &uot::destination(version)).await?;
            return uot::session(Box::new(stream), version, hint, self.link.tasks());
        }
        let server = self.link.server_socket(cx).await?;
        let codec = SsUdp::new(self.key.kind, self.key.key(), self.clock.clone())
            .with_identity(self.key.identity_keys());
        let session = UdpRelay::open(&self.link.egress, cx, server, codec, None).await?;
        Ok(Arc::new(session))
    }
}

fn plugin_link(def: &ProxyDef, opts: &SsOpts, ctx: &BuildCtx) -> Result<Link, BuildError> {
    let mut tls = None;
    let mut sni = opts.server.clone();
    let mut transport_host = opts.server.clone();
    let mut env_slot = None;
    let layers = match &opts.plugin {
        None => Vec::new(),
        Some(SsPlugin::Obfs { mode, host }) => {
            let mode = match mode.as_str() {
                "tls" => ObfsMode::Tls,
                "http" => ObfsMode::Http,
                other => return Err(BuildError::invalid(format!("obfs mode error: {other}"))),
            };
            vec![Layer::SimpleObfs(ObfsOptions {
                mode,
                host: host.clone(),
                port: opts.port.to_string(),
                clock: ctx.clock.clone(),
            })]
        }
        Some(SsPlugin::V2ray(plugin) | SsPlugin::Gost(plugin)) => {
            if plugin.mode != "websocket" {
                return Err(BuildError::invalid(format!(
                    "obfs mode error: {}",
                    plugin.mode
                )));
            }
            let header_host = plugin
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("host"))
                .map(|(_, value)| value.clone())
                .filter(|value| !value.is_empty());
            sni = header_host.unwrap_or_else(|| plugin.host.clone());
            if plugin.tls {
                let node_tls = TlsOpts {
                    enabled: true,
                    server_name: sni.clone(),
                    alpn: vec!["http/1.1".to_string()],
                    skip_cert_verify: plugin.skip_cert_verify,
                    fingerprint: plugin.fingerprint.clone(),
                    certificate: plugin.certificate.clone(),
                    private_key: plugin.private_key.clone(),
                    name_cert_verify: plugin.name_cert_verify.clone(),
                    client_fingerprint: "none".to_string(),
                    ech: plugin.ech.clone(),
                    ..TlsOpts::default()
                };
                let spec = TlsSpec {
                    sni: sni.clone(),
                    alpn: node_tls.alpn.clone(),
                };
                let slot: EnvSlot = Arc::new(ArcSwapOption::empty());
                tls = Some(connector(&node_tls, spec, ctx, Some(&slot))?);
                if looks_up_ech(&node_tls) {
                    env_slot = Some(slot);
                }
            }
            let options = V2rayPluginOptions {
                host: plugin.host.clone(),
                ws: WsOptions {
                    path: plugin.path.clone(),
                    headers: plugin
                        .headers
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                    max_early_data: 0,
                    early_data_header_name: String::new(),
                    v2ray_http_upgrade: plugin.v2ray_http_upgrade,
                    v2ray_http_upgrade_fast_open: plugin.v2ray_http_upgrade_fast_open,
                    random_host: false,
                },
                mux: plugin.mux,
            };
            vec![if matches!(&opts.plugin, Some(SsPlugin::Gost(_))) {
                Layer::GostPlugin(options)
            } else {
                Layer::V2rayPlugin(options)
            }]
        }
        Some(SsPlugin::Jls(plugin)) => {
            transport_host = plugin.host.clone();
            vec![crate::link::jls_layer(
                plugin,
                &opts.client_fingerprint,
                ctx,
            )?]
        }
        Some(SsPlugin::ShadowTls(plugin)) => {
            transport_host = plugin.host.clone();
            vec![shadow_tls_layer(plugin, &opts.client_fingerprint, ctx)?]
        }
    };
    Ok(Link {
        tls,
        sni_fallback: sni,
        stack: TransportStack::new(layers, ctx.tasks.clone()),
        transport_host,
        env_slot,
        ..Link::plain(def, &opts.server, opts.port, &ctx.tasks)
    })
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &SsOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    if matches!(opts.cipher.as_str(), "chacha20" | "xchacha20") {
        return legacy::build(def, opts, ctx);
    }
    let kind = parse_method(&opts.cipher)?;
    let key = SsKey::new(kind, &opts.password)?;
    if !key.identity_keys().is_empty()
        && matches!(
            kind,
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
                | CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305
        )
    {
        return Err(BuildError::invalid(
            "Shadowsocks 2022 EIH support only available in AES ciphers",
        ));
    }
    if kind.is_aead_2022() {
        let clock = ctx.clock.clone();
        shadowsocks::relay::tcprelay::set_clock(Box::new(move || clock()));
    }
    let link = plugin_link(def, opts, ctx)?;
    let version = uot_version(opts)?;
    let uot = opts.udp_over_tcp.then_some(version);
    Ok(Arc::new(Shadowsocks {
        info: info_for(
            def,
            OutboundKind::Shadowsocks,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        key,
        context: new_context(),
        uot,
        clock: ctx.clock.clone(),
    }))
}

fn uot_version(opts: &SsOpts) -> Result<u8, BuildError> {
    match opts.udp_over_tcp_version {
        0 | uot::LEGACY_VERSION => Ok(uot::LEGACY_VERSION),
        2 => Ok(2),
        other => Err(BuildError::invalid(format!(
            "ss {} unknown udp over tcp protocol version: {other}",
            opts.server
        ))),
    }
}
