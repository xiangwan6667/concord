use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use concord_config::proxy::MasqueOpts;
use concord_netstack::Congestion;
use ipnetwork::IpNetwork;

use crate::ctx::{BuildCtx, BuildError};
use crate::node::Egress;
use crate::quic::{Crypto, ObfsSpec, QuicLink};
use crate::wireguard::config::{DnsServer, dns_server};

pub(super) struct Config {
    pub(super) link: QuicLink,
    pub(super) tls: Arc<rustls::ClientConfig>,
    pub(super) sni: String,
    pub(super) uri: http::Uri,
    pub(super) network: String,
    pub(super) addrs: Vec<IpAddr>,
    pub(super) mtu: usize,
    pub(super) congestion: Congestion,
    pub(super) dns: Vec<DnsServer>,
    pub(super) timeout: Option<Duration>,
}

impl Config {
    pub(super) fn new(
        opts: &MasqueOpts,
        egress: Egress,
        ctx: &BuildCtx,
    ) -> Result<Self, BuildError> {
        let tls = super::tls::config(opts, ctx)?;
        let l4 = opts.network == "h3-l4proxy";
        let sni = if opts.sni.is_empty() {
            if l4 {
                "consumer-masque-proxy.cloudflareclient.com"
            } else {
                "consumer-masque.cloudflareclient.com"
            }
        } else {
            &opts.sni
        }
        .to_string();
        let raw_uri = if opts.uri.is_empty() {
            "https://cloudflareaccess.com"
        } else {
            &opts.uri
        };
        let uri: http::Uri = raw_uri
            .parse()
            .map_err(|e| BuildError::invalid(format!("masque URI: {e}")))?;
        if raw_uri.contains(['{', '}'])
            || !matches!(uri.scheme_str(), Some("https" | "http"))
            || uri.authority().is_none()
        {
            return Err(BuildError::invalid("masque requires a fixed HTTP URI"));
        }
        let addrs = local_addrs(opts, l4)?;
        let mtu = if opts.mtu == 0 {
            1280
        } else {
            opts.mtu as usize
        };
        if !(40..=65535).contains(&mtu) {
            return Err(BuildError::invalid("masque MTU must fit an IP packet"));
        }
        let congestion = stack_congestion(opts)?;
        let dns = remote_dns(opts, l4)?;
        let transport = transport(opts);
        let timeout =
            (opts.handshake_timeout != 0).then(|| Duration::from_secs(opts.handshake_timeout));
        Ok(Self {
            link: QuicLink {
                egress,
                server: concord_common::Address::new(&opts.server, opts.port),
                server_name: Some(sni.clone()),
                crypto: Crypto::Rustls(tls.clone()),
                transport: Arc::new(transport),
                obfs: ObfsSpec::None,
                hop: None,
                datagram_frame: Some(16_383),
                tasks: ctx.tasks.clone(),
            },
            tls,
            sni,
            uri,
            network: opts.network.clone(),
            addrs,
            mtu,
            congestion,
            dns,
            timeout,
        })
    }
}

fn local_addrs(opts: &MasqueOpts, l4: bool) -> Result<Vec<IpAddr>, BuildError> {
    let addrs = if l4 {
        Vec::new()
    } else {
        [&opts.ip, &opts.ipv6]
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<IpAddr>()
                    .or_else(|_| s.parse::<IpNetwork>().map(|net| net.ip()).map_err(|_| ()))
                    .map_err(|_| BuildError::invalid(format!("masque invalid local address {s:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    if !l4 && addrs.is_empty() {
        return Err(BuildError::invalid("masque missing local address"));
    }
    Ok(addrs)
}

fn stack_congestion(opts: &MasqueOpts) -> Result<Congestion, BuildError> {
    if !matches!(
        opts.ip_stack_mode.to_ascii_lowercase().as_str(),
        "" | "auto" | "mips" | "gvisor"
    ) {
        return Err(BuildError::invalid("invalid MASQUE IP stack mode"));
    }
    let congestion = match opts
        .ip_stack_congestion_controller
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "cubic" => Congestion::Cubic,
        "reno" => Congestion::Reno,
        "bbr" | "bbr3" => {
            tracing::warn!("MASQUE IP stack BBR is unavailable; using cubic");
            Congestion::Cubic
        }
        _ => {
            return Err(BuildError::invalid(
                "invalid MASQUE IP stack congestion controller",
            ));
        }
    };
    Ok(congestion)
}

fn remote_dns(opts: &MasqueOpts, l4: bool) -> Result<Vec<DnsServer>, BuildError> {
    let dns = if opts.remote_dns_resolve {
        opts.dns
            .iter()
            .map(|s| {
                dns_server(s).ok_or_else(|| {
                    BuildError::unsupported(format!(
                        "MASQUE remote DNS requires a literal UDP/TCP server: {s}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    if l4
        && dns
            .iter()
            .any(|server| server.transport != crate::wireguard::config::DnsTransport::Tcp)
    {
        return Err(BuildError::unsupported(
            "MASQUE L4 remote DNS requires tcp:// servers",
        ));
    }
    Ok(dns)
}

fn transport(opts: &MasqueOpts) -> quinn::TransportConfig {
    let mut transport = crate::quic::transport_config();
    let mut cubic = quinn::congestion::CubicConfig::default();
    cubic.initial_window(32 * 1242);
    transport.congestion_controller_factory(Arc::new(cubic));
    transport
        .initial_mtu(1242)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .datagram_receive_buffer_size(Some(crate::quic::datagram_buffer(16_383)));
    let cwnd = u64::from(if opts.cwnd == 0 { 32 } else { opts.cwnd });
    match opts.congestion_controller.as_str() {
        "new_reno" => {
            let mut reno = quinn::congestion::NewRenoConfig::default();
            reno.initial_window(32 * 1242);
            transport.congestion_controller_factory(Arc::new(reno));
        }
        "bbr" | "bbr_meta_v1" | "bbr_meta_v2" => {
            transport.congestion_controller_factory(crate::quic::bbr_factory(
                crate::quic::BbrProfile::parse(&opts.bbr_profile),
                cwnd * if opts.congestion_controller == "bbr_meta_v1" {
                    crate::quic::INITIAL_PACKET_SIZE
                } else {
                    1242
                },
            ));
        }
        _ => {}
    }
    transport
}
