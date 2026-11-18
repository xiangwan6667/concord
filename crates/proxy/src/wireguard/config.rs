use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use concord_common::Address;
use concord_config::proxy::{WgPeer, WireGuardOpts, wireguard_dns};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use super::amnezia::Settings;
use crate::ctx::BuildError;
use crate::stack::Congestion;

const DEFAULT_MTU: usize = 1408;
const MAX_MTU: usize = 65_495;
const MIN_MTU: usize = 1280;

pub(super) struct PeerConfig {
    pub(super) server: String,
    pub(super) port: u16,
    pub(super) public_key: [u8; 32],
    pub(super) preshared_key: Option<[u8; 32]>,
    pub(super) reserved: [u8; 3],
    pub(super) allowed_ips: Vec<IpNetwork>,
}

impl PeerConfig {
    pub(super) fn address(&self) -> Address {
        Address::new(&self.server, self.port)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DnsServer {
    pub(crate) addr: SocketAddr,
    pub(crate) transport: DnsTransport,
}

pub(super) struct WgConfig {
    pub(super) private_key: [u8; 32],
    pub(super) addrs: Vec<IpNetwork>,
    pub(super) mtu: usize,
    pub(super) keepalive: Option<u16>,
    pub(super) peers: Vec<PeerConfig>,
    pub(super) congestion: Congestion,
    pub(super) remote_dns: Vec<DnsServer>,
    pub(super) refresh: Option<Duration>,
    pub(super) amnezia: Option<Arc<Settings>>,
}

fn key(text: &str, what: &str) -> Result<[u8; 32], BuildError> {
    let bytes = STANDARD
        .decode(text.trim())
        .map_err(|err| BuildError::invalid(format!("decode {what}: {err}")))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| BuildError::invalid(format!("decode {what}: key must be 32 bytes")))
}

fn network(text: &str, default_prefix: u8) -> Result<IpNetwork, BuildError> {
    let with_prefix = if text.contains('/') {
        text.to_string()
    } else {
        format!("{text}/{default_prefix}")
    };
    IpNetwork::from_str(&with_prefix)
        .map_err(|err| BuildError::invalid(format!("parse {text:?}: {err}")))
}

fn host_prefix(text: &str) -> u8 {
    if text.contains(':') { 128 } else { 32 }
}

fn all_ips(addrs: &[IpNetwork]) -> Vec<IpNetwork> {
    let mut out = Vec::new();
    if addrs.iter().any(IpNetwork::is_ipv4) {
        out.extend(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).map(IpNetwork::V4));
    }
    if addrs.iter().any(IpNetwork::is_ipv6) {
        out.extend(Ipv6Network::new(Ipv6Addr::UNSPECIFIED, 0).map(IpNetwork::V6));
    }
    out
}

fn peer(index: usize, raw: &WgPeer, addrs: &[IpNetwork]) -> Result<PeerConfig, BuildError> {
    let public_key = key(&raw.public_key, &format!("public key for peer {index}"))?;
    let preshared_key = if raw.pre_shared_key.is_empty() {
        None
    } else {
        Some(key(
            &raw.pre_shared_key,
            &format!("pre shared key for peer {index}"),
        )?)
    };
    let reserved = match raw.reserved.as_slice() {
        [] => [0; 3],
        [a, b, c] => [*a, *b, *c],
        other => {
            return Err(BuildError::invalid(format!(
                "invalid reserved value for peer {index}, required 3 bytes, got {}",
                other.len()
            )));
        }
    };
    let allowed_ips = if raw.allowed_ips.is_empty() {
        all_ips(addrs)
    } else {
        raw.allowed_ips
            .iter()
            .map(|text| network(text, host_prefix(text)))
            .collect::<Result<_, _>>()?
    };
    Ok(PeerConfig {
        server: raw.server.clone(),
        port: raw.port,
        public_key,
        preshared_key,
        reserved,
        allowed_ips,
    })
}

pub(crate) fn dns_server(text: &str) -> Option<DnsServer> {
    let (addr, tcp) = wireguard_dns(text)?;
    let transport = if tcp {
        DnsTransport::Tcp
    } else {
        DnsTransport::Udp
    };
    Some(DnsServer { addr, transport })
}

pub(super) fn parse(opts: &WireGuardOpts) -> Result<WgConfig, BuildError> {
    let amnezia = match &opts.amnezia {
        Some(amnezia) => Settings::parse(amnezia)?.map(Arc::new),
        None => None,
    };
    let mut addrs = Vec::new();
    if !opts.ip.is_empty() {
        addrs.push(
            network(&opts.ip, 32)
                .map_err(|err| BuildError::invalid(format!("ip address parse error: {err}")))?,
        );
    }
    if !opts.ipv6.is_empty() {
        addrs.push(
            network(&opts.ipv6, 128)
                .map_err(|err| BuildError::invalid(format!("ipv6 address parse error: {err}")))?,
        );
    }
    if addrs.is_empty() {
        return Err(BuildError::invalid("missing local address"));
    }
    if opts.peers.is_empty() {
        return Err(BuildError::invalid(
            "wireguard: server or peers must be set",
        ));
    }
    let peers = opts
        .peers
        .iter()
        .enumerate()
        .map(|(index, raw)| peer(index, raw, &addrs))
        .collect::<Result<Vec<_>, _>>()?;
    let mtu = match opts.mtu {
        0 => DEFAULT_MTU,
        value => usize::try_from(value).unwrap_or(DEFAULT_MTU),
    };
    let congestion = match opts
        .ip_stack_congestion_controller
        .to_ascii_lowercase()
        .as_str()
    {
        "reno" => Congestion::Reno,
        "" | "cubic" => Congestion::Cubic,
        other @ ("bbr" | "bbr3") => {
            tracing::warn!("wireguard congestion-controller {other} is not available, using cubic");
            Congestion::Cubic
        }
        other => {
            return Err(BuildError::invalid(format!(
                "invalid IP stack congestion controller {other:?}; expected cubic, reno, bbr, or bbr3"
            )));
        }
    };
    let mode = opts.ip_stack_mode.to_ascii_lowercase();
    if !matches!(mode.as_str(), "" | "auto" | "mips" | "gvisor") {
        return Err(BuildError::invalid(format!(
            "invalid IP stack mode {mode:?}; expected auto, gvisor, or mips"
        )));
    }
    let remote_dns = if opts.remote_dns_resolve && !opts.dns.is_empty() {
        let servers: Vec<DnsServer> = opts
            .dns
            .iter()
            .filter_map(|text| {
                let parsed = dns_server(text);
                if parsed.is_none() {
                    tracing::warn!("wireguard dns server {text} is not supported, skipped");
                }
                parsed
            })
            .collect();
        if servers.is_empty() {
            return Err(BuildError::unsupported(
                "none of the wireguard dns servers is a plain udp or tcp server",
            ));
        }
        servers
    } else {
        Vec::new()
    };
    Ok(WgConfig {
        private_key: key(&opts.private_key, "private key")?,
        addrs,
        mtu: mtu.clamp(MIN_MTU, MAX_MTU),
        keepalive: u16::try_from(opts.persistent_keepalive)
            .ok()
            .filter(|secs| *secs != 0),
        peers,
        congestion,
        remote_dns,
        refresh: (opts.refresh_server_ip_interval != 0)
            .then(|| Duration::from_secs(u64::from(opts.refresh_server_ip_interval))),
        amnezia,
    })
}

#[cfg(test)]
mod tests {
    use concord_config::proxy::AmneziaWgOpts;

    use super::*;

    const KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    fn opts() -> WireGuardOpts {
        WireGuardOpts {
            ip: "10.0.0.2".into(),
            private_key: KEY.into(),
            peers: vec![WgPeer {
                server: "198.51.100.1".into(),
                port: 51820,
                public_key: KEY.into(),
                ..WgPeer::default()
            }],
            ..WireGuardOpts::default()
        }
    }

    #[test]
    fn a_bare_address_is_a_host_route_and_allowed_ips_default_to_everything() {
        let config = parse(&opts()).unwrap();
        assert_eq!(
            config.addrs,
            vec![IpNetwork::from_str("10.0.0.2/32").unwrap()]
        );
        assert_eq!(config.mtu, 1408);
        let peer = config.peers.first().unwrap();
        assert_eq!(
            peer.allowed_ips,
            vec![IpNetwork::from_str("0.0.0.0/0").unwrap()]
        );
    }

    #[test]
    fn reserved_must_be_three_bytes() {
        let mut bad = opts();
        bad.peers[0].reserved = vec![1, 2];
        assert!(parse(&bad).is_err());
        let mut good = opts();
        good.peers[0].reserved = vec![1, 2, 3];
        assert_eq!(parse(&good).unwrap().peers[0].reserved, [1, 2, 3]);
    }

    #[test]
    fn keys_are_checked() {
        let mut bad = opts();
        bad.private_key = "nope".into();
        assert!(parse(&bad).is_err());
        let mut short = opts();
        short.peers[0].public_key = "AAAA".into();
        assert!(parse(&short).is_err());
    }

    #[test]
    fn a_missing_local_address_is_an_error() {
        let mut bad = opts();
        bad.ip.clear();
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn dns_servers_accept_plain_forms_only() {
        assert_eq!(
            dns_server("1.1.1.1"),
            Some(DnsServer {
                addr: "1.1.1.1:53".parse().unwrap(),
                transport: DnsTransport::Udp
            })
        );
        assert_eq!(
            dns_server("tcp://8.8.8.8:5353").map(|s| (s.addr, s.transport)),
            Some(("8.8.8.8:5353".parse().unwrap(), DnsTransport::Tcp))
        );
        assert_eq!(
            dns_server("[2606:4700::1111]:53").map(|s| s.addr),
            Some("[2606:4700::1111]:53".parse().unwrap())
        );
        assert!(dns_server("https://dns.example/dns-query").is_none());
    }

    #[test]
    fn amnezia_options_that_leave_the_wire_unchanged_build_a_plain_tunnel() {
        let mut plain = opts();
        plain.amnezia = Some(Default::default());
        assert!(parse(&plain).unwrap().amnezia.is_none());
        let mut junk = opts();
        junk.amnezia = Some(AmneziaWgOpts {
            jc: 3,
            jmin: 40,
            jmax: 70,
            ..AmneziaWgOpts::default()
        });
        assert!(parse(&junk).unwrap().amnezia.is_some());
    }
}
