use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    BoxStream, FlowHandler, FlowMeta, IcmpAnswer, Initiator, SockOpts, UdpFlow, UdpPayload,
    UdpReply,
};
use concord_config::net::IpCidr;
use concord_config::tun::TunConfig;
use concord_net::Sockets;
use concord_platform::Platform;
use concord_tun::{
    Congestion, DeviceSource, DnsHijack, HandlerSink, IdRange, Prefix, SelfExclusion, StartError,
    TunDeps, TunOptions, TunRunner,
};
use concord_tunnel::Tunnel;

use crate::engine::{Engine, TunPatch, UpdateRequest};
use crate::error::Failure;

const DEFAULT_MTU: u32 = 9000;
const DEFAULT_INET4: &str = "198.18.0.1/30";
const DEFAULT_INET6: &str = "fdfe:dcba:9876::1/126";

/// What the TUN device asks of DNS, against whichever config is in force.
struct TunnelDns(Tunnel);

/// mihomo's order: the core's dials bind past the device before its routes go in, and follow
/// the routing table again only once the routes are gone. Sessions and resolver connections
/// dialled before the device existed are unbound, so its routes would take them in; they are
/// dropped for bound ones.
pub(crate) struct KeepOffDevice {
    pub platform: Arc<dyn Platform>,
    pub sockets: Arc<Sockets>,
    pub tunnel: Tunnel,
    pub auto_detect: bool,
}

impl SelfExclusion for KeepOffDevice {
    fn exclude(&self, device: &str) {
        self.platform
            .set_excluded_interfaces(vec![device.to_string()]);
        self.sockets.set_auto_detect_interface(self.auto_detect);
        if self.auto_detect
            && let Some(runtime) = self.tunnel.runtime()
        {
            runtime.outbounds.reset_sessions();
            runtime.dns.reset_connections();
        }
    }

    fn release(&self) {
        self.sockets.set_auto_detect_interface(false);
        self.platform.set_excluded_interfaces(Vec::new());
    }
}

#[async_trait]
impl DnsHijack for TunnelDns {
    async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let runtime = self.0.runtime()?;
        runtime.dns.handle_query_udp(query, Initiator::Other).await
    }

    async fn answer_stream(&self, query: &[u8]) -> Option<Vec<u8>> {
        let runtime = self.0.runtime()?;
        runtime.dns.handle_query(query, Initiator::Other).await
    }
}

const PING_WAIT: Duration = Duration::from_secs(10);

/// The tunnel's flows, and the echo requests it cannot see: a request goes to its
/// destination directly and is answered when the destination answers. One for a fake-ip
/// or an address of the device itself is answered by the stack, as mihomo does.
struct TunFlows {
    tunnel: Tunnel,
    sockets: Arc<Sockets>,
    device: Vec<Prefix>,
}

impl FlowHandler for TunFlows {
    fn handle_tcp(&self, meta: FlowMeta, stream: BoxStream) {
        self.tunnel.handle_tcp(meta, stream);
    }

    fn handle_udp(&self, flow: UdpFlow<'_>, payload: UdpPayload<'_>, reply: &Arc<dyn UdpReply>) {
        self.tunnel.handle_udp(flow, payload, reply);
    }

    fn udp_round(&self, round: &mut dyn FnMut()) {
        self.tunnel.udp_round(round);
    }

    #[cfg(any(unix, windows))]
    fn handle_icmp(&self, dst: IpAddr, message: &[u8], answer: IcmpAnswer) -> bool {
        let fake = self
            .tunnel
            .runtime()
            .is_none_or(|runtime| runtime.dns.is_fake_ip(dst));
        if fake || self.device.iter().any(|prefix| prefix.contains(dst)) {
            return false;
        }
        let sockets = Arc::clone(&self.sockets);
        let message = message.to_vec();
        tokio::spawn(async move {
            match sockets
                .ping(dst, &message, &SockOpts::default(), PING_WAIT)
                .await
            {
                Ok(()) => answer(),
                Err(err) => tracing::debug!("[ICMP] {dst} did not answer: {err}"),
            }
        });
        true
    }

    #[cfg(not(any(unix, windows)))]
    fn handle_icmp(&self, _dst: IpAddr, _message: &[u8], _answer: IcmpAnswer) -> bool {
        false
    }
}

fn prefixes(cidrs: &[IpCidr]) -> Vec<Prefix> {
    cidrs
        .iter()
        .filter_map(|cidr| Prefix::new(cidr.addr, cidr.prefix))
        .collect()
}

fn ids<T: Copy + Into<u32>>(ids: &[T]) -> Vec<IdRange> {
    ids.iter().map(|id| IdRange::single((*id).into())).collect()
}

/// `parseTun`: the device takes the first address of the fake-ip range.
pub(crate) fn inet4_of(fake_ip_range: Option<IpCidr>) -> Option<Prefix> {
    match fake_ip_range {
        Some(range) => Prefix::new(range.addr, 30),
        None => Prefix::parse(DEFAULT_INET4),
    }
}

pub(crate) fn options_of(config: &TunConfig, inet4: Option<Prefix>, ipv6: bool) -> TunOptions {
    TunOptions {
        device: Some(config.device.clone()).filter(|device| !device.is_empty()),
        mtu: if config.mtu == 0 {
            DEFAULT_MTU
        } else {
            config.mtu
        },
        inet4_address: inet4.into_iter().collect(),
        inet6_address: Prefix::parse(DEFAULT_INET6)
            .filter(|_| ipv6)
            .into_iter()
            .collect(),
        auto_route: config.auto_route,
        strict_route: config.strict_route,
        route_address: prefixes(&config.route_address),
        route_exclude_address: prefixes(&config.route_exclude_address),
        include_interface: config.include_interface.clone(),
        exclude_interface: config.exclude_interface.clone(),
        include_uid: ids(&config.include_uid),
        exclude_uid: ids(&config.exclude_uid),
        exclude_src_port: ids(&config.exclude_src_port),
        exclude_dst_port: ids(&config.exclude_dst_port),
        dns_hijack: config.dns_hijack.clone(),
        udp_timeout: u64::try_from(config.udp_timeout)
            .ok()
            .filter(|seconds| *seconds > 0)
            .map_or_else(|| TunOptions::default().udp_timeout, Duration::from_secs),
        disable_icmp_forwarding: config.disable_icmp_forwarding,
        ..TunOptions::default()
    }
}

/// `tun.Start`: how to run the descriptor the Android service hands over.
#[cfg(unix)]
pub(crate) fn vpn_options(
    tun: &InheritedTun,
) -> Result<(TunOptions, Congestion), InheritedTunError> {
    let mut options = TunOptions {
        device: Some(concord_common::PRODUCT_NAME.to_owned()),
        mtu: tun.mtu.filter(|mtu| *mtu != 0).unwrap_or(DEFAULT_MTU),
        auto_route: false,
        ..TunOptions::default()
    };
    for address in tun.address.iter().map(|address| address.trim()) {
        if address.is_empty() {
            continue;
        }
        let prefix = Prefix::parse(address)
            .ok_or_else(|| InheritedTunError::Address(address.to_string()))?;
        if prefix.addr().is_ipv4() {
            options.inet4_address.push(prefix);
        } else {
            options.inet6_address.push(prefix);
        }
    }
    for server in tun.dns.iter().map(|server| server.trim()) {
        if server.is_empty() {
            continue;
        }
        let ip: std::net::IpAddr = server
            .parse()
            .map_err(|_| InheritedTunError::Dns(server.to_string()))?;
        options
            .dns_hijack
            .push(std::net::SocketAddr::new(ip, 53).to_string());
    }
    let congestion = congestion_of(tun.congestion_controller.as_deref().unwrap_or_default());
    Ok((options, congestion))
}

pub(crate) fn congestion_of(name: &str) -> Congestion {
    let (congestion, exact) = Congestion::parse(name);
    if !exact {
        tracing::warn!("[TUN] congestion controller {name} is not available, using CUBIC");
    }
    congestion
}

/// `listener.ReCreateTun` and the Android start share everything but the descriptor.
pub(crate) async fn start_runner(
    tunnel: &Tunnel,
    sockets: &Arc<Sockets>,
    options: &TunOptions,
    source: DeviceSource,
    congestion: Congestion,
    exclusion: Option<Arc<dyn SelfExclusion>>,
) -> Result<TunRunner, StartError> {
    let handler: Arc<dyn FlowHandler> = Arc::new(TunFlows {
        tunnel: tunnel.clone(),
        sockets: Arc::clone(sockets),
        device: options
            .inet4_address
            .iter()
            .chain(&options.inet6_address)
            .copied()
            .collect(),
    });
    let runner = TunRunner::start(
        options,
        source,
        TunDeps {
            sink: Arc::new(HandlerSink::new(handler, &options.inbound_name)),
            dns: Some(Arc::new(TunnelDns(tunnel.clone()))),
            congestion,
            exclusion,
        },
    )
    .await?;
    for note in runner.notes() {
        tracing::info!("[TUN] {note}");
    }
    tracing::info!("[TUN] Tun adapter listening at: {}", runner.device_name());
    Ok(runner)
}

pub(crate) async fn stop_runner(runner: TunRunner) {
    let report = runner.stop().await;
    for failure in report.route_failures {
        tracing::error!("[TUN] restore routes: {failure}");
    }
    if let Err(err) = report.stack {
        tracing::warn!("[TUN] stack stopped: {err}");
    }
}

/// Why a TUN start a host asked for did not happen.
#[derive(Debug, thiserror::Error)]
pub enum TunStartError {
    #[error("TUN is unavailable: {0}")]
    Unavailable(String),
    #[cfg(unix)]
    #[error("the TUN device did not start: {0}")]
    Request(#[from] InheritedTunError),
    #[cfg(unix)]
    #[error("the TUN device did not start: {0}")]
    Start(#[from] StartError),
    #[error("applying the TUN change failed")]
    Failed(#[from] Failure),
}

/// What in an inherited device's settings cannot be used.
#[cfg(unix)]
#[derive(Debug, thiserror::Error)]
pub enum InheritedTunError {
    #[error("invalid tun address {0}")]
    Address(String),
    #[error("invalid tun dns {0}")]
    Dns(String),
}

/// A device the host opened and hands over, with how to run it.
#[cfg(unix)]
pub struct InheritedTun {
    pub mtu: Option<u32>,
    pub address: Vec<String>,
    pub dns: Vec<String>,
    pub congestion_controller: Option<String>,
}

impl Engine {
    /// Android hands the core a descriptor; elsewhere the core opens a device by name.
    pub fn named_tun_supported(&self) -> bool {
        !self.is_android()
    }

    /// Turns TUN on with this device and stack, and off again if it did not come up.
    pub async fn start_named_tun(
        &self,
        device: Option<String>,
        stack: Option<String>,
    ) -> Result<(), TunStartError> {
        self.update(UpdateRequest {
            tun: Some(TunPatch {
                enable: true,
                device,
                stack,
                auto_route: None,
            }),
            ..UpdateRequest::default()
        })
        .await?;
        if let Some(fault) = self.tun_fault() {
            self.disable_tun().await?;
            return Err(TunStartError::Unavailable(fault.message));
        }
        Ok(())
    }

    /// Turns off the TUN device the core opened by name.
    pub async fn disable_tun(&self) -> Result<(), Failure> {
        self.update(UpdateRequest {
            tun: Some(TunPatch {
                enable: false,
                device: None,
                stack: None,
                auto_route: None,
            }),
            ..UpdateRequest::default()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> IpCidr {
        let (addr, prefix) = text.split_once('/').unwrap();
        IpCidr {
            addr: addr.parse().unwrap(),
            prefix: prefix.parse().unwrap(),
        }
    }

    #[test]
    fn the_device_address_comes_from_the_fake_ip_range() {
        assert_eq!(
            inet4_of(Some(cidr("198.18.0.1/16"))),
            Prefix::parse("198.18.0.1/30")
        );
        assert_eq!(
            inet4_of(Some(cidr("28.0.0.1/8"))),
            Prefix::parse("28.0.0.1/30")
        );
        assert_eq!(inet4_of(None), Prefix::parse("198.18.0.1/30"));
    }

    #[test]
    fn the_v6_address_follows_the_ipv6_switch() {
        let config = TunConfig::default();
        assert_eq!(
            options_of(&config, None, true).inet6_address,
            Prefix::parse(DEFAULT_INET6).into_iter().collect::<Vec<_>>()
        );
        assert!(options_of(&config, None, false).inet6_address.is_empty());
    }

    #[test]
    fn an_unset_mtu_and_timeout_keep_the_defaults() {
        let options = options_of(&TunConfig::default(), None, true);
        assert_eq!(options.mtu, DEFAULT_MTU);
        assert_eq!(options.udp_timeout, TunOptions::default().udp_timeout);
        assert_eq!(options.device, None);
    }

    #[cfg(unix)]
    #[test]
    fn vpn_options_read_what_the_service_sends() {
        let tun = InheritedTun {
            mtu: Some(1480),
            address: vec!["172.19.0.1/30".into(), " fdfe:dcba:9876::1/126".into()],
            dns: vec!["172.19.0.2".into()],
            congestion_controller: Some("bbr".into()),
        };
        let (options, _) = vpn_options(&tun).unwrap();
        assert_eq!(options.mtu, 1480);
        assert_eq!(
            options.inet4_address,
            Prefix::parse("172.19.0.1/30")
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(options.inet6_address.len(), 1);
        assert_eq!(options.dns_hijack, vec!["172.19.0.2:53".to_string()]);
        assert!(!options.auto_route);
    }

    #[cfg(unix)]
    #[test]
    fn a_bad_vpn_request_is_refused() {
        let bad = |address: &str, dns: &str| {
            vpn_options(&InheritedTun {
                mtu: None,
                address: vec![address.into()],
                dns: vec![dns.into()],
                congestion_controller: None,
            })
            .is_err()
        };
        assert!(bad("nonsense", ""));
        assert!(bad("172.19.0.1/30", "nonsense"));
        assert!(!bad("172.19.0.1/30", "172.19.0.2"));
    }

    #[cfg(unix)]
    #[test]
    fn an_unset_or_zero_vpn_mtu_keeps_the_default() {
        for mtu in [None, Some(0)] {
            let tun = InheritedTun {
                mtu,
                address: Vec::new(),
                dns: Vec::new(),
                congestion_controller: None,
            };
            assert_eq!(vpn_options(&tun).unwrap().0.mtu, DEFAULT_MTU);
        }
    }
}
