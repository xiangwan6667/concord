use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use concord_common::dns_relay::DnsHijack;
use concord_common::{
    CoreError, DnsMode, EventSink, Host, HostResolver, Initiator, IpVersion, LookupIps, SockOpts,
    SocketFactory,
};
use concord_platform::Platform;
use concord_tls::TrustStore;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;

use crate::RuleEnv;
use crate::client::ClientRef;
use crate::dialer::UpstreamDialer;
use crate::enhance::Enhancer;
use crate::fakeip::FakeIpPool;
use crate::hosts::Hosts;
use crate::msg;
use crate::resolver::Group;
use crate::system::SystemServers;

pub struct ResolverDeps {
    pub sockets: Arc<dyn SocketFactory>,
    pub trust: Arc<TrustStore>,
    pub events: Arc<dyn EventSink>,
    pub platform: Arc<dyn Platform>,
    pub rules: Arc<dyn RuleEnv>,
    pub dialer: Weak<dyn UpstreamDialer>,
    pub sock_opts: SockOpts,
    pub ipv6: bool,
    pub store_fake_ip: bool,
}

pub struct Resolver {
    pub(crate) main: Arc<Group>,
    pub(crate) proxy: Option<Arc<Group>>,
    pub(crate) direct: Option<Arc<Group>>,
    pub(crate) default: Arc<Group>,
    pub(crate) hosts: Hosts,
    pub(crate) enhancer: Enhancer,
    pub(crate) ipv6: AtomicBool,
    pub(crate) clients: Vec<ClientRef>,
    pub(crate) system: Arc<SystemServers>,
}

impl Resolver {
    pub fn set_ipv6(&self, enabled: bool) {
        self.ipv6.store(enabled, Ordering::Relaxed);
    }

    pub fn mode(&self) -> DnsMode {
        self.enhancer.mode
    }

    pub fn hosts(&self) -> &Hosts {
        &self.hosts
    }

    pub fn fake_ip_enabled(&self) -> bool {
        self.enhancer.fake_ip_enabled()
    }

    pub fn mapping_enabled(&self) -> bool {
        self.enhancer.mode != DnsMode::Normal
    }

    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        self.enhancer.fake_ip_enabled() && self.enhancer.pools().any(|pool| pool.is_fake(ip))
    }

    pub fn is_exist_fake_ip(&self, ip: IpAddr) -> bool {
        self.enhancer.fake_ip_enabled() && self.enhancer.pools().any(|pool| pool.exists(ip))
    }

    pub fn is_fake_broadcast_ip(&self, ip: IpAddr) -> bool {
        self.enhancer.fake_ip_enabled() && self.enhancer.pools().any(|pool| pool.is_broadcast(ip))
    }

    pub fn fake_ip_reverse(&self, ip: IpAddr) -> Option<Host> {
        self.fake_ip_host(ip)
    }

    pub fn find_host_by_ip(&self, ip: IpAddr) -> Option<Host> {
        self.host_for(ip)
    }

    pub fn insert_host_by_ip(&self, ip: IpAddr, host: &str) {
        self.enhancer.insert_mapping(ip, host);
    }

    pub fn flush_fake_ip(&self) {
        self.enhancer.pools().for_each(|pool| pool.flush());
    }

    pub fn has_fake_ip_mappings(&self) -> bool {
        self.enhancer.pools().any(|pool| !pool.is_empty())
    }

    /// `store-fake-ip`: each pool under its file name.
    pub fn fake_ip_pools(&self) -> impl Iterator<Item = (&'static str, &FakeIpPool)> {
        let v4 = self
            .enhancer
            .pool4
            .as_ref()
            .map(|pool| ("fake-ip.cache", pool));
        let v6 = self
            .enhancer
            .pool6
            .as_ref()
            .map(|pool| ("fake-ip6.cache", pool));
        v4.into_iter().chain(v6)
    }

    pub async fn fake_ip_changed(&self) {
        tokio::select! {
            () = pool_changed(self.enhancer.pool4.as_ref()) => {}
            () = pool_changed(self.enhancer.pool6.as_ref()) => {}
        }
    }

    pub fn restore_fake_ip(&self, read: impl Fn(&str) -> Option<Vec<u8>>) {
        for (name, pool) in self.fake_ip_pools() {
            if let Some(bytes) = read(name)
                && !pool.restore(&bytes)
            {
                tracing::warn!(
                    "[FakeIP] {name} belongs to another range or is damaged, starting empty"
                );
            }
        }
    }

    pub fn patch_from(&self, old: &Resolver) {
        self.enhancer.patch_from(&old.enhancer);
    }

    /// An answer to a raw DNS message, going through hosts, fake-ip and the
    /// mapping the way the DNS server of mihomo does, for TUN `dns-hijack` over
    /// TCP. `None` only when the bytes are not a DNS message.
    pub async fn handle_query(&self, query: &[u8], initiator: Initiator) -> Option<Vec<u8>> {
        let req = Message::from_vec(query).ok()?;
        let resp = self.answer(&req, initiator).await;
        msg::encode(&resp)
    }

    /// As `handle_query`, cut to what a UDP reply may carry: the size the client
    /// advertised, at most 2048 bytes.
    pub async fn handle_query_udp(&self, query: &[u8], initiator: Initiator) -> Option<Vec<u8>> {
        let req = Message::from_vec(query).ok()?;
        let resp = self.answer(&req, initiator).await;
        msg::fit_udp(resp, msg::request_udp_size(&req).min(2048))
    }

    pub async fn exchange(&self, req: &Message, initiator: Initiator) -> io::Result<Message> {
        self.main.exchange(req, initiator).await
    }

    pub fn clear_cache(&self) {
        for group in self.groups() {
            group.clear_cache();
        }
        self.system.flush();
    }

    pub fn reset_connections(&self) {
        for client in &self.clients {
            client.reset();
        }
        self.system.flush();
    }

    pub fn set_system_servers(&self, servers: Vec<SocketAddr>) {
        self.system.set(servers);
        self.reset_connections();
        self.clear_cache();
    }

    pub fn set_system_blacklist(&self, ips: Vec<IpAddr>) {
        self.system.set_blacklist(ips);
    }

    fn groups(&self) -> impl Iterator<Item = &Arc<Group>> {
        [&self.main, &self.default]
            .into_iter()
            .chain(self.proxy.iter())
            .chain(self.direct.iter())
    }

    fn group_for(&self, initiator: Initiator) -> &Arc<Group> {
        match initiator {
            Initiator::Proxy => self.proxy.as_ref().unwrap_or(&self.main),
            Initiator::Direct => self.direct.as_ref().unwrap_or(&self.main),
            _ => &self.main,
        }
    }
}

fn split(ips: Vec<IpAddr>) -> LookupIps {
    let (v4, v6) = ips.into_iter().partition(IpAddr::is_ipv4);
    LookupIps { v4, v6 }
}

fn version_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "ip version error")
}

#[async_trait]
impl HostResolver for Resolver {
    async fn lookup(
        &self,
        host: &str,
        version: IpVersion,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        if version == IpVersion::Ipv6 && !self.ipv6.load(Ordering::Relaxed) {
            return Err(CoreError::Ipv6Disabled.into());
        }
        if let Some(ips) = self.hosts.lookup_ips(host) {
            let found = split(ips);
            match version {
                IpVersion::Ipv4 if !found.v4.is_empty() => {
                    return Ok(LookupIps {
                        v4: found.v4,
                        v6: Vec::new(),
                    });
                }
                IpVersion::Ipv6 if !found.v6.is_empty() => {
                    return Ok(LookupIps {
                        v4: Vec::new(),
                        v6: found.v6,
                    });
                }
                IpVersion::Ipv4 | IpVersion::Ipv6 => {}
                _ => return Ok(found),
            }
        }
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            let ip = concord_common::addr::unmap(ip);
            return match (version, ip.is_ipv4()) {
                (IpVersion::Ipv4, false) | (IpVersion::Ipv6, true) => Err(version_error()),
                _ => Ok(split(vec![ip])),
            };
        }
        let group = self.group_for(initiator);
        match version {
            IpVersion::Ipv4 => group.lookup_v4(host, initiator).await,
            IpVersion::Ipv6 => group.lookup_v6(host, initiator).await,
            _ if self.ipv6.load(Ordering::Relaxed) => group.lookup_dual(host, initiator).await,
            _ => group.lookup_v4(host, initiator).await,
        }
    }

    async fn resolve_ech(&self, host: &str, initiator: Initiator) -> io::Result<Vec<u8>> {
        let query = msg::build_query(host, RecordType::HTTPS)
            .ok_or_else(|| io::Error::from(CoreError::IpNotFound(host.to_string())))?;
        let resp = self
            .group_for(initiator)
            .exchange(&query, initiator)
            .await?;
        msg::ech_config_list(&resp)
            .ok_or_else(|| io::Error::other("no ECH config found in DNS records"))
    }

    fn dns_server(&self) -> Option<&dyn DnsHijack> {
        Some(self)
    }
}

#[async_trait]
impl DnsHijack for Resolver {
    async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        self.handle_query_udp(query, Initiator::Other).await
    }

    async fn answer_stream(&self, query: &[u8]) -> Option<Vec<u8>> {
        self.handle_query(query, Initiator::Other).await
    }
}

pub(crate) fn rcode_of(code: concord_config::dns::Rcode) -> ResponseCode {
    use concord_config::dns::Rcode;
    match code {
        Rcode::Success => ResponseCode::NoError,
        Rcode::FormatError => ResponseCode::FormErr,
        Rcode::ServerFailure => ResponseCode::ServFail,
        Rcode::NameError => ResponseCode::NXDomain,
        Rcode::NotImplemented => ResponseCode::NotImp,
        Rcode::Refused => ResponseCode::Refused,
    }
}

async fn pool_changed(pool: Option<&FakeIpPool>) {
    match pool {
        Some(pool) => pool.changed().await,
        None => std::future::pending().await,
    }
}
