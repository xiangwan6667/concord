use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use concord_common::sync::lock;
use concord_common::{
    Address, CoreError, DialCx, DialEnv, HostResolver, Initiator, IpVersion, LookupIps, SockOpts,
    Tasks,
};
use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnetwork::IpNetwork;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tokio_util::sync::CancellationToken;

use super::amnezia::Amnezia;
use super::config::{PeerConfig, WgConfig};
use super::dns::RemoteDns;
use super::transport::{Breaker, Carrier, Reserved, WireFactory};
use crate::node::{Egress, resolve_server};
use crate::stack::{Stack, StackConfig, StackRecv, StackSend, TcpConn, UdpPort};

const IDLE_TICK: Duration = Duration::from_secs(90);

type WgDevice = Device<(WireFactory, StackSend, StackRecv)>;

pub(super) struct Tunnel {
    pub(super) stack: Arc<Stack>,
    device: Option<WgDevice>,
    driver: JoinHandle<()>,
    tasks: Tasks,
    dropped: CancellationToken,
    reserved: Arc<Reserved>,
    amnezia: Option<Arc<Amnezia>>,
    broken: Arc<Breaker>,
    dns: Option<RemoteDns>,
    endpoints: Mutex<Endpoints>,
    epoch: AtomicU64,
}

struct Endpoints {
    resolved: HashMap<usize, SocketAddr>,
    checked: Instant,
}

/// gotatun's own `Drop` stops the device on a task nothing waits for; `stop` lets the engine
/// wait for it.
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.driver.abort();
        self.dropped.cancel();
        if let Some(device) = self.device.take() {
            self.tasks.spawn_to_end(device.stop());
        }
    }
}

fn bind_families(
    env: &DialEnv,
    egress: &Egress,
    endpoints: &[SocketAddr],
) -> io::Result<Vec<Arc<tokio::net::UdpSocket>>> {
    let opts = SockOpts {
        tunnel_udp_buffers: true,
        ..egress.sock_opts(env)
    };
    let mut sockets = Vec::new();
    for want_v4 in [true, false] {
        if let Some(endpoint) = endpoints.iter().find(|e| e.is_ipv4() == want_v4) {
            sockets.push(Arc::new(env.sockets.bind_udp(endpoint.ip(), &opts)?));
        }
    }
    Ok(sockets)
}

fn peer_of(config: &PeerConfig, endpoint: SocketAddr, keepalive: Option<u16>) -> Peer {
    let mut peer = Peer::new(PublicKey::from(config.public_key))
        .with_endpoint(endpoint)
        .with_allowed_ips(config.allowed_ips.iter().copied());
    peer.preshared_key = config.preshared_key;
    peer.keepalive = keepalive;
    peer
}

fn reserved_map(config: &WgConfig, resolved: &[SocketAddr]) -> HashMap<SocketAddr, [u8; 3]> {
    config
        .peers
        .iter()
        .zip(resolved)
        .filter(|(peer, _)| peer.reserved != [0; 3])
        .map(|(peer, endpoint)| (*endpoint, peer.reserved))
        .collect()
}

impl Tunnel {
    pub(super) async fn build(
        cx: &DialCx<'_>,
        egress: &Egress,
        config: &WgConfig,
        tasks: &Tasks,
    ) -> io::Result<Arc<Tunnel>> {
        let mut resolved = Vec::with_capacity(config.peers.len());
        for peer in &config.peers {
            resolved.push(resolve_server(cx, &peer.address(), egress.version()).await?);
        }
        let carrier = match egress.via() {
            Some(via) => {
                let inner = cx.enter(egress.name())?;
                let hint = resolved
                    .first()
                    .copied()
                    .map(Address::from)
                    .ok_or_else(|| io::Error::other("wireguard has no peer"))?;
                Carrier::Session(cx.env.nodes.associate_via(via, &inner, &hint).await?)
            }
            None => Carrier::Sockets(bind_families(cx.env, egress, &resolved)?),
        };
        let reserved = Arc::new(ArcSwap::from_pointee(reserved_map(config, &resolved)));
        let amnezia = config.amnezia.as_ref().map(|settings| {
            let own = PublicKey::from(&StaticSecret::from(config.private_key));
            let publics: Vec<[u8; 32]> = config.peers.iter().map(|peer| peer.public_key).collect();
            let amnezia = Arc::new(Amnezia::new(settings.clone(), own.as_bytes(), &publics));
            for (index, endpoint) in resolved.iter().enumerate() {
                amnezia.set_endpoint(index, *endpoint);
            }
            amnezia
        });
        let stack = Stack::start(
            &StackConfig {
                addrs: config.addrs.iter().map(|net| net.ip()).collect(),
                mtu: config.mtu,
            },
            tasks,
        );
        let broken = Arc::new(Breaker::new(stack.driver.abort_handle()));
        let factory = WireFactory::new(carrier, reserved.clone(), amnezia.clone(), broken.clone());
        let peers = config
            .peers
            .iter()
            .zip(&resolved)
            .map(|(peer, endpoint)| peer_of(peer, *endpoint, config.keepalive));
        let device = DeviceBuilder::new()
            .with_udp(factory)
            .with_ip_pair(stack.send, stack.recv)
            .with_private_key(StaticSecret::from(config.private_key))
            .with_peers(peers)
            .build()
            .await
            .map_err(|err| io::Error::other(format!("wireguard device: {err}")))?;
        let tunnel = Arc::new(Tunnel {
            stack: stack.stack,
            device: Some(device),
            driver: stack.driver,
            tasks: tasks.clone(),
            dropped: tasks.child_token(),
            reserved,
            amnezia,
            broken,
            dns: (!config.remote_dns.is_empty()).then(|| {
                RemoteDns::new(
                    config.remote_dns.clone(),
                    config.addrs.iter().any(IpNetwork::is_ipv6),
                )
            }),
            endpoints: Mutex::new(Endpoints {
                resolved: resolved.iter().copied().enumerate().collect(),
                checked: Instant::now(),
            }),
            epoch: AtomicU64::new(0),
        });
        Ok(tunnel)
    }

    pub(super) fn usable(&self) -> bool {
        !self.broken.tripped() && !self.driver.is_finished()
    }

    pub(super) fn touch(&self) -> u64 {
        self.epoch.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn tcp(
        self: &Arc<Self>,
        remote: SocketAddr,
        config: &WgConfig,
    ) -> io::Result<TcpConn> {
        self.stack.connect_tcp(remote, config.congestion)
    }

    pub(super) fn udp(&self) -> io::Result<UdpPort> {
        self.stack.bind_udp()
    }

    pub(super) async fn resolve(
        &self,
        config: &WgConfig,
        resolver: &dyn HostResolver,
        host: &str,
        version: IpVersion,
        initiator: Initiator,
    ) -> io::Result<IpAddr> {
        self.lookup(config, resolver, host, version, initiator)
            .await?
            .first(version)
            .ok_or_else(|| CoreError::IpNotFound(host.to_string()).into())
    }

    pub(super) async fn lookup(
        &self,
        config: &WgConfig,
        resolver: &dyn HostResolver,
        host: &str,
        version: IpVersion,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        match &self.dns {
            Some(dns) => dns.lookup(&self.stack, host, config.congestion).await,
            None => resolver.lookup(host, version, initiator).await,
        }
    }

    pub(super) async fn refresh_endpoints(
        &self,
        cx: &DialCx<'_>,
        egress: &Egress,
        config: &WgConfig,
    ) {
        let Some(interval) = config.refresh else {
            return;
        };
        {
            let mut endpoints = lock(&self.endpoints);
            if endpoints.checked.elapsed() < interval {
                return;
            }
            endpoints.checked = Instant::now();
        }
        for (index, peer) in config.peers.iter().enumerate() {
            let Ok(fresh) = resolve_server(cx, &peer.address(), egress.version()).await else {
                tracing::warn!("wireguard could not refresh the address of {}", peer.server);
                continue;
            };
            let old = {
                let mut endpoints = lock(&self.endpoints);
                endpoints.resolved.insert(index, fresh)
            };
            if old == Some(fresh) {
                continue;
            }
            let key = PublicKey::from(peer.public_key);
            let Some(device) = &self.device else { return };
            let updated = device
                .write(async |device| {
                    device
                        .modify_peer(&key, |peer| peer.set_endpoint(Some(fresh)))
                        .await
                })
                .await;
            if updated.is_ok()
                && let Some(amnezia) = &self.amnezia
            {
                amnezia.set_endpoint(index, fresh);
            }
            if updated.is_ok() && peer.reserved != [0; 3] {
                let mut map = (**self.reserved.load()).clone();
                map.insert(fresh, peer.reserved);
                self.reserved.store(Arc::new(map));
            }
        }
    }
}

/// Tears the tunnel down after it has carried no flow for two ticks, so an idle node costs nothing.
pub(super) fn watch_idle<F>(tunnel: &Arc<Tunnel>, retire: F)
where
    F: Fn(&Arc<Tunnel>) + Send + 'static,
{
    let weak: Weak<Tunnel> = Arc::downgrade(tunnel);
    let dropped = tunnel.dropped.clone();
    let watch = async move {
        let mut seen = 0;
        let mut quiet = false;
        loop {
            sleep(IDLE_TICK).await;
            let Some(tunnel) = weak.upgrade() else { return };
            let epoch = tunnel.epoch.load(Ordering::Relaxed);
            if !tunnel.usable() {
                retire(&tunnel);
                return;
            }
            let idle = tunnel.stack.active() == 0 && epoch == seen;
            if idle && quiet {
                retire(&tunnel);
                return;
            }
            quiet = idle;
            seen = epoch;
        }
    };
    tunnel.tasks.spawn(async move {
        let _ = dropped.run_until_cancelled_owned(watch).await;
    });
}
