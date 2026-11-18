#![allow(
    unsafe_code,
    reason = "socket options, process tables, rlimits and ownership syscalls have no safe std wrapper"
)]

mod accept;
mod certs;
mod clock;
mod cpus;
mod exhaustion;
mod home;
mod icmp;
mod identity;
mod limits;
mod mem;
pub mod mmap;
mod native;
mod netinfo;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod nosplice;
mod observer;
pub mod owner;
#[cfg(unix)]
mod sigpipe;
mod sockopt;
mod sparse;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod splice;
mod tproxy_udp;
mod transparent;
mod udp_batch;
mod udpbuf;
#[cfg(target_os = "macos")]
mod utun;
mod watch;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{FlowKey, ProcessInfo, RawSocket};

pub use accept::is_lost_connection;
pub use certs::{certs_from_dirs, system_root_certs};
pub use clock::{local_utc_offset, set_system_time};
pub use cpus::{assignable_cpus, available_cpus};
pub use exhaustion::is_local_exhaustion;
pub use home::HomeDir;
pub use icmp::{IcmpSocket, icmp_echo_socket};
pub use identity::{SocketIdentity, with_same_socket};
pub use limits::{FdPressure, fd_limit, open_fd_count, raise_fd_limit};
pub use mem::{release_free_memory, resident_memory};
pub use native::NativePlatform;
pub use netinfo::{interface_addrs, interface_by_name, parse_resolv_conf};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use nosplice::SplicePipe;
pub use observer::SocketObserver;
#[cfg(unix)]
pub use sigpipe::ignore_sigpipe;
pub use sockopt::{
    KEEP_ALIVE, SEND_TCP_VECTORED, TRY_SEND_VECTORED, bind_to_interface, enable_tfo,
    is_global_unicast, mptcp_protocol, prepare_udp_socket, raw_socket_of, send_space,
    send_tcp_vectored, set_routing_mark, try_send_vectored,
};
pub use sparse::SparseBuf;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use splice::SplicePipe;
pub use tproxy_udp::{TproxyDatagram, bind_foreign_udp, prepare_tproxy_udp, recv_original_dst};
pub use transparent::{make_transparent, original_dst, prepare_listener};
pub use udp_batch::{UDP_BATCH, UdpBatch};
pub use udpbuf::grow_udp_buffers;
#[cfg(target_os = "macos")]
pub use utun::{UTUN_BATCH, UTUN_BATCH_FRAME, utun_recv_batch, utun_send_batch};
pub use watch::FileWatch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: Arc<str>,
    pub index: u32,
    pub addrs: Vec<IpAddr>,
}

/// What the OS or the embedding app answers for the core. Nothing here may
/// create a socket of its own: a lookup that did would loop back into the VPN.
#[async_trait]
pub trait Platform: Send + Sync + 'static {
    /// Keeps `socket` out of the host's VPN. `false` when that is owed but could not be done now,
    /// as while no VPN is established; the caller retries on the next one.
    fn protect(&self, socket: RawSocket) -> bool;

    async fn find_owner(&self, flow: &FlowKey) -> Option<ProcessInfo>;

    fn default_interface(&self) -> Option<InterfaceInfo>;

    /// What auto-detect binds a socket for `dest` to.
    fn interface_for(&self, _dest: IpAddr) -> Option<InterfaceInfo> {
        self.default_interface()
    }

    fn interface_by_name(&self, name: &str) -> Option<InterfaceInfo> {
        interface_by_name(name)
    }

    fn system_dns(&self) -> Vec<SocketAddr>;

    fn fd_pressure(&self) -> bool {
        false
    }

    /// Whether `ip` is assigned to any interface of this machine.
    fn is_local_ip(&self, _ip: IpAddr) -> bool {
        false
    }

    /// Interfaces that never count as the default one, such as the TUN device.
    fn set_excluded_interfaces(&self, _names: Vec<String>) {}

    /// The host saw the network change: interfaces and routes read before are stale.
    fn network_changed(&self) {}
}
