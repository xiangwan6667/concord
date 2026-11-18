mod resolv;
mod select;
mod tables;
mod watch;

#[cfg(unix)]
mod ifaces;
#[cfg(target_os = "macos")]
mod route_macos;
#[cfg(any(target_os = "linux", target_os = "android", test))]
mod route_proc;
#[cfg(any(windows, test))]
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only parsed in tests off Windows")
)]
mod sockaddr;
#[cfg(windows)]
mod win;

use std::net::{IpAddr, SocketAddr};

use crate::InterfaceInfo;

pub use resolv::parse_resolv_conf;
pub use tables::{Cache, Tables};

/// Every address on the host's interfaces, as Go's `net.InterfaceAddrs`.
#[cfg(unix)]
pub fn interface_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    ifaces::walk(|_, _, addr, _| out.push(addr));
    out
}

#[cfg(windows)]
pub fn interface_addrs() -> Vec<IpAddr> {
    win::local_addrs()
}

#[cfg(unix)]
pub fn interface_by_name(name: &str) -> Option<InterfaceInfo> {
    ifaces::by_name(name)
}

#[cfg(windows)]
pub fn interface_by_name(name: &str) -> Option<InterfaceInfo> {
    win::adapters()
        .into_iter()
        .map(|adapter| adapter.info)
        .find(|info| info.name.as_ref() == name)
}

#[cfg(unix)]
pub fn system_dns() -> Vec<SocketAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|text| parse_resolv_conf(&text))
        .unwrap_or_default()
}

#[cfg(windows)]
pub fn system_dns() -> Vec<SocketAddr> {
    win::system_dns()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn default_interface(excluded: &[String]) -> Option<InterfaceInfo> {
    let name = route_proc::default_interface_name(excluded)?;
    ifaces::by_name(&name)
}

#[cfg(target_os = "macos")]
pub fn default_interface(excluded: &[String]) -> Option<InterfaceInfo> {
    route_macos::default_interface(excluded)
}

#[cfg(windows)]
pub fn default_interface(excluded: &[String]) -> Option<InterfaceInfo> {
    win::default_interface(excluded)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
pub fn default_interface(_excluded: &[String]) -> Option<InterfaceInfo> {
    None
}
