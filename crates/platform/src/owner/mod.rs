#[cfg(target_os = "macos")]
mod darwin;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(windows, test))]
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only parsed in tests off Windows")
)]
mod mib;
pub mod procnet;
#[cfg(windows)]
mod windows;

use std::net::SocketAddr;

use concord_common::{Network, ProcessInfo};

/// Whether an owner comes with the uid of its socket; mihomo refuses UID rules elsewhere
/// (`rules/common/uid.go::NewUid`).
pub const READS_UID: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// Blocking table scan, and `None` on Android where only the embedding app can answer.
pub fn find_owner_blocking(network: Network, src: SocketAddr) -> Option<ProcessInfo> {
    #[cfg(target_os = "macos")]
    return darwin::find(network, src);
    #[cfg(target_os = "linux")]
    return linux::find(network, src);
    #[cfg(windows)]
    return windows::find(network, src);
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (network, src);
        None
    }
}

/// The uid that owns a local socket, from the kernel's socket tables. On Android only a root
/// process may read them.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn find_uid(network: Network, src: SocketAddr) -> Option<u32> {
    linux::find_uid(network, src)
}
