#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod device;
mod dns;
mod options;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod provision;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod reactor;
pub mod route;
mod runner;
mod stack;
#[cfg(target_os = "linux")]
mod vnet;
#[cfg(windows)]
mod wintun;

#[cfg(any(test, feature = "testing"))]
#[doc(hidden)]
pub mod testing;

pub use device::{Device, TunDevice};
pub use dns::{DnsHijack, DnsMatcher, DnsRuleError};
pub use options::{IdRange, Prefix, TunOptions};
pub use runner::{
    DeviceSource, SelfExclusion, StartError, StartStep, StopReport, TunDeps, TunRunner,
};
pub use stack::{
    Congestion, DnsConfig, FlowSink, HandlerSink, IpStack, NetStack, StackOptions, StackStats,
    StatsSnapshot, Verdict,
};
