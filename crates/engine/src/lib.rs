//! Composition root: lifecycle, apply, and the state that outlives a config.

mod apply;
mod dns_server;
mod engine;
mod error;
mod fake_ip_store;
mod faults;
mod lan;
mod ntp;
pub mod ops;
pub mod probe;
mod probe_env;
mod proxy_tasks;
mod resources;
mod route;
mod tun;
mod views;

pub use concord_config::general::ControllerCors;
pub use concord_dns::{QueryView, QuestionView, RecordView};
pub use concord_group::{
    DelayRecord, GroupView, HealthSnapshot, NodeStateView, NodeView, ProxyView, ProxyViews,
    StatusRanges, UrlHealth,
};
pub use concord_platform::{HomeDir, local_utc_offset};
pub use engine::{
    Engine, EngineConfig, MitmService, Providers, SetupRequest, TunPatch, UpdateRequest,
};
pub use error::Failure;
pub use faults::{Service, ServiceFault};
pub use probe::RouteHit;
pub use route::RouteCounters;
pub use tun::TunStartError;
#[cfg(unix)]
pub use tun::{InheritedTun, InheritedTunError};
pub use views::*;

pub use concord_tunnel::ExplainFlow;
