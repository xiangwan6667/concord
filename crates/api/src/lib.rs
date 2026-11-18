//! The typed control surface of the core: one async function per protocol method,
//! adapting to the engine. Nothing here knows frames, JSON-RPC or a transport.

mod bus;
mod control;
mod convert;
mod fds;
mod logging;
mod service;
mod stream;
mod watch;

pub use bus::EventBus;
pub use concord_common::Origin;
pub use concord_common::sync;
pub use concord_engine::ControllerCors;
pub use concord_engine::local_utc_offset;
pub use control::{Control, ControlOptions, ControllerSettings, Reload, valid_status_ranges};
#[cfg(unix)]
pub use fds::AdoptedFds;
pub use logging::{LogBridge, LogGate};
pub use service::{ControlService, ServiceInfo};
pub use stream::{Delivery, EventStream, PolicyQueue, QueueStream, Subscription};
