use std::sync::Arc;

use concord_common::{Outbound, OutboundKind, Tasks};
use concord_net::LoopbackGuard;

use crate::direct::{self, Direct};
use crate::reject::Reject;

pub fn direct(name: &str) -> Arc<dyn Outbound> {
    direct_with(name, None, Tasks::default())
}

pub fn direct_with(
    name: &str,
    loopback: Option<Arc<LoopbackGuard>>,
    tasks: Tasks,
) -> Arc<dyn Outbound> {
    Arc::new(Direct::new(
        direct::info(name, OutboundKind::Direct),
        None,
        loopback,
        tasks,
    ))
}

pub fn compatible() -> Arc<dyn Outbound> {
    compatible_with(None, Tasks::default())
}

pub fn compatible_with(loopback: Option<Arc<LoopbackGuard>>, tasks: Tasks) -> Arc<dyn Outbound> {
    Arc::new(Direct::new(
        direct::info("COMPATIBLE", OutboundKind::Compatible),
        None,
        loopback,
        tasks,
    ))
}

pub fn reject() -> Arc<dyn Outbound> {
    Arc::new(Reject::new("REJECT", OutboundKind::Reject))
}

pub fn reject_drop() -> Arc<dyn Outbound> {
    Arc::new(Reject::new("REJECT-DROP", OutboundKind::RejectDrop))
}

pub fn pass() -> Arc<dyn Outbound> {
    Arc::new(Reject::new("PASS", OutboundKind::Pass))
}

pub fn pass_rule() -> Arc<dyn Outbound> {
    Arc::new(Reject::new("PASS-RULE", OutboundKind::PassRule))
}
