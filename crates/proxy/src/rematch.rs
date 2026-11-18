use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::RematchOpts;

use crate::reject::Reject;

pub(crate) struct Rematch {
    closed: Reject,
    update: concord_common::outbound::Rematch,
}

impl Rematch {
    pub(crate) fn new(name: &str, opts: &RematchOpts) -> Self {
        Self {
            closed: Reject::new(name, OutboundKind::Rematch),
            update: concord_common::outbound::Rematch {
                name: opts.target_rematch_name.as_deref().map(Arc::from),
                sub_rule: opts.target_sub_rule.as_deref().map(Arc::from),
            },
        }
    }
}

#[async_trait]
impl Outbound for Rematch {
    fn info(&self) -> &OutboundInfo {
        self.closed.info()
    }

    fn rematch(&self) -> Option<&concord_common::outbound::Rematch> {
        Some(&self.update)
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        self.closed.connect(cx, dst).await
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        self.closed.associate(cx, hint).await
    }

    async fn resolve_udp(
        &self,
        cx: &DialCx<'_>,
        host: &str,
    ) -> Option<io::Result<std::net::IpAddr>> {
        self.closed.resolve_udp(cx, host).await
    }
}
