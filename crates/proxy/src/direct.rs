use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Initiator, IpVersion, Outbound, OutboundInfo, OutboundKind,
    PacketSession, SockOpts, Tasks,
};
use concord_net::{DirectPacketSession, LoopbackGuard, dial_tcp};

use crate::node::Egress;

pub(crate) struct Direct {
    info: OutboundInfo,
    version: IpVersion,
    egress: Option<Egress>,
    loopback: Option<Arc<LoopbackGuard>>,
    tasks: Tasks,
}

impl Direct {
    pub(crate) fn new(
        info: OutboundInfo,
        egress: Option<Egress>,
        loopback: Option<Arc<LoopbackGuard>>,
        tasks: Tasks,
    ) -> Self {
        Direct {
            version: egress.as_ref().map_or(IpVersion::Dual, Egress::version),
            info,
            egress,
            loopback,
            tasks,
        }
    }

    fn opts(&self, cx: &DialCx<'_>) -> SockOpts {
        match &self.egress {
            Some(egress) => egress.sock_opts(cx.env),
            None => cx.env.sock_opts.clone(),
        }
    }
}

#[async_trait]
impl Outbound for Direct {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let direct = DialCx::new(cx.env, Initiator::Direct, cx.deadline);
        let stream = dial_tcp(&direct, dst, self.version, &self.opts(cx)).await?;
        Ok(match &self.loopback {
            Some(guard) => Box::new(guard.track_tcp(stream)),
            None => Box::new(stream),
        })
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let direct = DialCx::new(cx.env, Initiator::Direct, cx.deadline);
        let session = DirectPacketSession::associate(
            &direct,
            hint,
            self.version,
            &self.opts(cx),
            self.loopback.as_ref(),
            &self.tasks,
        )
        .await?;
        Ok(Arc::new(session))
    }
}

pub(crate) fn info(name: &str, kind: OutboundKind) -> OutboundInfo {
    OutboundInfo {
        name: Arc::from(name),
        kind,
        addr: Arc::from(""),
        udp: true,
        provider: None,
        ip_version: concord_common::IpVersion::Dual,
    }
}
