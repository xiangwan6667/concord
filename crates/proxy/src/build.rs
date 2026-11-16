use std::sync::Arc;

use concord_common::{Outbound, OutboundKind};
use concord_config::proxy::{ProxyDef, ProxyKind};

use crate::ctx::{BuildCtx, BuildError};
use crate::direct::{self, Direct};
use crate::node::Egress;
use crate::reject::Reject;

/// One arm per protocol module; a new protocol adds a module and a line here.
pub fn build_outbound(def: &ProxyDef, ctx: &BuildCtx) -> Result<Arc<dyn Outbound>, BuildError> {
    let outbound = build_kind(def, ctx)?;
    match def.smux.as_ref().filter(|smux| smux.enabled) {
        Some(smux) => crate::smux::wrap(outbound, smux),
        None => Ok(outbound),
    }
}

fn build_kind(def: &ProxyDef, ctx: &BuildCtx) -> Result<Arc<dyn Outbound>, BuildError> {
    match &def.kind {
        ProxyKind::Direct(_) => Ok(Arc::new(Direct::new(
            direct::info(&def.name, OutboundKind::Direct),
            Some(Egress::new(&def.name, &def.common)),
            ctx.loopback.clone(),
        ))),
        ProxyKind::Reject(_) => Ok(Arc::new(Reject::new(&def.name, OutboundKind::Reject))),
        ProxyKind::Socks5(opts) => crate::socks5::build(def, opts, ctx),
        ProxyKind::Http(opts) => crate::http::build(def, opts, ctx),
        ProxyKind::Ss(opts) => crate::ss::build(def, opts, ctx),
        ProxyKind::Vmess(opts) => crate::vmess::build(def, opts, ctx),
        ProxyKind::Vless(opts) => crate::vless::build(def, opts, ctx),
        ProxyKind::Trojan(opts) => crate::trojan::build(def, opts, ctx),
        ProxyKind::Hysteria(opts) => crate::hysteria::build(def, opts, ctx),
        ProxyKind::Hysteria2(opts) => crate::hysteria2::build(def, opts, ctx),
        ProxyKind::Tuic(opts) => crate::tuic::build(def, opts, ctx),
        ProxyKind::AnyTls(opts) => crate::anytls::build(def, opts, ctx),
        ProxyKind::Miu(opts) => crate::miu::build(def, opts, ctx),
        ProxyKind::WireGuard(opts) => crate::wireguard::build(def, opts, ctx),
        ProxyKind::Ssr(opts) => crate::ssr::build(def, opts, ctx),
        ProxyKind::Snell(opts) => crate::snell::build(def, opts, ctx),
        ProxyKind::Ssh(opts) => crate::ssh::build(def, opts, ctx),
        ProxyKind::ShadowQuic(opts) => crate::shadowquic::build(def, opts, ctx),
        ProxyKind::Mieru(opts) => crate::mieru::build(def, opts, ctx),
    }
}
