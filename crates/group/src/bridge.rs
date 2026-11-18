use std::sync::Arc;

use concord_common::Outbound;
use concord_config::proxy::{Capabilities, ProxyDef, ProxyParse, parse_proxy};
use concord_proxy::{BuildCtx, build_outbound, builtin};
use serde_json::{Map, Value};

use crate::deps::{BuildFailure, Built, Builtin, NodeFactory};

/// Builds nodes with the real protocol crate.
pub struct ProxyFactory {
    ctx: BuildCtx,
    capabilities: Capabilities,
}

impl ProxyFactory {
    pub fn new(ctx: BuildCtx, capabilities: Capabilities) -> Self {
        ProxyFactory { ctx, capabilities }
    }
}

impl NodeFactory for ProxyFactory {
    fn builtin(&self, which: Builtin) -> Arc<dyn Outbound> {
        match which {
            Builtin::Direct => {
                builtin::direct_with("DIRECT", self.ctx.loopback.clone(), self.ctx.tasks.clone())
            }
            Builtin::Reject => builtin::reject(),
            Builtin::RejectDrop => builtin::reject_drop(),
            Builtin::Compatible => {
                builtin::compatible_with(self.ctx.loopback.clone(), self.ctx.tasks.clone())
            }
            Builtin::Pass => builtin::pass(),
            Builtin::PassRule => builtin::pass_rule(),
        }
    }

    fn build_def(&self, def: &ProxyDef) -> Result<Arc<dyn Outbound>, BuildFailure> {
        build_outbound(def, &self.ctx).map_err(|err| BuildFailure {
            message: err.to_string(),
        })
    }

    fn build_map(&self, map: &Map<String, Value>) -> Result<Built, String> {
        match parse_proxy(map, &self.capabilities).map_err(|err| err.message)? {
            ProxyParse::Quarantined { name, kind, reason } => {
                Ok(Built::Quarantined { name, kind, reason })
            }
            ProxyParse::Ok(def) => match build_outbound(&def, &self.ctx) {
                Ok(outbound) => Ok(Built::Node(outbound)),
                Err(err) => Ok(Built::Quarantined {
                    name: def.name.clone(),
                    kind: def.kind.type_name().to_string(),
                    reason: err.to_string(),
                }),
            },
        }
    }
}
