use std::sync::Arc;
use std::time::Duration;

use concord_common::{DialEnv, EventSink, NodeDialer, Outbound};
use concord_config::proxy::ProxyDef;
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use serde_json::{Map, Value};

use crate::selection::SelectionStore;

pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(5);

pub trait RouteMoved: Send + Sync {
    fn moved(&self);
}

/// What the host last asked for. `None` means it asked for nothing, and the
/// built-in default applies.
pub trait TestDefaults: Send + Sync {
    fn test_url(&self) -> Option<String> {
        None
    }

    fn delay_timeout(&self) -> Option<Duration> {
        None
    }

    fn unified_delay(&self) -> bool {
        false
    }
}

pub struct NoDefaults;

impl TestDefaults for NoDefaults {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builtin {
    Direct,
    Reject,
    RejectDrop,
    Compatible,
    Pass,
    PassRule,
}

pub struct BuildFailure {
    pub message: String,
}

pub enum Built {
    Node(Arc<dyn Outbound>),
    Quarantined {
        name: String,
        kind: String,
        reason: String,
    },
}

/// The one place the group crate touches how a proxy mapping becomes an outbound.
pub trait NodeFactory: Send + Sync {
    fn builtin(&self, which: Builtin) -> Arc<dyn Outbound>;

    fn build_def(&self, def: &ProxyDef) -> Result<Arc<dyn Outbound>, BuildFailure>;

    /// A mapping out of a provider, which may be a type this core drops.
    fn build_map(&self, map: &Map<String, Value>) -> Result<Built, String>;
}

pub type EnvFactory = Arc<dyn Fn(Arc<dyn NodeDialer>) -> DialEnv + Send + Sync>;

#[derive(Clone)]
pub struct GroupDeps {
    pub selections: Arc<SelectionStore>,
    pub env: EnvFactory,
    pub fetcher: Arc<dyn crate::fetch::Fetcher>,
    pub events: Arc<dyn EventSink>,
    pub route: Arc<dyn RouteMoved>,
    pub options: Arc<dyn TestDefaults>,
    pub home: Arc<HomeDir>,
    pub trust: Arc<TrustStore>,
    pub factory: Arc<dyn NodeFactory>,
}
