use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use concord_common::Tasks;
use concord_net::LoopbackGuard;
use concord_platform::HomeDir;
use concord_tls::{TlsError, TrustStore};

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

#[derive(Clone)]
pub struct BuildCtx {
    pub trust: Arc<TrustStore>,
    /// `None` on Android, where DIRECT does not check for loops.
    pub loopback: Option<Arc<LoopbackGuard>>,
    pub clock: Clock,
    pub home: Option<Arc<HomeDir>>,
    /// Every task a built node or its sessions start; the engine stops them on shutdown.
    pub tasks: Tasks,
}

impl BuildCtx {
    pub fn new(trust: Arc<TrustStore>) -> Self {
        BuildCtx {
            trust,
            loopback: None,
            clock: Arc::new(SystemTime::now),
            home: None,
            tasks: Tasks::default(),
        }
    }

    pub fn with_loopback(mut self, guard: Option<Arc<LoopbackGuard>>) -> Self {
        self.loopback = guard;
        self
    }

    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_home(mut self, home: Arc<HomeDir>) -> Self {
        self.home = Some(home);
        self
    }

    /// mihomo's `C.Path.Resolve` and `IsSafePath`: a relative path joins the home
    /// directory, and where the platform confines profile files the file must lie inside it,
    /// so a profile cannot point a node at a key or certificate of the user's elsewhere.
    pub(crate) fn resolve_file(&self, path: &str) -> Result<PathBuf, BuildError> {
        let Some(home) = &self.home else {
            return Ok(PathBuf::from(path));
        };
        if !HomeDir::CONFINES_PROFILE_FILES {
            return Ok(home.join(path));
        }
        home.confine(path).map_err(|_| {
            BuildError::invalid(format!("path is not subpath of home directory: {path}"))
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Tls(#[from] TlsError),
}

impl BuildError {
    pub fn unsupported(message: impl Into<String>) -> Self {
        BuildError::Unsupported(message.into())
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        BuildError::Invalid(message.into())
    }

    pub fn is_unsupported(&self) -> bool {
        matches!(self, BuildError::Unsupported(_))
    }
}
