use concord_config::provider::RuleProviderDef;
use concord_group::FetchError;
use concord_rules::RuleSetError;
use concord_rules::geo::GeoError;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
pub struct Failure {
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
}

impl Failure {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Failure {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn core(message: impl Into<String>) -> Self {
        Self::new("core_error", message)
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

impl From<std::io::Error> for Failure {
    fn from(err: std::io::Error) -> Self {
        Failure::core(err.to_string())
    }
}

#[derive(Debug)]
pub(crate) enum ResourceError {
    Fetch(FetchError),
    Status(u16),
    Load(Box<RuleLoadError>),
    Other(String),
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceError::Fetch(err) => write!(f, "{err}"),
            ResourceError::Status(code) => {
                let reason = http::StatusCode::from_u16(*code)
                    .ok()
                    .and_then(|status| status.canonical_reason())
                    .unwrap_or("");
                write!(f, "{}", format!("{code} {reason}").trim_end())
            }
            ResourceError::Load(err) => write!(f, "{err}"),
            ResourceError::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ResourceError {}

/// Why a rule provider could not be set up or loaded.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RuleLoadError {
    #[error("rule provider {provider}: {source}: {path}")]
    Path {
        provider: String,
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Parse(#[from] RuleSetError),
    #[error(transparent)]
    Write(std::io::Error),
    #[error(transparent)]
    Pull(#[from] ResourceError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

impl RuleLoadError {
    pub(crate) fn path(def: &RuleProviderDef, path: &str) -> impl FnOnce(std::io::Error) -> Self {
        let (provider, path) = (def.name.clone(), path.to_string());
        move |source| RuleLoadError::Path {
            provider,
            path,
            source,
        }
    }
}

/// Why a geo file could not be fetched or refreshed. The text is what the resource event and
/// the apply failure report.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GeoUpdateError {
    #[error("can't download {what}: {source}")]
    Download { what: String, source: ResourceError },
    #[error("can't download {label} database file: no data")]
    NoData { label: &'static str },
    #[error("invalid {label} database file: {message}")]
    Invalid {
        label: &'static str,
        message: String,
    },
    #[error("can't save {label} database file: {source}")]
    Save {
        label: &'static str,
        source: WriteError,
    },
    #[error(transparent)]
    Write(#[from] WriteError),
    #[error(transparent)]
    Store(#[from] GeoError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WriteError {
    #[error("not initialized")]
    NotInitialized,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
