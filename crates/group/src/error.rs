use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("{0}")]
    Config(#[from] concord_config::ConfigError),
    #[error("loop is detected in ProxyGroup, please check following ProxyGroups: {0:?}")]
    Cycle(Vec<String>),
    #[error("{group}: `use` or `proxies` missing")]
    MissingMembers { group: String },
    #[error("{group}: '{name}' not found")]
    NotFound { group: String, name: String },
    #[error("{0} cannot be dialed")]
    CannotDial(String),
    #[error("{group}: empty fallback proxy '{name}' not found")]
    EmptyFallback { group: String, name: String },
    #[error("proxy group {0}: the duplicate name")]
    Duplicate(String),
    #[error("{group}: duplicate provider name")]
    DuplicateProvider { group: String },
    #[error("parse proxy provider {provider} error: {message}")]
    Provider { provider: String, message: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchErrorKind {
    Tls,
    Dns,
    Timeout,
    Connection,
    Other,
}

#[derive(Clone, Debug)]
pub struct FetchError {
    pub kind: FetchErrorKind,
    pub message: String,
}

impl FetchError {
    pub fn new(kind: FetchErrorKind, message: impl Into<String>) -> Self {
        FetchError {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FetchError {}

/// `Status` carries the text mihomo builds with `errors.New(resp.Status)`,
/// whose leading three digits the host parses.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("{0}")]
    Status(String),
    #[error("{0}")]
    Fetch(FetchError),
    #[error("{0}")]
    Content(String),
    #[error("{0}")]
    Io(String),
    #[error("external provider does not exist")]
    NotFound,
    #[error("external provider is updating")]
    Updating,
}

impl ProviderError {
    pub fn status_code(&self) -> Option<u16> {
        match self {
            ProviderError::Status(text) => text.get(..3)?.parse().ok(),
            _ => None,
        }
    }

    pub fn status(code: u16) -> Self {
        let reason = http::StatusCode::from_u16(code)
            .ok()
            .and_then(|status| status.canonical_reason())
            .unwrap_or("");
        ProviderError::Status(format!("{code} {reason}").trim_end().to_string())
    }
}
