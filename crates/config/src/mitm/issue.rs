use std::fmt;

use serde::Serialize;

/// What is wrong with a line of the section, for a host that marks lines by kind; the
/// message says the rest to a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IssueKind {
    Syntax,
    Missing,
    Unknown,
    Unsupported,
    Invalid,
    Pattern,
    Jq,
    Resource,
    Script,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineError {
    pub kind: IssueKind,
    pub message: String,
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LineError {}

impl LineError {
    pub fn new(kind: IssueKind, message: impl Into<String>) -> LineError {
        LineError {
            kind,
            message: message.into(),
        }
    }

    pub fn syntax(message: impl Into<String>) -> LineError {
        LineError::new(IssueKind::Syntax, message)
    }

    pub fn missing(message: impl Into<String>) -> LineError {
        LineError::new(IssueKind::Missing, message)
    }

    pub fn unknown(message: impl Into<String>) -> LineError {
        LineError::new(IssueKind::Unknown, message)
    }

    pub fn unsupported(message: impl Into<String>) -> LineError {
        LineError::new(IssueKind::Unsupported, message)
    }

    pub fn invalid(message: impl Into<String>) -> LineError {
        LineError::new(IssueKind::Invalid, message)
    }

    pub fn resource(message: impl Into<String>) -> LineError {
        LineError::new(IssueKind::Resource, message)
    }

    /// The same error with `context` before its message, as `data: invalid base64`.
    pub fn within(self, context: &str) -> LineError {
        LineError::new(self.kind, format!("{context}: {}", self.message))
    }
}
