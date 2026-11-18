use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub message: String,
    pub line: Option<u32>,
}

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        ConfigError {
            message: message.into(),
            line: None,
        }
    }

    pub fn at(message: impl Into<String>, line: u32) -> Self {
        ConfigError {
            message: message.into(),
            line: Some(line),
        }
    }

    pub fn with_line(mut self, line: Option<u32>) -> Self {
        if self.line.is_none() {
            self.line = line;
        }
        self
    }

    pub fn prefixed(mut self, prefix: &str) -> Self {
        self.message = format!("{prefix}{}", self.message);
        self
    }

    /// Names the section unless the message already names one of its keys.
    pub fn within(self, section: &str) -> Self {
        let named = self.message.trim_start_matches('\'');
        if named.starts_with(&format!("{section}.")) || named.starts_with(&format!("{section}[")) {
            self
        } else {
            self.prefixed(&format!("{section}: "))
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> Self {
        ConfigError::new(err.to_string())
    }
}

pub type Result<T, E = ConfigError> = std::result::Result<T, E>;
