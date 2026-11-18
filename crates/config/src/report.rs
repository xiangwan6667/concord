use serde::Serialize;

use crate::lenient::Ignored;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub level: Level,
    /// Stable across releases, unlike `message`.
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LoadReport {
    pub warnings: Vec<Warning>,
}

impl LoadReport {
    pub fn warn_ignored(&mut self, prefix: &str, notes: &[Ignored]) {
        for note in notes {
            self.warn(note.code, format!("{prefix}{}", note.key), note.to_string());
        }
    }

    pub fn warn(
        &mut self,
        code: &'static str,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.push(Level::Warning, code, path, message);
    }

    pub fn info(
        &mut self,
        code: &'static str,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.push(Level::Info, code, path, message);
    }

    pub fn push(
        &mut self,
        level: Level,
        code: &'static str,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.warnings.push(Warning {
            level,
            code,
            path: path.into(),
            message: message.into(),
        });
    }

    pub fn extend(&mut self, other: LoadReport) {
        self.warnings.extend(other.warnings);
    }

    pub fn has_warnings(&self) -> bool {
        self.warnings.iter().any(|w| w.level == Level::Warning)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Array(Vec::new()))
    }
}
