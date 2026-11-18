use fancy_regex::Regex;

use super::issue::{IssueKind, LineError};

/// Compiles a line's regex to check it and drops it: the rule that runs it compiles its own.
pub fn check_pattern(pattern: &str) -> Result<(), LineError> {
    compile(pattern)
}

/// The flag a body regex is compiled with, so that it matches line by line.
pub const MULTILINE: &str = "(?m)";

pub fn multiline(pattern: &str) -> String {
    format!("{MULTILINE}{pattern}")
}

/// As [check_pattern] for a body regex.
pub fn check_multiline(pattern: &str) -> Result<(), LineError> {
    compile(&multiline(pattern))
}

fn compile(source: &str) -> Result<(), LineError> {
    Regex::new(source)
        .map(drop)
        .map_err(|err| LineError::new(IssueKind::Pattern, err.to_string()))
}
