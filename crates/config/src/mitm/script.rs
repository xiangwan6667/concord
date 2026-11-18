use std::collections::HashMap;
use std::path::Path;

use super::heads::{HeadConditionsDef, REQUEST_HEAD, RESPONSE_HEAD};
use super::issue::LineError;
use super::pattern::check_pattern;
use super::text::{quote, split_fields};

pub const EVENT_NETWORK_CHANGED: &str = "network-changed";
pub const EVENT_ENGINE_STARTED: &str = "engine-started";
pub const EVENT_PROFILE_RELOADED: &str = "profile-reloaded";
const LOON_NETWORK_CHANGED: &str = "network-changed";

const SCRIPT_TYPES: &[&str] = &[
    "http-request",
    "http-response",
    "cron",
    "event",
    "generic",
    "dns",
    "rule",
    LOON_NETWORK_CHANGED,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptKind {
    HttpRequest,
    HttpResponse,
    Cron,
    Event,
    Generic,
}

impl ScriptKind {
    pub fn name(self) -> &'static str {
        match self {
            ScriptKind::HttpRequest => "http-request",
            ScriptKind::HttpResponse => "http-response",
            ScriptKind::Cron => "cron",
            ScriptKind::Event => "event",
            ScriptKind::Generic => "generic",
        }
    }

    pub fn is_task(self) -> bool {
        matches!(
            self,
            ScriptKind::Cron | ScriptKind::Event | ScriptKind::Generic
        )
    }
}

/// A `script` line; the file at `path` in the resources directory and the cron expression
/// are read where the script runs.
#[derive(Clone, Debug, PartialEq)]
pub struct ScriptDef {
    pub name: String,
    pub path: String,
    pub kind: ScriptKind,
    pub pattern: Option<String>,
    pub conditions: HeadConditionsDef,
    pub requires_body: bool,
    pub binary_body: bool,
    pub max_size: i64,
    pub cronexp: String,
    pub event: String,
    /// Seconds as written, positive and finite; the caller caps them for the kind.
    pub timeout: Option<f64>,
    pub argument: Option<serde_json::Value>,
}

type Params = HashMap<String, String>;

/// Reads Surge's line and Loon's legacy one.
pub fn parse_script(line: &str) -> Result<ScriptDef, LineError> {
    let (name, kind, params) = split_script_line(line)?;
    let param = |key: &str| params.get(key).cloned().unwrap_or_default();
    let kind = match kind.as_str() {
        "http-request" => ScriptKind::HttpRequest,
        "http-response" => ScriptKind::HttpResponse,
        "cron" => ScriptKind::Cron,
        "event" => ScriptKind::Event,
        "generic" => ScriptKind::Generic,
        other if SCRIPT_TYPES.contains(&other) => {
            return Err(LineError::unsupported(format!(
                "{other} scripts are not supported"
            )));
        }
        other => return Err(LineError::unknown(format!("unknown type {}", quote(other)))),
    };
    let path = param("script-path");
    if path.is_empty() {
        return Err(LineError::missing("script-path is missing"));
    }
    let name = if name.is_empty() {
        Path::new(&path)
            .file_name()
            .map(|base| base.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone())
    } else {
        name
    };
    let mut script = ScriptDef {
        name,
        path,
        kind,
        pattern: None,
        conditions: HeadConditionsDef::default(),
        requires_body: false,
        binary_body: false,
        max_size: 0,
        cronexp: String::new(),
        event: String::new(),
        timeout: None,
        argument: None,
    };
    match kind {
        ScriptKind::HttpRequest | ScriptKind::HttpResponse => {
            script.read_http(&params, kind == ScriptKind::HttpResponse)?
        }
        ScriptKind::Cron => {
            script.cronexp = param("cronexp");
            if script.cronexp.is_empty() {
                return Err(LineError::missing("cronexp is missing"));
            }
        }
        ScriptKind::Event => {
            script.event = param("event-name");
            match script.event.as_str() {
                EVENT_NETWORK_CHANGED | EVENT_ENGINE_STARTED | EVENT_PROFILE_RELOADED => {}
                "" => return Err(LineError::missing("event-name is missing")),
                other => {
                    return Err(LineError::unsupported(format!(
                        "the {other} event is not supported"
                    )));
                }
            }
        }
        ScriptKind::Generic => {}
    }
    if let Some(text) = params.get("timeout") {
        let seconds = text
            .parse::<f64>()
            .ok()
            .filter(|seconds| *seconds > 0.0 && seconds.is_finite())
            .ok_or_else(|| LineError::invalid(format!("invalid timeout {}", quote(text))))?;
        script.timeout = Some(seconds);
    }
    if let Some(text) = params.get("argument-json") {
        let value = serde_json::from_str(text)
            .map_err(|err| LineError::invalid(format!("argument-json: {err}")))?;
        script.argument = Some(value);
    } else if let Some(text) = params.get("argument") {
        script.argument = Some(serde_json::Value::String(text.clone()));
    }
    Ok(script)
}

impl ScriptDef {
    fn read_http(&mut self, params: &Params, response: bool) -> Result<(), LineError> {
        let pattern = params.get("pattern").cloned().unwrap_or_default();
        if pattern.is_empty() {
            return Err(LineError::missing("pattern is missing"));
        }
        for keyword in [REQUEST_HEAD, RESPONSE_HEAD] {
            if let Some(condition) = params.get(keyword) {
                self.conditions.set(keyword, Some(condition), response)?;
            }
        }
        self.requires_body = script_bool(params, "requires-body")?;
        self.binary_body = script_bool(params, "binary-body-mode")?;
        if script_bool(params, "full-header-mode").unwrap_or(true) {
            return Err(LineError::unsupported("full-header-mode is not supported"));
        }
        if let Some(text) = params.get("max-size") {
            let size = text
                .parse::<i64>()
                .ok()
                .filter(|size| *size >= -1)
                .ok_or_else(|| LineError::invalid(format!("invalid max-size {}", quote(text))))?;
            if size > 0 {
                self.max_size = size;
            }
        }
        check_pattern(&pattern)?;
        self.pattern = Some(pattern);
        Ok(())
    }
}

/// A line with a type parameter is Surge's form, so that a name may start with
/// a type; any other is Loon's legacy one.
fn split_script_line(line: &str) -> Result<(String, String, Params), LineError> {
    let (name, rest) = match line.split_once('=') {
        Some((name, rest)) => (Some(name), Some(rest)),
        None => (None, None),
    };
    let parsed = rest.map(script_params);
    let typed =
        matches!(&parsed, Some(Ok(params)) if params.get("type").is_some_and(|t| !t.is_empty()));
    if !typed && let Some(at) = line.find([' ', '\t']).filter(|at| *at > 0) {
        let head = line.get(..at).unwrap_or_default().to_ascii_lowercase();
        if SCRIPT_TYPES.contains(&head.as_str()) {
            return split_legacy_script(&head, line.get(at..).unwrap_or_default());
        }
    }
    let (Some(name), Some(parsed)) = (name, parsed) else {
        return Err(LineError::syntax("expected name = parameters"));
    };
    let params = parsed?;
    let mut kind = params
        .get("type")
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if kind.is_empty() {
        kind = "generic".to_string();
    }
    Ok((name.trim().to_string(), kind, params))
}

/// Files the value after the type where Surge's form keeps it.
fn split_legacy_script(kind: &str, rest: &str) -> Result<(String, String, Params), LineError> {
    let fields = split_fields(rest)?;
    let mut value = String::new();
    let mut from = 0;
    if let Some(first) = fields.first() {
        let http = kind == "http-request" || kind == "http-response";
        if http || !first.text.contains('=') {
            value = first.text.clone();
            from = first.to;
        }
    }
    let mut params = script_params(rest.get(from..).unwrap_or_default())?;
    let mut name = params.get("tag").cloned().unwrap_or_default();
    let mut kind = kind.to_string();
    match kind.as_str() {
        "http-request" | "http-response" => {
            if value.is_empty() {
                return Err(LineError::missing("expected a pattern"));
            }
            params.insert("pattern".to_string(), value);
        }
        "cron" => {
            params.insert("cronexp".to_string(), value);
        }
        "event" => {
            params.insert("event-name".to_string(), value);
        }
        LOON_NETWORK_CHANGED => {
            kind = "event".to_string();
            params.insert("event-name".to_string(), EVENT_NETWORK_CHANGED.to_string());
        }
        _ => {
            if name.is_empty() {
                name = value;
            }
        }
    }
    Ok((name, kind, params))
}

/// Splits on the commas outside quotes, groups and character classes, so an
/// unquoted `{1,3}` or Loon's `argument=[{a},{b}]` stays one value.
fn script_params(text: &str) -> Result<Params, LineError> {
    let mut params = Params::new();
    let mut add = |item: &str| -> Result<(), LineError> {
        let item = item.trim();
        if item.is_empty() {
            return Ok(());
        }
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| LineError::syntax(format!("expected key=value, got {}", quote(item))))?;
        let mut value = value.trim().to_string();
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            value = value
                .get(1..value.len() - 1)
                .unwrap_or_default()
                .replace("\\\"", "\"");
        }
        params.insert(key.trim().to_ascii_lowercase(), value);
        Ok(())
    };
    let bytes = text.as_bytes();
    let (mut quoted, mut class, mut depth, mut from) = (false, false, 0usize, 0usize);
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if quoted {
            if c == b'\\' && bytes.get(i + 1) == Some(&b'"') {
                i += 1;
            } else if c == b'"' {
                quoted = false;
            }
        } else if c == b'\\' {
            i += 1;
        } else if c == b'"' {
            quoted = true;
        } else if class {
            class = c != b']';
        } else if c == b'[' {
            class = true;
        } else if c == b'(' || c == b'{' {
            depth += 1;
        } else if (c == b')' || c == b'}') && depth > 0 {
            depth -= 1;
        } else if c == b',' && depth == 0 {
            add(text.get(from..i).unwrap_or_default())?;
            from = i + 1;
        }
        i += 1;
    }
    if quoted {
        return Err(LineError::syntax("unclosed quote"));
    }
    add(text.get(from.min(text.len())..).unwrap_or_default())?;
    Ok(params)
}

fn script_bool(params: &Params, key: &str) -> Result<bool, LineError> {
    let Some(text) = params.get(key) else {
        return Ok(false);
    };
    match text.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" | "" => Ok(false),
        _ => Err(LineError::invalid(format!("invalid {key} {}", quote(text)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_params_keep_what_they_quote() {
        let params = script_params(
            r#"pattern="^https://a\.com/\"q\",x",argument=[{a},{b}],max=\d{1,3},class=[,],json="{\"k\":\"a\\"b\"}""#,
        )
        .unwrap();
        for (key, want) in [
            ("pattern", r#"^https://a\.com/"q",x"#),
            ("argument", "[{a},{b}]"),
            ("max", r"\d{1,3}"),
            ("class", "[,]"),
            ("json", r#"{"k":"a\"b"}"#),
        ] {
            assert_eq!(params.get(key).map(String::as_str), Some(want), "{key}");
        }
    }
}
