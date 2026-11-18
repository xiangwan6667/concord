use std::collections::HashMap;
use std::path::Path;

use http::StatusCode;
use http::header::{HeaderMap, HeaderName, HeaderValue};

use super::heads::HeadConditionsDef;
use super::issue::LineError;
use super::pattern::{check_multiline, check_pattern};
use super::text::{Field, canonical_header, decode_base64, quote, remainder, split_fields, texts};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlAction {
    Header,
    Redirect302,
    Redirect307,
    Reject,
    Reject200,
    RejectImg,
    RejectDict,
    RejectArray,
}

impl UrlAction {
    fn named(text: &str) -> Option<UrlAction> {
        Some(match text {
            "header" => UrlAction::Header,
            "302" => UrlAction::Redirect302,
            "307" => UrlAction::Redirect307,
            "reject" => UrlAction::Reject,
            "reject-200" => UrlAction::Reject200,
            "reject-img" | "reject-tinygif" => UrlAction::RejectImg,
            "reject-dict" => UrlAction::RejectDict,
            "reject-array" => UrlAction::RejectArray,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            UrlAction::Header => "header",
            UrlAction::Redirect302 => "302",
            UrlAction::Redirect307 => "307",
            UrlAction::Reject => "reject",
            UrlAction::Reject200 => "reject-200",
            UrlAction::RejectImg => "reject-img",
            UrlAction::RejectDict => "reject-dict",
            UrlAction::RejectArray => "reject-array",
        }
    }

    pub fn rejects(self) -> bool {
        matches!(
            self,
            UrlAction::Reject
                | UrlAction::Reject200
                | UrlAction::RejectImg
                | UrlAction::RejectDict
                | UrlAction::RejectArray
        )
    }
}

/// A `url-rewrite` line; its patterns are regexes that compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlRewriteDef {
    pub pattern: String,
    /// Quantumult X's `url-and-header`: matched against the request head once the URL matches.
    pub head: Option<String>,
    pub replacement: String,
    pub action: UrlAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderEditDef {
    Add(HeaderName, HeaderValue),
    Del(HeaderName),
    Replace(HeaderName, HeaderValue),
    ReplaceRegex(HeaderName, String, String),
    /// Quantumult X's `request-header` and `response-header`: a replacement over the whole
    /// head, its first line included.
    Text(String, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRewriteDef {
    pub response: bool,
    pub pattern: String,
    pub conditions: HeadConditionsDef,
    pub edit: HeaderEditDef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyActionDef {
    /// Regexes over the body, multiline, each with its replacement.
    Replace(Vec<(String, String)>),
    /// A jq expression, compiled where the rule runs.
    Jq(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyRewriteDef {
    pub response: bool,
    pub pattern: String,
    pub conditions: HeadConditionsDef,
    pub action: BodyActionDef,
}

/// Where a `map-local` answer's body comes from: the line's `data` as text, a decoded
/// base64 one, a file of that name in the resources directory, or the 1x1 GIF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapLocalBody {
    Text,
    TinyGif,
    Base64(Vec<u8>),
    File,
}

impl MapLocalBody {
    pub fn data_type(&self) -> &'static str {
        match self {
            MapLocalBody::Text => "text",
            MapLocalBody::TinyGif => "tiny-gif",
            MapLocalBody::Base64(_) => "base64",
            MapLocalBody::File => "file",
        }
    }
}

/// A `map-local` line, or with `request` a `request-body-mock` one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapLocalDef {
    pub pattern: String,
    pub conditions: HeadConditionsDef,
    pub body: MapLocalBody,
    pub data: String,
    pub status: StatusCode,
    /// The headers the line gives; `content_type` applies when they name none.
    pub header: HeaderMap,
    pub content_type: &'static str,
    pub request: bool,
}

pub fn parse_url_rewrite(line: &str) -> Result<UrlRewriteDef, LineError> {
    let fields = split_fields(line)?;
    if fields.len() < 2 {
        return Err(LineError::syntax(
            "expected a pattern and a replacement or type",
        ));
    }
    let conditional = fields
        .get(2)
        .is_some_and(|field| field.text.eq_ignore_ascii_case("url-and-header"));
    let (head, first_arg) = if conditional {
        let head = field_text(&fields, 1);
        check_pattern(&head)?;
        (Some(head), 3)
    } else {
        (None, 1)
    };
    let args = texts(fields.get(first_arg..).unwrap_or_default());
    if args.is_empty() {
        return Err(LineError::missing("url-and-header needs a type"));
    }
    let first = args.first().copied().unwrap_or_default();
    let mut action = UrlAction::Header;
    let mut replacement = String::new();
    match args.len() {
        _ if first == "url" && args.len() >= 2 => {
            action = url_action_of(args.get(1).copied().unwrap_or_default())?;
            if let Some(third) = args.get(2) {
                replacement = (*third).to_string();
            }
        }
        1 => match UrlAction::named(first) {
            Some(named) if named.rejects() => action = named,
            _ => replacement = first.to_string(),
        },
        2 => {
            let second = args.get(1).copied().unwrap_or_default();
            if let Some(named) = UrlAction::named(second) {
                (replacement, action) = (first.to_string(), named);
            } else if let Some(named) = UrlAction::named(first) {
                (action, replacement) = (named, second.to_string());
            } else {
                return Err(LineError::unknown(format!(
                    "unknown type {}",
                    quote(second)
                )));
            }
        }
        _ => return Err(LineError::syntax("too many fields")),
    }
    if action.rejects() {
        replacement.clear();
    } else if replacement.is_empty() || replacement == "_" {
        return Err(LineError::missing(format!(
            "{} needs a replacement URL",
            action.name()
        )));
    }
    let pattern = field_text(&fields, 0);
    check_pattern(&pattern)?;
    Ok(UrlRewriteDef {
        pattern,
        head,
        replacement,
        action,
    })
}

fn field_text(fields: &[Field], at: usize) -> String {
    fields
        .get(at)
        .map(|field| field.text.clone())
        .unwrap_or_default()
}

fn checked(fields: &[Field], at: usize) -> Result<String, LineError> {
    let pattern = field_text(fields, at);
    check_pattern(&pattern)?;
    Ok(pattern)
}

fn url_action_of(text: &str) -> Result<UrlAction, LineError> {
    UrlAction::named(text)
        .ok_or_else(|| LineError::unknown(format!("unknown type {}", quote(text))))
}

pub fn parse_header_rewrite(line: &str) -> Result<HeaderRewriteDef, LineError> {
    let mut fields = split_fields(line)?;
    let mut response = false;
    if let Some(first) = fields.first() {
        match first.text.to_ascii_lowercase().as_str() {
            "http-response" => {
                response = true;
                fields.remove(0);
            }
            "http-request" => {
                fields.remove(0);
            }
            _ => {}
        }
    }
    let (conditions, at) = HeadConditionsDef::read(&fields, response, 1)?;
    let action_text = field_text(&fields, at).to_ascii_lowercase();
    let rest = fields.get(at + 1..).unwrap_or_default();
    if action_text == "header-text-replace" {
        if rest.len() != 2 {
            return Err(LineError::syntax(
                "header-text-replace needs a pattern and a replacement",
            ));
        }
        return Ok(HeaderRewriteDef {
            response,
            pattern: checked(&fields, 0)?,
            conditions,
            edit: HeaderEditDef::Text(checked(rest, 0)?, field_text(rest, 1)),
        });
    }
    let Some(name_field) = rest.first() else {
        return Err(LineError::syntax(
            "expected a pattern, an action and a header name",
        ));
    };
    let name_text = canonical_header(&name_field.text);
    if matches!(name_text.as_str(), "Content-Length" | "Transfer-Encoding") {
        return Err(LineError::unsupported(format!(
            "{name_text} frames the message and cannot be rewritten"
        )));
    }
    let name = HeaderName::from_bytes(name_text.as_bytes())
        .map_err(|_| LineError::invalid(format!("invalid header name {}", quote(&name_text))))?;
    let args = rest.get(1..).unwrap_or_default();
    let value = || {
        let text = remainder(line, name_field);
        HeaderValue::from_str(&text)
            .map_err(|_| LineError::invalid(format!("invalid header value {}", quote(&text))))
    };
    let edit = match action_text.as_str() {
        "header-add" => HeaderEditDef::Add(name, value()?),
        "header-replace" => HeaderEditDef::Replace(name, value()?),
        "header-del" => HeaderEditDef::Del(name),
        "header-replace-regex" => {
            if args.len() < 2 {
                return Err(LineError::syntax(
                    "header-replace-regex needs a pattern and a replacement",
                ));
            }
            HeaderEditDef::ReplaceRegex(name, checked(args, 0)?, field_text(args, 1))
        }
        _ => {
            return Err(LineError::unknown(format!(
                "unknown action {}",
                quote(&field_text(&fields, at))
            )));
        }
    };
    Ok(HeaderRewriteDef {
        response,
        pattern: checked(&fields, 0)?,
        conditions,
        edit,
    })
}

pub fn parse_body_rewrite(line: &str) -> Result<BodyRewriteDef, LineError> {
    let kind = line.split_whitespace().next().unwrap_or_default();
    let jq_response = match kind.to_ascii_lowercase().as_str() {
        "http-request-jq" => Some(false),
        "http-response-jq" => Some(true),
        _ => None,
    };
    if let Some(response) = jq_response {
        let rest = line.trim_start().get(kind.len()..).unwrap_or_default();
        let (pattern, mut expression) =
            leading_field(rest).ok_or_else(|| LineError::syntax("unclosed quote"))?;
        let mut conditions = HeadConditionsDef::default();
        while let Some((keyword, after)) = leading_field(expression)
            && let Some((condition, after)) = leading_field(after)
            && conditions.set(&keyword, Some(&condition), response)?
        {
            expression = after;
        }
        let expression = unwrap_quotes(expression.trim());
        if pattern.is_empty() || expression.is_empty() {
            return Err(LineError::syntax("expected a pattern and a jq expression"));
        }
        check_pattern(&pattern)?;
        return Ok(BodyRewriteDef {
            response,
            pattern,
            conditions,
            action: BodyActionDef::Jq(expression.to_string()),
        });
    }
    let fields = split_fields(line)?;
    if fields.len() < 4 {
        return Err(LineError::syntax(
            "expected a type, a pattern and a regex with its replacement",
        ));
    }
    let first = field_text(&fields, 0);
    let response = match first.to_ascii_lowercase().as_str() {
        "http-request" => false,
        "http-response" => true,
        _ => {
            return Err(LineError::unknown(format!(
                "unknown type {}",
                quote(&first)
            )));
        }
    };
    let (conditions, at) = HeadConditionsDef::read(&fields, response, 2)?;
    let pairs = fields.get(at..).unwrap_or_default();
    if pairs.is_empty() {
        return Err(LineError::syntax("expected a regex with its replacement"));
    }
    if pairs.len() % 2 != 0 {
        return Err(LineError::syntax("a regex is missing its replacement"));
    }
    let mut replacements = Vec::new();
    for pair in pairs.chunks(2) {
        let pattern = field_text(pair, 0);
        check_multiline(&pattern)?;
        replacements.push((pattern, field_text(pair, 1)));
    }
    Ok(BodyRewriteDef {
        response,
        pattern: checked(&fields, 1)?,
        conditions,
        action: BodyActionDef::Replace(replacements),
    })
}

/// The pattern of a jq line, and the expression after it as written: its own quotes and
/// spaces are jq's, not the line's.
fn leading_field(text: &str) -> Option<(String, &str)> {
    let text = text.trim_start();
    let Some(quoted) = text.strip_prefix('"') else {
        let end = text.find([' ', '\t']).unwrap_or(text.len());
        return Some((
            text.get(..end).unwrap_or_default().to_string(),
            text.get(end..).unwrap_or_default(),
        ));
    };
    let mut out = String::new();
    let mut chars = quoted.char_indices();
    while let Some((at, c)) = chars.next() {
        let after = quoted.get(at + 1..).unwrap_or_default();
        match c {
            '\\' if after.starts_with('"') => {
                out.push('"');
                chars.next();
            }
            '"' => return Some((out, after)),
            c => out.push(c),
        }
    }
    None
}

fn unwrap_quotes(text: &str) -> &str {
    for mark in ['\'', '"'] {
        if text.len() >= 2 && text.starts_with(mark) && text.ends_with(mark) {
            return text.get(1..text.len() - 1).unwrap_or_default();
        }
    }
    text
}

fn mime_by_extension(name: &str) -> Option<&'static str> {
    let ext = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "avif" => "image/avif",
        "css" => "text/css; charset=utf-8",
        "gif" => "image/gif",
        "htm" | "html" => "text/html; charset=utf-8",
        "jpeg" | "jpg" => "image/jpeg",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "wasm" => "application/wasm",
        "webp" => "image/webp",
        "xml" => "text/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        _ => return None,
    })
}

/// A `map-local` line, or with `request` a `request-body-mock` one, which takes the same
/// parameters but no status, as it answers nothing.
pub fn parse_map_local(line: &str, request: bool) -> Result<MapLocalDef, LineError> {
    let fields = split_fields(line)?;
    let (conditions, at) = HeadConditionsDef::read(&fields, false, 1)?;
    let args = fields.get(at..).unwrap_or_default();
    if args.is_empty() {
        return Err(LineError::syntax(
            "expected a pattern and the data to answer with",
        ));
    }
    let mut params = HashMap::new();
    for field in args {
        let (key, value) = field.text.split_once('=').ok_or_else(|| {
            LineError::syntax(format!("expected key=value, got {}", quote(&field.text)))
        })?;
        params.insert(key.to_ascii_lowercase(), value.to_string());
    }
    let get = |key: &str| params.get(key).map(String::as_str).unwrap_or_default();
    let data = get("data");
    let (body, content_type) = match get("data-type") {
        "text" => (MapLocalBody::Text, "text/plain; charset=utf-8"),
        "tiny-gif" => (MapLocalBody::TinyGif, "image/gif"),
        "base64" => (
            MapLocalBody::Base64(decode_base64(data).map_err(|err| err.within("data"))?),
            "application/octet-stream",
        ),
        "" | "file" => (
            MapLocalBody::File,
            mime_by_extension(data).unwrap_or("application/octet-stream"),
        ),
        other => {
            return Err(LineError::unknown(format!(
                "unknown data-type {}",
                quote(other)
            )));
        }
    };
    let mut status = StatusCode::OK;
    if request && params.contains_key("status-code") {
        return Err(LineError::unsupported(
            "a request body mock answers nothing, so it takes no status-code",
        ));
    }
    if let Some(text) = params.get("status-code") {
        status = text
            .parse::<u16>()
            .ok()
            .filter(|code| (200..=999).contains(code))
            .and_then(|code| StatusCode::from_u16(code).ok())
            .ok_or_else(|| LineError::invalid(format!("invalid status-code {}", quote(text))))?;
    }
    let mut header = HeaderMap::new();
    let header_text = get("header");
    if !header_text.is_empty() {
        parse_map_local_header(header_text, &mut header)?;
    }
    Ok(MapLocalDef {
        pattern: checked(&fields, 0)?,
        conditions,
        body,
        data: data.to_string(),
        status,
        header,
        content_type,
        request,
    })
}

fn parse_map_local_header(text: &str, header: &mut HeaderMap) -> Result<(), LineError> {
    let decoded;
    let (text, separator) = if text.contains(':') {
        (text, '|')
    } else {
        let bytes = decode_base64(text).map_err(|err| err.within("header"))?;
        decoded = String::from_utf8_lossy(&bytes).into_owned();
        (decoded.as_str(), '\n')
    };
    for line in text.split(separator) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| LineError::syntax(format!("header {} has no value", quote(line))))?;
        let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| {
            LineError::invalid(format!("invalid header name {}", quote(name.trim())))
        })?;
        let value = HeaderValue::from_str(value.trim()).map_err(|_| {
            LineError::invalid(format!("invalid header value {}", quote(value.trim())))
        })?;
        header.append(name, value);
    }
    Ok(())
}
