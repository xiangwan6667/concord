use std::collections::{BTreeMap, HashMap, HashSet};

use granit_parser::{Event, Options, Parser, ScalarStyle, Tag};
use serde_json::{Number, Value};

use crate::Map;
use crate::error::{ConfigError, Result};
use crate::rule::RuleLines;

/// go-yaml's alias guard, which mihomo decodes profiles with: past 100 aliased and 1000 decoded
/// nodes, the aliased share may not exceed 99% up to the low count, 10% from the high one.
const ALIAS_RATIO_LOW: usize = 400_000;
const ALIAS_RATIO_HIGH: usize = 4_000_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceLines {
    pub proxies: Vec<u32>,
    pub proxy_groups: Vec<u32>,
    pub rules: Vec<u32>,
    /// By list name, the lines of the `mitm` section's list items.
    pub mitm: BTreeMap<String, Vec<u32>>,
}

#[derive(Debug, Default)]
pub struct ParsedDocument {
    pub root: Map,
    pub lines: SourceLines,
    /// The top-level `rules` when the line scanner could read them; `root` then has none.
    pub rules: Option<RuleLines>,
    /// Top-level keys whose value carries an anchor.
    pub anchored: HashSet<String>,
}

pub fn parse_document(text: &str) -> Result<ParsedDocument> {
    if u32::try_from(text.len()).is_err() {
        return Err(ConfigError::new("the profile is larger than 4 GiB"));
    }
    match scan_rules(text) {
        Some(scan) => {
            let stripped = scan.strip(text);
            let mut parsed = build(&stripped, scan.lines.len())?;
            parsed.lines.rules = scan.lines;
            parsed.rules = Some(scan.rules);
            Ok(parsed)
        }
        None => build(text, 0),
    }
}

pub fn parse_document_slow(text: &str) -> Result<ParsedDocument> {
    build(text, 0)
}

struct RulesScan {
    rules: RuleLines,
    lines: Vec<u32>,
    byte_start: usize,
    byte_end: usize,
    line_count: usize,
}

impl RulesScan {
    fn strip(&self, text: &str) -> String {
        let before = text.get(..self.byte_start).unwrap_or_default();
        let after = text.get(self.byte_end..).unwrap_or_default();
        let mut out = String::with_capacity(before.len() + after.len() + self.line_count);
        out.push_str(before);
        out.extend(std::iter::repeat_n('\n', self.line_count));
        out.push_str(after);
        out
    }
}

fn is_rules_header(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("rules:") else {
        return false;
    };
    let rest = rest.trim_matches([' ', '\t', '\r', '\n']);
    rest.is_empty() || rest.starts_with('#')
}

fn plain_item(content: &str) -> Option<&str> {
    let mut text = content;
    if let Some(at) = text.find(" #") {
        text = text.get(..at)?;
    }
    let text = text.trim_matches([' ', '\t', '\r']);
    let first = text.chars().next()?;
    if "\"'[]{}&*!|>%@`#?:,-".contains(first) || text == "~" || text == "null" {
        return None;
    }
    if text.contains(": ") || text.ends_with(':') || text.contains(" #") || text.contains('\t') {
        return None;
    }
    Some(text)
}

fn scan_rules(text: &str) -> Option<RulesScan> {
    let mut offset = 0usize;
    let mut header: Option<(usize, usize)> = None;
    let mut count = 0usize;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        if line.starts_with("rules:") {
            count += 1;
            if count > 1 || !is_rules_header(line) {
                return None;
            }
            header = Some((offset, index));
        }
        offset += line.len();
    }
    let (byte_start, header_line) = header?;
    let mut rules = RuleLines::with_text_capacity(text.len() - byte_start);
    let mut lines = Vec::new();
    let mut indent: Option<usize> = None;
    let mut end = byte_start;
    let mut line_count = 0usize;
    for (index, line) in text.get(byte_start..)?.split_inclusive('\n').enumerate() {
        let body = line.trim_end_matches(['\n', '\r']);
        let trimmed = body.trim_start_matches([' ', '\t']);
        let blank = index == 0 || trimmed.is_empty() || trimmed.starts_with('#');
        if !blank {
            let depth = body.len() - trimmed.len();
            let is_item = trimmed == "-" || trimmed.starts_with("- ") || trimmed.starts_with("-\t");
            if depth == 0 && !is_item {
                break;
            }
            if !is_item || body.starts_with('\t') {
                return None;
            }
            match indent {
                None => indent = Some(depth),
                Some(expected) if expected != depth => return None,
                _ => {}
            }
            let content = trimmed.get(1..)?.trim_start_matches([' ', '\t']);
            rules.push(plain_item(content)?);
            lines.push(u32::try_from(header_line + index + 1).ok()?);
        }
        end += line.len();
        line_count += 1;
    }
    rules.shrink_to_fit();
    Some(RulesScan {
        rules,
        lines,
        byte_start,
        byte_end: end,
        line_count,
    })
}

enum Frame {
    Seq {
        items: Vec<Value>,
        anchor: usize,
        text: bool,
    },
    Map {
        map: Map,
        key: Option<String>,
        merging: bool,
        merges: Vec<Value>,
        anchor: usize,
        text: bool,
    },
}

struct Builder {
    frames: Vec<Frame>,
    anchors: HashMap<usize, Value>,
    anchored: HashSet<String>,
    decoded: usize,
    aliased: usize,
    root: Option<Value>,
    lines: SourceLines,
}

fn error_at(message: impl Into<String>, line: usize) -> ConfigError {
    let line = u32::try_from(line).unwrap_or(u32::MAX);
    ConfigError::at(format!("yaml: line {line}: {}", message.into()), line)
}

/// `decoded` counts the nodes already read outside the parser, such as the scanned rules.
fn build(text: &str, decoded: usize) -> Result<ParsedDocument> {
    let mut options = Options::default();
    options.emit_comments = false;
    let mut builder = Builder {
        frames: Vec::new(),
        anchors: HashMap::new(),
        anchored: HashSet::new(),
        decoded,
        aliased: 0,
        root: None,
        lines: SourceLines::default(),
    };
    let mut documents = 0;
    for event in Parser::new_from_str_with_options(text, options) {
        let (event, span) = event.map_err(|err| {
            let line = err.marker().line();
            error_at(err.info(), line)
        })?;
        let line = span.start.line();
        match event {
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    break;
                }
            }
            Event::Scalar(value, style, anchor, tag) => {
                builder.decoded += 1;
                builder.scalar(&value, style, anchor, tag.as_deref(), line)?;
            }
            Event::SequenceStart(_, anchor, _) => {
                builder.decoded += 1;
                builder.record_line(line);
                let text = builder.child_text();
                builder.frames.push(Frame::Seq {
                    items: Vec::new(),
                    anchor,
                    text,
                });
            }
            Event::MappingStart(_, anchor, _) => {
                builder.decoded += 1;
                builder.record_line(line);
                let text = builder.child_text();
                builder.frames.push(Frame::Map {
                    map: Map::new(),
                    key: None,
                    merging: false,
                    merges: Vec::new(),
                    anchor,
                    text,
                });
            }
            Event::SequenceEnd => {
                if let Some(Frame::Seq { items, anchor, .. }) = builder.frames.pop() {
                    builder.finish(Value::Array(items), anchor, line)?;
                }
            }
            Event::MappingEnd => {
                if let Some(Frame::Map {
                    mut map,
                    anchor,
                    merges,
                    ..
                }) = builder.frames.pop()
                {
                    merge_into(&mut map, merges);
                    builder.finish(Value::Object(map), anchor, line)?;
                }
            }
            Event::Alias(id) => {
                builder.record_line(line);
                let nodes = builder
                    .anchors
                    .get(&id)
                    .map(count_nodes)
                    .ok_or_else(|| error_at("unknown anchor referenced", line))?;
                builder.charge(nodes, line)?;
                let value = builder.anchors.get(&id).cloned().unwrap_or_default();
                builder.finish(value, 0, line)?;
            }
            _ => {}
        }
    }
    let mut parsed = ParsedDocument::default();
    match builder.root.take() {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => parsed.root = map,
        Some(_) => {
            return Err(ConfigError::at(
                "yaml: unmarshal errors: line 1: cannot unmarshal a non-mapping node into config.RawConfig",
                1,
            ));
        }
    }
    parsed.lines = builder.lines;
    parsed.anchored = builder.anchored;
    Ok(parsed)
}

fn merge_into(map: &mut Map, merges: Vec<Value>) {
    for source in merges {
        let sources = match source {
            Value::Array(items) => items,
            other => vec![other],
        };
        for item in sources {
            if let Value::Object(inner) = item {
                for (key, value) in inner {
                    if !map.contains_key(&key) {
                        map.insert(key, value);
                    }
                }
            }
        }
    }
}

fn allowed_alias_ratio(decoded: usize) -> f64 {
    if decoded <= ALIAS_RATIO_LOW {
        0.99
    } else if decoded >= ALIAS_RATIO_HIGH {
        0.10
    } else {
        let span = (ALIAS_RATIO_HIGH - ALIAS_RATIO_LOW) as f64;
        0.99 - 0.89 * ((decoded - ALIAS_RATIO_LOW) as f64 / span)
    }
}

/// Mapping keys count as nodes, as go-yaml decodes them.
fn count_nodes(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(count_nodes).sum::<usize>(),
        Value::Object(map) => {
            1 + map
                .values()
                .map(|value| 1 + count_nodes(value))
                .sum::<usize>()
        }
        _ => 1,
    }
}

impl Builder {
    fn charge(&mut self, nodes: usize, line: usize) -> Result<()> {
        self.decoded = self.decoded.saturating_add(nodes);
        self.aliased = self.aliased.saturating_add(nodes);
        if self.aliased > 100
            && self.decoded > 1000
            && self.aliased as f64 / self.decoded as f64 > allowed_alias_ratio(self.decoded)
        {
            return Err(error_at("document contains excessive aliasing", line));
        }
        Ok(())
    }

    fn child_text(&self) -> bool {
        match self.frames.last() {
            Some(Frame::Seq { text, .. }) => *text,
            Some(Frame::Map {
                key: Some(key),
                text,
                ..
            }) => *text || key == "short-id",
            _ => false,
        }
    }

    fn record_line(&mut self, line: usize) {
        let line = u32::try_from(line).unwrap_or(u32::MAX);
        let target = match self.frames.as_slice() {
            [Frame::Map { key: Some(key), .. }, Frame::Seq { .. }] => match key.as_str() {
                "proxies" => &mut self.lines.proxies,
                "proxy-groups" => &mut self.lines.proxy_groups,
                "rules" => &mut self.lines.rules,
                _ => return,
            },
            [
                Frame::Map { key: Some(top), .. },
                Frame::Map {
                    key: Some(list), ..
                },
                Frame::Seq { .. },
            ] if top == "mitm" => self.lines.mitm.entry(list.clone()).or_default(),
            _ => return,
        };
        target.push(line);
    }

    fn scalar(
        &mut self,
        text: &str,
        style: ScalarStyle,
        anchor: usize,
        tag: Option<&Tag>,
        line: usize,
    ) -> Result<()> {
        if let Some(Frame::Map {
            key: key @ None,
            merging,
            ..
        }) = self.frames.last_mut()
        {
            *merging = style == ScalarStyle::Plain && text == "<<" && tag.is_none();
            *key = Some(text.to_string());
            return Ok(());
        }
        self.record_line(line);
        let force_text = self.child_text();
        let value = resolve_scalar(text, style, tag, force_text);
        self.finish(value, anchor, line)
    }

    fn finish(&mut self, value: Value, anchor: usize, line: usize) -> Result<()> {
        if anchor != 0 {
            self.anchors.insert(anchor, value.clone());
        }
        let top_level = self.frames.len() == 1;
        match self.frames.last_mut() {
            None => self.root = Some(value),
            Some(Frame::Seq { items, .. }) => items.push(value),
            Some(Frame::Map {
                map,
                key,
                merging,
                merges,
                ..
            }) => {
                let name = key.take().unwrap_or_default();
                if std::mem::take(merging) {
                    match &value {
                        Value::Object(_) => merges.push(value),
                        Value::Array(items) if items.iter().all(Value::is_object) => {
                            merges.push(value);
                        }
                        _ => {
                            return Err(error_at(
                                "map merge requires map or sequence of maps as the value",
                                line,
                            ));
                        }
                    }
                } else if map.contains_key(&name) {
                    return Err(error_at(
                        format!("mapping key \"{name}\" already defined"),
                        line,
                    ));
                } else {
                    if top_level && anchor != 0 {
                        self.anchored.insert(name.clone());
                    }
                    map.insert(name, value);
                }
            }
        }
        Ok(())
    }
}

fn is_canonical_int(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" && text == "0" || !digits.starts_with('0'))
}

fn is_canonical_float(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let Some((whole, fraction)) = digits.split_once('.') else {
        return false;
    };
    !whole.is_empty()
        && !fraction.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fraction.bytes().all(|b| b.is_ascii_digit())
        && (whole == "0" || !whole.starts_with('0'))
        && !fraction.ends_with('0')
}

pub fn resolve_scalar(
    text: &str,
    style: ScalarStyle,
    tag: Option<&Tag>,
    force_text: bool,
) -> Value {
    if style != ScalarStyle::Plain {
        return Value::String(text.to_string());
    }
    if tag.is_some_and(|tag| tag.is_yaml_core_schema_tag("str")) {
        return Value::String(text.to_string());
    }
    if matches!(text, "" | "~" | "null" | "Null" | "NULL") {
        return Value::Null;
    }
    if force_text {
        return Value::String(text.to_string());
    }
    match text {
        "true" | "True" | "TRUE" => return Value::Bool(true),
        "false" | "False" | "FALSE" => return Value::Bool(false),
        _ => {}
    }
    if is_canonical_int(text) {
        if let Ok(n) = text.parse::<i64>() {
            return Value::Number(n.into());
        }
        if let Ok(n) = text.parse::<u64>() {
            return Value::Number(n.into());
        }
    } else if is_canonical_float(text)
        && let Some(n) = text.parse::<f64>().ok().and_then(Number::from_f64)
    {
        return Value::Number(n);
    }
    Value::String(text.to_string())
}

pub fn plain_resolves_to_string(text: &str) -> bool {
    matches!(
        resolve_scalar(text, ScalarStyle::Plain, None, false),
        Value::String(_)
    )
}

fn plain_safe(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_alphanumeric() || first == '_' || first == '/' || first == '.') {
        return false;
    }
    if text.ends_with([' ', ':']) || text.contains(": ") || text.contains(" #") {
        return false;
    }
    if !text.chars().all(|c| {
        c.is_alphanumeric()
            || matches!(
                c,
                '_' | '-' | '.' | '/' | ' ' | ':' | '@' | '+' | '(' | ')' | '=' | '*' | ','
            )
    }) {
        return false;
    }
    if first == '.' && text.len() > 1 {
        return false;
    }
    plain_resolves_to_string(text)
        && !matches!(
            text.to_ascii_lowercase().as_str(),
            "y" | "n" | "yes" | "no" | "on" | "off" | "<<"
        )
}

fn write_string(out: &mut String, text: &str) {
    if plain_safe(text) {
        out.push_str(text);
    } else {
        match serde_json::to_string(text) {
            Ok(quoted) => out.push_str(&quoted),
            Err(_) => out.push_str("\"\""),
        }
    }
}

fn write_key(out: &mut String, key: &str) {
    write_string(out, key);
    out.push(':');
}

fn write_scalar(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(out, s),
        Value::Array(_) => out.push_str("[]"),
        Value::Object(_) => out.push_str("{}"),
    }
}

fn indent(out: &mut String, depth: usize) {
    out.extend(std::iter::repeat_n(' ', depth * 2));
}

fn write_object(out: &mut String, map: &Map, depth: usize, in_seq: bool) {
    let mut first = true;
    for (key, item) in map {
        if !(first && in_seq) {
            indent(out, depth);
        }
        first = false;
        write_key(out, key);
        write_child(out, item, depth);
    }
}

fn write_value(out: &mut String, value: &Value, depth: usize, in_seq: bool) {
    match value {
        Value::Object(map) if map.is_empty() => {
            out.push_str("{}\n");
        }
        Value::Array(items) if items.is_empty() => {
            out.push_str("[]\n");
        }
        Value::Object(map) => write_object(out, map, depth, in_seq),
        Value::Array(items) => {
            let mut first = true;
            for item in items {
                if !(first && in_seq) {
                    indent(out, depth);
                }
                first = false;
                out.push_str("- ");
                match item {
                    Value::Object(map) if !map.is_empty() => {
                        write_object(out, map, depth + 1, true);
                    }
                    Value::Array(inner) if !inner.is_empty() => {
                        write_value(out, item, depth + 1, true);
                    }
                    other => {
                        write_scalar_or_empty(out, other);
                        out.push('\n');
                    }
                }
            }
        }
        other => {
            write_scalar(out, other);
            out.push('\n');
        }
    }
}

fn write_scalar_or_empty(out: &mut String, value: &Value) {
    match value {
        Value::Object(_) => out.push_str("{}"),
        Value::Array(_) => out.push_str("[]"),
        other => write_scalar(out, other),
    }
}

fn write_child(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            out.push('\n');
            write_value(out, value, depth + 1, false);
        }
        Value::Array(items) if !items.is_empty() => {
            out.push('\n');
            write_value(out, value, depth + 1, false);
        }
        other => {
            out.push(' ');
            write_scalar_or_empty(out, other);
            out.push('\n');
        }
    }
}

pub fn write_map(out: &mut String, map: &Map) {
    for (key, value) in map {
        write_key(out, key);
        write_child(out, value, 0);
    }
}

pub fn write_entry(out: &mut String, key: &str, value: &Value) {
    write_key(out, key);
    write_child(out, value, 0);
}

pub fn write_map_list(out: &mut String, key: &str, items: &[Map]) {
    write_key(out, key);
    if items.is_empty() {
        out.push_str(" []\n");
        return;
    }
    out.push('\n');
    for item in items {
        indent(out, 1);
        out.push_str("- ");
        if item.is_empty() {
            out.push_str("{}\n");
        } else {
            write_object(out, item, 2, true);
        }
    }
}

pub fn write_rules(out: &mut String, key: &str, rules: &RuleLines) {
    write_key(out, key);
    if rules.is_empty() {
        out.push_str(" []\n");
        return;
    }
    out.push('\n');
    for rule in rules.iter() {
        out.push_str("  - ");
        write_string(out, rule);
        out.push('\n');
    }
}

pub fn to_yaml(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Object(map) => write_map(&mut out, map),
        other => write_value(&mut out, other, 0, false),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Map {
        parse_document(text).unwrap().root
    }

    #[test]
    fn plain_scalars_keep_their_spelling_when_ambiguous() {
        let root =
            parse("a: 443\nb: 0x1BB\nc: 000000\nd: yes\ne: 1.5\nf: ~\ng: true\nh: \"443\"\n");
        assert_eq!(root["a"], Value::from(443));
        assert_eq!(root["b"], Value::from("0x1BB"));
        assert_eq!(root["c"], Value::from("000000"));
        assert_eq!(root["d"], Value::from("yes"));
        assert_eq!(root["e"], Value::from(1.5));
        assert_eq!(root["f"], Value::Null);
        assert_eq!(root["g"], Value::from(true));
        assert_eq!(root["h"], Value::from("443"));
    }

    #[test]
    fn merge_keys_and_anchors_expand() {
        let root = parse(
            "base: &b {type: ss, port: 1, name: base}\nitems:\n  - <<: *b\n    name: one\n  - <<: [*b]\n    port: 2\n",
        );
        let items = root["items"].as_array().unwrap();
        assert_eq!(items[0]["name"], "one");
        assert_eq!(items[0]["type"], "ss");
        assert_eq!(items[0]["port"], 1);
        assert_eq!(items[1]["name"], "base");
        assert_eq!(items[1]["port"], 2);
    }

    #[test]
    fn aliasing_is_held_to_go_yaml_ratio() {
        let list = format!("[{}]", vec!["x"; 1000].join(", "));
        let refs = |count: usize| vec!["*a"; count].join(", ");
        let few = format!("a: &a {list}\nb: [{}]\n", refs(50));
        assert!(parse_document(&few).is_ok());
        let many = format!("a: &a {list}\nb: [{}]\n", refs(150));
        let err = parse_document(&many).unwrap_err().to_string();
        assert!(err.contains("excessive aliasing"), "{err}");
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let err = parse_document("a: 1\na: 2\n").unwrap_err();
        assert!(err.message.contains("already defined"), "{err}");
        assert_eq!(err.line, Some(2));
    }

    #[test]
    fn short_ids_stay_text_in_every_position() {
        let root = parse(
            "proxies:\n  - {name: o, reality-opts: {public-key: k, short-id: 0123}}\n  - name: z\n    reality-opts:\n      short-id: 00\n  - name: e\n    reality-opts:\n      short-id: 1e5\n  - name: q\n    reality-opts:\n      short-id: \"0189\"\nlisteners:\n  - reality-config:\n      short-id: [01234567, \"\"]\n",
        );
        let proxies = root["proxies"].as_array().unwrap();
        assert_eq!(proxies[0]["reality-opts"]["short-id"], "0123");
        assert_eq!(proxies[1]["reality-opts"]["short-id"], "00");
        assert_eq!(proxies[2]["reality-opts"]["short-id"], "1e5");
        assert_eq!(proxies[3]["reality-opts"]["short-id"], "0189");
        let ids = root["listeners"][0]["reality-config"]["short-id"]
            .as_array()
            .unwrap();
        assert_eq!(ids[0], "01234567");
        assert_eq!(ids[1], "");
    }

    #[test]
    fn the_rules_fast_path_matches_the_full_parse() {
        let text = "mixed-port: 7890\nrules:\n  - DOMAIN,a.com,DIRECT # note\n  # comment\n\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - MATCH,PROXY\nmode: rule\n";
        let fast = parse_document(text).unwrap();
        let slow = parse_document_slow(text).unwrap();
        assert!(!fast.root.contains_key("rules"));
        let fast_rules: Vec<&str> = fast.rules.as_ref().unwrap().iter().collect();
        assert_eq!(serde_json::json!(fast_rules), slow.root["rules"]);
        assert_eq!(fast.root["mode"], slow.root["mode"]);
        assert_eq!(fast.lines.rules, vec![3, 6, 7]);
    }

    #[test]
    fn the_rules_fast_path_falls_back_on_quotes_and_flow() {
        for text in [
            "rules:\n  - \"DOMAIN,a.com,DIRECT\"\n  - MATCH,P\n",
            "rules: [MATCH,P]\n",
            "rules:\n  - &x MATCH,P\n",
            "rules:\n  - a: b\n",
            "rules:\n  - AND,((DOMAIN,a),(NETWORK,UDP)),X\n  - 'MATCH,P'\n",
        ] {
            assert!(scan_rules(text).is_none(), "{text}");
            assert!(parse_document(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn indentless_rule_lists_are_scanned() {
        let doc = parse_document("rules:\n- MATCH,P\nmode: global\n").unwrap();
        assert_eq!(doc.rules.unwrap(), ["MATCH,P"]);
        assert_eq!(doc.root["mode"], "global");
    }

    #[test]
    fn written_yaml_parses_back_to_the_same_tree() {
        let value = serde_json::json!({
            "proxies": [
                {"name": "a b", "port": 443, "short-id": "0123", "alpn": ["h2", "http/1.1"], "empty": [], "nested": {"x": null, "y": true, "z": "yes"}},
                {"name": "- dash", "pass": "p: w # x", "text": "line\nbreak"}
            ],
            "dns": {"nameserver": ["https://doh.pub/dns-query", "tls://223.5.5.5:853"]},
            "rule": ["DOMAIN,a,b"],
            "hosts": {},
            "list": [[1, 2], [3]]
        });
        let text = to_yaml(&value);
        let parsed = parse_document_slow(&text).unwrap();
        assert_eq!(Value::Object(parsed.root), value, "{text}");
    }

    #[test]
    fn a_scalar_document_is_not_a_config() {
        assert!(parse_document("just text").is_err());
        assert!(parse_document("").unwrap().root.is_empty());
    }
}
