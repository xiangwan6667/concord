use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

use base64::Engine;
use indexmap::IndexMap;
use serde_json::Value;

use crate::Map;
use crate::error::{ConfigError, Result};

pub fn parse_int_base0(text: &str) -> Option<i128> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let lower = digits.to_ascii_lowercase();
    let (radix, body) = if let Some(rest) = lower.strip_prefix("0x") {
        (16, rest)
    } else if let Some(rest) = lower.strip_prefix("0b") {
        (2, rest)
    } else if let Some(rest) = lower.strip_prefix("0o") {
        (8, rest)
    } else if lower.len() > 1 && lower.starts_with('0') {
        (8, lower.get(1..).unwrap_or_default())
    } else {
        (10, lower.as_str())
    };
    if body.is_empty() || body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    let cleaned: String = body.chars().filter(|c| *c != '_').collect();
    let magnitude = i128::from_str_radix(&cleaned, radix).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "nil",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float64",
        Value::Number(_) => "int",
        Value::String(_) => "string",
        Value::Array(_) => "slice",
        Value::Object(_) => "map",
    }
}

pub fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(match n.as_f64() {
            Some(f) if n.is_f64() => format_float(f),
            _ => n.to_string(),
        }),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn format_float(f: f64) -> String {
    if f.fract() == 0.0 && f.abs() < 1e15 {
        format!("{f:.0}")
    } else {
        f.to_string()
    }
}

pub fn to_i128(value: &Value) -> Option<i128> {
    match value {
        Value::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
            .or_else(|| n.as_f64().map(|f| f as i128)),
        Value::String(s) => parse_int_base0(s.trim()),
        _ => None,
    }
}

pub fn to_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => Some(n.as_f64().is_some_and(|f| f != 0.0)),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "t" | "1" | "yes" | "y" | "on" => Some(true),
            "false" | "f" | "0" | "no" | "n" | "off" | "" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

enum Lookup<'a> {
    Direct(&'a Map),
    Folded(HashMap<String, &'a Value>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ignored {
    pub code: &'static str,
    pub key: String,
    pub why: String,
}

impl fmt::Display for Ignored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is ignored: {}", self.key, self.why)
    }
}

pub struct Fields<'a> {
    lookup: Lookup<'a>,
    path: String,
    missing: Vec<String>,
    replace_underscore: bool,
    /// Shared with the fields of every sub-map, so a note from one reaches the caller.
    ignored: Rc<RefCell<Vec<Ignored>>>,
}

impl<'a> Fields<'a> {
    pub fn new(map: &'a Map, path: &str, replace_underscore: bool) -> Self {
        let clean = map.keys().all(|key| {
            !key.bytes()
                .any(|b| b.is_ascii_uppercase() || (replace_underscore && b == b'_'))
        });
        let lookup = if clean {
            Lookup::Direct(map)
        } else {
            let mut folded = HashMap::with_capacity(map.len());
            for (key, value) in map {
                let mut key = key.to_ascii_lowercase();
                if replace_underscore {
                    key = key.replace('_', "-");
                }
                folded.entry(key).or_insert(value);
            }
            Lookup::Folded(folded)
        };
        Fields {
            lookup,
            path: path.to_string(),
            missing: Vec::new(),
            replace_underscore,
            ignored: Rc::default(),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    fn name(&self, key: &str) -> String {
        if self.path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{key}", self.path)
        }
    }

    fn lookup(&self, key: &str) -> Option<&'a Value> {
        self.lookup_present(key).filter(|value| !value.is_null())
    }

    fn lookup_present(&self, key: &str) -> Option<&'a Value> {
        let lowered;
        let key = if key.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = key.to_ascii_lowercase();
            lowered.as_str()
        } else {
            key
        };
        match &self.lookup {
            Lookup::Direct(map) => map.get(key),
            Lookup::Folded(map) => map.get(key).copied(),
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.lookup(key).is_some()
    }

    pub fn raw(&self, key: &str) -> Option<&'a Value> {
        self.lookup(key)
    }

    fn mismatch(&self, key: &str, expected: &str, value: &Value) -> ConfigError {
        ConfigError::new(format!(
            "'{}' expected type '{expected}', got unconvertible type '{}'",
            self.name(key),
            kind_name(value)
        ))
    }

    /// A key written with no value is set, as mihomo's decoder reads it; it keeps the zero value.
    pub fn require(&mut self, key: &str) {
        if self.lookup_present(key).is_none() {
            self.missing.push(key.to_string());
        }
    }

    pub fn opt_string(&mut self, key: &str) -> Result<Option<String>> {
        match self.lookup(key) {
            None => Ok(None),
            Some(value) => scalar_text(value)
                .map(Some)
                .ok_or_else(|| self.mismatch(key, "string", value)),
        }
    }

    pub fn string(&mut self, key: &str) -> Result<String> {
        Ok(self.opt_string(key)?.unwrap_or_default())
    }

    pub fn req_string(&mut self, key: &str) -> Result<String> {
        self.require(key);
        self.string(key)
    }

    pub fn opt_bool(&mut self, key: &str) -> Result<Option<bool>> {
        match self.lookup(key) {
            None => Ok(None),
            Some(value) => to_bool(value)
                .map(Some)
                .ok_or_else(|| self.mismatch(key, "bool", value)),
        }
    }

    pub fn boolean(&mut self, key: &str) -> Result<bool> {
        Ok(self.opt_bool(key)?.unwrap_or(false))
    }

    fn integer(&self, key: &str, expected: &str, min: i128, max: i128) -> Result<Option<i128>> {
        let Some(value) = self.lookup(key) else {
            return Ok(None);
        };
        let number = to_i128(value).ok_or_else(|| self.mismatch(key, expected, value))?;
        if number < min || number > max {
            return Err(ConfigError::new(format!(
                "cannot parse '{}' as int: value out of range",
                self.name(key)
            )));
        }
        Ok(Some(number))
    }

    pub fn opt_u16(&mut self, key: &str) -> Result<Option<u16>> {
        Ok(self
            .integer(key, "uint16", 0, i128::from(u16::MAX))?
            .and_then(|n| u16::try_from(n).ok()))
    }

    pub fn u16(&mut self, key: &str) -> Result<u16> {
        Ok(self.opt_u16(key)?.unwrap_or(0))
    }

    pub fn req_u16(&mut self, key: &str) -> Result<u16> {
        self.require(key);
        self.u16(key)
    }

    /// A number mihomo keeps as a Go `int` and does not check: one this type cannot hold is
    /// noted and read as `fallback`, as is an absent one.
    pub fn loose<T: TryFrom<i128>>(&mut self, key: &str, fallback: T) -> Result<T> {
        let Some(number) = self.integer(key, "int", i128::MIN, i128::MAX)? else {
            return Ok(fallback);
        };
        Ok(T::try_from(number).unwrap_or_else(|_| {
            self.note("out_of_range", key, format!("{number} is out of range"));
            fallback
        }))
    }

    pub fn u32(&mut self, key: &str) -> Result<u32> {
        Ok(self
            .integer(key, "uint32", 0, i128::from(u32::MAX))?
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0))
    }

    pub fn u64(&mut self, key: &str) -> Result<u64> {
        Ok(self
            .integer(key, "uint64", 0, i128::from(u64::MAX))?
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0))
    }

    pub fn i64(&mut self, key: &str) -> Result<i64> {
        Ok(self
            .integer(key, "int64", i128::from(i64::MIN), i128::from(i64::MAX))?
            .and_then(|n| i64::try_from(n).ok())
            .unwrap_or(0))
    }

    /// mihomo keeps a mark as an `int` and hands it to `setsockopt` as a C `int`, so its low 32
    /// bits are the mark.
    pub fn mark(&mut self, key: &str) -> Result<u32> {
        Ok(self.i64(key)? as u32)
    }

    pub fn i32(&mut self, key: &str) -> Result<i32> {
        Ok(self
            .integer(key, "int", i128::from(i32::MIN), i128::from(i32::MAX))?
            .and_then(|n| i32::try_from(n).ok())
            .unwrap_or(0))
    }

    pub fn strings(&mut self, key: &str) -> Result<Vec<String>> {
        let Some(value) = self.lookup(key) else {
            return Ok(Vec::new());
        };
        match value {
            Value::Array(items) => items
                .iter()
                .map(|item| match item {
                    Value::Null => Ok(String::new()),
                    other => scalar_text(other).ok_or_else(|| self.mismatch(key, "string", other)),
                })
                .collect(),
            other => scalar_text(other)
                .map(|text| vec![text])
                .ok_or_else(|| self.mismatch(key, "slice", other)),
        }
    }

    pub fn ints(&mut self, key: &str, min: i128, max: i128) -> Result<Vec<i128>> {
        let Some(value) = self.lookup(key) else {
            return Ok(Vec::new());
        };
        let items: Vec<&Value> = match value {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        items
            .into_iter()
            .map(|item| match to_i128(item) {
                Some(n) if (min..=max).contains(&n) => Ok(n),
                _ => Err(self.mismatch(key, "integer", item)),
            })
            .collect()
    }

    pub fn u8_list(&mut self, key: &str) -> Result<Vec<u8>> {
        let Some(value) = self.lookup(key) else {
            return Ok(Vec::new());
        };
        let items: Vec<&Value> = match value {
            Value::String(text) => {
                return base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .map_err(|err| {
                        ConfigError::new(format!("try decode '{key}' by base64 error: {err}"))
                    });
            }
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        items
            .into_iter()
            .map(|item| {
                to_i128(item)
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| self.mismatch(key, "uint8", item))
            })
            .collect()
    }

    pub fn sub(&mut self, key: &str) -> Result<Option<Fields<'a>>> {
        match self.lookup(key) {
            None => Ok(None),
            Some(Value::Object(map)) => {
                let mut sub = Fields::new(map, &self.name(key), self.replace_underscore);
                sub.ignored = self.ignored.clone();
                Ok(Some(sub))
            }
            Some(other) => Err(ConfigError::new(format!(
                "'{}' expected a map, got '{}'",
                self.name(key),
                kind_name(other)
            ))),
        }
    }

    pub fn object(&self, key: &str) -> Result<Option<&'a Map>> {
        match self.lookup(key) {
            None => Ok(None),
            Some(Value::Object(map)) => Ok(Some(map)),
            Some(other) => Err(ConfigError::new(format!(
                "'{}' expected a map, got '{}'",
                self.name(key),
                kind_name(other)
            ))),
        }
    }

    pub fn string_map(&mut self, key: &str) -> Result<IndexMap<String, String>> {
        let mut out = IndexMap::new();
        if let Some(map) = self.object(key)? {
            for (name, value) in map {
                let text = match value {
                    Value::Array(items) => items.first().and_then(scalar_text),
                    other => scalar_text(other),
                }
                .unwrap_or_default();
                out.insert(name.clone(), text);
            }
        }
        Ok(out)
    }

    pub fn list_map(&mut self, key: &str) -> Result<IndexMap<String, Vec<String>>> {
        let mut out = IndexMap::new();
        if let Some(map) = self.object(key)? {
            for (name, value) in map {
                let items = match value {
                    Value::Array(items) => items.iter().filter_map(scalar_text).collect(),
                    other => scalar_text(other).into_iter().collect(),
                };
                out.insert(name.clone(), items);
            }
        }
        Ok(out)
    }

    /// Notes a key this core reads past when it asks for something, for the load report.
    pub fn ignore(&mut self, key: &str, why: &str) {
        if self.lookup(key).is_some_and(crate::raw::asks_for_something) {
            self.note("not_applied", key, why.to_string());
        }
    }

    fn note(&self, code: &'static str, key: &str, why: String) {
        self.ignored.borrow_mut().push(Ignored {
            code,
            key: self.name(key),
            why,
        });
    }

    pub fn take_ignored(&mut self) -> Vec<Ignored> {
        std::mem::take(&mut *self.ignored.borrow_mut())
    }

    pub fn finish(self) -> Result<()> {
        if self.missing.is_empty() {
            return Ok(());
        }
        let mut missing = self.missing;
        missing.sort();
        Err(ConfigError::new(format!(
            "'{}' has unset fields: {}",
            self.path,
            missing.join(", ")
        )))
    }
}

pub fn value_to_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().filter_map(scalar_text).collect(),
        other => scalar_text(other).into_iter().collect(),
    }
}
