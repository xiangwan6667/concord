use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

use super::issue::LineError;

/// Go's `%q` for a string.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go's `%q` for a rune.
pub fn quote_char(c: char) -> String {
    match c {
        '\'' => "'\\''".to_string(),
        '\\' => "'\\\\'".to_string(),
        c if c.is_control() => format!("'\\x{:02x}'", c as u32),
        c => format!("'{c}'"),
    }
}

pub fn canonical_header(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for c in name.chars() {
        if upper {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c.to_ascii_lowercase());
        }
        upper = c == '-';
    }
    out
}

pub fn decode_base64(text: &str) -> Result<Vec<u8>, LineError> {
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(data) = engine.decode(text) {
            return Ok(data);
        }
    }
    Err(LineError::invalid("invalid base64"))
}

#[derive(Clone, Debug)]
pub struct Field {
    pub text: String,
    pub to: usize,
}

/// Splits on spaces and keeps a double-quoted run, which may start inside a
/// field as in `data="{}"`, in one field without its quotes. Inside quotes only
/// `\"` is unescaped, so a regex keeps its backslashes.
pub fn split_fields(line: &str) -> Result<Vec<Field>, LineError> {
    let bytes = line.as_bytes();
    let mut fields = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes.get(i), Some(b' ' | b'\t')) {
            i += 1;
            continue;
        }
        let mut text = Vec::new();
        let mut quoted = false;
        while let Some(&c) = bytes.get(i) {
            if quoted && c == b'\\' && bytes.get(i + 1) == Some(&b'"') {
                text.push(b'"');
                i += 2;
                continue;
            }
            if c == b'"' {
                quoted = !quoted;
            } else if !quoted && (c == b' ' || c == b'\t') {
                break;
            } else {
                text.push(c);
            }
            i += 1;
        }
        if quoted {
            return Err(LineError::syntax("unclosed quote"));
        }
        fields.push(Field {
            text: String::from_utf8_lossy(&text).into_owned(),
            to: i,
        });
    }
    Ok(fields)
}

pub fn texts(fields: &[Field]) -> Vec<&str> {
    fields.iter().map(|field| field.text.as_str()).collect()
}

/// What follows `after` on the line, unquoted when it is one quoted run.
pub fn remainder(line: &str, after: &Field) -> String {
    let rest = line.get(after.to..).unwrap_or_default().trim();
    if rest.len() >= 2 && rest.starts_with('"') && rest.ends_with('"') {
        return rest
            .get(1..rest.len() - 1)
            .unwrap_or_default()
            .replace("\\\"", "\"");
    }
    rest.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_runs_stay_in_one_field() {
        let fields = split_fields(r#"^https://a data="{\"k\": 1}" x"#).unwrap();
        let got: Vec<_> = fields.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(got, ["^https://a", r#"data={"k": 1}"#, "x"]);
        assert!(split_fields("a \"b").is_err());
    }

    #[test]
    fn regex_backslashes_survive_quotes() {
        let fields = split_fields(r#"a "b\d+" c"#).unwrap();
        assert_eq!(fields[1].text, r"b\d+");
    }

    #[test]
    fn canonical_header_names() {
        assert_eq!(canonical_header("content-type"), "Content-Type");
        assert_eq!(canonical_header("x-mitm"), "X-Mitm");
    }

    #[test]
    fn base64_accepts_every_alphabet() {
        assert_eq!(decode_base64("aGk=").unwrap(), b"hi");
        assert_eq!(decode_base64("aGk").unwrap(), b"hi");
        assert!(decode_base64("!!").is_err());
    }
}
