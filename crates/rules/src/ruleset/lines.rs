//! The line readers for text and YAML rule-set files.

use super::RuleSetError;

/// mihomo reads a YAML rule set one line at a time: a `payload:` or `rules:`
/// head, then each `- item` line decoded on its own. A line that is not an
/// item is skipped.
pub(crate) fn yaml_items(buf: &[u8]) -> Result<Vec<String>, RuleSetError> {
    let mut items = Vec::new();
    let mut head_seen = false;
    let mut rest = buf;
    while !rest.is_empty() {
        let (line, tail, last_without_newline) = match rest.iter().position(|b| *b == b'\n') {
            Some(at) => (
                rest.get(..at).unwrap_or_default(),
                rest.get(at + 1..).unwrap_or_default(),
                false,
            ),
            None => (rest, rest.get(..0).unwrap_or_default(), true),
        };
        rest = tail;
        if last_without_newline && !head_seen {
            return Err(RuleSetError::NoPayload);
        }
        let text = String::from_utf8_lossy(line);
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !head_seen {
            head_seen = is_head(trimmed);
            continue;
        }
        if let Some(item) = item_of(trimmed)
            && !item.is_empty()
        {
            items.push(item);
        }
    }
    Ok(items)
}

pub(crate) fn text_items(buf: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(buf)
        .split('\n')
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
        .map(str::to_string)
        .collect()
}

/// Surge's DOMAIN-SET lines as Clash domain patterns: a leading dot covers the domain itself
/// as well as what is under it, which Clash writes `+.`.
pub(crate) fn domain_set_items(buf: &[u8]) -> Vec<String> {
    text_items(buf)
        .into_iter()
        .map(|item| match item.strip_prefix('.') {
            Some(rest) => format!("+.{rest}"),
            None => item,
        })
        .collect()
}

fn is_head(line: &str) -> bool {
    let Some((key, after)) = line.split_once(':') else {
        return false;
    };
    let key = key.trim().trim_matches(['"', '\'']);
    if key != "payload" && key != "rules" {
        return false;
    }
    let after = after.trim();
    after.is_empty() || after.starts_with('#')
}

/// The scalar of a `- item` line, or `None` when the line holds anything else.
fn item_of(line: &str) -> Option<String> {
    let body = line.strip_prefix('-')?;
    if !body.is_empty() && !body.starts_with([' ', '\t']) {
        return None;
    }
    let body = body.trim_start();
    if body.is_empty() {
        return Some(String::new());
    }
    let first = body.chars().next()?;
    match first {
        '\'' => single_quoted(body),
        '"' => double_quoted(body),
        '[' | '{' | '*' | '&' | '!' | '|' | '>' | '%' | '@' | '`' | '#' => None,
        _ => plain(body),
    }
}

fn after_scalar(rest: &str) -> bool {
    let rest = rest.trim_start();
    rest.is_empty() || rest.starts_with('#')
}

fn single_quoted(body: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = body.get(1..)?.char_indices().peekable();
    let inner = body.get(1..)?;
    while let Some((at, c)) = chars.next() {
        if c != '\'' {
            out.push(c);
            continue;
        }
        if matches!(chars.peek(), Some((_, '\''))) {
            out.push('\'');
            chars.next();
            continue;
        }
        return after_scalar(inner.get(at + 1..)?).then_some(out);
    }
    None
}

fn double_quoted(body: &str) -> Option<String> {
    let inner = body.get(1..)?;
    let mut out = String::new();
    let mut chars = inner.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return after_scalar(inner.get(at + 1..)?).then_some(out),
            '\\' => match chars.next()?.1 {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                '0' => out.push('\0'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                ' ' => out.push(' '),
                'x' => out.push(hex_char(&mut chars, 2)?),
                'u' => out.push(hex_char(&mut chars, 4)?),
                _ => return None,
            },
            other => out.push(other),
        }
    }
    None
}

fn hex_char(chars: &mut std::str::CharIndices<'_>, digits: usize) -> Option<char> {
    let mut value = 0u32;
    for _ in 0..digits {
        value = value * 16 + chars.next()?.1.to_digit(16)?;
    }
    char::from_u32(value)
}

fn plain(body: &str) -> Option<String> {
    let mut end = body.len();
    for (at, _) in body.match_indices('#') {
        if body
            .get(..at)
            .is_some_and(|before| before.ends_with([' ', '\t']))
        {
            end = at;
            break;
        }
    }
    let value = body.get(..end)?.trim_end();
    if value.ends_with(':') || value.contains(": ") || value.contains(":\t") {
        return None;
    }
    if matches!(value, "~" | "null" | "Null" | "NULL") {
        return Some(String::new());
    }
    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Vec<String> {
        yaml_items(text.as_bytes()).unwrap()
    }

    #[test]
    fn items_follow_the_head() {
        assert_eq!(
            yaml("payload:\n  - '+.example.com'\n  - \"a.com\"\n  - b.com # note\n"),
            ["+.example.com", "a.com", "b.com"]
        );
        assert_eq!(yaml("# c\nrules:\n- DOMAIN,a.com\n"), ["DOMAIN,a.com"]);
    }

    #[test]
    fn lines_that_are_not_items_are_skipped() {
        let items = yaml("payload:\n  - a.com\n  key: value\n  - [x]\n  - 'b.com'\n  -\n  - ~\n");
        assert_eq!(items, ["a.com", "b.com"]);
        assert_eq!(yaml("name: x\npayload:\n  - a.com\n"), ["a.com"]);
    }

    #[test]
    fn quoting_is_decoded() {
        assert_eq!(
            yaml("payload:\n  - 'it''s.com'\n  - \"a\\x41.com\"\n"),
            ["it's.com", "aA.com"]
        );
    }

    #[test]
    fn a_missing_head_is_an_error_only_on_an_unterminated_last_line() {
        assert!(yaml_items(b"- a.com").is_err());
        assert!(yaml("- a.com\n").is_empty());
        assert!(yaml_items(b"payload:\n  - a.com").is_ok());
    }

    #[test]
    fn text_skips_comments_and_blanks() {
        assert_eq!(
            text_items(b"# x\n\n  a.com  \n// y\nb.com"),
            ["a.com", "b.com"]
        );
    }
}
