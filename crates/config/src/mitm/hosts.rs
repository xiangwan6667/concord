use ipnetwork::IpNetwork;

use super::issue::LineError;
use super::text::{quote, quote_char};

/// An item of Surge's `[MITM] hostname`: a lower-case glob, and the port it is limited to
/// unless `bare`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEntryDef {
    pub pattern: String,
    pub exclude: bool,
    pub bare: bool,
    pub port: u16,
}

/// One error per bad item, naming it; the good items apply all the same.
pub fn parse_host_line(line: &str) -> (Vec<HostEntryDef>, Vec<LineError>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for item in line.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        match parse_host_entry(item) {
            Ok(entry) => entries.push(entry),
            Err(err) => errors.push(err.within(&quote(item))),
        }
    }
    (entries, errors)
}

fn parse_host_entry(item: &str) -> Result<HostEntryDef, LineError> {
    let (exclude, item) = match item.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, item),
    };
    let (host, port) = split_host_pattern(item)?;
    if host.is_empty() {
        return Err(LineError::invalid("empty host"));
    }
    if let Some(bad) = host.chars().find(|c| !is_host_pattern_char(*c)) {
        return Err(LineError::invalid(format!(
            "unsupported character {}",
            quote_char(bad)
        )));
    }
    Ok(HostEntryDef {
        pattern: host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase(),
        exclude,
        bare: port.is_none(),
        port: port.unwrap_or(0),
    })
}

fn split_host_pattern(item: &str) -> Result<(&str, Option<u16>), LineError> {
    if let Some(rest) = item.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| LineError::syntax("unclosed bracket"))?;
        if tail.is_empty() {
            return Ok((host, None));
        }
        let port = tail.strip_prefix(':').ok_or_else(|| {
            LineError::syntax(format!("unexpected {} after the address", quote(tail)))
        })?;
        return Ok((host, Some(parse_port(port)?)));
    }
    if item.matches(':').count() != 1 {
        return Ok((item, None));
    }
    let (host, port) = item.split_once(':').unwrap_or((item, ""));
    Ok((host, Some(parse_port(port)?)))
}

fn parse_port(text: &str) -> Result<u16, LineError> {
    text.parse::<u16>()
        .map_err(|_| LineError::invalid(format!("invalid port {}", quote(text))))
}

fn is_host_pattern_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._*?:".contains(c)
}

/// An item of Surge's `client-source-address`; with `exclude` its clients are left out
/// whatever else names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceEntryDef {
    pub network: IpNetwork,
    pub exclude: bool,
}

/// Reads a line of comma-separated addresses and CIDRs, as Surge writes the key. The entries
/// before a bad one are kept, and come back with its error.
pub fn parse_source_line(line: &str) -> (Vec<SourceEntryDef>, Option<LineError>) {
    let mut entries = Vec::new();
    for entry in line
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (text, exclude) = match entry.strip_prefix('-') {
            Some(text) => (text.trim(), true),
            None => (entry, false),
        };
        let Ok(network) = text.parse::<IpNetwork>() else {
            let error = LineError::invalid(format!("invalid address or CIDR {entry:?}"));
            return (entries, Some(error));
        };
        entries.push(SourceEntryDef { network, exclude });
    }
    (entries, None)
}
