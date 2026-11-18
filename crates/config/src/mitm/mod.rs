//! The `mitm` section: Surge's `[MITM]` and its rewrite and script lines, each read on its
//! own. A line that cannot be read is skipped, not fatal to the profile.

mod heads;
mod hosts;
mod issue;
mod pattern;
mod rules;
mod script;
pub mod text;

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

pub use heads::{HeadConditionsDef, REQUEST_HEAD, RESPONSE_HEAD};
pub use hosts::{HostEntryDef, SourceEntryDef, parse_host_line, parse_source_line};
pub use issue::{IssueKind, LineError};
pub use pattern::{MULTILINE, check_multiline, check_pattern, multiline};
pub use rules::{
    BodyActionDef, BodyRewriteDef, HeaderEditDef, HeaderRewriteDef, MapLocalBody, MapLocalDef,
    UrlAction, UrlRewriteDef, parse_body_rewrite, parse_header_rewrite, parse_map_local,
    parse_url_rewrite,
};
pub use script::{
    EVENT_ENGINE_STARTED, EVENT_NETWORK_CHANGED, EVENT_PROFILE_RELOADED, ScriptDef, ScriptKind,
    parse_script,
};

use crate::Map;
use crate::report::LoadReport;
use text::quote;

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// The section as written, its lines in Surge's syntax.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct MitmSection {
    #[serde(deserialize_with = "null_default")]
    pub enable: bool,
    #[serde(deserialize_with = "null_default")]
    pub hostname: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub skip_server_cert_verify: bool,
    /// Hosts whose servers' certificates go unchecked while the switch above is off, as a
    /// module that skips verifying asks for its own hostnames only.
    #[serde(deserialize_with = "null_default")]
    pub skip_server_cert_verify_hostname: Vec<String>,
    /// The clients decrypted for, in Surge's syntax; all of them while it is empty.
    #[serde(deserialize_with = "null_default")]
    pub client_source_address: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_quic_block: Option<bool>,
    #[serde(deserialize_with = "null_default")]
    pub url_rewrite: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub header_rewrite: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub body_rewrite: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub map_local: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub request_body_mock: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub script: Vec<String>,
    /// Off while the device does not trust the CA: HTTPS is then relayed as
    /// is, and only plain HTTP is rewritten.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decrypt_tls: Option<bool>,
    /// The CA the host verified; TLS is decrypted only with it, so a CA that
    /// another process replaced is read again rather than used stale.
    #[serde(
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub ca_fingerprint: String,
    /// Offers HTTP/2 to clients, as Surge's h2; servers are always offered it.
    #[serde(deserialize_with = "null_default")]
    pub h2: bool,
    #[serde(deserialize_with = "null_default")]
    pub limits: MitmLimits,
}

/// Budgets as written; zero or less keeps the engine's default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct MitmLimits {
    #[serde(skip_serializing_if = "is_zero")]
    pub max_body_size: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub body_buffer: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub certificate_cache: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub max_sessions: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub script_concurrency: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub script_memory: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub capture_entries: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub capture_bytes: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// A line of one of the section's lists, by its index there, and how it reads.
#[derive(Clone, Debug, PartialEq)]
pub struct MitmLine<T> {
    pub index: usize,
    pub text: String,
    pub read: T,
}

/// A line of comma-separated items: those that read, and what was wrong with the others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Items<T> {
    pub items: Vec<T>,
    pub error: Option<LineError>,
}

pub type Read<T> = Result<T, LineError>;

/// The section with each of its lines read; blank lines and `#` comments are left out.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MitmDef {
    pub enable: bool,
    pub skip_server_cert_verify: bool,
    pub auto_quic_block: Option<bool>,
    pub decrypt_tls: Option<bool>,
    pub ca_fingerprint: String,
    pub h2: bool,
    pub limits: MitmLimits,
    pub hostname: Vec<MitmLine<Items<HostEntryDef>>>,
    pub skip_server_cert_verify_hostname: Vec<MitmLine<Items<HostEntryDef>>>,
    pub client_source_address: Vec<MitmLine<Items<SourceEntryDef>>>,
    pub url_rewrite: Vec<MitmLine<Read<UrlRewriteDef>>>,
    pub header_rewrite: Vec<MitmLine<Read<HeaderRewriteDef>>>,
    pub body_rewrite: Vec<MitmLine<Read<BodyRewriteDef>>>,
    pub map_local: Vec<MitmLine<Read<MapLocalDef>>>,
    pub request_body_mock: Vec<MitmLine<Read<MapLocalDef>>>,
    pub script: Vec<MitmLine<Read<ScriptDef>>>,
}

/// A line that cannot be read, or the items of one that cannot.
pub struct BadLine<'a> {
    pub list: &'static str,
    pub index: usize,
    pub text: &'a str,
    pub error: &'a LineError,
}

fn each_line<T>(lines: &[String], read: impl Fn(&str) -> T) -> Vec<MitmLine<T>> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#')).then(|| MitmLine {
                index,
                text: line.to_string(),
                read: read(line),
            })
        })
        .collect()
}

/// A line's bad items as one error, of the first item's kind.
fn host_items(line: &str) -> Items<HostEntryDef> {
    let (items, errors) = parse_host_line(line);
    let error = errors.first().map(|first| {
        let message = errors
            .iter()
            .map(|err| err.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        LineError::new(first.kind, message)
    });
    Items { items, error }
}

fn source_items(line: &str) -> Items<SourceEntryDef> {
    let (items, error) = parse_source_line(line);
    Items { items, error }
}

fn same_reads<T: PartialEq>(lines: &[MitmLine<T>], other: &[MitmLine<T>]) -> bool {
    lines
        .iter()
        .map(|line| &line.read)
        .eq(other.iter().map(|line| &line.read))
}

fn bad<'a, T>(
    list: &'static str,
    lines: &'a [MitmLine<T>],
    error: impl Fn(&'a T) -> Option<&'a LineError>,
) -> impl Iterator<Item = BadLine<'a>> {
    lines.iter().filter_map(move |line| {
        error(&line.read).map(|error| BadLine {
            list,
            index: line.index,
            text: &line.text,
            error,
        })
    })
}

impl MitmDef {
    pub fn read(section: &MitmSection) -> MitmDef {
        MitmDef {
            enable: section.enable,
            skip_server_cert_verify: section.skip_server_cert_verify,
            auto_quic_block: section.auto_quic_block,
            decrypt_tls: section.decrypt_tls,
            ca_fingerprint: section.ca_fingerprint.clone(),
            h2: section.h2,
            limits: section.limits,
            hostname: each_line(&section.hostname, host_items),
            skip_server_cert_verify_hostname: each_line(
                &section.skip_server_cert_verify_hostname,
                host_items,
            ),
            client_source_address: each_line(&section.client_source_address, source_items),
            url_rewrite: each_line(&section.url_rewrite, parse_url_rewrite),
            header_rewrite: each_line(&section.header_rewrite, parse_header_rewrite),
            body_rewrite: each_line(&section.body_rewrite, parse_body_rewrite),
            map_local: each_line(&section.map_local, |line| parse_map_local(line, false)),
            request_body_mock: each_line(&section.request_body_mock, |line| {
                parse_map_local(line, true)
            }),
            script: each_line(&section.script, parse_script),
        }
    }

    /// Whether `other` puts the same section in force: its lines read the same and come in
    /// the same order, wherever blank lines and comments put them and however they are spaced.
    pub fn reads_the_same(&self, other: &MitmDef) -> bool {
        let MitmDef {
            enable,
            skip_server_cert_verify,
            auto_quic_block,
            decrypt_tls,
            ca_fingerprint,
            h2,
            limits,
            hostname,
            skip_server_cert_verify_hostname,
            client_source_address,
            url_rewrite,
            header_rewrite,
            body_rewrite,
            map_local,
            request_body_mock,
            script,
        } = self;
        *enable == other.enable
            && *skip_server_cert_verify == other.skip_server_cert_verify
            && *auto_quic_block == other.auto_quic_block
            && *decrypt_tls == other.decrypt_tls
            && *ca_fingerprint == other.ca_fingerprint
            && *h2 == other.h2
            && *limits == other.limits
            && same_reads(hostname, &other.hostname)
            && same_reads(
                skip_server_cert_verify_hostname,
                &other.skip_server_cert_verify_hostname,
            )
            && same_reads(client_source_address, &other.client_source_address)
            && same_reads(url_rewrite, &other.url_rewrite)
            && same_reads(header_rewrite, &other.header_rewrite)
            && same_reads(body_rewrite, &other.body_rewrite)
            && same_reads(map_local, &other.map_local)
            && same_reads(request_body_mock, &other.request_body_mock)
            && same_reads(script, &other.script)
    }

    /// The lines that cannot be read, list by list in the order the engine reads them.
    pub fn bad_lines(&self) -> impl Iterator<Item = BadLine<'_>> {
        bad("hostname", &self.hostname, unread)
            .chain(bad(
                "skip-server-cert-verify-hostname",
                &self.skip_server_cert_verify_hostname,
                unread,
            ))
            .chain(bad(
                "client-source-address",
                &self.client_source_address,
                unread,
            ))
            .chain(bad("url-rewrite", &self.url_rewrite, failed))
            .chain(bad("header-rewrite", &self.header_rewrite, failed))
            .chain(bad("body-rewrite", &self.body_rewrite, failed))
            .chain(bad("map-local", &self.map_local, failed))
            .chain(bad("request-body-mock", &self.request_body_mock, failed))
            .chain(bad("script", &self.script, failed))
    }
}

fn unread<T>(read: &Items<T>) -> Option<&LineError> {
    read.error.as_ref()
}

fn failed<T>(read: &Read<T>) -> Option<&LineError> {
    read.as_ref().err()
}

/// The profile's section, with what of it cannot be read in `report`; `lines` holds the
/// YAML line of each list item by list. An unreadable section leaves MITM off.
pub(crate) fn load(
    section: &Map,
    lines: &BTreeMap<String, Vec<u32>>,
    report: &mut LoadReport,
) -> MitmDef {
    let section = match serde_json::from_value(serde_json::Value::Object(section.clone())) {
        Ok(section) => section,
        Err(err) => {
            report.warn(
                "mitm_section",
                "mitm",
                format!("the section cannot be read: {err}"),
            );
            return MitmDef::default();
        }
    };
    let def = MitmDef::read(&section);
    if def.enable {
        for line in def.bad_lines() {
            let at = lines
                .get(line.list)
                .and_then(|lines| lines.get(line.index))
                .map(|number| format!("line {number}: "))
                .unwrap_or_default();
            report.warn(
                "mitm_line",
                format!("mitm.{}[{}]", line.list, line.index),
                format!("{at}{}: {}", quote(line.text), line.error),
            );
        }
    }
    def
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LoadOptions, load_str};

    fn mitm_warnings(profile: &str) -> Vec<(String, String, String)> {
        let profile = load_str(profile, &LoadOptions::default()).unwrap();
        profile
            .report
            .warnings
            .iter()
            .filter(|warning| warning.path.starts_with("mitm"))
            .map(|warning| {
                (
                    warning.code.to_string(),
                    warning.path.clone(),
                    warning.message.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn a_profile_reports_each_line_it_cannot_read_with_its_line() {
        let warnings = mitm_warnings(
            "\
mitm:
  enable: true
  hostname:
    - a.test, bad host
  url-rewrite:
    - ^ok _ reject
    - \"# note\"
    - (broken _ reject
  script:
    - x = type=dns,script-path=a.js
",
        );
        assert_eq!(
            warnings,
            [
                (
                    "mitm_line".into(),
                    "mitm.hostname[0]".into(),
                    "line 4: \"a.test, bad host\": \"bad host\": unsupported character ' '".into(),
                ),
                (
                    "mitm_line".into(),
                    "mitm.url-rewrite[2]".into(),
                    format!(
                        "line 8: \"(broken _ reject\": {}",
                        fancy_regex::Regex::new("(broken").unwrap_err()
                    ),
                ),
                (
                    "mitm_line".into(),
                    "mitm.script[0]".into(),
                    "line 10: \"x = type=dns,script-path=a.js\": dns scripts are not supported"
                        .into(),
                ),
            ]
        );
    }

    #[test]
    fn a_section_that_is_off_reports_no_lines() {
        let warnings = mitm_warnings("mitm: {enable: false, url-rewrite: [broken]}\n");
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_section_that_cannot_be_read_leaves_mitm_off() {
        let profile = load_str(
            "mitm: {enable: true, hostname: 5}\n",
            &LoadOptions::default(),
        )
        .unwrap();
        assert!(!profile.mitm.enable);
        assert_eq!(profile.report.warnings.len(), 1);
        assert_eq!(profile.report.warnings[0].code, "mitm_section");
        assert_eq!(profile.report.warnings[0].path, "mitm");
    }

    #[test]
    fn lines_read_into_typed_definitions() {
        let def = MitmDef::read(&MitmSection {
            enable: true,
            url_rewrite: vec![
                "".into(),
                r"^http://a\.test/(.*) http://b.test/$1 302".into(),
            ],
            header_rewrite: vec![
                "http-response ^https://a request-head x-y header-add X-K v w".into(),
            ],
            map_local: vec!["^https://a data-type=base64 data=aGk= status-code=404".into()],
            script: vec![
                "s = type=cron,cronexp=\"0 * * * *\",timeout=7200,script-path=d/s.js".into(),
            ],
            ..MitmSection::default()
        });
        let url = def.url_rewrite[0].read.as_ref().unwrap();
        assert_eq!(def.url_rewrite[0].index, 1);
        assert_eq!(url.action, UrlAction::Redirect302);
        assert_eq!(url.replacement, "http://b.test/$1");
        let header = def.header_rewrite[0].read.as_ref().unwrap();
        assert!(header.response);
        assert_eq!(header.conditions.request.as_deref(), Some("x-y"));
        assert_eq!(
            header.edit,
            HeaderEditDef::Add(
                http::HeaderName::from_static("x-k"),
                http::HeaderValue::from_static("v w")
            )
        );
        let local = def.map_local[0].read.as_ref().unwrap();
        assert_eq!(local.body, MapLocalBody::Base64(b"hi".to_vec()));
        assert_eq!(local.status, http::StatusCode::NOT_FOUND);
        assert_eq!(local.content_type, "application/octet-stream");
        let script = def.script[0].read.as_ref().unwrap();
        assert_eq!((script.kind, script.name.as_str()), (ScriptKind::Cron, "s"));
        assert_eq!(script.cronexp, "0 * * * *");
        assert_eq!(script.timeout, Some(7200.0));
    }

    #[test]
    fn a_line_with_a_bad_regex_is_a_pattern_issue() {
        for (line, read) in [
            ("(x _ reject", parse_url_rewrite("(x _ reject").err()),
            (
                "http-request ^a request-head (x header-del X",
                parse_header_rewrite("http-request ^a request-head (x header-del X").err(),
            ),
            (
                "http-response ^a (x y",
                parse_body_rewrite("http-response ^a (x y").err(),
            ),
        ] {
            assert_eq!(read.map(|err| err.kind), Some(IssueKind::Pattern), "{line}");
        }
    }
}
