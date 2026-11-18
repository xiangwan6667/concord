use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

pub use concord_config::mitm::MitmSection as RawConfig;
use concord_config::mitm::text::quote;
use concord_config::mitm::{HostEntryDef, IssueKind, Items, LineError, MitmDef, MitmLine, Read};
use serde::Serialize;

use crate::hostlist::HostList;
use crate::limits::{Limits, Resolve};
use crate::rules::{
    Rules, compile_body_rewrite, compile_header_rewrite, compile_map_local, compile_url_rewrite,
};
use crate::script::{ScriptHost, compile_script};
use crate::sources::SourceList;
use crate::view::{LineView, SourcesView};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub index: usize,
    pub kind: IssueKind,
    pub message: String,
}

pub struct ParseEnv {
    pub resources: PathBuf,
    pub scripts: Arc<ScriptHost>,
}

pub struct Config {
    pub enable: bool,
    pub decrypt_tls: bool,
    pub ca_fingerprint: String,
    pub hosts: HostList,
    pub skip_server_cert_verify: bool,
    pub skip_verify_hosts: HostList,
    pub(crate) sources: SourceList,
    pub auto_quic_block: bool,
    pub h2: bool,
    pub limits: Limits,
    pub(crate) rules: Rules,
    /// Plain HTTP on port 80 is read whatever its host while a rule can act on a request, as
    /// Surge's HTTP engine reads it without a hostname entry.
    pub(crate) plain_http: bool,
    def: MitmDef,
}

/// What a line put in force and what of it could not be read or compiled: a hostname or
/// source line has both when some of its items apply. `unread` marks an error the section's
/// reading found, before any compiling.
struct LineRead {
    view: Option<LineView>,
    error: Option<LineError>,
    unread: bool,
}

/// The list's key, the line's index in it and its text.
type Visit<'a> = dyn FnMut(&'static str, usize, &str, LineRead) + 'a;

fn items<T>(read: &Items<T>, view: Option<LineView>) -> LineRead {
    LineRead {
        view,
        error: read.error.clone(),
        unread: true,
    }
}

fn compiled<D, R>(
    read: &Read<D>,
    compile: impl FnOnce(&D) -> Result<R, LineError>,
    add: impl FnOnce(R) -> LineView,
) -> LineRead {
    let (view, error, unread) = match read.as_ref().map(compile) {
        Err(err) => (None, Some(err.clone()), true),
        Ok(Err(err)) => (None, Some(err), false),
        Ok(Ok(rule)) => (Some(add(rule)), None, false),
    };
    LineRead {
        view,
        error,
        unread,
    }
}

fn each<T>(
    key: &'static str,
    lines: &[MitmLine<T>],
    visit: &mut Visit<'_>,
    mut read: impl FnMut(&T) -> LineRead,
) {
    for line in lines {
        visit(key, line.index, &line.text, read(&line.read));
    }
}

fn read_hosts(list: &mut HostList, read: &Items<HostEntryDef>) -> LineRead {
    let hosts = HostList::from(read.items.clone());
    let view = hosts.view();
    list.extend(hosts);
    items(read, view)
}

impl Config {
    fn empty(def: &MitmDef) -> Config {
        Config {
            enable: def.enable,
            decrypt_tls: def.decrypt_tls.unwrap_or(true),
            ca_fingerprint: normalize_fingerprint(&def.ca_fingerprint),
            hosts: HostList::default(),
            skip_server_cert_verify: def.skip_server_cert_verify,
            skip_verify_hosts: HostList::default(),
            sources: SourceList::default(),
            auto_quic_block: def.auto_quic_block.unwrap_or(true),
            h2: def.h2,
            limits: def.limits.resolve(),
            rules: Rules::default(),
            plain_http: false,
            def: MitmDef::default(),
        }
    }

    /// Puts each line of `def` in force, list by list, and hands it with how it read to `visit`.
    fn add_lines(&mut self, def: &MitmDef, env: &ParseEnv, visit: &mut Visit<'_>) {
        each("hostname", &def.hostname, visit, |read| {
            read_hosts(&mut self.hosts, read)
        });
        each(
            "skip-server-cert-verify-hostname",
            &def.skip_server_cert_verify_hostname,
            visit,
            |read| read_hosts(&mut self.skip_verify_hosts, read),
        );
        each(
            "client-source-address",
            &def.client_source_address,
            visit,
            |read| {
                let entries = self.sources.add(&read.items);
                let view =
                    (!entries.is_empty()).then_some(LineView::Sources(SourcesView { entries }));
                items(read, view)
            },
        );
        let rules = &mut self.rules;
        each("url-rewrite", &def.url_rewrite, visit, |read| {
            compiled(read, compile_url_rewrite, |rule| {
                let view = rule.view();
                rules.url_rewrites.push(rule);
                view
            })
        });
        each("header-rewrite", &def.header_rewrite, visit, |read| {
            compiled(read, compile_header_rewrite, |rule| {
                let view = rule.view();
                rules.header_rewrites.push(rule);
                view
            })
        });
        each("body-rewrite", &def.body_rewrite, visit, |read| {
            compiled(read, compile_body_rewrite, |rule| {
                let view = rule.view();
                rules.body_rewrites.push(Arc::new(rule));
                view
            })
        });
        let local = |def: &_| compile_map_local(def, &env.resources);
        each("map-local", &def.map_local, visit, |read| {
            compiled(read, local, |(rule, view)| {
                rules.map_locals.push(rule);
                view
            })
        });
        each("request-body-mock", &def.request_body_mock, visit, |read| {
            compiled(read, local, |(rule, view)| {
                rules.request_mocks.push(rule);
                view
            })
        });
        each("script", &def.script, visit, |read| {
            compiled(
                read,
                |def| compile_script(def, &env.resources, &env.scripts),
                |script| {
                    let view = script.view();
                    rules.scripts.push(Arc::new(script));
                    view
                },
            )
        });
    }

    /// Lines that cannot be read are skipped and named in the errors.
    pub fn parse(raw: RawConfig, env: &ParseEnv) -> (Config, Vec<String>) {
        Config::compile(MitmDef::read(&raw), env, true)
    }

    /// The section in force, and the lines that could not be compiled, with those that
    /// could not be read when `unread`.
    pub(crate) fn compile(def: MitmDef, env: &ParseEnv, unread: bool) -> (Config, Vec<String>) {
        let mut config = Config::empty(&def);
        let mut errors = Vec::new();
        config.add_lines(&def, env, &mut |key, _, text, read| {
            if let Some(err) = read.error
                && (unread || !read.unread)
            {
                errors.push(format!("{key} {}: {err}", quote(text)));
            }
        });
        env.scripts.keep(&config.rules.scripts);
        config.plain_http = config.rules.acts_on_requests();
        config.def = def;
        (config, errors)
    }

    pub fn same(&self, other: &Config) -> bool {
        self.def.reads_the_same(&other.def)
    }

    pub fn script_names(&self) -> Vec<&str> {
        self.rules
            .scripts
            .iter()
            .map(|script| script.name.as_str())
            .collect()
    }
}

/// By list, the lines that cannot be read, and how each line in force reads; a line some of
/// whose items apply is in both.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Validation {
    pub issues: BTreeMap<String, Vec<Issue>>,
    pub views: BTreeMap<String, Vec<LineEntry>>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LineEntry {
    pub index: usize,
    pub view: LineView,
}

pub fn check(raw: &RawConfig, env: &ParseEnv) -> Validation {
    let mut validation = Validation::default();
    let mut scratch = Config::empty(&MitmDef::default());
    scratch.add_lines(&MitmDef::read(raw), env, &mut |key, index, _, read| {
        if let Some(err) = read.error {
            let issue = Issue {
                index,
                kind: err.kind,
                message: err.message,
            };
            validation
                .issues
                .entry(key.to_string())
                .or_default()
                .push(issue);
        }
        if let Some(view) = read.view {
            let entry = LineEntry { index, view };
            validation
                .views
                .entry(key.to_string())
                .or_default()
                .push(entry);
        }
    });
    validation
}

/// Upper-case hex pairs joined by colons.
pub fn normalize_fingerprint(text: &str) -> String {
    let hex: String = text
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != ' ')
        .collect::<String>()
        .to_uppercase();
    let mut pairs = Vec::with_capacity(hex.len() / 2 + 1);
    let mut rest = hex.as_str();
    while rest.len() > 2 {
        let (pair, tail) = rest.split_at(2);
        pairs.push(pair);
        rest = tail;
    }
    if !rest.is_empty() {
        pairs.push(rest);
    }
    pairs.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> (tempfile::TempDir, ParseEnv) {
        let home = tempfile::tempdir().unwrap();
        let env = ParseEnv {
            resources: home.path().join("resources"),
            scripts: Arc::new(ScriptHost::default()),
        };
        (home, env)
    }

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn check_names_the_item_of_a_hostname_line() {
        let (_home, env) = env();
        let raw = RawConfig {
            hostname: lines(&["b.com", "a.com, bad host"]),
            ..RawConfig::default()
        };
        let issues = check(&raw, &env).issues;
        let want = vec![Issue {
            index: 1,
            kind: IssueKind::Invalid,
            message: "\"bad host\": unsupported character ' '".to_string(),
        }];
        assert_eq!(issues, BTreeMap::from([("hostname".to_string(), want)]));
    }

    #[test]
    fn validate_names_the_lines_of_each_list() {
        let (_home, env) = env();
        let raw = RawConfig {
            hostname: lines(&["a.test"]),
            url_rewrite: lines(&["^ok _ reject", "(broken _ reject", "# note"]),
            ..RawConfig::default()
        };
        let issues = check(&raw, &env).issues;
        assert_eq!(issues.len(), 1);
        assert_eq!(issues["url-rewrite"].len(), 1);
        assert_eq!(issues["url-rewrite"][0].index, 1);
    }

    #[test]
    fn parse_names_the_bad_line() {
        let (_home, env) = env();
        let raw = RawConfig {
            url_rewrite: lines(&["# comment", "", "^ok _ reject", "broken"]),
            map_local: lines(&["^x data-type=nope"]),
            ..RawConfig::default()
        };
        let (_, errors) = Config::parse(raw, &env);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(
            errors[0].contains("url-rewrite \"broken\""),
            "{}",
            errors[0]
        );
        assert!(errors[1].contains("map-local"), "{}", errors[1]);
    }

    #[test]
    fn a_profile_section_leaves_the_lines_it_cannot_read_to_its_load() {
        let (_home, env) = env();
        let raw = RawConfig {
            enable: true,
            url_rewrite: lines(&["broken"]),
            map_local: lines(&["^x data=missing.json"]),
            ..RawConfig::default()
        };
        let (_, errors) = Config::compile(MitmDef::read(&raw), &env, false);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].starts_with("map-local"), "{}", errors[0]);
        let (_, errors) = Config::parse(raw, &env);
        assert_eq!(errors.len(), 2, "{errors:?}");
    }

    #[test]
    fn defaults_follow_the_go_core() {
        let (_home, env) = env();
        let (config, errors) = Config::parse(
            RawConfig {
                enable: true,
                ..RawConfig::default()
            },
            &env,
        );
        assert!(errors.is_empty());
        assert!(config.decrypt_tls && config.auto_quic_block && !config.h2);
    }

    #[test]
    fn same_compares_the_section_not_the_compiled_rules() {
        let (_home, env) = env();
        let raw = RawConfig {
            enable: true,
            hostname: lines(&["a.test"]),
            ..RawConfig::default()
        };
        let (a, _) = Config::parse(raw.clone(), &env);
        let (b, _) = Config::parse(raw.clone(), &env);
        let (c, _) = Config::parse(
            RawConfig {
                enable: false,
                ..raw
            },
            &env,
        );
        assert!(a.same(&b) && !a.same(&c));
    }

    #[test]
    fn same_ignores_where_comments_and_blank_lines_put_a_line() {
        let (_home, env) = env();
        let raw = RawConfig {
            enable: true,
            hostname: lines(&["a.test, b.test"]),
            url_rewrite: lines(&["^ok _ reject", "^next _ reject"]),
            ..RawConfig::default()
        };
        let (a, _) = Config::parse(raw.clone(), &env);
        let (moved, _) = Config::parse(
            RawConfig {
                hostname: lines(&["# hosts", "", "a.test,b.test"]),
                url_rewrite: lines(&["", "# ads", "  ^ok   _ reject", "^next _ reject"]),
                ..raw.clone()
            },
            &env,
        );
        let (swapped, _) = Config::parse(
            RawConfig {
                url_rewrite: lines(&["^next _ reject", "^ok _ reject"]),
                ..raw.clone()
            },
            &env,
        );
        let (changed, _) = Config::parse(
            RawConfig {
                url_rewrite: lines(&["^ok _ reject", "^other _ reject"]),
                ..raw
            },
            &env,
        );
        assert!(a.same(&moved));
        assert!(!a.same(&swapped) && !a.same(&changed));
    }

    #[test]
    fn raw_config_reads_the_wire_names_and_nulls() {
        let raw: RawConfig = serde_json::from_str(
            r#"{"enable":true,"hostname":null,"skip-server-cert-verify":true,"decrypt-tls":false,
            "ca-fingerprint":"ab","h2":true,"limits":{"max-body-size":10}}"#,
        )
        .unwrap();
        assert!(raw.enable && raw.skip_server_cert_verify && raw.h2);
        assert_eq!(raw.decrypt_tls, Some(false));
        assert_eq!(raw.limits.max_body_size, 10);
        assert!(raw.hostname.is_empty());
    }

    #[test]
    fn the_section_reads_its_hosts_and_switches() {
        let (_home, env) = env();
        let raw: RawConfig = serde_json::from_value(serde_json::json!({
            "enable": true,
            "hostname": ["-skip.a.test", "*.a.test"],
            "url-rewrite": [r"^https://x\.a\.test/ad _ reject", "broken"],
        }))
        .unwrap();
        let (config, errors) = Config::parse(raw, &env);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(config.enable && config.auto_quic_block);
        assert!(config.hosts.matches("x.a.test", 443) && !config.hosts.matches("skip.a.test", 443));

        let raw: RawConfig = serde_json::from_value(serde_json::json!({
            "enable": true,
            "decrypt-tls": false,
            "ca-fingerprint": "aa:bb",
            "h2": true,
        }))
        .unwrap();
        let (config, _) = Config::parse(raw, &env);
        assert!(!config.decrypt_tls && config.h2);
        assert_eq!(config.ca_fingerprint, "AA:BB");
    }

    #[test]
    fn fingerprints_normalize() {
        assert_eq!(normalize_fingerprint(" ab:cd ef "), "AB:CD:EF");
        assert_eq!(normalize_fingerprint("aabbcc"), "AA:BB:CC");
        assert_eq!(normalize_fingerprint(" AA:bb:CC "), "AA:BB:CC");
        assert_eq!(normalize_fingerprint("aa bb cc"), "AA:BB:CC");
        assert_eq!(normalize_fingerprint("AA:BB:CC:DD"), "AA:BB:CC:DD");
        assert_eq!(normalize_fingerprint("abc"), "AB:C");
        assert_eq!(normalize_fingerprint(""), "");
    }
}
