use serde_json::json;

use crate::config::{Config, ParseEnv, RawConfig, check};
use crate::script::ScriptResult;
use crate::script::testkit::{host_with, sync_program};

fn lines(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

fn env() -> (tempfile::TempDir, ParseEnv) {
    let home = tempfile::tempdir().unwrap();
    let resources = home.path().join("resources");
    let program = || sync_program(|_| Ok(ScriptResult::default()));
    let scripts = host_with(&resources, vec![("a", program()), ("b", program())]);
    (home, ParseEnv { resources, scripts })
}

#[test]
fn each_list_reads_as_its_view() {
    let (_home, env) = env();
    let raw = RawConfig {
        url_rewrite: lines(&[
            r"^https://a\.com/(.*) https://b.com/$1 302",
            r"^https://ad\.com _ reject-dict",
            r"^https://a\.com/x ^GET url-and-header https://c.com/ 307",
        ]),
        header_rewrite: lines(&[
            r"http-response ^https://a\.com header-replace-regex Set-Cookie (a)=1 $1=2",
            r"^https://a\.com request-head ^POST header-add x-token abc",
            r"^https://a\.com header-text-replace ^GET POST",
        ]),
        body_rewrite: lines(&[
            r"http-response ^https://a\.com/api ad x foo bar",
            r"http-response-jq ^https://a\.com/j '.a = 1'",
        ]),
        map_local: lines(&[
            r#"^https://a\.com/m data-type=text data="{}" status-code=404 header="X-A:1|Content-Type:application/json""#,
        ]),
        request_body_mock: lines(&[r"^https://a\.com/p data-type=tiny-gif"]),
        script: lines(&[
            "daily = type=cron, cronexp=0 8 * * *, script-path=a.js, timeout=10",
            r"http-response ^https://a\.com/x script-path=b.js, requires-body=true, tag=b",
        ]),
        ..RawConfig::default()
    };
    let validation = check(&raw, &env);
    assert!(validation.issues.is_empty(), "{:?}", validation.issues);
    let want = json!({
        "url-rewrite": [
            {"index": 0, "view": {"type": "urlRewrite", "pattern": r"^https://a\.com/(.*)",
                "action": "302", "replacement": "https://b.com/$1"}},
            {"index": 1, "view": {"type": "urlRewrite", "pattern": r"^https://ad\.com",
                "action": "reject-dict"}},
            {"index": 2, "view": {"type": "urlRewrite", "pattern": r"^https://a\.com/x",
                "action": "307", "replacement": "https://c.com/", "requestHead": "^GET"}},
        ],
        "header-rewrite": [
            {"index": 0, "view": {"type": "headerRewrite", "phase": "response",
                "pattern": r"^https://a\.com", "action": "header-replace-regex",
                "name": "Set-Cookie", "regex": "(a)=1", "replacement": "$1=2"}},
            {"index": 1, "view": {"type": "headerRewrite", "phase": "request",
                "pattern": r"^https://a\.com", "requestHead": "^POST", "action": "header-add",
                "name": "X-Token", "value": "abc"}},
            {"index": 2, "view": {"type": "headerRewrite", "phase": "request",
                "pattern": r"^https://a\.com", "action": "header-text-replace",
                "regex": "^GET", "replacement": "POST"}},
        ],
        "body-rewrite": [
            {"index": 0, "view": {"type": "bodyRewrite", "phase": "response",
                "pattern": r"^https://a\.com/api",
                "replacements": [{"regex": "ad", "replacement": "x"},
                    {"regex": "foo", "replacement": "bar"}]}},
            {"index": 1, "view": {"type": "bodyRewrite", "phase": "response",
                "pattern": r"^https://a\.com/j", "replacements": [], "jq": ".a = 1"}},
        ],
        "map-local": [
            {"index": 0, "view": {"type": "mapLocal", "pattern": r"^https://a\.com/m",
                "dataType": "text", "data": "{}", "status": 404,
                "headers": [{"name": "X-A", "value": "1"},
                    {"name": "Content-Type", "value": "application/json"}],
                "contentType": "application/json"}},
        ],
        "request-body-mock": [
            {"index": 0, "view": {"type": "mapLocal", "pattern": r"^https://a\.com/p",
                "dataType": "tiny-gif", "data": "", "headers": [], "contentType": "image/gif"}},
        ],
        "script": [
            {"index": 0, "view": {"type": "script", "name": "daily", "kind": "cron",
                "path": "a.js", "cronexp": "0 8 * * *", "requiresBody": false,
                "binaryBody": false, "timeoutMs": 10000}},
            {"index": 1, "view": {"type": "script", "name": "b", "kind": "httpResponse",
                "path": "b.js", "pattern": r"^https://a\.com/x", "requiresBody": true,
                "binaryBody": false, "timeoutMs": 5000}},
        ],
    });
    assert_eq!(serde_json::to_value(&validation.views).unwrap(), want);
}

#[test]
fn a_line_whose_items_partly_apply_has_a_view_of_those_and_an_issue() {
    let (_home, env) = env();
    let raw = RawConfig {
        hostname: lines(&[
            "a.com, bad host, -[::1]:8443",
            "bad host",
            "# note",
            "*.b.com:443",
        ]),
        client_source_address: lines(&["10.0.0.0/8, lan, 192.168.0.1", "-192.168.1.2"]),
        ..RawConfig::default()
    };
    let validation = check(&raw, &env);
    let issues = serde_json::to_value(&validation.issues).unwrap();
    assert_eq!(
        issues,
        json!({
            "hostname": [
                {"index": 0, "kind": "invalid", "message": "\"bad host\": unsupported character ' '"},
                {"index": 1, "kind": "invalid", "message": "\"bad host\": unsupported character ' '"},
            ],
            "client-source-address": [
                {"index": 0, "kind": "invalid", "message": "invalid address or CIDR \"lan\""},
            ],
        })
    );
    let views = serde_json::to_value(&validation.views).unwrap();
    assert_eq!(
        views,
        json!({
            "hostname": [
                {"index": 0, "view": {"type": "hosts", "entries": [
                    {"host": "a.com", "exclude": false},
                    {"host": "::1", "port": 8443, "exclude": true}]}},
                {"index": 3, "view": {"type": "hosts", "entries": [
                    {"host": "*.b.com", "port": 443, "exclude": false}]}},
            ],
            "client-source-address": [
                {"index": 0, "view": {"type": "sources", "entries": [
                    {"network": "10.0.0.0/8", "exclude": false}]}},
                {"index": 1, "view": {"type": "sources", "entries": [
                    {"network": "192.168.1.2/32", "exclude": true}]}},
            ],
        })
    );
}

#[test]
fn a_script_view_names_it_as_the_tasks_do() {
    let (_home, env) = env();
    let raw = RawConfig {
        enable: true,
        script: lines(&[
            r#"cron "0 8 * * *" script-path=a.js"#,
            "named = type=generic, script-path=b.js",
        ]),
        ..RawConfig::default()
    };
    let names: Vec<String> = check(&raw, &env).views["script"]
        .iter()
        .map(|entry| serde_json::to_value(&entry.view).unwrap()["name"].to_string())
        .map(|name| name.trim_matches('"').to_string())
        .collect();
    let (config, errors) = Config::parse(raw, &env);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(names, config.script_names());
}
