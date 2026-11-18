//! `xtask mihomo-keys <mihomo checkout>`: the profile keys mihomo's `config/config.go` decodes,
//! per section, written to `schema/mihomo-keys.json` with the commit they were read at.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Map, Value, json};

/// Each section `config-schema.json` tiers, and the struct mihomo decodes it into.
const SECTIONS: [(&str, &str); 8] = [
    ("keys", "RawConfig"),
    ("dns", "RawDNS"),
    ("dns.fallback-filter", "RawFallbackFilter"),
    ("tun", "RawTun"),
    ("sniffer", "RawSniffer"),
    ("ntp", "RawNTP"),
    ("geox-url", "RawGeoXUrl"),
    ("profile", "RawProfile"),
];

fn snapshot_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../schema/mihomo-keys.json")
}

pub fn run(checkout: Option<&str>) -> Result<(), String> {
    let checkout = Path::new(checkout.ok_or("usage: xtask mihomo-keys <mihomo checkout>")?);
    let source = checkout.join("config/config.go");
    let text = fs::read_to_string(&source).map_err(|err| format!("{}: {err}", source.display()))?;
    let commit = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .map_err(|err| format!("git: {err}"))?;
    let commit = String::from_utf8_lossy(&commit.stdout).trim().to_string();
    if commit.is_empty() {
        return Err(format!("{} is not a git checkout", checkout.display()));
    }
    let mut out = Map::new();
    out.insert("mihomo".into(), json!(commit));
    for (section, name) in SECTIONS {
        out.insert(section.into(), json!(struct_keys(&text, name)?));
    }
    let mut rendered =
        serde_json::to_string_pretty(&Value::Object(out)).map_err(|err| err.to_string())?;
    rendered.push('\n');
    let path = snapshot_path();
    fs::write(&path, rendered).map_err(|err| format!("{}: {err}", path.display()))
}

fn struct_keys(text: &str, name: &str) -> Result<Vec<String>, String> {
    let open = format!("type {name} struct {{");
    let body = text
        .split_once(&open)
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map(|(body, _)| body)
        .ok_or_else(|| format!("config.go has no {name}"))?;
    let keys = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter_map(|line| line.split_once("yaml:\"").map(|(_, tag)| tag))
        .filter_map(|tag| tag.split(['"', ',']).next())
        .filter(|key| !key.is_empty() && *key != "-")
        .map(str::to_string)
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return Err(format!("{name} has no yaml tags"));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_read_in_order_and_comments_skipped() {
        let text = "type RawX struct {\n\
                    \tA bool `yaml:\"a\" json:\"a\"`\n\
                    \t//B int `yaml:\"b\"`\n\
                    \tC int `yaml:\"c,omitempty\"`\n\
                    \tD int `yaml:\"-\"`\n\
                    \n\tE map[string]any `yaml:\"e\"`\n}\n\
                    type RawY struct {\n\tF bool `yaml:\"f\"`\n}\n";
        assert_eq!(struct_keys(text, "RawX").unwrap(), ["a", "c", "e"]);
        assert!(struct_keys(text, "RawZ").is_err());
    }
}
