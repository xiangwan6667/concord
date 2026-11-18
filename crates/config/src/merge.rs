use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::Map;
use crate::crypt;
use crate::error::{ConfigError, Result};
use crate::raw::{expect_strings, parse_raw_with_key};
use crate::rule::RuleLines;
use crate::yaml::{self, ParsedDocument};

const PROFILE_SECTIONS: [&str; 3] = ["proxies", "proxy-groups", "sub-rules"];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProfileBase {
    pub config: Value,
    pub digest: String,
    #[serde(rename = "match-rules")]
    pub match_rules: Vec<String>,
    pub proxies: usize,
    #[serde(rename = "proxy-groups")]
    pub proxy_groups: usize,
    pub rules: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProfileOutbound {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProfileOutbounds {
    pub proxies: Vec<ProfileOutbound>,
    #[serde(rename = "proxy-groups")]
    pub proxy_groups: Vec<ProfileOutbound>,
}

pub fn is_match_rule(rule: &str) -> bool {
    let kind = rule.split(',').next().unwrap_or_default();
    kind.trim_matches(|c: char| c.is_whitespace())
        .eq_ignore_ascii_case("MATCH")
}

pub fn profile_base(bytes: &[u8], age_secret_key: Option<&str>) -> Result<ProfileBase> {
    let digest = hex::encode(Sha256::digest(bytes));
    let raw = parse_raw_with_key(bytes, age_secret_key)?;
    Ok(ProfileBase {
        digest,
        match_rules: raw
            .rules
            .iter()
            .filter(|rule| is_match_rule(rule))
            .map(str::to_string)
            .collect(),
        proxies: raw.proxies.len(),
        proxy_groups: raw.proxy_groups.len(),
        rules: raw.rules.len(),
        config: raw.to_json_light(),
    })
}

fn outbounds(items: &[Map]) -> Vec<ProfileOutbound> {
    items
        .iter()
        .map(|item| {
            let text = |key: &str| {
                item.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            ProfileOutbound {
                name: text("name"),
                kind: text("type"),
            }
        })
        .collect()
}

pub fn profile_outbounds(bytes: &[u8], age_secret_key: Option<&str>) -> Result<ProfileOutbounds> {
    let raw = parse_raw_with_key(bytes, age_secret_key)?;
    Ok(ProfileOutbounds {
        proxies: outbounds(&raw.proxies),
        proxy_groups: outbounds(&raw.proxy_groups),
    })
}

fn no_rules(rules: Option<&Value>) -> bool {
    match rules {
        None | Some(Value::Null) => true,
        Some(Value::Array(items)) => items.is_empty(),
        Some(_) => false,
    }
}

fn rules_after(added: Option<Value>, profile: RuleLines) -> Result<RuleLines> {
    if no_rules(added.as_ref()) {
        return Ok(profile);
    }
    let added = match added {
        Some(value @ Value::Array(_)) => expect_strings(value, "rules")?,
        _ => return Err(ConfigError::new("rules must be a list")),
    };
    let bytes = added.iter().map(String::len).sum::<usize>();
    let mut merged =
        RuleLines::with_text_capacity(bytes + profile.iter().map(str::len).sum::<usize>());
    added.iter().for_each(|line| merged.push(line));
    profile.iter().for_each(|line| merged.push(line));
    Ok(merged)
}

fn value_after(added: Option<Value>, profile: Value) -> Result<Value> {
    if no_rules(added.as_ref()) {
        return Ok(profile);
    }
    let Some(added) = added else {
        return Ok(profile);
    };
    match (added, profile) {
        (added, Value::Null) => Ok(added),
        (Value::Array(mut first), Value::Array(second)) => {
            first.extend(second);
            Ok(Value::Array(first))
        }
        _ => Err(ConfigError::new("rules must be a list")),
    }
}

/// The overlay over the profile, without the text round trip: the profile's heavy
/// sections replace the overlay's, and rules the overlay adds go first.
pub fn merge_document(
    profile: &[u8],
    overlay: &str,
    age_secret_key: Option<&str>,
) -> Result<ParsedDocument> {
    let keys: Vec<&str> = age_secret_key.into_iter().collect();
    let plain = crypt::decrypt_config(profile, &keys)?;
    let text = std::str::from_utf8(&plain)
        .map_err(|_| ConfigError::new("yaml: invalid leading UTF-8 octet"))?;
    let mut merged = yaml::parse_document(text.strip_prefix('\u{feff}').unwrap_or(text))?;
    let overlay = yaml::parse_document(overlay.strip_prefix('\u{feff}').unwrap_or(overlay))?;
    let mut root = overlay.root;
    for key in PROFILE_SECTIONS {
        if let Some(value) = merged.root.remove(key) {
            root.insert(key.to_string(), value);
        }
    }
    let added = match overlay.rules {
        Some(lines) => Some(Value::Array(
            lines
                .iter()
                .map(|line| Value::String(line.to_string()))
                .collect(),
        )),
        None => root.shift_remove("rules"),
    };
    if !no_rules(added.as_ref()) {
        merged.lines.rules.clear();
    }
    merged.lines.mitm = overlay.lines.mitm;
    let rules = match (merged.rules.take(), merged.root.remove("rules")) {
        (Some(lines), _) => Some(rules_after(added, lines)?),
        (None, Some(value)) => {
            root.insert("rules".to_string(), value_after(added, value)?);
            None
        }
        (None, None) => {
            if let Some(added) = added {
                root.insert("rules".to_string(), added);
            }
            None
        }
    };
    Ok(ParsedDocument {
        root,
        lines: merged.lines,
        rules,
        ..ParsedDocument::default()
    })
}

pub fn merge_profile(
    profile: &[u8],
    overlay: &str,
    age_secret_key: Option<&str>,
) -> Result<String> {
    let merged = merge_document(profile, overlay, age_secret_key)?;
    let mut out = String::new();
    yaml::write_map(&mut out, &merged.root);
    if let Some(rules) = &merged.rules {
        yaml::write_rules(&mut out, "rules", rules);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::raw::{RawConfig, parse_raw_str, raw_to_yaml};

    fn merged(profile: &[u8], overlay: &str) -> Result<RawConfig> {
        RawConfig::from_document(merge_document(profile, overlay, None)?)
    }

    const BASE: &str = r#"x-defaults: &socks {type: socks5, server: 127.0.0.1, port: 1080}
mixed-port: 7000
dns:
  enable: true
  nameserver: [223.5.5.5]
proxies:
  - {<<: *socks, name: a}
  - name: b
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 2a70e3a9-b4ce-4f20-908d-e99950a0a611
    network: tcp
    tls: true
    reality-opts: {public-key: SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc, short-id: 0123}
proxy-groups:
  - {name: g, type: select, proxies: [a, b]}
sub-rules:
  sub: ["MATCH,g"]
rules:
  - DOMAIN-SUFFIX,example.com,g
  - match,DIRECT
  - MATCH,g
"#;

    fn overlay_of(base: &ProfileBase, rules: &[&str], patch: Value) -> String {
        let mut overlay = base.config.as_object().cloned().unwrap_or_default();
        overlay.remove("rule");
        overlay.insert("rules".into(), json!(rules));
        if let Value::Object(patch) = patch {
            overlay.extend(patch);
        }
        Value::Object(overlay).to_string()
    }

    #[test]
    fn base_leaves_the_bulk_sections_out_and_counts_them() {
        let base = profile_base(BASE.as_bytes(), None).unwrap();
        for key in ["proxies", "proxy-groups", "rule", "sub-rules"] {
            assert_eq!(base.config[key], Value::Null, "{key}");
        }
        assert_eq!(base.config["mixed-port"], 7000);
        assert_eq!(base.config["dns"]["enable"], true);
        assert_eq!((base.proxies, base.proxy_groups, base.rules), (2, 1, 3));
        assert_eq!(base.match_rules, ["match,DIRECT", "MATCH,g"]);
        assert_eq!(base.digest, hex::encode(Sha256::digest(BASE.as_bytes())));
    }

    #[test]
    fn outbounds_list_names_and_types_only() {
        let outbounds = profile_outbounds(BASE.as_bytes(), None).unwrap();
        let names: Vec<(&str, &str)> = outbounds
            .proxies
            .iter()
            .map(|o| (o.name.as_str(), o.kind.as_str()))
            .collect();
        assert_eq!(names, [("a", "socks5"), ("b", "vless")]);
        assert_eq!(outbounds.proxy_groups[0].kind, "select");
    }

    #[test]
    fn merging_puts_added_rules_first_and_the_overlay_over_the_rest() {
        let base = profile_base(BASE.as_bytes(), None).unwrap();
        let overlay = overlay_of(
            &base,
            &["DOMAIN,added.test,DIRECT"],
            json!({"mixed-port": 7890, "dns": {"enable": true, "nameserver": ["1.1.1.1"]}}),
        );
        let raw = merged(BASE.as_bytes(), &overlay).unwrap();
        assert_eq!(
            raw.rules,
            [
                "DOMAIN,added.test,DIRECT",
                "DOMAIN-SUFFIX,example.com,g",
                "match,DIRECT",
                "MATCH,g"
            ]
        );
        assert_eq!(raw.general["mixed-port"], 7890);
        assert_eq!(raw.dns["nameserver"], json!(["1.1.1.1"]));
        assert_eq!(raw.proxies.len(), 2);
        assert_eq!(raw.proxies[0]["server"], "127.0.0.1");
        assert_eq!(raw.sub_rules["sub"], ["MATCH,g"]);
        assert_eq!(raw.proxies[1]["reality-opts"]["short-id"], "0123");
    }

    #[test]
    fn the_merged_text_loads_without_the_profile() {
        let base = profile_base(BASE.as_bytes(), None).unwrap();
        let raw = merged(
            BASE.as_bytes(),
            &overlay_of(&base, &["DOMAIN,added.test,DIRECT"], json!({})),
        )
        .unwrap();
        let again = parse_raw_str(&raw_to_yaml(&raw)).unwrap();
        assert_eq!(again.rules.len(), 4);
        assert_eq!(again.proxies.len(), 2);
        assert_eq!(again.proxies[1]["reality-opts"]["short-id"], "0123");
    }

    #[test]
    fn the_built_text_reads_back_as_the_merged_config() {
        let base = profile_base(BASE.as_bytes(), None).unwrap();
        let overlay = overlay_of(&base, &["DOMAIN,added.test,DIRECT"], json!({}));
        let built = merge_profile(BASE.as_bytes(), &overlay, None).unwrap();
        let again = parse_raw_str(&built).unwrap();
        assert_eq!(
            again.rules,
            merged(BASE.as_bytes(), &overlay).unwrap().rules
        );
        assert_eq!(again.rules.len(), 4);
        assert_eq!(again.proxies.len(), 2);
    }

    #[test]
    fn an_empty_profile_keeps_the_overlay() {
        let raw = merged(b"", r#"{"rules": ["MATCH,DIRECT"]}"#).unwrap();
        assert_eq!(raw.rules, ["MATCH,DIRECT"]);
    }

    #[test]
    fn a_profile_that_is_not_a_mapping_is_rejected() {
        assert!(merged(b"- a\n- b\n", "{}").is_err());
        assert!(merged(BASE.as_bytes(), "- a").is_err());
    }

    #[test]
    fn rules_that_are_not_lists_are_rejected() {
        let err = merged(b"rules: x\n", r#"{"rules": ["MATCH,DIRECT"]}"#).unwrap_err();
        assert!(err.message.contains("rules must be a list"));
    }

    #[test]
    fn match_rules_are_found_by_their_first_field() {
        assert!(is_match_rule(" match ,DIRECT"));
        assert!(!is_match_rule("DOMAIN,match,DIRECT"));
    }
}
