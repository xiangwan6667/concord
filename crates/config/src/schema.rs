use serde_json::{Map, Value, json};

use crate::keys;
use crate::proxy::{T0_PROXY_TYPES, T1_PROXY_TYPES, T2_PROXY_TYPES};
use crate::rule::{T0_RULE_TYPES, T1_RULE_TYPES};

fn tiers(t0: &[&str], t1: &[&str], t2: &[&str]) -> Value {
    json!({"t0": t0, "t1": t1, "t2": t2})
}

fn key_tiers(tiers: &keys::Tiers, defaults: Value) -> Value {
    json!({"t0": tiers.t0, "t1": tiers.t1, "t2": tiers.t2, "inert": tiers.inert, "defaults": defaults})
}

/// What a profile that leaves a key out gets, which is mihomo's default.
fn section_defaults(section: &str) -> Value {
    let dns = keys::dns_defaults();
    Value::Object(match section {
        "" => keys::general_defaults(),
        "dns" => dns,
        "dns.fallback-filter" => match dns.get("fallback-filter") {
            Some(Value::Object(filter)) => filter.clone(),
            _ => Map::new(),
        },
        "tun" => keys::tun_defaults(),
        "sniffer" => keys::sniffer_defaults(),
        "ntp" => keys::ntp_defaults(),
        "geox-url" => keys::geox_defaults(),
        "profile" => keys::profile_defaults(),
        _ => Map::new(),
    })
}

pub fn config_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("version".into(), json!(1));
    for (section, tiers) in keys::SECTIONS {
        let name = if section.is_empty() { "keys" } else { section };
        schema.insert(name.into(), key_tiers(tiers, section_defaults(section)));
    }
    schema.insert(
        "rule-types".into(),
        tiers(T0_RULE_TYPES, T1_RULE_TYPES, &[]),
    );
    schema.insert(
        "proxy-types".into(),
        tiers(T0_PROXY_TYPES, T1_PROXY_TYPES, T2_PROXY_TYPES),
    );
    schema.insert(
        "group-types".into(),
        json!(["select", "url-test", "fallback", "load-balance"]),
    );
    schema.insert("proxy-groups".into(), key_tiers(&keys::GROUP, json!({})));
    Value::Object(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo xtask mihomo-keys <checkout>` writes it from mihomo's `config/config.go`.
    const MIHOMO_KEYS: &str = include_str!("../../../schema/mihomo-keys.json");

    #[test]
    fn every_key_mihomo_decodes_has_a_tier() {
        let mihomo: Value = serde_json::from_str(MIHOMO_KEYS).unwrap();
        let mut untiered = Vec::new();
        for (section, tiers) in keys::SECTIONS {
            let name = if section.is_empty() { "keys" } else { section };
            let listed = mihomo[name].as_array().unwrap_or_else(|| panic!("{name}"));
            for key in listed.iter().filter_map(Value::as_str) {
                if tiers.of(key).is_none() {
                    untiered.push(format!("{name}: {key}"));
                }
            }
        }
        assert!(
            untiered.is_empty(),
            "keys mihomo {} decodes without a tier: {untiered:?}",
            mihomo["mihomo"]
        );
    }

    #[test]
    fn the_schema_lists_every_tier() {
        let schema = config_schema();
        assert_eq!(
            schema["keys"]["t0"].as_array().map(Vec::len),
            Some(keys::TOP_T0.len())
        );
        assert_eq!(schema["keys"]["inert"], json!(["geodata-loader"]));
        assert_eq!(
            schema["rule-types"]["t0"].as_array().map(Vec::len),
            Some(30)
        );
        assert!(
            schema["proxy-types"]["t2"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "tailscale"))
        );
    }
}
