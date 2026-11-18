use concord_config::group::{GroupDef, parse_group};
use concord_config::{LoadOptions, load_str};
use serde_json::{Value, json};

fn group(options: Value) -> GroupDef {
    let mut map = json!({"name": "g", "type": "url-test", "proxies": ["DIRECT"]})
        .as_object()
        .unwrap()
        .clone();
    map.extend(options.as_object().unwrap().clone());
    parse_group(&map).unwrap()
}

#[test]
fn group_health_options_keep_defaults_separate_from_explicit_values() {
    let def = group(json!({}));
    assert_eq!((def.url.as_str(), def.empty_fallback.as_str()), ("", ""));
    assert_eq!(def.explicit_url, None);
    assert!(!def.explicit_empty_fallback);
    assert_eq!(def.interval, 0);
    assert!(def.interval_is_zero);
    assert!(!def.builtin_global);

    let def =
        group(json!({"url": "https://probe.test/", "interval": 90, "empty-fallback": "DIRECT"}));
    assert_eq!(def.url, "https://probe.test/");
    assert_eq!(def.explicit_url.as_deref(), Some("https://probe.test/"));
    assert_eq!(def.empty_fallback, "DIRECT");
    assert!(def.explicit_empty_fallback);
    assert_eq!(def.interval, 90);
    assert!(!def.interval_is_zero);

    for empty in [Value::Null, json!("")] {
        let def = group(json!({"url": empty, "empty-fallback": empty}));
        assert!(def.url.is_empty() && def.empty_fallback.is_empty());
        assert_eq!(def.explicit_url, None);
        assert!(!def.explicit_empty_fallback);
    }
}

#[test]
fn group_zero_interval_preserves_decimal_and_scalar_distinctions() {
    for (value, interval, zero) in [
        (Value::Null, 0, true),
        (json!(0), 0, true),
        (json!(" 0 "), 0, true),
        (json!("+0"), 0, true),
        (json!("0x0"), 0, false),
        (json!("0o0"), 0, false),
        (json!("00_0"), 0, false),
        (json!(0.0), 0, false),
        (json!(0.5), 0, false),
        (json!("90"), 90, false),
        (json!(u32::MAX), u32::MAX, false),
    ] {
        let def = group(json!({"interval": value}));
        assert_eq!(
            (def.interval, def.interval_is_zero),
            (interval, zero),
            "{value}"
        );
    }
}

#[test]
fn group_text_coercion_does_not_make_an_explicit_runtime_override() {
    for value in [json!(123), json!(false), json!(1.5)] {
        let def = group(json!({"url": value, "empty-fallback": value}));
        assert!(!def.url.is_empty() && !def.empty_fallback.is_empty());
        assert_eq!(def.explicit_url, None);
        assert!(!def.explicit_empty_fallback);
    }
    let def =
        group(json!({"URL": "https://probe.test/", "INTERVAL": 90, "EMPTY-FALLBACK": "DIRECT"}));
    assert_eq!(def.url, "https://probe.test/");
    assert_eq!(def.interval, 90);
    assert_eq!(def.empty_fallback, "DIRECT");
    assert_eq!(def.explicit_url, None);
    assert!(def.interval_is_zero);
    assert!(!def.explicit_empty_fallback);
}

#[test]
fn invalid_group_health_options_are_rejected_with_the_key_and_line() {
    for (key, values) in [
        (
            "interval",
            vec!["-1", "4294967296", "abc", "false", "'0_0'", "[]", "{}"],
        ),
        ("url", vec!["[]", "{}"]),
        ("empty-fallback", vec!["[]", "{}", "missing", "GLOBAL"]),
    ] {
        for value in values {
            let text = format!(
                "proxy-groups:\n  - {{name: g, type: url-test, proxies: [DIRECT], {key}: {value}}}\n"
            );
            let err = load_str(&text, &LoadOptions::default()).unwrap_err();
            assert_eq!(err.line, Some(2), "{key}: {value}: {err}");
            assert!(
                err.message.contains(key) || err.message.contains("empty fallback"),
                "{err}"
            );
        }
    }
}

#[test]
fn resolved_group_defaults_keep_the_original_interval_and_builtin_origin() {
    let options = LoadOptions::default();
    let profile = load_str(
        "proxy-groups: [{name: g, type: url-test, proxies: [DIRECT]}]",
        &options,
    )
    .unwrap();
    let def = &profile.groups[0];
    assert_eq!(def.interval, 300);
    assert!(def.interval_is_zero);
    assert_eq!(def.url, "https://www.gstatic.com/generate_204");
    assert_eq!(def.explicit_url, None);
    assert_eq!(def.empty_fallback, "COMPATIBLE");
    assert!(!def.explicit_empty_fallback && !def.builtin_global);
    assert!(
        profile
            .groups
            .iter()
            .find(|def| def.name == "GLOBAL")
            .unwrap()
            .builtin_global
    );

    let profile = load_str(
        "proxy-groups: [{name: GLOBAL, type: select, proxies: [DIRECT]}]",
        &options,
    )
    .unwrap();
    assert!(!profile.groups[0].builtin_global);
    assert!(load_str("proxy-groups: [{}]", &options).is_err());
}
