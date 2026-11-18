use std::process::Command;

#[test]
fn config_check_validates_group_health_options() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("profile.yaml");
    for (options, valid, key) in [
        ("", true, ""),
        ("url: https://probe.test/", true, "url"),
        ("url: null", true, "url"),
        ("url: []", false, "url"),
        ("interval: 0", true, "interval"),
        ("interval: '0x0'", true, "interval"),
        ("interval: 90", true, "interval"),
        ("interval: null", true, "interval"),
        ("interval: -1", false, "interval"),
        ("interval: abc", false, "interval"),
        ("empty-fallback: DIRECT", true, "empty-fallback"),
        ("empty-fallback: null", true, "empty-fallback"),
        ("empty-fallback: []", false, "empty-fallback"),
        ("empty-fallback: missing", false, "empty fallback"),
    ] {
        std::fs::write(
            &config,
            format!("proxy-groups: [{{name: g, type: url-test, proxies: [DIRECT], {options}}}]\n"),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_concord"))
            .args(["-t", "-c"])
            .arg(&config)
            .output()
            .unwrap();
        let answer: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            output.status.code(),
            Some(if valid { 0 } else { 1 }),
            "{options}: {answer}"
        );
        if valid {
            assert_eq!(answer["warnings"], serde_json::json!([]), "{options}");
        } else {
            assert!(
                answer["error"].as_str().unwrap().contains(key),
                "{options}: {answer}"
            );
        }
    }
}
