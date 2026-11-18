use std::any::Any;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::{Path, PathBuf};

use concord_config::proxy::ProxyParse;
use concord_config::{
    LoadOptions, Map, crypt, filter, load_raw, parse_proxy, parse_raw, share_link,
};
use concord_platform::HomeDir;
use serde_json::Value;

use crate::apply;
use crate::error::Failure;
use crate::views::{ValidationIssue, WarningView};

const PARSE_STACK_BYTES: usize = 32 * 1024 * 1024;

/// YAML, regex and JSON trees all recurse with the depth of the document.
pub(crate) async fn on_parse_stack<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Failure> {
    let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<T, Box<dyn Any + Send>>>();
    std::thread::Builder::new()
        .name("concord-parse".to_string())
        .stack_size(PARSE_STACK_BYTES)
        .spawn(move || {
            let _ = result_tx.send(catch_unwind(AssertUnwindSafe(work)));
        })
        .map_err(Failure::from)?;
    match result_rx.await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(panic)) => resume_unwind(panic),
        Err(_) => Err(Failure::core("the parse thread ended without an answer")),
    }
}

pub(crate) enum RuleSetSource {
    Downloaded(Vec<u8>),
    Local(PathBuf),
}

pub(crate) async fn compile_rule_set(
    source: RuleSetSource,
) -> Result<(Vec<u8>, concord_rules::CompiledRuleSet), Failure> {
    on_parse_stack(move || {
        let (bytes, allow_empty) = match source {
            RuleSetSource::Downloaded(bytes) => (bytes, false),
            RuleSetSource::Local(path) => (std::fs::read(path).map_err(Failure::from)?, true),
        };
        let compiled = concord_rules::compile_rule_set(&bytes, allow_empty)
            .map_err(|err| Failure::new(err.code(), err.to_string()))?;
        Ok((bytes, compiled))
    })
    .await?
}

pub(crate) fn read_file(path: &str) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|err| Failure::core(format!("open {path}: {}", io_message(&err))))
}

fn io_message(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::NotFound => "no such file or directory".to_string(),
        io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        io::ErrorKind::IsADirectory => "is a directory".to_string(),
        _ => err.to_string(),
    }
}

pub async fn validate_config(path: String) -> Result<Option<String>, Failure> {
    on_parse_stack(move || {
        let bytes = match read_file(&path) {
            Ok(bytes) => bytes,
            Err(failure) => return Some(failure.message),
        };
        parse_raw(&bytes).err().map(|err| err.to_string())
    })
    .await
}

/// Loads the profile at `path` as an apply would and returns what that apply would warn about,
/// without running anything.
pub async fn check_config(path: String, android: bool) -> Result<Vec<WarningView>, Failure> {
    on_parse_stack(move || {
        let raw = parse_raw(&read_file(&path)?).map_err(config_failure)?;
        let options = LoadOptions {
            capabilities: apply::capabilities(),
            android,
            age_secret_key: None,
        };
        let profile = load_raw(raw, &options).map_err(config_failure)?;
        Ok(apply::warning_views(&profile, android))
    })
    .await?
}

pub async fn read_config(path: String) -> Result<Value, Failure> {
    on_parse_stack(move || {
        let bytes = read_file(&path)?;
        let raw = parse_raw(&bytes).map_err(config_failure)?;
        Ok(raw.to_json())
    })
    .await?
}

/// The mapping a configured node was written with, as `config.yaml` has it now.
pub(crate) fn configured_proxy(path: &Path, name: &str) -> Result<Option<Map>, Failure> {
    let bytes = std::fs::read(path).map_err(Failure::from)?;
    let raw = parse_raw(&bytes).map_err(config_failure)?;
    Ok(raw
        .proxies
        .into_iter()
        .find(|proxy| proxy.get("name").and_then(Value::as_str) == Some(name)))
}

pub async fn decrypt_config(path: String, key: String) -> Result<String, Failure> {
    on_parse_stack(move || {
        let bytes = read_file(&path)?;
        let plain = crypt::decrypt_bytes(&bytes, &[key.as_str()]).map_err(config_failure)?;
        Ok(String::from_utf8_lossy(&plain).into_owned())
    })
    .await?
}

pub async fn profile_base(path: String) -> Result<Value, Failure> {
    on_parse_stack(move || {
        let bytes = read_file(&path)?;
        let base = concord_config::profile_base(&bytes, None).map_err(config_failure)?;
        serde_json::to_value(base).map_err(|err| Failure::core(err.to_string()))
    })
    .await?
}

pub async fn profile_outbounds(path: String) -> Result<Value, Failure> {
    on_parse_stack(move || {
        let bytes = read_file(&path)?;
        let outbounds = concord_config::profile_outbounds(&bytes, None).map_err(config_failure)?;
        serde_json::to_value(outbounds).map_err(|err| Failure::core(err.to_string()))
    })
    .await?
}

pub async fn merge_profile(path: String, overlay: String) -> Result<String, Failure> {
    on_parse_stack(move || {
        let bytes = read_file(&path)?;
        concord_config::merge_profile(&bytes, &overlay, None).map_err(config_failure)
    })
    .await?
}

pub async fn dump_rule_set(path: String) -> Result<String, Failure> {
    let bytes = read_file(&path)?;
    on_parse_stack(move || concord_rules::dump_mrs(&bytes))
        .await?
        .map_err(|errors| Failure::core(errors.join("\n")))
}

/// The id is rendered from an integer, so the last path element cannot carry a
/// separator or `..`; that is what keeps this from deleting anything else.
pub(crate) fn clear_effect(home: &HomeDir, profile_id: i64) -> Result<(), Failure> {
    if profile_id <= 0 {
        return Err(Failure::core("invalid profile id"));
    }
    let root = home.join("profiles").join("providers");
    match std::fs::remove_dir_all(root.join(profile_id.to_string())) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let _ = std::fs::remove_dir(root);
    Ok(())
}

pub fn validate_proxies(proxies: &[Map]) -> Vec<ValidationIssue> {
    let capabilities = crate::apply::capabilities();
    let mut issues = Vec::new();
    for (index, proxy) in proxies.iter().enumerate() {
        let message = match parse_proxy(proxy, &capabilities) {
            Ok(ProxyParse::Ok(_)) => continue,
            Ok(ProxyParse::Quarantined { reason, .. }) => reason,
            Err(err) => err.to_string(),
        };
        issues.push(ValidationIssue { index, message });
    }
    issues
}

pub async fn convert_proxies(path: String) -> Result<Vec<Map>, Failure> {
    on_parse_stack(move || {
        let bytes = read_file(&path)?;
        share_link::decode_subscription_bytes(&bytes).map_err(config_failure)
    })
    .await?
}

pub fn encode_share_links(proxies: &[Map]) -> Vec<String> {
    proxies.iter().map(share_link::encode_link).collect()
}

pub fn decode_share_links(lines: &[String]) -> Vec<Vec<Map>> {
    lines
        .iter()
        .map(|line| share_link::decode_link(line))
        .collect()
}

pub fn validate_filters(filters: &[String]) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    for (index, value) in filters.iter().enumerate() {
        if let Err(err) = filter::validate(value) {
            issues.push(ValidationIssue {
                index,
                message: err.to_string(),
            });
        }
    }
    issues
}

fn config_failure(err: concord_config::ConfigError) -> Failure {
    Failure::core(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panic_on_the_parse_stack_reaches_the_caller() {
        let handle = tokio::spawn(on_parse_stack(|| -> i32 { panic!("boom") }));
        assert!(handle.await.unwrap_err().is_panic());
    }

    #[tokio::test]
    async fn the_parse_stack_handles_deep_recursion() {
        fn depth(left: u32) -> u32 {
            let padding = [left; 64];
            if left == 0 {
                0
            } else {
                1 + depth(left - 1) + padding[0] - padding[63]
            }
        }
        assert_eq!(on_parse_stack(|| depth(50_000)).await.unwrap(), 50_000);
    }

    #[tokio::test]
    async fn a_check_reports_the_load_and_the_engine_warnings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            "geodata-mode: true\ntun: {enable: true, congestion-controller: bbr}\n",
        )
        .unwrap();
        let path = path.to_string_lossy().into_owned();
        let codes = |warnings: Vec<WarningView>| -> Vec<(String, &'static str)> {
            warnings.into_iter().map(|w| (w.path, w.code)).collect()
        };
        let desktop = codes(check_config(path.clone(), false).await.unwrap());
        assert!(desktop.contains(&("geodata-mode".into(), "unsupported_key")));
        assert!(desktop.contains(&("tun.congestion-controller".into(), "not_applied")));
        let android = codes(check_config(path, true).await.unwrap());
        assert!(!android.iter().any(|(path, _)| path.starts_with("tun.")));

        std::fs::write(dir.path().join("bad.yaml"), "mode: sideways\n").unwrap();
        let bad = dir.path().join("bad.yaml").to_string_lossy().into_owned();
        assert!(check_config(bad, false).await.is_err());
    }

    #[test]
    fn a_missing_file_reads_like_the_other_core() {
        let failure = read_file("/definitely/not/here").unwrap_err();
        assert_eq!(
            failure.message,
            "open /definitely/not/here: no such file or directory"
        );
    }

    #[test]
    fn clearing_effects_only_touches_the_profile_directory() {
        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::new(dir.path());
        let target = dir.path().join("profiles/providers/7");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("a.yaml"), "a").unwrap();
        std::fs::create_dir_all(dir.path().join("profiles/providers/8")).unwrap();

        clear_effect(&home, 7).unwrap();
        assert!(!target.exists());
        assert!(dir.path().join("profiles/providers/8").exists());

        clear_effect(&home, 8).unwrap();
        assert!(!dir.path().join("profiles/providers").exists());
        assert!(clear_effect(&home, 0).is_err());
        assert!(clear_effect(&home, -1).is_err());
    }

    #[test]
    fn share_link_lines_answer_one_by_one() {
        let results = decode_share_links(&["not a link".to_string()]);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_empty());
    }
}
