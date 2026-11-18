use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// The release `opt-level` a crate is built with. `Speed` is what the data path
/// needs: a crate that falls back to the workspace's `z` runs slower without any
/// other sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opt {
    Inherit,
    Size,
    Speed,
}

impl Opt {
    fn of(level: Option<&str>) -> Option<Self> {
        match level {
            None => Some(Opt::Inherit),
            Some("s") => Some(Opt::Size),
            Some("3") => Some(Opt::Speed),
            Some(_) => None,
        }
    }
}

/// Each crate, its release `opt-level`, and exactly the workspace crates it
/// depends on directly.
const LAYERS: &[(&str, Opt, &[&str])] = &[
    ("concord-common", Opt::Speed, &[]),
    ("concord-config", Opt::Size, &["concord-common"]),
    (
        "concord-rules",
        Opt::Size,
        &["concord-common", "concord-config"],
    ),
    ("concord-platform", Opt::Inherit, &["concord-common"]),
    (
        "concord-net",
        Opt::Speed,
        &["concord-common", "concord-platform"],
    ),
    (
        "concord-tls",
        Opt::Speed,
        &["concord-common", "concord-platform"],
    ),
    (
        "concord-transport",
        Opt::Speed,
        &["concord-common", "concord-tls"],
    ),
    (
        "concord-proxy",
        Opt::Speed,
        &[
            "concord-common",
            "concord-config",
            "concord-net",
            "concord-tls",
            "concord-transport",
            "concord-platform",
            "concord-netstack",
        ],
    ),
    (
        "concord-dns",
        Opt::Inherit,
        &[
            "concord-common",
            "concord-config",
            "concord-tls",
            "concord-transport",
            "concord-platform",
        ],
    ),
    (
        "concord-group",
        Opt::Speed,
        &[
            "concord-common",
            "concord-config",
            "concord-platform",
            "concord-proxy",
            "concord-tls",
        ],
    ),
    (
        "concord-tunnel",
        Opt::Speed,
        &[
            "concord-common",
            "concord-rules",
            "concord-dns",
            "concord-group",
            "concord-net",
            "concord-platform",
        ],
    ),
    (
        "concord-inbound",
        Opt::Speed,
        &["concord-common", "concord-platform"],
    ),
    (
        "concord-netstack",
        Opt::Speed,
        &["concord-common", "concord-platform"],
    ),
    (
        "concord-tun",
        Opt::Speed,
        &["concord-common", "concord-platform", "concord-netstack"],
    ),
    (
        "concord-engine",
        Opt::Inherit,
        &[
            "concord-common",
            "concord-config",
            "concord-rules",
            "concord-platform",
            "concord-net",
            "concord-tls",
            "concord-proxy",
            "concord-dns",
            "concord-group",
            "concord-tunnel",
            "concord-inbound",
            "concord-tun",
            "concord-mitm",
        ],
    ),
    (
        "concord-mitm",
        Opt::Inherit,
        &[
            "concord-common",
            "concord-config",
            "concord-platform",
            "concord-tls",
        ],
    ),
    ("concord-proto", Opt::Inherit, &[]),
    (
        "concord-api",
        Opt::Inherit,
        &["concord-common", "concord-engine", "concord-proto"],
    ),
    (
        "concord-controller",
        Opt::Inherit,
        &["concord-api", "concord-proto"],
    ),
    (
        "concord-rpc",
        Opt::Inherit,
        &["concord-api", "concord-proto"],
    ),
    (
        "concord-ipc",
        Opt::Inherit,
        &["concord-rpc", "concord-proto"],
    ),
    ("concord-ffi", Opt::Inherit, &["concord-api", "concord-rpc"]),
    ("concord-test-support", Opt::Inherit, &[]),
];

const BINS: &[&str] = &["concord-desktop", "concord-android"];

/// Third-party packages a crate must not reach through its normal dependencies,
/// resolved for that crate alone so features other crates turn on do not hide it.
const FORBIDDEN: &[(&str, &[&str])] = &[
    // The parser and the rule compiler stay synchronous: `concord-common`'s `io`
    // feature is what keeps tokio out, and a workspace build unifies it away.
    ("concord-config", &["tokio"]),
    ("concord-rules", &["tokio"]),
];

pub fn check() -> Result<(), String> {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .map_err(|err| format!("cargo metadata: {err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout).map_err(|err| err.to_string())?;
    let root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .ok_or("cargo metadata has no workspace_root")?;
    let manifest = std::fs::read_to_string(Path::new(root).join("Cargo.toml"))
        .map_err(|err| format!("{root}/Cargo.toml: {err}"))?;

    let mut problems = violations(&workspace_graph(&metadata, false));
    problems.extend(bin_dependents(&workspace_graph(&metadata, true)));
    problems.extend(opt_level_problems(&release_opt_levels(&manifest)));
    for (name, forbidden) in FORBIDDEN {
        let reached = normal_dependencies(name)?;
        problems.extend(forbidden_problems(name, forbidden, &reached));
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems.join("\n"))
}

fn workspace_graph(metadata: &Value, with_dev: bool) -> BTreeMap<String, BTreeSet<String>> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let names: BTreeSet<&str> = packages
        .iter()
        .filter_map(|package| package.get("name").and_then(Value::as_str))
        .collect();
    packages
        .iter()
        .filter_map(|package| {
            let name = package.get("name")?.as_str()?.to_string();
            let dependencies = package
                .get("dependencies")?
                .as_array()?
                .iter()
                .filter(|dependency| {
                    with_dev || dependency.get("kind").and_then(Value::as_str) != Some("dev")
                })
                .filter_map(|dependency| dependency.get("name")?.as_str())
                .filter(|dependency| names.contains(dependency))
                .map(str::to_string)
                .collect();
            Some((name, dependencies))
        })
        .collect()
}

fn violations(graph: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, dependencies) in graph {
        if !name.starts_with("concord-") || BINS.contains(&name.as_str()) {
            continue;
        }
        let Some((_, _, permitted)) = LAYERS.iter().find(|(layer, _, _)| layer == name) else {
            problems.push(format!("{name} has no entry in the layer table"));
            continue;
        };
        for dependency in dependencies {
            if !permitted.contains(&dependency.as_str()) {
                problems.push(format!("{name} must not depend on {dependency}"));
            }
        }
        for listed in *permitted {
            if !dependencies.contains(*listed) {
                problems.push(format!(
                    "{name} lists {listed} in the layer table but does not depend on it"
                ));
            }
        }
    }
    for (name, _, _) in LAYERS {
        if !graph.contains_key(*name) {
            problems.push(format!(
                "{name} is in the layer table but not in the workspace"
            ));
        }
    }
    problems
}

fn bin_dependents(graph: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    graph
        .iter()
        .flat_map(|(name, dependencies)| {
            dependencies
                .iter()
                .filter(|dependency| BINS.contains(&dependency.as_str()))
                .map(move |bin| format!("{name} must not depend on the binary {bin}"))
        })
        .collect()
}

/// `[profile.release.package.<name>]` sections and the `opt-level` each sets.
fn release_opt_levels(manifest: &str) -> BTreeMap<String, Option<String>> {
    let mut levels = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            current = line
                .strip_prefix("[profile.release.package.")
                .and_then(|rest| rest.strip_suffix(']'))
                .map(|name| name.trim_matches('"').to_string());
            if let Some(name) = &current {
                levels.insert(name.clone(), None);
            }
            continue;
        }
        let Some(name) = &current else {
            continue;
        };
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == "opt-level"
        {
            let value = value.trim().trim_matches('"').to_string();
            levels.insert(name.clone(), Some(value));
        }
    }
    levels
}

fn opt_level_problems(levels: &BTreeMap<String, Option<String>>) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, expected, _) in LAYERS {
        let set = levels.get(*name).map(Option::as_deref);
        let actual = match set {
            None => Some(Opt::Inherit),
            Some(level) => Opt::of(level),
        };
        if actual != Some(*expected) {
            problems.push(format!(
                "{name} is built with opt-level {} in release, the layer table says {expected:?}",
                set.flatten().unwrap_or("inherited"),
            ));
        }
    }
    for name in levels.keys() {
        if name.starts_with("concord-") && !LAYERS.iter().any(|(layer, _, _)| layer == name) {
            problems.push(format!(
                "{name} has a release profile but no entry in the layer table"
            ));
        }
    }
    problems
}

fn normal_dependencies(name: &str) -> Result<BTreeSet<String>, String> {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree", "-p", name, "-e", "normal", "--target", "all", "--prefix", "none", "--format",
            "{p}",
        ])
        .output()
        .map_err(|err| format!("cargo tree: {err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect())
}

fn forbidden_problems(name: &str, forbidden: &[&str], reached: &BTreeSet<String>) -> Vec<String> {
    forbidden
        .iter()
        .filter(|package| reached.contains(**package))
        .map(|package| format!("{name} must not depend on {package}, even indirectly"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(edges: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
        edges
            .iter()
            .map(|(name, dependencies)| {
                (
                    (*name).to_string(),
                    dependencies.iter().map(|d| (*d).to_string()).collect(),
                )
            })
            .collect()
    }

    fn table_graph() -> BTreeMap<String, BTreeSet<String>> {
        let edges: Vec<(&str, &[&str])> = LAYERS
            .iter()
            .map(|(name, _, deps)| (*name, *deps))
            .collect();
        graph(&edges)
    }

    #[test]
    fn the_table_as_written_passes() {
        assert!(violations(&table_graph()).is_empty());
    }

    #[test]
    fn an_upward_dependency_is_reported() {
        let mut graph = table_graph();
        graph
            .get_mut("concord-rules")
            .unwrap()
            .insert("concord-tunnel".to_string());
        assert_eq!(
            violations(&graph),
            ["concord-rules must not depend on concord-tunnel"]
        );
    }

    #[test]
    fn an_entry_without_a_dependency_is_reported() {
        let mut graph = table_graph();
        graph
            .get_mut("concord-group")
            .unwrap()
            .remove("concord-proxy");
        assert_eq!(
            violations(&graph),
            ["concord-group lists concord-proxy in the layer table but does not depend on it"]
        );
    }

    #[test]
    fn a_new_crate_needs_a_table_entry() {
        let mut graph = table_graph();
        graph.insert("concord-new".to_string(), BTreeSet::new());
        assert_eq!(
            violations(&graph),
            ["concord-new has no entry in the layer table"]
        );
    }

    #[test]
    fn a_dependency_on_a_binary_is_reported() {
        let problems = bin_dependents(&graph(&[("concord-ipc", &["concord-desktop"])]));
        assert_eq!(
            problems,
            ["concord-ipc must not depend on the binary concord-desktop"]
        );
    }

    #[test]
    fn opt_levels_are_read_per_package() {
        let levels = release_opt_levels(
            "[profile.release]\nopt-level = \"z\"\n\n\
             [profile.release.package.concord-net]\nopt-level = 3\n\n\
             [profile.release.package.\"concord-config\"]\nopt-level = \"s\"\n\n\
             [patch.crates-io]\nopt-level = 1\n",
        );
        assert_eq!(
            levels,
            BTreeMap::from([
                ("concord-config".to_string(), Some("s".to_string())),
                ("concord-net".to_string(), Some("3".to_string())),
            ])
        );
    }

    #[test]
    fn a_data_plane_crate_left_at_the_default_is_reported() {
        let mut levels: BTreeMap<String, Option<String>> = LAYERS
            .iter()
            .filter_map(|(name, opt, _)| {
                let level = match opt {
                    Opt::Inherit => return None,
                    Opt::Size => "s",
                    Opt::Speed => "3",
                };
                Some(((*name).to_string(), Some(level.to_string())))
            })
            .collect();
        assert!(opt_level_problems(&levels).is_empty());

        levels.remove("concord-tunnel");
        levels.insert("concord-quic".to_string(), Some("3".to_string()));
        assert_eq!(
            opt_level_problems(&levels),
            [
                "concord-tunnel is built with opt-level inherited in release, the layer table says Speed",
                "concord-quic has a release profile but no entry in the layer table",
            ]
        );
    }

    #[test]
    fn a_forbidden_package_is_reported() {
        let reached = BTreeSet::from(["serde".to_string(), "tokio".to_string()]);
        assert_eq!(
            forbidden_problems("concord-config", &["tokio"], &reached),
            ["concord-config must not depend on tokio, even indirectly"]
        );
        assert!(forbidden_problems("concord-config", &["hyper"], &reached).is_empty());
    }
}
