//! `xtask check-interop-peers`: every peer an ignored test needs, in an integration test target that CI's
//! `interop` job runs with `--ignored`, is either provided to that step (by an action or a `run` line that
//! writes `$GITHUB_ENV`, the step's `env:`, or an `export`) or the test is left out with `--skip`, which a
//! comment right above the step names. A test names its peers in `#[ignore = "needs CONCORD_…"]` and
//! through `concord_test_support::peer("CONCORD_…")`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const WORKFLOW: &str = ".github/workflows/ci.yaml";
const JOB: &str = "interop";

pub fn check() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let problems = problems(&root)?;
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

struct Step {
    comment: String,
    name: String,
    lines: Vec<String>,
}

fn problems(root: &Path) -> Result<Vec<String>, String> {
    let workflow = read(root, WORKFLOW)?;
    let steps = job_steps(&workflow, JOB).ok_or(format!("{WORKFLOW} has no `{JOB}` job"))?;
    let mut persisted = BTreeSet::new();
    let mut problems = Vec::new();
    let mut checked = 0;
    for step in &steps {
        for line in &step.lines {
            if let Some(action) = line.trim().strip_prefix("uses: ./") {
                let text = read(root, &format!("{action}/action.yml"))?;
                persisted.extend(text.lines().flat_map(github_env_writes));
            }
        }
        persisted.extend(step.lines.iter().flat_map(|line| github_env_writes(line)));
        let mut provided = persisted.clone();
        provided.extend(step.lines.iter().flat_map(|line| assignments(line)));
        let words: Vec<&str> = step
            .lines
            .iter()
            .flat_map(|l| l.split_whitespace())
            .collect();
        let Some((package, target, skips)) = ignored_test_run(&words) else {
            continue;
        };
        checked += 1;
        for skip in &skips {
            if !step.comment.contains(skip.as_str()) {
                problems.push(format!(
                    "{WORKFLOW}: step `{}` skips `{skip}` without a comment above it that names the test and says why",
                    step.name
                ));
            }
        }
        let tests = ignored_tests(root, &package, &target)?;
        for skip in &skips {
            if !tests.iter().any(|test| test.name.contains(skip.as_str())) {
                problems.push(format!(
                    "{WORKFLOW}: step `{}` skips `{skip}`, which matches no ignored test in `{package}` `--test {target}`",
                    step.name
                ));
            }
        }
        for test in &tests {
            if skips.iter().any(|skip| test.name.contains(skip.as_str())) {
                continue;
            }
            for peer in test.peers.difference(&provided) {
                problems.push(format!(
                    "{}: `{}` needs {peer}, which the `{JOB}` step `{}` neither provides nor skips",
                    test.at, test.name, step.name
                ));
            }
        }
    }
    if checked == 0 {
        problems.push(format!(
            "{WORKFLOW}: the `{JOB}` job runs no `cargo test … --test <target> -- --ignored`"
        ));
    }
    Ok(problems)
}

fn read(root: &Path, path: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(path)).map_err(|err| format!("{path}: {err}"))
}

/// The steps of `job`, each with the comment lines just above it.
fn job_steps(workflow: &str, job: &str) -> Option<Vec<Step>> {
    let mut lines = workflow
        .lines()
        .skip_while(|line| *line != format!("  {job}:"));
    lines.next()?;
    let mut steps = Vec::new();
    let mut comment = String::new();
    for line in lines {
        if line.starts_with("  ") && !line.starts_with("   ") && !line.trim().starts_with('#') {
            break;
        }
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with('#') && indent <= 6 {
            comment.push_str(trimmed);
            comment.push('\n');
        } else if let Some(first) = trimmed.strip_prefix("- ") {
            let name = first.strip_prefix("name: ").unwrap_or(first).to_string();
            steps.push(Step {
                comment: std::mem::take(&mut comment),
                name,
                lines: vec![first.to_string()],
            });
        } else if indent > 6
            && let Some(step) = steps.last_mut()
        {
            step.lines.push(line.to_string());
        } else {
            comment.clear();
        }
    }
    Some(steps)
}

/// Variables a line writes to `$GITHUB_ENV`, so later steps of the job have them.
fn github_env_writes(line: &str) -> Vec<String> {
    if line.contains("GITHUB_ENV") {
        assignments(line)
    } else {
        Vec::new()
    }
}

/// `CONCORD_…` names set on a line: `NAME=…`, `export NAME=…` or an `env:` key `NAME: …`.
fn assignments(line: &str) -> Vec<String> {
    variables(line)
        .filter(|(_, rest)| rest.starts_with('=') || rest.starts_with(':'))
        .map(|(name, _)| name)
        .collect()
}

/// Each `CONCORD_…` name in `text`, with the text after it.
fn variables(text: &str) -> impl Iterator<Item = (String, &str)> {
    text.match_indices("CONCORD_").filter_map(move |(at, _)| {
        if text[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return None;
        }
        let len = text[at..]
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(text.len() - at);
        Some((text[at..at + len].to_string(), &text[at + len..]))
    })
}

/// The package, test target and `--skip` filters of a `cargo test -p <package> --test <target> -- --ignored`.
fn ignored_test_run(words: &[&str]) -> Option<(String, String, Vec<String>)> {
    let cargo = words.windows(2).position(|w| w == ["cargo", "test"])?;
    let words = &words[cargo..];
    let split = words.iter().position(|w| *w == "--")?;
    let (cargo_args, test_args) = (&words[..split], &words[split + 1..]);
    let after = |flag: &str, args: &[&str]| {
        args.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].to_string())
            .collect::<Vec<_>>()
    };
    if !test_args.contains(&"--ignored") {
        return None;
    }
    let package = after("-p", cargo_args).pop()?;
    let target = after("--test", cargo_args).pop()?;
    Some((package, target, after("--skip", test_args)))
}

struct Test {
    name: String,
    at: String,
    peers: BTreeSet<String>,
}

/// The ignored tests of `package`'s `tests/<target>.rs` and the modules under `tests/<target>/`, each with
/// the peers it names. A `peer(…)` call outside any test (a helper above the first one) counts for
/// every ignored test of its file.
fn ignored_tests(root: &Path, package: &str, target: &str) -> Result<Vec<Test>, String> {
    let dir = package_dir(root, package)?;
    let main = dir.join("tests").join(format!("{target}.rs"));
    let mut files = vec![(main.clone(), String::new())];
    if let Ok(entries) = std::fs::read_dir(dir.join("tests").join(target)) {
        let mut modules: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
            .collect();
        modules.sort();
        for path in modules {
            let module = path.file_stem().unwrap().to_string_lossy().into_owned();
            files.push((path, format!("{module}::")));
        }
    }
    let mut tests = Vec::new();
    for (path, prefix) in files {
        let text =
            std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
        let shown = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        tests.extend(file_tests(&text, &prefix, &shown));
    }
    Ok(tests)
}

fn file_tests(text: &str, prefix: &str, shown: &str) -> Vec<Test> {
    let lines: Vec<&str> = text.lines().collect();
    let is_test = |line: &str| {
        let line = line.trim();
        line == "#[test]" || line.starts_with("#[tokio::test")
    };
    let starts: Vec<usize> = (0..lines.len()).filter(|&i| is_test(lines[i])).collect();
    let shared: BTreeSet<String> = lines[..starts.first().copied().unwrap_or(lines.len())]
        .iter()
        .flat_map(|line| peer_calls(line))
        .collect();
    let mut tests = Vec::new();
    for (n, &start) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(lines.len());
        let span = &lines[start..end];
        let Some(ignore) = span.iter().position(|l| l.trim().starts_with("#[ignore")) else {
            continue;
        };
        let Some(name) = span.iter().find_map(|line| function_name(line)) else {
            continue;
        };
        let mut peers: BTreeSet<String> = variables(span[ignore]).map(|(name, _)| name).collect();
        peers.extend(span.iter().flat_map(|line| peer_calls(line)));
        peers.extend(shared.iter().cloned());
        tests.push(Test {
            name: format!("{prefix}{name}"),
            at: format!("{shown}:{}", start + ignore + 1),
            peers,
        });
    }
    tests
}

fn peer_calls(line: &str) -> Vec<String> {
    line.split("peer(\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(name, _)| name.to_string()))
        .collect()
}

fn function_name(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix("async ").unwrap_or(line.trim());
    let rest = rest.strip_prefix("fn ")?;
    rest.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()
}

fn package_dir(root: &Path, package: &str) -> Result<PathBuf, String> {
    let manifest = read(root, "Cargo.toml")?;
    let wanted = format!("name = \"{package}\"");
    manifest
        .lines()
        .skip_while(|line| !line.starts_with("members"))
        .skip(1)
        .take_while(|line| !line.starts_with(']'))
        .filter_map(|line| {
            line.trim()
                .trim_end_matches(',')
                .strip_prefix('"')?
                .strip_suffix('"')
        })
        .map(|member| root.join(member))
        .find(|dir| {
            std::fs::read_to_string(dir.join("Cargo.toml"))
                .is_ok_and(|text| text.lines().any(|line| line.trim() == wanted))
        })
        .ok_or(format!("no workspace member is the package `{package}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTION: &str =
        "runs:\n  steps:\n    - run: echo \"CONCORD_MIHOMO=$peer\" >> \"$GITHUB_ENV\"\n";
    const TESTS: &str =
        "#[tokio::test]\n#[ignore = \"needs CONCORD_MIHOMO\"]\nasync fn talks_to_mihomo() {}\n";
    const MODULE: &str = "#[tokio::test]\n#[ignore]\nasync fn talks_to_xray() {\n    \
                          let _ = concord_test_support::peer(\"CONCORD_XRAY\");\n}\n";
    const FETCH_XRAY: &str =
        "      - name: Fetch xray\n        run: echo \"CONCORD_XRAY=/x\" >> \"$GITHUB_ENV\"\n\n";
    const SKIP_REASON: &str = "      # talks_to_xray needs Xray, which this job does not fetch.\n";

    /// A repository whose `interop` job fetches mihomo, runs `extra`, then runs the tests with `skips` under
    /// `comment`; another job exports CONCORD_XRAY.
    fn problems_with(extra: &str, comment: &str, skips: &str) -> Vec<String> {
        let workflow = format!(
            "jobs:\n  interop:\n    steps:\n      - name: Fetch mihomo\n        uses: ./.github/actions/mihomo\n\n\
             {extra}{comment}      - name: Run the interop tests\n        run: >-\n          \
             cargo test --locked -p concord-proxy --test interop --\n          --ignored{skips}\n\n  \
             other:\n    steps:\n      - run: export CONCORD_XRAY=/bin/xray\n"
        );
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in [
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\n    \"crates/proxy\",\n]\n",
            ),
            (
                "crates/proxy/Cargo.toml",
                "[package]\nname = \"concord-proxy\"\n",
            ),
            ("crates/proxy/tests/interop.rs", TESTS),
            ("crates/proxy/tests/interop/xray.rs", MODULE),
            (".github/actions/mihomo/action.yml", ACTION),
            (WORKFLOW, &workflow),
        ] {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        problems(dir.path()).unwrap()
    }

    #[test]
    fn the_interop_job_provides_or_skips_every_peer() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let problems = problems(&root).unwrap();
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    #[test]
    fn a_provided_peer_or_an_explained_skip_passes() {
        assert_eq!(problems_with(FETCH_XRAY, "", ""), Vec::<String>::new());
        assert_eq!(
            problems_with("", SKIP_REASON, " --skip talks_to_xray"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_missing_peer_fails_even_when_another_job_sets_it() {
        let found = problems_with("", "", "");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with(
                "crates/proxy/tests/interop/xray.rs:2: `xray::talks_to_xray` needs CONCORD_XRAY"
            ),
            "{found:?}"
        );
    }

    #[test]
    fn a_skip_without_a_reason_or_without_a_test_fails() {
        let found = problems_with("", "", " --skip talks_to_xray");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("skips `talks_to_xray` without a comment"),
            "{found:?}"
        );

        let comment = "      # gone_test and talks_to_xray are left out on purpose.\n";
        let found = problems_with("", comment, " --skip gone_test --skip talks_to_xray");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("skips `gone_test`, which matches no ignored test"),
            "{found:?}"
        );
    }
}
