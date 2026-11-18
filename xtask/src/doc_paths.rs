//! Holds the repository paths the docs name in backticks to files and directories that exist, and a
//! `path:line` to a line the file has. A path that names an upstream project's file is listed in
//! `UPSTREAM`.

use std::path::Path;
use std::process::Command;

const ROOTS: &[&str] = &[
    ".agents/", ".github/", "assets/", "bins/", "cmake/", "crates/", "docs/", "fuzz/", "schema/",
    "tools/", "vendor/", "xtask/",
];
const EXTRA_DOCS: &[&str] = &["xtask/tunables.txt"];
const PRIVATE: &str = "docs/private/";
const SKIPPED: &[&str] = &["vendor/", PRIVATE];
const UPSTREAM: &[&str] = &[
    // shadowsocks-rust's local service, cited in `reference-choices.md`.
    "crates/shadowsocks-service/src/local/utils.rs",
];

fn check(root: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .args(["ls-files", "-z", "--", "*.md"])
        .current_dir(root)
        .output()
        .map_err(|err| format!("git: {err}"))?;
    let mut docs: Vec<String> = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .filter(|path| !SKIPPED.iter().any(|skip| path.starts_with(skip)))
        .collect();
    docs.extend(EXTRA_DOCS.iter().map(|path| path.to_string()));
    let mut problems = Vec::new();
    for doc in docs {
        let text =
            std::fs::read_to_string(root.join(&doc)).map_err(|err| format!("{doc}: {err}"))?;
        for (number, line) in text.lines().enumerate() {
            for (path, at) in references(line) {
                if let Some(problem) = problem(root, path, at) {
                    problems.push(format!("{doc}:{}: {problem}", number + 1));
                }
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

/// Each backticked span that starts at a repository root and is a plain path, with its `:line` if any.
fn references(line: &str) -> Vec<(&str, Option<usize>)> {
    line.split('`')
        .skip(1)
        .step_by(2)
        .filter(|span| ROOTS.iter().any(|root| span.starts_with(root)))
        .filter_map(|span| {
            let (path, at) = match span.rsplit_once(':') {
                Some((path, number)) => (path, Some(number.parse().ok()?)),
                None => (span, None),
            };
            let plain = path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c));
            plain.then_some((path, at))
        })
        .collect()
}

fn problem(root: &Path, path: &str, at: Option<usize>) -> Option<String> {
    if UPSTREAM.contains(&path) || path.starts_with(PRIVATE) {
        return None;
    }
    let full = root.join(path);
    if !full.exists() {
        return Some(format!("`{path}` does not exist"));
    }
    let at = at?;
    let lines = std::fs::read_to_string(&full).ok()?.lines().count();
    (at == 0 || at > lines).then(|| format!("`{path}:{at}` is past the file's {lines} lines"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_docs_name_paths_that_exist() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check(&root) {
            panic!("{problems}");
        }
    }

    #[test]
    fn references_keep_paths_and_lines_and_skip_the_rest() {
        let line = "see `crates/tun/src/lib.rs:12`, `crates/*/src`, `cargo xtask`, `xtask/src` and \
                    `crates/a.rs::copy`";
        assert_eq!(
            references(line),
            vec![("crates/tun/src/lib.rs", Some(12)), ("xtask/src", None)]
        );
    }

    #[test]
    fn a_missing_path_and_a_line_past_the_end_are_reported() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert!(problem(&root, "crates/no-such-crate/src/lib.rs", None).is_some());
        assert!(problem(&root, "xtask/Cargo.toml", Some(100_000)).is_some());
        assert!(problem(&root, "xtask/Cargo.toml", Some(1)).is_none());
    }
}
