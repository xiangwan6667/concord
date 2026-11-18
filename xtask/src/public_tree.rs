//! Holds the published tree to what a reader outside the project can use. The docs state the current
//! rule, choice or number: no commit hash of this repository, no date, and no pointer into the
//! git-ignored `docs/private/` beyond one line in `AGENTS.md`. No tracked file outside `vendor/` names
//! a home directory or the project's internal coordination (`internal_marks`), and no tracked file that
//! is not Rust source names a public IPv4 host outside the documentation ranges and the public
//! resolvers. When `docs/private/public-tree-deny.txt` exists, no such file uses the names it lists
//! either.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::internal_marks;

const DOC_FILES: &[&str] = &[
    "AGENTS.md",
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "xtask/tunables.txt",
];
const DOC_DIRS: &[&str] = &[".agents", "docs"];
const POINTER_HOME: &str = "AGENTS.md";
const PRIVATE_DIR: &str = "docs/private";
const DENY_FILE: &str = "docs/private/public-tree-deny.txt";
/// Years a dated note could carry; a date outside them is a spec example, such as `1900-01-01`.
const HISTORY_YEARS: std::ops::RangeInclusive<u16> = 2020..=2039;
const HOMES: &[&str] = &["/Users/", "/home/"];
/// The checks themselves, which spell out what they look for.
const EXEMPT: &[&str] = &["xtask/src/public_tree.rs", "xtask/src/internal_marks.rs"];
const PUBLIC_RESOLVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(1, 0, 0, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(8, 8, 4, 4),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(114, 114, 114, 114),
    Ipv4Addr::new(119, 29, 29, 29),
    Ipv4Addr::new(223, 5, 5, 5),
    Ipv4Addr::new(223, 6, 6, 6),
];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let mut problems = Vec::new();
    let mut docs = Vec::new();
    for file in DOC_FILES {
        if let Ok(text) = std::fs::read_to_string(root.join(file)) {
            docs.push((file.to_string(), text));
        }
    }
    for dir in DOC_DIRS {
        let entries = std::fs::read_dir(root.join(dir)).map_err(|err| format!("{dir}: {err}"))?;
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".md"))
            .collect();
        names.sort();
        for name in names {
            let path = format!("{dir}/{name}");
            let text =
                std::fs::read_to_string(root.join(&path)).map_err(|e| format!("{path}: {e}"))?;
            docs.push((path, text));
        }
    }
    let candidates: Vec<String> = docs
        .iter()
        .flat_map(|(_, text)| hex_words(text))
        .map(str::to_string)
        .collect();
    let commits = concord_commits(root, &candidates);
    let deny = load_deny(root)?;
    for (path, text) in &docs {
        problems.extend(doc_problems(path, text, &commits));
    }
    for path in tracked(root) {
        if path.starts_with("vendor/")
            || path.ends_with("Cargo.lock")
            || EXEMPT.contains(&path.as_str())
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root.join(&path)) else {
            continue;
        };
        problems.extend(file_problems(&path, &text, &deny));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

/// A name the private deny list keeps out of the tree. A pattern ending in `_` or `-` matches a word
/// that starts with it, one ending in `/` a path that starts with it, and any other a whole word.
struct Deny {
    pattern: String,
    category: String,
}

impl Deny {
    fn matches(&self, line: &str) -> bool {
        if self.pattern.ends_with('/') {
            return line.match_indices(self.pattern.as_str()).any(|(start, _)| {
                !line[..start].ends_with(|c: char| c.is_ascii_alphanumeric() || "_/".contains(c))
            });
        }
        let prefix = self.pattern.ends_with(['_', '-']);
        internal_marks::words(line).any(|word| {
            if prefix {
                word.len() > self.pattern.len() && word.starts_with(self.pattern.as_str())
            } else {
                word == self.pattern
            }
        })
    }
}

/// Reads `<pattern> [category]` lines; `#` starts a comment. No file, no names.
fn load_deny(root: &Path) -> Result<Vec<Deny>, String> {
    let text = match std::fs::read_to_string(root.join(DENY_FILE)) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("{DENY_FILE}: {err}")),
    };
    Ok(text
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(body, _)| body).trim())
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (pattern, category) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let category = category.trim();
            Deny {
                pattern: pattern.to_string(),
                category: if category.is_empty() {
                    "a private name"
                } else {
                    category
                }
                .to_string(),
            }
        })
        .collect())
}

fn doc_problems(path: &str, text: &str, commits: &[String]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut pointers = 0;
    for (index, line) in text.lines().enumerate() {
        let at = format!("{path}:{}", index + 1);
        for word in hex_words(line) {
            if commits.iter().any(|commit| commit == word) {
                problems.push(format!(
                    "{at}: `{word}` is a Concord commit; state what it changed or measured"
                ));
            }
        }
        if let Some(date) = date(line) {
            problems.push(format!(
                "{at}: `{date}` dates history; state the rule as it stands"
            ));
        }
        if line.contains(PRIVATE_DIR) {
            pointers += 1;
            if path != POINTER_HOME || pointers > 1 {
                problems.push(format!(
                    "{at}: `{PRIVATE_DIR}` is git-ignored; only one line in {POINTER_HOME} may name it"
                ));
            }
        }
    }
    problems
}

fn file_problems(path: &str, text: &str, deny: &[Deny]) -> Vec<String> {
    let mut problems = Vec::new();
    let is_rust = path.ends_with(".rs");
    for (index, line) in text.lines().enumerate() {
        let at = format!("{path}:{}", index + 1);
        for (name, kind) in internal_marks::internal_marks(line) {
            problems.push(format!(
                "{at}: `{name}` is {kind}; say what it is, not where the project keeps it"
            ));
        }
        for name in deny.iter().filter(|name| name.matches(line)) {
            problems.push(format!("{at}: `{}` is {}", name.pattern, name.category));
        }
        for home in HOMES {
            if line.contains(home) {
                problems.push(format!(
                    "{at}: `{home}` names a home directory; use `$HOME` or a relative path"
                ));
            }
        }
        if is_rust {
            continue;
        }
        for (address, is_range) in ipv4s(line) {
            if !is_range && !is_allowed_host(address) {
                problems.push(format!(
                    "{at}: `{address}` is a public host; use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24"
                ));
            }
        }
    }
    problems
}

fn hex_words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| {
            (7..=40).contains(&word.len())
                && word
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
                && word.chars().any(|c| ('a'..='f').contains(&c))
        })
}

fn date(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    (0..bytes.len().saturating_sub(9)).find_map(|start| {
        let candidate = line.get(start..start + 10)?;
        let shape = candidate.char_indices().all(|(i, c)| match i {
            4 | 7 => c == '-',
            _ => c.is_ascii_digit(),
        });
        if !shape {
            return None;
        }
        let bounded = !line[..start].ends_with(|c: char| c.is_ascii_alphanumeric())
            && !line[start + 10..].starts_with(|c: char| c.is_ascii_digit());
        let plausible = HISTORY_YEARS.contains(&candidate[..4].parse::<u16>().unwrap_or(0))
            && (1..=12).contains(&candidate[5..7].parse::<u8>().unwrap_or(0))
            && (1..=31).contains(&candidate[8..10].parse::<u8>().unwrap_or(0));
        (bounded && plausible).then_some(candidate)
    })
}

/// Dotted quads not part of a longer dotted number, with whether a `/` prefix length follows.
fn ipv4s(line: &str) -> Vec<(Ipv4Addr, bool)> {
    let mut found = Vec::new();
    for (start, token) in line
        .match_indices(|c: char| c.is_ascii_digit() || c == '.')
        .fold(Vec::<(usize, String)>::new(), |mut runs, (at, piece)| {
            match runs.last_mut() {
                Some((begin, run)) if *begin + run.len() == at => run.push_str(piece),
                _ => runs.push((at, piece.to_string())),
            }
            runs
        })
    {
        let start = start + (token.len() - token.trim_start_matches('.').len());
        let token = token.trim_matches('.');
        if token.split('.').count() != 4
            || line[..start].ends_with(|c: char| c.is_ascii_alphabetic())
        {
            continue;
        }
        if let Ok(address) = token.parse::<Ipv4Addr>() {
            let after = &line[start + token.len()..];
            found.push((address, after.starts_with('/')));
        }
    }
    found
}

fn is_allowed_host(address: Ipv4Addr) -> bool {
    let [a, b, ..] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_documentation()
        || (a == 100 && (64..128).contains(&b))
        || (a == 198 && (18..20).contains(&b))
        || a >= 240
        || PUBLIC_RESOLVERS.contains(&address)
}

/// The words among `candidates` that name a commit of this repository. Without git, or outside a
/// clone, nothing resolves and the hash check passes.
fn concord_commits(root: &Path, candidates: &[String]) -> Vec<String> {
    let mut unique: Vec<&String> = candidates.iter().collect();
    unique.sort();
    unique.dedup();
    if unique.is_empty() {
        return Vec::new();
    }
    let Ok(mut child) = Command::new("git")
        .args(["cat-file", "--batch-check=%(objecttype)"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return Vec::new();
    };
    let input: String = unique
        .iter()
        .map(|word| format!("{word}^{{commit}}\n"))
        .collect();
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(input.as_bytes());
    }
    let Ok(output) = child.wait_with_output() else {
        return Vec::new();
    };
    let answers = String::from_utf8_lossy(&output.stdout);
    unique
        .into_iter()
        .zip(answers.lines())
        .filter(|(_, answer)| *answer == "commit")
        .map(|(word, _)| word.clone())
        .collect()
}

fn tracked(root: &Path) -> Vec<String> {
    Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            output
                .stdout
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
                .map(|path| String::from_utf8_lossy(path).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_DENY: &str = "# fake names\n\
                             zzq_ an internal run name\n\
                             zzqres/ an internal result directory\n\
                             Zzqboss a coordination name\n\
                             zzq-ledger.md\n\
                             ZZQPLAN- a coordination file\n";

    fn fake_deny() -> Vec<Deny> {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("docs/private")).unwrap();
        std::fs::write(root.path().join(DENY_FILE), FAKE_DENY).unwrap();
        load_deny(root.path()).unwrap()
    }

    fn doc(path: &str, text: &str) -> Vec<String> {
        doc_problems(path, text, &["abc1234".to_string()])
    }

    fn denied(line: &str) -> Vec<String> {
        file_problems("crates/x/src/lib.rs", line, &fake_deny())
    }

    #[test]
    fn the_published_tree_carries_no_history_or_private_detail() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check(&root) {
            panic!("{problems}");
        }
    }

    #[test]
    fn present_tense_docs_pass() {
        let text = "sing-tun `611d83b7` reads 34 kB (`stack_go.go:12`, `client_cores`, v1.19.33).\n\
                    Maintainers may keep notes in `docs/private/`.\n";
        assert_eq!(doc("AGENTS.md", text), Vec::<String>::new());
    }

    #[test]
    fn a_commit_of_this_repository_is_reported() {
        assert!(doc("x.md", "measured on `abc1234`")[0].contains("commit"));
        assert!(doc("x.md", "sing-box `abc1235`").is_empty());
    }

    #[test]
    fn a_date_is_reported_and_a_version_is_not() {
        assert!(doc("x.md", "(user, 2026-11-10)")[0].contains("dates history"));
        assert!(doc("x.md", "fires on 2096-02-29 and from 1900-01-01").is_empty());
        assert!(
            doc(
                "x.md",
                "sing `v0.9.7-0.20261023115510`, build 10.0.26300.9818"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_private_pointer_outside_its_one_line_is_reported() {
        assert!(doc(".agents/x.md", "see `docs/private/x`")[0].contains("only one line"));
        let twice = "`docs/private/`\n`docs/private/`\n";
        assert_eq!(doc("AGENTS.md", twice).len(), 1);
    }

    #[test]
    fn every_tracked_file_is_held_to_the_internal_names() {
        for (line, kind) in internal_marks::tests::INTERNAL_LINES {
            let found = file_problems("crates/x/src/lib.rs", line, &[]);
            assert_eq!(found.len(), 1, "{line}: {found:?}");
            assert!(found[0].contains(kind), "{line}: {found:?}");
        }
        for line in internal_marks::tests::PUBLIC_LINES {
            assert_eq!(
                file_problems("crates/x/src/lib.rs", line, &[]),
                Vec::<String>::new(),
                "{line}"
            );
        }
    }

    #[test]
    fn the_private_deny_list_reports_its_names_by_category() {
        for (line, category) in [
            ("`zzq_rec_land_2`", "an internal run name"),
            ("(`zzq_diag_{6,9b}`)", "an internal run name"),
            ("read in `zzqres/refs/x`", "an internal result directory"),
            ("the Zzqboss approves", "a coordination name"),
            ("the `zzq-ledger.md` entry", "a private name"),
            ("see ZZQPLAN-T-TUN.md", "a coordination file"),
        ] {
            let found = denied(line);
            assert_eq!(found.len(), 1, "{line}");
            assert!(found[0].ends_with(category), "{line}: {found:?}");
        }
        for line in [
            "`zzq_` alone",
            "a/zzqres/x",
            "Zzqbosses",
            "`zzqx_run`",
            "ZZQPLAN-",
        ] {
            assert_eq!(denied(line), Vec::<String>::new(), "{line}");
        }
    }

    #[test]
    fn without_a_deny_list_no_names_are_denied() {
        let root = tempfile::tempdir().unwrap();
        assert!(load_deny(root.path()).unwrap().is_empty());
    }

    #[test]
    fn home_directories_are_reported_everywhere() {
        assert!(!file_problems("a.rs", "let p = \"/Users/someone/x\";", &[]).is_empty());
        assert!(!file_problems("ci.yaml", "cd /home/someone", &[]).is_empty());
        assert!(file_problems("ci.yaml", "cd $HOME/x", &[]).is_empty());
    }

    #[test]
    fn only_reserved_hosts_and_public_resolvers_pass_outside_rust() {
        for ok in [
            "server: 192.0.2.1",
            "nameserver: [223.5.5.5, 8.8.8.8]",
            "route: 128.0.0.0/1",
            "fake-ip-range: 198.18.0.1/16",
            "10.0.0.2 127.0.0.1 100.64.0.1 0.0.0.0",
            "build 10.0.26300.9818, v1.19.33.1",
        ] {
            assert_eq!(
                file_problems("c.yaml", ok, &[]),
                Vec::<String>::new(),
                "{ok}"
            );
        }
        assert!(file_problems("c.yaml", "server: 45.77.10.3", &[])[0].contains("public host"));
        assert!(file_problems("a.rs", "server: 45.77.10.3", &[]).is_empty());
    }
}
