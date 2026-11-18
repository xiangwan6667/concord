//! Names from the project's own coordination, which nobody outside it can follow: its working
//! directories and notes, run and branch names, and work-line codes in test and variable names.
//! `public_tree` keeps them out of every tracked file and `commits` out of every commit message.

const INTERNAL_DIRS: &[&str] = &[
    "codex-rootcause",
    "concord-wt",
    "flclash-sync",
    "lead-tools",
];
const INTERNAL_NOTES: &[&str] = &[
    "REVIEW-QUEUE",
    "HOST-HOLD",
    "SHARED-JOBS",
    "COORDINATION.md",
    "known-gaps.md",
    "main-regressions.md",
];
const INTERNAL_NOTE_PREFIXES: &[&str] = &["REPORT-", "BRIEF-", "HANDOVER-", "PLAN-", "VM-BUSY-"];
const INTERNAL_PATHS: &[&str] = &["evidence/", "cb/"];

pub(crate) fn internal_marks(line: &str) -> Vec<(String, &'static str)> {
    let mut found = Vec::new();
    for word in words(line) {
        let kind = if INTERNAL_DIRS.contains(&word) {
            "an internal directory"
        } else if INTERNAL_NOTES.contains(&word)
            || INTERNAL_NOTE_PREFIXES
                .iter()
                .any(|prefix| word.strip_prefix(prefix).is_some_and(starts_upper_or_digit))
        {
            "an internal note"
        } else if is_run_name(word) {
            "an internal run name"
        } else if is_work_line_code(word) {
            "an internal work-line code"
        } else {
            continue;
        };
        found.push((word.to_string(), kind));
    }
    for path in INTERNAL_PATHS {
        for (start, _) in line.match_indices(path) {
            if !line[..start].ends_with(|c: char| c.is_ascii_alphanumeric() || "_/.-".contains(c)) {
                found.push((path.to_string(), "an internal result directory"));
            }
        }
    }
    found
}

fn starts_upper_or_digit(rest: &str) -> bool {
    rest.starts_with(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// `cx` and up to three more letters or digits, or `cl` and one to three more whose first is not a
/// vowel (or `clo`, `clu`, `cly`), then `_` or `-` and a label. The vowel rule keeps words like
/// `clear_`, `close-` and `clash_` out; `cxx` is C++.
fn is_run_name(word: &str) -> bool {
    let Some(split) = word.find(['_', '-']) else {
        return false;
    };
    let (prefix, rest) = (&word[..split], &word[split + 1..]);
    if !rest.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !prefix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return false;
    }
    match (prefix.get(..2), prefix.get(2..)) {
        (Some("cx"), Some(tail)) => tail.len() <= 3 && prefix != "cxx",
        (Some("cl"), Some(tail)) => {
            matches!(tail, "o" | "u" | "y")
                || ((1..=3).contains(&tail.len()) && !tail.starts_with(['a', 'e', 'i', 'o', 'u']))
        }
        _ => false,
    }
}

fn is_work_line_code(word: &str) -> bool {
    let shape = |rest: &str, separators: &str, next: fn(char) -> bool| {
        let mut chars = rest.chars();
        chars.next().is_some_and(|c| c.is_ascii_digit())
            && (separators.is_empty() || chars.next().is_some_and(|c| separators.contains(c)))
            && chars.next().is_some_and(next)
    };
    word.strip_prefix("TestP")
        .is_some_and(|rest| shape(rest, "", |c| c.is_ascii_uppercase()))
        || word
            .strip_prefix('P')
            .is_some_and(|rest| shape(rest, "_", |c| c.is_ascii_uppercase()))
        || word
            .strip_prefix('p')
            .is_some_and(|rest| shape(rest, "_-", |c| c.is_ascii_lowercase()))
}

pub(crate) fn words(line: &str) -> impl Iterator<Item = &str> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || "_-.".contains(c)))
        .map(|word| word.trim_matches('.'))
        .filter(|word| !word.is_empty())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const INTERNAL_LINES: &[(&str, &str)] = &[
        (
            "// generator in codex-rootcause/x.go",
            "an internal directory",
        ),
        ("worktree concord-wt/x", "an internal directory"),
        ("see REVIEW-QUEUE", "an internal note"),
        ("as REPORT-H says", "an internal note"),
        ("(bench clw_rec_win_1)", "an internal run name"),
        ("branch clr-quinn-ack", "an internal run name"),
        ("cxxe_cid_2 and", "an internal run name"),
        ("cltc-android.toolchain.cmake", "an internal run name"),
        ("clu_jobs", "an internal run name"),
        ("-run '^TestP6Vectors$'", "an internal work-line code"),
        ("(P6_AUTH)", "an internal work-line code"),
        ("place p7_vectors_test.go", "an internal work-line code"),
        ("cd p4-chacha && go run .", "an internal work-line code"),
        ("cd evidence/x && go run .", "an internal result directory"),
        ("read cb/x", "an internal result directory"),
    ];

    pub(crate) const PUBLIC_LINES: &[&str] = &[
        "self.clear_failure(); close_all(); clash_config.dart; client_h2; clip-path",
        "cl_len, cl-status, cx_, cl_, clap_builder, cxx_std_17, claude-code",
        "clamp_value cloud_config clock_offset clone_from class_name claim_lookup",
        "DOMAIN,x.a.com,P1 and MATCH,P7; P256_KEY; p99_latency; p50-rtt; P1 in a list",
        "TestPlain, TestP256, PLAN-, REPORT-, `PLAN-` alone, a report-card",
        "src/evidence/x, ./cb/y, abcb/z, a known gap, the plan, the lead byte, SIMD lanes",
        "https://example.com/cb/x and fixtures/evidence/y",
    ];

    #[test]
    fn internal_marks_report_each_name_by_kind() {
        for (line, kind) in INTERNAL_LINES {
            let found = internal_marks(line);
            assert_eq!(found.len(), 1, "{line}: {found:?}");
            assert_eq!(found[0].1, *kind, "{line}");
        }
    }

    #[test]
    fn names_shaped_like_internal_marks_pass() {
        for line in PUBLIC_LINES {
            assert_eq!(internal_marks(line), Vec::new(), "{line}");
        }
    }
}
