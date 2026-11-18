use concord_config::mitm::text::quote;
use concord_config::mitm::{IssueKind, LineError};
use jaq_core::compile;
use jaq_core::load::{Arena, File, Loader, lex, parse};
use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
use jaq_json::{Val, read};

type Filter = jaq_core::Filter<data::JustLut<Val>>;

/// A jq filter over a JSON body, as Surge's `http-request-jq` and `http-response-jq` run it.
pub(crate) struct Jq {
    filter: Filter,
    code: String,
}

impl std::fmt::Debug for Jq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Jq")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid jq expression: {0}")]
pub(crate) struct JqError(String);

impl From<JqError> for LineError {
    fn from(err: JqError) -> LineError {
        LineError::new(IssueKind::Jq, err.to_string())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JqOutcome {
    Rewritten(String),
    NotJson,
    /// Surge keeps the body as it was when the filter gives nothing.
    Empty,
    Failed(String),
}

impl Jq {
    pub(crate) fn compile(code: &str) -> Result<Jq, JqError> {
        let defs = jaq_core::defs()
            .chain(jaq_std::defs())
            .chain(jaq_json::defs());
        let funs = jaq_core::funs()
            .chain(jaq_std::funs())
            .chain(jaq_json::funs());
        let arena = Arena::default();
        let modules = Loader::new(defs)
            .load(&arena, File { code, path: () })
            .map_err(|errors| load_error(code, errors))?;
        let filter = Compiler::default()
            .with_funs(funs)
            .compile(modules)
            .map_err(compile_error)?;
        Ok(Jq {
            filter,
            code: code.to_string(),
        })
    }

    pub(crate) fn code(&self) -> &str {
        &self.code
    }

    /// Runs on `body` and keeps the first value it gives, as the body that replaces it.
    pub(crate) fn run(&self, body: &str) -> JqOutcome {
        let Ok(input) = read::parse_single(body.as_bytes()) else {
            return JqOutcome::NotJson;
        };
        let ctx = Ctx::<data::JustLut<Val>>::new(&self.filter.lut, Vars::new([]));
        match self.filter.id.run((ctx, input)).map(unwrap_valr).next() {
            None => JqOutcome::Empty,
            Some(Ok(value)) => JqOutcome::Rewritten(value.to_string()),
            Some(Err(err)) => JqOutcome::Failed(err.to_string()),
        }
    }
}

fn near(code: &str, rest: &str) -> String {
    let at = code.len().saturating_sub(rest.len());
    match code.get(at..).map(str::trim) {
        Some(tail) if !tail.is_empty() => {
            let shown: String = tail.chars().take(24).collect();
            format!(" near {}", quote(&shown))
        }
        _ => " at the end".to_string(),
    }
}

fn load_error(code: &str, errors: jaq_core::load::Errors<&str, ()>) -> JqError {
    let mut messages = Vec::new();
    for (_, error) in errors {
        match error {
            jaq_core::load::Error::Io(items) => {
                messages.extend(
                    items
                        .into_iter()
                        .map(|(path, err)| format!("{path}: {err}")),
                );
            }
            jaq_core::load::Error::Lex(items) => {
                messages.extend(items.into_iter().map(|(expect, rest): lex::Error<&str>| {
                    format!("expected {}{}", expect.as_str(), near(code, rest))
                }));
            }
            jaq_core::load::Error::Parse(items) => {
                messages.extend(items.into_iter().map(|(expect, rest): parse::Error<&str>| {
                    format!("expected {}{}", expect.as_str(), near(code, rest))
                }));
            }
        }
    }
    JqError(messages.join("; "))
}

fn compile_error(errors: compile::Errors<&str, ()>) -> JqError {
    let names: Vec<String> = errors
        .into_iter()
        .flat_map(|(_, undefined)| undefined)
        .map(|(name, kind)| match kind {
            compile::Undefined::Filter(arity) => format!("{name}/{arity}"),
            other => format!("{} {name}", other.as_str()),
        })
        .collect();
    JqError(format!("undefined {}", names.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(code: &str, body: &str) -> JqOutcome {
        Jq::compile(code)
            .unwrap_or_else(|err| panic!("{code}: {err}"))
            .run(body)
    }

    fn rewritten(text: &str) -> JqOutcome {
        JqOutcome::Rewritten(text.to_string())
    }

    #[test]
    fn module_filters_rewrite_bodies_in_place() {
        let cases = [
            (".dt = []", r#"{"dt":[1,2],"v":1}"#, r#"{"dt":[],"v":1}"#),
            (
                ".dt.hot = [] | .dt.recommand = [] | .dt.bannerList = []",
                r#"{"dt":{"hot":[1],"recommand":[2],"bannerList":[3],"keep":"é\"\n"}}"#,
                r#"{"dt":{"hot":[],"recommand":[],"bannerList":[],"keep":"é\"\n"}}"#,
            ),
            (
                "del(.reskinConfig.sidebarExSquareStyle.moreList, .reskinConfig.sidebarExSquareStyle.topList)",
                r#"{"reskinConfig":{"sidebarExSquareStyle":{"moreList":[1],"topList":[2],"x":3}}}"#,
                r#"{"reskinConfig":{"sidebarExSquareStyle":{"x":3}}}"#,
            ),
            (
                r#".headers |= with_entries(select(.key | test("^X-") | not))"#,
                r#"{"headers":{"X-A":"1","Accept":"*/*"}}"#,
                r#"{"headers":{"Accept":"*/*"}}"#,
            ),
            (".[0]", "[{\"a\":1},2]", r#"{"a":1}"#),
        ];
        for (code, body, want) in cases {
            assert_eq!(rewrite(code, body), rewritten(want), "{code}");
        }
    }

    #[test]
    fn a_body_that_is_not_json_or_gives_nothing_is_kept() {
        assert_eq!(rewrite(".a = 1", "<html>"), JqOutcome::NotJson);
        assert_eq!(rewrite(".a = 1", ""), JqOutcome::NotJson);
        assert_eq!(rewrite("empty", "{}"), JqOutcome::Empty);
        assert!(matches!(rewrite(".a.b", "[1]"), JqOutcome::Failed(_)));
        assert_eq!(rewrite(".[]", "[1,2]"), rewritten("1"));
    }

    #[test]
    fn a_bad_expression_says_what_is_wrong() {
        let err = Jq::compile(".a = ").unwrap_err().to_string();
        assert!(err.contains("at the end"), "{err}");
        let err = Jq::compile(".a | nosuchfn(1)").unwrap_err().to_string();
        assert!(err.contains("nosuchfn/1"), "{err}");
        let err = Jq::compile(".a ]").unwrap_err().to_string();
        assert!(err.starts_with("invalid jq expression"), "{err}");
    }

    #[test]
    fn a_filter_runs_on_other_threads() {
        fn shared<T: Send + Sync>(_: &T) {}
        shared(&Jq::compile(".").unwrap());
    }
}
