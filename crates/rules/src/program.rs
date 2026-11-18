use std::fmt;
use std::sync::Arc;

use indexmap::IndexMap;
use smallvec::SmallVec;

use crate::geo::{GeoError, GeoFile, GeoStore};
use crate::kind::RuleKind;
use crate::prog::Prog;
use crate::ruleset::{RuleSetHandle, RuleSetStore};
use crate::run::{Frame, Run};

pub use concord_config::rule::{Cond, RuleDef, RuleLines};

/// A rule in the list where matching started, by list and position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RuleRef(pub(crate) u32, pub(crate) u32);

impl RuleRef {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleInfo<'p> {
    pub type_name: &'static str,
    pub payload: &'p str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step<'p> {
    Candidate { target: &'p str, rule: RuleRef },
    Done,
    NeedIp,
    NeedProcess,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Demands {
    pub domain: bool,
    pub ip: bool,
    pub resolve_ip: bool,
    pub process: bool,
}

impl Demands {
    pub(crate) fn merge(&mut self, other: Demands) {
        self.domain |= other.domain;
        self.ip |= other.ip;
        self.resolve_ip |= other.resolve_ip;
        self.process |= other.process;
    }
}

#[derive(Clone, Copy)]
pub struct MatchCtx<'a> {
    pub geo: &'a GeoStore,
    pub dscp: u8,
}

impl<'a> MatchCtx<'a> {
    pub fn new(geo: &'a GeoStore) -> Self {
        MatchCtx { geo, dscp: 0 }
    }
}

type TargetCheck = dyn Fn(&str) -> bool + Send + Sync;

pub struct CompileEnv {
    pub geo: Arc<GeoStore>,
    pub rule_sets: Arc<RuleSetStore>,
    /// Runs shorter than this stay as individual rules.
    pub merge_min: usize,
    /// Rejects a rule whose target is not a known outbound, group or sub-rule name.
    pub known_target: Option<Box<TargetCheck>>,
}

impl CompileEnv {
    pub fn new(geo: Arc<GeoStore>, rule_sets: Arc<RuleSetStore>) -> Self {
        CompileEnv {
            geo,
            rule_sets,
            merge_min: 8,
            known_target: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    UnknownTarget {
        section: String,
        index: usize,
        line: String,
        target: String,
    },
    UnknownSubRule {
        section: String,
        index: usize,
        line: String,
        name: String,
    },
    UnknownRuleSet {
        section: String,
        index: usize,
        line: String,
        name: String,
    },
    SubRuleCycle(String),
    EmptySubRuleName,
    Invalid {
        section: String,
        index: usize,
        line: String,
        message: String,
    },
    Geo {
        section: String,
        index: usize,
        line: String,
        source: GeoError,
    },
    TooManyTargets,
}

impl CompileError {
    /// Set when the failure is an absent geo file, which the caller may download and retry.
    pub fn invalid_geo_file(&self) -> Option<GeoFile> {
        match self {
            CompileError::Geo {
                source: GeoError::Invalid { file, .. },
                ..
            } => Some(*file),
            _ => None,
        }
    }

    pub fn missing_geo_file(&self) -> Option<GeoFile> {
        match self {
            CompileError::Geo {
                source: GeoError::Missing { file, .. },
                ..
            } => Some(*file),
            _ => None,
        }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::UnknownTarget {
                section,
                index,
                line,
                target,
            } => {
                write!(
                    f,
                    "{section}[{index}] [{line}] error: proxy [{target}] not found"
                )
            }
            CompileError::UnknownSubRule {
                section,
                index,
                line,
                name,
            } => {
                write!(
                    f,
                    "{section}[{index}] [{line}] error: sub-rule [{name}] not found"
                )
            }
            CompileError::UnknownRuleSet {
                section,
                index,
                line,
                name,
            } => {
                write!(
                    f,
                    "{section}[{index}] [{line}] error: rule set [{name}] not found"
                )
            }
            CompileError::SubRuleCycle(path) => {
                write!(f, "sub-rule error: circular references [{path}]")
            }
            CompileError::EmptySubRuleName => f.write_str("sub-rule name is empty"),
            CompileError::Invalid {
                section,
                index,
                line,
                message,
            } => {
                write!(f, "{section}[{index}] [{line}] error: {message}")
            }
            CompileError::Geo {
                section,
                index,
                line,
                source,
            } => {
                write!(f, "{section}[{index}] [{line}] error: {source}")
            }
            CompileError::TooManyTargets => f.write_str("too many distinct rule targets"),
        }
    }
}

impl std::error::Error for CompileError {}

pub struct RouteProgram {
    /// Index 0 is the main list, `n + 1` the n-th sub-rule list.
    pub(crate) progs: Box<[Prog]>,
    pub(crate) sub_rule_names: Box<[Box<str>]>,
    pub(crate) targets: Box<[Box<str>]>,
    pub(crate) rule_sets: Box<[(Arc<RuleSetHandle>, bool, bool)]>,
    pub(crate) demands: Demands,
    pub(crate) deferred_geo: Box<[GeoFile]>,
}

impl RouteProgram {
    pub fn compile(
        rules: &[RuleDef],
        sub_rules: &IndexMap<String, Vec<RuleDef>>,
        env: &CompileEnv,
    ) -> Result<RouteProgram, CompileError> {
        crate::compile::compile(rules, sub_rules, env)
    }

    /// `compile` over lines `load_raw` has checked, holding few definitions at a time.
    pub fn compile_lines(
        rules: &RuleLines,
        sub_rules: &IndexMap<String, Vec<RuleDef>>,
        env: &CompileEnv,
    ) -> Result<RouteProgram, CompileError> {
        crate::compile::compile_lines(rules, sub_rules, env)
    }

    pub fn start(&self) -> Run<'_> {
        Run::new(self, SmallVec::from_elem(Frame::default(), 1))
    }

    pub fn len(&self) -> usize {
        self.progs.first().map_or(0, |p| p.table.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Geo files the rules use but did not find; their rules do not match until the
    /// file is loaded, and nothing needs compiling again then.
    pub fn deferred_geo(&self) -> &[GeoFile] {
        &self.deferred_geo
    }

    pub fn demands(&self) -> Demands {
        let mut demands = self.demands;
        for (handle, src, resolves) in self.rule_sets.iter() {
            let mut inner = handle.load().demands();
            if *src {
                inner.ip = false;
            }
            inner.resolve_ip &= *resolves;
            demands.merge(inner);
        }
        demands
    }

    pub fn rule_at(&self, rule: RuleRef) -> RuleInfo<'_> {
        let main = self.progs.get(rule.1 as usize);
        RuleInfo {
            type_name: main
                .and_then(|p| p.table.kind(rule.0))
                .map_or("Unknown", RuleKind::name),
            payload: main
                .and_then(|p| p.table.payload(rule.0))
                .unwrap_or_default(),
        }
    }

    /// The main list in match order, each rule with its target.
    pub fn rules(&self) -> impl Iterator<Item = (RuleInfo<'_>, &str)> {
        let main = self.progs.first();
        (0..u32::try_from(self.len()).unwrap_or(u32::MAX)).map(move |index| {
            let target = main
                .and_then(|p| p.table.target(index))
                .map_or("", |id| self.target_name(id));
            (self.rule_at(RuleRef(index, 0)), target)
        })
    }

    pub fn memory_estimate(&self) -> usize {
        self.progs.iter().map(Prog::heap_bytes).sum::<usize>()
            + self.targets.iter().map(|t| t.len() + 16).sum::<usize>()
            + self
                .sub_rule_names
                .iter()
                .map(|t| t.len() + 16)
                .sum::<usize>()
    }

    pub(crate) fn target_name(&self, id: u16) -> &str {
        self.targets.get(usize::from(id)).map_or("", |t| &**t)
    }
}
