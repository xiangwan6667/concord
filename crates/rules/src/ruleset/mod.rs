//! Rule sets: `domain`, `ipcidr` and `classical` behaviors, their handles and the `.mrs` forms.

mod convert;
mod lines;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use arc_swap::{ArcSwap, Guard};
use concord_common::sync::lock;
use concord_common::{Address, FlowMeta, InboundInfo, InboundKind, Network, RouteState};
use concord_config::provider::{RuleBehavior, RuleFormat};

pub use convert::{CompileSetError, CompiledRuleSet, SetInfo, compile_rule_set, dump_mrs};

use crate::cidr_set::IpCidrSet;
use crate::domain_set::{DomainSet, DomainSetBuilder};
use crate::error::FormatError;
use crate::eval::{Ev, EvResult};
use crate::geo::{GeoFile, GeoStore};
use crate::mrs::{self, MrsBehavior, MrsPayload};
use crate::prog::Prog;
use crate::program::{CompileEnv, CompileError, Demands};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Behavior {
    Domain,
    IpCidr,
    Classical,
}

impl Behavior {
    pub fn name(self) -> &'static str {
        match self {
            Behavior::Domain => "domain",
            Behavior::IpCidr => "ipcidr",
            Behavior::Classical => "classical",
        }
    }
}

impl From<RuleBehavior> for Behavior {
    fn from(value: RuleBehavior) -> Self {
        match value {
            RuleBehavior::Domain => Behavior::Domain,
            RuleBehavior::IpCidr => Behavior::IpCidr,
            RuleBehavior::Classical => Behavior::Classical,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    Yaml,
    Text,
    Mrs,
    DomainSet,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Yaml => "yaml",
            Format::Text => "text",
            Format::Mrs => "mrs",
            Format::DomainSet => "domain-set",
        }
    }
}

impl From<RuleFormat> for Format {
    fn from(value: RuleFormat) -> Self {
        match value {
            RuleFormat::Yaml => Format::Yaml,
            RuleFormat::Text => Format::Text,
            RuleFormat::Mrs => Format::Mrs,
            RuleFormat::DomainSet => Format::DomainSet,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleSetError {
    NoPayload,
    InvalidFormat,
    Mrs(FormatError),
}

impl fmt::Display for RuleSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleSetError::NoPayload => f.write_str("file must have a `payload` field"),
            RuleSetError::InvalidFormat => f.write_str("invalid format"),
            RuleSetError::Mrs(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for RuleSetError {}

enum Body {
    Domain(Option<DomainSet>),
    Ip(IpCidrSet),
    Classical { prog: Prog, demands: Demands },
}

pub struct RuleSet {
    body: Body,
    count: usize,
}

/// A parsed set and the entries that were skipped.
pub struct ParsedRuleSet {
    pub set: RuleSet,
    pub warnings: Vec<String>,
    /// Geo files whose absence or damage dropped classical entries; fetching them and parsing
    /// again keeps those entries.
    pub geo_faults: Vec<GeoFault>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoFault {
    Missing(GeoFile),
    Invalid(GeoFile),
}

impl GeoFault {
    pub(crate) fn of(err: &CompileError) -> Option<GeoFault> {
        err.missing_geo_file()
            .map(GeoFault::Missing)
            .or_else(|| err.invalid_geo_file().map(GeoFault::Invalid))
    }
}

impl RuleSet {
    pub fn empty(behavior: Behavior) -> RuleSet {
        let body = match behavior {
            Behavior::Domain => Body::Domain(None),
            Behavior::IpCidr => Body::Ip(IpCidrSet::new()),
            Behavior::Classical => Body::Classical {
                prog: Prog::default(),
                demands: Demands::default(),
            },
        };
        RuleSet { body, count: 0 }
    }

    pub fn behavior(&self) -> Behavior {
        match self.body {
            Body::Domain(_) => Behavior::Domain,
            Body::Ip(_) => Behavior::IpCidr,
            Body::Classical { .. } => Behavior::Classical,
        }
    }

    /// Entries that were accepted.
    pub fn count(&self) -> usize {
        self.count
    }

    pub(crate) fn demands(&self) -> Demands {
        match &self.body {
            Body::Domain(_) => Demands {
                domain: true,
                ..Demands::default()
            },
            Body::Ip(_) => Demands {
                ip: true,
                resolve_ip: true,
                ..Demands::default()
            },
            Body::Classical { demands, .. } => *demands,
        }
    }

    pub fn from_entries(behavior: Behavior, entries: &[String], env: &CompileEnv) -> ParsedRuleSet {
        let mut warnings = Vec::new();
        let mut geo_faults = Vec::new();
        let mut count = 0usize;
        let body = match behavior {
            Behavior::Domain => {
                let mut builder = DomainSetBuilder::new();
                for entry in entries {
                    if entry.contains('/') {
                        warnings.push(format!(
                            "skip invalid domain from rule provider: invalid domain {entry:?}: slash is not allowed"
                        ));
                    } else if let Err(err) = builder.insert(entry) {
                        warnings.push(format!("skip invalid domain from rule provider: {err}"));
                    } else {
                        count += 1;
                    }
                }
                Body::Domain(builder.build())
            }
            Behavior::IpCidr => {
                let mut set = IpCidrSet::new();
                for entry in entries {
                    if set.add_str(entry) {
                        count += 1;
                    } else {
                        warnings.push(format!("invalid Ipcidr:[{entry}]"));
                    }
                }
                set.merge();
                Body::Ip(set)
            }
            Behavior::Classical => {
                let built = crate::compile::compile_classical(entries, env);
                warnings = built.warnings;
                geo_faults = built.geo_faults;
                count = built.count;
                Body::Classical {
                    prog: built.prog,
                    demands: built.demands,
                }
            }
        };
        ParsedRuleSet {
            set: RuleSet { body, count },
            warnings,
            geo_faults,
        }
    }

    /// Reads rule-set file contents the way a rule provider does.
    pub fn parse(
        behavior: Behavior,
        format: Format,
        bytes: &[u8],
        env: &CompileEnv,
    ) -> Result<ParsedRuleSet, RuleSetError> {
        match format {
            Format::Mrs => {
                let mrs_behavior = match behavior {
                    Behavior::Domain => MrsBehavior::Domain,
                    Behavior::IpCidr => MrsBehavior::IpCidr,
                    Behavior::Classical => return Err(RuleSetError::InvalidFormat),
                };
                let file = mrs::decode(bytes, mrs_behavior).map_err(RuleSetError::Mrs)?;
                let body = match file.payload {
                    MrsPayload::Domain(set) => Body::Domain(Some(set)),
                    MrsPayload::IpCidr(set) => Body::Ip(set),
                };
                Ok(ParsedRuleSet {
                    set: RuleSet {
                        body,
                        count: file.count as usize,
                    },
                    warnings: Vec::new(),
                    geo_faults: Vec::new(),
                })
            }
            Format::Yaml => Ok(Self::from_entries(
                behavior,
                &lines::yaml_items(bytes)?,
                env,
            )),
            Format::Text => Ok(Self::from_entries(behavior, &lines::text_items(bytes), env)),
            Format::DomainSet => Ok(Self::from_entries(
                behavior,
                &lines::domain_set_items(bytes),
                env,
            )),
        }
    }

    pub(crate) fn matches(&self, ev: &mut Ev<'_>) -> EvResult {
        match &self.body {
            Body::Domain(set) => Ok(set.as_ref().is_some_and(|set| set.has(ev.host))),
            Body::Ip(set) => {
                let ip = ev.dst_ip(true)?;
                Ok(ip.is_some_and(|ip| set.contains(ip)))
            }
            Body::Classical { prog, .. } => prog.any_match(ev),
        }
    }

    /// A domain-only query, as `nameserver-policy` and `fake-ip-filter` ask.
    pub fn match_domain(&self, host: &str, geo: &GeoStore) -> bool {
        self.query(host, None, geo)
    }

    pub fn match_ip(&self, ip: IpAddr, geo: &GeoStore) -> bool {
        self.query("", Some(ip), geo)
    }

    fn query(&self, host: &str, ip: Option<IpAddr>, geo: &GeoStore) -> bool {
        let src: std::net::SocketAddr = ([0, 0, 0, 0], 0).into();
        let flow = FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound: InboundInfo::new(InboundKind::Inner),
            src,
            dst: Address::Socket(src),
        };
        let state = RouteState {
            host: (!host.is_empty()).then(|| host.into()),
            ip,
            ip_resolved: true,
            process_looked_up: true,
            ..RouteState::default()
        };
        let mut ev = Ev::new(&flow, &state, geo, 0, 0, Default::default());
        self.matches(&mut ev).unwrap_or(false)
    }
}

/// A named rule set behind a swap point: programs hold the handle, so an
/// update reaches them without recompiling.
pub struct RuleSetHandle {
    name: Arc<str>,
    behavior: Behavior,
    set: ArcSwap<RuleSet>,
}

impl RuleSetHandle {
    fn new(name: &str, behavior: Behavior) -> Self {
        RuleSetHandle {
            name: name.into(),
            behavior,
            set: ArcSwap::from_pointee(RuleSet::empty(behavior)),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn behavior(&self) -> Behavior {
        self.behavior
    }

    pub fn load(&self) -> Guard<Arc<RuleSet>> {
        self.set.load()
    }

    /// Takes the contents `other` holds now, unless it declared another behavior.
    pub fn take_from(&self, other: &RuleSetHandle) -> bool {
        if other.behavior != self.behavior {
            return false;
        }
        self.set.store(other.set.load_full());
        true
    }

    /// Replaces the contents. A set of another behavior is refused.
    pub fn store(&self, set: RuleSet) -> bool {
        if set.behavior() != self.behavior {
            return false;
        }
        self.set.store(Arc::new(set));
        true
    }

    pub fn count(&self) -> usize {
        self.set.load().count()
    }

    pub fn match_domain(&self, host: &str, geo: &GeoStore) -> bool {
        self.set.load().match_domain(host, geo)
    }

    pub fn match_ip(&self, ip: IpAddr, geo: &GeoStore) -> bool {
        self.set.load().match_ip(ip, geo)
    }
}

#[derive(Default)]
pub struct RuleSetStore {
    handles: Mutex<HashMap<String, Arc<RuleSetHandle>>>,
}

impl RuleSetStore {
    pub fn new() -> Self {
        RuleSetStore::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<RuleSetHandle>>> {
        lock(&self.handles)
    }

    /// The handle for `name`, created empty on first use. A name keeps the behavior it was declared with.
    pub fn declare(&self, name: &str, behavior: Behavior) -> Arc<RuleSetHandle> {
        self.lock()
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(RuleSetHandle::new(name, behavior)))
            .clone()
    }

    pub fn get(&self, name: &str) -> Option<Arc<RuleSetHandle>> {
        self.lock().get(name).cloned()
    }

    pub fn names(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    pub fn remove(&self, name: &str) -> Option<Arc<RuleSetHandle>> {
        self.lock().remove(name)
    }
}

#[cfg(test)]
mod tests;
