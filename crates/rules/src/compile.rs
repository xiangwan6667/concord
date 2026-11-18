use std::borrow::Borrow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use concord_common::{InboundKind, Network};
use concord_config::filter::{Matcher, compile_pattern};
use concord_config::rule::{Cond, NetworkKind, RuleDef, RuleLines, parse_rule};
use indexmap::IndexMap;

use crate::eval::{GeoIpSource, Node, PortKind, ProcessMode, inbound_bit};
use crate::geo::{GeoError, GeoFile};
use crate::kind::RuleKind;
use crate::payload::rule_payload;
use crate::prog::{HostMatch, Op, Prog};
use crate::program::{CompileEnv, CompileError, Demands, RouteProgram};
use crate::ruleset::GeoFault;
use crate::ruleset::RuleSetHandle;
use crate::runs::{DomainItem, DomainRun, IpRun};
use crate::table::TableBuilder;
use crate::text::go_lower;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Domain,
    Ip { src: bool, resolves: bool },
    Other,
}

fn class_of(def: &RuleDef) -> Class {
    match &def.cond {
        Cond::Domain(_)
        | Cond::DomainSuffix(_)
        | Cond::DomainKeyword(_)
        | Cond::DomainWildcard(_)
        | Cond::DomainRegex(_) => Class::Domain,
        Cond::IpCidr(_) | Cond::IpCidr6(_) => Class::Ip {
            src: def.src,
            resolves: !def.no_resolve && !def.src,
        },
        Cond::SrcIpCidr(_) => Class::Ip {
            src: true,
            resolves: false,
        },
        _ => Class::Other,
    }
}

struct Loc<'a> {
    section: &'a str,
    index: usize,
    line: &'a str,
}

impl Loc<'_> {
    fn invalid(&self, message: impl Into<String>) -> CompileError {
        CompileError::Invalid {
            section: self.section.to_string(),
            index: self.index,
            line: self.line.to_string(),
            message: message.into(),
        }
    }

    fn geo(&self, source: GeoError) -> CompileError {
        CompileError::Geo {
            section: self.section.to_string(),
            index: self.index,
            line: self.line.to_string(),
            source,
        }
    }
}

struct Cx<'e> {
    env: &'e CompileEnv,
    targets: Vec<Box<str>>,
    target_ids: HashMap<String, u16>,
    sub_ids: HashMap<&'e str, u32>,
    empty_sub: u32,
    demands: Demands,
    rule_sets: Vec<(Arc<RuleSetHandle>, bool, bool)>,
    check_targets: bool,
    deferred_geo: Vec<GeoFile>,
}

impl<'e> Cx<'e> {
    fn new(env: &'e CompileEnv, check_targets: bool) -> Self {
        Cx {
            env,
            targets: Vec::new(),
            target_ids: HashMap::new(),
            sub_ids: HashMap::new(),
            empty_sub: 0,
            demands: Demands::default(),
            rule_sets: Vec::new(),
            check_targets,
            deferred_geo: Vec::new(),
        }
    }

    fn intern(&mut self, target: &str) -> Result<u16, CompileError> {
        if let Some(id) = self.target_ids.get(target) {
            return Ok(*id);
        }
        let id = u16::try_from(self.targets.len()).map_err(|_| CompileError::TooManyTargets)?;
        self.targets.push(target.into());
        self.target_ids.insert(target.to_string(), id);
        Ok(id)
    }
}

pub(crate) fn compile(
    rules: &[RuleDef],
    sub_rules: &IndexMap<String, Vec<RuleDef>>,
    env: &CompileEnv,
) -> Result<RouteProgram, CompileError> {
    compile_from(rules.iter().map(Ok), sub_rules, env)
}

pub(crate) fn compile_lines(
    rules: &RuleLines,
    sub_rules: &IndexMap<String, Vec<RuleDef>>,
    env: &CompileEnv,
) -> Result<RouteProgram, CompileError> {
    let defs = rules.iter().enumerate().map(|(index, line)| {
        parse_rule(line).map_err(|err| CompileError::Invalid {
            section: "rules".to_string(),
            index,
            line: line.to_string(),
            message: err.message,
        })
    });
    compile_from(defs, sub_rules, env)
}

fn compile_from<D: Borrow<RuleDef>>(
    rules: impl Iterator<Item = Result<D, CompileError>>,
    sub_rules: &IndexMap<String, Vec<RuleDef>>,
    env: &CompileEnv,
) -> Result<RouteProgram, CompileError> {
    if sub_rules.keys().any(String::is_empty) {
        return Err(CompileError::EmptySubRuleName);
    }
    verify_sub_rules(sub_rules)?;
    let mut cx = Cx::new(env, true);
    for (id, name) in sub_rules.keys().enumerate() {
        cx.sub_ids.insert(name, id as u32);
    }
    cx.empty_sub = sub_rules.len() as u32;
    let mut progs = Vec::with_capacity(sub_rules.len() + 2);
    progs.push(compile_list(&mut cx, rules, "rules")?);
    for (name, list) in sub_rules {
        let section = format!("sub-rules[{name}]");
        progs.push(compile_list(&mut cx, list.iter().map(Ok), &section)?);
    }
    progs.push(Default::default());
    Ok(RouteProgram {
        progs: progs.into_boxed_slice(),
        sub_rule_names: sub_rules.keys().map(|name| name.as_str().into()).collect(),
        targets: cx.targets.into_boxed_slice(),
        rule_sets: cx.rule_sets.into_boxed_slice(),
        demands: cx.demands,
        deferred_geo: cx.deferred_geo.into_boxed_slice(),
    })
}

fn verify_sub_rules(sub_rules: &IndexMap<String, Vec<RuleDef>>) -> Result<(), CompileError> {
    for name in sub_rules.keys() {
        let mut path = Vec::new();
        verify_from(name, sub_rules, &mut path)?;
    }
    Ok(())
}

fn verify_from<'a>(
    name: &'a str,
    sub_rules: &'a IndexMap<String, Vec<RuleDef>>,
    path: &mut Vec<&'a str>,
) -> Result<(), CompileError> {
    path.push(name);
    for rule in sub_rules.get(name).into_iter().flatten() {
        if !matches!(rule.cond, Cond::SubRule(_)) || !sub_rules.contains_key(&rule.target) {
            continue;
        }
        if path.contains(&rule.target.as_str()) {
            path.push(&rule.target);
            return Err(CompileError::SubRuleCycle(path.join("->")));
        }
        verify_from(&rule.target, sub_rules, path)?;
    }
    path.pop();
    Ok(())
}

/// Same-class rules as they are read. They stay definitions until the run is long
/// enough to merge, so at most `merge_min` are held however long the list is.
struct OpenRun<D> {
    class: Class,
    start: usize,
    count: usize,
    held: Vec<D>,
    domains: Vec<(u32, DomainItem)>,
    nets: Vec<(u32, IpAddr, u8)>,
}

impl<D: Borrow<RuleDef>> OpenRun<D> {
    fn new(class: Class, start: usize) -> Self {
        OpenRun {
            class,
            start,
            count: 0,
            held: Vec::new(),
            domains: Vec::new(),
            nets: Vec::new(),
        }
    }

    fn add(&mut self, def: D, merge_min: usize, section: &str) -> Result<(), CompileError> {
        let index = self.start + self.count;
        self.count += 1;
        if self.count > merge_min {
            return self.add_item(def.borrow(), index, section);
        }
        self.held.push(def);
        if self.count == merge_min {
            for (i, def) in std::mem::take(&mut self.held).iter().enumerate() {
                self.add_item(def.borrow(), self.start + i, section)?;
            }
        }
        Ok(())
    }

    fn add_item(&mut self, def: &RuleDef, index: usize, section: &str) -> Result<(), CompileError> {
        match &def.cond {
            Cond::IpCidr(net) | Cond::IpCidr6(net) | Cond::SrcIpCidr(net) => {
                self.nets.push((index as u32, net.addr, net.prefix));
            }
            _ => {
                if let Some(item) = domain_item(def, index, section)? {
                    self.domains.push((index as u32, item));
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct ListBuilder {
    table: TableBuilder,
    ops: Vec<Op>,
    nodes: Vec<Node>,
    domain_runs: Vec<DomainRun>,
    ip_runs: Vec<IpRun>,
}

impl ListBuilder {
    fn leaf(
        &mut self,
        cx: &mut Cx<'_>,
        def: &RuleDef,
        index: usize,
        section: &str,
    ) -> Result<(), CompileError> {
        let idx = index as u32;
        if let Some(how) = host_match(def, self.table.payload(idx)) {
            cx.demands.domain = true;
            self.ops.push(Op::Host { idx, how });
            return Ok(());
        }
        let loc = Loc {
            section,
            index,
            line: &def.text,
        };
        self.nodes.push(node_for_def(cx, def, &loc)?);
        self.ops.push(Op::Leaf {
            idx,
            node: self.nodes.len() as u32 - 1,
        });
        Ok(())
    }

    fn close<D: Borrow<RuleDef>>(
        &mut self,
        cx: &mut Cx<'_>,
        run: OpenRun<D>,
        merge_min: usize,
        section: &str,
    ) -> Result<(), CompileError> {
        let (start, end) = (run.start as u32, (run.start + run.count) as u32);
        if run.count < merge_min {
            for (i, def) in run.held.iter().enumerate() {
                self.leaf(cx, def.borrow(), run.start + i, section)?;
            }
            return Ok(());
        }
        match run.class {
            Class::Domain => {
                cx.demands.domain = true;
                self.domain_runs
                    .push(DomainRun::build(start, end, run.domains, &self.table));
                self.ops.push(Op::Domain(self.domain_runs.len() as u32 - 1));
            }
            Class::Ip { src, resolves } => {
                if !src {
                    cx.demands.ip = true;
                    cx.demands.resolve_ip |= resolves;
                }
                self.ip_runs
                    .push(IpRun::build(start, end, src, resolves, &run.nets));
                self.ops.push(Op::Ip(self.ip_runs.len() as u32 - 1));
            }
            Class::Other => {}
        }
        Ok(())
    }
}

fn compile_list<D: Borrow<RuleDef>>(
    cx: &mut Cx<'_>,
    defs: impl Iterator<Item = Result<D, CompileError>>,
    section: &str,
) -> Result<Prog, CompileError> {
    let merge_min = cx.env.merge_min.max(1);
    let mut list = ListBuilder::default();
    let mut open: Option<OpenRun<D>> = None;
    for (index, def) in defs.enumerate() {
        let def = def?;
        let rule = def.borrow();
        let loc = Loc {
            section,
            index,
            line: &rule.text,
        };
        let target = cx.intern(&rule.target)?;
        if cx.check_targets {
            check_target(cx, rule, &loc)?;
        }
        list.table.push(
            RuleKind::of(&rule.cond, rule.src),
            target,
            &rule_payload(rule),
        );
        let class = class_of(rule);
        if let Some(run) = open.take_if(|run| run.class != class) {
            list.close(cx, run, merge_min, section)?;
        }
        if class == Class::Other {
            list.leaf(cx, rule, index, section)?;
        } else {
            open.get_or_insert_with(|| OpenRun::new(class, index))
                .add(def, merge_min, section)?;
        }
    }
    if let Some(run) = open {
        list.close(cx, run, merge_min, section)?;
    }
    Ok(Prog {
        table: list.table.finish(),
        ops: list.ops.into_boxed_slice(),
        nodes: list.nodes.into_boxed_slice(),
        domain_runs: list.domain_runs.into_boxed_slice(),
        ip_runs: list.ip_runs.into_boxed_slice(),
    })
}

/// How to match a lone domain rule from its payload alone. The payload shows the rule
/// to the user, so it only stands in for the condition when the two agree.
fn host_match(def: &RuleDef, payload: Option<&str>) -> Option<HostMatch> {
    let (how, pattern) = match &def.cond {
        Cond::Domain(pattern) => (HostMatch::Exact, pattern),
        Cond::DomainSuffix(pattern) => (HostMatch::Suffix, pattern),
        Cond::DomainKeyword(pattern) => (HostMatch::Keyword, pattern),
        _ => return None,
    };
    let payload = payload?;
    let same = if pattern.is_ascii() {
        payload.eq_ignore_ascii_case(pattern)
    } else {
        payload == pattern.to_lowercase()
    };
    same.then_some(how)
}

/// mihomo runs a top-level `SUB-RULE` aimed at a proxy as a rule that never matches.
fn dead_sub_rule(cx: &Cx<'_>, def: &RuleDef, loc: &Loc<'_>) -> bool {
    loc.section == "rules"
        && !cx.sub_ids.contains_key(def.target.as_str())
        && cx
            .env
            .known_target
            .as_ref()
            .is_none_or(|known| known(&def.target))
}

fn check_target(cx: &Cx<'_>, def: &RuleDef, loc: &Loc<'_>) -> Result<(), CompileError> {
    if matches!(def.cond, Cond::SubRule(_)) {
        if cx.sub_ids.contains_key(def.target.as_str()) || dead_sub_rule(cx, def, loc) {
            return Ok(());
        }
        return Err(CompileError::UnknownSubRule {
            section: loc.section.to_string(),
            index: loc.index,
            line: loc.line.to_string(),
            name: def.target.clone(),
        });
    }
    match &cx.env.known_target {
        Some(known) if !known(&def.target) => Err(CompileError::UnknownTarget {
            section: loc.section.to_string(),
            index: loc.index,
            line: loc.line.to_string(),
            target: def.target.clone(),
        }),
        _ => Ok(()),
    }
}

fn domain_item(
    def: &RuleDef,
    index: usize,
    section: &str,
) -> Result<Option<DomainItem>, CompileError> {
    Ok(Some(match &def.cond {
        Cond::Domain(_) => DomainItem::Exact,
        Cond::DomainSuffix(_) => DomainItem::Suffix,
        Cond::DomainKeyword(_) => DomainItem::Keyword,
        Cond::DomainWildcard(_) => DomainItem::Wildcard,
        Cond::DomainRegex(pattern) => {
            let loc = Loc {
                section,
                index,
                line: &def.text,
            };
            DomainItem::Regex(regex(pattern, &loc)?)
        }
        _ => return Ok(None),
    }))
}

fn regex(pattern: &str, loc: &Loc<'_>) -> Result<Matcher, CompileError> {
    compile_pattern(pattern, true).map_err(|err| loc.invalid(err.message))
}

fn node_for_def(cx: &mut Cx<'_>, def: &RuleDef, loc: &Loc<'_>) -> Result<Node, CompileError> {
    match &def.cond {
        Cond::SubRule(inner) => {
            let sub = match cx.sub_ids.get(def.target.as_str()) {
                Some(&sub) => sub,
                None if dead_sub_rule(cx, def, loc) => cx.empty_sub,
                None => {
                    return Err(CompileError::UnknownSubRule {
                        section: loc.section.to_string(),
                        index: loc.index,
                        line: loc.line.to_string(),
                        name: def.target.clone(),
                    });
                }
            };
            let cond = node_for_cond(cx, inner, false, true, loc)?;
            Ok(Node::SubRule {
                cond: Box::new(cond),
                sub,
            })
        }
        cond => {
            let src = def.src;
            node_for_cond(cx, cond, src, !def.no_resolve && !src, loc)
        }
    }
}

fn ip_view(cx: &mut Cx<'_>, src: bool, resolves: bool) {
    if !src {
        cx.demands.ip = true;
        cx.demands.resolve_ip |= resolves;
    }
}

fn node_for_cond(
    cx: &mut Cx<'_>,
    cond: &Cond,
    src: bool,
    resolves: bool,
    loc: &Loc<'_>,
) -> Result<Node, CompileError> {
    Ok(match cond {
        Cond::Match => Node::Match,
        Cond::Domain(p) => {
            cx.demands.domain = true;
            Node::Domain(p.to_lowercase().into())
        }
        Cond::DomainSuffix(p) => {
            cx.demands.domain = true;
            Node::Suffix(p.to_lowercase().into())
        }
        Cond::DomainKeyword(p) => {
            cx.demands.domain = true;
            Node::Keyword(p.to_lowercase().into())
        }
        Cond::DomainWildcard(p) => {
            cx.demands.domain = true;
            Node::Wildcard(p.to_lowercase().into_bytes().into())
        }
        Cond::DomainRegex(p) => {
            cx.demands.domain = true;
            Node::Regex(Box::new(regex(p, loc)?))
        }
        Cond::GeoSite(code) => {
            cx.demands.domain = true;
            let slot = cx.env.geo.site_slot(code).map_err(|err| loc.geo(err))?;
            Node::GeoSite(slot)
        }
        Cond::GeoIp(country) | Cond::SrcGeoIp(country) => {
            let src = src || matches!(cond, Cond::SrcGeoIp(_));
            ip_view(cx, src, resolves && !src);
            let country = country.to_lowercase();
            let (negate, country) = match country.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, country.as_str()),
            };
            let source = if country == "lan" {
                GeoIpSource::Lan
            } else {
                cx.env
                    .geo
                    .ensure(GeoFile::Mmdb)
                    .map_err(|err| loc.geo(err))?;
                GeoIpSource::Mmdb
            };
            Node::GeoIp {
                country: country.into(),
                negate,
                source,
                src,
                resolves: resolves && !src,
            }
        }
        Cond::IpAsn(asn) | Cond::SrcIpAsn(asn) => {
            let src = src || matches!(cond, Cond::SrcIpAsn(_));
            ip_view(cx, src, resolves && !src);
            match cx.env.geo.ensure(GeoFile::Asn) {
                Err(GeoError::Missing { .. }) => {
                    if !cx.deferred_geo.contains(&GeoFile::Asn) {
                        cx.deferred_geo.push(GeoFile::Asn);
                    }
                }
                loaded => loaded.map_err(|err| loc.geo(err))?,
            }
            Node::Asn {
                asn: asn.as_str().into(),
                src,
                resolves: resolves && !src,
            }
        }
        Cond::IpCidr(net) | Cond::IpCidr6(net) | Cond::SrcIpCidr(net) => {
            let src = src || matches!(cond, Cond::SrcIpCidr(_));
            ip_view(cx, src, resolves && !src);
            Node::Cidr {
                net: *net,
                src,
                resolves: resolves && !src,
            }
        }
        Cond::IpSuffix(net) | Cond::SrcIpSuffix(net) => {
            let src = src || matches!(cond, Cond::SrcIpSuffix(_));
            ip_view(cx, src, resolves && !src);
            Node::IpSuffix {
                ip: net.addr,
                bits: net.prefix,
                src,
                resolves: resolves && !src,
            }
        }
        Cond::SrcPort(ranges) => port(PortKind::Src, ranges),
        Cond::DstPort(ranges) => port(PortKind::Dst, ranges),
        Cond::InPort(ranges) => port(PortKind::In, ranges),
        Cond::Dscp(ranges) => Node::Dscp(ranges.ranges.as_slice().into()),
        Cond::ProcessName(p) => process(cx, true, ProcessMode::Equal(p.as_str().into())),
        Cond::ProcessPath(p) => process(cx, false, ProcessMode::Equal(p.as_str().into())),
        Cond::ProcessNameRegex(p) => {
            process(cx, true, ProcessMode::Regex(Box::new(regex(p, loc)?)))
        }
        Cond::ProcessPathRegex(p) => {
            process(cx, false, ProcessMode::Regex(Box::new(regex(p, loc)?)))
        }
        Cond::ProcessNameWildcard(p) => process(
            cx,
            true,
            ProcessMode::Wildcard(go_lower(p).into_bytes().into()),
        ),
        Cond::ProcessPathWildcard(p) => process(
            cx,
            false,
            ProcessMode::Wildcard(go_lower(p).into_bytes().into()),
        ),
        Cond::Network(NetworkKind::Tcp) => Node::Network(Network::Tcp),
        Cond::Network(NetworkKind::Udp) => Node::Network(Network::Udp),
        Cond::Uid(ranges) => {
            cx.demands.process = true;
            Node::Uid(ranges.as_slice().into())
        }
        Cond::InType(items) => Node::InType(in_type_mask(items)),
        Cond::InUser(items) => Node::InUser(items.iter().map(|i| i.as_str().into()).collect()),
        Cond::InName(items) => Node::InName(items.iter().map(|i| i.as_str().into()).collect()),
        Cond::RematchName(items) => {
            Node::RematchName(items.iter().map(|i| i.as_str().into()).collect())
        }
        Cond::And(children) => Node::And(children_of(cx, children, loc)?),
        Cond::Or(children) => Node::Or(children_of(cx, children, loc)?),
        Cond::Not(child) => Node::Not(Box::new(node_for_cond(cx, child, false, true, loc)?)),
        Cond::RuleSet(name) => {
            cx.demands.domain = true;
            ip_view(cx, src, resolves && !src);
            let handle =
                cx.env
                    .rule_sets
                    .get(name)
                    .ok_or_else(|| CompileError::UnknownRuleSet {
                        section: loc.section.to_string(),
                        index: loc.index,
                        line: loc.line.to_string(),
                        name: name.clone(),
                    })?;
            cx.rule_sets.push((handle.clone(), src, resolves && !src));
            Node::RuleSet {
                handle,
                src,
                resolves: resolves && !src,
            }
        }
        Cond::Flagged {
            cond,
            src: flagged,
            no_resolve,
        } => {
            let src = src || *flagged;
            node_for_cond(cx, cond, src, resolves && !*no_resolve && !src, loc)?
        }
        Cond::SubRule(_) => {
            return Err(loc.invalid("unsupported rule type [SUB-RULE] on logic rule"));
        }
    })
}

fn children_of(
    cx: &mut Cx<'_>,
    children: &[Cond],
    loc: &Loc<'_>,
) -> Result<Box<[Node]>, CompileError> {
    children
        .iter()
        .map(|child| node_for_cond(cx, child, false, true, loc))
        .collect()
}

fn port(kind: PortKind, ranges: &[concord_config::net::PortRange]) -> Node {
    Node::Port {
        kind,
        ranges: ranges.into(),
    }
}

fn process(cx: &mut Cx<'_>, by_name: bool, mode: ProcessMode) -> Node {
    cx.demands.process = true;
    Node::Process { by_name, mode }
}

fn in_type_mask(items: &[String]) -> u8 {
    const KINDS: [InboundKind; 8] = [
        InboundKind::Http,
        InboundKind::Https,
        InboundKind::Socks4,
        InboundKind::Socks5,
        InboundKind::Redir,
        InboundKind::TProxy,
        InboundKind::Tun,
        InboundKind::Inner,
    ];
    let mut mask = 0u8;
    for item in items {
        let upper = item.to_uppercase();
        for kind in KINDS {
            let wanted = if upper == "SOCKS" {
                matches!(kind, InboundKind::Socks4 | InboundKind::Socks5)
            } else {
                kind.rule_name() == upper
            };
            if wanted {
                mask |= inbound_bit(kind);
            }
        }
    }
    mask
}

pub(crate) struct Classical {
    pub(crate) prog: Prog,
    pub(crate) demands: Demands,
    pub(crate) count: usize,
    pub(crate) warnings: Vec<String>,
    pub(crate) geo_faults: Vec<GeoFault>,
}

const COMMA_IN_PAYLOAD: &[&str] = &[
    "NOT",
    "OR",
    "AND",
    "SUB-RULE",
    "DOMAIN-REGEX",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
];

fn classical_rule(entry: &str) -> Result<RuleDef, String> {
    let items: Vec<&str> = entry
        .split(',')
        .map(|part| part.trim_matches(' '))
        .collect();
    let kind = items.first().copied().unwrap_or_default().to_uppercase();
    if matches!(kind.as_str(), "MATCH" | "RULE-SET" | "SUB-RULE") {
        return Err(format!(
            "unsupported rule type on classical rule-set: {kind}"
        ));
    }
    let with_target = if COMMA_IN_PAYLOAD.contains(&kind.as_str()) {
        format!("{entry},DIRECT")
    } else {
        let payload = items.get(1).copied().unwrap_or_default();
        if payload.is_empty() {
            return Err(format!("missing subsequent parameters: {kind}"));
        }
        let mut parts = vec![
            items.first().copied().unwrap_or_default(),
            payload,
            "DIRECT",
        ];
        parts.extend(items.iter().skip(2));
        parts.join(",")
    };
    parse_rule(&with_target).map_err(|err| err.message)
}

pub(crate) fn compile_classical(entries: &[String], env: &CompileEnv) -> Classical {
    let mut cx = Cx::new(env, false);
    let mut warnings = Vec::new();
    let mut geo_faults = Vec::new();
    let mut defs = Vec::with_capacity(entries.len());
    for entry in entries {
        let def = match classical_rule(entry) {
            Ok(def) => def,
            Err(message) => {
                warnings.push(format!("parse classical rule [{entry}] error: {message}"));
                continue;
            }
        };
        let probe = matches!(
            def.cond,
            Cond::GeoSite(_)
                | Cond::GeoIp(_)
                | Cond::SrcGeoIp(_)
                | Cond::IpAsn(_)
                | Cond::SrcIpAsn(_)
                | Cond::And(_)
                | Cond::Or(_)
                | Cond::Not(_)
        );
        if probe {
            let loc = Loc {
                section: "classical",
                index: defs.len(),
                line: entry,
            };
            let mut scratch = Cx::new(env, false);
            if let Err(err) = node_for_def(&mut scratch, &def, &loc) {
                if let Some(fault) = GeoFault::of(&err)
                    && !geo_faults.contains(&fault)
                {
                    geo_faults.push(fault);
                }
                warnings.push(format!("parse classical rule [{entry}] error: {err}"));
                continue;
            }
        }
        defs.push(def);
    }
    let count = defs.len();
    let prog = compile_list(&mut cx, defs.iter().map(Ok), "classical").unwrap_or_default();
    for file in cx.deferred_geo {
        let fault = GeoFault::Missing(file);
        if !geo_faults.contains(&fault) {
            geo_faults.push(fault);
        }
    }
    Classical {
        prog,
        demands: cx.demands,
        count,
        warnings,
        geo_faults,
    }
}
