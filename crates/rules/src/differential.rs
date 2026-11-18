use std::collections::HashMap;
use std::net::IpAddr;

use concord_common::{InboundKind, Network};
use concord_config::net::IpCidr;
use concord_config::rule::{NetworkKind, parse_rule};
use indexmap::IndexMap;
use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use rand::{Rng, SeedableRng};

use crate::geo::is_lan;
use crate::testkit::{Flow, Kit, Trace, drive};
use crate::text::{equal_fold, wildcard_match};
use crate::{Behavior, Cond, RouteProgram, RuleDef, RuleSet};

const HOSTS: [&str; 12] = [
    "a.com",
    "x.a.com",
    "deep.x.a.com",
    "b.com",
    "www.b.com",
    "c.org",
    "zzz.net",
    "kw.io",
    "kwa.com",
    "d.c.org",
    "ab.com",
    "1.example",
];
const IPS: [&str; 8] = [
    "10.1.1.1",
    "10.2.0.5",
    "20.1.1.1",
    "192.168.1.9",
    "8.8.8.8",
    "30.0.0.1",
    "::1",
    "2001:db8::5",
];
const CIDRS: [&str; 9] = [
    "10.0.0.0/8",
    "10.1.0.0/16",
    "20.0.0.0/8",
    "192.168.1.0/24",
    "8.8.8.8/32",
    "30.0.0.0/8",
    "2001:db8::/32",
    "::1/128",
    "0.0.0.0/0",
];
const WILDCARDS: [&str; 4] = ["*.a.com", "x.*.com", "*b*", "d?.c.org"];
const REGEXES: [&str; 3] = ["^x\\.", "\\.org$", "^[a-z]{1,2}\\.com$"];
const TARGETS: [&str; 6] = ["T0", "T1", "T2", "T3", "PASS", "PASS-RULE"];
const PROCESSES: [&str; 3] = ["curl", "chrome", "wget"];

struct SetModel {
    behavior: Behavior,
    domains: Vec<&'static str>,
    cidrs: Vec<IpCidr>,
    rules: Vec<RuleDef>,
}

struct Case {
    rules: Vec<String>,
    subs: Vec<(String, Vec<String>)>,
}

fn choose<'a, T: ?Sized>(rng: &mut StdRng, items: &[&'a T]) -> &'a T {
    items.choose(rng).copied().unwrap_or(items[0])
}

fn flags(rng: &mut StdRng) -> &'static str {
    match rng.random_range(0..6) {
        0 => ",no-resolve",
        1 => ",src",
        _ => "",
    }
}

fn simple_cond(rng: &mut StdRng, with_flags: bool) -> String {
    let flag = if with_flags { flags(rng) } else { "" };
    match rng.random_range(0..17) {
        0 => format!("DOMAIN,{}", choose(rng, &HOSTS)),
        1 => format!(
            "DOMAIN-SUFFIX,{}",
            choose(rng, &["a.com", "x.a.com", "c.org", "b.com", "io"])
        ),
        2 => format!(
            "DOMAIN-KEYWORD,{}",
            choose(rng, &["kw", "zz", "a.c", "org"])
        ),
        3 => format!("DOMAIN-WILDCARD,{}", choose(rng, &WILDCARDS)),
        4 => format!("DOMAIN-REGEX,{}", choose(rng, &REGEXES)),
        5..=7 => format!("IP-CIDR,{}{flag}", choose(rng, &CIDRS)),
        8 => format!(
            "SRC-IP-CIDR,{}",
            choose(rng, &["192.168.1.0/24", "10.0.0.0/8"])
        ),
        9 => format!("GEOIP,LAN{flag}"),
        10 => format!("NETWORK,{}", choose(rng, &["tcp", "udp"])),
        11 => format!("DST-PORT,{}", choose(rng, &["443", "80", "8000-9000"])),
        12 => format!("PROCESS-NAME,{}", choose(rng, &PROCESSES)),
        13 => format!("UID,{}", choose(rng, &["1000", "500-600", "0"])),
        14 => format!("IN-TYPE,{}", choose(rng, &["HTTP", "SOCKS", "TUN"])),
        _ => format!("RULE-SET,{}{flag}", choose(rng, &["dom", "ips", "cls"])),
    }
}

fn logic(rng: &mut StdRng, depth: u32) -> String {
    let count = rng.random_range(1..4);
    let mut children = Vec::new();
    for _ in 0..count {
        if depth == 0 && rng.random_bool(0.2) {
            children.push(format!(
                "({})",
                logic(rng, 1)
                    .rsplit_once(',')
                    .map(|x| x.0.to_string())
                    .unwrap_or_default()
            ));
        } else {
            children.push(format!("({})", simple_cond(rng, true)));
        }
    }
    match rng.random_range(0..3) {
        0 => format!("AND,({}),{}", children.join(","), choose(rng, &TARGETS)),
        1 => format!("OR,({}),{}", children.join(","), choose(rng, &TARGETS)),
        _ => format!(
            "NOT,({}),{}",
            children.first().cloned().unwrap_or_default(),
            choose(rng, &TARGETS)
        ),
    }
}

fn rule_line(rng: &mut StdRng, sub_names: &[&str]) -> String {
    let roll = rng.random_range(0..20);
    if roll == 0 {
        return logic(rng, 0);
    }
    if roll == 1 && !sub_names.is_empty() {
        return format!(
            "SUB-RULE,({}),{}",
            simple_cond(rng, true),
            choose(rng, sub_names)
        );
    }
    let cond = simple_cond(rng, true);
    let target = choose(rng, &TARGETS);
    match cond.matches(',').count() {
        1 => format!("{cond},{target}"),
        _ => {
            let (head, flag) = cond.rsplit_once(',').unwrap_or((&cond, ""));
            if flag == "no-resolve" || flag == "src" {
                format!("{head},{target},{flag}")
            } else {
                format!("{cond},{target}")
            }
        }
    }
}

fn list(rng: &mut StdRng, length: usize, sub_names: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    while out.len() < length {
        let burst = if rng.random_bool(0.5) {
            rng.random_range(1..14)
        } else {
            1
        };
        let family = rng.random_range(0..3);
        for _ in 0..burst {
            let line = match family {
                0 => {
                    let host = choose(
                        rng,
                        &["a.com", "x.a.com", "c.org", "b.com", "kw", "*.a.com", "zzz"],
                    );
                    let target = choose(rng, &TARGETS);
                    match rng.random_range(0..4) {
                        0 => format!("DOMAIN,{},{target}", choose(rng, &HOSTS)),
                        1 => format!("DOMAIN-SUFFIX,{host},{target}").replace("*.a.com", "a.com"),
                        2 => format!(
                            "DOMAIN-KEYWORD,{},{target}",
                            choose(rng, &["kw", "zz", "org"])
                        ),
                        _ => format!("DOMAIN-WILDCARD,{},{target}", choose(rng, &WILDCARDS)),
                    }
                }
                1 => {
                    let target = choose(rng, &TARGETS);
                    let cidr = choose(rng, &CIDRS);
                    format!("IP-CIDR,{cidr},{target}{}", flags(rng))
                }
                _ => rule_line(rng, sub_names),
            };
            out.push(line);
        }
    }
    if rng.random_bool(0.3) {
        out.push(format!("MATCH,{}", choose(rng, &TARGETS)));
    }
    out
}

fn generate(rng: &mut StdRng) -> Case {
    let length = rng.random_range(1..60);
    let mut subs = Vec::new();
    let first = rng.random_range(1..8);
    subs.push(("s0".to_string(), list(rng, first, &[])));
    let second = rng.random_range(1..8);
    subs.push(("s1".to_string(), list(rng, second, &["s0"])));
    Case {
        rules: list(rng, length, &["s0", "s1"]),
        subs,
    }
}

fn flow(rng: &mut StdRng) -> Flow {
    let mut flow = if rng.random_bool(0.3) {
        Flow::ip(choose(rng, &IPS))
    } else {
        Flow::domain(choose(rng, &HOSTS))
    };
    flow.resolves_to = rng
        .random_bool(0.8)
        .then(|| choose(rng, &IPS).parse().unwrap());
    flow.network = if rng.random_bool(0.3) {
        Network::Udp
    } else {
        Network::Tcp
    };
    flow.dst_port = *[443u16, 80, 8443, 8080].choose(rng).unwrap();
    flow.src = format!(
        "{}:{}",
        choose(rng, &["192.168.1.5", "10.1.1.9", "172.16.0.2"]),
        50000
    )
    .parse()
    .unwrap();
    flow.kind = *[InboundKind::Http, InboundKind::Socks5, InboundKind::Tun]
        .choose(rng)
        .unwrap();
    flow.process = rng.random_bool(0.7).then(|| {
        (
            choose(rng, &PROCESSES),
            "/usr/bin/p",
            *[0u32, 500, 550, 1000].choose(rng).unwrap(),
        )
    });
    flow
}

fn install_sets(kit: &Kit) -> HashMap<&'static str, SetModel> {
    let env = kit.env(8);
    let domains = vec!["+.a.com", "b.com", "+.c.org", "kw.io"];
    let cidrs = [
        "10.0.0.0/8",
        "192.168.1.0/24",
        "2001:db8::/32",
        "8.8.8.8/32",
    ];
    let classical: [(&str, &str); 6] = [
        ("DOMAIN-KEYWORD,kw", ""),
        ("IP-CIDR,30.0.0.0/8", "no-resolve"),
        ("IP-CIDR,20.0.0.0/8", ""),
        ("SRC-IP-CIDR,10.1.1.0/24", ""),
        ("DOMAIN-SUFFIX,c.org", ""),
        ("IP-CIDR,192.168.1.0/24", ""),
    ];
    let mut out = HashMap::new();

    let strings = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    kit.sets
        .declare("dom", Behavior::Domain)
        .store(RuleSet::from_entries(Behavior::Domain, &strings(&domains), &env).set);
    out.insert(
        "dom",
        SetModel {
            behavior: Behavior::Domain,
            domains: domains
                .iter()
                .map(|d| &*Box::leak(d.to_string().into_boxed_str()))
                .collect(),
            cidrs: Vec::new(),
            rules: Vec::new(),
        },
    );

    kit.sets
        .declare("ips", Behavior::IpCidr)
        .store(RuleSet::from_entries(Behavior::IpCidr, &strings(&cidrs), &env).set);
    out.insert(
        "ips",
        SetModel {
            behavior: Behavior::IpCidr,
            domains: Vec::new(),
            cidrs: cidrs.iter().map(|c| IpCidr::parse(c).unwrap()).collect(),
            rules: Vec::new(),
        },
    );

    let entries: Vec<String> = classical
        .iter()
        .map(|(rule, flag)| {
            if flag.is_empty() {
                rule.to_string()
            } else {
                format!("{rule},{flag}")
            }
        })
        .collect();
    kit.sets
        .declare("cls", Behavior::Classical)
        .store(RuleSet::from_entries(Behavior::Classical, &entries, &env).set);
    let rules = classical
        .iter()
        .map(|(rule, flag)| {
            let (kind, payload) = rule.split_once(',').unwrap();
            let line = if flag.is_empty() {
                format!("{kind},{payload},X")
            } else {
                format!("{kind},{payload},X,{flag}")
            };
            parse_rule(&line).unwrap()
        })
        .collect();
    out.insert(
        "cls",
        SetModel {
            behavior: Behavior::Classical,
            domains: Vec::new(),
            cidrs: Vec::new(),
            rules,
        },
    );
    out
}

#[derive(Clone, Copy)]
struct View {
    swapped: bool,
    quiet: bool,
}

struct Model<'a> {
    flow: &'a Flow,
    sets: &'a HashMap<&'static str, SetModel>,
    subs: &'a IndexMap<String, Vec<RuleDef>>,
    ip: Option<IpAddr>,
    resolved: bool,
    process_done: bool,
    accept_first: bool,
    done: bool,
    trace: Trace,
}

impl Model<'_> {
    fn host(&self) -> &str {
        self.flow
            .host
            .filter(|_| self.flow.literal_ip.is_none())
            .unwrap_or("")
    }

    fn dst(&mut self, view: View, resolves: bool) -> Option<IpAddr> {
        if view.swapped {
            return Some(self.flow.src.ip());
        }
        let unknown = self.ip.is_none() && !self.resolved && self.flow.literal_ip.is_none();
        if unknown && resolves && !view.quiet {
            self.trace.ip_lookups += 1;
            self.ip = self.flow.resolves_to;
            self.resolved = true;
        }
        self.ip
    }

    fn src(&self, view: View) -> Option<IpAddr> {
        if view.swapped {
            self.ip
        } else {
            Some(self.flow.src.ip())
        }
    }

    fn process(&mut self) -> (&'static str, &'static str, Option<u32>) {
        if !self.process_done {
            self.process_done = true;
            self.trace.process_lookups += 1;
        }
        self.flow
            .process
            .map_or(("", "", None), |(name, path, uid)| (name, path, Some(uid)))
    }

    fn ip_view(&mut self, view: View, src: bool, resolves: bool) -> Option<IpAddr> {
        if src {
            self.src(view)
        } else {
            self.dst(view, resolves)
        }
    }

    fn eval(&mut self, cond: &Cond, src: bool, resolves: bool, view: View) -> bool {
        match cond {
            Cond::Match => true,
            Cond::Domain(p) => self.host() == p.to_lowercase(),
            Cond::DomainSuffix(p) => {
                let p = p.to_lowercase();
                let host = self.host();
                host == p || host.ends_with(&format!(".{p}"))
            }
            Cond::DomainKeyword(p) => self.host().contains(&p.to_lowercase()),
            Cond::DomainWildcard(p) => {
                wildcard_match(p.to_lowercase().as_bytes(), self.host().as_bytes(), false)
            }
            Cond::DomainRegex(p) => regex::Regex::new(p).unwrap().is_match(self.host()),
            Cond::IpCidr(net) | Cond::IpCidr6(net) | Cond::SrcIpCidr(net) => {
                let src = src || matches!(cond, Cond::SrcIpCidr(_));
                self.ip_view(view, src, resolves && !src)
                    .is_some_and(|ip| net.contains(ip))
            }
            Cond::GeoIp(country) => {
                assert_eq!(country.to_lowercase(), "lan");
                self.ip_view(view, src, resolves && !src)
                    .is_some_and(is_lan)
            }
            Cond::Network(kind) => {
                self.flow.network
                    == if matches!(kind, NetworkKind::Tcp) {
                        Network::Tcp
                    } else {
                        Network::Udp
                    }
            }
            Cond::DstPort(ranges) => {
                let port = if view.swapped {
                    self.flow.src.port()
                } else {
                    self.flow.dst_port
                };
                ranges.iter().any(|r| r.contains(port))
            }
            Cond::ProcessName(name) => equal_fold(self.process().0, name),
            Cond::Uid(ranges) => match self.process().2 {
                Some(uid) if uid != 0 => ranges.iter().any(|r| (r.start..=r.end).contains(&uid)),
                _ => false,
            },
            Cond::InType(items) => items.iter().any(|item| {
                let want = item.to_uppercase();
                want == self.flow.kind.rule_name()
                    || (want == "SOCKS" && self.flow.kind == InboundKind::Socks5)
            }),
            Cond::And(children) => children.iter().all(|c| self.eval(c, false, true, view)),
            Cond::Or(children) => children.iter().any(|c| self.eval(c, false, true, view)),
            Cond::Not(child) => !self.eval(child, false, true, view),
            Cond::Flagged {
                cond,
                src: flagged,
                no_resolve,
            } => {
                let src = src || *flagged;
                self.eval(cond, src, resolves && !*no_resolve && !src, view)
            }
            Cond::RuleSet(name) => {
                let inner = if src {
                    View {
                        swapped: true,
                        quiet: true,
                    }
                } else if !resolves {
                    View {
                        quiet: true,
                        ..view
                    }
                } else {
                    view
                };
                self.set(name, inner)
            }
            other => panic!("unmodelled {}", other.type_name()),
        }
    }

    fn set(&mut self, name: &str, view: View) -> bool {
        let sets = self.sets;
        let model = &sets[name];
        match model.behavior {
            Behavior::Domain => {
                let host = self.host();
                !host.is_empty()
                    && model
                        .domains
                        .iter()
                        .any(|entry| match entry.strip_prefix("+.") {
                            Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
                            None => host == *entry,
                        })
            }
            Behavior::IpCidr => {
                let ip = self.dst(view, true);
                ip.is_some_and(|ip| model.cidrs.iter().any(|net| net.contains(ip)))
            }
            Behavior::Classical => {
                for rule in &model.rules {
                    let (src, resolves) = (rule.src, !rule.no_resolve && !rule.src);
                    if self.eval(&rule.cond, src, resolves, view) {
                        return true;
                    }
                }
                false
            }
        }
    }

    fn matches(&mut self, def: &RuleDef) -> bool {
        let view = View {
            swapped: false,
            quiet: false,
        };
        match &def.cond {
            Cond::SubRule(inner) => self.eval(inner, false, true, view),
            cond => self.eval(cond, def.src, !def.no_resolve && !def.src, view),
        }
    }

    /// Returns true when the caller's list is abandoned (a sub-rule candidate that is not `PASS-RULE`).
    fn run(&mut self, list: &[RuleDef], top: Option<usize>) -> bool {
        for (i, def) in list.iter().enumerate() {
            if self.done {
                return false;
            }
            let idx = top.unwrap_or(i);
            if !self.matches(def) {
                continue;
            }
            if let Cond::SubRule(_) = def.cond {
                let subs = self.subs;
                let sub = subs.get(def.target.as_str()).map_or(&[][..], Vec::as_slice);
                if self.run(sub, Some(idx)) && top.is_some() {
                    return true;
                }
                continue;
            }
            self.trace.candidates.push((idx, def.target.clone()));
            match def.target.as_str() {
                "PASS-RULE" => {}
                "PASS" => {
                    if top.is_some() {
                        return true;
                    }
                }
                _ if self.accept_first => {
                    self.trace.accepted = self.trace.candidates.last().cloned();
                    self.done = true;
                    return false;
                }
                _ => {
                    if top.is_some() {
                        return true;
                    }
                }
            }
        }
        false
    }
}

fn oracle(
    case: &[RuleDef],
    subs: &IndexMap<String, Vec<RuleDef>>,
    sets: &HashMap<&'static str, SetModel>,
    flow: &Flow,
    accept_first: bool,
) -> Trace {
    let mut model = Model {
        flow,
        sets,
        subs,
        ip: flow.literal_ip,
        resolved: flow.literal_ip.is_some(),
        process_done: false,
        accept_first,
        done: false,
        trace: Trace::default(),
    };
    model.run(case, None);
    model.trace
}

fn compile_case(
    kit: &Kit,
    case: &Case,
    merge: usize,
) -> (RouteProgram, Vec<RuleDef>, IndexMap<String, Vec<RuleDef>>) {
    let parse = |lines: &[String]| -> Vec<RuleDef> {
        lines
            .iter()
            .map(|line| parse_rule(line).unwrap_or_else(|err| panic!("{line}: {err}")))
            .collect()
    };
    let rules = parse(&case.rules);
    let subs: IndexMap<String, Vec<RuleDef>> = case
        .subs
        .iter()
        .map(|(name, lines)| (name.clone(), parse(lines)))
        .collect();
    let program = RouteProgram::compile(&rules, &subs, &kit.env(merge))
        .unwrap_or_else(|err| panic!("{err}\n{:#?}", case.rules));
    (program, rules, subs)
}

#[derive(Default)]
struct Coverage {
    probes: usize,
    candidates: usize,
    accepted: usize,
    ip_lookups: u32,
    process_lookups: u32,
}

fn run_seed(seed: u64, cases: usize, flows: usize) -> Coverage {
    let mut seen = Coverage::default();
    let mut rng = StdRng::seed_from_u64(seed);
    let kit = Kit::new();
    let sets = install_sets(&kit);
    for case_no in 0..cases {
        let case = generate(&mut rng);
        let probes: Vec<Flow> = (0..flows).map(|_| flow(&mut rng)).collect();
        for merge in [1, 2, 8] {
            let (program, rules, subs) = compile_case(&kit, &case, merge);
            for flow in &probes {
                for accept_first in [false, true] {
                    let want = oracle(&rules, &subs, &sets, flow, accept_first);
                    let got = drive(&program, &kit.geo, flow, accept_first);
                    seen.probes += 1;
                    seen.candidates += got.candidates.len();
                    seen.accepted += usize::from(got.accepted.is_some());
                    seen.ip_lookups += got.ip_lookups;
                    seen.process_lookups += got.process_lookups;
                    assert!(
                        want == got,
                        "seed {seed} case {case_no} merge {merge} accept_first {accept_first}\nrules: {:#?}\nsubs: {:#?}\nflow host {:?} ip {:?} resolves {:?} net {:?} src {} port {} proc {:?}\nwant {want:?}\n got {got:?}",
                        case.rules,
                        case.subs,
                        flow.host,
                        flow.literal_ip,
                        flow.resolves_to,
                        flow.network,
                        flow.src,
                        flow.dst_port,
                        flow.process,
                    );
                }
            }
        }
    }
    seen
}

#[test]
fn programs_agree_with_a_linear_evaluator() {
    let mut total = Coverage::default();
    for seed in 0..6 {
        let seen = run_seed(seed, 120, 12);
        total.probes += seen.probes;
        total.candidates += seen.candidates;
        total.accepted += seen.accepted;
        total.ip_lookups += seen.ip_lookups;
        total.process_lookups += seen.process_lookups;
    }
    eprintln!(
        "probes {} candidates {} accepted {} ip lookups {} process lookups {}",
        total.probes, total.candidates, total.accepted, total.ip_lookups, total.process_lookups
    );
    assert!(total.accepted > total.probes / 4);
    assert!(total.candidates > total.probes);
    assert!(total.ip_lookups > 1000 && total.process_lookups > 1000);
}

#[test]
#[ignore = "long-running soak"]
fn programs_agree_with_a_linear_evaluator_soak() {
    for seed in 100..160 {
        run_seed(seed, 300, 20);
    }
}
