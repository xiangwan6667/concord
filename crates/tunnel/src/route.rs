use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use concord_common::{
    CoreError, FindProcessMode, Initiator, IpVersion, LookupIps, Network, Outbound, TunnelMode,
};
use concord_group::{Resolved, Touch};
use concord_rules::{MatchCtx, RuleInfo, Step};
use rand::seq::IndexedRandom;
use tokio::time::timeout;

use crate::flow::FlowState;
use crate::runtime::{LiveOptions, Runtime};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct MatchedRule {
    pub type_name: Arc<str>,
    pub payload: Arc<str>,
}

pub(crate) struct Decision {
    pub target: String,
    pub leaf: Arc<dyn Outbound>,
    pub chain: Box<[Arc<str>]>,
    pub provider_chain: Box<[Arc<str>]>,
    pub exit_group: Option<Arc<str>>,
    pub rule: Option<MatchedRule>,
}

impl Decision {
    fn of(target: &str, resolved: Resolved, rule: Option<MatchedRule>) -> io::Result<Self> {
        match resolved {
            Resolved::Route {
                leaf,
                chain,
                provider_chain,
                exit_group,
                ..
            } => Ok(Decision {
                target: target.to_string(),
                leaf,
                chain,
                provider_chain,
                exit_group,
                rule,
            }),
            Resolved::Rematch(leaf) => Ok(rematch_decision(target, leaf, rule)),
            Resolved::Rejected(reason) => Err(CoreError::Rejected(reason.to_string()).into()),
            Resolved::Pass | Resolved::PassRule | Resolved::Unknown => {
                Err(CoreError::UnknownNode(target.to_string()).into())
            }
        }
    }

    /// `exitName`: a load balancer is the exit, since it spreads connections without
    /// the route moving.
    pub fn exit_name(&self) -> String {
        match &self.exit_group {
            Some(group) => concord_group::load_balancer_exit(group),
            None => concord_group::node_exit(self.leaf.info()),
        }
    }

    /// Mihomo's `Chains.String`: the outermost name with the exit in brackets.
    pub fn chain_text(&self) -> String {
        match (self.chain.first(), self.chain.last()) {
            (None, _) | (_, None) => String::new(),
            (Some(exit), Some(_)) if self.chain.len() == 1 => exit.to_string(),
            (Some(exit), Some(outer)) => format!("{outer}[{exit}]"),
        }
    }

    pub fn dial_label(&self) -> String {
        match &self.rule {
            Some(rule) => format!(
                "{} (match {}/{})",
                self.target, rule.type_name, rule.payload
            ),
            None => self.target.clone(),
        }
    }

    pub fn match_text(&self, flow: &FlowState, live: &LiveOptions) -> String {
        let source = flow.source_detail();
        let remote = flow.remote_text();
        let network = flow.network_name();
        let chain = self.chain_text();
        if flow.special_proxy.is_some() {
            return format!("[{network}] {source} --> {remote} using {chain}");
        }
        match (&self.rule, live.mode) {
            (Some(rule), _) if rule.payload.is_empty() => {
                format!(
                    "[{network}] {source} --> {remote} match {} using {chain}",
                    rule.type_name
                )
            }
            (Some(rule), _) => format!(
                "[{network}] {source} --> {remote} match {}({}) using {chain}",
                rule.type_name, rule.payload
            ),
            (None, TunnelMode::Global) => {
                format!("[{network}] {source} --> {remote} using GLOBAL")
            }
            (None, TunnelMode::Direct) => {
                format!("[{network}] {source} --> {remote} using DIRECT")
            }
            (None, TunnelMode::Rule) => {
                format!("[{network}] {source} --> {remote} doesn't match any rule using {chain}")
            }
        }
    }
}

pub(crate) async fn lookup_process(flow: &mut FlowState, runtime: &Runtime) {
    if flow.process_looked_up {
        return;
    }
    flow.process_looked_up = true;
    let key = flow.owner_key();
    if let Some(known) = runtime.owner_cache.get(&key, Instant::now()) {
        flow.process = known;
        return;
    }
    flow.process = runtime.platform.find_owner(&key).await.map(Arc::new);
    runtime
        .owner_cache
        .put(key, flow.process.clone(), Instant::now());
}

/// `resolveMetadata` and `match`, with the walk through groups and rules made an
/// explicit loop.
pub(crate) async fn route(
    flow: &mut FlowState,
    runtime: &Runtime,
    live: &LiveOptions,
    touch: Touch,
) -> io::Result<Decision> {
    let host_key = flow.host.clone();
    let host_key = host_key.as_deref();
    if let Some(name) = flow.special_proxy.clone() {
        let resolved = runtime
            .outbounds
            .resolve(&name, &flow.meta, host_key, touch);
        return Decision::of(&name, resolved, None);
    }

    if let Some(host) = host_key
        && let (Some(node), true) = runtime.dns.hosts().search(host, false)
    {
        flow.dst_ip = node.rand_ip();
        flow.ip_resolved = true;
    }

    match live.find_process_mode {
        FindProcessMode::Always => lookup_process(flow, runtime).await,
        FindProcessMode::Strict => {}
        FindProcessMode::Off => flow.process_looked_up = true,
    }

    match live.mode {
        TunnelMode::Direct => {
            let resolved = runtime
                .outbounds
                .resolve("DIRECT", &flow.meta, host_key, touch);
            return Decision::of("DIRECT", resolved, None);
        }
        TunnelMode::Global => {
            let resolved = runtime
                .outbounds
                .resolve("GLOBAL", &flow.meta, host_key, touch);
            return Decision::of("GLOBAL", resolved, None);
        }
        TunnelMode::Rule => {}
    }

    match_rules(flow, runtime, touch, host_key).await
}

async fn match_rules(
    flow: &mut FlowState,
    runtime: &Runtime,
    touch: Touch,
    host_key: Option<&str>,
) -> io::Result<Decision> {
    let ctx = MatchCtx {
        geo: &runtime.geo,
        dscp: flow.dscp,
    };
    let mut state = flow.route_state();
    let mut run = runtime.program.start();
    if state.special_rules.is_some() {
        run.restart(state.special_rules.as_deref());
    }
    let mut rematch_chain = Vec::new();
    loop {
        match run.step(&flow.meta, &state, &ctx) {
            Step::Done => {
                flow.observed = run.take_observed();
                let resolved = runtime
                    .outbounds
                    .resolve("DIRECT", &flow.meta, host_key, touch);
                return Decision::of("DIRECT", resolved, None);
            }
            Step::NeedIp => {
                resolve_rule_ip(flow, runtime).await;
                state.ip = flow.dst_ip;
                state.ip_resolved = true;
            }
            Step::NeedProcess => {
                lookup_process(flow, runtime).await;
                state.process = flow.process.clone();
                state.process_looked_up = true;
            }
            Step::Candidate { target, rule } => {
                let candidate = runtime
                    .outbounds
                    .resolve(target, &flow.meta, host_key, Touch::No);
                let (target, candidate) = match candidate {
                    Resolved::Rematch(leaf) => {
                        if rematch(flow, &mut state, leaf.as_ref(), &mut rematch_chain) {
                            run.restart(state.special_rules.as_deref());
                            continue;
                        }
                        flow.observed = run.take_observed();
                        let name = leaf.info().name.clone();
                        return Ok(rematch_decision(
                            &name,
                            leaf,
                            Some(matched_rule(runtime.program.rule_at(rule))),
                        ));
                    }
                    Resolved::Unknown | Resolved::Pass => {
                        run.skip();
                        continue;
                    }
                    Resolved::PassRule if run.in_sub_rule() => {
                        run.skip_pass_rule();
                        continue;
                    }
                    Resolved::PassRule => (
                        "REJECT",
                        runtime
                            .outbounds
                            .resolve("REJECT", &flow.meta, host_key, Touch::No),
                    ),
                    Resolved::Route { udp: false, .. } if flow.meta.network == Network::Udp => {
                        run.skip();
                        continue;
                    }
                    candidate => (target, candidate),
                };
                let resolved = if touch == Touch::Yes && matches!(candidate, Resolved::Route { .. })
                {
                    runtime
                        .outbounds
                        .resolve(target, &flow.meta, host_key, touch)
                } else {
                    candidate
                };
                flow.observed = run.take_observed();
                let matched = matched_rule(runtime.program.rule_at(rule));
                return Decision::of(target, resolved, Some(matched));
            }
        }
    }
}

fn matched_rule(info: RuleInfo<'_>) -> MatchedRule {
    MatchedRule {
        type_name: Arc::from(info.type_name),
        payload: Arc::from(info.payload),
    }
}

fn rematch_decision(target: &str, leaf: Arc<dyn Outbound>, rule: Option<MatchedRule>) -> Decision {
    let name = leaf.info().name.clone();
    Decision {
        target: target.to_string(),
        provider_chain: vec![
            leaf.info()
                .provider
                .clone()
                .unwrap_or_else(|| Arc::from("")),
        ]
        .into(),
        leaf,
        chain: vec![name].into(),
        exit_group: None,
        rule,
    }
}

fn rematch(
    flow: &mut FlowState,
    state: &mut concord_common::RouteState,
    leaf: &dyn Outbound,
    chain: &mut Vec<Arc<str>>,
) -> bool {
    let Some(update) = leaf.rematch() else {
        return false;
    };
    let cycle = chain.contains(&leaf.info().name);
    if let Some(name) = &update.name {
        state.rematch_name = Some(name.clone());
        flow.rematch_name = Some(name.clone());
    }
    if let Some(sub_rule) = &update.sub_rule {
        state.special_rules = Some(sub_rule.clone());
        flow.special_rules = Some(sub_rule.clone());
    }
    if cycle {
        tracing::warn!("[Rule] rematch cycle detected on {}", leaf.info().name);
        false
    } else {
        chain.push(leaf.info().name.clone());
        true
    }
}

fn pick_ip(ips: &LookupIps) -> Option<IpAddr> {
    let pool = if ips.v4.is_empty() { &ips.v6 } else { &ips.v4 };
    pool.choose(&mut rand::rng()).copied()
}

async fn resolve_rule_ip(flow: &mut FlowState, runtime: &Runtime) {
    flow.ip_resolved = true;
    let Some(host) = flow.host.clone() else {
        return;
    };
    let lookup = runtime.dns_lookup(&host, IpVersion::Dual, Initiator::Rule);
    match timeout(DNS_TIMEOUT, lookup).await {
        Ok(Ok(ips)) => {
            flow.dst_ip = pick_ip(&ips);
            if let Some(ip) = flow.dst_ip {
                tracing::debug!("[DNS] {host} --> {ip}");
            }
        }
        Ok(Err(err)) => tracing::debug!("[DNS] resolve {host} error: {err}"),
        Err(_) => tracing::debug!("[DNS] resolve {host} error: timeout"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_v4_answer_wins_over_v6_and_v6_is_the_fallback() {
        let v4: Vec<IpAddr> = ["1.1.1.1", "2.2.2.2"]
            .map(|ip| ip.parse().unwrap())
            .to_vec();
        let v6: Vec<IpAddr> = vec!["2001:db8::1".parse().unwrap()];
        let both = LookupIps {
            v4: v4.clone(),
            v6: v6.clone(),
        };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let ip = pick_ip(&both).unwrap();
            assert!(v4.contains(&ip));
            seen.insert(ip);
        }
        assert_eq!(seen.len(), 2);
        let only_v6 = LookupIps { v4: Vec::new(), v6 };
        assert_eq!(pick_ip(&only_v6), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(pick_ip(&LookupIps::default()), None);
    }
}
