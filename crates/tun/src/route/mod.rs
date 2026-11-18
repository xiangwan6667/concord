mod desktop;
mod linux;
pub mod packages;
mod ranges;
mod strict;
#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "SystemConfiguration is a C API")]
mod system_dns;
#[cfg(windows)]
#[allow(unsafe_code, reason = "the Windows Filtering Platform is a C API")]
mod wfp;

use std::io;
use std::net::IpAddr;

use async_trait::async_trait;
#[cfg(test)]
use concord_common::sync::lock;

use crate::options::{Prefix, TunOptions};

pub use desktop::{ManagerBackend, plan_desktop};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::android_tables;
pub use linux::{plan_android, plan_linux, rules_for, rules_for_android};
pub use ranges::{excluded_uids, subtract};
pub use strict::{Cond, FilterSpec, Layer, StrictRoute, Verdict};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::NetlinkBackend;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Table(u32),
    Goto(u32),
    Nop,
    Unreachable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSpec {
    pub family: Family,
    pub priority: u32,
    pub action: RuleAction,
    pub invert: bool,
    pub iif: Option<String>,
    pub oif: Option<String>,
    pub src: Option<Prefix>,
    pub dst: Option<Prefix>,
    pub uid_range: Option<(u32, u32)>,
    pub sport: Option<(u16, u16)>,
    pub dport: Option<(u16, u16)>,
    pub suppress_prefixlen: Option<u32>,
}

impl RuleSpec {
    pub fn new(family: Family, priority: u32, action: RuleAction) -> Self {
        RuleSpec {
            family,
            priority,
            action,
            invert: false,
            iif: None,
            oif: None,
            src: None,
            dst: None,
            uid_range: None,
            sport: None,
            dport: None,
            suppress_prefixlen: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    pub dest: Prefix,
    pub gateway: Option<IpAddr>,
    pub if_index: u32,
    pub table: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Route(RouteSpec),
    Rule(RuleSpec),
    /// Point the system resolver at the interface: `resolvectl` on Linux, a temporary
    /// dynamic store entry on macOS.
    Dns {
        ifname: String,
        servers: Vec<IpAddr>,
    },
    /// Loose reverse-path filtering on the interface when the system runs it strict.
    RpFilter {
        ifname: String,
    },
    /// Windows firewall filters for `strict-route`; they live as long as the session.
    StrictRoute(StrictRoute),
}

impl Step {
    pub fn describe(&self) -> String {
        match self {
            Step::Route(route) => match route.gateway {
                Some(gateway) => format!("route {} via {gateway}", route.dest),
                None => format!("route {}", route.dest),
            },
            Step::Rule(rule) => {
                format!("rule {} {:?} {:?}", rule.priority, rule.family, rule.action)
            }
            Step::Dns { ifname, .. } => format!("dns on {ifname}"),
            Step::RpFilter { ifname } => format!("rp_filter on {ifname}"),
            Step::StrictRoute(strict) => format!("strict-route on interface {}", strict.if_index),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Add,
    Delete,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<Step>,
    /// Priorities of the policy rules a crashed run may have left behind.
    pub stale_rule_priorities: Option<(u32, u32)>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct IfaceInfo {
    pub name: String,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
    Other,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(target_os = "linux") {
            Os::Linux
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "windows") {
            Os::Windows
        } else {
            Os::Other
        }
    }
}

/// What routes, rules and DNS settings the options need on this platform. Android
/// and anything unknown get an empty plan: the `VpnService` owns the routes there.
pub fn plan(os: Os, options: &TunOptions, iface: &IfaceInfo) -> Plan {
    match os {
        Os::Linux => plan_linux(options, iface),
        Os::MacOs | Os::Windows => plan_desktop(os, options, iface),
        Os::Other => Plan::default(),
    }
}

#[async_trait]
pub trait RouteBackend: Send {
    async fn apply(&mut self, op: Op, step: &Step) -> io::Result<()>;

    /// Removes rules a previous run left behind; returns how many.
    async fn clean_stale(&mut self, priorities: (u32, u32)) -> io::Result<usize>;
}

/// Why a step failed, with how many already-applied steps could not be undone afterwards.
#[derive(Debug, thiserror::Error)]
#[error("{step}: {source}")]
pub struct RouteError {
    pub step: String,
    #[source]
    pub source: io::Error,
    pub undo_failures: usize,
}

pub struct RouteSession<B: RouteBackend> {
    backend: B,
    applied: Vec<Step>,
}

impl<B: RouteBackend> RouteSession<B> {
    /// Applies the plan in order. A failing step undoes the ones before it and reports itself.
    pub async fn install(mut backend: B, plan: &Plan) -> Result<(Self, Vec<String>), RouteError> {
        let mut notes = plan.warnings.clone();
        if let Some(range) = plan.stale_rule_priorities {
            match backend.clean_stale(range).await {
                Ok(0) => {}
                Ok(count) => notes.push(format!("removed {count} stale policy rules")),
                Err(err) => notes.push(format!("stale rule cleanup failed: {err}")),
            }
        }
        let mut session = RouteSession {
            backend,
            applied: Vec::with_capacity(plan.steps.len()),
        };
        for step in &plan.steps {
            if let Err(source) = session.backend.apply(Op::Add, step).await {
                // mihomo runs resolvectl detached and ignores its exit status. It fails
                // whenever systemd-resolved cannot see the interface, such as one inside
                // a network namespace, and the tunnel still works without it.
                if matches!(step, Step::Dns { .. }) {
                    notes.push(format!("{}: {source}", step.describe()));
                    continue;
                }
                let undo_failures = session.teardown().await.len();
                return Err(RouteError {
                    step: step.describe(),
                    source,
                    undo_failures,
                });
            }
            session.applied.push(step.clone());
        }
        Ok((session, notes))
    }

    /// Undoes everything applied, newest first, and keeps going past failures.
    pub async fn teardown(&mut self) -> Vec<RouteError> {
        let mut failures = Vec::new();
        while let Some(step) = self.applied.pop() {
            if let Err(source) = self.backend.apply(Op::Delete, &step).await {
                failures.push(RouteError {
                    step: step.describe(),
                    source,
                    undo_failures: 0,
                });
            }
        }
        failures
    }

    pub fn applied(&self) -> &[Step] {
        &self.applied
    }

    pub fn forget(&mut self, gone: impl Fn(&Step) -> bool) {
        self.applied.retain(|step| !gone(step));
    }

    pub fn into_parts(mut self) -> (B, Vec<Step>) {
        let applied = std::mem::take(&mut self.applied);
        (self.backend, applied)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    pub struct Recorder {
        pub log: Arc<Mutex<Vec<(Op, String)>>>,
        pub fail_add_at: Option<usize>,
        pub fail_delete_of: Option<usize>,
        pub stale: Arc<Mutex<Vec<(u32, u32)>>>,
    }

    #[async_trait]
    impl RouteBackend for Recorder {
        async fn apply(&mut self, op: Op, step: &Step) -> io::Result<()> {
            let mut log = lock(&self.log);
            let adds = log.iter().filter(|(op, _)| *op == Op::Add).count();
            let deletes = log.iter().filter(|(op, _)| *op == Op::Delete).count();
            log.push((op, step.describe()));
            let fail = match op {
                Op::Add => self.fail_add_at == Some(adds),
                Op::Delete => self.fail_delete_of == Some(deletes),
            };
            if fail {
                return Err(io::Error::other("boom"));
            }
            Ok(())
        }

        async fn clean_stale(&mut self, priorities: (u32, u32)) -> io::Result<usize> {
            lock(&self.stale).push(priorities);
            Ok(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Recorder;
    use super::*;

    fn route(dest: &str) -> Step {
        Step::Route(RouteSpec {
            dest: Prefix::parse(dest).unwrap(),
            gateway: None,
            if_index: 1,
            table: None,
        })
    }

    fn plan_of(dests: &[&str]) -> Plan {
        Plan {
            steps: dests.iter().map(|dest| route(dest)).collect(),
            stale_rule_priorities: Some((9000, 9010)),
            warnings: vec!["note".into()],
        }
    }

    #[tokio::test]
    async fn install_cleans_stale_rules_then_applies_in_order() {
        let backend = Recorder::default();
        let log = backend.log.clone();
        let stale = backend.stale.clone();
        let (session, notes) =
            RouteSession::install(backend, &plan_of(&["10.0.0.0/8", "20.0.0.0/8"]))
                .await
                .unwrap();
        assert_eq!(session.applied().len(), 2);
        assert_eq!(*lock(&stale), [(9000, 9010)]);
        assert_eq!(notes, ["note", "removed 2 stale policy rules"]);
        let log = lock(&log);
        assert_eq!(log[0].1, "route 10.0.0.0/8");
        assert_eq!(log[1].1, "route 20.0.0.0/8");
    }

    #[tokio::test]
    async fn a_failing_step_undoes_the_applied_ones_and_names_itself() {
        let backend = Recorder {
            fail_add_at: Some(2),
            ..Recorder::default()
        };
        let log = backend.log.clone();
        let err = match RouteSession::install(
            backend,
            &plan_of(&["10.0.0.0/8", "20.0.0.0/8", "30.0.0.0/8"]),
        )
        .await
        {
            Ok(_) => panic!("install should fail"),
            Err(err) => err,
        };
        assert_eq!(err.step, "route 30.0.0.0/8");
        assert_eq!(err.undo_failures, 0);
        let deleted: Vec<_> = lock(&log)
            .iter()
            .filter(|(op, _)| *op == Op::Delete)
            .map(|(_, what)| what.clone())
            .collect();
        assert_eq!(deleted, ["route 20.0.0.0/8", "route 10.0.0.0/8"]);
    }

    #[tokio::test]
    async fn a_failing_dns_step_is_a_note_and_keeps_the_rest() {
        let backend = Recorder {
            fail_add_at: Some(1),
            ..Recorder::default()
        };
        let mut plan = plan_of(&["10.0.0.0/8"]);
        plan.steps.push(Step::Dns {
            ifname: "tun0".into(),
            servers: vec!["198.18.0.1".parse().unwrap()],
        });
        plan.steps.push(route("20.0.0.0/8"));
        let (session, notes) = RouteSession::install(backend, &plan).await.unwrap();
        assert_eq!(session.applied().len(), 2);
        assert!(notes.iter().any(|note| note.starts_with("dns on tun0")));
    }

    #[tokio::test]
    async fn forgotten_steps_are_not_removed() {
        let backend = Recorder::default();
        let log = backend.log.clone();
        let (mut session, _) =
            RouteSession::install(backend, &plan_of(&["10.0.0.0/8", "20.0.0.0/8"]))
                .await
                .unwrap();
        session.forget(
            |step| matches!(step, Step::Route(route) if route.dest.to_string() == "10.0.0.0/8"),
        );
        assert!(session.teardown().await.is_empty());
        let deleted: Vec<_> = lock(&log)
            .iter()
            .filter(|(op, _)| *op == Op::Delete)
            .map(|(_, step)| step.clone())
            .collect();
        assert_eq!(deleted, ["route 20.0.0.0/8"]);
    }

    #[tokio::test]
    async fn teardown_continues_past_a_failed_removal() {
        let backend = Recorder {
            fail_delete_of: Some(0),
            ..Recorder::default()
        };
        let log = backend.log.clone();
        let (mut session, _) =
            RouteSession::install(backend, &plan_of(&["10.0.0.0/8", "20.0.0.0/8"]))
                .await
                .unwrap();
        let failures = session.teardown().await;
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].step, "route 20.0.0.0/8");
        let deletes = lock(&log)
            .iter()
            .filter(|(op, _)| *op == Op::Delete)
            .count();
        assert_eq!(deletes, 2);
        assert!(session.applied().is_empty());
        assert!(session.teardown().await.is_empty());
    }

    #[test]
    fn android_and_unknown_platforms_plan_nothing() {
        let options = TunOptions {
            auto_route: true,
            inet4_address: vec![Prefix::parse("198.18.0.1/30").unwrap()],
            ..TunOptions::default()
        };
        let iface = IfaceInfo {
            name: "tun0".into(),
            index: 5,
        };
        assert_eq!(plan(Os::Other, &options, &iface), Plan::default());
    }
}
