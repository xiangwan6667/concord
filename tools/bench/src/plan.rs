//! The tiers. Their lists and counts live here rather than in a document, so
//! two runs of the same tier measure the same thing.

use std::time::Duration;

use serde::Serialize;

use crate::cases::{self, Spec};
use crate::load::Workload;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// The representative cases: five protocols, the throughput and latency workloads.
    Quick,
    /// Every protocol and workload, run only when the user asks for it.
    Full,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub tier: Tier,
    #[serde(serialize_with = "names")]
    pub cases: Vec<Spec>,
    pub workloads: Vec<Workload>,
    pub rounds: usize,
    pub warmup: Duration,
    pub duration: Duration,
    /// Pause after each trial, so one trial's TIME_WAIT and GC tail stay out of the next.
    pub gap: Duration,
    pub flows: usize,
    pub crr_conns: usize,
    pub crr_concurrency: usize,
    pub udp_size: usize,
    pub udp_window: usize,
    pub idle_conns: usize,
    pub large_proxies: usize,
    pub large_rules: usize,
    pub tun: bool,
    pub tun_stack: String,
    pub tun_mtu: u32,
    /// Start every core afresh for each round of the shared workloads, so the interval covers process starts.
    pub fresh_cores: bool,
    pub count_syscalls: bool,
    pub net_counters: bool,
    pub origin_rate: Option<f64>,
    /// A load that runs through the same core for the whole of every trial of the others.
    pub background: Option<Workload>,
}

fn names<S: serde::Serializer>(cases: &[Spec], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(cases.iter().map(|c| c.name))
}

impl Plan {
    pub fn tier(tier: Tier) -> Plan {
        use Workload::*;
        match tier {
            Tier::Quick => Plan {
                tier,
                cases: cases::QUICK.iter().filter_map(|n| cases::find(n)).collect(),
                workloads: vec![TcpDown, TcpUp, TcpRr, TcpCrr, UdpStream, Startup],
                rounds: 5,
                warmup: Duration::from_millis(700),
                duration: Duration::from_secs(3),
                gap: Duration::from_millis(200),
                flows: 4,
                crr_conns: 1500,
                crr_concurrency: 16,
                udp_size: 1200,
                udp_window: 64,
                idle_conns: 500,
                large_proxies: 5_000,
                large_rules: 50_000,
                tun: false,
                tun_stack: "system".into(),
                tun_mtu: 1500,
                fresh_cores: false,
                count_syscalls: false,
                net_counters: false,
                origin_rate: None,
                background: None,
            },
            Tier::Full => Plan {
                tier,
                cases: cases::ALL
                    .iter()
                    .filter(|case| !matches!(case.name, "ss-gost" | "gost-relay"))
                    .copied()
                    .collect(),
                workloads: Workload::ALL.to_vec(),
                rounds: 5,
                warmup: Duration::from_secs(1),
                duration: Duration::from_secs(5),
                gap: Duration::from_millis(300),
                flows: 8,
                crr_conns: 3000,
                crr_concurrency: 32,
                udp_size: 1200,
                udp_window: 64,
                idle_conns: 2000,
                large_proxies: 20_000,
                large_rules: 200_000,
                tun: false,
                tun_stack: "system".into(),
                tun_mtu: 1500,
                fresh_cores: false,
                count_syscalls: false,
                net_counters: false,
                origin_rate: None,
                background: None,
            },
        }
    }

    pub fn estimate(&self, cores: usize) -> Duration {
        let stream = self.warmup + self.duration + self.gap + Duration::from_millis(300);
        let mut per_case = Duration::ZERO;
        let mut once = Duration::ZERO;
        for w in &self.workloads {
            let trial = match w {
                Workload::Startup => Duration::from_secs(3),
                Workload::Idle => Duration::from_secs(8),
                Workload::Large => Duration::from_secs(15),
                Workload::TcpCrr => Duration::from_secs(3),
                _ => stream,
            };
            let warmups = match (w.fresh_core(), self.fresh_cores) {
                (true, _) => 0,
                (false, false) => 1,
                (false, true) => self.rounds as u32,
            };
            let total = trial * (self.rounds as u32 + warmups) * cores as u32;
            if w.per_case() {
                per_case += total;
            } else {
                once += total;
            }
        }
        per_case * self.cases.len() as u32 + once
    }
}
