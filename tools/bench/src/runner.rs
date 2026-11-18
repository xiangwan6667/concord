//! Runs a plan: the origin and server once, then per case every core side by side
//! on its own port, trials interleaved in a rotating order so drift over the run
//! lands on every core alike.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt;
use tokio::process::Child;

use crate::cases::{self, Case};
use crate::core::{CoreSpec, Launch, Running};
use crate::isolate::{self, CpuPlan, Netns, Placement, Role};
use crate::load::{self, Ctx, Metrics, Pids, Workload};
use crate::origin::Ports;
use crate::plan::Plan;
use crate::report::{Cell, Results};
use crate::socks::Entry;

/// The cores of one case started together, and the rounds they run before they stop.
struct Phase<'a> {
    case: &'a Case,
    cores: &'a [usize],
    workloads: &'a [Workload],
    rounds: Range<usize>,
}

/// A core that is already running, typically inside an app, measured as it is.
pub struct Attached {
    pub name: String,
    pub pid: u32,
}

pub struct Rig {
    pub plan: Plan,
    pub cores: Vec<CoreSpec>,
    pub mihomo: PathBuf,
    pub sing_box: Option<PathBuf>,
    pub cpus: Option<CpuPlan>,
    pub netns: Option<Netns>,
    pub dir: PathBuf,
}

struct Far {
    ip: IpAddr,
    ports: Ports,
    origin: Child,
    server: Option<Child>,
    singbox: Option<Child>,
    xray: Option<Child>,
    gost: Vec<(String, Child)>,
    masque: Option<Child>,
    cases: Vec<Case>,
    /// Cases whose listener the server refused, with its reason.
    refused: Vec<(String, String)>,
}

impl Rig {
    fn start_masque_peer(&self, built: &[Case]) -> Result<Option<Child>, String> {
        let child = if let Some(case) = built.iter().find(|case| case.name() == "masque-l4") {
            let proxy = case.proxy.as_ref().ok_or("MASQUE case has no proxy")?;
            let host = proxy["server"].as_str().ok_or("MASQUE server is missing")?;
            let port = proxy["port"].as_u64().ok_or("MASQUE port is missing")?;
            let placement = self.placement(Role::Server);
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let log = std::fs::File::create(self.dir.join("logs/masque.log"))
                .map_err(|e| e.to_string())?;
            let mut command = isolate::command(&exe, &placement);
            let ip: IpAddr = host.parse().map_err(|e| format!("MASQUE server IP: {e}"))?;
            let port = u16::try_from(port).map_err(|e| e.to_string())?;
            let address = std::net::SocketAddr::new(ip, port);
            command
                .args(["masque-server", "--listen", &address.to_string()])
                .stdin(Stdio::null())
                .stdout(log.try_clone().map_err(|e| e.to_string())?)
                .stderr(log);
            Some(
                isolate::spawn(&mut command, &placement)
                    .map_err(|e| format!("spawn MASQUE peer: {e}"))?,
            )
        } else {
            None
        };
        Ok(child)
    }

    fn placement(&self, role: Role) -> Placement {
        Placement {
            cpus: self
                .cpus
                .as_ref()
                .and_then(|p| p.get(role))
                .map(<[usize]>::to_vec),
            netns: match role {
                Role::Server | Role::Origin => self.netns.as_ref().map(|n| n.far.clone()),
                Role::Core | Role::Client => None,
            },
        }
    }

    fn far_ip(&self) -> IpAddr {
        self.netns
            .as_ref()
            .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |n| n.far_ip)
    }

    async fn start_far(&self) -> Result<Far, String> {
        let ip = self.far_ip();
        let (ports, _, origin) = self.start_origin(ip).await?;

        // mihomo reads files only from under its home directory.
        let certs = self.dir.join("server/certs");
        std::fs::create_dir_all(&certs).map_err(|e| e.to_string())?;
        cases::write_certs(&certs).map_err(|e| e.to_string())?;
        let mut port = 21_000 + (std::process::id() % 2000) as u16 * 10;
        let mut built = Vec::new();
        for spec in &self.plan.cases {
            let host = if ip.is_loopback() {
                "127.0.0.1".to_string()
            } else {
                ip.to_string()
            };
            let main = free_port_from(&mut port, ip);
            let decoy = if cases::needs_decoy(*spec) {
                free_port_from(&mut port, ip)
            } else {
                0
            };
            built.push(cases::build(*spec, &host, main, decoy, &certs));
        }
        let server = if built.iter().any(|c| c.listener.is_some()) {
            let home = self.dir.join("server");
            std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
            let config = home.join("config.yaml");
            std::fs::write(&config, cases::server_config(&built)).map_err(|e| e.to_string())?;
            let log = std::fs::File::create(self.dir.join("logs/server.log"))
                .map_err(|e| e.to_string())?;
            let mut command = isolate::command(&self.mihomo, &self.placement(Role::Server));
            command
                .arg("-d")
                .arg(&home)
                .arg("-f")
                .arg(&config)
                .env("DISABLE_LOOPBACK_DETECTOR", "true")
                .stdin(Stdio::null())
                .stdout(log.try_clone().map_err(|e| e.to_string())?)
                .stderr(log);
            Some(
                isolate::spawn(&mut command, &self.placement(Role::Server))
                    .map_err(|e| format!("spawn mihomo server: {e}"))?,
            )
        } else {
            None
        };
        let singbox = if built.iter().any(|c| c.singbox_listener.is_some()) {
            let binary = self
                .sing_box
                .as_ref()
                .ok_or("hysteria-brutal needs --sing-box")?;
            let config = self.dir.join("server/singbox.json");
            std::fs::write(&config, cases::singbox_config(&built).to_string())
                .map_err(|e| e.to_string())?;
            let log = std::fs::File::create(self.dir.join("logs/singbox.log"))
                .map_err(|e| e.to_string())?;
            let placement = self.placement(Role::Server);
            let mut command = isolate::command(binary, &placement);
            command
                .args(["run", "-c"])
                .arg(config)
                .stdin(Stdio::null())
                .stdout(log.try_clone().map_err(|e| e.to_string())?)
                .stderr(log);
            Some(
                isolate::spawn(&mut command, &placement)
                    .map_err(|e| format!("spawn sing-box server: {e}"))?,
            )
        } else {
            None
        };
        let xray = if built.iter().any(|case| case.xray_listener.is_some()) {
            let binary =
                std::env::var_os("CONCORD_XRAY").ok_or("xhttp HTTP/3 needs CONCORD_XRAY")?;
            let config = self.dir.join("server/xray.json");
            std::fs::write(&config, cases::xray_config(&built).to_string())
                .map_err(|err| err.to_string())?;
            let log = std::fs::File::create(self.dir.join("logs/xray.log"))
                .map_err(|err| err.to_string())?;
            let placement = self.placement(Role::Server);
            let mut command = isolate::command(Path::new(&binary), &placement);
            command
                .args(["run", "-config"])
                .arg(config)
                .stdin(Stdio::null())
                .stdout(log.try_clone().map_err(|err| err.to_string())?)
                .stderr(log);
            Some(
                isolate::spawn(&mut command, &placement)
                    .map_err(|err| format!("spawn Xray server: {err}"))?,
            )
        } else {
            None
        };
        let gost = crate::gost::start(&built, &self.dir, &self.placement(Role::Server))?;
        let masque = self.start_masque_peer(&built)?;
        tokio::time::sleep(Duration::from_millis(800)).await;
        let log = std::fs::read_to_string(self.dir.join("logs/server.log")).unwrap_or_default();
        let refused = built
            .iter()
            .filter_map(|c| {
                let marker = format!("Listener {} listen err", c.name());
                let line = log.lines().find(|l| l.contains(&marker))?;
                Some((
                    c.name().to_string(),
                    line.split_once("msg=")
                        .map_or(line, |(_, m)| m)
                        .trim_matches('"')
                        .to_string(),
                ))
            })
            .collect();
        Ok(Far {
            ip,
            ports,
            origin,
            server,
            singbox,
            xray,
            gost,
            masque,
            cases: built,
            refused,
        })
    }

    /// Only the workloads that leave the core as they found it apply, since the
    /// harness cannot restart it. A remote origin is not measured.
    pub async fn run_attached(
        &self,
        attached: &[Attached],
        entry: Entry,
        origin: Option<SocketAddr>,
        results: &mut Results,
        out: &Path,
    ) -> Result<(), String> {
        let (ip, ports, child) = match origin {
            Some(base) => (base.ip(), Ports::from_base(base.port()), None),
            None => {
                let far = self.start_origin(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
                (far.1, far.0, Some(far.2))
            }
        };
        let case = "attached";
        if matches!(entry, Entry::Tun) {
            let target = SocketAddr::new(ip, ports.echo);
            match crate::env::route_interface(target) {
                Some(dev) if dev.starts_with("tun") => {}
                Some(dev) => {
                    return Err(format!(
                        "traffic to {target} leaves through {dev}, not the VPN: this user's traffic is outside the \
                         VPN, or the profile bypasses that address"
                    ));
                }
                None => eprintln!("  warning: could not tell which interface reaches {target}"),
            }
        }
        for a in attached {
            crate::core::echo_once(entry, SocketAddr::new(ip, ports.echo))
                .await
                .map_err(|e| format!("{}: nothing comes back through it: {e}", a.name))?;
        }
        let workloads: Vec<Workload> = self
            .plan
            .workloads
            .iter()
            .copied()
            .filter(|w| !w.fresh_core())
            .collect();
        let subjects: Vec<Option<(String, Ctx)>> = attached
            .iter()
            .map(|a| {
                let pids = Pids {
                    core: a.pid,
                    server: None,
                    origin: child.as_ref().and_then(Child::id),
                };
                Some((a.name.clone(), self.load_ctx(entry, ip, ports, pids)))
            })
            .collect();
        for workload in workloads {
            self.trials(
                case,
                workload,
                &subjects,
                |_| true,
                0..self.plan.rounds,
                results,
                out,
            )
            .await;
        }
        Ok(())
    }

    async fn start_origin(&self, ip: IpAddr) -> Result<(Ports, IpAddr, Child), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut origin = isolate::command(&exe, &self.placement(Role::Origin));
        origin
            .args(["origin", "--bind", &ip.to_string()])
            .args(
                self.plan
                    .origin_rate
                    .map(|rate| format!("--rate-mbit={rate}")),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut origin = isolate::spawn(&mut origin, &self.placement(Role::Origin))
            .map_err(|e| format!("spawn origin: {e}"))?;
        let stdout = origin.stdout.take().ok_or("origin stdout")?;
        let mut line = String::new();
        tokio::io::BufReader::new(stdout)
            .read_line(&mut line)
            .await
            .map_err(|e| format!("origin: {e}"))?;
        let ports: Ports =
            serde_json::from_str(line.trim()).map_err(|e| format!("origin said {line:?}: {e}"))?;
        Ok((ports, ip, origin))
    }

    pub async fn run(&self, results: &mut Results, out: &Path) -> Result<(), String> {
        let mut far = self.start_far().await?;
        let tun = self.plan.tun.then(|| self.tun_section());
        let started = Instant::now();
        for index in 0..far.cases.len() {
            let case = &far.cases[index];
            if let Some((_, reason)) = far.refused.iter().find(|(n, _)| n == case.name()) {
                eprintln!(
                    "  {}: the server refused its listener: {reason}",
                    case.name()
                );
                for w in self.plan.workloads.iter().filter(|w| w.per_case()) {
                    for core in &self.cores {
                        results
                            .cell(case.name(), *w, &core.name)
                            .errors
                            .push(format!("server listener: {reason}"));
                    }
                }
                continue;
            }
            let workloads: Vec<Workload> = self
                .plan
                .workloads
                .iter()
                .copied()
                .filter(|w| w.per_case() && (!w.needs_udp() || case.spec.udp))
                .filter(|_| !self.plan.background.is_some_and(Workload::needs_udp) || case.spec.udp)
                .collect();
            let shared: Vec<Workload> = workloads
                .iter()
                .copied()
                .filter(|w| !w.fresh_core())
                .collect();
            let fresh: Vec<Workload> = workloads
                .iter()
                .copied()
                .filter(|w| w.fresh_core())
                .collect();
            let groups: Vec<Vec<usize>> = if tun.is_some() {
                (0..self.cores.len()).map(|core| vec![core]).collect()
            } else {
                vec![(0..self.cores.len()).collect()]
            };
            let per_process = if self.plan.fresh_cores {
                1
            } else {
                self.plan.rounds.max(1)
            };
            for start in (0..self.plan.rounds).step_by(per_process) {
                for group in &groups {
                    let phase = Phase {
                        case,
                        cores: group,
                        workloads: &shared,
                        rounds: start..(start + per_process).min(self.plan.rounds),
                    };
                    self.shared_phase(&far, phase, tun.as_ref(), results, out)
                        .await;
                }
            }
            for workload in fresh {
                self.fresh_phase(&far, case, workload, tun.as_ref(), results, out)
                    .await;
            }
            eprintln!("  {} done, {:.0?} elapsed", case.name(), started.elapsed());
            check_far(&mut far)?;
        }
        if self.plan.workloads.contains(&Workload::Large) {
            let direct = cases::build(
                cases::find("direct").ok_or("direct case")?,
                "127.0.0.1",
                0,
                0,
                &self.dir,
            );
            self.fresh_phase(&far, &direct, Workload::Large, None, results, out)
                .await;
        }
        drop(far.server.take());
        drop(far.singbox.take());
        drop(far.xray.take());
        drop(std::mem::take(&mut far.gost));
        drop(far.masque.take());
        drop(far.origin);
        Ok(())
    }

    fn tun_section(&self) -> Value {
        json!({
            "enable": true,
            "device": "cbtun0",
            "stack": self.plan.tun_stack,
            "auto-route": true,
            "auto-detect-interface": true,
            "strict-route": false,
            "mtu": self.plan.tun_mtu,
        })
    }

    fn ctx(&self, far: &Far, case: &Case, entry: Entry, core: u32) -> Ctx {
        let pids = Pids {
            core,
            server: if case.xray_listener.is_some() {
                far.xray.as_ref().and_then(Child::id)
            } else if case.gost.is_some() {
                far.gost
                    .iter()
                    .find(|(name, _)| name == case.name())
                    .and_then(|(_, child)| child.id())
            } else if case.name() == "masque-l4" {
                far.masque.as_ref().and_then(Child::id)
            } else if case.singbox_listener.is_some() {
                far.singbox.as_ref().and_then(Child::id)
            } else if case.listener.is_some() {
                far.server.as_ref().and_then(Child::id)
            } else {
                None
            },
            origin: far.origin.id(),
        };
        self.load_ctx(entry, far.ip, far.ports, pids)
    }

    fn load_ctx(&self, entry: Entry, origin: IpAddr, ports: Ports, pids: Pids) -> Ctx {
        Ctx {
            entry,
            origin,
            ports,
            warmup: self.plan.warmup,
            duration: self.plan.duration,
            pids,
            flows: self.plan.flows,
            crr_conns: self.plan.crr_conns,
            crr_concurrency: self.plan.crr_concurrency,
            udp_size: self.plan.udp_size,
            udp_window: self.plan.udp_window,
            idle_conns: self.plan.idle_conns,
            net_counters: self.plan.net_counters,
            far_netns: self.netns.as_ref().map(|n| n.far.clone()),
        }
    }

    async fn launch(
        &self,
        far: &Far,
        case: &Case,
        core: usize,
        tag: &str,
        profile: Option<String>,
        tun: Option<&Value>,
    ) -> Result<Running, String> {
        let spec = &self.cores[core];
        let mixed = free_port(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let home = self
            .dir
            .join("homes")
            .join(format!("{}-{}-{tag}", spec.name, case.name()));
        let _ = std::fs::remove_dir_all(&home);
        let entry = if tun.is_some() {
            Entry::Tun
        } else {
            Entry::Socks(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), mixed))
        };
        let profile = profile.unwrap_or_else(|| cases::client_profile(case, mixed, tun));
        Running::start(Launch {
            spec,
            home,
            profile: profile.replace("mixed-port: 0\n", &format!("mixed-port: {mixed}\n")),
            proxy: case.proxy.clone(),
            tun: tun.cloned(),
            mixed,
            placement: self.placement(Role::Core),
            log: self
                .dir
                .join("logs")
                .join(format!("{}-{}-{tag}.log", spec.name, case.name())),
            probe: SocketAddr::new(far.ip, far.ports.echo),
            entry,
        })
        .await
    }

    async fn shared_phase(
        &self,
        far: &Far,
        phase: Phase<'_>,
        tun: Option<&Value>,
        results: &mut Results,
        out: &Path,
    ) {
        let Phase {
            case,
            cores,
            workloads,
            rounds,
        } = phase;
        if workloads.is_empty() {
            return;
        }
        let tag = if self.plan.fresh_cores {
            format!("shared-r{}", rounds.start)
        } else {
            "shared".to_string()
        };
        let mut running: Vec<Option<Running>> = Vec::new();
        for &core in cores {
            match self.launch(far, case, core, &tag, None, tun).await {
                Ok(r) => running.push(Some(r)),
                Err(err) => {
                    eprintln!("  {} {}: {err}", self.cores[core].name, case.name());
                    for &w in workloads {
                        results
                            .cell(case.name(), w, &self.cores[core].name)
                            .errors
                            .push(err.clone());
                    }
                    running.push(None);
                }
            }
        }
        let subjects: Vec<Option<(String, Ctx)>> = running
            .iter()
            .map(|r| {
                r.as_ref()
                    .map(|r| (r.name.clone(), self.ctx(far, case, r.entry, r.pid)))
            })
            .collect();
        for &workload in workloads {
            let alive = |slot: usize| running[slot].as_mut().is_some_and(Running::alive);
            self.trials(
                case.name(),
                workload,
                &subjects,
                alive,
                rounds.clone(),
                results,
                out,
            )
            .await;
        }
        for r in running.into_iter().flatten() {
            r.stop().await;
        }
    }

    /// One warmup trial per subject, then the trials of `rounds` in rotating order. A
    /// `None` subject failed to start; `alive` is asked before each of its trials.
    #[allow(
        clippy::too_many_arguments,
        reason = "two call sites; a struct would only rename these"
    )]
    async fn trials(
        &self,
        case: &str,
        workload: Workload,
        subjects: &[Option<(String, Ctx)>],
        mut alive: impl FnMut(usize) -> bool,
        rounds: Range<usize>,
        results: &mut Results,
        out: &Path,
    ) {
        if !self.plan.warmup.is_zero() {
            for (_, ctx) in subjects.iter().flatten() {
                let _ = self.loaded(workload, ctx).await;
            }
        }
        for round in rounds {
            for slot in rotation(subjects.len(), round) {
                let Some((name, ctx)) = &subjects[slot] else {
                    continue;
                };
                if !alive(slot) {
                    results
                        .cell(case, workload, name)
                        .errors
                        .push("the core died".into());
                    continue;
                }
                let outcome = self.loaded(workload, ctx).await;
                record(results, case, workload, name, round, outcome);
                tokio::time::sleep(self.plan.gap).await;
            }
        }
        let _ = results.save(out);
    }

    /// One trial of `workload`, beside the plan's background load when it has one. A trial
    /// whose background failed is an error: its figures would be those of an unloaded core.
    async fn loaded(&self, workload: Workload, ctx: &Ctx) -> Result<Metrics, String> {
        let Some(background) = self.plan.background else {
            return load::run(workload, ctx).await;
        };
        let (outcome, beside) = tokio::join!(load::run(workload, ctx), load::run(background, ctx));
        let mut metrics = outcome?;
        let beside = beside.map_err(|err| format!("background {}: {err}", background.name()))?;
        metrics.extend(
            beside
                .into_iter()
                .map(|(name, value)| (format!("bg_{name}"), value)),
        );
        Ok(metrics)
    }

    async fn fresh_phase(
        &self,
        far: &Far,
        case: &Case,
        workload: Workload,
        tun: Option<&Value>,
        results: &mut Results,
        out: &Path,
    ) {
        let profile = (workload == Workload::Large)
            .then(|| cases::large_profile(0, self.plan.large_proxies, self.plan.large_rules));
        for round in 0..self.plan.rounds {
            for slot in rotation(self.cores.len(), round) {
                let name = self.cores[slot].name.clone();
                let outcome = self
                    .fresh_trial(far, case, slot, workload, profile.clone(), tun)
                    .await;
                record(results, case.name(), workload, &name, round, outcome);
            }
        }
        let _ = results.save(out);
    }

    async fn fresh_trial(
        &self,
        far: &Far,
        case: &Case,
        core: usize,
        workload: Workload,
        profile: Option<String>,
        tun: Option<&Value>,
    ) -> Result<Metrics, String> {
        let launch = self.launch(far, case, core, workload.name(), profile, tun);
        let running = launch.await?;
        let pid = running.pid;
        let result = match workload {
            Workload::Idle => load::idle(&self.ctx(far, case, running.entry, pid)).await,
            Workload::Startup => {
                Ok(load::settled(pid, running.ready, Duration::from_secs(2)).await)
            }
            Workload::Large => Ok(load::settled(pid, running.ready, Duration::from_secs(3)).await),
            other => Err(format!("{} is not a fresh-core workload", other.name())),
        };
        let stop = running.stop().await;
        result.map(|mut m| {
            if workload == Workload::Startup {
                m.insert("stop_ms".into(), stop.as_secs_f64() * 1e3);
            }
            m
        })
    }
}

fn record(
    results: &mut Results,
    case: &str,
    workload: Workload,
    core: &str,
    round: usize,
    outcome: Result<Metrics, String>,
) {
    let cell: &mut Cell = results.cell(case, workload, core);
    match outcome {
        Ok(metrics) => {
            let headline = crate::report::headline(workload, &metrics);
            eprintln!(
                "  {case:<13} {:<10} {core:<10} r{round} {headline}",
                workload.name()
            );
            cell.trials.push(metrics);
        }
        Err(err) => {
            eprintln!(
                "  {case:<13} {:<10} {core:<10} r{round} error: {err}",
                workload.name()
            );
            cell.errors.push(err);
        }
    }
}

/// Round `r` starts at a different core each time: ABC, BCA, CAB.
fn rotation(n: usize, round: usize) -> impl Iterator<Item = usize> {
    (0..n).map(move |i| (i + round) % n.max(1))
}

fn check_far(far: &mut Far) -> Result<(), String> {
    for (name, child) in &mut far.gost {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "the gost server for {name} exited: {status}; see logs/{name}-gost.log"
            ));
        }
    }
    if let Ok(Some(status)) = far.origin.try_wait() {
        return Err(format!("the origin exited: {status}"));
    }
    if let Some(server) = far.xray.as_mut()
        && let Some(status) = server.try_wait().map_err(|err| err.to_string())?
    {
        return Err(format!(
            "the Xray server exited: {status}; see logs/xray.log"
        ));
    }
    if let Some(server) = far.masque.as_mut()
        && let Ok(Some(status)) = server.try_wait()
    {
        return Err(format!(
            "the MASQUE peer exited: {status}; see logs/masque.log"
        ));
    }
    if let Some(server) = far.singbox.as_mut()
        && let Ok(Some(status)) = server.try_wait()
    {
        return Err(format!(
            "the sing-box server exited: {status}; see logs/singbox.log"
        ));
    }
    if let Some(server) = far.server.as_mut()
        && let Ok(Some(status)) = server.try_wait()
    {
        return Err(format!(
            "the mihomo server exited: {status}; see logs/server.log"
        ));
    }
    Ok(())
}

fn free_port(ip: IpAddr) -> u16 {
    std::net::TcpListener::bind((ip, 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
}

/// Server ports in the far namespace cannot be probed from here, so they come
/// from a range above the ephemeral one's start, checked locally when on loopback.
fn free_port_from(next: &mut u16, ip: IpAddr) -> u16 {
    loop {
        let port = *next;
        *next = next.wrapping_add(1).max(20_000);
        if !ip.is_loopback() {
            return port;
        }
        let tcp = std::net::TcpListener::bind((ip, port)).is_ok();
        let udp = std::net::UdpSocket::bind((ip, port)).is_ok();
        if tcp && udp {
            return port;
        }
    }
}
