//! `concord-bench`: Concord against mihomo, and against Concord at another
//! commit, per protocol. See `.agents/benchmarking.md`.

#![allow(
    clippy::disallowed_methods,
    reason = "the harness and its peers stand for the outside world, not the core's own sockets"
)]
#![allow(
    clippy::undocumented_unsafe_blocks,
    reason = "each unsafe use in the harness states its argument in its allow(unsafe_code) reason"
)]

mod awake;
mod cases;
mod control;
mod core;
mod env;
mod gost;
mod isolate;
mod load;
mod masque;
mod netstat;
mod origin;
mod plan;
mod probe;
mod report;
mod revs;
mod runner;
mod sockets;
mod socks;
mod stats;
mod syscalls;

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::core::{CoreSpec, Kind};
use crate::isolate::{CpuPlan, Link, Netns, Role};
use crate::load::Workload;
use crate::plan::{Plan, Tier};
use crate::report::Results;

#[derive(Parser)]
#[command(
    name = "concord-bench",
    version,
    about = "Throughput, latency and cost of Concord against mihomo and other Concord builds"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(hide = true)]
    MasqueServer {
        #[arg(long)]
        listen: std::net::SocketAddr,
    },
    #[command(about = "Measure a tier.")]
    Run(Box<RunArgs>),
    #[command(about = "Compare two results.json files and fail on a significant regression.")]
    Compare(CompareArgs),
    #[command(about = "Print the cases, workloads and tiers.")]
    List,
    #[command(hide = true)]
    #[command(
        about = "Serve the origin. With --base-port its ports are fixed (source, sink, echo, crr, udp in order), for a harness on another machine."
    )]
    Origin {
        #[arg(long)]
        bind: IpAddr,
        #[arg(long)]
        base_port: Option<u16>,
        #[arg(long)]
        rate_mbit: Option<f64>,
    },
    #[command(hide = true)]
    #[command(about = "One of the busy loops of run --keep-awake.")]
    Spin {
        #[arg(long)]
        cpu: usize,
        #[arg(long)]
        parent: u32,
    },
}

#[derive(Args)]
struct RunArgs {
    #[arg(long, value_enum, default_value = "quick")]
    tier: Tier,
    #[arg(
        help = "`NAME=concord:PATH`, `NAME=mihomo:PATH`, `NAME=singbox:PATH` (the direct, trojan-tls and plain Shadowsocks cases), `NAME=ssrust:PATH` (sslocal), or `NAME=rev:GITREV`, repeatable. The first is the subject; the others are what it is compared with. Defaults to `concord=concord:target/release/concord` and, with --mihomo, `go=mihomo:<that binary>`."
    )]
    #[arg(long = "core")]
    cores: Vec<String>,
    #[arg(
        help = "The mihomo binary that serves the protocol cases; xhttp HTTP/3 uses CONCORD_XRAY. Upstream builds start their `listeners:`; some forks of Clash.Meta do not."
    )]
    #[arg(long, env = "MIHOMO")]
    mihomo: Option<PathBuf>,
    #[arg(
        long,
        help = "sing-box with QUIC support, serving the Hysteria v1 Brutal case."
    )]
    sing_box: Option<PathBuf>,
    #[arg(help = "Comma-separated case names; replaces the tier's list.")]
    #[arg(long, value_delimiter = ',')]
    cases: Vec<String>,
    #[arg(help = "Comma-separated workload names; replaces the tier's list.")]
    #[arg(long, value_delimiter = ',')]
    workloads: Vec<String>,
    #[arg(long)]
    rounds: Option<usize>,
    #[arg(help = "Seconds each throughput or latency window lasts.")]
    #[arg(long)]
    duration: Option<f64>,
    #[arg(help = "Seconds of traffic before each window opens.")]
    #[arg(long)]
    warmup: Option<f64>,
    #[arg(help = "Connections each tcp-crr window opens, in place of the tier's count.")]
    #[arg(long)]
    crr_conns: Option<usize>,
    #[arg(
        help = "Linux: `core=0-1,server=2-3,origin=4,client=5-7`, or `off`. By default the CPUs this process may use are split between the four."
    )]
    #[arg(long)]
    cpus: Option<String>,
    #[arg(
        help = "Linux, as root: put the server and origin behind a veth pair in their own network namespace, shaped by netem. `veth`, `lan`, `wan`, `lossy`, or `rtt=40ms,rate=200mbit,loss=0.5%`."
    )]
    #[arg(long)]
    link: Option<String>,
    #[arg(
        help = "Linux, as root: send the load through the core's TUN device instead of its mixed port. Implies `--link veth` unless --link is given."
    )]
    #[arg(long)]
    tun: bool,
    #[arg(
        help = "With --tun, also run the mihomo cores on the TUN entry. They are diagnostic arms: the TUN reference is a sing-box core (`NAME=singbox:PATH`), which runs sing-tun's default Go stack."
    )]
    #[arg(long)]
    tun_mihomo: bool,
    #[arg(long, default_value = "system")]
    tun_stack: String,
    #[arg(long, default_value_t = 1500)]
    tun_mtu: u32,
    #[arg(
        help = "Start every core afresh for each round of the workloads that otherwise share one core process per case (tcp, udp), so the interval covers process starts. Each new process gets its own warmup trial."
    )]
    #[arg(long)]
    fresh_cores: bool,
    #[arg(
        help = "Linux, usually as root: count the core's and the server's system calls by name with the syscall tracepoints. While they are on, every system call on the machine takes the kernel's slow path, so use such a run for counts, not for timing."
    )]
    #[arg(long)]
    count_syscalls: bool,
    #[arg(
        help = "Cap each download flow the origin serves at this many Mbit/s, to compare cores at one rate. Uploads are not capped."
    )]
    #[arg(long)]
    origin_rate: Option<f64>,
    #[arg(
        help = "Run this workload through the same core for the whole of every trial of the others (tcp and udp workloads only), to read one flow's latency while another loads the core. Its figures are kept with a `bg_` prefix; the core's CPU figures then cover both loads."
    )]
    #[arg(long)]
    background: Option<String>,
    #[arg(
        help = "Linux: run an idle-priority busy loop on every CPU for the whole run, so no CPU sleeps between bursts of work. A control for a VM, where a lightly loaded run is charged for that sleep; report it beside the plain run."
    )]
    #[arg(long)]
    keep_awake: bool,
    #[arg(
        help = "Linux: read each namespace's IP and TCP counters, the link's packet counts and the state of the flows' sockets at the two edges of every bulk TCP window, and report them per MB. A diagnostic; the link and server figures need --link."
    )]
    #[arg(long)]
    net_counters: bool,
    #[arg(
        help = "Measure a core that is already running instead of starting any: `NAME=pid:<N>` or `NAME=pkg:<process name>` (an app's process, as `pidof` names it). Needs --via."
    )]
    #[arg(long)]
    attach: Vec<String>,
    #[arg(
        help = "How the load reaches an attached core: `socks:HOST:PORT` (its mixed port) or `tun` (plain sockets the system routes into its VPN; then --origin must be off this device, because loopback never enters a VPN)."
    )]
    #[arg(long)]
    via: Option<String>,
    #[arg(
        help = "`HOST:BASE_PORT` of an origin started elsewhere with `concord-bench origin --bind <ip> --base-port BASE_PORT`; by default one is started here on loopback. A load `--via tun` needs one off this device, since loopback never enters a VPN; an Android emulator reaches its host's loopback at 10.0.2.2."
    )]
    #[arg(long)]
    origin: Option<std::net::SocketAddr>,
    #[arg(
        help = "Create the load's sockets as this uid (`N` or `pkg:<package>`), so an Android VPN, which routes by uid, carries them; needs root. Pick an app other than the one holding the VPN, which excludes itself."
    )]
    #[arg(long)]
    load_uid: Option<String>,
    #[arg(help = "Where results go; defaults to `target/bench/runs/<time>`.")]
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct CompareArgs {
    base: PathBuf,
    new: PathBuf,
    #[arg(help = "Core name in the base run; defaults to its subject.")]
    #[arg(long)]
    base_core: Option<String>,
    #[arg(help = "Core name in the new run; defaults to its subject.")]
    #[arg(long)]
    new_core: Option<String>,
    #[arg(
        help = "Relative change below which a significant difference is still not a regression."
    )]
    #[arg(long, default_value_t = 0.05)]
    threshold: f64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run(*args),
        Command::MasqueServer { listen } => masque::serve(listen),
        Command::Compare(args) => compare(args),
        Command::List => {
            list();
            Ok(true)
        }
        Command::Origin {
            bind,
            base_port,
            rate_mbit,
        } => origin(bind, base_port, rate_mbit),
        Command::Spin { cpu, parent } => awake::spin(cpu, parent).map(|()| true),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

fn list() {
    println!("cases:");
    for c in cases::ALL {
        println!(
            "  {:<14} {}{}",
            c.name,
            c.about,
            if c.udp { "" } else { " (no UDP)" }
        );
    }
    println!("workloads:");
    for w in Workload::ALL {
        println!("  {:<14} {}", w.name(), w.about());
    }
    for tier in [Tier::Quick, Tier::Full] {
        let plan = Plan::tier(tier);
        println!(
            "{tier:?}: {} rounds, {:?} windows; cases {}; workloads {}",
            plan.rounds,
            plan.duration,
            plan.cases
                .iter()
                .map(|c| c.name)
                .collect::<Vec<_>>()
                .join(","),
            plan.workloads
                .iter()
                .map(|w| w.name())
                .collect::<Vec<_>>()
                .join(","),
        );
    }
}

fn positive_rate(flag: &str, rate: Option<f64>) -> Result<(), String> {
    match rate {
        Some(rate) if !(rate.is_finite() && rate > 0.0) => {
            Err(format!("{flag} takes a positive rate in Mbit/s"))
        }
        _ => Ok(()),
    }
}

fn origin(bind: IpAddr, base_port: Option<u16>, rate_mbit: Option<f64>) -> Result<bool, String> {
    positive_rate("--rate-mbit", rate_mbit)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime
        .block_on(origin::serve(bind, base_port, rate_mbit))
        .map_err(|e| e.to_string())?;
    Ok(true)
}

fn compare(args: CompareArgs) -> Result<bool, String> {
    let base = Results::load(&args.base)?;
    let new = Results::load(&args.new)?;
    let pick = |r: &Results, name: Option<String>| {
        name.or_else(|| r.core_order.first().cloned())
            .ok_or_else(|| "a results file has no cores".to_string())
    };
    let base_core = pick(&base, args.base_core)?;
    let new_core = pick(&new, args.new_core)?;
    let (table, regressed) = report::compare(&base, &new, &base_core, &new_core, args.threshold);
    println!("{table}");
    if regressed {
        eprintln!(
            "regression beyond {:.0}% with significance",
            args.threshold * 100.0
        );
    }
    Ok(!regressed)
}

fn parse_attach(text: &str) -> Result<runner::Attached, String> {
    let (name, target) = text.split_once('=').ok_or(format!(
        "--attach {text}: expected NAME=pid:<N> or NAME=pkg:<name>"
    ))?;
    let pid = match target.split_once(':') {
        Some(("pid", pid)) => pid
            .parse()
            .map_err(|_| format!("--attach {text}: bad pid"))?,
        Some(("pkg", process)) => {
            let out = std::process::Command::new("pidof")
                .arg(process)
                .output()
                .map_err(|e| format!("pidof: {e}"))?;
            let text = String::from_utf8_lossy(&out.stdout);
            let mut pids = text.split_whitespace();
            let pid = pids
                .next()
                .and_then(|p| p.parse().ok())
                .ok_or(format!("no process named {process}"))?;
            if pids.next().is_some() {
                return Err(format!(
                    "more than one process named {process}; pass pid:<N>"
                ));
            }
            pid
        }
        _ => {
            return Err(format!(
                "--attach {text}: expected NAME=pid:<N> or NAME=pkg:<name>"
            ));
        }
    };
    Ok(runner::Attached {
        name: name.to_string(),
        pid,
    })
}

fn parse_uid(text: &str) -> Result<u32, String> {
    if let Some(package) = text.strip_prefix("pkg:") {
        let out = std::process::Command::new("pm")
            .args(["list", "packages", "-U", package])
            .output()
            .map_err(|e| format!("pm: {e}"))?;
        return String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| {
                let rest = l.strip_prefix("package:")?;
                let (name, uid) = rest.split_once(" uid:")?;
                (name == package).then(|| uid.trim().parse().ok()).flatten()
            })
            .ok_or(format!("no package {package}"));
    }
    text.parse()
        .map_err(|_| format!("--load-uid {text}: expected a uid or pkg:<package>"))
}

fn parse_via(text: &str) -> Result<socks::Entry, String> {
    match text.split_once(':') {
        _ if text == "tun" => Ok(socks::Entry::Tun),
        Some(("socks", address)) => address
            .parse()
            .map(socks::Entry::Socks)
            .map_err(|_| format!("--via {text}: expected socks:HOST:PORT")),
        _ => Err(format!("--via {text}: expected socks:HOST:PORT or tun")),
    }
}

fn seconds(value: f64) -> Duration {
    Duration::from_secs_f64(value.max(0.0))
}

fn run(args: RunArgs) -> Result<bool, String> {
    let mut plan = Plan::tier(args.tier);
    if !args.cases.is_empty() {
        plan.cases = args
            .cases
            .iter()
            .map(|n| cases::find(n).ok_or(format!("unknown case {n}; see `concord-bench list`")))
            .collect::<Result<_, _>>()?;
    }
    if !args.workloads.is_empty() {
        plan.workloads = args
            .workloads
            .iter()
            .map(|n| {
                Workload::parse(n).ok_or(format!("unknown workload {n}; see `concord-bench list`"))
            })
            .collect::<Result<_, _>>()?;
    }
    if let Some(rounds) = args.rounds {
        plan.rounds = rounds.max(1);
    }
    if let Some(d) = args.duration {
        plan.duration = seconds(d);
    }
    if let Some(w) = args.warmup {
        plan.warmup = seconds(w);
    }
    if let Some(count) = args.crr_conns {
        if count == 0 {
            return Err("--crr-conns must be positive".into());
        }
        plan.crr_conns = count;
    }
    plan.tun = args.tun;
    plan.tun_stack = args.tun_stack.clone();
    plan.tun_mtu = args.tun_mtu;
    plan.fresh_cores = args.fresh_cores;
    if args.count_syscalls {
        syscalls::enable()?;
    }
    plan.count_syscalls = args.count_syscalls;
    plan.net_counters = args.net_counters;
    positive_rate("--origin-rate", args.origin_rate)?;
    if args.origin_rate.is_some() && args.origin.is_some() {
        return Err("--origin-rate: start the remote origin with --rate-mbit instead".into());
    }
    plan.origin_rate = args.origin_rate;
    if let Some(name) = &args.background {
        let background = Workload::parse(name)
            .filter(|workload| !workload.fresh_core())
            .ok_or(format!("--background: {name} is not a tcp or udp workload"))?;
        plan.background = Some(background);
    }

    let link = match (&args.link, args.tun) {
        (Some(text), _) => Some(Link::parse(text)?),
        (None, true) => Some(Link::parse("veth")?),
        (None, false) => None,
    };
    if link.is_some() && !(cfg!(target_os = "linux") && env::is_root()) {
        return Err("--link and --tun need Linux and root".into());
    }

    let stamp = time::OffsetDateTime::now_utc();
    let out = args.out.clone().unwrap_or_else(|| {
        PathBuf::from("target/bench/runs").join(
            stamp
                .format(time::macros::format_description!(
                    "[year][month][day]-[hour][minute][second]"
                ))
                .unwrap_or_default(),
        )
    });
    std::fs::create_dir_all(out.join("logs")).map_err(|e| format!("{}: {e}", out.display()))?;
    let out = std::path::absolute(&out).map_err(|e| e.to_string())?;

    let attached = args
        .attach
        .iter()
        .map(|a| parse_attach(a))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(uid) = &args.load_uid {
        socks::set_load_uid(parse_uid(uid)?);
    }
    let entry = match (&args.via, attached.is_empty()) {
        (_, true) => None,
        (None, false) => return Err("--attach needs --via socks:HOST:PORT or --via tun".into()),
        (Some(via), false) => Some(parse_via(via)?),
    };
    let mihomo = args.mihomo.clone();
    let mut specs = args.cores.clone();
    if !attached.is_empty() {
        specs.clear();
    } else if specs.is_empty() {
        specs.push("concord=concord:target/release/concord".into());
        if let Some(m) = mihomo.as_ref().filter(|_| !args.tun || args.tun_mihomo) {
            specs.push(format!("go=mihomo:{}", m.display()));
        }
    }
    let cores: Vec<CoreSpec> = specs
        .iter()
        .map(|s| CoreSpec::parse(s, &out.join("bin"), args.tun))
        .collect::<Result<_, _>>()?;
    core::check_tun_cores(&cores, args.tun, args.tun_mihomo)?;
    let mut names: Vec<&str> = cores.iter().map(|c| c.name.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|w| w[0] == w[1]) {
        return Err("two cores share a name".into());
    }
    if attached.is_empty()
        && plan.cases.iter().any(|c| c.name == "hysteria-brutal")
        && args.sing_box.is_none()
    {
        return Err("hysteria-brutal needs --sing-box with QUIC support".into());
    }
    let needs_server = attached.is_empty()
        && plan.cases.iter().any(|c| {
            !matches!(
                c.name,
                "direct" | "rematch" | "hysteria-brutal" | "masque-l4"
            )
        });
    let mihomo = match mihomo {
        Some(m) => m,
        None if !needs_server => cores
            .iter()
            .find(|c| c.kind == Kind::Mihomo)
            .map(|c| c.binary.clone())
            .unwrap_or_default(),
        None => return Err("protocol cases need --mihomo (or MIHOMO) for the server side".into()),
    };

    let mut environment = env::collect();
    let present = isolate::present_cpus();
    let every_cpu = isolate::allowed_cpus();
    let allowed = every_cpu.len();
    // An attached core keeps the CPUs it has, so the load gets all of them unless told otherwise.
    let cpus = if attached.is_empty() || args.cpus.is_some() {
        CpuPlan::resolve(args.cpus.as_deref())?
    } else {
        None
    };
    let netns = link.as_ref().map(Netns::create).transpose()?;
    if let Some(client) = cpus.as_ref().and_then(|p| p.get(Role::Client)) {
        isolate::pin_self(client)?;
    }
    if let Some(ns) = &netns {
        ns.enter_near()?;
    }
    env::raise_fd_limit();

    let mut warnings = Vec::new();
    if cpus.is_none() && attached.is_empty() {
        warnings.push(if cfg!(any(target_os = "linux", target_os = "android")) {
            "fewer than 4 CPUs or --cpus off: the processes share CPUs".to_string()
        } else {
            "no CPU isolation on this OS: the core, server, origin and load generator share CPUs; \
             read wait_share and the *_cores columns before trusting a throughput ceiling"
                .to_string()
        });
    }
    if let Some(present) = present.filter(|&p| args.cpus.is_none() && allowed < p) {
        warnings.push(format!(
            "only {allowed} of {present} CPUs are allowed to this process (on a phone, often power \
             management holding back the big cores): the automatic split may be uneven; check *_cores or pass --cpus"
        ));
    }
    if let Some(status) = environment["thermal_status"].as_u64().filter(|s| *s > 0) {
        warnings.push(format!(
            "the device reports thermal status {status}: it is throttling"
        ));
    }
    if env::on_battery() == Some(true) {
        warnings.push("running on battery: the CPU may be throttled".into());
    }
    if let Some(load) = env::load_average()
        && load > 2.0
    {
        warnings.push(format!(
            "1-minute load average is {load:.1}: other work will add noise"
        ));
    }

    environment["cpus"] = serde_json::to_value(&cpus).unwrap_or_default();
    environment["link"] = serde_json::to_value(&link).unwrap_or_default();
    environment["entry"] = (if plan.tun { "tun" } else { "socks" }).into();
    environment["warnings"] = serde_json::to_value(&warnings).unwrap_or_default();
    let mut results = Results {
        schema: report::SCHEMA,
        started: stamp
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        args: std::env::args().skip(1).collect(),
        env: environment,
        plan: serde_json::to_value(&plan).unwrap_or_default(),
        cores: if attached.is_empty() {
            serde_json::to_value(&cores).unwrap_or_default()
        } else {
            serde_json::json!(attached.iter().map(|a| serde_json::json!({"name": a.name, "attached_pid": a.pid, "via": args.via})).collect::<Vec<_>>())
        },
        core_order: if attached.is_empty() {
            cores.iter().map(|c| c.name.clone()).collect()
        } else {
            attached.iter().map(|a| a.name.clone()).collect()
        },
        ..Results::default()
    };

    let eta = plan.estimate(cores.len().max(attached.len()));
    eprintln!(
        "{:?} tier: {} cases × {} workloads × {} cores × {} rounds, about {} min",
        plan.tier,
        plan.cases.len(),
        plan.workloads.len(),
        cores.len(),
        plan.rounds,
        eta.as_secs().div_ceil(60)
    );
    for c in &cores {
        eprintln!(
            "  {:<10} {:?} {} ({:.1} MB, {})",
            c.name,
            c.kind,
            c.source,
            c.size as f64 / 1e6,
            &c.sha256[..12]
        );
    }
    if let Some(p) = &cpus {
        eprintln!("  cpus {:?}", p.sets);
    }
    for w in &warnings {
        eprintln!("  warning: {w}");
    }
    eprintln!("  results in {}", out.display());
    let awake = args
        .keep_awake
        .then(|| awake::Awake::start(&every_cpu))
        .transpose()?;
    if let Some(awake) = &awake {
        results.env["keep_awake"] = serde_json::json!({"loops": awake.describe()});
    }

    let workers = cpus
        .as_ref()
        .and_then(|p| p.get(Role::Client))
        .map_or(4, |c| c.len().max(1));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let rig = runner::Rig {
        plan,
        cores,
        mihomo,
        sing_box: args.sing_box,
        cpus,
        netns,
        dir: out.clone(),
    };
    let outcome = runtime.block_on(async {
        tokio::select! {
            r = async {
                match entry {
                    Some(entry) => rig.run_attached(&attached, entry, args.origin, &mut results, &out).await,
                    None => rig.run(&mut results, &out).await,
                }
            } => r,
            _ = tokio::signal::ctrl_c() => Err("interrupted; partial results kept".to_string()),
        }
    });
    if let Some(awake) = awake {
        results.env["keep_awake"]["stopped"] = awake.stop().into();
    }
    results.finished = Some(
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    );
    results.save(&out).map_err(|e| e.to_string())?;
    drop(runtime);
    drop(rig);
    eprintln!("{}", report::terminal(&results));
    eprintln!(
        "report: {}\nresults: {}",
        out.join("report.md").display(),
        out.join("results.json").display()
    );
    outcome.map(|()| true)
}
