# Performance

How to run `concord-bench` and read its report is in `benchmarking.md`. This file is the standard a result is
held to and what goes wrong when measuring.

## The Standard

- **End goal.** Every bench item beats or ties Go (upstream mihomo as the client). A tie needs a reason shown by data,
  such as the peer server, the origin or the kernel being the limit.
- **TUN is compared with sing-box's Go stack.** On the TUN path, Go means sing-box as the client
  with sing-tun's default stack (`""` or `"go"`), at the version `reference-choices.md` pins. mihomo's TUN, on any
  stack, is not a reference: a TUN gate against Go, a TUN figure in a known gap and a TUN review entry use the
  sing-box arm, and a figure from a mihomo TUN arm is labelled as such and decides nothing.
- **CPU efficiency against Go is read at 1 Gbit/s.** Whether Concord's core or the server costs
  more CPU per GB than Go is decided with both arms held to the same rate (`benchmarking.md`, The 1 Gbit/s group),
  for `tcp-down` and `tcp-up`. Throughput, `tcp-multi` and fairness against Go are read at full speed on the
  three-server-CPU plan, and so are RR, CRR and `udp-stream`. Regressions against `main` are read at full speed,
  CPU per GB included.
- **Landing gate for a change.** All of these, from runs in the same session against `main` built from the same tree:
  - its target metric improves against `main`, with the 95% interval excluding zero;
  - no gate metric gets worse against `main` with an interval excluding zero. Gate metrics: throughput, core and
    server CPU per GB, RR p99 and fairness (Jain and the slowest flow). Diagnostics (context switches, p999 and
    other tail extremes, busy-core share, interval variance) do not block on their own; they count only when they
    explain a gate-metric regression, and the review entry lists them;
  - memory only has to be reasonable: no higher than Go, no growth with connection count or run time, and the same
    order as `main`. A change in memory against `main` that meets this is recorded in the review entry and as a known
    gap and does not block, nor does it call for a rerun;
  - correctness tests and the full gate pass, and the bench tier the change's reach calls for ran (below).
  Gaps against Go that `main` already had are known gaps; they do not block the change. A change that lands with any
  metric worse than `main` (under a rule below, or a reasonable memory change) records each such regression, with its
  numbers, when it lands (Known Gaps, below).
- **Bench tier by reach.** What the changed code can execute decides the tier, not the size of the diff:
  - *Local*: one protocol, transport or workload path. The quick tier on the cases that run the changed code is the
    last layer; no full tier and no other case. Reach comes from the call paths, not file names: a "VMess-only"
    change that edits a shared helper reaches every caller of it. A change to one protocol also moves the code of
    the others in the binary and can shift their numbers by a few percent; that is not its regression, and it is
    not measured for. A change on one side of the relay (an inbound such as the TUN stack, or one outbound) runs
    under every protocol on the other side, but those protocols are not separate reach: measure DIRECT plus one
    case per behaviour the prediction depends on (one encrypted stream protocol when the other side's drain rate
    matters, say), not every protocol.
  - *Global*: code or settings every case runs through, such as the runtime, relay, engine, buffers, allocator, a
    dependency or a build setting all protocols link. Write the predicted side effects (which cases, which metrics,
    which direction) before measuring. When each is predictable, sound in theory and in line with mainstream
    practice (argued in the review entry; matching mihomo alone is not the test), the quick workloads on the cases
    the predictions name are enough; otherwise the standard quick tier as well. When those runs have no
    unexplained regression, the change lands before the full tier, marked as such: the mark names the change, what it
    reaches, the runs, and the side effects it could still have.
- **Each change measures its own reach, the same way on every platform.** Reach is the cases and
  workloads its code paths execute, on each platform those paths run on, and nothing beyond it. A path the change
  touches (TUN, a BoringSSL fingerprint, a mux, UDP over a stream, WireGuard) is part of its reach and measured by
  the change itself. The review entry lists the reach as platform × case × workload; a Global change lists the
  representative set.
- **The representative set** is the quick tier (`direct`, `ss-aes128`, `trojan-tls`, `vmess-grpc-tls`, `hysteria2`
  through SOCKS) plus `direct` over TUN. Windows adds `hysteria2-brutal` and `mieru-tcp`: their Windows cells lag on
  their own (Brutal's loss and tail latency, mieru's download and multi-flow), which the five do not show. The set is
  run in three places only: on a platform that has gathered many landings since it was last measured, in place of the
  full tier; before a release, beta included; and for a toolchain upgrade, on Linux alone (below). A release ships
  when the set ties or beats Go on every platform's current `main` and each confirmed known issue is fixed or deferred
  under the rules below. Go is upstream mihomo through SOCKS and sing-box over TUN. Windows has no TUN arm in the
  bench yet, so its TUN cell is not measured.
- **Android is measured on the Linux VM with an Android-shaped build**: its TUN device takes the shape a VpnService
  descriptor has (one queue, no offload), against the same Go arms as Linux. A phone is
  used only for a path the VM cannot run.
- **A toolchain upgrade** (`rust-toolchain.toml` and `rust-version`) is Global and measures the representative set on
  Linux only: one job builds the same commit with the old and the new toolchain as two arms and runs them in the same
  rounds. Windows, macOS and Android are not measured for it; the full gate still runs everywhere it runs for any
  change.
- **The full tier runs only when the maintainers ask for it**; neither a landing nor a release calls for
  it. A gate on it comes after the known gaps are cleared and the methods settled.
- **Clearing a mark**, whichever comes first:
  - each listed side effect is ruled out, by reasoning from the code in the review entry or by a run that measures
    that effect;
  - later runs on `main` from other work (baselines, landing runs) cover the listed effects with nothing pointing
    at the change.
  Time on `main` alone clears nothing. A full tier on `main`, when one is asked for, clears every mark. A
  regression found later is bisected over the marked commits first.
- **A regression where the change cannot run.** A gate-metric regression in a case that cannot execute the changed
  code is measured once more on that case alone before it blocks. If it repeats, find the shared cause (binary
  layout, a shared crate, the build) before deciding; the change is not rejected on the number alone.
- **An unpredicted regression under 5%** in a case the change reaches is measured once more on that case before it
  is recorded as open. One that repeats is recorded; one that does not is noted in the review entry.
- **A correctness fix** lands on the full gate, its regression test and an argument from the
  protocol specification or a mainstream implementation, when it changes only the faulty path. A benchmark
  regression the changed code cannot plausibly cause (no mechanism found in the code) is recorded as a known gap and
  measured again after landing; it does not block. One with a plausible mechanism is
  explained before landing. The fix's correctness, not a figure, is what it is judged on, so a perf claim still needs
  the standard above.
- **Go, not `main`, is the target.** A change that leaves Concord more correct or closer to the
  reference as a whole (protocol behaviour, rate control, the relay's read and write shape as mihomo and sing have
  it) may land as a staged choice with some gate metrics worse than `main`, when all of these hold:
  - the review entry gives the argument (specification, the pinned mihomo or sing source, or a measured defect in
    `main`) and the target metrics it improves;
  - on each metric worse than `main`, the case still beats or ties Go, or its gap against Go meets the deferral
    rule below;
  - each regression against `main` is recorded as a known gap with its numbers, measurement and next lead.
  A regression that leaves a case behind Go beyond the deferral rule still blocks.
  When such a regression has a located cause with a known fix (a writer that does not yet take the new path, say),
  the change lands without waiting for it. The fix is the same owner's next task, and the known gap names that owner
  and what reopens it. This never covers correctness, fairness or
  the slowest flow, or RR p99.
- **Deferring a gap.** A gap against Go may be set aside, so one hard item does not stall the rest, only when all of
  these hold:
  - it is at most 5% on its metric, and throughput, RR p99 and fairness are not behind by more than that;
  - the reason is shown by data (peer server, kernel or origin as the bottleneck, or a measured mechanism), not
    argued in advance;
  - the implementation is the reasonable, idiomatic one.
  A deferred gap is still owed and is recorded as a known gap.
- **Concurrency-model trade-offs.** Concord aligns wire behaviour with Go and sets I/O scheduling
  (read and write sizes, batching, wakes, task structure) by Tokio's costs. Across all protocols the aim is to beat
  Go on nearly every case and lead overall. A gap may stay as a deliberate trade-off, beyond the deferral rule, only
  when all of these hold:
  - its cause is the difference between Go's runtime and Tokio's, shown in code and measured, and matching Go there
    has a clear measured cost elsewhere;
  - it is on CPU, throughput or memory, never on correctness, fairness or the slowest flow, or RR p99; those follow
    the rules above;
  - when the choice is forced, CPU outranks throughput and throughput outranks memory;
  - no metric falls more than 10% behind Go, and the protocol still leads Go over its cases as a whole.
  A gap that is fixable but not yet fixed, or whose cause is unknown, is not a trade-off. Each trade-off is a row
  in `reference-choices.md` (Deliberate Differences) and a known gap.

## Known Gaps

A known gap is a gap against Go, or a regression against `main` accepted at landing, that is still owed. Its record
gives the numbers, the platform, case and workload that measured them, the reason and the evidence for it, the next
lead to try, and what would make it urgent. A change that adds or edits a known gap gives that text in its review
entry. A figure measured on an earlier `main` is measured again before it is read as a gap.

## Iterating On A Change

Reason first. From the code, write down what the change can affect and how (which cases execute it, what it changes
in work, waiting, memory or wire shape), then measure those effects. A case the changed code cannot execute is not
measured to show it did not change.

Measure in layers, cheapest first; only the last layer decides landing.

1. **Mechanism counts** (seconds, one run). Quantities fixed by the code path rather than by timing: syscalls,
   bytes read and written and their mean size (`/proc/<pid>/io`), allocations, copies and context switches per GB.
   Use them to check that a change does what it intends (fewer writes, larger reads) and touches nothing it should not
   (the other direction). They are not results on their own. System calls by name, and socket bytes per receive and
   send call, come from a separate `--count-syscalls` run (root; it slows every system call, so it is not a timing
   run). `vfs_*` misses socket `recv`, `send` and `splice`, which is all of Concord's socket I/O, so it says nothing
   about Concord's data path; `ctx_per_mb` is in every report. `benchmarking.md` has the details.
2. **Targeted signal** (minutes). Only the cases and workloads the change can affect, 2 to 3 rounds, fresh processes
   (`--fresh-cores`), with low-noise signals beside CPU: TCP segment size and non-data segments per wire MB from the
   sockets (the report's `far_*` and `near_*` metrics), read and write sizes. A state the server enters or not (small segments under `tcp-multi`) shows in one window per round;
   CPU averages need many. Put two or three variants in one run as separate `--core` arms instead of one run each.
3. **Landing gate** (the standard above). The full gate and the bench tier its reach calls for, once, on the change
   that survived the first two layers.

Keep CPU rounds for the landing gate. A change that removes work the counts can see (a copy, a
system call, an allocation or a wake per MB) is screened by those counts, which settle in one or two rounds; its
CPU and throughput are read once, in the landing gate, not first in a CPU screen of ten or more rounds. A change
whose code path is shown equivalent, such as a refactor off the hot path, lands on that argument and the full gate
alone. Before a candidate is frozen, run a short smoke on every case its reach names, so a regression against `main`
shows while the candidate can still change rather than in the landing matrix. Several fixes the counts have
screened may share one landing gate. Latency tails, fairness and the slowest flow, and throughput set by kernel or
peer feedback have no count that stands in for them; they are measured. A count that does not track the cost the
change claims to remove settles nothing: batching ciphertext into fewer send calls did not lower CPU per GB.

Stopping is decided before a run: state the rounds to check at (for example 3, 6, 12) and the rule (stop when the
interval excludes zero by the minimum effect, or when its far end cannot reach the target). Adding rounds until one
run agrees is not a stopping rule.

Size the rounds from the effect sought, not by habit. Take the per-round spread `s` of the paired difference (candidate
minus `main`, same round) for that metric and case, from an earlier run or a short run of `main` against itself. With
minimum effect `d`, about `8 × (s / d)²` rounds give an 80% chance that a real effect of `d` shows with its interval
excluding zero. Plan that many, split by case when long. The minimum effect `d` is at least 5%: the gaps to Go are
mostly larger, and a smaller effect costs tens of rounds on the one measurement machine. A change worth less than that
lands on its argument under the Go-target rule above, not on a long run to prove it. A run of more than about 12 rounds
is argued for before it starts. When a run's interval spans zero and its point is at or beyond the target, the run was
too small, not a finding of no effect. Record it as underpowered. The next step is a new run sized for it and planned
before it starts, not more rounds on the same run.

## Evidence

- Compare only within one run: the harness rotates cores per round, so drift hits each alike. Absolute numbers from
  different runs, windows or machines are not comparable.
- A difference counts when its 95% interval excludes zero. A run that decides landing or a verdict against Go has
  at least 5 rounds; 4 rounds is a targeted signal only (`benchmarking.md`, Reading the report). For a close call,
  raise `--rounds` (6 to 12) rather than repeating until one run agrees.
- Two release builds of the same commit can differ by about 1.5% in CPU per GB. A change smaller than that is not a
  result on its own.
- Use `server_cores`, `origin_cores` and `client_cores` before blaming Concord: a role at its CPU limit is the limit.
- `tcp-multi` runs all rounds of an arm in one core process, so its interval covers connections, not process starts.
  A result that depends on a process's early state needs fresh processes per round (`--fresh-cores`) to be believed.
- Tracing (BPF, heavy perf) changes timing and can change the state being studied. Use it to find a mechanism, and
  decide on untraced runs.

## Pitfalls

**Builds.**

- Two Concord checkouts that build into one target without distinct cfgs link each other's artifacts, and the
  "baseline" is then your change; Target Directory And Disk in `commands.md` gives the cause and the rule. Confirm
  with a symbol or test count when in doubt. A tree extracted from an archive keeps old mtimes: extract with `tar -m`.
- In build scripts, `cargo build | tail` hides failures; use `set -o pipefail`.
- Stale metadata in a shared target produces "missing symbol" errors; see `commands.md`. Results taken in that state
  are rerun.

**Linux and VMs.**

- Peak memory varies by about 2 MiB per process at random: glibc advises the brk heap for transparent huge pages once
  it crosses 2 MiB. Compare peaks as a median over several processes; a single 2 MiB step is not a regression. The
  harness samples a core by its executable path, since it copies the binary it measures.
- A VM's numbers drift between runs, and the host's other load (another VM, a build) moves them a lot. Run on a quiet
  host and compare Concord with `main` only within one run. The Go arm may be left out only for a case listed under
  "Fixed Go references" in `benchmarking.md`, read as that section says; everywhere else trust same-run ratios only.
  A link-bound run on a second machine (`benchmarking.md`) is not such load: in the calibration it moved neither the
  VM's arm ratios nor its single arms. A build on the host is: at nice 19 with two jobs it moved both arms by about
  4%, so builds never overlap a measurement.

- WAN `tuic` `tcp-up`: when the Go arm runs after a Concord arm in the round, its throughput falls to about
  0.035 Gbit/s and the server's CPU per GB to about 45, in all eleven such rounds over three runs on the Linux VM;
  run first, Go held 0.285 Gbit/s in six of seven. Cause not examined.
  Read this cell on the rounds where Go runs first, and add rounds when they are too few.
- A netem rate cap needs a 30 s window before CPU per GB settles; 10 s windows range over tens of percent between
  rounds with nothing wrong in either arm (`benchmarking.md`, The 1 Gbit/s group).
- Multi-flow cases over loopback, and a single `trojan-tls`, `vless-tls` or `vmess-ws-tls` download, can lock each
  connection into a small-segment regime that follows the client's read speed, not its cost (`benchmarking.md`, `--link
  ts=usec`). For the cases checked there the landing gate reads the `ts=usec` run; the loopback far-leg state table is a
  diagnostic, and how often a candidate enters the small state is not a landing condition. Correctness, fairness, the
  slowest flow and RR p99 are not exempt on either topology.
- `tcp-multi` decides landing with three server CPUs (`benchmarking.md`, Isolation). With two, a core
  that outruns mihomo's server makes the server the limit and the run measures the server; that run is still
  reported, as a diagnostic. Fairness and the slowest flow are judged on the three-CPU plan and are not exempt.

**Windows.**

- Protocols whose mihomo server paces itself with short timers (mieru over TCP, the QUIC servers) are measured partly
  on how promptly Windows fires the server's timers, which depends on whether the client keeps vCPU 0 awake; see
  `benchmarking.md`. Read such a gap with the idle-priority busy loop control first. Raising the timer resolution
  (`timeBeginPeriod`) was measured and changes nothing.
- A socket-buffer change that helps on a quiet host can look like a regression on a loaded one; confirm on a quiet one.

**Android.**

- Bench the core with an upstream mihomo built for the device; a fork that leaves listeners to its host app cannot serve as a bench client.
- `tcp-crr` depends on `netd` state: the same binary moves between two plateaus. Compare only interleaved results.
- Throughput on a phone often measures the origin, pinned to a little core, not the proxy. Compare `cycles_per_byte`;
  `cpu_s_per_gb` is masked by frequency scaling (a lightly loaded core is clocked down), unless the policy is set to
  `performance` for the run.
- `core_ctl` can isolate big cores, and binding only to isolated cores fails with `EINVAL`; pick cores that stay
  online (on a Snapdragon 888, `--cpus core=4-5,server=6-7,origin=0,client=1-3`).
- `libconcord.so` is a `cdylib`, so SIGPIPE is not ignored by a Rust runtime; `concord_start` ignores it, and splice is
  refused while SIGPIPE would still be fatal.
- The VPN path needs root, `--load-uid` of an app allowed background network, and an origin off the device's subnet;
  see `benchmarking.md`.

**External TUN comparisons.** When comparing the TUN path with sing-box in another harness, make every
implementation take the same relay path; sing-box's route override goes direct by default. A single run there can vary
by ±40%: run at least twice and compare CPU per Gbit/s. With iperf, its cookie makes the connection a peeked stream,
so check that the direct attach actually happened.

## Crypto Backends

rustls and the ss AEAD ciphers use aws-lc. On ARM big cores BoringSSL's newer AES-GCM kernel is about 20% faster for
the cipher alone (aws-lc is faster on little cores), and aws-lc's 8-way kernel requires SHA3 and specific cores. The
cipher is a small share of per-byte CPU, so this does not justify switching libraries. Recheck when aws-lc is
upgraded and on a phone with SHA3 (Cortex-X2 or later).
