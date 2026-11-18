# Benchmarking

`tools/bench` (`concord-bench`) measures Concord's data path against mihomo and against Concord built from another
commit. Every protocol case runs the same one-node profile with a `MATCH` rule on every core. A mihomo process
serves its protocol listeners; sing-box serves Hysteria v1.

## Running

```sh
cargo xtask bench --quick --base <ref> --mihomo /path/to/mihomo   # while you change code
cargo xtask bench --full --base <ref> --mihomo /path/to/mihomo --sing-box /path/to/sing-box
```

`xtask bench` builds `concord` and `concord-bench` in release and compares the working tree with:

- `base`: the tree at `--base <ref>`, built in a scratch worktree into `target/bench/rev-target`, so the first one is a
  full build. Without `--base` it is `HEAD` when the tree has uncommitted changes, and is skipped when it has none;
  `--no-baseline` skips it. A clean tree against its own `HEAD` measures the noise floor.
- `go`: the mihomo binary as a client, from `--mihomo`, `CONCORD_BENCH_MIHOMO` or `MIHOMO`. Without one only the
  `direct` case runs.

`--only a,b` picks cases and `--secs S` sets the measurement window. Any other argument goes through to `concord-bench
run`: `--only hysteria2 --workloads tcp-up` measures one cell, and `--rounds 8` tightens the intervals. `concord-bench
list` prints the cases, workloads and tiers.

While you change code, run the cases your change reaches, and run nothing else on the machine while it measures. The
full tier runs only when the user asks for it; `performance.md` says what a change measures. Results go to
`target/bench/runs/<time>/`: `report.md`, `results.json` with every trial, `logs/`, and copies of the binaries that were
measured.

`concord-bench compare <base.json> <new.json>` matches two runs by case and workload. It exits 1 when a headline metric
got worse beyond `--threshold` (5% by default) with significance, so CI can use it as a gate.

`concord-bench run --core ref=ssrust:/path/to/sslocal` adds a shadowsocks-rust TCP reference for plain `ss-aes128`
and `ss-chacha` cases. It derives the endpoint and cipher from the case and enables TCP_NODELAY to match the other
clients. Other proxy types, plugins and the TUN entry are rejected. Keep the pinned source, lock, compiler and binary
SHA with the reference builds. Its server-first handshake can wait 500 ms; use the same warmup of at least 1 s for
every arm when measuring steady downloads.

### The mihomo binary

Use an upstream build from `MetaCubeX/mihomo`:

```sh
git clone --depth 1 https://github.com/MetaCubeX/mihomo && cd mihomo
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags '-s -w' -o mihomo .
```

A fork that leaves `listeners:` and `tun:` to its host app, rather than starting them from the config, can serve
neither as the server nor as a standalone client.

## What runs

Four roles take part, and each one is measured:

| Role | Process |
|---|---|
| core | the core under test: `concord` driven over its control connection (`core.hello`, `core.init`, `config.apply`, `engine.start`), or mihomo with `-d -f` |
| server | mihomo, or sing-box for Hysteria v1; the serving process is measured for each case |
| origin | `concord-bench origin`: TCP source, sink, echo and close-first, and UDP echo |
| client | the harness, generating load through the core's SOCKS5 mixed port, or through its TUN device with `--tun` |

For each case, every core starts on its own port and stays up. Rounds run the cores in rotating order (AB, BA, ...), so
drift over the run affects each core alike. Each workload has one warmup trial per core that is not counted, and each
trial measures over a window that opens after `warmup`. `idle`, `startup` and `large` start a fresh core for every
trial. With `--fresh-cores`, the other workloads also start every core afresh for each round, with a warmup trial per
process, so an interval covers process starts rather than only connections. Concord is stopped by closing its control connection, as a host does when it quits; mihomo by SIGTERM, and on
Windows by terminating it, so `stop_ms` only compares on Unix.

The control connection is a Unix socket on macOS and Linux and a named pipe on Windows. On Android it is a loopback TCP
port, because SELinux does not let the shell user create socket files.

### Isolation

On Linux, Android and Windows, the CPUs the harness may use are split between the four roles
(`--cpus core=0-1,server=2-3,origin=4,client=5-7` sets them explicitly). The fastest CPUs, by `cpuinfo_max_freq`, go to
the core under test, so on a big.LITTLE phone it gets the big cores. Go's `GOMAXPROCS` and Concord's worker count both
follow the mask, so both cores get the same number of threads. Windows sets the mask right after spawning and passes
`GOMAXPROCS` and `TOKIO_WORKER_THREADS` explicitly, because a mask cannot be inherited there and is set only after both
cores have read their CPU count.

As root on Linux, `--link` moves the server and origin into a separate network namespace behind a veth pair with netem
shaping: `veth`, `lan` (0.5 ms, 1 Gbit/s), `wan` (40 ms, 300 Mbit/s), `lossy` (80 ms, 100 Mbit/s, 1% loss), or
`rtt=..,rate=..,loss=..`. A preset may be followed by settings (`wan,ts=usec`), and `ts=usec` alone is a plain veth
with them. The harness and the core run in a second namespace whose default route is the veth. `--tun` sends the load
through the core's TUN device with `auto-route`. Use a disposable container or VM for these modes. A `--tun` result is
judged against sing-box on its default Go stack, not against a mihomo TUN arm (`performance.md`): give the Go arm as
`--core go=singbox:/path/to/sing-box`. The harness writes that core a sing-box configuration with a `tun` inbound that
names no `stack`, which is sing-tun's Go stack, and translates the `direct`, `trojan-tls` and plain Shadowsocks
cases (no plugin, no mux); the server stays mihomo for every arm. A mihomo core is refused with `--tun` unless
`--tun-mihomo` is given, and then it is a diagnostic arm: its entry in `cores` of `results.json` has
`"role": "diagnostic"` where a reference has `"reference"` and Concord `"subject"`, and the report marks its
comparison column as not the reference.

`ts=usec` gives both namespaces' default routes microsecond TCP timestamps (`ip route ... features tcp_usec_ts`, Linux
6.7 and later), so only the far leg between the core and the server changes. Use `--link ts=usec` for `trojan-tls` and
`ss-aes128` `tcp-multi`, and for `trojan-tls`, `vless-tls` and `vmess-ws-tls` `tcp-down`, when they decide landing.
`snell` shows the same
per-connection regime over loopback, but `ts=usec` does not move it: its server still sends about 59 non-data segments
per wire MB there against Go's 14, so Snell keeps the loopback reading. Over loopback or a plain veth with millisecond
timestamps, receive autotuning opens a fast client's window fully; the server then runs app-limited with an empty send
queue and sends each record as its own segment, which costs it CPU and throughput, while a slightly slower client keeps
it receive-window limited and its writes coalesce. Each connection settles in one of the two and stays, so the outcome
measures the client's read speed against the server rather than its cost, and any probe or `tcp_info` polling on the
core shifts it. With accurate timestamps the window follows the real RTT and most of the effect goes: on the Linux VM,
`trojan-tls` with four flows had four of six candidate trials at 0.42-0.48 server CPU-s/GB on a plain veth and one of
six on `ts=usec`, where candidate and `main` tie at 0.37; `ss-aes128` also settles there (12.6-15.3 non-data segments
per MB, Go 13.8). It is reduced, not gone, so read single high trials with care. One `trojan-tls` flow does the same:
a candidate whose socket reads took 34 kB against `main`'s 17 kB was in the small state in six of
nine loopback `tcp-down` trials against none, at `main`'s rate and 0.46-0.51 server CPU-s/GB against 0.36-0.40, and in
two of six on `ts=usec` against one. `vless-tls` and `vmess-ws-tls` single flows are
read the same way: the counters show the same state, one record a packet with the server at a full
CPU and not held by the receive window. `ts=usec` thins it less there: three of six trials each for that candidate
against one of six on `trojan-tls` and none for `main`; over loopback it was 20 of 30 trials, 10
of 30 for `main` and none of 30 for mihomo as the client. No other case's single flow is read
this way.

`tcp-multi` decides landing on `--cpus core=0-1,server=2-4,origin=5,client=6-7`, three CPUs for the server; every
other workload keeps `core=0-1,server=2-3,origin=4,client=5-7`, and a `tcp-multi` run on that plan is still reported,
as a diagnostic. With two CPUs a core that reads faster than mihomo's server writes empties the
server's send queue: the server sends each record as a packet of its own, pays more CPU per byte for it and becomes
the limit, so the run measures the server in that state and not the core. A slower client is the limit itself, keeps
the server waiting on the receive window and gets large packets. `--net-counters` shows which of the two a trial was:
the limiting side has its CPUs busy, and `server_link_rwnd_held_flows` is all the flows when it is the core. On
`ts=usec` with 8 flows, AnyTLS with two server CPUs ran at 26.4 Gbit/s
against Go's 28.4 with the server at 1.96 CPUs, no flow held by the window, 11 KB per packet and Jain 0.675; with three
it ran at 32.7 against 29.0 with the core at 2.00 CPUs, all eight flows held, 48 KB per packet and Jain 1.000, and Go
did not move. Fairness and the slowest flow are judged on the three-CPU plan and are not exempt. Snell's server stays
the limit with three CPUs too.

`hysteria-brutal`, `hysteria2-brutal` and `shadowquic-brutal` set 100 Mbit/s in both directions on the client and
server. Use them with `--link wan`, `--link lossy` or an explicit link; the ordinary `hysteria2` case uses BBR.
Hysteria v1 needs `--sing-box <binary>` built with QUIC support, because mihomo has no v1 listener. Its server CPU
is measured separately from the mihomo servers. ShadowQUIC uses a local TLS listener on the same mihomo server
for its JLS upstream. Include `tcp-multi` for fairness and `udp-stream` for end-to-end loss.

A second Linux machine on the same host may take the link-bound runs while the main VM measures: a plan whose
`--link` sets a rate (`lossy`, `wan`, or `rate=` of at most 300 Mbit/s) and that runs only `tcp-down`, `tcp-up`,
`tcp-multi`, `tcp-rr`, `tcp-crr`, `udp-stream` and `udp-rr`. Loopback, a plain or `ts=usec` veth, `idle`, `startup`
and `large`, and any run read for CPU per GB at full speed stay on the main VM and keep it to themselves. In a
calibration with the main VM alternating between measuring and idle, such a run moved neither the VM's arm ratios
nor its single arms, and its own link metrics (throughput, RR p50, transactions per second) and arm ratios
did not move either. Its CPU per transaction and per GB, though, dropped by a quarter to a third for every arm
while the VM measured. So on the second machine:

- read link metrics (throughput, RR p50, transactions per second) as same-run ratios;
- read CPU metrics as same-run ratios only when the main VM measured for none or all of the run, and otherwise
  only as a diagnostic, rerunning when a decision needs them;
- do not decide on RR p99 or p999 there; RR tails are decided on the main VM. A p99 decision on the second machine
  needs that case qualified there first.

The RR rule comes from a shadow of a twelve-round Hysteria2 Brutal `lossy` `tcp-rr` series, run on the second machine
with the main VM's binaries and order while the VM was busy, idle or mixed. RR p50 and transactions per second were as
steady as on the VM (run-to-run CV at most 1.6% against 1.5%), and their verdicts against `main` and Go agreed with the
VM's. RR p99 did not hold: one round's Go p99 was 93.6 ms against 202.8-212.6 ms in the other eleven (Go p99 CV 16.0%
against 1.5%), and the candidate against `main` came out better there, 0.956 [0.787, 1.000], where the VM's interval
spanned one.

The two machines differ in kernel, scheduler and CPU count, so never compare numbers across them, and keep a series
on the machine it started on.

macOS has no CPU affinity, so every process competes for the same CPUs. There, compare CPU cost per byte rather than
throughput ceilings, and check `wait_share` and the `*_cores` columns. The harness warns when you are on battery or the
load average is high.

`--keep-awake` (Linux) runs an idle-priority busy loop on every CPU the harness may use, for the whole run: one
`SCHED_IDLE` process per CPU that calls `sched_yield` in a loop, which gives way to anything runnable and only keeps the
CPU from sleeping. It is a control for a lightly loaded run on a VM (a rate cap, a paced server). There a CPU that
sleeps between short bursts charges the processes several times more for the same work, and the arm whose timing lets
it sleep more looks the more expensive one, down to the origin and the client. On the Linux VM, `direct` over TUN at
1 Gbit/s read Concord 47% above sing-box in core CPU per GB without the loops; with them both arms fell about fourfold
and Concord read 2% below downstream and 13% below upstream; downstream the origin's and the client's CPU, about twice
apart between the arms without, came within 10% (loops started by hand). Run both and report both.

A loop that never enters the kernel is not a control. The VM's kernel (7.0, `PREEMPT_LAZY`, HZ 1000) lets a woken task
preempt it only at the next tick, so the run is batched to the tick instead of kept awake: the core's context switches
fall to exactly 1000 per second, `wait_share` rises above 10, the ACKs it sends per MB drop by up to two thirds and
`udp-stream` RTT goes from 0.6 ms to 4 ms. Read a run with the loops only when its context switches per second,
`wait_share` (below 1) and ACKs per MB match the run without them. `results.json` lists the loops under
`env.keep_awake` with their pids and how many were still running when the harness stopped them; a loop also dies with
the harness.

### The 1 Gbit/s group

CPU efficiency against Go is read with both cores held to the same rate (`performance.md`): `--link rate=1000mbit`
with no added delay, `tcp-down` and `tcp-up`, `--duration 30`, at least 6 rounds, `--fresh-cores --net-counters`, on
the main VM, with a same-run Go arm. Read the core's and the server's CPU per GB there. It is a reading of its own, not
the full-speed one scaled down: through SOCKS the core runs at 0.03 to 0.4 of a CPU and pays per small batch and per
wakeup. The cap is on the far leg, so the two directions differ too: a download reaches the core packet by packet as
netem releases it, and an upload is read from an uncapped near leg and written into the capped link.

A cell is valid when both arms' on-link rate is at least 95% of the cap and their payload rates differ by under 1%.
netem counts bytes on the wire, headers and the protocol's framing included, so read the on-link rate from the link
counters (payload rate × bytes per packet × packets per payload MB, `link_to_core_*` for a download and
`link_to_server_*` for an upload), not from the payload rate: the payload was 935 to 956 Mbit/s (`hysteria2` lowest,
`direct` highest) in cells whose median on-link rate was 958 to 967, over three pilot runs.

The window is 30 s because 10 s does not hold a steady reading on a netem cap. Over six rounds of 10 s the core's CPU
per GB ranged over 16% to 127% of its median in nine of ten cells, mostly one or two rounds 50% to 100% above a tight
cluster, and on three of five uploads the ratio to Go could not separate 20%. With 30 s the range was 2% to 10% and
the ratio's interval about two points either side (`direct` and `trojan-tls`).

On the VM the group runs twice, without and with `--keep-awake`, and both passes are reported. A capped run is the
lightly loaded case `--keep-awake` is for: over TUN the plain pass read Concord 47% above sing-box, and the arms stood
level with the CPUs kept awake. The decision reads the second pass, and only when it passes the checks above: Concord's
context switches per second, `wait_share` below 1 and ACKs per MB at the plain pass's level. Where they do not, neither
pass decides and the cell needs a real machine.

`udp-stream` joins the group only where both arms reach the cap and differ by under 1%; it has no link counters, so
that is read on the payload rate. Through SOCKS no arm reached it (406 to 818 Mbit/s, the arms up to 13% apart), and
over TUN `direct` did with the arms 1.6% apart, so `udp-stream` is judged at full speed everywhere for now.

`--link` needs Linux. Elsewhere `--origin-rate 1000` holds both arms of a download to one rate, and nothing does for an
upload or UDP. Concord's arm is tight there in 10 s windows (3% to 11% over six rounds);
mihomo's had one round a third below the rest in two of three cases, so read it with 6 rounds or more. It is another
regime: the origin under-supplies the server, which then writes small bursts, where a netem cap leaves the server
backlogged. The levels do not transfer (`ss-aes128` download, Concord: 2.79 CPU-s/GB for the core and 3.18 for the
server under the origin's cap, 1.63 and 0.48 under netem's), so never compare a figure across the two.

## Fixed Go references

A fixed reference stands in for the same-run Go arm when Concord is compared against Go. It holds only for the
bench binary, Go client, server, kernel, plan shape and link it was measured with; a run that differs in any of
them cannot use it. It is built from at least four runs spanning at least an hour, kept only when every gate
metric's run medians vary by at most 3% and drift by at most 2% from the first to the last run on a line fitted
over time (from six runs, also no rank trend), and its value is the best of those medians (highest throughput,
fairness and slowest flow; lowest CPU and latency), with the range of the medians beside it. The values are collected
by script from the Go arms of finished runs, one record per group with the runs behind it, and are never typed in.

Read Concord's 95% interval against it: wholly better is not behind, wholly worse is behind, and an interval that
touches the value or the reference's range needs a same-run Go arm before it decides anything. A run that uses a
fixed reference still measures Go on one cell; if that cell falls outside the reference's range, the run is read
against same-run Go instead. `main` is never a fixed reference: it moves with every merge and drifts as much as Go
across runs.

The first usable group is Hysteria2 Brutal `tcp-rr` on `lossy`, on the main VM (one bench build, mihomo `v1.19.33` as
client and server, kernel 7.0.0-42, the RR series' plan shape), from six runs over 244 minutes: p99 209.78 ms, p50
86.70 ms, 11.191 transactions per second, 949.4 us of CPU per transaction, each with a run-to-run CV of at most 2.45%
and a drift of at most 1.61%. The same case on the second machine is a separate group and is not usable.

## Workloads

| Workload | Headline metrics |
|---|---|
| `tcp-down`, `tcp-up` | Gbit/s, core CPU-s/GB, cycles/byte, server CPU-s/GB, peak memory |
| `tcp-multi` | aggregate Gbit/s over parallel flows, Jain fairness, slowest flow |
| `tcp-rr` | 64-byte transactions/s, p50/p90/p99/p99.9 latency, CPU-µs per transaction |
| `tcp-crr` | connect, exchange one byte, close: connections/s, p50/p99 setup latency, errors, CPU-µs per connection |
| `udp-stream` | windowed UDP echo through SOCKS5 UDP ASSOCIATE: Mbit/s, loss, RTT percentiles, CPU-s/GB |
| `udp-rr` | one UDP ping in flight: RTT and loss |
| `idle` | KiB per held connection, KiB still held after they close, fds per connection, time to open them all |
| `startup` | spawn to first proxied byte, idle memory, threads, fds, CPU spent starting, time to exit after SIGTERM |
| `large` | a generated profile (quick tier 5k proxies and 50k rules, full tier 20k and 200k): time to ready, peak and settled memory |

Upload rates come from the origin's receive counter, which it reports every 100 ms, not from the client's send
calls, so socket buffers cannot inflate them. `interval_cv` and `interval_p10_gbps` show how steady the 100 ms rates
were.

The `quick` tier is the SOCKS part of the representative set (`performance.md` has the rest): `direct`, `ss-aes128`,
`trojan-tls`, `vmess-grpc-tls` and `hysteria2` with the throughput, latency, UDP and startup workloads, 5 rounds of 3 s
windows. `full` covers every case and workload, 5 rounds of 5 s windows. The lists are in `tools/bench/src/plan.rs`, so
the same tier always measures the same thing.
`--crr-conns N` replaces the tier's `tcp-crr` connection count (1500 quick, 3000 full) for a run that needs a long
connection series. `--origin-rate M` caps each download flow the origin serves at M Mbit/s, so cores are compared at one
rate (the server's CPU per GB at the slower core's rate, say); the origin paces in bursts of about a millisecond, and
uploads are not capped. `--background W` runs workload `W` through the same core for the whole of every trial of the
others, to read one flow's latency while another loads the core (`--workloads tcp-rr --background udp-stream`); its
figures are kept with a `bg_` prefix, and the core's CPU figures then cover both loads.

## Counters

| | macOS | Linux and Android | Windows |
|---|---|---|---|
| CPU time | `proc_pid_rusage`, ns | the process CPU clock, ns; `/proc` stat splits user and kernel time | `GetProcessTimes`, 100 ns |
| instructions, cycles | `proc_pid_rusage` | `perf_event_open` per thread, when `perf_event_paranoid` allows it | cycles from `QueryProcessCycleTime` |
| waiting for a CPU | `ri_runnable_time` | `schedstat` run delay | none |
| context switches, syscalls | `proc_pidinfo` | context switches from `/proc` | none |
| read and write calls | none | `/proc/<pid>/io`, VFS calls only | none |
| TCP segments | none | `INET_DIAG` `tcp_info` of the core's sockets | none |
| memory | `phys_footprint`, its lifetime peak, RSS | PSS (`smaps_rollup`), `VmHWM`, RSS | private working set, peak and current working set |
| open files | `proc_pidinfo` | `/proc/<pid>/fd` | handle count |

Virtual machines usually expose no hardware counters, so instructions and cycles are missing in the Parallels macOS
VM and the Android emulator.

The report omits a counter the platform does not provide rather than showing it as zero.

For `startup` and `large`, `ready_cpu_ms` samples the core's cumulative CPU time just after the first proxied byte.
`startup_cpu_ms` keeps its historical sampling point after the idle settling period (2 seconds for `startup`,
3 seconds for `large`); it includes that additional work and is not CPU time to ready.

Two counters on Linux serve the mechanism-count and targeted-signal layers of `performance.md` and appear only under
"all metrics" of the throughput workloads:

- `vfs_reads_per_mb`, `vfs_writes_per_mb` and the bytes per call, from `/proc/<pid>/io`. They count the read and write
  families that pass through the VFS (`read`, `readv`, `write`, `writev`, `sendfile`); `recv*`, `send*` and `splice`
  on a socket are not counted. Rust's `TcpStream` reads with `recv` and writes with `write`, while Go reads and writes
  with `read` and `write`, so compare these only between builds that use the same calls.
- `far_*` and `near_*`, from the `tcp_info` of the core's own sockets at the two edges of the window. The near leg is
  the connections the core accepted on its mixed port; the far leg is every other TCP socket it holds, to the server or,
  for `direct`, to the origin. `*_rx_segment_bytes` and `*_tx_segment_bytes` are the mean size of the data segments
  it received and sent, `*_nondata_rx_per_mb` and `*_nondata_tx_per_mb` the segments without data (mostly ACKs) per MB
  on that leg, and `*_retrans_per_mb` the retransmits. Segments are counted the way the kernel counts them, so a GRO
  or GSO packet counts as its MSS-sized parts.

`ctx_per_mb` is the context switches per MB; per GB it is a thousand times that.

`--count-syscalls` (Linux, as root) adds system call counts for the core and the server, read per thread from the
`syscalls:sys_enter_*` and `raw_syscalls:sys_enter` tracepoints with `perf_event_open` in counting mode, so the
binaries are unchanged: `syscalls_per_mb` (all calls), `sys_<name>_per_mb` for the read, write, recv, send, splice,
`epoll_pwait` and `futex` families, `recv_calls_per_mb` and `send_calls_per_mb`, `socket_bytes_per_recv_call` and
`socket_bytes_per_send_call` (the core's TCP bytes from the socket counters divided by those calls; left out when
the core called `splice`, since those bytes pass through neither), and the same with a `server_` prefix. `tcp-rr`
and `tcp-crr` report the call counts per transaction and per connection instead (`syscalls_per_conn`,
`sys_<name>_per_conn`, `recv_calls_per_conn`, and `_per_tx` likewise). Threads started after a window opens are not
counted. While any syscall tracepoint is on, every system call on the machine takes the kernel's slow entry path, so
CPU and rates from such a run are not comparable with a run without it; use it for the counts only.

`--net-counters` (Linux) is a diagnostic for the bulk TCP workloads that reads kernel state at the two edges of each
window and never inside it, at the instants the socket counters above are already read:

- `nstat_near_<Counter>_per_mb` and, with `--link`, `nstat_far_<Counter>_per_mb`: every `Ip`, `IpExt`, `Tcp` and
  `TcpExt` counter of `/proc/net/snmp` and `/proc/net/netstat` that moved, per MB of payload, named as `nstat` names
  them. A namespace's counters cover all its sockets: near is the load generator and both legs of the core, far is the
  server and the origin.
- With `--link`, `link_to_core_*` and `link_to_server_*`: bytes per packet and packets per payload MB on the far
  namespace's veth. The veth counts a GSO packet once, so bytes per packet towards the core is the size of what the
  server's TCP handed down, which the MSS-based segment counts above cannot show on a link.
- With `--link` and a server, for the server's sockets towards the core that moved at least 1 MB:
  `server_link_busy_share` (the share of the window they had data to send), `server_link_rwnd_limited_share` and
  `server_link_sndbuf_limited_share` (the shares of that busy time the core's receive window or their own send buffer
  held them, from `tcpi_busy_time`, `tcpi_rwnd_limited` and `tcpi_sndbuf_limited`), `server_link_flows` and
  `server_link_rwnd_held_flows` (those sockets, and how many of them the receive window held for at least half the
  window), and `server_link_unsent_bytes` (the median unsent queue as the window closes).
- For the core's far-leg flows as the window closes, the median `far_rcv_rtt_us`, `far_rcv_space_bytes` and
  `far_rcv_wnd_bytes`: the receiver's RTT estimate and the receive space and window its autotuning reached.
- On `tcp-multi`, `flow_<n>_gbps`: each flow's rate. The flows connect one after another, so `n` is the connect order.

## Reading the report

Each cell shows the median over rounds and the half-width of its 95% bootstrap interval. The comparison columns show the
subject (the first `--core`) relative to each other core, with the 95% interval of the ratio. ▲ means better, ▼ worse,
and ≈ that the difference is not significant: the interval spans zero, the exact Mann-Whitney p is at least 0.05, or the
difference is under 2%. A run that decides anything has at least 5 rounds. With 3 a side the smallest possible p is 0.1,
so nothing could ever count as significant. With 4 a side it is 0.029, enough only for differences that never overlap:
read on their first 4 rounds, past runs found about four in five of the cells their full rounds showed behind Go. A
4-round run is a targeted signal only; for a close call, raise `--rounds`.

`server_cores`, `origin_cores` and `client_cores` show which process limited a throughput: when one of them uses all
the CPUs it was given, the core under test was not the limit.

For `tcp-multi` on loopback (no `--link`) the report adds a far-leg state table: each trial is `small` (under 25 KB
per server segment and over 15 non-data segments per wire MB), `large` (at least 35 KB and at most 15) or `between`,
with the server CPU per GB and throughput of each group. A veth link counts every 1500-byte MSS as a segment, so the
table is left out there. It is a diagnostic of the loopback regime above; compare cores on a `ts=usec` run instead.

On macOS, a loopback connection-rate run leaves ports in TIME_WAIT. The harness aborts its own connections with RST and
the origin closes first, but a full run with many cases can still exhaust the roughly 16k ephemeral ports. If it does,
widen the range with `sudo sysctl net.inet.ip.portrange.first=10000`.

## Windows

Build in the VM with the toolchain `commands.md` lists for Windows, then run as on the other platforms:

```bat
cargo build --release -p concord-desktop -p bench
target\release\concord-bench.exe run --mihomo mihomo.exe --core concord=concord:target\release\concord.exe --core go=mihomo:mihomo.exe
```

`--link` and `--tun` need Linux, so they are not available on Windows.

In a Windows VM, protocols whose mihomo server paces itself with short timers are measured partly on how promptly
Windows fires the server's timers, and that depends on the other processes, the core under test included. mieru over TCP
sleeps 100 µs on the server after every 32 KiB it queues, and that sleep sets its per-session rate. The QUIC servers
(tuic, hysteria2) wait for their pacer's 1 ms timer. A Go client keeps vCPU 0, where Windows expires timers, awake, and
its own fine-grained timers wake the system more often. A client that parks idle threads does neither, so the same
server fires the same timers later. In one run, the server's 100 µs sleep averaged 1.1 ms under the Go client and 2.3 ms
under Concord. Before reading a Windows gap on these cases as the core's own cost, rerun with an idle-priority busy loop
pinned to CPU 0. In our runs that cut Concord's deficit on these cases from about 50% to 5-20%. What remained still
showed up in the server's per-chunk sleep and pacer queue, not in the core:

```bat
start /low /affinity 1 powershell -NoProfile -Command "while ($true) {}"
```

Connection-rate cases exhaust the VM's ephemeral ports on Windows defaults: 16 384 dynamic ports from 49152, TIME_WAIT
held 120 s, and no loopback reuse such as Linux's `tcp_tw_reuse=2` (the Linux VM has 28 232 ports, 32768-60999, and a
fixed 60 s TIME_WAIT). A tcp-crr window opens about 3 300 connections, and the core's own leg to the server can leave a
TIME_WAIT for each, so later cells in a round failed with `early eof` whichever core ran there. The Windows VM's
dynamic TCP range is therefore 41100-65534:

```bat
netsh int ipv4 set dynamicport tcp start=41100 num=24435
```

It starts above the harness's server ports, which begin at 21000 + 10 × (pid mod 2000) and add one per case
(`tools/bench/src/runner.rs`), so they fall in 21000-40990 plus the case count and must stay outside the dynamic
range. The setting persists across reboots; `start=49152 num=16384` restores the default.

The Windows VM runs with PMU virtualization on. Absolute numbers taken with it off are not comparable with these. CPU
sampling still fails there (`PROFILE` kernel sessions return 0x32), so there are no CPU profiles from this VM.

Windows updates itself in the VM, and a new build can move every arm: from build 10.0.26300.9818 to 10.0.26300.9974,
`tcp-crr` fell to about 40% of its rate on both arms. Name the build in each report (`ver`, or the
`kernel` field of `results.json`), and do not compare one arm's absolute numbers across builds.

On Windows the harness places the core on CPUs 0-1, the server on CPU 2, the origin on CPU 3 and the load generator on
CPUs 4-5 of the six-vCPU VM, so the core shares CPU 0 with Windows timer expiry and the server has a single CPU.

## Android

There are two levels.

**The core alone, on the device.** Build `concord` and `concord-bench` for `aarch64-linux-android` with the NDK,
using the same environment as the Gradle `cargoCore` task. An executable that links `c++_static` also needs `-C
link-arg=-lc++abi`. mihomo can be a static `GOOS=linux GOARCH=arm64` build. Push all three to `/data/local/tmp` and run
there as the shell user:

```sh
adb shell 'cd /data/local/tmp/cb && TMPDIR=$PWD ./concord-bench run --mihomo ./mihomo \
  --core concord=concord:./concord --core go=mihomo:./mihomo'
```

This measures the protocol and relay cost on the phone's CPUs, without JNI or VpnService. The results record the
device, SoC, per-CPU maximum frequency and thermal status, and the run warns if the device is already throttling.
Instructions and cycles need `perf_event_paranoid` of 1 or lower, which many devices already have; the results record
the value. Keep the device on charge with its screen off, and let it cool between full runs.

Power management on a phone can withhold the big cores from a shell process, and the run then warns that only some
CPUs are allowed. Pass the split explicitly, with the server on big cores too: one mihomo serving every protocol from a
little core is slower than the core under test, and every throughput then measures the server. On a Snapdragon 888
(little 0-3, big 4-6, prime 7), `--cpus core=4-5,server=6-7,origin=0,client=1-3`. `server_cores` near the number of
CPUs it was given means the server was the limit.

**Inside an app.** `--attach` measures a core that is already running in an app's process instead of starting one.
That process may also do the app's UI work, so leave the app in the background while it measures. Only the workloads
that leave the core as they found it run in this mode. Two apps cannot hold the VPN at the same time, so to compare an
app built on Concord with one built on mihomo, measure each in its own run and compare them with
`concord-bench compare go/results.json rs/results.json --base-core go --new-core rs`.

Through the app's mixed port, with the origin on the device, as the shell user (`<package>` is the app's package
name):

```sh
./concord-bench run --attach rs=pkg:<package> --via socks:127.0.0.1:7890
```

Through its VPN, which adds the TUN reads and writes, the user-space stack and `protect()`, the path users actually
take. This needs root (an emulator's `google_apis` image, or `adb root` on a userdebug build):

```sh
# On another machine the device reaches, off its own subnet:
concord-bench origin --bind 172.20.10.2 --base-port 47000
# On the device, as root:
./concord-bench run --attach rs=pkg:<package> --via tun --origin 172.20.10.2:47000 \
  --load-uid pkg:com.google.android.inputmethod.latin
```

Four things have to line up, and the run checks the first before it starts:

- Android routes into a VPN by the socket's uid, and never the shell's or root's. `--load-uid` creates the load's
  sockets as another app's uid. The run refuses to start if traffic to the origin would not leave through a tun device.
- That app must be allowed network in the background, or Android drops its replies: on Android 17 pick one with
  `BACKGROUND_MATCH` in `dumpsys connectivity trafficcontroller`, and with `PERMISSION_ACCESS_LOCAL_NETWORK` for a
  private origin. The keyboard app usually qualifies; Chrome does not.
- The origin cannot be on loopback, on the device's own subnet (Android sends that to the interface's local table ahead
  of the VPN), or on a private address while the app bypasses private addresses; turn that off in its network
  settings and restart the VPN. An emulator reaches its host's LAN address through its NAT.
- The core binds its outbound sockets to the physical interface, so the origin must be reachable through it.

Running as root also lets the harness read the app's PSS and file descriptors. On an emulator the numbers include its
NAT, which caps throughput near 150 Mbit/s, so compare CPU per byte and latency rather than rates, and only between two
apps or two builds on the same host. Leave out `tcp-crr` there: every connection becomes a host socket in the NAT, and
past about a thousand the emulator's main loop spins in `select` and the whole device hangs.

## Control API

`tools/api-bench` measures the control API rather than the data path, against an engine in the same process over the
local socket: `wire` the bytes `connection.watch` sends for 1000 connections idle and under churn, `rtt` the
round-trip percentiles of a few cheap methods, and `subs` the memory each idle subscription holds. Run it in release
(`cargo run --release -p api-bench -- wire`) on Linux or macOS; it needs Unix sockets.

## Gost peers

The `ss-gost` case uses gost v2 (`CONCORD_GOST2`) as its Shadowsocks-over-WebSocket/smux server.
Set the variable to a binary for the measurement platform. The harness starts it in the server's CPU/network
placement and includes its CPU in the server counters. For example, after building the bench and cores:

```sh
CONCORD_GOST2=/path/to/gost-v2 cargo xtask bench --quick --only ss-gost --rounds 1 --no-baseline --mihomo /path/to/mihomo
```

This is an opt-in case, excluded from both tiers; select it with `--only ss-gost` and set `CONCORD_GOST2`. The upstream interop test
`gost::gost_plugin_round_trips_with_upstream_gost_and_mihomo` uses `CONCORD_GOST2` and `CONCORD_MIHOMO` and
checks WebSocket with and without TLS and smux, forwarding to mihomo's Shadowsocks listener.

The `gost-relay` case similarly uses gost v3 (`CONCORD_GOST3`), with TCP and UDP. It is also excluded from both
tiers; select it with `--only gost-relay` and set `CONCORD_GOST3`.
The relay server is launched with `nodelay=true`: mihomo and Concord both await CONNECT before application data.
Its interop test is `gost_relay::gost_relay_round_trips_with_upstream_gost`; it covers authenticated relay,
forward mode, TLS, smux, TCP and destination-bound UDP against upstream gost v3.
CI's interop job runs both tests against gost v2.12.0 and v3.3.3, the releases they were written against
(`.github/actions/gost`).
