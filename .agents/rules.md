# Rules

## Layering And Ownership

- `xtask/src/layers.rs` is the source of truth for which workspace crate may depend on which, exactly (an unused
  entry fails too), and for each crate's release `opt-level`. A new crate gets an entry; a new edge is a design
  decision, not a fix for a compile error. `concord-config` and `concord-rules` must not reach tokio, and nothing
  depends on a binary.
- Cycles are broken by traits in `concord-common` (or the lower crate) that the engine injects: `FlowHandler` hands
  inbound flows to the tunnel, `SocketFactory`, `HostResolver` and `NodeDialer` reach sockets, DNS and named nodes
  from `proxy`, `dns::UpstreamDialer` lets DNS dial through the tunnel, `group::Fetcher` lets providers download through
  it, and `common::intercept` connects MITM. Add a trait at the lower layer rather than an upward dependency.
- Each concern has one owner, and a change lands there: socket creation and `protect` in `concord-net::Sockets` and
  `concord-platform`; platform `cfg` in `concord-platform` and `concord-tun`; traffic metering in the tunnel's
  connection table; config parsing in `concord-config`, which produces typed definitions and no runtime objects;
  lifecycle and apply in `concord-engine`; wire types in `concord-proto`. Do not add a second source of truth
  elsewhere.
- `clippy.toml` forbids `TcpStream::connect`, `UdpSocket::bind`, `lookup_host` and `to_socket_addrs`: every outbound
  socket goes through `Sockets`, or Android skips `protect` and `getaddrinfo` loops back into the VPN.
- A `Stream` impl over another stream declares every capability once with `concord_common::stream_policy!`:
  `forward` hands it unchanged to the inner stream, `own` names the methods the impl writes, and `default` keeps the
  trait default, which copies through the type's own `AsyncRead`/`AsyncWrite` and exposes nothing beneath it. A
  wrapper that frames or meters must not forward `tcp`, `raw_socket` or `direct`, which let the relay bypass it.
  A missing forward compiles and silently takes the slower path, so xtask's `stream_policy` test rejects a wrapper
  without a policy, a capability left out or named twice, and a hand-written plain forward. A new `Stream` method
  gets a forwarding arm in the macro and a decision in every policy.
- A data-path crate is built at `opt-level = 3` in the release profile and declared `Speed` in the layer table; the
  rest inherit `z` or use `s`. Moving a third-party crate to 3 needs a measurement that shows it.
- `unsafe` is denied in the workspace and allowed only in `concord-platform`, `concord-tun`, `concord-ffi`, the
  binaries and `tools/`, and in test files. Clippy's `undocumented_unsafe_blocks` holds every block to a `// SAFETY:`
  comment above it; the bench harness alone states its argument in the `allow(unsafe_code)` reason instead. xtask's
  `unsafe_policy` test rejects an `allow` or `expect` of `unsafe_code` anywhere else. A file that must call FFI
  outside those crates is listed here with its reason and in that test's `EXEMPT`; none is today (the record-layer
  reads `concord-tls` needed are safe methods in `vendor/boring`). The same test requires `[lints] workspace = true`
  in every member's `Cargo.toml`, since a member that sets its own lints could allow `unsafe_code` there.
- `#[allow]` always carries a `reason`.
- An error a caller branches on, or that reaches the host as a code, is a typed enum (`thiserror`) that keeps its
  cause as the source. An error that only joins a list of diagnostics shown to a person (a config line that does not
  parse, a script's message) may stay a `String`.
- Non-test files stay within 800 lines and functions within 120. xtask's `ratchets` test holds `xtask/ratchets.txt`
  to the code exactly, so every change in a listed size updates its line in the same commit. Nothing new joins the
  list. A listed file or function may grow when a change needs it, with `raised from <old>: <reason>` on its line
  saying why and when it comes back down (`raised from 809: GSO coalesced write, split in B1`); the reviewer weighs
  the reason, and a raise without one fails. A reason that names its condition (`back down when X`) is a promise:
  the change that lands X brings the number back down in the same commit, and its review checks the line. A
  per-crate `Result<_, String>` count only goes down.
- `panic = "unwind"`: a malformed packet may end one connection's task, never the process. Infrastructure tasks whose
  failure would leave a VPN that only looks alive are the exception.

## Shaping A Fix

- Design with Rust and tokio's own mechanisms: cooperative budgets, split ownership of the two directions, zero-copy
  and vectored I/O, forwarding a trait's capabilities faithfully through wrappers. Go is a reference for behaviour,
  for data and for language-neutral structure ("Behaviour Against mihomo"); its runtime-bound shape is not one to
  copy: tokio schedules cooperatively and owns differently, so a port of it is rarely the best Rust.
- Not acceptable as a fix, even when a bench improves: forced or periodic yields, spinning or busy loops (including to
  keep a CPU awake for someone else's timers), copies or allocations added to shift timing, arbitrary socket-buffer
  caps or locks, raising the system timer resolution, global sysctl or kernel feature changes, and swapping a crypto
  library for one micro-benchmark. These may be used as isolation experiments; the fix addresses the cause they
  isolate.
- Secondary metrics count. A fix that wins its headline but costs server CPU, fairness, RR p99 or memory against
  `main` is not done; fix the side effect or show why it is not Concord's. Diagnostics such as context switches and
  p999 are reported and explained in the review entry, not a veto on their own (`performance.md`).
- A change that makes the implementation more idiomatic (fewer copies, faithful trait forwarding, plain tokio) is worth
  landing for a small gain, as long as it meets the landing gate in `performance.md`.

## Behaviour Against mihomo

- Where Concord differs from mihomo in wire defaults, padding, framing, queue sizes or edge cases, align it to mihomo
  in the same pass. Keep a deviation only when it is a clear improvement with no compatibility risk (batched reads,
  per-destination UDP sessions where mihomo misdelivers), and say so where it lives.
- For system-level edge cases (signals, fd limits, quotas, half-close, platform differences), first read how mihomo,
  sing and meow-rs handle the same thing, and adopt a guard that costs nothing rather than rediscovering the failure.
- Tuning choices (sizes, batch and flush points, timers and timeouts, thresholds, queue depths) start from what
  mature implementations chose for the same trade-off: mihomo, sing-box and sing, the kernel, the RFC, the defaults
  of rustls, quinn or tokio. Read the choice and its reason in their code, record it in the review entry, and adopt
  it. Deviate only where Concord's model changes the trade-off (async tasks instead of goroutines, a different
  ownership split), argued from the code and confirmed by a run; when the references disagree, follow the one whose
  model is closest and say why. Reasoning out a new value or sweeping measurements does not replace reading them.
  `reference-choices.md` keeps what has been read; extend it rather than searching again.
- Architecture choices follow the references the same way. A choice is runtime-bound when the reference made it for
  a reason specific to Go's runtime (cheap goroutines, the garbage collector, the netpoller, IOCP completion I/O),
  and language-neutral otherwise. Language-neutral choices (whether state is cached or queried on every use, whether
  a monitor or a timer invalidates it, which layer owns it and when it is refreshed, how failure and retry are
  structured) adopt the structure mihomo and sing-box share; where they differ, sing-box's leads and the other's
  mechanism may stay only as a fallback. Runtime-bound choices (I/O scheduling, wakeups, task structure, ownership
  splits, synchronisation primitives) may follow Rust and tokio as "Shaping A Fix" and `performance.md`
  (Concurrency-model trade-offs) set out. A language-neutral deviation needs what a tuning deviation needs: an
  argument from the code that Concord's model changes the trade-off, and a run.
- Compare with the reference at the same position. Where Concord's host supplies something a standalone reference
  finds for itself (Android reports network changes through `network_update`), the reference is the path it takes
  when its own host supplies it (sing-box's platform interface), not its standalone path. `reference-choices.md`
  names the path for each area.
- Every entry under "Deviations To Resolve", "Matching The References" and "Deliberate Differences" in
  `reference-choices.md` states its kind and cites `file:line` or `file::symbol` in a pinned reference; a
  language-neutral deliberate difference also names its run. xtask's `reference_choices` test holds that shape. It
  checks form, not the design; the reviewer still opens a citation.
- A plan or review entry that says what a reference does cites `file:line` in the version `reference-choices.md`
  pins, from the reference that table names for the area, and says whether that path is the one the reference takes
  by default. A claim without a citation, or about a fallback or optional variant, does not justify a change; the
  reviewer opens at least one citation before accepting.
- Deliberate differences and settings whose meaning follows the fork of mihomo that FlClash shipped are part of the design; check before
  "fixing" one.

## Tunables

- A tunable is any value Concord chooses that sets scheduling, yielding, batching, buffering, a window, a queue or
  pool capacity, concurrency, a timeout, an interval, retries and backoff, a cache's size or lifetime, or an
  input-size or work budget, on any path. A wire or format constant fixed by a protocol, a file format or a platform
  API is not one.
- Every tunable has one of four bases, written down:
  - (A) a spec, cited: an RFC or draft, a `file:line`, or a published specification's URL and section name
    (the Surge manual is the specification of the script behaviour MITM ports).
  - (B) the mature reference's value for the same knob, cited to `file:line` with the value (language-neutral
    choices follow the reference, as "Behaviour Against mihomo" sets out). Where mihomo and sing-box have no such
    knob, B may cite the default of the Rust library Concord uses at that place, or whose part Concord implements
    there, as `Rust <crate> <version>` with `file:line`; where they have one, theirs wins. A knob only Concord has
    may take the nearest analogue in the same family of references, and its row says it is an analogue.
  - (C) a derivation from a runtime mechanism (Tokio, the kernel, the platform API), with the mechanism cited to
    source or documentation and the number following from it.
  - (O) for a feature only Concord has, a derivation from a written requirement (a host constant, a host API
    limit, a user-visible time limit the docs state), with the requirement cited to `file:line`.
- When no requirement and no analogue fixes a value of Concord's own, the simple choice is to remove the knob: no
  cap, no timer, or a depth of one with backpressure. A row for what remains says "no requirement: knob removed".
  Picking an integer is not a basis; such an item stays in the ratchet.
- A number chosen because a screen or a benchmark on our machines liked it is not a basis, and neither is "Concord's
  own" or a comment that names only a direction. A measurement tests a prediction written before the run; it does
  not pick a constant.
- A value that differs by platform or shape follows from a condition derived from the mechanism and written where
  the value is registered. If no condition can be derived, use one value.
- xtask's `tunables` test holds every numeric or `Duration` `const` and `static` in non-test code to this: a row in
  `reference-choices.md` "Tunables" with its value, basis and citation, or a line under "Wire And Format
  Constants" there with its spec. B, C and O need a `file:line`. A row's value must equal the code's, so a changed
  value updates its row and basis in the same commit. `xtask/tunables.txt` lists the tunables still without a basis;
  it only shrinks, and a new tunable without a basis fails at once. A literal inside an expression is not gated; the
  rule covers it and review enforces it.

## Vendored Crates

`vendor/` holds crates.io releases with listed changes, wired through `[patch.crates-io]`. Every source change carries
a `Concord:` comment, and a change to a vendored crate updates `vendor/PATCHES.md` in the same commit. An upgrade
replays the list on the new release.

## Comments And Docs

- A comment carries what the code cannot say: a non-obvious constraint, an upstream or platform behaviour being worked
  around, a coupling to a value defined elsewhere, a reason the next reader would get wrong. Never restate the code,
  narrate the change, record what the code used to be, or annotate step by step; a block that seems to need a comment
  per line needs better names or smaller functions. No line-by-line `upstream: file.go` mappings.
- Keep density low (standalone comment lines well under 5% of added lines). Delete commented-out code and stale notes
  in files you touch. Lint directives, license headers and vendored upstream comments are exempt.
- Docs in this repository hold rules and facts, not narratives: no session history, conversation dates or agent names.
  A measured number carries its platform, case and the commit or run it came from.
- Nothing tracked and no commit message names the project's own coordination: its working directories and notes, run
  or branch names, work-line codes. A test vector says which upstream, version and call produced it. The `public_tree`
  test and `check-commits` hold both to the same list.

## Commits

- Conventional Commits with a scope (`fix(tun): …`, `refactor(proxy): …`, `docs(agents): …`), one concern per commit.
- No `Co-authored-by` or any other trailer that credits or links a coding agent.
- No machine-local identifiers in anything committed: home directories, user names, absolute checkout paths, host
  names, personal emails. Use a path relative to the repository, `$HOME` or a placeholder.
- Never push. Pushing Concord, and FlClash's pointer to it, is the user's step.
