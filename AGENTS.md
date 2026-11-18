# AGENTS.md

Entry point for coding agents working in Concord. Keep it small: detailed guidance lives under `.agents/`.

## Start Here

Read these before changing code:

- [.agents/project.md](.agents/project.md): what Concord is, its scope, and where its boundary with the host app runs.
- [.agents/commands.md](.agents/commands.md): build, the full gate, benchmarks, and the target directory.
- [.agents/rules.md](.agents/rules.md): layering and ownership, how a fix is shaped, mihomo alignment, the basis
  every tunable needs, commits.

Read these when the task touches their area:

- [.agents/architecture.md](.agents/architecture.md): crate layers, the data path, and the control plane.
- [.agents/performance.md](.agents/performance.md): the bar against Go, the landing gate, deferring a gap, how to
  measure, and measurement pitfalls. Required before any change to the data path.
- [.agents/reference-choices.md](.agents/reference-choices.md): what mihomo, sing and sing-box chose for sizes, flush
  points, windows and timers, and where Concord still deviates.
- [.agents/embedding.md](.agents/embedding.md): how a host runs Concord, the session handshake, the C ABI, and the
  build- and run-time variables.
- [.agents/behaviour-checklist.md](.agents/behaviour-checklist.md): behaviour a host relies on beyond the method
  signatures, and the test that holds each item.
- [.agents/benchmarking.md](.agents/benchmarking.md): running `concord-bench` and reading its report.
- [docs/compatibility.md](docs/compatibility.md): user-facing differences from mihomo; keep it current with scope.
- [vendor/PATCHES.md](vendor/PATCHES.md): what the vendored crates change against their releases.

`README.md` and `docs/` (`usage.md`, `compatibility.md`, `performance.md`) are public
and describe the product only: features, platforms, building and running, compatibility, and the published results
against mihomo. Development detail (build internals, the embedding protocol, how to benchmark a change, tests, layout)
belongs in `.agents/`.

## Highest Priority Rules

- Every bench item is to beat or tie Go (mihomo). A change lands when its target metric improves against `main` in the
  same run and nothing it measures gets worse; gaps `main` already had do not block it. The full standard is in
  `performance.md`.
- Fix causes with the idiomatic Rust and tokio mechanism. Forced yields, spinning or busy loops, extra copies or
  allocations that only shift timing, arbitrary socket-buffer caps, and global timer or sysctl changes are not fixes,
  even when a benchmark improves. An experiment that moves a number is evidence until its cause is known.
- When Concord behaves differently from mihomo (wire defaults, padding, framing, queue sizes, edge cases), align it to
  mihomo unless the deviation is a clear improvement with no compatibility risk.
- Whether a profile key takes effect is what `concord -t` reports and what `crates/config/tests/tiers.rs` proves for
  its tier, never what a search for the field name suggests. A key joins the inert tier in `keys.rs` only when mihomo's
  results ignore it too or the host owns it, with that reason beside its list and an entry in `docs/compatibility.md`.
- Keep the layering: `cargo xtask check-layers` holds each crate to its exact dependencies and release `opt-level`.
  Every outbound socket goes through `concord_net::Sockets`; `clippy.toml` rejects the bypasses.
- Before reporting a change done, run the full gate in `commands.md`. Name any check you could not run and why.
- Worktrees share the main checkout's `target/`, each build under its own `--cfg` (Target Directory And Disk in
  `commands.md`); clean what you build when you are done with it.
- Comments carry only what the code cannot say; see `rules.md`. No agent trailers in commits, and no machine-local
  paths, user names, host names or personal emails anywhere in the repository.

Maintainers may keep local notes in the git-ignored `docs/private/`; read its `README.md` if it exists.
