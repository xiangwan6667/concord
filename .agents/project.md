# Project

Concord is a proxy core written from scratch in Rust; it is not a fork of mihomo, but reads the same configuration
and aims at the same behaviour. A host application controls it over a typed JSON-RPC 2.0 API described by
`schema/api.json`. Its main embedder is FlClash, which checks this repository out as `concord/` and builds it from
there. Toolchain: Rust as pinned in `rust-toolchain.toml`, edition 2024.

## Direction

- **Performance before size.** The release binary's size is a reference, not a ceiling; a reasoned increase is fine,
  and size never justifies a slower data path. Do not propose `panic = "abort"`, dropping aws-lc or dropping QuickJS
  to save bytes.
- **Lean.** Obsolete compatibility and options with a tiny audience are not implemented; code with no effect is
  deleted; a setting that maps onto an existing mechanism is mapped, not rebuilt.
- **Modern.** Old protocols, ciphers and fingerprints are not replicated for their own sake. What is not supported is
  reported as a clear config warning.
- Fix a functional defect directly. A change with a trade-off or a visible side effect goes to the user as a judgment
  with the evidence, and the user decides.

## Scope

Config keys, outbound types, transports and plugins are tiered T0, T1 and T2 by the design. T0 and T1 are implemented;
T2 is not, and is dropped at parse time with a warning. The T2 outbound types, networks, TLS keys and ss plugins are
the `T2_*` lists in `crates/config/src/proxy/parse.rs`. Not everything mihomo has is in scope. When a request and the
tiering disagree, report the conflict instead of choosing.

Unsupported input is handled in three ways, and a key whose loss would change where traffic goes is never ignored
silently:

| Handling | When |
|---|---|
| Reject the profile (`config_rejected`), then run the built-in empty config, which routes direct | The profile is wrong: unknown or malformed rules, illegal fields, a reference to something that never existed |
| Quarantine the node and warn | The node is valid but unsupported. A group left empty by quarantine, or whose selected node was quarantined, refuses connections rather than falling back |
| Ignore and warn | The key does not change routing, or the app overrides it |

Inbound listeners named in a profile (`listeners`, `tunnels`, `external-controller-tls`, `-unix`, `-pipe` and the
like) are never opened. The exception is `external-controller`: `concord-controller` serves the Clash API at the
profile's address when the core runs on its own, and at the address a host gives in `config.patch` when it is
embedded; with neither, nothing opens.
`GEOIP` reads only the mmdb; `GeoIP.dat` and `geodata-mode` are ignored with a warning. Do not add the dat path back.
`docs/compatibility.md` lists what is left out, what is partial and the deliberate differences from mihomo; keep it
current when scope changes.

## Boundary With The Host

The API is Concord's own. It is designed so that any client could use it, not shaped after how Dart called the Go
core; FlClash, the main host, adapts to it.

| Owner | Owns |
|---|---|
| Concord `crates/proto` | Wire types, error kinds, the method registry (execution class, cancellation, streams, capabilities) and the generated schema |
| Concord `crates/api`, `rpc`, `ipc`, `ffi` | Typed methods over the engine; JSON-RPC dispatch, cancellation and credit-based streams; the socket or pipe framing and token handshake; the C ABI that Android and Dart FFI share |
| Concord `bins/desktop`, `bins/android` | The `concord` executable and the `libconcord.so` C library: argument parsing, signals, platform hooks |
| Concord engine | Engine state (`created → initialized → configured → running`, or `failed`) and the route counters; the Core is the source of truth for both |
| FlClash `lib/core/desktop/` | Desktop Core process lifecycle: who starts it, who stops it, leases, session generations |
| FlClash `ServiceState` | Android service intent. `engine.start` and `engine.stop` are requests to the engine, not service intent |
| FlClash build hooks | `plugins/setup/` builds `concord` and installs it as `FlClashCore`; the `:core` Gradle module's `cargoCore` task builds `libconcord.so` and FlClash's own JNI glue over its C ABI; both set `CONCORD_PRODUCT_NAME` |
| FlClash `test/core/api/contract_test.dart` | Checks every Dart call and DTO against `schema/api.json` |

The Core keeps no record of intent. Latest-intent arbitration for start, stop and restart happens in the host before
it sends a request; a queued request the host supersedes is cancelled and never runs.

A host validates only what it can know itself. What only the Core can resolve (filters, provider contents,
runtime selections) is left to the Core, which must report the problem as an error or event, never crash on it; a
dial that would loop through its own `dialer-proxy`, for example, fails with `DialerLoop`.

Nothing in Concord is named after a host. The name end users see (the MITM CA's subject and the Android TUN device) is
`concord_common::PRODUCT_NAME`, read from `CONCORD_PRODUCT_NAME` at build time with `Concord` as the default; a host
sets it, and Concord's code, docs and file names stay neutral.

A protocol change regenerates `schema/` (`cargo xtask schema`) in the same commit and needs the matching FlClash
change; a behaviour a host relies on without the signature showing it belongs in `.agents/behaviour-checklist.md`.
