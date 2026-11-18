# Architecture

This describes the tree as it is. Where this file and the code disagree, the code wins; fix this file.

## Principles

- **Config is data.** `concord-config` parses YAML into typed definitions with no sockets, no tokio and no runtime
  objects, so parsing, validation, share links and dumps work on their own.
- **No global mutable state.** Everything hangs off an `Engine` instance; tests run several at once.
- **Capabilities are types.** Closed enums and explicit `Stream` methods (`tcp`, `peer_addr`, `needs_handshake`,
  `direct`, `into_split`), never `Any` and downcasts.
- **Abstraction cost follows frequency.** Per connection may box (`async_trait`, `Box<dyn Stream>`); per packet may
  not allocate (`PacketSession` is `poll_*`, `PacketBuf` keeps headroom so headers are written in place); TUN uses
  concrete types.
- **One entry for outbound sockets** (`concord_net::Sockets`), enforced by `clippy.toml`.
- **A config snapshot is separate from state that outlives it.** Selections, the connection table and counters are
  not part of the config.
- **Platform differences stay in `concord-platform` and `concord-tun`.**

## Crate Layers

The exact edges are in `xtask/src/layers.rs`. From the bottom up:

| Layer | Crates | Role |
|---|---|---|
| Base | `common` | Addresses, flow metadata, `Stream`, `Outbound`, `PacketSession`, events, errors, and the injected traits (`FlowHandler`, `SocketFactory`, `HostResolver`, `NodeDialer`, `EventSink`, `intercept`) |
| Pure | `config`, `rules` | Profile parsing and validation; the rule compiler and route program. No tokio |
| OS | `platform` | The `Platform` trait a host implements (`protect`, process lookup, default interface) and native system calls (sockopts, splice, tproxy, rlimits, owned mmap buffers) |
| Sockets and crypto | `net`, `tls`, `netstack` | Socket factory, dialing, loopback guard, the relay; rustls and BoringSSL backends, fingerprints, REALITY, ECH; the user-space TCP/IP stack shared by TUN and WireGuard |
| Links | `transport`, `proxy` | ws, gRPC, h2, xhttp, obfs, ShadowTLS, sing-mux, QUIC over a `PacketSession` (proxy and DNS); the outbound protocols and how a node's link is composed |
| Services | `dns`, `group` | Resolver, upstreams, fake-ip, cache; groups, providers, health checks |
| Pipeline | `tunnel` | Pre-handle, sniff, route, dial, track, relay; UDP NAT; connection table |
| Edges | `inbound`, `tun`, `mitm` | mixed/http/socks/redir/tproxy listeners; TUN device, routes and stack driver; MITM, scripts, capture |
| Root | `engine` | Composition, lifecycle, apply, background tasks, state that outlives a config |
| Control | `proto`, `api`, `rpc`, `ipc`, `ffi` | Wire types and registry; one typed function per method; JSON-RPC; socket framing and handshake; the C ABI |
| Binaries | `bins/desktop`, `bins/android` | The `concord` executable and the C ABI `cdylib` `libconcord.so` |

Inversions that keep it acyclic: inbound and tun hand flows to the tunnel through `FlowHandler`; proxy dials named
nodes (`dialer-proxy` may name a group) through `NodeDialer`; DNS dials through the tunnel with `dns::UpstreamDialer`,
which the engine implements and guards against loops; providers download through `group::Fetcher`; MITM is offered
flows through `common::intercept`, and the engine's default-on `mitm` feature links it.

## TCP Data Path

`tunnel/src/tcp.rs` `handle`, in mihomo's order, which apps depend on:

1. An inbound or the TUN stack produces `FlowMeta` and a `BoxStream` and calls `FlowHandler::handle_tcp`.
2. Pre-handle: fake-ip reverse lookup, hosts; an unmapped fake-ip is dropped.
3. Sniff: a bounded peek (TLS SNI, HTTP Host); the bytes are kept and replayed with `PeekedStream`.
4. MITM offer, when an interceptor is installed: it takes the flow or hands it back.
5. Route and dial, overlapped with reading the client's first bytes: the route program resolves IP and process
   lazily, groups resolve to a leaf, the leaf's `Outbound::connect` dials through `Sockets`. A retry happens only
   when another IP or route could succeed, at most twice.
6. Track: the connection is registered in `ConnTable`, which owns metering and cancellation; dropping the
   registration removes it.
7. Relay: `net/src/relay.rs` drives both directions in one task. Each ordinary read borrows a pooled buffer with a
   32 KiB fallback, reader/writer MTU sizing and writer headroom; the owner returns after the write. A bare TCP sink
   can batch eight owned reads without copying their payloads, draining on source Pending, EOF or error. Two bare
   TCP sockets use `splice` from the first byte on Linux; a netstack connection to a direct socket is attached so the
   stack moves bytes itself with no relay task. After one side's EOF the relay shuts the other's write side and runs
   until the open direction ends on its own, with no timer.

A config apply builds a new `tunnel::Runtime` and swaps it in; flows already running keep the old one.

## UDP

The route decision and the outbound socket are two tables (`tunnel/src/udp/`): flows keyed by (source,
destination) are routed once, and sessions keyed by (source, outbound) are shared, so each destination follows its
own rule while the external mapping stays endpoint-independent. A protocol that can reach only one destination per
session (plain vmess) adds the destination to the session key. One connection record per session; idle sessions are
swept on a coarse timer; the flow table is capped. Sending tries `poll_send` inline and falls back to a bounded
per-session queue; each session has one receive task.

UDP inbound loops charge tokio's cooperative budget per receive (`consume_budget`), because a socket that reports
spurious readiness (Windows AFD) would otherwise hold a worker indefinitely.

## Outbounds

`Outbound` is the one trait a leaf implements; groups are not outbounds. `proxy/src/build.rs` maps each
`ProxyKind` to its builder, wrapped in sing-mux when configured. A node's `Link` composes dial, TLS and a
`TransportStack` of closed `Layer` variants; QUIC protocols (hysteria, hysteria2, tuic, shadowquic) use quinn through
`proxy/src/quic`. Dependencies arrive through `DialEnv` (`SocketFactory`, `HostResolver`, `NodeDialer`,
`EventSink`). Datagram-over-stream protocols share `dgram::{Encoder, Decoder}`.

TLS has two backends: rustls with aws-lc-rs by default, BoringSSL where a `client-fingerprint` needs a browser
ClientHello; REALITY and ECH are implemented in `concord-tls`.
rustls runs on the native record engine as soon as the handshake ends. A node's own TLS (`Link::open`) and the
HTTP/2 carriers (Gun, XHTTP) use `connect_whole`: a read takes the rest of the current record and up to a copy
buffer of the next off the socket. `connect`, for Vision and the handshakes that hand the transport back, reads to
record boundaries. `into_split` hands each half its direction's keys, sequences, KeyUpdate schedule and what was
read ahead. BoringSSL keeps its own object and moves to the engine at a quiescent `into_split` when the suite
allows it; a buffered, previously read or closing connection keeps its original object behind the plain-lock
fallback. Vision's explicit record-boundary connection and REALITY already own their records.

## TUN

`concord-tun` opens the device (Linux with offload and one queue per worker, utun, wintun), installs routes and runs
the stack driver over `concord-netstack`, Concord's own TCP stack. Flows go to the tunnel through `FlowHandler`
like any inbound. Receive rings are owned mmaps that opt out of transparent huge pages.

## Engine And Control Plane

`concord-engine` owns home, platform, the event hub, `ConnTable`, selections, route counters, options, listeners and
the current runtime. An apply is serialized: load the profile, compile the route program, build the runtime, swap it,
then reconcile listeners, TUN and DNS; providers load afterwards and report `loaded`. A rejected profile falls back to
the built-in empty config and says so. Background tasks belong to the engine's `TaskTracker` and are awaited on
shutdown, up to a bound. The proxy layer registers its tasks there through `concord_common::Tasks`, which a build
context carries; a node's tasks end when the node is dropped or the engine stops, and xtask's `task_owner` test
keeps `tokio::spawn` out of `proxy`, `transport`, `net` and `tls`.

The control plane is layered: `proto` (types, errors, the method registry with execution class `inline`, `serial` or
`concurrent`, stream policies `latest`, `drop_oldest` or `resync`) → `api` (one async function per method) → `rpc`
(JSON-RPC 2.0, cancellation, credit-based subscriptions) → `ipc` (length-prefixed frames and the token handshake over
a Unix socket, named pipe or loopback port) or `ffi` (C ABI for in-process hosts). Core work never blocks on event
delivery.

## Pending Restructure

Still open:

- Proxy and transport owners: move the QUIC infrastructure in `proxy/src/quic` into its own crate, preserving
  the transport and DNS users' dependency direction.
- Proxy owners: fold `udprelay::UdpCodec` into `dgram`.

`proxy/src/quic/congestion.rs` and `proxy/src/quic/socket.rs` already use `concord_common::sync::lock`.
mieru's and AmneziaWG's `invalid` add a protocol prefix and stay local.

Settled, not pending: `ss::crypto::CryptoIo` and `SsKey` stay in `ss`, because Trojan's `ss` option is the Shadowsocks
AEAD stream itself, not a general AEAD layer. The per-protocol counting nonces stay separate: mieru increments
big-endian (`proxy/src/mieru/cipher.rs`), Snell little-endian (`proxy/src/snell/frame.rs`), VMess writes a 16-bit
count over the first two IV bytes (`proxy/src/vmess/crypto.rs`), and REALITY XORs the TLS 1.3 sequence into the last
eight (`tls/src/reality/schedule.rs`); each follows its protocol, so one helper would need a mode per caller.
`net::relay`'s `Half` asks its streams for `tcp` and `direct` at each use rather than once per turn:
`PeekedStream::tcp` and `direct` (`common/src/stream.rs`) turn from `None` to `Some` once the replayed head has been
read inside the same `Half::poll` loop, and `RecordIo::tcp` (`tls/src/record.rs`) follows record alignment, so a
snapshot would hold back the switch to splice or direct I/O by a turn.

Found in the structure survey and left to their owners:

- `proxy/src/lazy.rs` spreads the deferred-header state across `HeadFirst`'s stage and `Kick`'s four states. Low
  priority: one state machine when the file next changes.

The tunnel first-byte window and sniff waits, h2io ping timeout and xhttp keepalive period are registered in
`reference-choices.md`. `tunnel::tcp::MeteredStream` forwards both owned reads and writes and meters their bytes.
