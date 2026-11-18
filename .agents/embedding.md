# Embedding

How a host runs Concord and talks to it. The methods and types are in `schema/api.json`; the behaviour a host relies on
beyond the signatures, and the test that holds each item, is in `behaviour-checklist.md`.

## As A Process (Desktop)

1. The host listens on a local endpoint: a Unix socket path, a Windows named pipe, or a loopback TCP port.
2. It starts `concord` with that endpoint as the only argument; an all-digit argument is a TCP port. No
   argument prints an error and exits 1.
3. It writes a 32-digit lowercase hex session token to the core's standard input. The token reaches the core only
   that way, never on the command line.
4. The core dials the host, and both ends prove they hold the token (`concord_ipc::initiate` on the core's
   side, `respond` on the host's).
5. They exchange length-prefixed JSON-RPC frames (little-endian length, 64 MiB limit) until the connection closes.
   Closing it stops the core.

## In-Process (Android)

`libconcord.so` holds one core per process and speaks only C; a host binds it to its own runtime, so the JNI
glue, its class names and attaching core threads to the JVM are the host's. `bins/android` exports:

| Function | Purpose |
|---|---|
| `concord_start(on_thread_start, context)` | Build the core, once per process; the hook runs on every runtime thread first (a JVM host attaches it there). Also ignores SIGPIPE, which a `cdylib` does not get from a Rust runtime |
| `concord_set_platform_host(host)` | Register the `ConcordPlatformHost` callbacks the core calls: `protect` for every outbound socket, and the uid and package behind a connection; null clears it. Android routes every socket of the VPN app into its VPN once it is established, sockets opened before then included, so a socket whose `protect` returns `false`, or that is opened while no host is set, is protected again when `tun.start` adopts the next VPN: set the host before it |

`concord-ffi` adds the sessions of the same JSON-RPC server:

| Function | Purpose |
|---|---|
| `concord_init_dart_api` | Initialise Dart's native API before the first Dart session |
| `concord_open(port)` | Open a session whose messages are posted to a Dart `ReceivePort` |
| `concord_open_callback(deliver, context, release)` | Open a session whose messages go to a C callback |
| `concord_send(session, data, len)` | Send one message |
| `concord_close(session)` | Close a session |
| `concord_adopt_fd(fd)` | Hand the core a TUN descriptor; returns the handle `tun.start` names as an `inherited` source |

Callbacks may run on any core thread; a `release` callback runs once the core lets go of its context. The doc comments
on the exported functions are the contract.

### Privileged TUN

A host that keeps the core in its unprivileged app process can still have a TUN device without Android's
`VpnService`: a root helper process loads the same `libconcord.so`, calls these without `concord_start`, and passes
the descriptor to the app, which hands it to the core with `concord_adopt_fd`.

| Function | Purpose |
|---|---|
| `concord_tun_provision(request, len, fd, error, capacity)` | Open a TUN device, give it the request's MTU and addresses and install sing-tun's Android policy routing (`route::plan_android`, plus an IPv6 rule for the unspecified source that sing-tun lacks there): routes in table 2022, rules from priority 9000, ahead of netd's. Local port 53 in both families, IPv6 included when the request has no IPv6 address, goes to table 2023, which holds only a default route to the device: system resolvers on the LAN or on IPv6 would otherwise miss a `routeAddress` that leaves private ranges out, and the core would never see the queries. sing-tun means the same with `not dport 53 lookup main suppress_prefixlength 0`, which it skips on Android: there each network routes from its own table, chosen by fwmark, and `main` is nearly empty, so a rule against `main` keeps nothing. Without an IPv6 address only IPv6 port 53 enters the device, as a `VpnService` takes every system query; sing-tun instead blocks IPv6 with `unreachable` under `strictRoute` and leaves it off the device otherwise. Writes the descriptor to `fd` and keeps no copy; returns a handle, or 0 with the reason in `error` as a NUL-terminated string cut to fit `capacity`. Rules a crashed run left in the priority range are removed first |
| `concord_tun_release(handle)` | Remove the routes and rules, then the device once no process holds it; returns how many steps failed, -1 for an unknown handle |
| `concord_tun_clean_stale()` | Remove the rules a provision left in the default priority range, and the routes in tables 2022 and 2023, when its process was killed before its release; returns how many, -1 on failure |
| `concord_socket_uid(protocol, source)` | The uid owning the local TCP (6) or UDP (17) socket at `host:port`, from sock_diag or `/proc/net`; -1 when none. Stands in for `getConnectionOwnerUid`, which answers only the VPN owner |

The request is camelCase JSON: `mtu`, `inet4Address` and optionally `device`, `inet6Address`, `routeAddress`,
`routeExcludeAddress`, `strictRoute`, `includeUid`, `excludeUid`, `includePackage`, `excludePackage`. Packages are
read from `/data/system/packages.list` and expanded to every user in `/data/user`, as sing-tun's `include-package`;
a request whose included packages are all missing is refused. Rules left by a killed helper are inert once the device is gone: the
tables they point to are empty, so lookups fall through to netd's rules. The exception is `strictRoute` with one address family
missing, whose `unreachable` rule for that family keeps blocking it until the next provision or `concord_tun_clean_stale`. The app's own uid belongs in `excludeUid`: its core's
sockets are not protected by a `VpnService`, so that rule is what keeps them off the device.

## Session

A host sends `core.hello` (version and capabilities) and `core.init` (its home directory, and the SDK level on Android),
applies a profile with `config.apply`, and opens listeners and TUN with `engine.start`. Streams (`traffic`,
`connection`, `log`, `dns`, `route`, `events`, `proxy`) are opened with a `*.watch` call and paced by the host's credit;
each declares one policy (`latest`, `drop_oldest`, `resync`) and never blocks core work. The `log` stream's lowest level
is `debug`: release builds of `concord` and `libconcord.so` compile out `trace` records, Concord's and its dependencies'
(`tracing` and `log` with `release_max_level_debug`), and other builds send them as `debug`. Engine state and the route
counters are the Core's; the host keeps no shadow copy.

## External Controller And State Sync

`config.patch` with `externalController` (and `secret`) opens the Clash REST API at that address through
`concord-controller`; an empty address closes it, and a change moves it, ending the sessions on the old address.
`externalControllerCors` (`allowOrigins`, `allowPrivateNetwork`) says which browser origins may call it; an absent
field takes mihomo's default (every origin, private network allowed), and `allowOrigins: []` refuses every
cross-origin request, which a profile cannot ask for. The profile's `external-controller`, `secret` and
`external-controller-cors` are ignored while a host drives the core (`host_owned_key` warning).

A dashboard may change what the host keeps: a group's pick (`PUT /proxies/:name`, `DELETE` to clear a fixed pick)
and the general settings `PATCH /configs` reaches (`mode`, `log-level`, `ipv6`, `allow-lan`, `mixed-port`,
`tcp-concurrent`, `find-process-mode`). It may not replace the profile (`PUT /configs` answers 405) or touch `tun`.
Every such change, from either side, is numbered by one counter in the engine in the order it took effect. A host
that lets a dashboard in keeps its own copy in step:

1. Open `events.watch` with `state: true`, then call `config.general`. Take its `selections` and settings as the
   current state and its `seq` as the last change they include; drop any `stateChanged` with a `seq` at or below it.
2. Apply every later `stateChanged` in order, whatever its `origin`: a `selected` sets or clears one pick, a
   `general` sets the fields it carries, an `applied` means a `config.apply` replaced the picks with its `selection`.
   Changes the host made itself come back too, with `origin: host`. A fallback group that drops a pick because
   its node died sends `selected` with an empty `proxy` and `origin: core`, once, as mihomo forgets such a pick.
3. On `Resync`, start again from step 1.
4. Build the next `config.apply` (`selection`) and `config.patch` from that copy; otherwise they undo the dashboard.

The latest change wins by `seq`, not by clock. `proxy.select` and `config.patch` answer with the `seq` of the change
they made (or the last one when they made none), so a host that shows its own change at once can ignore an older
event for the same pick or field that arrives after it.

What a host does not write back stays out of `stateChanged`: delays, provider updates, closed connections, the
fake-IP flush and geo updates. A provider a dashboard updates shows its new nodes on `proxy.watch` and the next
`proxy.groups`.

## Provider And Geo Updates

`events.watch` sends one `resourceUpdate` per step of every fetch of a proxy provider, a rule provider or a geo
database, whatever started it: a provider's first load, a retry after a failure, its interval, its file changing,
`provider.update`, `provider.sideLoad`, `geo.update`, the automatic geo update, a geo database a profile needs and
lacks, and the same requests from a dashboard. Each fetch is `updating`, then `updated` (the content in force
changed), `unchanged` (fetched, and the same), or `failed` with `error`. A geo database is named `MMDB`, `ASN` or
`GEOSITE`. Every step of a provider's first load waits until the `config.apply` that made it has finished, so a
host that reads `provider.list` on it finds the provider; on the connection it may still arrive just before that
apply's answer. A fetch cut short by a newer apply or by shutdown ends with `failed` and the error `superseded`, so
every `updating` has an end. There is no switch: these come hours apart, and none carries a `seq`, because a host
reads them again rather than writes them back.

A host that handled `providerLoaded` and `geoUpdate` moves to this one event: on `updated` or `unchanged` of a
provider it reads the provider again (its `updatedAt` and subscription numbers change on every fetch, not only the
first); a geo database's `updating` and outcome replace `geoUpdate`'s `updating` and `skipped`/`error`. The two old
events are gone, so the host change lands in the same commit as the core it embeds.

## Build-Time And Run-Time Settings

| Variable | When | Effect |
|---|---|---|
| `CONCORD_PRODUCT_NAME` | Build | The name end users see: the generated MITM CA's subject and organisation (`<name> CA XXXXXXXX`) and the Android TUN device. Default `Concord`. Read with `option_env!`, so changing it rebuilds |
| `CONCORD_DEBUG` | Run | Any value also writes errors to standard error |
| `BORING_BSSL_RUST_CPPLIB=c++_static` | Android build | Links BoringSSL against the NDK's static C++ runtime |
| `AWS_LC_SYS_NO_JITTER_ENTROPY` | Build | Workspace default `1` disables AWS-LC's optional CPU jitter entropy collector; `0` restores the dependency default |

An executable that links `c++_static` on Android also needs `-C link-arg=-lc++abi`.

Workspace builds use non-FIPS `aws-lc-sys`. Its OS entropy path avoids jitter collector initialization on the
process's first random request, including the first TLS connection. This setting affects every AWS-LC caller;
BoringSSL is separate. The DRBG is still seeded by the operating system and uses hardware randomness for
personalization when available. Without it, the extra input also comes from the OS, so upstream's two independent
entropy sources are no longer guaranteed. This is an entropy-source policy choice, not a FIPS configuration.
