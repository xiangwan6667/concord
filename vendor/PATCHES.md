# Vendored crates

Each crate here is the crates.io release named below with the listed changes, wired in through `[patch.crates-io]` in
the workspace `Cargo.toml`. Every source change carries a `Concord:` comment. To upgrade, unpack the new release, replay
the changes below, and compare against the registry copy:

```sh
diff -r ~/.cargo/registry/src/index.crates.io-*/shadowsocks-1.25.0 vendor/shadowsocks
```

A change to a vendored crate adds its entry here in the same commit. Each bullet that opens with backticked paths
lists files that differ from the release, a path relative to the crate, a trailing part of the bullet's first path, or
a directory ending in `/`. `vendor/UPSTREAM.sha256` holds the SHA-256 of every file in each pinned package as cargo
unpacks it, and xtask's `vendor_patches` test (part of `cargo test --workspace`) fails when a file differs without a
bullet or a bullet names a file that does not differ. An upgrade regenerates the manifest from the new release:

```sh
cd ~/.cargo/registry/src/index.crates.io-*/shadowsocks-1.25.0 &&
  find . -type f ! -name .cargo-ok | LC_ALL=C sort | xargs shasum -a 256 | sed 's#  \./#  shadowsocks/#'
```

### Upstream route

Each change below should reach its upstream, so the vendored copy can go, unless its row says otherwise. A row's
status is what this file records; check the tracker before acting on it. When upstream releases the change: drop the
crate's directory, its `[patch.crates-io]` entry and its lines in `UPSTREAM.sha256`, and the section below.

| Crate | Change | Upstream | Route |
|---|---|---|---|
| blake3 | Byte-string key-derivation contexts | None | Propose the byte-slice counterpart of `hash_derive_key_context` to BLAKE3-team/BLAKE3 |
| boring | Read-only `SslRef` record-layer accessors | None | None planned: the change stays in the vendored copy |
| h2 | Ignore DATA and HEADERS on forgotten client streams | None as of 0.4.20 | Issue and PR to hyperium/h2 with the delayed-DATA-after-reset transport test |
| mio | High-resolution timed waits on Windows | None | PR to tokio-rs/mio, citing Go's default poller path |
| quinn | `MAX_TRANSMIT_DATAGRAMS` 80 (`MAX_TRANSMIT_SEGMENTS` back to upstream's 10) | n0-computer/noq#636 (noq) | The segment cap is upstream's again; propose only the datagram limit to quinn-rs/quinn |
| quinn | Stamp each received batch with its own read time | None; quinn `main` `8fe66c3` passes one `now` | PR with `crates/proxy/tests/quinn_recv_time.rs` as the regression |
| quinn-proto | `send_quantum`, `on_packet_lost`, `min_pacing_delay` and explicit-rate pacing | quinn-rs/quinn#2481; merged as noq#611 | Follow #2481. `min_pacing_delay` is Concord's own addition and needs its own proposal; the pacer changes cannot move into `proxy/src/quic/congestion.rs` while the controller API lacks these hooks |
| quinn-proto | Requeue unacknowledged STREAM data on a PTO; withdraw acknowledged copies | None; quinn `main` `765abecf` requeues only control frames | PR with the recovery contracts of `crates/proxy/tests/quinn_pto.rs` |
| quinn-proto | A DATAGRAM-only packet does not bundle a pending ACK | None | PR citing quic-go's default path and the `quinn_pto.rs` ACK contracts |
| rustls | Check that a buffered client can be exported to the record engine | None | PR adding the eligibility check next to rustls's kernel-TLS export |
| shadowsocks | Zero the AEAD-2022 request padding | None | Small bug-fix PR first: the padding was uninitialized memory |
| shadowsocks | Send the first write over as many chunks as it needs | None | Bug-fix PR |
| shadowsocks | AEAD-2022 padding of 1 to 900 bytes under 900-byte payloads | None | PR citing sing-shadowsocks |
| shadowsocks | `set_clock`; split halves; owned in-place writes | None | Last, as one design discussion: the largest and most Concord-specific |
| tun-rs | `AsyncDevice::into_sync` keeps the owned device | None | PR to tun-rs |

## blake3 1.8.7

- `src/hazmat.rs`: expose `hash_derive_key_context_bytes` beside its string counterpart. VLESS Encryption derives keys from binary IVs and handshake records, as the Go BLAKE3 API permits. Both APIs share the existing hash implementation.

## boring 5.4.0

The package archive checksum is `7227623e47342428b893b9401d85cae09c4656aecaae524206652e8f6a6246c4`.

- `src/ssl/mod.rs`: `SslRef` gains `has_pending`, `read_sequence`, `write_sequence`, `shutdown_state` and
  `key_block`, read-only wrappers over `SSL_has_pending`, `SSL_get_read_sequence`, `SSL_get_write_sequence`,
  `SSL_get_shutdown`, and `SSL_get_key_block_len` with `SSL_generate_key_block`. `concord-tls` reads them once per
  connection, when a finished BoringSSL handshake hands its keys and sequence numbers to the directional record layer
  (`crates/tls/src/boring_backend.rs` `record_state`). The release wraps none of them on `SslRef` (`get_shutdown` is
  on `SslStream` and takes `&mut self`), so tls otherwise needs `boring-sys` and `unsafe`. No upstream PR is planned.

## h2 0.4.20

The package archive checksum is `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118`.

- `src/proto/streams/streams.rs`: a client ignores HEADERS, and refunds and ignores DATA, on forgotten streams it
  initiated, matching the pinned Go HTTP/2 client's cancellation handling. The bounded reset history can discard a
  canceled stream before its in-flight response DATA arrives; turning that DATA into new protocol-error resets
  otherwise exhausts the connection's local-error budget. Future stream IDs and the server path retain their
  errors. Ignored non-final DATA retains the existing framing guard and releases its accounting immediately, since
  no payload is buffered. Reset limits, flow-control limits and empty non-final DATA limits are unchanged.
  Workspace transport tests cover delayed DATA after cancellation beyond the reset-history bound, connection
  flow-control refunds, connection reuse, unsolicited DATA and the empty-frame guard. Upstream h2 has no
  equivalent as of 0.4.20.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

## mio 1.2.4

- `Cargo.lock`: registry lockfile omitted; the workspace uses its root lockfile.
- `src/sys/windows/hires_timer.rs`, `selector.rs`, `mod.rs`, `overlapped.rs`, `Cargo.toml`: a timed `select` arms a
  high-resolution waitable timer and associates it with the completion port through `NtAssociateWaitCompletionPacket`,
  so the wait ends at its deadline instead of on the system tick that `GetQueuedCompletionStatusEx`'s own timeout
  follows. This is the default path of Go 1.27.3's poller (`reference-choices.md`, Reference by area): `netpoll`
  queues the timer for any positive delay (`runtime/netpoll_windows.go:167-174`) and keeps its millisecond timeout
  on the call as the bound (`:182-197`); `netpollQueueTimer` cancels, sets and associates (`:251`, `:259`, `:264`);
  each M gets the timer and packet whenever `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` and
  `NtCreateWaitCompletionPacket` exist (`runtime/os_windows.go:871-878`), and `timeBeginPeriod` is only the
  fallback without them (`osRelax`, `:380-386`). One timer per selector suffices because one thread polls at a time.
  The packet carries an odd key and an `Overlapped` whose callback adds no event, so it only ends the wait and never
  reaches the caller as a token. Re-arming first cancels the previous association with
  `NtCancelWaitCompletionPacket(.., TRUE)`, which also drops a packet already queued for it; only when that cancel
  returns `STATUS_PENDING` (the packet is being delivered) can a late packet end a later wait early, with no event,
  and the caller then sees an early timeout and waits again for its own deadline. An untimed wait cancels the
  association, so an idle poller is not woken; Go leaves it armed. Go also re-arms on every timed wait
  (`netpoll_windows.go:174`); here a wait whose deadline lies less than 1 ms after the armed one keeps the armed
  timer, since tokio rounds deadlines to whole milliseconds and a request-response loop waits on the same timer
  again and again. Re-arming every time cost 15-22% more client CPU per `udp-rr` transaction on the Windows VM
  (`clw_hrt_c2b` direct and ss-aes128, `clw_hrt_c1` hysteria2-brutal). Without the high-resolution flag (before Windows
  10 1803) the selector waits as the release does. `windows-link` declares the three ntdll calls, which
  `windows-sys` does not; `Overlapped::new` is built without `os-ext`.

## quinn 0.11.12

- `src/connection.rs`: `MAX_TRANSMIT_DATAGRAMS` 20 → 80, the value proposed in n0-computer/noq#636. A bulk sender
  yields, and wakes another tokio worker, a quarter as often (`8452ddc`). `MAX_TRANSMIT_SEGMENTS` stays at upstream's
  10: `8452ddc` raised it to 40 with #645, and a 40-datagram GSO packet cost the receiving Go server 30% more CPU per
  GB on a WAN upload than ten (`clq_hy2_wan_burst_1`); quic-go never coalesces more than its ten-packet pacer burst.
- `src/endpoint.rs`: `RecvState::poll_socket` stamps each received batch with the time it was read, instead of the
  one `now` that `EndpointDriver::poll` took when the driver woke. A receive cycle runs until the socket is drained
  or the work limiter stops it, while connection tasks keep sending on other threads; an ACK for such a packet,
  read later in the same cycle, carried a time before the packet was sent, so the RTT sample saturated to zero,
  `min_rtt` stayed zero and BBR's delivery-rate samples grew without bound (Windows: every bulk connection of
  `clw_stats_1`). Upstream `main` (`8fe66c3`) still passes one `now` through `drive_recv` and `poll_socket`.
  quic-go stamps every packet as it reads it (sing-box quic-go `v0.61.0-sing-box-mod.12` `sys_conn.go:154`,
  `:194`, `sys_conn_oob.go:406`); a batch here comes from one `recvmmsg` or `WSARecvMsg` call, so stamping per
  batch is the same up to the call's own duration. Contract: `crates/proxy/tests/quinn_recv_time.rs`.
- `Cargo.toml`, `benches/`, `examples/`, `tests/`: the `[[example]]`, `[[test]]` and `[[bench]]` targets are removed
  with their sources.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

`quinn-udp` is not vendored; an upgrade moves all three crates together.

## quinn-proto 0.11.19

The package archive checksum is the original Cargo.lock checksum
`0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`.

- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

- `src/congestion.rs`: optional `send_quantum` and `on_packet_lost` follow the API proposed in
  [quinn#2481](https://github.com/quinn-rs/quinn/pull/2481) (head `01b8848d`) and merged in
  [noq#611](https://github.com/n0-computer/noq/pull/611) (`0ac6b462`). An additional optional
  `min_pacing_delay` preserves fixed-rate controllers' timer granularity. `pacing_rate` keeps Quinn's bits/s
  units; supplying a send quantum opts in, so existing diagnostic rates do not activate pacing.
- `src/connection/pacing.rs`, `src/connection/mod.rs`, `src/connection/packet_builder.rs`: an opted-in controller
  supplies the rate and burst separately from its window. Other controllers retain the original pacer. The
  rate budget charges actual packet lengths, including ACK-only packets, while the native budget still charges
  congestion-controlled bytes. Pacing inputs are sampled once per outgoing batch before ACK-only sends can
  bypass admission; the per-datagram congestion window remains current. Loss callbacks count ack-eliciting packets,
  excluding ECN and MTU probes.
- `src/connection/pacing.rs`, `src/connection/mod.rs`: on an explicit-rate deficit, schedule a refill using Quinn's
  existing 2ms burst interval, leaving the controller's minimum-delay worth of headroom for timer overshoot and
  reserving exact pending packet bytes. Existing credit still admits immediately; native pacing is unchanged.
- `src/congestion/cubic.rs`, `src/congestion/new_reno.rs`, `src/congestion/bbr/mod.rs`: default the optional pacing
  inputs to unset.
- Pacer unit tests run through `crates/proxy/tests/quinn_pacing.rs`, which includes the vendored source so the
  workspace gate executes the tests without a separate target or dependency graph. Late-wake tests check H2/SQ's
  rate headroom and H1's unchanged reference minimum-wait deadline, including its packet-remainder clipping.
- Admission and refill subtract the exact buffered packet reservation before applying the quantum bound;
  a one-MTU quantum test checks that the buffered packet cannot lend that credit to the next packet.
- A repeated budget-query regression test checks that unsent fractional credit is not lost between polls.
  Explicit pacing caches its current rate and computes budget from the last actual send, as the reference
  pacer's `Budget`/`SentPacket` pair does; polling cannot consume fractional elapsed credit. Native accounting
  and refill arithmetic remain unchanged.
  Explicit credit and its minimum-delay floor share one last-send timestamp, avoiding duplicate connection state.
  The H1 deadline comparison maintains an independent reference budget and last-send time.
- A buffered-packet regression test covers the minimum-delay anchor at cold start and on an early H1 poll.
  A reserved packet is finalized at the current transmit time before the connection returns, so it also
  anchors the next scheduled minimum delay. No timer value, capacity or native arithmetic changes.

- `src/connection/mod.rs`, `src/connection/spaces.rs`, `src/connection/streams/state.rs`: when a PTO has no new
  STREAM data, queue the oldest packet's still-unacknowledged STREAM ranges through the existing stream retransmit
  scheduler. Original STREAM/FIN metadata remains available for ACKs; PTO does not report congestion loss. New
  stream data and the existing control-only recovery path retain priority and behaviour.
- `src/connection/send_buffer.rs`, `src/connection/streams/send.rs`: an ACK withdraws queued copies of its bytes/FIN;
  later retransmit requests clip the discarded prefix and exclude selectively ACKed ranges. Empty/reset/closed
  scheduler entries cannot resurrect data or FIN after an original or probe copy was acknowledged.
- Recovery contracts in `crates/proxy/tests/quinn_pto.rs` run real QUIC endpoints on a virtual link, including
  delivery before any new ACK, both ACK orders, pending-probe cancellation, repeated probes, FIN/reset, exhausted
  flow credit, new-data priority and control-only probes.
- `src/connection/mod.rs`: a 1-RTT packet that carries DATAGRAM frames and nothing else no longer bundles a pending
  ACK at the end of `populate_packet`; it carries one only when an ACK is already due (`PendingAcks::can_send`, the
  ACK branch at the top of the packet), and otherwise the `MaxAckDelay` timer sends it alone. A datagram exchange
  then acknowledges every second ack-eliciting packet instead of every one. This is the default path of sing-box's
  quic-go `v0.61.0-sing-box-mod.12` (`reference-choices.md`, Reference by area): `packet_packer.go:724-729` asks
  for an ACK only if queued unless the packet has stream data, control frames or retransmissions; `framer.go:62-71`
  counts stream data, control frames and PATH_RESPONSE, not DATAGRAM; `received_packet_tracker.go:79`, `:187` and
  `:209-213` queue an ACK every second ack-eliciting packet or when the ACK alarm fires. Quinn's own immediate
  threshold is the same two packets (`spaces.rs` `ack_eliciting_threshold` 1). Only a packet whose payload is
  wholly DATAGRAM frames changes: PING, IMMEDIATE_ACK, PATH_CHALLENGE, PATH_RESPONSE, NEW_TOKEN, STREAM and every
  retransmitted frame keep the bundling, as quic-go's control frames and path responses do. Quinn bundled an ACK
  into the next packet after every ack-eliciting one, so a request-response over datagrams gave the peer one ACK
  per small packet; on the Windows VM mihomo's BBR server then sampled about 75 KB/s and paced `udp-rr` replies at
  1.5 ms after a bulk transfer (`clw_rrack_2`, Go 0.21 ms). Contracts in `crates/proxy/tests/quinn_pto.rs`: every
  second datagram reply carries the ACK, a lone one waits for the ACK delay, and a STREAM reply still carries it.

Upstream comparison: [quinn main `765abecf`](https://github.com/quinn-rs/quinn/blob/765abecf7b5e18e5eeb8aa46e30e2174c54547d7/quinn-proto/src/connection/spaces.rs)
still queues only control retransmits in `maybe_queue_probe`, with no equivalent STREAM requeue or ACK-copy
bookkeeping. The independent upstream DATAGRAM-ready guard is outside this patch.

Upgrade `quinn`, `quinn-proto` and `quinn-udp` together; replay these changes and the quinn changes above.

## rustls 0.23.46

- `src/conn.rs`, `src/client/client_conn.rs`, `src/common_state.rs`: a checked buffered-client handoff to the
  existing kernel connection export. It refuses retained ciphertext/plaintext, partial handshake messages, pending
  output, a queued KeyUpdate answer or a pending key refresh, errors and close state; successful export keeps
  traffic sequences and the KeyUpdate schedule. The caller can check eligibility without consuming the connection
  and retain upstream I/O when it is not quiescent.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

## shadowsocks 1.25.0

- `src/relay/tcprelay/crypto_io.rs`, `proxy_stream/client.rs`, `proxy_stream/mod.rs`: split cipher and client
  streams over independently owned transport halves. The reader preserves response authentication and the sent
  request nonce; the writer retains its handshake and cipher state. Mutable transport access lets ciphertext
  already accepted from a caller-owned buffer drain before a subsequent encrypted write after splitting.
- `src/relay/tcprelay/aead.rs`, `aead_2022.rs`, `crypto_io.rs`, `proxy_stream/client.rs`: an opt-in owned write.
  Once a writer's startup bytes have drained (the classic AEAD salt and address; the AEAD-2022 authenticated header
  and EIH), `EncryptedWriter::encrypt_in_place` seals one normal record in caller-owned length/payload/tag space.
  `crypto_io::seal_owned_record` frames the record for both families; each writer passes its own payload limit
  (`0x3FFF`, `0xFFFF`) and its cipher, which advances the record nonces. `CryptoStream` dispatches the hook to the
  active writer. Pending ciphertext remains the caller's responsibility; stream ciphers, request construction,
  padding and all readers keep their original paths.
- `src/relay/mod.rs`: an AEAD-2022 request header whose payload is under 900 bytes gets 1 to 900 bytes of padding, as
  sing-shadowsocks sends; upstream padded only an empty payload, by 0 to 900 (`f53191e`).
- `src/relay/tcprelay/proxy_stream/client.rs`:
  - the padding is zeroed instead of left as uninitialized memory (`f53191e`);
  - the first write, which carries the address, goes out over as many `poll_write_encrypted` calls as it needs, since
    each seals at most one chunk (`8f40a78`).
- `src/relay/tcprelay/aead_2022.rs`, `src/relay/tcprelay/mod.rs`: `set_clock` replaces the system clock for AEAD-2022
  timestamps; `concord-proxy` points it at the engine's NTP-corrected clock (`f53191e`).
- `Cargo.toml`, `tests/`: the `[[test]]` targets, their sources and the `env_logger` dev-dependency are removed.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

## tun-rs 2.8.16

- `Cargo.lock`: registry lockfile omitted; the workspace uses its root lockfile.

- `src/async_device/unix/mod.rs`: `AsyncDevice::into_sync` returns the existing owned device after reactor deregistration, preserving its FD, queued packets and VNET/offload state. TUN queue owners use it with `AsyncDevice::new` to register on their runtime; raw-fd adoption rejects VNET descriptors.

