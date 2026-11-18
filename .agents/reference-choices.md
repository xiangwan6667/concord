# Reference Choices

What mature implementations chose for the tuning values and the architecture Concord also has to choose, so a
change starts from them instead of searching again (`rules.md`, "Behaviour Against mihomo"). Each row names the
reference file, path relative to its repository or Go module. Values are pinned to the versions below; re-read the
reference before relying on a value in a change, and update the row in the same commit when a reference or Concord
moves.

## Entry Shape

Every entry under "Deviations To Resolve", "Matching The References" and "Deliberate Differences" states its kind:
`runtime-bound` when the reference chose it for a reason specific to Go's runtime (sing-tun starting a goroutine per
SYN and yielding once per burst), `language-neutral` otherwise (sing-box's interface table, cached and refreshed by
a monitor). A table row carries it in its `Kind` column; a bullet starts with `[language-neutral]` or
`[runtime-bound]`. Each entry cites `file:line`, `file::symbol` or `` `file` (`symbol`) `` in a reference listed
under References and names that reference. A deviation names its owner; a language-neutral deliberate difference
states its measurement in its Measurement column as a sentence that names the platform it ran on and gives the
figures, or, when it changes behaviour and not cost, says `None (behaviour, no performance effect)` there and names
the test that holds the behaviour in its reason. Evidence is described, never cited by a run name or a Concord
commit. xtask's
`reference_choices` test checks this shape.

## References

- mihomo `v1.19.33` (`3f27ef39`), the bench's Go client. Its protocol libraries are the versions pinned in its
  `go.mod`: `metacubex/sing v0.5.8`, `sing-shadowsocks2 v0.2.8`, `sing-vmess v0.2.5`, `sing-mux v0.3.12`,
  `smux 20260105030934`, `yamux 20250918083631`, `sing-quic 20260904234848`, `quic-go v0.61.1-0.20260727080200`,
  `sing-tun v0.4.28`, `wireguard-go 20250820062549`; mieru from `enfein/mieru/v3 v3.38.1`.
- mihomo `v1.19.34` (`0455d0d2`), the peer CI fetches (`.github/actions/mihomo`) for the interop job and the
  bench smoke: the first release with the Snell v6 listener (`f1f640b1`). Measurements keep `v1.19.33`.
- mihomo Alpha `3c0d10a5`, Snell v6 wire/profile and adapter validation (`f1f640b1`, `d569d9eb`).
- mihomo Alpha `3c0d10a5`, the reference for TCP JLS (`transport/jls/` and `adapter/outbound/jls.go`).
- mihomo Alpha `3c0d10a5`, the xhttp HTTP/3 reference (`transport/xhttp/client.go`).
- sing-box `v1.15.0-alpha.13` (`824dbcf`), the TUN reference (`performance.md`), with the versions its `go.mod` pins:
  sing-tun `611d83b7`, sing `v0.9.7-0.20261023115510` (`03a6cce6`), sing-anytls `580984e4`.
- shadowsocks-rust `v1.25.0` (`ab388c7466d21f979430e33cc9ef10e22fb05955`), the Tokio TCP reference. Its original lock
  uses Tokio 1.53.1 and aws-lc-rs 1.18.0; the source build keeps the upstream full features and release profile.
- Go 1.27.3, the toolchain of the reference builds; Rust 1.100.0 (`rust-toolchain.toml`) and Tokio 1.54.1
  (`Cargo.lock`), Concord's own; Linux v7.0.
- A clean mihomo source archive and the sing-box build provenance are kept with the bench reference builds.

### Reference by area

Read the path a reference takes by default; a fallback or an optional variant in the same tree is not its choice.
Where mihomo and sing-box differ on tuning, architecture or I/O, sing-box leads; wire and configuration behaviour
follow mihomo (`rules.md`, "Behaviour Against mihomo"). Compare at the same position: where Concord's host supplies
something, read the reference's path for a host that supplies it.

| Area | Reference to read | Default path, not to be confused with |
|---|---|---|
| TUN stack | sing-box's sing-tun Go stack: `stack.go` (`""` and `"go"` select `NewGo`), `stack_go*.go`, `gtcpip/` | gVisor, `system` and `mixed` are optional stacks |
| Windows socket I/O and timers | Go runtime of the reference builds (Go 1.27.3): `runtime/netpoll_windows.go`, `runtime/os_windows.go`, `internal/poll/fd_windows.go` | `osRelax` returns early when a high-resolution waitable timer exists; `timeBeginPeriod` is only the fallback without one |
| TCP socket options | Go `net` (`tcpsock.go`, `sockopt_*.go`); neither reference sets TCP send or receive buffers | sing's `control.UDPSocketBuffer` applies to UDP only |
| UDP socket buffers | sing `common/control/socket_buffer*.go`, wireguard-go and quic-go's own buffer sizing | |
| QUIC transports (Hysteria2, TUIC) | sing-quic over sing-box's quic-go; mihomo's `metacubex` forks for its client | |
| Multiplexing (smux, yamux, h2mux) | sing-mux (`client_conn.go`, `client.go`); yamux follows hashicorp/yamux v0.1.2, the version sing-mux pins (`go.mod:6`), where mihomo's metacubex fork differs | |
| Shadowsocks, SS2022 | sing-shadowsocks2; shadowsocks-rust for the Tokio relay shape | |
| VMess, VLESS, Trojan, AnyTLS | sing-vmess, sing-box `protocol/vless` and `protocol/trojan`, sing-anytls | |
| gRPC, HTTP/2, WebSocket, XHTTP | mihomo `transport/gun`, `transport/vmess`, `transport/xhttp` for the wire; sing-box `transport/v2raygrpclite` and `transport/v2raywebsocket` for the Go implementation | sing-box `transport/v2raygrpc` is the optional google.golang.org/grpc build |
| Snell, mieru | mihomo `transport/snell`; `enfein/mieru/v3` `pkg/protocol` (`underlay_stream.go`, `session.go`) | |
| TLS records and fingerprints | Go `crypto/tls` (`conn.go`); `metacubex/utls` for client fingerprints and REALITY | |
| MASQUE | mihomo `3c0d10a5` `adapter/outbound/masque.go:51-78`, `transport/masque/masque.go:33-235`, `client_h2.go:27-138`, `l4proxy.go:82-116` | WARP H3/H2 CONNECT-IP and H3 L4 proxy |
| WireGuard | sing-box's wireguard-go (`device/`, `conn/`) | |
| Interface lookup and network-change monitoring | sing-box `route/network.go`: a dial binds through `AutoDetectInterfaceFunc` (`:342-366`), which reads the interface table (sing `common/control/bind_finder_default.go:113`, `ByAddr`) and the monitor's default interface (sing-tun `monitor_shared.go:115`); the table is refreshed only when the network monitor reports a change (`route/network.go:267-270`), a netlink subscription on Linux (sing-tun `monitor_linux.go:18`, `:65-70`). Where the host reports network changes (Android, `network_update`), sing-box's platform-interface path: `route/network.go:343-348`, `UsePlatformAutoDetectInterfaceControl` | mihomo's 20 s interface cache (`component/iface/iface.go:35`), cleared by its TUN monitor, is a fallback bound only; sing-box's standalone monitor is not the reference where the host reports changes |

## Measured Receive References

Linux arm64, kernel 7.0.0-42: three fresh rotating rounds, four download flows, 3 s windows after 1 s warmup,
upstream sslocal and clean mihomo clients against the bench's Go server.
TCP_NODELAY is enabled for sslocal to match Concord. Both implementations retain their ordinary release settings;
Tokio and crypto versions differ, so this compares whole implementations rather than isolating one copy operation.

| Reference | Read/write choice | Outcome |
|---|---|---|
| shadowsocks-rust classic AEAD | `crates/shadowsocks/src/relay/tcprelay/utils.rs::copy_encrypted_bidirectional`: two permanent 16383-byte buffers, one positive read then a complete write, no write-pending top-up or read-pending flush. Crypto reads the length and payload separately (`aead.rs`); the local service waits up to 500 ms for first payload (`crates/shadowsocks-service/src/local/utils.rs`). | Server bytes/data segment for AES128: 53.4/56.7/57.6 kB versus Go 54.3/55.1/55.5; ChaCha: 11.2/11.3/11.0 versus Go 54.2/54.1/54.8. AES passes the combined segment/non-data screen in 2/3 rounds (first non-data is 1.315 times Go); ChaCha passes 0/3. The TCP receive-state investigation stays open; read a mature Tokio/kernel mitigation before choosing another relay policy. |

## Deviations To Resolve

Each is a value, write pattern or structure Concord reasoned out where the references settled it differently.
Resolve by adopting the reference, or by arguing in the review entry why Concord's model changes the trade-off and
confirming it with a run.

| Area | Kind | Concord | References | Owner |
|---|---|---|---|---|
| Shadowsocks runt chunks | language-neutral | Relay uses pooled MTU-aware reads; established classic AEAD and normal AEAD-2022 writes seal a caller-owned frame in place. `Tail` still holds a short write until it fills a chunk or a flush (`crates/proxy/src/ss/chunk.rs`); startup, insufficient headroom and oversized writes retain that scalar path. | sing's classic and 2022 client `WriteBuffer` methods retain their startup path and then use sing-shadowsocks2 `internal/shadowio/writer.go::WriteBuffer`, which extends caller head/tag space and seals length and payload in place before transferring the owner. Copy reads use `N.NewReadWaitOptions` (`sing/common/bufio/copy.go`). | proxy and relay |
| Hysteria and ShadowQUIC Brutal | language-neutral | Retain the original 1.25-BDP controller and Quinn pacing while Hysteria2 alone adopts independent rate control | mihomo's Hysteria uses 1.5 BDP, 1252 bytes and a 2 ms bucket (`transport/hysteria/congestion/brutal.go:64-70`, `pacer.go:11-13`); ShadowQUIC uses 2 BDP, 1280 bytes and a 4 ms bucket (`transport/tuic/congestion_v2/brutal.go:14-15`, `:39`, `pacer.go:12`) | Hysteria pacing owner (remaining alignment) |
| TUN offload | language-neutral | Always tries Linux vnet offload (`crates/tun/src/vnet.rs`); only an explicit `tun.gso: false` there is reported as not applied | sing-box enables GSO on Linux without a platform interface, on the `""`, `go` or `gvisor` stack, only while the TUN MTU is below 49152 (`protocol/tun/inbound.go:129-134`), so the two differ only at an MTU of 49152 or more. mihomo leaves GSO off by default. | TUN owner |
| Interface monitor on macOS and Windows | language-neutral | No monitor: the interface `Tables` are dropped on the host's network change and on `set_excluded_interfaces`, and otherwise read again after 20 s (`crates/platform/src/netinfo/tables.rs`) | sing-tun `611d83b7` re-reads on every change it is told of: a route socket on macOS (`monitor_darwin.go:66`), route and interface change callbacks on Windows (`monitor_windows.go:40-46`) | TUN owner |
| Stored fake-ip pool size | language-neutral | A pool with `store-fake-ip` keeps at most 65536 mappings in memory (`crates/dns/src/fakeip.rs:12-14`) and writes the whole pool as one snapshot on every change, so a v6 range cannot grow without bound | mihomo ignores the pool size once persistence is on and keeps one bbolt record per address handed out, bounded only by the range (`component/fakeip/pool.go:160-166`, `component/profile/cachefile/fakeip.go:70-100`); the store lives on disk, Concord's in memory | dns owner: argue the in-memory model with a run of a large stored v6 pool, or adopt a disk store |
| WireGuard send batches | language-neutral | Sends up to `UDP_BATCH` queued WireGuard datagrams per `sendmmsg` on Linux and Android, through gotatun's `send_many_to` (`crates/proxy/src/wireguard/transport.rs` (`WireSend`)); other targets, Amnezia and a session carrier send one per call | sing-box's `ClientBind` reports `BatchSize` 1 (sing-box `v1.15.0-alpha.13` wireguard-go `conn`), so every datagram is one `sendto`; unmeasured, owed one upload run | WireGuard owner |
| MaxMind database on Windows | language-neutral | Maps the GEOIP and ASN databases read-only on unix (`crates/platform/src/mmap.rs` (`MappedFile`)) and reads them onto the heap on Windows, which refuses to replace a file that has a mapped view while the updater renames the download over it before it reloads | mihomo maps the file on unix and Windows through `maxminddb.Open` (`component/mmdb/mmdb.go:47`, `:58`, `:80`; `oschwald/maxminddb-golang` v1.12.0 `reader_mmap.go:16`) and closes the reader before it replaces the file; the Windows heap copy is unmeasured | Rules owner |

## To Verify

| Area | Concord | What to read |
|---|---|---|
| VMess UDP size | Rejects a datagram above 15000 bytes (`crates/proxy/src/vmess/mod.rs:171`) | how sing-vmess packet writes treat a datagram larger than one chunk |
| TLS record sizing | rustls defaults | Go `crypto/tls` caps records at 16384 with dynamic record sizing (`metacubex/tls/conn.go`, `maxPayloadSizeForWrite`) |
| TLS split ownership | rustls runs on the native record engine from the end of the handshake, so a split only hands each half its direction. BoringSSL keeps its own object; a quiescent split exports keys and the post-handshake schedule into owned directions, and late or buffered splits retain the upstream object. | Tokio TCP owned halves and rustls 0.23.46 kernel export; the buffered-client vendor hook checks pending input/output, fragmented handshake and close state. Native record high-state debt stays Open. |
| XHTTP message size | 32 KiB scalar chunks | mihomo `transport/xhttp` |
| SSH | no window or packet constants of its own | `metacubex/ssh` channel window and maximum packet |

## Matching The References

Concord already takes these from the references; keep them unless the reference moves.

- [language-neutral] **What a stop sends** follows sing-box `824dbcf`: an outbound's close cancels its context
  and runs its cleanups (`adapter/lifecycle.go:128-142`); TUIC closes its QUIC connection with
  CONNECTION_CLOSE (`protocol/tuic/outbound.go:164-171`) and SSH closes the TCP connection without
  SSH_MSG_DISCONNECT (`protocol/ssh/outbound.go:263-270`). mihomo Alpha `3c0d10a5` closes no outbound on shutdown
  (`hub/executor/executor.go:532-538`). Concord's engine stop cancels every teardown that only tells a peer
  goodbye (an SSH disconnect, a sing-mux close, a queued control frame) and keeps only a QUIC connection's
  CONNECTION_CLOSE and its drain; `proxy::quic::tests::a_stop_sends_connection_close_and_the_drivers_end_with_the_connection`
  holds it.

- [language-neutral] **Proxy group/provider name collisions** follow mihomo `v1.19.33` (`3f27ef39`)
  `adapter/outboundgroup/parser.go:155-163`: reject a provider with the group's name only when the group's
  `proxies` list is nonempty; a provider-only group may share a provider's name.

- [language-neutral] **DoH connection concurrency** follows mihomo `v1.19.33`
  `dns/doh.go:388-397`: its HTTP transport leaves `MaxConnsPerHost` unset. The pinned
  metacubex/http `v0.1.8` starts an independent dial whenever no idle connection is available
  (`transport.go:1539-1542`, `:1587-1625`); the idle HTTP/1 limit of two is not an active connection
  limit (`:209-219`). Concord likewise lets cold queries dial concurrently, including before TLS
  has selected HTTP/1 or HTTP/2. Established HTTP/2 senders remain shared; simultaneous HTTP/2
  handshakes keep the first live cached sender and drop redundant ones, as metacubex/http does
  in `h2_bundle.go:882-911`. The independent-dial and established-sender behaviours are held by
  `concurrent_http1_queries_keep_independent_senders` and
  `concurrent_queries_reuse_an_established_http2_connection` in the DNS tests.

- [runtime-bound] **QUIC receive scratch** follows the polling lifetime. mihomo Alpha `3c0d10a5` pins
  metacubex/quic-go `2548683b76f4`, whose `buffer_pool.go:33-95` returns packet buffers to `sync.Pool` and
  `sys_conn_oob.go:161-178` borrows buffers for a receive batch. Quinn already copies received bytes into owned
  packets before dispatch. Concord leases the unchanged full batch/GRO scratch from one cache per polling OS
  thread; endpoints retain only the required length. Rust's deterministic drop returns it on every poll exit,
  without Go's garbage-collector-dependent pool lifetime or per-endpoint closing-period storage.

- [language-neutral] **TCP JLS authentication** follows mihomo Alpha `3c0d10a5`
  `transport/jls/utls.go:243-334`: AES-256-GCM authenticates each full TLS 1.3 Hello with its
  32-byte random zeroed, using SHA-256(password || Hello) as key and SHA-256(username || Hello)
  as the 32-byte nonce. The seed is 16 random bytes. Session tickets are disabled; the
  authenticated server still proves possession of its certificate key. Unauthenticated fallback
  validates the ordinary chain and hostname regardless of the node's skip-cert-verify, then sends
  one HTTP request synchronously for an explicit fingerprint (`transport/jls/utls.go:44-115,120-158,169-208`). Its padding
  cookie contains 30 through 61 zeroes, without the REALITY spider's delayed lifetime. Native
  JLS sends no HTTP fallback (`transport/jls/jls.go:102-117`). Its Hello matches the AES-capable
  jls-tls `67adc0e2f796` defaults (`handshake_client.go:58-151`, `handshake_messages.go:104-309`),
  including the TLS 1.2 offer, signature-algorithms-cert and hybrid/P-curve group ordering.
- [language-neutral] **XHTTP over HTTP/3** uses the same request factory, packet ordering, streaming modes
  and XMUX policy as HTTP/1.1 and HTTP/2. Like mihomo Alpha `3c0d10a5`
  `transport/xhttp/client.go:27,30,158-176`, an ALPN list containing only `h3` selects QUIC, forbids
  server-initiated bidirectional streams, keeps an idle connection for 300 seconds and sends keepalives
  every 10 seconds unless overridden or disabled, capped at half the local idle timeout.
  quic-go uses half the negotiated timeout (`connection.go:2432-2436`); Quinn has no public
  negotiated-timeout getter or keepalive setter, so shorter peer timeouts remain a compatibility limit. TLS is mandatory; additional security modes are
  rejected (`adapter/outbound/vless.go:676-708`). `download-settings` selects its own HTTP version
  and connection settings (`adapter/outbound/vless.go:867-903`).

- [language-neutral] **MASQUE transport and identity defaults** follow mihomo's MTU 1280, QUIC
  initial packet 1242, keepalive 30 s and 20-byte CID (`adapter/outbound/masque.go:208-219`, `:267-275`).
  The certificate lasts one day with serial zero (`transport/masque/masque.go:96-100`). BBR CWND defaults
  to 32 (`transport/tuic/common/congestion.go:17-18`); Cubic/Reno and BBR v2 count the actual initial packet
  size (`transport/tuic/congestion/cubic_sender.go:62-71`, `congestion_v2/bbr_sender.go:303-308`), while
  legacy BBR v1 counts InitialMaxDatagramSize (`transport/tuic/common/congestion.go:33-49`). H2 caps the
  response header list at 10 MiB (`metacubex/http` 0.1.8 `h2_bundle.go:7513-7522`). Empty User-Agent is
  omitted on both IP transports; L4 sends quic-go HTTP/3's default agent and gzip advertisement
  (`quic-go` `http3/request_writer.go:174-208`, `http3/client.go:32`); H2 also advertises gzip by default
  (`metacubex/http` 0.1.8 `internal/httpcommon/httpcommon.go:417-433`). H3 sends only the 10 MiB field limit
  and, for IP, the two datagram settings, without grease or disabled extensions (`quic-go`
  `http3/client.go:33`, `http3/frames.go:263-296`).
  QUIC advertises max_datagram_frame_size 16383 (`quic-go` `internal/wire/datagram_frame.go:14`).

- [language-neutral] **Gun HTTP/2 receive limits** are Go's HTTP/2 client defaults, which both references run for gun:
  mihomo `3f27ef39` through `metacubex/http` 0.1.8 (`h2_bundle.go:7358`, `:7363`, `:3555`), sing-box
  `transport/v2raygrpclite` through `x/net/http2`. A 4 MiB stream window, 1 GiB of connection credit on top of the
  initial 65535 bytes, 1 MiB maximum frame payload and a 10 MiB header list. Gun reserves 16 bytes of writer headroom
  like `GunConn.FrontHeadroom`. The owned path prepends its gRPC and protobuf header and hands the storage to h2; h2's
  codec and TLS can still copy.

- [language-neutral] **Canceled HTTP/2 requests** follow the Go client mihomo pins, `processHeaders` and `processData`
  (`metacubex/http` 0.1.8 `h2_bundle.go:9637`, `:9965`): response HEADERS and DATA for forgotten local streams are
  ignored, with connection flow control refunded for DATA. The codec still updates HPACK state. Bounded reset history
  and protocol-error limits remain in force; ignored non-final DATA keeps the framing guard without buffering its
  payload.

- [runtime-bound] **Linux attached-socket writes**: sing-tun `611d83b7`, `stack_go_socket_unix.go` uses `MSG_DONTWAIT |
  MSG_NOSIGNAL`; `stack_go_splice.go::spliceFlushUpload` attempts I/O before waiting and arms writable interest only
  after blocking. A socket newly registered on a TUN queue's Tokio reactor has no cached readiness yet. Concord makes
  the same nonblocking attempt, then clears cached readiness through the owning reactor and parks after WouldBlock. Only
  the Tokio fallback needs a second attempt through its readiness API; the private owner clears on the first attempt.

- [runtime-bound] **DIRECT UDP on a TUN queue with its own poller** (a Linux queue, an Android `VpnService`
  descriptor): sing-tun `611d83b7` registers a spliced UDP flow's socket in
  its engine's own epoll for reads only (`stack_go_splice.go:617`, `stack_go_io_linux.go:227-229`), sends a round's
  datagrams once and counts what a full socket refuses as sent (`stack_go_splice.go::flushPacketUploads`). A DIRECT
  session whose replies the driver adopted does the same on its queue's poller: the socket is watched for reads only,
  a send goes straight to the descriptor, and what a full socket does not take is dropped and counted. A session
  nobody adopted, and every device without a queue poller, stays on Tokio's reactor.

- [language-neutral] **Relay copy buffers** use a pooled 32 KiB fallback, MTU sizing and writer front/rear headroom,
  with the owner returned after the write. mihomo `common/pool/buffer_standard.go` and sing
  `common/buf/buffer_standard.go` both choose 32 KiB; sing `common/network/thread.go::CalculateMTU` combines
  reader/writer MTU and reader overhead. A frame-aware reader can allocate after decoding its length and transfer the
  authenticated owner, as `sing-shadowsocks2/internal/shadowio/reader.go::readBuffer` and `WaitReadBuffer` do. Protocol
  implementations retain their framing and authentication state; scalar AsyncRead remains the default capability
  fallback.
- [runtime-bound] **Vectored TCP signal handling** on Linux/Android uses socket2's
  `send_vectored_with_flags(MSG_NOSIGNAL)`. Rust 1.100's scalar TCP write supplies the same flag
  (`library/std/src/sys/net/connection/socket/mod.rs:446`); its vectored path delegates to `writev` through
  `socket/unix.rs:376-377` and `sys/fd/unix.rs`. Per-call suppression preserves the scalar error behaviour without
  depending on the embedding host's signal disposition.

- [language-neutral] **AnyTLS writes** coalesce the frames of each accepted write into one TLS write group, with
  65535-byte wire payloads and the original 16-frame FIFO budget. Partial acceptance follows bounded mpsc capacity; a
  single task owns the transport. mihomo `transport/anytls/session/session.go` (`writeDataFrame`, `writeConn`) groups a
  whole `Stream.Write` to keep it contiguous against other streams and control frames. sing-box `824dbcf` pins
  `sing-anytls v0.0.0-20260928104022-580984e4d8cb`, whose `session.go` `writeData` also groups a write. A relay buffer
  with 7 bytes of headroom is framed in place and queued as it is, one frame a queue slot, as sing-anytls's `stream.go`
  `writeBufferLocked` does with its `FrontHeadroom`; one without, or over a frame, is copied as above.

- [language-neutral] **Shadowsocks** AEAD chunk 0x3FFF (`sing-shadowsocks2/shadowaead/protocol.go`); request header
  leaves with the first payload. **ShadowsocksR** auth_aes128 frame threshold `32 KiB − overhead` and random pad below
  1024 (`transport/ssr/protocol/auth_aes128_sha1.go`). **Snell** chunk 0x3FFF (`transport/snell/snell.go:26`).
- [language-neutral] **Shadowsocks write ownership** follows sing-shadowsocks2's `Writer.WriteBuffer`
  (`internal/shadowio/writer.go:76`): an established classic AEAD frame or normal AEAD-2022 record keeps its payload
  allocation through length and body sealing. The original cipher owns nonce progression; the client retains at most one
  pending ciphertext owner and drains it before accepting another write, flushing or closing. Readers, startup bytes and
  scalar fallbacks keep their existing implementation.
- [language-neutral] **VMess** chunk 15000 and padding up to 64 from sing-vmess, which mihomo's client uses
  (`sing-vmess/protocol.go`); header coalesced with the first chunk. **VLESS Vision** padding header 21, buffer limit
  8192 − 21 (`transport/vless/vision/padding.go`). **Trojan** UDP packet 8192 (`transport/trojan/trojan.go:19`).
- [language-neutral] **smux** frame 32 KiB, receive buffer 4 MiB; **sing-mux** 16 padded first frames, 5 s TCP timeout,
  minimum 8 streams (`padding.go:16`, `client.go:66-69`), h2mux idle 30 s; **yamux** message 64 KiB including header,
  keepalive 30 s.
- [language-neutral] **h2mux** client SETTINGS: maximum frame 32 KiB, sing-mux's `MaxReadFrameSize: buf.BufferSize`
  (`h2mux.go:180`; sing `common/buf/buffer_standard.go:6`), and the Go HTTP/2 client's windows, 4 MiB per stream and 1
  GiB on top of the initial 65535 per connection (x/net `v0.35.0` `http2/transport.go:43,48`, `config.go:103,108`). The
  server cuts every DATA frame at the advertised maximum (`http2/writesched.go:120-121`) and sing-shadowsocks2 writes
  each 16383-byte chunk separately (`internal/shadowio/writer.go:47-66`), so a 16 KiB frame costs the server two writes,
  one of them 10 bytes. Concord keeps h2's window-update threshold (half the window) rather than x/net's 4 KiB: it sends
  the server fewer frames.
- [language-neutral] **Brutal** uses independent rate/ACK-ratio pacing: Hysteria's window is 1.5 times the
  bandwidth-delay product, using the greater of latest and smoothed RTT; Hysteria2 and ShadowQUIC use twice the
  smoothed-RTT product (mihomo `transport/hysteria/congestion/brutal.go:64-70`, pinned sing-quic
  `hysteria2/congestion/brutal.go:18`, mihomo `transport/tuic/congestion_v2/brutal.go:14-15`). Their burst budgets are
  at least ten packets and respectively 2/4/4 ms of bandwidth, with a 1 ms scheduled minimum pacing delay. Loss uses
  actual packet counts in five one-second slots, at least 50 samples and an ACK-ratio floor of 0.8. Unknown RTT starts
  at 10240 bytes. H1/H2's fallback packet size is 1252; ShadowQUIC's is the pinned quic-go's `InitialPacketSize`, 1280.
  Hysteria2 replays the known Quinn path MTU when installing Brutal and seeds its window with the established RTT. Its
  actual wire bytes, including ACK-only packets, consume the independent rate budget. Hysteria and ShadowQUIC retain
  their original controller until their remaining alignment is resolved.
- [language-neutral] **Hysteria** stream/connection windows 15/64 MB, keepalive 10 s, hop interval 10 s
  (`adapter/outbound/hysteria.go:35-40`, `:188`). **Hysteria2** windows 8/20 MB, idle 30 s, keepalive 10 s, UDP MTU
  1197, hop interval 30 s, minimum 5 s (`sing-quic/hysteria2/protocol.go:8-11`, `adapter/outbound/hysteria2.go`).
  **TUIC** windows 15/64 MB, heartbeat 10 s, request timeout 8 s, UDP packet 1252, datagram frame 1400, CWND 32
  (`adapter/outbound/tuic.go:157-171`, `transport/tuic`). **ShadowQUIC** datagram frame 1400, 1024 streams, CWND 32,
  Brutal negotiation 10 s.
- [language-neutral] **mieru** MTU 1400, window 16–4096, send queue 1024, ACK delay 1 ms, retransmission check 10 ms,
  back-off 1.5 up to 10 s, heartbeat 5 s with 1 s jitter, initial RTO 2 s, stream padding at most 255
  (`mieru/v3/pkg/protocol/session.go:51-54`, `:82`, `pkg/congestion/rtt.go`).
- [language-neutral] **Tunnel and sockets** follow mihomo: UDP session timeout 60 s (`tunnel/tunnel.go:63`), dial
  timeout 5 s (`component/dialer/dialer.go:22`), TCP keepalive 15 s. **WireGuard** MTU 1408 (`adapter/outbound/wireguard.go`).
  **TUN** MTU 9000 (`listener/sing_tun/server.go`).

- [language-neutral] **Hysteria2 Brutal admission** makes sing-quic's check under Quinn's API. sing-quic admits a packet
  while the bytes in flight are at most the window (`hysteria2/congestion/brutal.go:69-70`, `CanSend`); Quinn reserves
  the next datagram before it sends, so the controller reports the reference window plus one current MTU and one byte,
  including the unknown-RTT fallback (`:73-76`), and admits exactly what sing-quic admits. Its pacer uses the
  independent rate and burst supplied through the opt-in metrics API (`vendor/PATCHES.md`); substituting the reference
  window factors into Quinn's default 1.25-window/RTT pacer would overrun the configured rate.

- [language-neutral] **Interface lookups for auto-detect** answer from one reading of the interfaces and the
  default route, read again only after a change. sing-box `824dbcf` binds a dial through `AutoDetectInterfaceFunc`
  (`route/network.go:342-366`): the destination is looked up in the cached `DefaultInterfaceFinder` (sing
  `03a6cce6`, `common/control/bind_finder_default.go:113-131`), else the monitor's default interface is taken
  (sing-tun `611d83b7`, `monitor_shared.go:115`); the table is re-read from the monitor's callback
  (`route/network.go:178`, `:267-270`), which watches the netlink link, address and route groups
  (`monitor_linux.go:18-22`). Concord's `netinfo::Cache` drops its `Tables` on those netlink groups, on
  `set_excluded_interfaces` and on the host's network change, and reads them again after 20 s at most, mihomo's
  bound for its interface table (`component/iface/iface.go:35`). `is_local_ip` and a configured `interface-name`
  answer from the same reading.

- [runtime-bound] **Runtime worker threads** are one per CPU the process may use, on every platform: Tokio's
  default (`tokio-1.54.1/src/loom/std/mod.rs:99`, `available_parallelism`) and what Go gives mihomo and sing-box
  at start (Go 1.27.3 `runtime/proc.go:947`, `defaultGOMAXPROCS(numCPUStartup)`: the affinity mask, `os_linux.go:101`,
  within the cgroup CPU quota, `cgroup_linux.go:85`). Neither reference caps it, and an idle worker parks without
  waking (`scheduler/multi_thread/park.rs`). On Windows the count follows the process affinity mask
  (`crates/platform/src/cpus.rs` (`available_cpus`)). On Linux the TUN device opens one queue per worker
  (`crates/tun/src/device/mod.rs`). Go re-reads the mask and quota once a second (`runtime/proc.go:6637`,
  `sysmonUpdateGOMAXPROCS`) when the main module's `go` line is 1.25 or later (`internal/godebugs/table.go:72`,
  `updatemaxprocs`): sing-box's `go.mod` says 1.25.5 and follows the mask, mihomo's says 1.20 and keeps the count it
  started with. A Tokio pool cannot grow or shrink once built (`runtime/scheduler/multi_thread/worker.rs:273`,
  `create`), so it is sized for the most CPUs the process can get over its life. Where the launcher sets the mask
  (a shell, `taskset`, systemd, a container, the bench's CPU split) that is the mask at start. An Android app
  process is moved between cpusets as its state changes, and one started in the background holds the background
  cpuset's CPUs at start, so `libconcord.so` counts the online CPUs within the same quota
  (`crates/platform/src/cpus.rs` (`assignable_cpus`)); in the background it then runs more workers than sing-box
  has P's.

- [language-neutral] **Provider downloads and `.mrs` rule sets** have no size cap unless the provider sets
  `size-limit`: mihomo applies a limit only when it is positive (`component/resource/vehicle.go:157-160`), passes
  the provider's `size-limit` with no default (`adapter/provider/parser.go:94`), and decodes `.mrs` without one
  (`rules/provider/mrs_reader.go:17-20`). Concord fails a download over the limit where mihomo truncates it.

## Deliberate Differences

| Area | Kind | Reference and reason | Measurement |
|---|---|---|---|
| Crypto build optimization | language-neutral | AWS-LC C code uses release optimization level 3, like the data-path crates and the pinned shadowsocks-rust release, whose release profile sets no `opt-level` (`Cargo.toml:50-52`). The workspace size profile otherwise reaches the C compiler and enables AWS-LC size mode. No cipher or hardware capability is overridden. | Linux arm64: in the release binary (21,715,992 B) the size-mode load and xor helpers are inlined. Over ten rounds `ss-aes128` CPU against the same build without the setting moved -1.684% (95% CI -6.196% to +8.546%), short of the 10% sought, so the choice rests on release code generation, not on a measured CPU gain. Over 28 rounds `ss-aes128` CPU against Go is +0.880% [-0.334%, +2.436%], a known gap not fully attributed and not a runtime trade-off. |
| BoringSSL build optimization | language-neutral | `boring-sys` uses release optimization level 3, following the pinned shadowsocks-rust release's default speed optimization (`Cargo.toml:50-52`) and the AWS-LC choice above. `boring-sys` 5.4.0 creates a CMake configuration (`build/main.rs:233-235`); cmake 0.1.58 maps `z` to `MinSizeRel` and 3 to `Release` (`src/lib.rs:110-117,146-176`). No cipher or hardware capability is overridden. | Linux arm64, Rust 1.99.0, six fresh rounds of `trojan-chrome`: CRR CPU per connection 260.15 versus 326.23 microseconds, -20.25% [95% CI -20.64%, -18.76%]; connections per second 6671 versus 5688, +17.28% [+13.56%, +19.68%]. RR p99 -1.92% [-11.80%, +1.93%]. The release binary grows by 327,680 B; peak memory is 23.877 versus 22.541 MiB, below Go's 46.902-49.986 MiB across the measured workloads. |
| TLS read size | language-neutral | Go reads about one record per call on its default path: `readFromUntil` grows `rawInput` by what the record still lacks plus `bytes.MinRead` and reads into the free capacity (mihomo: `metacubex/tls v0.1.9` `conn.go:834-846`; sing-box: Go 1.27.3 `crypto/tls/conn.go:805-838`). A node's rustls TLS instead reads the rest of the record and up to a 32 KiB copy buffer of the next in one `readv` (`crates/tls/src/record.rs`, `Recv::poll_fill`), about two records. Nothing on the wire changes: the records written are the ones buffered rustls writes (`crates/tls/src/tests/whole.rs`). With the core out of CPU and the server under 1 ms away, one-record reads leave the kernel receive buffers of some flows near their initial size and those flows starve; with two-record reads every buffer grows. Why autotuning divides them is not traced. | Linux arm64, six rounds against one-record reads: TUN `trojan-tls` with 8 flows Jain 1.000 against 0.564 (sing-box 0.999), slowest flow 3.81 against 1.13 Gbit/s (sing-box 2.62), rate +9.2% [+7.4%, +17.2%], core CPU/GB -7.6% [-12.8%, -6.3%]; without TUN Jain 0.999 against 0.895 and rate +12.8% [+9.6%, +16.8%]. A socket read takes 34 kB against 17 kB. It costs 28% to 35% more peak memory under TUN, and one flow puts mihomo's server in its small-segment state more often (`benchmarking.md`, Isolation); both are known gaps. |
| Relay buffer size | runtime-bound | sing-box's sing copies one MTU-sized owner, or its 32 KiB fallback, per read (`common/bufio/copy.go:189-191`, `common/buf/buffer_standard.go:6`). Tokio instead fills up to eight independent owners with one raw TCP scatter read (`try_read_vectored`) after a full read; the first read and reads after a short read stay scalar. Each owner keeps its declared MTU sizing and writer headroom, including the 32 KiB fallback. The bound follows Linux `UIO_FASTIOV`, preserves frame/headroom boundaries, and amortizes readiness and kernel entry without a payload concatenation copy or a larger per-connection copy buffer. Prefetched bytes precede any direct socket handoff, and raw TCP pairs keep their splice path. | Linux arm64, uploads on `ss-aes128`, SS2022 and `trojan-tls`: core CPU against one scalar MTU-sized read per call fell 7.256% (95% CI 2.635–10.557), 7.390% (3.317–12.213) and 10.895% (8.576–10.982). These targeted runs settle the receive-side choice; its memory, fairness and latency effects were read in the landing gate. |
| Windows timed waits | runtime-bound | Go 1.27.3 re-arms its high-resolution waitable timer and re-associates it with the completion port on every timed `netpoll` (`runtime/netpoll_windows.go:174`), one per M, and leaves it armed across an untimed wait. The vendored mio arms one per selector the same way (`vendor/PATCHES.md`, mio 1.2.4) but keeps the armed timer when the new deadline lies less than 1 ms after it, because tokio rounds deadlines to whole milliseconds and a request-response loop waits on the same deadline again and again, and cancels it on an untimed wait so an idle poller is not woken. | Windows 11 ARM64 VM, `udp-rr` client CPU per GB against main: re-arming on every wait +22.1% [+7%, +30%] direct and +15.7% [+9%, +44%] ss-aes128; with the reuse -1.0% [-9%, +9%] and -7.8% [-13%, +5%], Brutal upload -1.5% [-3%, -1%] against Go. Idle and with an open idle connection: no context switches, mihomo 5/s. |
| Async TCP write batching | runtime-bound | Keeps at most eight owned reads for a bare TCP sink and drains on source Pending, EOF or error. Tokio 1.54.1 flushes when its source is Pending so a request can reach a peer waiting to reply (`src/io/util/copy.rs:138-145`). This boundary lets a task gather currently ready reads before the writer flushes; blocking Go reads provide no corresponding Pending return. Linux v7.0's `UIO_FASTIOV = 8` (`include/uapi/linux/uio.h`) and `___sys_sendmsg` (`net/socket.c`) keep that many imported iovecs on the stack. The bound follows that stack import threshold; each read still has its own buffer and no payload is copied to assemble the write. Accepted buffered writes are flushed before a source error is returned, including after a full queue has drained: sing's blocking `WriteBuffer` completes before the next source read, so Tokio's accepted plaintext must not be discarded with the source error. Bare TCP pairs retain splice and DirectIo retains its handoff. | — |
| TUN attached upload writes | runtime-bound | Take up to 64 queued 16 KiB chunks per `writev` (`crates/netstack/src/attach.rs`, `upload`), not the relay's eight. Once the outbound socket has filled, the queued payload leaves in the writes this loop makes, and with `TCP_NODELAY` each write ends in a short TSO packet; eight chunks (128 KiB) cut the stream into 45.6 KB packets where sing-box sends 65.2 KB. sing-tun writes all it holds in one `writeVector`, one iovec per 32 KiB slab and no count limit (`stack_go_splice.go:329-338`), which sing-box takes for a DIRECT connection from a TUN `GoConn` (`route/splice.go:122-164`, `v1.15.0-alpha.13`). Above `UIO_FASTIOV` the kernel allocates the iovec array per call, at about 2.4 calls per MB here. The relay's read bound stays at eight. | Linux arm64, TUN `direct` `tcp-up` at `--link rate=1000mbit` (2 rounds): packets to the server per MB 22.3 with eight chunks, 15.6 with 64, sing-box 15.5. At full speed the socket never fills and both write 828 KB per call. |
| Hysteria2 Brutal deficit batching | runtime-bound | On a budget deficit, Quinn's existing 2 ms userspace burst interval sets a useful-batch refill goal, with one minimum-delay interval of headroom below the reference burst capacity. Available credit still sends immediately, including an early ACK-driven poll; low-rate deadlines still cover the next packet. This differs from the reference pacer's next-packet deadline (sing-quic `hysteria2/congestion/pacer.go:76`) to reduce wake/dispatch work in Quinn's GSO sender. | Linux arm64, Hysteria2 Brutal upload on the `wan` link: core CPU per GB 13.09% lower than an arm on the reference's next-packet deadline (paired 95% interval 9.60–21.56% lower), throughput 0.64% lower (0.42–1.03% lower). Against the build without it and Go, over 60 fresh rotating rounds: 97.144, 105.918 and 97.625 Mbit/s; core CPU per GB 9.316, 9.232 and 24.503; server CPU per GB 15.400, 15.935 and 23.819. The 0.492% throughput gap to Go is a known gap; the `lossy` RR p99 gap to Go has an unknown cause and is neither explained nor exempted by this trade-off. |
| QUIC send batches | runtime-bound | Quinn coalesces at most ten datagrams per GSO send (upstream's `MAX_TRANSMIT_SEGMENTS`, kept in `vendor/quinn`), while one driver pass may still send 80. quic-go coalesces only within its pacer burst of ten packets (`internal/congestion/pacer.go:12`). A ten-packet pacer burst on top of the ten-datagram cap cost more than the cap alone, so the pacer keeps Quinn's burst. | Forty-datagram sends left the mihomo server spending 30% more CPU per GB receiving a WAN upload; with the cap it spends less than on the Go client. |
| TUN driver scheduling | runtime-bound | sing-tun `611d83b7` runs one engine goroutine per queue that sleeps on its own epoll, loops over bursts without a time bound and yields to the Go scheduler only after a burst that woke a handler (`stack_go_engine.go:317-320`, `:361-380`). Concord's driver is a Tokio task: a busy poll ends after `MAX_ROUNDS` rounds and wakes itself, and Tokio 1.54.1 sends a task woken during its own poll to the back of the run queue and wakes a parked worker for it (`src/runtime/scheduler/multi_thread/worker.rs:1393-1416`). Each such yield costs that wake and can move the driver to another CPU; the engine goroutine pays neither. The two ways around it were measured and not taken: a driver that reruns in place on a worker keeps Tokio's I/O driver from the tasks that wait on it (`tcp-crr` beside a `udp-stream` on one CPU: p99 24 times `main`'s), and a driver on a thread of its own halves a proxied download, whose relay tasks then run on other threads than the driver. | TUN `direct`, 6 rounds: `udp-stream` CPU per GB 1.675 against sing-box 1.305, +28.4% [+17.6, +30.8]. `ss-aes128` `tcp-down`, 3 rounds: the driver on its own thread 7.11 Gbit/s against 13.82 as a Tokio task. 5 rounds: `tcp-crr` p99 65.5 ms with the driver rerunning in place against 2.69 as a Tokio task. |
| Fake-IP mappings across a range change | language-neutral | mihomo's `CloneFrom` copies the previous pool's whole store (`component/fakeip/pool.go:90-102`), so after `fake-ip-range` changes a host seen before keeps an address outside the new range, which the TUN route no longer covers and the pool no longer counts as fake, until the mapping ages out. The new pool takes over only the mappings whose addresses it hands out itself (`crates/dns/src/fakeip.rs`, `FakeIpPool::adopt`); any other host gets an address from the new range; `adopting_from_another_range_keeps_only_the_addresses_this_one_hands_out` holds it. | None (behaviour, no performance effect) |
| ECH retry configs | language-neutral | mihomo sets the ECH list it was given or looked up on the TLS config (`component/ech/ech.go:19-24`, `:38-43`) and never reads the `retry_configs` a rejecting server sends, so a rejected offer is a failed connection. sing-box reads them: on an ECH rejection with a non-empty retry list it closes the connection, makes the list the node's ECH list and dials one more TCP connection with retry off; a second rejection is the error (`common/tls/client.go:154-170`, `common/tls/std_client.go:111-113`). Concord follows sing-box on the TCP paths of both TLS backends (rustls; BoringSSL, whose verify then checks the public name the way ECH requires). The list is kept for the node's later connections until its source changes: a configured `config` until reload, a looked-up one until the lookup answers with another list (sing-box replaces a looked-up list when the DNS answer's TTL runs out, `common/tls/ech.go:133-170`; Concord asks its resolver on every handshake, so it follows the answer). QUIC does not retry, as in sing-box. `crates/tls/src/tests/ech_retry.rs` holds both backends, the kept list and its end with a changed lookup. | None (behaviour, no performance effect) |
| MASQUE oversized datagrams | runtime-bound | The stack retains its configured MTU, like mihomo (`adapter/outbound/masque.go:218-239`). Each packet is checked against Quinn's current datagram limit, so an initial small path does not permanently reduce the stack's UDP capacity. An oversized packet is dropped; mihomo's connect-ip-go 67ccdb0cf771 instead returns PMTU ICMP (`conn.go:361-378`), which the native shared stack does not process. | macOS regression `masque_initial_path_mtu_drops_large_udp_without_shrinking_the_ip_stack` fixes the path at the initial MTU and checks that a 1200-byte UDP payload is admitted by the stack, dropped by the transport, and followed by a successful small datagram. Performance screening is pending. |
| WireGuard across a network reset | language-neutral | sing-box keeps the WireGuard device and rebinds it: its `ResetNetwork` first closes every connection (`route/network.go:471-474`), then calls each endpoint's `InterfaceUpdated` (`:476-481`), whose `BindUpdate` reopens the sockets and keeps the peers and their keypairs (`protocol/wireguard/endpoint.go:171-197`, sing-box's wireguard-go `device/device.go:756-814`). mihomo keeps the device and its socket and has no network-change hook for it (`listener/sing_tun/server.go:366-374`). Concord's `reset_sessions` drops the tunnel and builds a new one on the next dial (`crates/proxy/src/wireguard/mod.rs`, `WireGuard::reset_sessions`). On a network change no flow survives either way, since both close every connection first (Concord's `reset_network`, `crates/engine/src/engine.rs`); keeping the device would only save the first handshake after the change, and Rust gotatun 0.10.2 cannot rebind without that handshake: `Device::resume`, the only rebuild of its sockets without a configuration change, resets every peer's sessions (`src/device/mod.rs:333-358`). Dropping the tunnel also matches Concord's on-demand tunnel, retired when idle, and `release_memory`, which resets sessions to free them. `a_tunnel_made_across_a_reset_is_not_kept` holds it. | None (behaviour, no performance effect) |


## Tunables

The MASQUE benchmark peer reads 8192 bytes per TCP read, matching Rust Tokio 1.54.1
`src/io/util/mod.rs:88` (basis B, the runtime copy helper's default).

Every tunable (`rules.md`, "Tunables") with its basis: A, a spec; B, the reference's value for the same knob (or,
where mihomo and sing-box have none, the default of the Rust library used there, or the nearest analogue named as
one); C, a derivation from a runtime mechanism; O, a derivation from a cited requirement of a feature only Concord
has. An item is the constant's path: its crate's directory name, its module, then any
inline module, `impl` type or function around it. Values are written as numbers, optionally with a unit (B, KiB,
MiB, GiB, ns, µs, ms, s, min, h), or as the source text in backticks; `cfg` variants of one item are joined by
` / ` in source order. A tunable not listed here is in `xtask/tunables.txt`, which only shrinks. xtask's
`tunables` test holds each row's value to the code.

| Item | Value | Basis | Citation or derivation |
|---|---|---|---|
| `android::abi::PACKAGE_CAPACITY` | 223 | C | Android installs a package only if its manifest name passes validateName, which allows ASCII letters, digits, `_` and `.` up to MAX_FILE_NAME_SIZE = 223 characters (Android 36 sources `android/content/pm/parsing/FrameworkParsingPackageUtils.java:58`, `:98-99`, called from `ApkLiteParseUtils.java:916-917`), so 223 bytes hold any name the host returns; the grow-and-retry path stays for anything else. |
| `api::bus::DNS_CAPACITY` | 1024 | B | Analogue: mihomo has no DNS event stream; a client watching resolutions reads them as log lines (`tunnel/tunnel.go:345`) through the same per-client /logs queue of 1024 that drops when full (`hub/route/server.go:515`, `:521-525`). |
| `api::bus::EVENT_CAPACITY` | 1024 | B | Analogue: mihomo has no engine-event push; its one bounded per-client push queue, for /logs, holds 1024 (`hub/route/server.go:515`), the same trade-off of how far a slow subscriber may fall behind. |
| `api::bus::LOG_CAPACITY` | 1024 | B | How far one slow log subscriber may fall behind before entries are lost: mihomo queues each /logs client in `make(chan log.Event, 1024)` and drops when it is full (`hub/route/server.go:515`, `:521-525`). |
| `api::watch::DEFAULT_INTERVAL_MS` | 1000 | B | Default traffic sample period 1000 ms equals mihomo's /traffic ticker `time.NewTicker(time.Second)` (`hub/route/server.go:386`) and /connections default interval 1000 (`hub/route/connections.go:37`). |
| `api::watch::PROXY_DEBOUNCE` | 250 ms | B | sing-box pushes the group table to its GUI host at most every urlTestPushMinInterval = 250 ms (`daemon/started_service.go:40`, applied after each change at `:558-563`). |
| `common::backoff::GEO_RETRY_CAP` | 24 h | B | A GEO file the rules wait for is fetched again with the provider back-off up to mihomo's default geo-update-interval = 24 h (`config/config.go:492`); mihomo itself downloads it once while parsing and fails the profile when that fails (`component/geodata/init.go:168-192`). |
| `common::backoff::MIN_BACKOFF` | 10 s | B | mihomo resource fetcher backs off from min(10 s, interval), doubling up to the interval: `component/resource/fetcher.go:254` minBackoff = 10 * time.Second, Factor 2 at `:268`; same value. |
| `common::dns_relay::RELAY_TIMEOUT` | 5 s | B | mihomo DefaultDnsRelayTimeout = time.Second * 5 (`component/resolver/relay.go:16`), used by its TUN DNS hijack (`listener/sing_tun/dns.go:107`) and its `dns` outbound (`component/resolver/relay.go:55`, `adapter/outbound/dns.go:107`); same value. |
| `common::packet::PacketBuf::CAPACITY` | `u16::MAX as usize + Self::DEFAULT_HEADROOM` | A | RFC 768: the UDP length field is 16 bits, so a payload is under 65535 bytes; capacity is that plus DEFAULT_HEADROOM. |
| `common::packet::PacketBuf::DEFAULT_HEADROOM` | 342 | C | The longest header written in front of a datagram in place: a Shadowsocks 2022 UDP header to a 255-byte domain, 24 + 16 + 11 + 259 + 32 (`crates/proxy/src/ss/udp.rs:397`); the SOCKS5 262, VMess 276 and Hysteria2 271 fit under it. |
| `common::packet::RECV_MAX` | 32 | B | sing-tun packetSpliceRead doubles the receive batch up to goPacketBatchSize = 32 (`stack_go_udp.go:22`, used at `stack_go_splice.go:855`); same value. |
| `common::packet::RECV_MIN` | 8 | B | sing-tun packetSpliceRead halves the batch down to goReceiveBatchMin = 8 (`stack_go_profile_default.go:13`, used at `stack_go_splice.go:857`); same value. |
| `common::packet::RECV_SLOT` | 65536 | A | RFC 791 §3.1: Total Length is 16 bits, so a datagram is at most 65535 bytes; a 65536-byte slot holds any datagram (sing-tun also configures 65535-byte packet slots, `stack_go_splice.go:846`). |
| `common::packet::SLAB_LIMIT` | 64 | C | A thread keeps what one task poll can release at once: a UDP drain takes 64 datagrams (`crates/inbound/src/udp.rs::DRAIN_BATCH`) and a tunnel send round handles 64 (`crates/tunnel/src/udp/batch.rs::BATCH_DATAGRAMS`). The shared overflow holds one such batch per Tokio worker, read from the runtime (tokio `RuntimeMetrics::num_workers`). Go's sync.Pool has no count (`sync/pool.go`, emptied by GC), so no reference value exists. |
| `common::stream_buffer::CLASSES` | 11 | B | sing's allocator pools 11 power-of-two classes 1<<6..1<<16 (`common/buf/alloc.go:25-35`, plus one 72 KiB class at `:36`); same 11 classes. |
| `common::stream_buffer::COPY_BUFFER_SIZE` | 32768 | B | sing BufferSize = 32 * 1024 (`common/buf/buffer_standard.go:6`), the relay copy fallback; mihomo pool also 32 KiB. Same value. |
| `common::stream_buffer::FIRST_CLASS` | 6 | B | sing's smallest pooled class is 1<<6 = 64 bytes (`common/buf/alloc.go:25`, index -= 6 at `:53`); same value. |
| `common::stream_buffer::LOCAL_LIMIT` | 8 | C | A thread keeps what one relay write can release at once, its batch of 8 buffers (`crates/net/src/relay.rs::TCP_BATCH_BUFFERS`, itself Linux UIO_FASTIOV); the shared overflow holds one batch per Tokio worker (tokio `RuntimeMetrics::num_workers`). Go's sync.Pool has no count, so no reference value exists. |
| `config::yaml::ALIAS_RATIO_HIGH` | 4000000 | B | go.yaml.in/yaml/v3 v3.0.5, as mihomo uses it: from alias_ratio_range_high = 4000000 decodes the aliased share may be 10%, falling linearly from 99% between the two counts (`decode.go:462`, `:473-480`). |
| `config::yaml::ALIAS_RATIO_LOW` | 400000 | B | mihomo decodes profiles with go.yaml.in/yaml/v3 v3.0.5 (mihomo `go.mod:63`), which allows 99% of decoded nodes to come from aliases up to alias_ratio_range_low = 400000 decodes (`decode.go:458`, `:469-472`), checked once 100 aliased and 1000 decoded nodes are passed (`decode.go:539-541`). |
| `controller::FIRST_ACCEPT_BACKOFF` | 5 ms | B | mihomo's and sing-box's controllers run Go's `http.Server` (mihomo `hub/route/server.go:180-184`, sing-box `experimental/clashapi/server.go:85-88`), whose `Serve` waits 5 ms after the first accept error (Go `net/http/server.go:3580-3581`). |
| `controller::MAX_ACCEPT_BACKOFF` | 1 s | B | Go's `http.Server.Serve` doubles that wait up to 1 s and resets it on a successful accept (Go `net/http/server.go:3583-3586`, `:3601`). |
| `controller::stream::TICK` | 1 s | B | mihomo pushes /traffic and /memory on `time.NewTicker(time.Second)` (`hub/route/server.go:386`, `:432`) and defaults /connections to interval 1000 ms (`hub/route/connections.go:37`); Concord 1 s matches. |
| `desktop::TOKEN_LINE_LIMIT` | `concord_ipc::TOKEN_LEN as u64 + 2` | O | The session token (`crates/ipc/src/auth.rs:14`) plus its line end, CR LF at most: the host writes it with `stdin.writeln` and closes stdin (FlClash `rs` `lib/core/desktop/launcher.dart:56-57`), and `read_token` trims both (`bins/desktop/src/main.rs:141`). |
| `dns::client::EXCHANGE_TIMEOUT` | 5 s | B | mihomo's DNS client exchange timeout is 5 s (`dns/client.go:54`, and the DoT client `dns/dot.go:81`); Concord 5 s matches. |
| `dns::doh::DIAL_TIMEOUT` | 10 s | B | mihomo DoH dial and TLS-handshake timeout dialTimeout = 10 s (`dns/doh.go:39`, used at `:391`, `:396`); Concord 10 s matches. |
| `dns::doh::MAX_IDLE` | 2 | B | Idle HTTP/1 DoH connections kept: mihomo's DoH transport sets no `MaxIdleConnsPerHost` (`dns/doh.go:388-398`), so Go's `DefaultMaxIdleConnsPerHost` = 2 applies (mihomo `metacubex/http@v0.1.8/transport.go:61`). |
| `dns::doh::PING_INTERVAL` | 30 s | B | mihomo DoH enables HTTP/2 pings on idle connections after SendPingTimeout = 30 s (`dns/doh.go:33`, set at `:445`); Concord's h2 keep-alive interval 30 s matches. |
| `dns::doh::PING_TIMEOUT` | 15 s | B | HTTP/2 ping ack timeout: mihomo leaves `PingTimeout` unset (`dns/doh.go:444-446`), so metacubex/http defaults it to 15 s (`h2_bundle.go:1134`). |
| `dns::dot::MAX_IDLE` | 8 | B | mihomo keeps at most maxOldDotConns = 8 idle DoT connections (`dns/dot.go:20`, used at `:100`); Concord 8 matches. |
| `dns::enhance::FAKE_RECORD_TTL` | 600 | B | mihomo builds the fake-ip A/AAAA record with dnsDefaultTTL = 600 (`dns/server.go:19`, `dns/middleware.go:167`) and then applies fake-ip-ttl (`:189`), as Concord does with 600 then fake_ttl. |
| `dns::enhance::HOSTS_TTL` | 10 | B | mihomo answers hosts records with Ttl 10 and maps them for 10 s (`dns/middleware.go:61`, `:65`); Concord 10 matches. |
| `dns::enhance::MAPPING_SIZE` | 4096 | B | mihomo's enhancer IP-to-host mapping is `lru.WithSize(4096)` (`dns/enhancer.go:188`); Concord 4096 matches. |
| `dns::fakeip::STORE_SIZE` | 1000 | B | mihomo creates fake-ip pools with Size 1000 (`config/config.go:1545`, `:1557`), the memory store LRU size (`component/fakeip/memory.go:77`); Concord 1000 matches. |
| `dns::hosts::SYSTEM_HOSTS_TTL` | 5 s | B | mihomo re-checks the system hosts file after cacheMaxAge = 5 s (`component/resolver/hosts/hosts.go:18`, copied from Go `net/hosts.go:16`); Concord 5 s matches. |
| `dns::msg::SERVER_FAILURE_TTL` | 5 | B | mihomo caches a SERVFAIL answer for serverFailureCacheTTL = 5 s (`dns/util.go:26`, used at `:78`); Concord 5 matches. |
| `dns::resolver::DEFAULT_CACHE_SIZE` | 4096 | B | mihomo defaults CacheMaxSize to 4096 (`dns/resolver.go:489-490`); Concord 4096 matches. |
| `dns::resolver::DEFAULT_IPV6_WAIT` | 100 ms | B | mihomo waits 100 ms for AAAA (`dns/resolver.go:94`, config default IPv6Timeout 100 at `config/config.go:511`); Concord 100 ms matches. |
| `dns::resolver::DNS_TIMEOUT` | 5 s | B | mihomo DefaultDNSTimeout = 5 s (`component/resolver/resolver.go:38`); Concord 5 s matches. |
| `dns::system::REFRESH` | 300 s | B | mihomo re-reads system DNS servers after SystemDnsFlushTime = 5 min (`dns/system.go:16`); Concord 300 s matches. |
| `engine::dns_server::MAX_DATAGRAM` | 512 | B | Query buffer of the `dns.listen` UDP server: mihomo's is a miekg/dns `Server` with `UDPSize` unset (`dns/server.go:114`), which takes `MinMsgSize` = 512 (miekg/dns v1.1.63 `server.go:285-286`, `dns.go:15`). Answers are not bounded by it. |
| `engine::dns_server::STREAM_IDLE` | 8 s | B | mihomo's DNS listener is a miekg/dns Server (`dns/server.go:126`) whose TCP idle timeout defaults to tcpIdleTimeout = 8 s (`miekg/dns@v1.1.63/client.go:17`, used at `server.go:572`); Concord 8 s matches. |
| `engine::engine::SHUTDOWN_GRACE` | 5 s | B | How long shutdown waits for the background tasks it stopped before it logs how many still run and returns: sing-box's `StopTimeout` = 5 s (`824dbcf` `constant/timeout.go:17`), after which it warns about a service still closing (`adapter/lifecycle.go:104`, `common/taskmonitor/monitor.go:25`); its process gives up at `FatalStopTimeout` = 10 s (`cmd/sing-box/cmd_run.go:226`). Concord stops waiting at the first bound because the engine is restarted in place. What a stop leaves running is within it (C): a QUIC connection drains for 3 PTO after its close (RFC 9000 §10.2), PTO = smoothed RTT + 4 × RTT variance + 25 ms max ack delay (RFC 9002 §6.2.1), about 1 s at the 100 ms initial RTT `proxy::quic::transport_config` sets and under 5 s while RTT plus four variances stays below 1.6 s; gotatun 0.10.2's `Device::stop` aborts and joins its tasks (`device/mod.rs:279`). |
| `engine::engine::proxies::DEFAULT_DELAY_TIMEOUT` | 5 s | B | Delay test timeout when none is given: mihomo's health check defaults timeout to 5000 ms (`adapter/provider/healthcheck.go:200-201`); Concord 5 s matches. |
| `engine::ntp::ATTEMPTS` | 3 | B | mihomo's NTP update tries the exchange 3 times (`ntp/ntp/service.go:68`); Concord 3 matches. |
| `engine::ntp::EXCHANGE_TIMEOUT` | 5 s | B | sing's NTP exchange, which mihomo calls, sets the deadline defaultTimeout = 5 s (metacubex sing v0.5.8 `common/ntp/message.go:42`, used at `common/ntp/ntp.go:19`); Concord 5 s matches. |
| `engine::probe::PROBE_CONCURRENCY` | 10 | B | Probes share one pool of dials, the nearest mihomo knob being its health check's per-round limit: `SetLimit(10)` (mihomo `adapter/provider/healthcheck.go:132`). |
| `engine::probe::fetch::MAX_REDIRECTS` | 10 | B | mihomo's HTTP client sets no CheckRedirect (`component/http/http.go:89`), so metacubex/http stops after 10 redirects (`metacubex/http@v0.1.8/client.go:838`); Concord 10 matches. |
| `engine::resources::fetch::MAX_REDIRECTS` | 10 | B | mihomo's HTTP client sets no CheckRedirect (`component/http/http.go:89`), so metacubex/http stops after 10 redirects (`metacubex/http@v0.1.8/client.go:838`), the same cap as Go's `http.Client` (`net/http/client.go:846`); Concord 10 matches. |
| `engine::resources::geo::GEO_REPARSES` | 2 | B | mihomo downloads a geo file at most twice while a rule needs it, once when it is missing and once more when it is invalid, then fails (`component/geodata/init.go:93-110`); each round here fetches every fault of one parse, so a second round is the second download. |
| `engine::resources::geo::GEO_TIMEOUT` | 90 s | B | mihomo downloads geo databases with defaultHttpTimeout = 90 s (`component/updater/utils.go:14`, used at `component/updater/update_geo.go:48`); Concord 90 s matches. |
| `engine::resources::rule_providers::PROVIDER_TIMEOUT` | 20 s | B | mihomo fetches proxy and rule providers with DefaultHttpTimeout = 20 s (`component/resource/vehicle.go:20`, used at `adapter/provider/parser.go:94`, `rules/provider/parse.go:59`); Concord 20 s matches. |
| `engine::tun::DEFAULT_MTU` | 9000 | B | mihomo's TUN listener defaults MTU to 9000 (`listener/sing_tun/server.go:192-194`); Concord 9000 matches. |
| `engine::tun::PING_WAIT` | 10 s | B | Wait for a forwarded ICMP echo reply: sing-box's TUN takes `C.ICMPTimeout` (`protocol/tun/inbound.go:499`), 10 s (`constant/timeout.go:13`). |
| `group::check::SHARE_ROUND` | 1 s | B | mihomo's health check runs through `singledo.NewSingle(time.Second)` (`adapter/provider/healthcheck.go:215`), reusing a result younger than 1 s (`common/singledo/singledo.go:31`); Concord 1 s matches. |
| `group::deps::DEFAULT_TEST_TIMEOUT` | 5 s | B | mihomo v1.19.33 (`3f27ef39`) defaults health-check and group timeouts to 5000 ms (`adapter/provider/healthcheck.go:200-201`, `adapter/outboundgroup/groupbase.go:94-95`); Concord 5 s matches. |
| `group::health::HISTORY` | 10 | B | mihomo keeps defaultHistoriesNum = 10 delay records per proxy (`adapter/adapter.go:26`, trimmed at `:178`); Concord 10 matches. |
| `group::outbounds::build::DEFAULT_MAX_FAILED_TIMES` | 5 | B | mihomo v1.19.33 (`3f27ef39`) defaults maxFailedTimes to 5 (`adapter/outboundgroup/groupbase.go:97-98`); Concord's group failure threshold matches. |
| `group::outbounds::select::PROBE_TIMEOUT` | 5 s | B | mihomo's Fallback.Set tests a dead selected proxy with a 5000 ms timeout (`adapter/outboundgroup/fallback.go:140-141`); Concord's fallback selection probe 5 s matches. |
| `group::provider::HTTP_TIMEOUT` | 20 s | B | mihomo fetches proxy providers with DefaultHttpTimeout = 20 s (`component/resource/vehicle.go:20`, used at `adapter/provider/parser.go:94`); Concord 20 s matches. |
| `group::shared::LOOP_REPORT_INTERVAL` | 3 s | O | The dialer-loop event exists for the host banner, which the FlClash host throttles to one per 3 s, firing on the leading edge (FlClash `rs` `lib/manager/core_manager.dart:353-362`, `lib/common/function.dart:88-98`). A window up to 3 s drops only events the host would drop; a longer one would hide a banner. Change it with the host constant. |
| `group::strategy::MAX_RETRY` | 5 | B | mihomo load-balance tries maxRetry = 5 (`adapter/outboundgroup/loadbalance.go:197`, `:222`); Concord 5 matches. |
| `group::strategy::STICKY_SIZE` | 1000 | B | mihomo sticky-sessions LRU `lru.WithSize(1000)` (`adapter/outboundgroup/loadbalance.go:225`); Concord 1000 matches. |
| `group::strategy::STICKY_TTL` | 600 s | B | mihomo sticky-sessions ttl = 10 min (`adapter/outboundgroup/loadbalance.go:221`, applied at `:224`); Concord 600 s matches. |
| `group::urltest::HEAD_LIMIT` | 10 MiB | B | mihomo's URL test sends HEAD through Go's `http.Client` (`adapter/adapter.go:218`), whose transport reads at most 10 MiB of response head (Go `net/http/transport.go:336-340`, `maxHeaderResponseSize`). |
| `group::urltest::ROUND_CONCURRENCY` | 10 | B | mihomo's health-check round runs at most 10 tests at once (`adapter/provider/healthcheck.go:131-132`, errgroup SetLimit(10)); Concord 10 matches. |
| `inbound::accept::MAX_BACKOFF` | 1 s | B | Accept-error backoff ceiling; Go `net/http/server.go:3585` (Server.Serve tempDelay max 1 s), same doubling loop. |
| `inbound::accept::MIN_BACKOFF` | 5 ms | B | Accept-error backoff start; Go `net/http/server.go:3581` (Server.Serve tempDelay starts at 5 ms, doubles). |
| `inbound::bind::LISTEN_BACKLOG` | 2147483647 | C | Linux lowers a listen backlog to `net.core.somaxconn` (`net/socket.c::__sys_listen_socket`), XNU to `kern.ipc.somaxconn` (`bsd/kern/uipc_socket.c::solisten`), and Windows takes `SOMAXCONN` = 0x7fffffff as the provider's maximum (Go `syscall/types_windows.go:649`); asking for the most gives each system's limit, which is what Go passes after reading it (`net/sock_linux.go:33-52`, `net/sock_bsd.go:14-31`). |
| `inbound::ctx::HANDSHAKE_TIMEOUT` | 15 s | B | sing-box bounds reading a request head by TCPTimeout = 15 s (`constant/timeout.go:9`, used as ReadHeaderTimeout at `transport/v2rayhttp/server.go:65`); same value. |
| `inbound::http::body::MAX_LINE` | 4096 | B | Go `net/http/internal/chunked.go:19` maxLineLength = 4096 for a chunk-size line, which mihomo's HTTP inbound reads through (`listener/http/proxy.go:51`); same value. |
| `inbound::http::forward::IDLE_TIMEOUT` | 90 s | B | HTTP inbound upstream pool idle 90 s; mihomo `listener/http/client.go:22` IdleConnTimeout 90 s (from Go `net/http/transport.go:55`). |
| `inbound::http::forward::MAX_IDLE` | 100 | B | HTTP inbound upstream idle pool cap 100; mihomo `listener/http/client.go:21` MaxIdleConns 100 (Go `net/http/transport.go:54`). |
| `inbound::http::head::MAX_REQUEST_HEAD` | 1 MiB | B | Go's server caps a request head at DefaultMaxHeaderBytes = 1 << 20 (`net/http/server.go:939`); mihomo reads requests with no cap (`listener/http/hack.go:10`), so the Go server's bound is the family's. |
| `inbound::http::head::MAX_RESPONSE_HEAD` | 10 MiB | B | mihomo forwards HTTP through Go's Transport, whose MaxResponseHeaderBytes defaults to 10 << 20 (`net/http/transport.go:336-341`, mihomo `listener/http/client.go:18-24`); same value. |
| `inbound::socks4::MAX_FIELD` | 256 | B | SOCKS4 NUL-terminated userid/host field cap 256; mihomo `transport/socks4/socks4.go:184` maxLen = 256. |
| `inbound::spec::DEFAULT_KEEPALIVE` | 15 s | B | TCP keepalive idle/interval default 15 s; Go `net/dial.go:20`, `:24` defaultTCPKeepAliveIdle/Interval 15 s, which mihomo gets by leaving them 0 (`component/keepalive/tcp_keepalive_go123.go:16-17`). |
| `inbound::tproxy_udp::DRAIN_BATCH` | 64 | B | sing DefaultPacketReadBatchSize = 64 (`common/bufio/copy.go:20`), the batch sing-box's UDP listener reads per wake (`common/listener/listener_udp.go:176`); same value. |
| `inbound::udp::DRAIN_BATCH` | 64 | B | sing DefaultPacketReadBatchSize = 64 (`common/bufio/copy.go:20`), the batch sing-box's UDP listener reads per wake (`common/listener/listener_udp.go:176`); same value. |
| `mitm::ca::BACKDATE` | `Duration::hours(1)` | B | sing-box forges a per-name certificate on the fly with NotBefore one hour back (`common/tls/mkcert.go:40`, called per ClientHello at `common/tls/std_server.go:435`). |
| `mitm::ca::CA_VALIDITY` | `Duration::days(10 * 365)` | B | Analogue: sing-box's product code issues no CA; the one CA it creates, in its test tree, is valid ten years (`test/mkcert.go:47`). |
| `mitm::ca::LEAF_RENEWAL` | `Duration::minutes(20)` | B | sing-box renews a certificate it serves min(lifetime / 3, 30 days) before expiry (`service/origin_ca/service.go:266-271`, `:46`); for the one-hour leaf that is 20 minutes. |
| `mitm::ca::LEAF_VALIDITY` | `Duration::hours(1)` | B | sing-box's forged per-name certificate expires one hour after issue (`common/tls/mkcert.go:18`). |
| `mitm::capture::EXCHANGE_OVERHEAD` | `std::mem::size_of::<Capture>() as i64` | C | The fixed memory one kept exchange takes, charged against the capture byte budget besides its strings and bodies: the store keeps one `Arc<Capture>` per exchange (`crates/mitm/src/capture.rs:143`), whose size is the type's layout (Rust std `mem::size_of`). |
| `mitm::clienthello::MAX_CLIENT_HELLO_LEN` | 65536 | B | mihomo bounds the read-ahead its sniffer buffers to read a ClientHello at maxSniffBufferSize = 64 * 1024 (`component/sniffer/dispatcher.go:27`, `:243`); Go crypto/tls, behind sing-box's TLS sniff, refuses a handshake message over maxHandshake = 65536 (Go `crypto/tls/common.go:71`). |
| `mitm::cron::SEARCH_HORIZON` | 252979200 | A | A cron schedule has no year field, so its fire dates follow the Gregorian leap-year rule of RFC 3339 Appendix C; the longest gap between two fires of a schedule that fires at all is 29 February across a skipped century leap year, 2096-02-29 to 2104-02-29, eight years. |
| `mitm::engine::ACCEPT_TIMEOUT` | 15 s | B | TLS handshake with the client: sing-box bounds a server handshake by `C.TCPTimeout` (`common/tls/server.go:49-51`), 15 s (`constant/timeout.go:9`). |
| `mitm::engine::HANDSHAKE_TIMEOUT`, `mitm::quickjs::fetch::HANDSHAKE_TIMEOUT` | 10 s | B | TLS handshake to an upstream: Go's `DefaultTransport` `TLSHandshakeTimeout` (`net/http/transport.go:56`). |
| `mitm::engine::SNIFF_WINDOW` | 1 s | B | mihomo's sniffer waits 1 s for a connection's first byte, then gives every further read one fresh 1 s window (`component/sniffer/dispatcher.go:226`, `:238`). |
| `mitm::engine::TASK_CONCURRENCY` | 2 | A | The Surge manual: "At most 2 JSC sessions run in parallel; additional sessions are queued." (`https://manual.nssurge.com/scripting/overview.html`, "Script Engine", "JavaScriptCore"). |
| `mitm::quickjs::fetch::MAX_REDIRECTS` | 10 | B | Go's `http.Client` stops after 10 redirects (`net/http/client.go:847`). |
| `mitm::quickjs::run::DEFAULT_REQUEST_TIMEOUT_MS` | 5000 | A | The Surge manual on `$httpClient`: "The request timeout in seconds. The default is 5 seconds." (`https://manual.nssurge.com/scripting/api.html`, "$httpClient"). |
| `mitm::quickjs::store::FLUSH_DELAY` | 10 ms | B | Analogue: mihomo persists its key-value storage through bbolt `DB.Batch` (`component/profile/cachefile/storage.go:79`), which holds a batch at most DefaultMaxBatchDelay = 10 ms (mihomo dep metacubex bbolt `db.go:199`, `internal/common/types.go:29`), the same coalescing of a burst of writes into one commit. |
| `mitm::quickjs::store::MAX_VALUE` | 4194304 | A | The Surge manual, which specifies the script behaviour MITM ports: "The maximum value size is 4 MB on iOS and 32 MB on Mac." (`https://manual.nssurge.com/scripting/api.html`, "$persistentStore", `write`). No condition picks the platform, so one value, the smaller. |
| `mitm::script::DEFAULT_SCRIPT_TIMEOUT` | 5 s | A | The Surge manual: "`timeout`: Optional, in seconds, default: 5" (`https://manual.nssurge.com/scripting/overview.html`, "Parameters"). |
| `mitm::session::MAX_IDLE_PER_HOST` | 2 | B | Idle HTTP/1 upstream connections kept per host: Go's `DefaultMaxIdleConnsPerHost` (`net/http/transport.go:62`), which mihomo's HTTP clients run with. |
| `mitm::session::READ_HEADER_TIMEOUT` | 15 s | B | Wait for a client's request head: sing-box's HTTP servers set `ReadHeaderTimeout: C.TCPTimeout` (`transport/v2rayhttp/server.go:65`), 15 s (`constant/timeout.go:9`). |
| `net::dial::FALLBACK_AFTER` | 300 ms | B | mihomo dualStackFallbackTimeout = 300 * time.Millisecond (`component/dialer/dialer.go:24`), the head start of the preferred family; same value. |
| `net::relay::ATTACHED_REPORT` | 1 s | B | mihomo's statistic manager samples traffic once a second (`tunnel/statistic/manager.go:116`); a report more often than the consumer's sample adds nothing. Same period. |
| `net::relay::TCP_BATCH_BUFFERS` | 8 | C | Linux UIO_FASTIOV = 8 (`include/uapi/linux/uio.h`, read as NDK sysroot `usr/include/linux/uio.h:26`): sendmsg/writev keep up to 8 imported iovecs on the stack, so 8 owned reads per write avoid a per-call iovec allocation. |
| `net::sockets::DEFAULT_KEEP_ALIVE` | 15 s | B | Go net defaultTCPKeepAliveIdle = 15 * time.Second (`net/dial.go:20`), which mihomo gets when keep-alive-idle is unset (`component/keepalive/tcp_keepalive.go:12`, default 0); same value. |
| `netstack::cc::CUBIC_BETA` | 0.7 | B | sing-tun mirrors Linux tcp_cubic: goCubicBeta = 717 / goCubicBetaScale 1024 = 0.7 (`stack_go_tcp_cubic.go:11-13`); RFC 9438 beta_cubic 0.7. Same value. |
| `netstack::cc::CUBIC_C` | 0.4 | B | sing-tun mirrors Linux tcp_cubic: goCubicScale = 41, round-trip scale 41*10/1024 = 0.4 (`stack_go_tcp_cubic.go:14`, `:29`); RFC 9438 C = 0.4. Same value. |
| `netstack::cc::INITIAL_RTO` | 1000000 | B | sing-tun goRTOInitialMicros = 1000000 (`stack_go_tcp_input.go:21`, set at `:181`), the RFC 6298 §2.1 initial RTO of 1 s. Same value. |
| `netstack::cc::MAX_RTO` | 60000000 | B | sing-tun goRTOMaxMicros = 60000000 (`stack_go_tcp_input.go:22`, backoff cap at `:1309`); RFC 6298 §2.5 allows a maximum of at least 60 s. Same value. |
| `netstack::cc::MIN_RTO` | 300000 | B | sing-tun goRTOFloorMicros = 300000 (`stack_go_tcp_input.go:20`), above the peers' delayed-ACK timers (comment `:16-18`); same value and reason. |
| `netstack::tcp::ORPHAN_TIMEOUT` | 60000000 | B | sing-tun goFinWait2Timeout = 60 s resets an orphaned FIN_WAIT_2 connection (`stack_go_tcp_input.go:35`, `:1518`); Concord closes a dropped FinWait2 after the same 60 s. |
| `netstack::tcp::recovery::REO_PERSIST` | 16 | B | sing-tun sets reorderWindowPersist = goRackRecoveryThreshold = 16 on DSACK (`stack_go_tcp_cong.go:36`, `stack_go_tcp_ack.go:714`); RFC 8985 reo_wnd_persist 16. Same value. |
| `netstack::tcp::timers::DELAYED_ACK_WORST` | 200000 | B | sing-tun goProbeDelayedAck = 200000 us added to the tail-loss probe when one segment is in flight (`stack_go_tcp_input.go:30`); RFC 8985 WCDelAckT 200 ms. Same value and use. |
| `platform::netinfo::tables::MAX_AGE` | 20 s | B | mihomo re-reads its interface table after 20 s, `singledo.NewSingle(time.Second * 20)` (`component/iface/iface.go:35`); Concord 20 s matches. |
| `platform::splice::CHUNK` | 1048576 | B | Go asks splice(2) for at most maxSpliceSize = 1 << 20 per call (`internal/poll/splice_linux.go:25`, Go 1.27.3), which sing-box's TCP copy reaches through Go's splice path; Concord 1 MiB matches. |
| `platform::splice::DEFAULT_PIPE_USER_PAGES_SOFT` | 16384 | C | A splice pipe returns to the pool only while the process's live pipes, in use and pooled, fit the full-size pipes the per-user quota allows: `fs.pipe-user-pages-soft` (read once from /proc) over the pages of one PIPE_SIZE pipe. Past the quota the kernel gives a new pipe two pages (Linux `fs/pipe.c` too_many_pipe_buffers_soft, account_pipe_buffers) and `crates/platform/src/splice.rs::MIN_PIPE` refuses it. Without /proc the quota is Linux's default, PIPE_DEF_BUFFERS * INR_OPEN_CUR = 16 * 1024 pages (`fs/pipe.c` pipe_user_pages_soft). Go's splicePipePool has no count (`internal/poll/splice_linux.go:184-221`, Go 1.27.3). |
| `platform::udp_batch::MAX_SEGMENTS` | 64 | B | sing-tun 611d83b7 stops a coalesced UDP_SEGMENT run at 64 datagrams (`stack_go_socket_linux.go:165`, `end-index < 64`); Concord 64 matches. |
| `platform::udp_batch::UDP_BATCH` | 64 | B | sing DefaultPacketReadBatchSize = 64 (`common/bufio/copy.go:20`) sizes its sendmmsg/recvmmsg batch (`common/bufio/packet_batch_mmsg.go:77-78`); same value. |
| `platform::udpbuf::BUFFER` | 7340032 | B | wireguard-go socketBufferSize = 7 << 20 (`conn/controlfns.go:17`), set once on its UDP sockets with a refusal ignored (`conn/controlfns_unix.go:19-20`); same value, same single attempt. |
| `platform::utun::UTUN_BATCH` | 64 | B | sing-tun 611d83b7 reads utun in batches of goReadBatch = 64 on non-iOS (`stack_go_profile_default.go:14`, used at `stack_go_io_darwin.go:135`); Concord 64 matches. |
| `platform::utun::UTUN_BATCH_FRAME` | 4092 | B | sing-tun 611d83b7 batches only frames up to goDarwinBatchFrameLimit = 4096 - PacketOffset (`stack_go_io_darwin.go:30`), from xnu's 4 KB mbuf cluster (MBIGCLBYTES) limit on sendmsg_x; Concord 4092 matches. |
| `platform::watch::SETTLE` | 100 ms | B | mihomo watches a file provider with fswatch and passes no WaitTimeout (`component/resource/fetcher.go:215-218`), so a Create or Write reloads once the file has been quiet for DefaultWaitTimeout = 100 ms, each further event restarting the wait (mihomo dep metacubex fswatch v0.1.1 `watcher.go:15`, `:56-59`, `:123-131`). |
| `proto::MAX_BATCH_BYTES` | 51200 | O | FlClash decodes every event frame on its UI isolate and moves only a response of coreOffloadBytes = 51200 bytes or more off it (FlClash `rs` `lib/core/api/core_client.dart:13-14`, `:296-322`); a batch cut at that size keeps event frames at the host bound for inline decoding. |
| `proxy::anytls::DEFAULT_INTERVAL` | 30 s | B | Default idle-session check interval 30 s when configured value is at or below 5 s: mihomo `transport/anytls/session/client.go:51` (`time.Second * 30`). |
| `proxy::anytls::MIN_INTERVAL` | 5 s | B | Idle-session check interval floor 5 s: mihomo `transport/anytls/session/client.go:50` (`if idleSessionCheckInterval <= time.Second*5`), same threshold. |
| `proxy::anytls::session::CHUNK_QUEUE` | 1 | B | sing-anytls holds one pending read buffer per stream and blocks the session reader until the stream takes it (`stream.go:24`, `:59-83`); mihomo uses an unbuffered pipe (`transport/anytls/pipe/io_pipe.go:209-210`). Same depth, same blocking. |
| `proxy::anytls::session::OUT_QUEUE` | 1 | B | sing-anytls writes a frame synchronously under the session's one-slot write lock (`session.go:78`, `:446`, `:477`), as mihomo writes under connLock (`transport/anytls/session/session.go:445-447`): a writer waits for the frame before it. One queued frame, with the writer waiting for a slot, is the same back-pressure. |
| `proxy::anytls::session::SYNACK_DEADLINE` | 3 s | B | SYNACK wait 3 s for peer version >= 2: mihomo `transport/anytls/session/session.go:148` (`util.NewDeadlineWatcher(time.Second*3, ...)`), same value and condition. |
| `proxy::dgram::INITIAL_READ_BUFFER` | 16384 | B | sing reads one UDP packet into UDPBufferSize = 16 KiB (`common/buf/buffer_standard.go:7`), as mihomo does (`common/pool/buffer_standard.go:13`, sized for TUN's 9000-byte MTU); same value. |
| `proxy::dgram::MAX_QUEUED` | 65536 | C | sing writes each frame synchronously (`common/uot/conn.go::WritePacket`), a backlog of one frame; one frame is at most its 2-byte length, 65535 bytes (`common/uot/conn.go:138`), so a send waits once a frame's worth is queued. |
| `proxy::dgram::MAX_READ_BUFFER` | 131072 | C | A frame carries a 2-byte length (sing `common/uot/conn.go:138`), so it is at most 65535 bytes plus its header; the read buffer doubles from INITIAL_READ_BUFFER until one fits, and the first power of two above that is 2 x 65536. |
| `proxy::dns::ANSWER_QUEUE` | 1 | B | mihomo's `dnsPacketConn` hands answers to the reader through `make(chan dnsPacket, 1)` (`adapter/outbound/dns.go:42`); same capacity. |
| `proxy::dns::PIPE_CAPACITY` | 65537 | A | One DNS message over TCP: a two-byte length and at most 65535 bytes (RFC 1035 §4.2.2), so the server side of the in-memory pipe writes a whole answer without waiting for the reader; mihomo's `N.Pipe` (`adapter/outbound/dns.go:27`) is unbuffered, which Go's goroutine-per-side copy tolerates. |
| `proxy::dns::SAFE_PACKET` | 2048 | B | mihomo SafeDnsPacketSize = 2 * 1024 (`component/resolver/relay.go:18`): its `dns` outbound takes a longer datagram and drops it (`adapter/outbound/dns.go:97-100`); same value. |
| `proxy::http::MAX_HEAD` | 10 MiB | B | Go's net/http caps a response head at 10 << 20 (`net/http/transport.go:336-340`), the limit Go applies to an HTTP proxy's CONNECT response (`:2012`); sing-box and mihomo read the head through http.ReadResponse with no smaller cap (sing `protocol/http/client.go:124-125`, mihomo `adapter/outbound/http.go:123`). Same value as `transport::http1::MAX_HEAD`. |
| `proxy::hysteria2::DATAGRAM_FRAME` | 16383 | B | quic-go advertises MaxDatagramSize = 16383 as max_datagram_frame_size (sing-box's quic-go `internal/wire/datagram_frame.go:14`), which sing-quic and mihomo's Hysteria2 clients run; same value. |
| `proxy::hysteria2::DEFAULT_CONN_WINDOW` | 20971520 | B | Connection receive window 20 MiB (8 MiB x 5/2): sing-quic `hysteria2/protocol.go:9` (`DefaultConnReceiveWindow = DefaultStreamReceiveWindow * 5 / 2`), applied in `hysteria2/client.go:100-104`. |
| `proxy::hysteria2::DEFAULT_CWND` | 32 | B | Default BBR initial window 32 packets: mihomo `transport/tuic/common/congestion.go:18` (`cwnd = 32` when unset), used for Hysteria2 via `adapter/outbound/hysteria2.go:232`. |
| `proxy::hysteria2::DEFAULT_HOP` | 30 | B | Default port-hop interval 30 s: mihomo `adapter/outbound/hysteria2.go:30` (`defaultHopInterval = 30`). |
| `proxy::hysteria2::DEFAULT_STREAM_WINDOW` | 8388608 | B | Stream receive window 8 MiB: sing-quic `hysteria2/protocol.go:8` (`DefaultStreamReceiveWindow = 8388608`). |
| `proxy::hysteria2::DEFAULT_UDP_MTU` | 1197 | B | Default UDP message size 1197: mihomo `adapter/outbound/hysteria2.go:198` (`option.UdpMTU = 1200 - 3`). |
| `proxy::hysteria2::KEEP_ALIVE` | 10 s | B | QUIC keepalive 10 s: sing-quic `hysteria2/protocol.go:11` (`DefaultKeepAlivePeriod = 10 * time.Second`). |
| `proxy::hysteria2::MAX_IDLE` | 30 s | B | QUIC max idle timeout 30 s: sing-quic `hysteria2/protocol.go:10` (`DefaultMaxIdleTimeout = 30 * time.Second`). |
| `proxy::hysteria2::MIN_HOP` | 5 | B | Minimum port-hop interval 5 s: mihomo `adapter/outbound/hysteria2.go:29` (`minHopInterval = 5`), clamped at `:255-256`. |
| `proxy::hysteria2::realm::control::MAX_ERROR_BODY` | 65536 | B | sing-quic reads at most maxErrorBodySize = 64 KiB of a non-2xx realm control response (`hysteria2/realm/control.go:291`, `:298`) and decodes a success body unbounded (`:127`); same value, same scope. |
| `proxy::hysteria2::realm::control::MAX_HEAD` | 10 MiB | B | Go's net/http caps a response head at 10 << 20 (`net/http/transport.go:336-340`), the limit Go applies to an HTTP proxy's CONNECT response (`:2012`); sing-box and mihomo talk to the realm control server through net/http without MaxResponseHeaderBytes (mihomo `adapter/outbound/hysteria2.go:290-299`). Same value. |
| `proxy::hysteria2::realm::punch::INTERVAL` | 100 ms | B | Hole-punch packet interval 100 ms: sing-quic `hysteria2/realm/punch_engine.go:18` (`punchInterval = 100 * time.Millisecond`). |
| `proxy::hysteria2::realm::punch::SYMMETRIC_EXTRA` | 4 | B | Extra ports probed per symmetric-NAT host 4: sing-quic `hysteria2/realm/punch_engine.go:21` (`symmetricNATExtraPorts = 4`). |
| `proxy::hysteria2::realm::punch::SYMMETRIC_GAP` | 4 | B | Symmetric-NAT port gap 4: sing-quic `hysteria2/realm/punch_engine.go:20` (`symmetricNATPortGap = 4`). |
| `proxy::hysteria2::realm::punch::SYMMETRIC_PER_HOST` | 32 | B | Max ports per symmetric-NAT host 32: sing-quic `hysteria2/realm/punch_engine.go:22` (`symmetricNATMaxPortsPerHost = 32`). |
| `proxy::hysteria2::realm::punch::TIMEOUT` | 10 s | B | Hole-punch timeout 10 s: sing-quic `hysteria2/realm/punch_engine.go:17` (`punchTimeout = 10 * time.Second`). |
| `proxy::hysteria2::realm::stun::ATTEMPTS` | `[Duration::from_millis(500), Duration::from_secs(2), Duration::from_secs(4), ]` | B | STUN attempt timeouts 500 ms, 2 s, 4 s: sing-quic `hysteria2/realm/stun.go:206-210` (`attemptTimeouts`), same three values. |
| `proxy::hysteria2::udp::QUEUE` | 64 | B | Per-session received UDP message queue 64: sing-quic `hysteria2/packet.go:139` (`data: make(chan *udpMessage, 64)`). |
| `proxy::hysteria2::wire::DEFRAG_TTL` | 10 s | B | Fragment reassembly lifetime 10 s: sing-quic `hysteria2/packet.go:337` (`cache.WithAge(10)`, seconds per sing `common/cache/lrucache.go:123`). |
| `proxy::hysteria::DEFAULT_CONN_WINDOW` | 67108864 | B | Connection receive window 64 MiB: mihomo `adapter/outbound/hysteria.go:36` (`DefaultConnectionReceiveWindow = 67108864`). |
| `proxy::hysteria::DEFAULT_HOP_SECS` | 10 | B | Port-hop interval 10 s: mihomo `adapter/outbound/hysteria.go:40` (`DefaultHopInterval = 10`), applied at `:198-199`. |
| `proxy::hysteria::DEFAULT_STREAM_WINDOW` | 15728640 | B | Stream receive window 15 MiB: mihomo `adapter/outbound/hysteria.go:35` (`DefaultStreamReceiveWindow = 15728640`). |
| `proxy::hysteria::KEEP_ALIVE` | 10 s | B | QUIC keepalive 10 s: mihomo `adapter/outbound/hysteria.go:188` (`KeepAlivePeriod: 10 * time.Second`). |
| `proxy::hysteria::MAX_IDLE` | 30 s | B | QUIC idle timeout 30 s: mihomo leaves MaxIdleTimeout unset so quic-go uses `internal/protocol/params.go:100` (`DefaultIdleTimeout = 30 * time.Second`, applied `config.go:71`). |
| `proxy::hysteria::PROTOCOL_TIMEOUT` | 10 s | B | Handshake/control stream timeout 10 s: mihomo `transport/hysteria/core/protocol.go:13` (`protocolTimeout = 10 * time.Second`), used at `core/client.go:81`. |
| `proxy::hysteria::QUIC_STREAM_WINDOW` | 6291456 | B | Stream window 6 MiB when only recv-window is set: mihomo then leaves MaxStreamReceiveWindow 0 and quic-go uses `internal/protocol/params.go:31` (`DefaultMaxReceiveStreamFlowControlWindow = 6 * (1 << 20)`). |
| `proxy::hysteria::udp::QUEUE` | 64 | B | sing-quic's Hysteria session queue `make(chan *udpMessage, 64)` (`hysteria/packet.go:142`), dropping when full (`:271-275`); same value. |
| `proxy::mieru::MTU` | 1400 | B | Packet underlay MTU 1400: mieru `pkg/common/mtu.go:19` (`DefaultMTU = 1400`), applied in `pkg/appctl/appctlcommon/client.go:224`. |
| `proxy::mieru::congestion::CUBIC_BETA` | 0.7 | B | CUBIC multiplicative decrease 0.7: mieru `pkg/congestion/cubic.go:32` (`cubicBeta float64 = 0.7`). |
| `proxy::mieru::congestion::CUBIC_C` | 0.4 | B | CUBIC scaling constant 0.4: mieru `pkg/congestion/cubic.go:33` (`cubicC float64 = 0.4`). |
| `proxy::mieru::congestion::INITIAL_RTO` | 2 s | B | Initial RTO 2 s: mieru `pkg/congestion/rtt.go:88` (`return 2 * defaultInitialRTT`, `defaultInitialRTT = time.Second` at `:38`). |
| `proxy::mieru::congestion::MIN_DEVIATION` | 10 ms | B | RTO minimum deviation term 10 ms: mieru `pkg/congestion/rtt.go:90` (`mathext.Max(4*r.MeanDeviation(), 10*time.Millisecond)`). |
| `proxy::mieru::congestion::RTT_ALPHA` | 0.125 | B | Smoothed-RTT gain 0.125: mieru `pkg/congestion/rtt.go:34` (`rttAlpha = 0.125`). |
| `proxy::mieru::congestion::RTT_BETA` | 0.25 | B | RTT deviation gain 0.25: mieru `pkg/congestion/rtt.go:36` (`rttBeta = 0.25`). |
| `proxy::mieru::meta::MAX_PDU` | 32768 | B | Max protocol data unit written without splitting, 32 KiB: mieru `pkg/protocol/segment.go:36` (`maxPDU = 32 * 1024`). |
| `proxy::mieru::packet::EVENT_QUEUE` | 256 | B | Per-session received segment channel 256 on the packet underlay: mieru `pkg/protocol/session.go:45` (`segmentChanCapacity = 256`, used at `:216`). |
| `proxy::mieru::packet::IDLE_BASE` | 120 s | B | Idle underlay lifetime 120 s plus 0-60 s jitter: mieru `pkg/protocol/scheduler.go:28` (`scheduleIdleTime = cipher.KeyRefreshInterval + FixedIntVH(61) s`, KeyRefreshInterval 2 min). |
| `proxy::mieru::packet::INBOUND_QUEUE` | 256 | B | mieru buffers segmentChanCapacity = 256 segments between the underlay input loop and a session (`pkg/protocol/session.go:45`, `recvChan` `:216`); same value. |
| `proxy::mieru::packet::KEY_LIFE` | 60 s | B | Packet underlay scheduling lifetime 60 s: mieru `pkg/protocol/underlay_packet.go:103` (`SetRemainingTime(cipher.KeyRefreshInterval / 2)`, 2 min / 2). |
| `proxy::mieru::packet::TICK` | 5 s | B | Idle/cleanup check period 5 s: mieru `pkg/protocol/underlay_base.go:39` (`sessionCleanInterval = 5 * time.Second`), also `mux.go:42` underlayCleanInterval 5 s. |
| `proxy::mieru::session::ACK_DELAY` | 1 ms | B | ACK delay 1 ms: mieru `pkg/protocol/session.go:70` (`packetAckDelay = 1 * time.Millisecond`). |
| `proxy::mieru::session::BACK_OFF` | 1.5 | B | Send-timeout back-off multiplier 1.5: mieru `pkg/protocol/session.go:82` (`txTimeoutBackOff = 1.5`). |
| `proxy::mieru::session::BURST` | 128 | C | Segments drained with try_recv after one recv before the session task runs output again. try_recv takes no Tokio coop budget, so the drain bounds itself at Tokio's per-poll budget of 128 operations (tokio `src/task/coop/mod.rs:116`), the work a task does before Tokio makes it yield. mieru reads input on its own goroutine (`pkg/protocol/session.go:711-728`), so it has no counterpart. |
| `proxy::mieru::session::CLOSE_DRAIN` | 1 s | B | mieru queues the close request behind data and waits up to 1000 x 1 ms for it to be sent, then sends it and does not wait for the response (`pkg/protocol/session.go:1355-1385`); same bound, no response wait. |
| `proxy::mieru::session::EARLY_RETRANSMISSION` | 3 | B | ACK count triggering early retransmission 3: mieru `pkg/protocol/session.go:78` (`earlyRetransmission = 3`). |
| `proxy::mieru::session::EARLY_RETRANSMISSION_LIMIT` | 1 | B | Max early retransmissions 1: mieru `pkg/protocol/session.go:80` (`earlyRetransmissionLimit = 1`). |
| `proxy::mieru::session::HEARTBEAT` | 5 s | B | Session heartbeat 5 s: mieru `pkg/protocol/session.go:57` (`sessionHeartbeatInterval = 5 * time.Second`). |
| `proxy::mieru::session::HEARTBEAT_JITTER_MS` | 1000 | B | Heartbeat jitter 1000 ms: mieru `pkg/protocol/session.go:58` (`sessionHeartbeatJitterMs = 1000`). |
| `proxy::mieru::session::MAX_BACK_OFF` | 10 s | B | Max back-off 10 s: mieru `pkg/protocol/session.go:84` (`maxBackOffDuration = 10 * time.Second`). |
| `proxy::mieru::session::MIN_OUTPUT` | 1 ms | B | Minimum interval between output loops 1 ms: mieru `pkg/protocol/session.go:61` (`minOutputInterval = 1 * time.Millisecond`). |
| `proxy::mieru::session::MIN_WINDOW` | 16 | B | Minimum congestion window 16 segments: mieru `pkg/protocol/session.go:53` (`minWindowSize = 16`). |
| `proxy::mieru::session::RETRANSMISSION_CHECK` | 10 ms | B | First retransmission check delay 10 ms: mieru `pkg/protocol/session.go:75` (`retransmissionCheckDelay = 10 * time.Millisecond`). |
| `proxy::mieru::session::SEND_QUEUE` | 1024 | B | Send queue capacity 1024 segments: mieru `pkg/protocol/session.go:51` (`segmentSendQueueTreeCapacity = 1024`). |
| `proxy::mieru::session::SILENCE_LIMIT` | 60 s | B | mieru fails a session with no receive for idleSessionTimeout = 1 minute (`pkg/protocol/underlay_packet.go:40`, checked `:832`); same value. |
| `proxy::mieru::session::TREE` | 4096 | B | Segment tree / max window 4096: mieru `pkg/protocol/session.go:48` (`segmentTreeCapacity = 4096`). |
| `proxy::mieru::session::TX_LIMIT` | 20 | B | Max transmissions before session is dead 20: mieru `pkg/protocol/segment.go:39` (`txCountLimit = 20`). |
| `proxy::mieru::stream::RESPONSE_TIMEOUT` | 10 s | B | Server open-session response timeout 10 s: mieru `pkg/protocol/session.go:56` (`serverRespTimeout = 10 * time.Second`). |
| `proxy::mieru::underlay::EVENT_QUEUE` | 256 | B | mieru buffers segmentChanCapacity = 256 segments between the underlay input loop and a session (`pkg/protocol/session.go:45`, `recvChan` `:216`); same value. |
| `proxy::mieru::underlay::IDLE_BASE` | 120 s | B | Idle underlay lifetime 120 s plus 0-60 s jitter: mieru `pkg/protocol/scheduler.go:28` (`scheduleIdleTime = cipher.KeyRefreshInterval + FixedIntVH(61) s`). |
| `proxy::mieru::underlay::TICK` | 5 s | B | Idle check period 5 s: mieru `pkg/protocol/underlay_base.go:39` (`sessionCleanInterval = 5 * time.Second`). |
| `proxy::mieru::underlay::WINDOW` | 4096 | B | Advertised receive window 4096: mieru `pkg/protocol/session.go:54` (`maxWindowSize = segmentTreeCapacity`, 4096 at `:48`). |
| `proxy::quic::DATAGRAM_QUEUE` | 128 | B | quic-go keeps maxDatagramRcvQueueLen = 128 received datagrams per connection and drops beyond it (sing-box's quic-go `datagram_queue.go:14`, `:98`), the stack sing-quic and mihomo's QUIC clients run; same count, turned into quinn's byte budget by the advertised frame size. |
| `proxy::quic::HANDSHAKE_IDLE` | 5 s | B | Handshake bound 5 s: quic-go `internal/protocol/params.go:103` (`DefaultHandshakeIdleTimeout = 5 * time.Second`), the quic-go default mihomo and sing-box dial with. |
| `proxy::quic::INITIAL_PACKET_SIZE` | 1280 | B | quic-go InitialPacketSize = 1280 (`internal/protocol/params.go:12`), which sing-quic multiplies the BBR initial window by (`hysteria2/client.go:604-605`) as mihomo does for TUIC and ShadowQUIC (`transport/tuic/common/congestion.go:48`, `transport/shadowquic/congestion.go:20`); same value. |
| `proxy::quic::INITIAL_WINDOW` | 40960 | B | Cubic initial window 32 x 1280: quic-go `internal/congestion/cubic_sender.go:20` (`initialCongestionWindow = 32`, multiplied by the initial datagram size at `:84`) and `internal/protocol/params.go:12` (`InitialPacketSize = 1280`). |
| `proxy::quic::bbr::MIN_RTT_EXPIRY` | 10 s | B | BBR min_rtt expiry 10 s: mihomo `transport/tuic/congestion_v2/bbr_sender.go:51` (`minRttExpiry = 10 * time.Second`). |
| `proxy::quic::bbr::PACING_GAIN` | `[1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]` | B | BBR PROBE_BW gain cycle [1.25, 0.75, 1 x6]: mihomo `transport/tuic/congestion_v2/bbr_sender.go:42` (`pacingGain`), same values. |
| `proxy::quic::bbr::PROBE_RTT_TIME` | 200 ms | B | BBR minimum PROBE_RTT time 200 ms: mihomo `transport/tuic/congestion_v2/bbr_sender.go:53` (`probeRttTime = 200 * time.Millisecond`). |
| `proxy::quic::bbr::STARTUP_GROWTH_TARGET` | 1.25 | B | BBR startup growth target 1.25: mihomo `transport/tuic/congestion_v2/bbr_sender.go:57` (`startupGrowthTarget = 1.25`). |
| `proxy::quic::congestion::MIN_ACK_RATE` | 0.8 | B | Brutal ACK-rate floor 0.8: sing-quic `hysteria2/congestion/brutal.go:17` (`minAckRate = 0.8`). |
| `proxy::quic::congestion::MIN_PACING_DELAY` | 1 ms | B | Brutal minimum pacing delay 1 ms: sing-quic `hysteria2/congestion/pacer.go:13` (`minPacingDelay = time.Millisecond`). |
| `proxy::quic::congestion::MIN_SAMPLES` | 50 | B | Brutal minimum loss samples 50: sing-quic `hysteria2/congestion/brutal.go:16` (`minSampleCount = 50`). |
| `proxy::quic::congestion::SLOT_COUNT` | 5 | B | Brutal one-second packet-info slots 5: sing-quic `hysteria2/congestion/brutal.go:15` (`pktInfoSlotCount = 5`). |
| `proxy::quic::congestion::UNKNOWN_RTT_WINDOW` | 10240 | B | Brutal window when RTT unknown 10240 bytes: sing-quic `hysteria2/congestion/brutal.go:75-76` (`if rtt <= 0 { return 10240 }`). |
| `proxy::quic::obfs::GECKO_DEFAULT_MAX` | 1200 | B | Default Gecko max packet size 1200: sing-quic `hysteria2/gecko.go:23` (`geckoDefaultMaxPacketSize = 1200`). |
| `proxy::quic::obfs::GECKO_DEFAULT_MIN` | 512 | B | Default Gecko min packet size 512: sing-quic `hysteria2/gecko.go:22` (`geckoDefaultMinPacketSize = 512`). |
| `proxy::quic::obfs::MAX_PER_SOURCE` | 8 | B | Gecko pending reassemblies per source 8: sing-quic `hysteria2/gecko.go:26` (`geckoMaxPerSource = 8`). |
| `proxy::quic::obfs::MAX_REASSEMBLY` | 4096 | B | Gecko total pending reassemblies 4096: sing-quic `hysteria2/gecko.go:25` (`geckoMaxReassembly = 4096`). |
| `proxy::quic::obfs::REASSEMBLY_TTL` | 8 s | B | Gecko reassembly lifetime 8 s: sing-quic `hysteria2/gecko.go:24` (`geckoReassemblyTTL = 8 * time.Second`). |
| `proxy::reject::DROP_TIME` | 60 s | B | REJECT-DROP hold equals mihomo `constant/adapters.go:63` DefaultDropTime = 12 * DefaultTCPTimeout, with DefaultTCPTimeout 5 s at `component/dialer/dialer.go:22`, i.e. 60 s (slept in `adapter/outbound/reject.go:140`). |
| `proxy::shadowquic::DEFAULT_CONN_WINDOW` | 67108864 | B | mihomo ShadowQUIC max connection receive window = tuic DefaultConnectionReceiveWindow 67108864 (`transport/tuic/common/congestion.go:13`, used at `adapter/outbound/shadowquic.go:157`). |
| `proxy::shadowquic::DEFAULT_CWND` | 32 | B | mihomo ShadowQUIC CWND default 32 packets (`adapter/outbound/shadowquic.go:124`, also `transport/shadowquic/congestion.go:18`). |
| `proxy::shadowquic::DEFAULT_FRAME` | 1400 | B | mihomo ShadowQUIC MaxDatagramFrameSize default 1400 (`adapter/outbound/shadowquic.go:118`). |
| `proxy::shadowquic::DEFAULT_STREAMS` | 1024 | B | mihomo ShadowQUIC MaxOpenStreams default 1024 (`adapter/outbound/shadowquic.go:121`). |
| `proxy::shadowquic::DEFAULT_STREAM_WINDOW` | 15728640 | B | mihomo ShadowQUIC max stream receive window = tuic DefaultStreamReceiveWindow 15728640 (`transport/tuic/common/congestion.go:12`, used at `adapter/outbound/shadowquic.go:153`). |
| `proxy::shadowquic::MAX_IDLE` | 30 s | B | mihomo ShadowQUIC sets no MaxIdleTimeout, so its quic-go fork (metacubex jls-quic-go) default applies: DefaultIdleTimeout 30 s (`internal/protocol/params.go:100`, applied `config.go:71`). |
| `proxy::shadowquic::NEGOTIATION_TIMEOUT` | 10 s | B | mihomo brutalNegotiationTimeout 10 s (`transport/shadowquic/extension_brutal.go:20`). |
| `proxy::shadowquic::udp::INBOX` | 128 | B | mihomo ShadowQUIC association input channel packetInputQueue = 128 (`transport/shadowquic/packet.go:14`, `:42`). |
| `proxy::shadowquic::udp::MAX_PENDING_PER_ID` | 32 | B | mihomo ShadowQUIC maxPendingPacketsPerID = 32 (`transport/shadowquic/state.go:14`). |
| `proxy::shadowquic::udp::WRITER_QUEUE` | 64 | C | ShadowQUIC control entries and stream-mode packets wait for the writer: a drop-on-full queue between a session's sender and its writer task absorbs one burst the sender hands over before the writer runs; a sender hands at most one tunnel round, `tunnel::udp::batch::BATCH_DATAGRAMS` = 64 (`crates/tunnel/src/udp/batch.rs::BATCH_DATAGRAMS`), the depth sing-quic gives each session's packet queue (`tuic/packet.go:147`). |
| `proxy::smux::QUEUE` | 128 | B | mihomo queues a UDP session's packets in senderCapacity = 128 (`tunnel/tunnel.go:37`, `tunnel/connection.go:31`), the same queue between a packet session and its sender; same value. |
| `proxy::smux::TCP_TIMEOUT` | 5 s | B | sing-mux client tcpTimeout default 5 s (sing-mux v0.3.12 `client.go:68-69`), which mihomo's singmux uses. |
| `proxy::snell::stream::READ_CHUNK` | 17408 | B | Use the same 17 * 1024-byte read fragment as mihomo's classic Snell AEAD stream (`transport/shadowsocks/shadowaead/stream.go:16`, payloadSizeMask 0x3FFF `:15`). The incremental opener accumulates multiple fragments for larger v6 records (Alpha `3c0d10a5` `transport/snell/v6.go:67`). |
| `proxy::snell::udp::READ_CHUNK` | 17408 | B | Snell UDP shares the 17 * 1024-byte read fragment of mihomo's classic AEAD stream (`transport/shadowsocks/shadowaead/stream.go:16`); the opener accumulates fragments when a v6 record exceeds that size (Alpha `3c0d10a5` `transport/snell/v6.go:67`). |
| `proxy::ss::udp::SERVER_SESSION_SECS` | 60 | B | sing-shadowsocks2 keeps the previous server session of a UDP association and refuses a new one while the previous was heard from within 60 s, `c.method.time().Unix()-c.session.lastRemoteSeen < 60` (`shadowaead_2022/method.go:596`); same value. |
| `proxy::ss::window::RING_BLOCKS` | 128 | B | sing-shadowsocks2 filters replayed SS2022 UDP packet ids with a ring of swRingBlocks = 1 << 7 64-bit blocks, a window of (128 - 1) × 64 = 8128 ids (`shadowaead_2022/slidingwindow.go:5`, `:9`); same ring. |
| `proxy::ssh::DISCONNECT_TIMEOUT` | 5 s | B | mihomo Alpha `3c0d10a5` dials a node, its SSH session included (`adapter/outbound/ssh.go:44-45`), under DefaultTCPTimeout = 5 s (`component/dialer/dialer.go:22`, applied `tunnel/tunnel.go:581`); Concord bounds the SSH_MSG_DISCONNECT it queues for a session a reset overtook by the same value, after which the session is dropped. mihomo itself closes the TCP connection without one. |
| `proxy::ssr::obfs::MAX_HEADER` | 32768 | B | mihomo looks for the http_simple response head in one RelayBufferSize = 32 KiB read (`transport/ssr/obfs/http_simple.go:56-58`, `common/pool/buffer_standard.go:8`); same bound. |
| `proxy::ssr::obfs::Tls::flight_len::MAX_FLIGHT` | 32768 | B | Analogue: mihomo takes one read of RelayBufferSize = 32 KiB as the whole tls1.2_ticket_auth server flight (`transport/ssr/obfs/tls1.2_ticket_auth.go:52-55`, `common/pool/buffer_standard.go:8`); the record walk stops where that read would. |
| `proxy::ssr::stream::READ_CHUNK` | 32768 | B | mihomo reads an SSR protocol stream into one RelayBufferSize = 32 KiB buffer per read (`transport/ssr/protocol/stream.go:22-24`, `common/pool/buffer_standard.go:8`); same size. |
| `proxy::stack::EPHEMERAL_END` | 60999 | B | sing-tun's ephemeral span ends at 60999 (`stack_go_dial.go:21`), Linux's default ip_local_port_range; same value. |
| `proxy::stack::EPHEMERAL_START` | 32768 | B | sing-tun goEphemeralPortBase = 32768 (`stack_go_dial.go:20`); same value. |
| `proxy::stack::MAX_TX_BACKLOG` | 256 | B | sing-tun's MemoryTun holds 2 x batchSize = 256 data packets per peer for wireguard-go (`tun_memory_queue.go:33`, `memoryTunDefaultBatchSize = 128` `tun_memory.go:12`), the device sing-box gives WireGuard; same value. |
| `proxy::stack::OUTBOUND_QUEUE` | 1024 | B | wireguard-go QueueOutboundSize = QueueInboundSize = 1024 (sing-box's wireguard-go `device/queueconstants_default.go:14-15`); same value. |
| `proxy::stack::RX_BATCH` | 64 | B | sing-tun goReadBatch = 64 (`stack_go_profile_default.go:14`), packets its stack takes per read; same value. |
| `proxy::stack::UDP_RECEIVE_CAPACITY` | 212992 | B | sing-tun charges a userspace UDP socket's queued datagrams in bytes up to goUDPReceiveCapacity = 212992 (`stack_go_udp_socket.go:26`, checked `:175`), the stack sing-box runs WireGuard over; same value, also in bytes. |
| `proxy::tuic::DEFAULT_CONN_WINDOW` | 67108864 | B | mihomo TUIC max connection receive window DefaultConnectionReceiveWindow 67108864 (`transport/tuic/common/congestion.go:13`, applied `adapter/outbound/tuic.go:217`). |
| `proxy::tuic::DEFAULT_CWND` | 32 | B | mihomo TUIC CWND default 32 (`adapter/outbound/tuic.go:179`, also `transport/tuic/common/congestion.go:18`). |
| `proxy::tuic::DEFAULT_STREAM_WINDOW` | 15728640 | B | mihomo TUIC max stream receive window DefaultStreamReceiveWindow 15728640 (`transport/tuic/common/congestion.go:12`, applied `adapter/outbound/tuic.go:213`). |
| `proxy::tuic::MAX_FRAG_V5` | `1200 - wire::V5_OVERHEAD - 3` | B | Same formula as mihomo MaxFragSize = 1200 - PacketOverHead - 3 (`transport/tuic/v5/frag.go:17`, quic-go 1200 datagram minus DatagramFrame overhead). mihomo applies it to its server relay size (`transport/tuic/server.go:234`); its client refragments on DatagramTooLargeError instead. |
| `proxy::tuic::MAX_FRAME` | 1400 | B | mihomo TUIC caps MaxDatagramFrameSize at 1400 (`adapter/outbound/tuic.go:191-192`). |
| `proxy::tuic::MAX_IDLE` | 30 s | B | mihomo TUIC sets no MaxIdleTimeout, so quic-go (metacubex fork) DefaultIdleTimeout 30 s applies (`internal/protocol/params.go:100`, `config.go:71`). |
| `proxy::tuic::MAX_OPEN_STREAMS` | 100 | B | mihomo TUIC MaxOpenStreams default 100 (`adapter/outbound/tuic.go:175`), raised 1.1x for the QUIC stream limit at `:198`. |
| `proxy::tuic::UDP_PACKET` | 1252 | B | mihomo TUIC MaxUdpRelayPacketSize default 1252 (`adapter/outbound/tuic.go:171`). |
| `proxy::tuic::conn::IDLE_CLOSE` | 1800 s | B | mihomo TUIC pool closes a non-best client with no open streams idle for 30 min (`transport/tuic/pool_client.go:103`). |
| `proxy::tuic::conn::MAX_STREAM_PACKET` | 65804 | B | sing-quic reads one TUIC Packet command per uni stream, its payload sized by a 16-bit length (`tuic/packet.go:475-484`): 2-byte head, 8-byte packet header, an address of at most 259 bytes and 65535 bytes of data. |
| `proxy::tuic::conn::QUEUE` | 64 | B | sing-quic's TUIC session queue `make(chan *udpMessage, 64)` (`tuic/packet.go:147`), dropping when full (`:283-287`); same value. |
| `proxy::tuic::udp::WRITER_QUEUE` | 64 | C | TUIC quic-mode frames wait for the uni-stream writer: a drop-on-full queue between a session's sender and its writer task absorbs one burst the sender hands over before the writer runs; a sender hands at most one tunnel round, `tunnel::udp::batch::BATCH_DATAGRAMS` = 64 (`crates/tunnel/src/udp/batch.rs::BATCH_DATAGRAMS`), the depth sing-quic gives each session's packet queue (`tuic/packet.go:147`). |
| `proxy::tuic::wire::DEFRAG_TTL` | 10 s | B | mihomo TUIC v5 deFragger LRU entry age 10 s (`transport/tuic/v5/frag.go:69`, seconds per `common/lru/lrucache.go:57`). |
| `proxy::vless::encryption::record::MAX_PLAINTEXT` | 8192 | B | mihomo `transport/vless/encryption/common.go:46-52` splits writes at 8192 to avoid another copy on peer reads. |
| `proxy::vmess::stream::MIN_BUFFER` | 16384 | B | sing-vmess reads the body through a chunk reader of ReadChunkSize = 16384 (`protocol.go:26`), as mihomo's sing-vmess does; same size. |
| `proxy::wireguard::amnezia::TRAILER_WINDOW` | 500 | B | Random trailer padding window 500 equals mihomo amneziawg-go (wireguard-go fork, metacubex 0c1c6f40) DefaultUdpWindow 500 (`device/constants.go:27`, used `device/send.go:561-564`). |
| `proxy::wireguard::amnezia::template::MAX_RANDOM` | 1000 | B | Template random-piece size limit 1000 as mihomo amneziawg-go (wireguard-go fork, metacubex 0c1c6f40) `device_v1/awg/tag_generator.go:73-74`. |
| `proxy::wireguard::amnezia::template::MAX_WAIT_MS` | 5000 | B | Template wait limit 5000 ms as mihomo amneziawg-go (wireguard-go fork, metacubex 0c1c6f40) `device_v1/awg/tag_generator.go:206-207`. |
| `proxy::wireguard::config::DEFAULT_MTU` | 1408 | B | mihomo WireGuard MTU default 1408 (`adapter/outbound/wireguard.go:457-458`). |
| `proxy::wireguard::config::MAX_MTU` | 65495 | B | wireguard-go caps the MTU at MaxContentSize = 65495 (sing-box's wireguard-go `device/constants.go:32`, applied `device/tun.go:31-33`); sing-box and mihomo set no other bound. Same value. |
| `proxy::wireguard::dns::MAX_CACHE` | 4096 | B | mihomo's DNS cache holds CacheMaxSize = 4096 entries by default (`dns/resolver.go:488-490`); same value. |
| `proxy::wireguard::dns::QUERY_TIMEOUT` | 5 s | B | mihomo races every nameserver under DefaultDNSTimeout = 5 s (`dns/util.go:417-418`, `component/resolver/resolver.go:38`), the resolver its WireGuard remote-dns-resolve builds (`adapter/outbound/wireguard.go:489-492`); same bound, same race. |
| `proxy::wireguard::dns::SECOND_ANSWER_GRACE` | 100 ms | B | mihomo waits 100 ms for the AAAA answer after A (`dns/resolver.go:90-95`); same value. |
| `proxy::wireguard::tunnel::IDLE_TICK` | 90 s | C | A tunnel is retired after two quiet ticks, idle at least 180 s = wireguard-go RejectAfterTime (`device/constants.go:22`): past that, reusing the tunnel needs a new handshake anyway, so retiring sooner only adds handshakes. sing-box keeps the device up (`transport/wireguard/endpoint.go:279-285`). |
| `tls::jls::HANDSHAKE_TIMEOUT` | 5 s | B | JLS handshake and synchronous fallback share the tunnel dial context: mihomo Alpha `3c0d10a5` `tunnel/tunnel.go:581-584` uses DefaultTCPTimeout, `component/dialer/dialer.go:22` 5 s; fallback uses the dial context at `transport/jls/utls.go:110,120-149`. |
| `tls::boring_backend::MAX_DECOMPRESSED_CERTS` | 16777215 | A | RFC 8879 §4: a CompressedCertificate's uncompressed_length is a uint24, so a decompressed Certificate is at most 2^24 - 1 bytes. |
| `tls::reality::handshake::MAX_CERTIFICATE_MESSAGE` | 262144 | B | mihomo's utls maxHandshakeCertificateMsg = 262144 for Certificate messages (metacubex/utls v1.8.8 `common.go:69`, applied `conn.go:1164`); same value. |
| `tls::reality::handshake::MAX_DECOMPRESSED` | 16777215 | A | RFC 8879 §4: a CompressedCertificate's uncompressed_length is a uint24, so a decompressed Certificate is at most 2^24 - 1 bytes. |
| `tls::reality::handshake::MAX_HANDSHAKE` | 65536 | B | mihomo's utls maxHandshake = 65536 (metacubex/utls v1.8.8 `common.go:68`), the per-message bound in mihomo's REALITY client; same value. |
| `tls::record::MAX_HANDSHAKE_MESSAGE` | 65536 | B | mihomo's TLS maxHandshake = 65536 (metacubex/tls v0.1.9 `common.go:66`), as Go crypto/tls `common.go:71` that sing-box runs: the bound on a post-handshake message; same value. |
| `tls::record::MAX_USELESS_RECORDS` | 16 | B | Consecutive non-advancing records before failing; Go `crypto/tls/common.go:73` maxUselessRecords = 16. |
| `tls::record::MAX_WRITE` | 114688 | C | Plaintext one write seals = (MAX_WRITE_SLICES - 1) x 16 KiB records (`crates/tls/src/record.rs::MAX_WRITE_SLICES`): the sealed records plus a KeyUpdate answer leave in one writev, one slice each. Go seals the whole caller buffer before writing (crypto/tls `conn.go::writeRecordLocked`), so there is no Go cap to take. |
| `tls::record::MAX_WRITE_SLICES` | 8 | C | Linux UIO_FASTIOV = 8 (`include/uapi/linux/uio.h:26`, as `net::relay::TCP_BATCH_BUFFERS` reads it): a writev of up to 8 slices imports them on the stack, so sealed records go out 8 per call. |
| `tls::rustls_backend::HANDSHAKE_READ` | 18437 | A | Initial handshake input buffer = one maximal TLS 1.2 record on the wire, RFC 5246 §6.2.3 (2^14 + 2048) plus the 5-byte header; Go `crypto/tls/common.go:68` maxCiphertext = 16384 + 2048. |
| `tls::rustls_backend::MAX_HANDSHAKE_BUFFER` | 83976 | C | rustls joins a split handshake message in the input buffer and refuses one above MAX_HANDSHAKE_SIZE = 0xffff (rustls 0.23.46 `src/msgs/deframer/handshake.rs:376`): the buffer holds that message, its 4-byte header and the record being read, `crates/tls/src/rustls_backend.rs::HANDSHAKE_READ` = 18437. |
| `transport::gun::CONN_WINDOW` | 1073807359 | B | Gun h2 connection window 65535 + 1 GiB = Go HTTP/2 client default that mihomo runs for gun: metacubex/http v0.1.8 `h2_bundle.go:7358` transportDefaultConnFlow 1 << 30 on top of `:3553` initialWindowSize 65535. |
| `transport::gun::MAX_FRAME_SIZE` | 1048576 | B | Gun h2 SETTINGS_MAX_FRAME_SIZE 1 MiB = Go HTTP/2 default mihomo runs: metacubex/http v0.1.8 `h2_bundle.go:3555` defaultMaxReadFrameSize 1 << 20. |
| `transport::gun::MAX_HEADER_LIST_SIZE` | 10485760 | B | Gun h2 max header list 10 MiB = Go HTTP/2 client default mihomo runs: metacubex/http v0.1.8 `h2_bundle.go:7522` maxHeaderListSize returns 10 << 20. |
| `transport::gun::frame::MAX_MESSAGE` | 32768 | B | mihomo writes each Write as one gRPC message (`transport/gun/gun.go:134-146`) and its relay writes at most RelayBufferSize = 32 KiB at a time (mihomo `common/pool/buffer_standard.go:8`, sing BufferSize `common/buf/buffer_standard.go:6`); same size. |
| `transport::h2io::CONN_WINDOW` | 1073807359 | B | Go HTTP/2 client default 65535 + transportDefaultConnFlow 1 GiB, which mihomo runs for xhttp and h2 (metacubex/http v0.1.8 `h2_bundle.go:7358`, mihomo `transport/xhttp/client.go:210-228`); same value as `transport::gun::CONN_WINDOW`. |
| `transport::h2io::MAX_WRITE` | 524288 | B | Go's HTTP/2 client copies a request body in chunks of at most 512 KiB (mihomo's metacubex/http v0.1.8 `h2_bundle.go:9138` frameScratchBufferLen, the x/net client sing-box runs); h2 splits them at the peer's frame size as Go does. Same value. |
| `transport::h2io::PING_TIMEOUT` | 15 s | B | h2 keepalive ping answer timeout 15 s; Go HTTP/2 PingTimeout default 15 s (metacubex/http v0.1.8 `h2_bundle.go:1134`, used by mihomo). |
| `transport::h2io::STREAM_WINDOW` | 4194304 | B | h2 stream window 4 MiB; Go HTTP/2 client transportDefaultStreamFlow 4 << 20 (metacubex/http v0.1.8 `h2_bundle.go:7363`, `:1131`), which mihomo runs for gun/h2. |
| `transport::http1::MAX_HEAD` | 10 MiB | B | Go's Transport caps a response head at 10 << 20 by default (`net/http/transport.go:336-341`), the client mihomo's HTTP-upgrade transports read with; same value. |
| `transport::http1::READ_CHUNK` | 4096 | B | Go's Transport reads a connection through a 4 << 10 bufio reader by default (`net/http/transport.go:329-334`), which mihomo's HTTP-upgrade transports use; same size. |
| `transport::session_socket::SESSION_QUEUE` | 256 | B | quic-go drops a received packet once MaxConnUnprocessedPackets = 256 wait for a connection (`internal/protocol/params.go:49`, `connection.go:1985-1990`); Concord's receive queue holds and drops the same way. The send queue takes the same depth: quic-go writes to its PacketConn directly and has no dropping send queue to take a value from. |
| `transport::singmux::h2mux::CONN_WINDOW` | 1073807359 | B | h2mux connection window 65535 + 1 GiB, Go HTTP/2 client default sing-mux uses: x/net v0.35.0 `http2/transport.go:43` transportDefaultConnFlow 1 << 30, `http2/config.go:103`. |
| `transport::singmux::h2mux::IDLE_TIMEOUT` | 30 s | B | h2mux idle ping interval 30 s; sing-mux `h2mux.go:23` idleTimeout 30 s used as ReadIdleTimeout (`h2mux.go:179`) (metacubex/sing-mux v0.3.12). |
| `transport::singmux::h2mux::MAX_FRAME_SIZE` | 32768 | B | h2mux SETTINGS_MAX_FRAME_SIZE 32 KiB; sing-mux `h2mux.go:180` MaxReadFrameSize buf.BufferSize = 32 KiB (sing v0.5.8 `common/buf/buffer_standard.go:6`). |
| `transport::singmux::smux::DRAIN_TIMEOUT` | 30 s | B | Single-session close deadline follows metacubex/smux `session.go:43` openCloseTimeout = 30 * time.Second and `stream.go:562` FIN write timeout. The deadline bounds the whole released session writer, including an in-flight PSH. |
| `transport::singmux::smux::MAX_FRAME` | 32768 | B | smux max frame 32768; metacubex/smux d0c8756d (mihomo pin) `mux.go:67` DefaultConfig MaxFrameSize 32768, kept by sing-mux `session.go:128`. |
| `transport::singmux::smux::MAX_RECEIVE_BUFFER` | 4194304 | B | smux session receive buffer 4 MiB; metacubex/smux d0c8756d `mux.go:68` DefaultConfig MaxReceiveBuffer 4194304, kept by sing-mux `session.go:128`. |
| `transport::singmux::smux::QUEUE` | 64 | B | smux hands each frame to its writer and waits for it (sing-box smux `session.go:41` shaper, writer wait in mihomo smux `session.go:671-695`), so its queue never holds more than one frame per writing stream; Concord queues without waiting, so the session queue takes the depth sing-mux's other session protocol uses, yamux sendCh = 64 (hashicorp yamux v0.1.2 `session.go:109`, as `transport::singmux::yamux::QUEUE`). |
| `transport::singmux::wire::FIRST_WRITE_MAX` | 32768 | B | sing-mux sends the whole first Write with the stream request, and its relay writes at most RelayBufferSize = 32 KiB at a time (mihomo `common/pool/buffer_standard.go:8`, sing BufferSize `common/buf/buffer_standard.go:6`); same size. |
| `transport::singmux::yamux::KEEPALIVE` | 30 s | B | yamux keepalive ping interval 30 s; metacubex/yamux dd5f17c0 `mux.go:74` DefaultConfig KeepAliveInterval 30 s, kept by sing-mux `session.go:134` (only smux disables keepalive). |
| `transport::singmux::yamux::MAX_MESSAGE` | 65524 | B | yamux data frame payload max 64 KiB - 12-byte header; metacubex/yamux dd5f17c0 `mux.go:82` MaxMessageSize 64 KiB and `stream.go:181` MaxMessageSize-headerSize. |
| `transport::singmux::yamux::QUEUE` | 64 | B | yamux's session send channel `make(chan *sendReady, 64)` in the version mihomo pins (metacubex/yamux `session.go:142`), as in sing-box's hashicorp yamux v0.1.2 (`session.go:109`); same value. |
| `transport::singmux::yamux::RECV_WINDOW` | 262144 | B | hashicorp/yamux v0.1.2, which sing-mux pins, keeps a stream window fixed at initialStreamWindow = 256 KiB (`mux.go:68` MaxStreamWindowSize, `const.go:125`) and sends an update once half is spent (`stream.go:272-287`); same value and threshold. mihomo's metacubex fork grows it to 16 MiB; sing-box leads. |
| `transport::v2ray_plugin::MAX_DATA` | 32768 | B | mihomo writes each Write as one mux.cool data frame (`transport/v2ray-plugin/mux.go:112-116`) and its relay writes at most RelayBufferSize = 32 KiB at a time (mihomo `common/pool/buffer_standard.go:8`, sing BufferSize `common/buf/buffer_standard.go:6`); same size. |
| `transport::v2ray_plugin::MAX_META` | 512 | B | mux.cool metadata length cap 512; mihomo `transport/v2ray-plugin/mux.go:65` rejects metalen > 512. |
| `transport::ws::frame::MAX_DATA_FRAME` | 32768 | B | mihomo writes each Write as one WebSocket message (`transport/vmess/websocket.go:105-106`) and its relay writes at most RelayBufferSize = 32 KiB at a time (mihomo `common/pool/buffer_standard.go:8`, sing BufferSize `common/buf/buffer_standard.go:6`); same size. |
| `proxy::link::xhttp_quic::IDLE_TIMEOUT` | 300 s | B | mihomo Alpha `3c0d10a5` `transport/xhttp/client.go:27,171` ConnIdleTimeout. |
| `proxy::link::xhttp_quic::KEEP_ALIVE` | 10 s | B | mihomo Alpha `3c0d10a5` `transport/xhttp/client.go:30,160-166` QuicgoH3KeepAlivePeriod; disabled for negative input, positive input capped at local idle/2; metacubex/quic-go `2548683b76f4` `connection.go:2432-2436` instead uses negotiated idle/2 (Quinn exposes neither a getter nor a post-connect keepalive setter). |
| `transport::xhttp::h1::MAX_LINE` | 4096 | B | xhttp HTTP/1 chunk-size line cap 4096; Go `net/http/internal/chunked.go:19` maxLineLength = 4096 (Go 1.27.3), the reader mihomo's xhttp h1 path uses. |
| `transport::xhttp::padding::AVG_HUFFMAN_BYTES_PER_CHAR_BASE62` | 0.8 | B | Estimate of HPACK Huffman bytes per base62 char for x-padding; mihomo `transport/xhttp/xpadding.go:24` avgHuffmanBytesPerCharBase62 = 0.8. |
| `transport::xhttp::padding::VALIDATION_TOLERANCE` | 2 | B | Accepted Huffman-length deviation for x-padding tokens; mihomo `transport/xhttp/xpadding.go:26` validationTolerance = 2. |
| `transport::xhttp::transport::CHROME_H2_KEEP_ALIVE` | 45 s | B | xhttp h2 keepalive ping period 45 s; mihomo `transport/xhttp/client.go:33` ChromeH2KeepAlivePeriod = 45 s (used at `:198`, `:226`). |
| `tun::device::MAX_BATCH` | 64 | B | sing-tun goReadBatch = 64 (`stack_go_profile_default.go:14`), the per-read batch of its Darwin TUN I/O (`stack_go_io_darwin.go:135-136`, `:316`); same value. |
| `tun::device::apple::TunDevice::BATCH` | `concord_platform::UTUN_BATCH` | B | Equals concord_platform::UTUN_BATCH = 64, sing-tun goReadBatch = 64 used for utun recvmsg_x batches (`stack_go_profile_default.go:14`, `stack_go_io_darwin.go:135-136`); same value. |
| `tun::dns::READ_TIMEOUT` | 10 s | B | mihomo DefaultDnsReadTimeout = time.Second * 10 (`component/resolver/relay.go:15`), used by its TUN DNS hijack (`listener/sing_tun/dns.go:33`, `:79`); same value. |
| `tun::route::packages::PER_USER` | 100000 | A | Android runs app id `a` of user `n` as uid `n * PER_USER_RANGE + a`, PER_USER_RANGE = 100000 (Android 36 `android/os/UserHandle.java`); sing-tun's androidUserRange is the same 100000 (`tun_rules.go:18`). |
| `tun::stack::driver::RX_BATCH` | 64 | B | sing-tun goReadBatch = 64 (`stack_go_profile_default.go:14`), the frames one engine burst reads (`stack_go_engine.go:216`, `:641`); same value. |
| `tun::stack::driver::RX_BATCH_START` | 8 | B | sing-tun starts its TUN receive batch at goReceiveBatchMin = 8 and halves no lower (`stack_go_profile_default.go:13`, `stack_go_io_darwin.go:138`, `:342`); same value. |
| `tun::vnet::UDP_RUN_LIMIT` | 32 | B | sing-tun writePacketBatch takes at most goPacketBatchSize = 32 frames (`stack_go_udp.go:22`, `:368`, `stack_go_io_linux.go:535`); same value. |
| `tunnel::route::DNS_TIMEOUT` | 5 s | B | mihomo DefaultDNSTimeout = time.Second * 5 (`component/resolver/resolver.go:38`), the default DNS request timeout; same value. |
| `tunnel::runtime::DEFAULT_UDP_TIMEOUT` | 60 s | B | mihomo udpTimeout = 60 * time.Second (`tunnel/tunnel.go:63`), the UDP NAT session read deadline; same value. |
| `tunnel::runtime::OWNER_CACHE_CAPACITY` | 256 | B | sing-box caches process lookups in a 256-entry LRU keyed by network, source and destination, misses included (`route/router.go:203`, `route/process_cache.go:13-36`); same size, same key. |
| `tunnel::runtime::OWNER_LIFETIME` | 200 ms | B | sing-box gives a process-cache entry a 200 ms lifetime (`route/router.go:204`); same value. |
| `tunnel::sniff::dispatcher::FIRST_BYTE_WAIT` | 1 s | B | mihomo gives the first sniff byte its own 1 s deadline (`component/sniffer/dispatcher.go:226`); same value. |
| `tunnel::sniff::dispatcher::MAX_SNIFF_BUFFER` | 65536 | B | mihomo maxSniffBufferSize = 64 * 1024 (`component/sniffer/dispatcher.go:27`); same value. |
| `tunnel::sniff::dispatcher::READ_CHUNK` | 4096 | B | mihomo sniffs through a bufio.Reader (`common/net/bufconn.go:22`), whose defaultBufSize = 4096 (Go `bufio/bufio.go:19`); same read size. |
| `tunnel::sniff::dispatcher::SNIFF_WAIT` | 1 s | B | mihomo shares a fresh 1 s deadline across candidates after the first byte (`component/sniffer/dispatcher.go:238`); same value. |
| `tunnel::sniff::quic::MAX_CRYPTO_STREAM_OFFSET` | 65536 | B | mihomo maxCryptoStreamOffset = 64 KiB, a resource policy sharing the TCP sniff budget (`component/sniffer/quic_sniffer.go:40`, comment `:31-39`); same value. |
| `tunnel::sniff::quic::QUIC_WAIT` | 3 s | B | mihomo quicWaitConn = time.Second * 3 (`component/sniffer/quic_sniffer.go:29`); same value. |
| `tunnel::sniff::skip_list::CAPACITY` | 128 | B | mihomo sniff skip list lru.WithSize 128 (`component/sniffer/dispatcher.go:329`); same value. |
| `tunnel::sniff::skip_list::FAILURES_BEFORE_SKIP` | 5 | B | mihomo skips sniffing a destination once its failure count > 5 (`component/sniffer/dispatcher.go:141`); same threshold. |
| `tunnel::sniff::skip_list::MAX_AGE` | 600 s | B | mihomo sniff skip list lru.WithAge 600 seconds (`component/sniffer/dispatcher.go:329`); same value. |
| `tunnel::table::RATE_WINDOW` | 1 s | B | mihomo computes per-second traffic from a 1 s ticker (`tunnel/statistic/manager.go:116`); same 1 s rate window. |
| `tunnel::table::REPORT_INTERVAL` | 1 s | B | Traffic report tick, 1 s, as mihomo's statistic manager samples traffic every second (`tunnel/statistic/manager.go:116`); same period. |
| `tunnel::tcp::DIAL_TIMEOUT` | 5 s | B | mihomo DefaultTCPTimeout = 5 * time.Second (`component/dialer/dialer.go:22`), the TCP dial context at `tunnel/tunnel.go:574`; same value. |
| `tunnel::tcp::FIRST_BYTES_MAX` | 4096 | B | mihomo peeks first bytes through bufio.NewReader (`common/net/bufconn.go:22`), Go defaultBufSize = 4096 (`bufio/bufio.go:19`); same size. |
| `tunnel::tcp::FIRST_BYTES_WINDOW` | 200 ms | B | mihomo peeks the client with a 200 * time.Millisecond read deadline while routing and dialing (`tunnel/tunnel.go:548`); same value. |
| `tunnel::udp::ASSOCIATE_TIMEOUT` | 5 s | B | mihomo DefaultUDPTimeout = DefaultTCPTimeout = 5 s (`component/dialer/dialer.go:22-23`), the UDP dial context at `tunnel/tunnel.go:467`; same value. |
| `tunnel::udp::MAX_FLOWS` | 16384 | B | sing-tun's UDP NAT holds UDPNATMax flows, 16384 by default (`stack_go.go:114`, `udp_nat.go:119`), evicting the oldest; same value. |
| `tunnel::udp::OVERFLOW_CAPACITY` | 128 | B | mihomo senderCapacity = 128 (`tunnel/tunnel.go:37`), the per-session PacketSender channel capacity; same value. |
| `tunnel::udp::PENDING_CAPACITY` | 128 | B | mihomo senderCapacity = 128 (`tunnel/tunnel.go:37`), the per-session PacketSender channel capacity; same value. |
| `tunnel::udp::batch::BATCH_DATAGRAMS` | 64 | C | Equals the TUN driver's read batch `RX_BATCH` = 64 (`crates/tun/src/stack/driver.rs::RX_BATCH`, sing-tun goReadBatch `stack_go_profile_default.go:14`): a round holds no more datagrams of one session than one read can bring, so the cap never splits a round. |

## Wire And Format Constants

Numeric constants a protocol, a file format, a platform API or Concord's own host wire format fixes; they are not
tunables. `module::*` covers every constant in that module and its submodules that is not registered above or in
`xtask/tunables.txt`, so it is used only for modules that define nothing else.

| Item or module | Spec |
|---|---|
| `dns::doh3::*` | Largest DNS message, 65535 bytes (16-bit length, RFC 1035 §4.2.2); mihomo `dns/util.go:23` MaxMsgSize 65535 |
| `dns::doq::*` | DoQ message carries a 2-octet length prefix (RFC 9250 §4.2), max 65535; mihomo `dns/doq.go:212` with MaxMsgSize 65535 (`dns/util.go:23`) |
| `dns::lru::*` | ARC algorithm list tag (ghost list B1 of Megiddo-Modha ARC), an index not a tunable; ARC algorithm list tag (ghost list B2), an index not a tunable; Sentinel index (usize::MAX) for an absent linked-list node, not a tunable; ARC algorithm list tag (recency list T1), an index not a tunable; ARC algorithm list tag (frequency list T2), an index not a tunable |
| `engine::probe::region::*` | Record width of the packed ISO 3166 alpha-3 + alpha-2 table (3 + 2 characters) |
| `inbound::socks5::*` | RFC 1928 §4 ATYP domain name = 3; RFC 1928 §4 ATYP IPv4 = 1; RFC 1928 §4 ATYP IPv6 = 4; RFC 1928 §4 CMD CONNECT = 1; RFC 1928 §4 CMD UDP ASSOCIATE = 3; RFC 1928 §7 maximum UDP request header: RSV 2 + FRAG 1 + ATYP 1 + len 1 + 255-byte domain + port 2 |
| `mitm::hostlist::*` | IANA well-known port for https, 443 (RFC 9110 §4.2.2); IANA well-known port for http, 80 (RFC 9110 §4.2.1) |
| `mitm::target::*` | IANA well-known port for https, 443 (RFC 9110 §4.2.2); IANA well-known port for http, 80 (RFC 9110 §4.2.1) |
| `proxy::masque::datagram::HEADER_MAX` | 9 bytes: RFC 9000 §16 maximum QUIC variable integer width (8), plus the zero Context ID (1) of RFC 9484 §4.4; Quarter Stream ID is defined in RFC 9297 §2.1 |
| `netstack::readiness::*` | In-memory readiness bit flags READ=1, WRITE=2, FLAGS=READ or WRITE of Concord's own atomic state word; bit layout, no tuning. |
| `netstack::wire::*` | IP/TCP/UDP header lengths (RFC 791, 8200, 9293, 768), TCP flag bits (RFC 9293 §3.1), IANA protocol numbers, IPv4 MF bit and IPv6 fragment header (RFC 8200 §4.5), 4 SACK blocks fit 40-byte options (RFC 2018 §3), default TTL 64 (RFC 1700). |
| `platform::clock::*` | Windows API GetTimeZoneInformation return code TIME_ZONE_ID_DAYLIGHT = 2 (timezoneapi.h); Unit conversion: seconds from the Windows FILETIME epoch 1601-01-01 to the Unix epoch |
| `platform::netinfo::route_macos::*` | macOS routing-socket constants: RTF_UP/HOST/REJECT/BLACKHOLE/IFSCOPE from `net/route.h:94-119` (macOS SDK) and AF_INET 2 / AF_INET6 30 from `sys/socket.h:398`. |
| `platform::netinfo::route_proc::*` | Linux /proc/net/route flag bits RTF_UP 0x1 and RTF_REJECT 0x200 (linux/route.h). |
| `platform::netinfo::sockaddr::*` | Windows ABI address families AF_INET 2 and AF_INET6 23 (ws2def.h). |
| `platform::netinfo::watch::*` | rtnetlink multicast group bits RTMGRP_LINK/IPV4_IFADDR/IPV4_ROUTE/IPV6_IFADDR/IPV6_ROUTE and their union (linux/rtnetlink.h) |
| `platform::netinfo::win::*` | IANA ifType softwareLoopback = 24 (Windows ipifcons.h IF_TYPE_SOFTWARE_LOOPBACK) |
| `platform::owner::darwin::*` | xnu pcblist_n record kinds XSO_SOCKET/XSO_INPCB and minimum xsocket_n/xinpcb_n sizes (xsocket_n read through so_flags at 84), INP_IPV4/INP_IPV6 (`netinet/in_pcb.h:266-267`, macOS SDK), SS_NOFDREF/SOF_MP_SUBFLOW (xnu `sys/socketvar.h`), PATH_MAX = PROC_PIDPATHINFO_MAXSIZE 4*MAXPATHLEN (`sys/proc_info.h:749`). |
| `platform::owner::linux::*` | Linux sock_diag netlink: NETLINK_SOCK_DIAG 4, SOCK_DIAG_BY_FAMILY 20, NLMSG_ERROR/DONE, NLM_F_REQUEST plus NLM_F_DUMP, nlmsghdr 16 and inet_diag_msg 72 bytes (linux/netlink.h, linux/sock_diag.h, linux/inet_diag.h). |
| `platform::owner::mib::*` | Windows MIB_TCP_STATE_ESTAB = 5 (tcpmib.h). |
| `platform::owner::windows::*` | Windows fixed PIDs System Idle 0 and System 4, and the extended-length path limit 32768 UTF-16 units (Windows file naming API). |
| `platform::transparent::*` | macOS pf direction PF_OUT = 2 for DIOCNATLOOK (net/pfvar.h) |
| `proto::error::*` | JSON-RPC 2.0 error code -32603 Internal error (JSON-RPC 2.0 Specification §5.1); JSON-RPC 2.0 error code -32602 Invalid params (JSON-RPC 2.0 Specification §5.1); JSON-RPC 2.0 error code -32600 Invalid Request (JSON-RPC 2.0 Specification §5.1); JSON-RPC 2.0 error code -32601 Method not found (JSON-RPC 2.0 Specification §5.1); JSON-RPC 2.0 error code -32700 Parse error (JSON-RPC 2.0 Specification §5.1) |
| `proxy::addr_codec::*` | SOCKS5 address encoding max length (atyp 1 + len 1 + 255-byte domain + port 2), RFC 1928 §5 |
| `proxy::anytls::frame::*` | AnyTLS frame command codes 0-10, 7-byte header (cmd 1 + sid 4 + len 2) and u16 length cap: mihomo `transport/anytls/session/frame.go:8-23` |
| `proxy::hysteria::wire::*` | Hysteria v1 wire format: protocol version 3, client hello 1+8+8+2, response and UDP message fixed field lengths; mihomo `transport/hysteria/core/protocol.go:12-40` |
| `proxy::mieru::cipher::*` | mieru key derivation and cipher format: PBKDF2 64 iterations (`pkg/cipher/keygen.go:32`), time-salt refresh 2 min (`keygen.go:38`, both ends must agree), user-hint prefix 16 and suffix 4 (`pkg/cipher/api.go:35-36`), XChaCha20 subkey input 16 |
| `proxy::mieru::meta::*` | mieru segment metadata format: protocol type codes 2-11 (`pkg/protocol/metadata.go:32-41`), metadata 32 bytes and max session-open payload 1024 (`metadata.go:99`, `:102`), XChaCha20-Poly1305 nonce 24 and tag 16 |
| `proxy::mieru::padding::*` | mieru traffic padding shape: low-entropy chunk 8 bytes (`pkg/protocol/low_entropy.go:30`), recommended ASCII run 24 + 0..16 and target probability 0.325 (`pkg/protocol/padding.go:30-31`) |
| `proxy::mieru::pattern::*` | mieru traffic-pattern limits: max padding 255 (`apis/trafficpattern/config.go:30`), nonce length at most 12 (`:264-273`), 31 mask rotations (`:228`, LowEntropyMaskRotation names) |
| `proxy::mieru::udp::*` | mieru packet-over-stream framing 0x00 + length + packet + 0xff: mieru `apis/common/packet_over_stream.go:30`, `:66` |
| `proxy::quic::datagram::*` | QUIC transport parameter ID max_datagram_frame_size 0x20, RFC 9221 §3 |
| `proxy::shadowquic::jls::*` | TLS 1.3 handshake layout (RFC 8446 §4.1.3: 32-byte random at offset 6, ServerHello type 2, 4-byte header, DOWNGRD canaries, HelloRetryRequest random tail) and JLS 16-byte seed. |
| `proxy::shadowquic::wire::*` | ShadowQUIC command bytes and mihomo Brutal extension wire: mihomo `transport/shadowquic/protocol.go:16-21`, `transport/shadowquic/extension_brutal.go:12-19` (opcode, version 1, payload 8..64, rx-auto flag 1). |
| `proxy::snell::frame::*` | Snell AEAD chunk 0x3FFF, mihomo `transport/snell/snell.go:26`; AEAD nonce 12 bytes, mihomo `transport/snell/v4.go:21`; Snell salt 16 bytes, mihomo `transport/snell/v4.go:20`; AEAD (AES-GCM / ChaCha20-Poly1305) tag 16 bytes, RFC 5116 / RFC 8439; Snell v4 frame size 1460, mihomo `transport/snell/v4.go:24` (payload limits at `:295-304`); Snell v4 plain header 7 bytes, mihomo `transport/snell/v4.go:22`; Snell v4 initial padding min 0x100, mihomo `transport/snell/v4.go:25`; Snell v4 initial padding span 0x100, mihomo `transport/snell/v4.go:26` |
| `proxy::socks5::*` | SOCKS5 version, command and auth method codes, RFC 1928 §3-4 and RFC 1929. |
| `proxy::ss::udp::*` | SIP022 MaxPaddingLength 900 for port-53 packets, sing-shadowsocks2 `shadowaead_2022/protocol.go:19`, used `shadowaead_2022/method.go:425`; Largest Shadowsocks AEAD salt (32 bytes for 256-bit ciphers), SIP004 / sing-shadowsocks2 `shadowaead/method.go` key-salt lengths; SIP022 timestamp tolerance 30 s, sing-shadowsocks2 `shadowaead_2022/method.go:585`; SIP022 UDP packet nonce 24 bytes, sing-shadowsocks2 `shadowaead_2022/protocol.go:20` PacketNonceSize; AEAD tag 16 bytes (AES-GCM / ChaCha20-Poly1305), RFC 5116 / RFC 8439; SIP022 HeaderTypeClient 0, sing-shadowsocks2 `shadowaead_2022/protocol.go:17`; SIP022 HeaderTypeServer 1, sing-shadowsocks2 `shadowaead_2022/protocol.go:18` |
| `proxy::ssh::rsa_key::*` | DER of OID rsaEncryption 1.2.840.113549.1.1.1, RFC 8017 Appendix C |
| `proxy::ssr::cipher::*` | SSR 'dummy'/'none' cipher derives a 16-byte key for the protocol layer, as mihomo `adapter/outbound/shadowsocksr.go:130` (core.Kdf(password, 16)) |
| `proxy::trojan::*` | Trojan CommandTCP 1, mihomo `transport/trojan/trojan.go:32`; Trojan CommandUDP 3, mihomo `transport/trojan/trojan.go:33`; Trojan UDP packet maxLength 8192, mihomo `transport/trojan/trojan.go:19` |
| `proxy::tuic::stream::*` | TUIC v4 Response REP 0xff = failed, mihomo `transport/tuic/v4/protocol.go:382`, `:423` |
| `proxy::tuic::wire::*` | TUIC v4/v5 command and address-type codes and packet header overheads, mihomo `transport/tuic/v5/protocol.go:30-37`, `:409-414`, `transport/tuic/v4/protocol.go:30-37`, overhead `v5/protocol.go:330`, `v4/protocol.go:287`. |
| `proxy::uot::*` | UDP-over-TCP legacy protocol version 1, sing `common/uot/protocol.go:14` (metacubex sing v0.5.8) |
| `proxy::vless::stream::*` | VLESS commands (mihomo `transport/vless/vless.go:22-24`) and XTLS Vision wire: TLS record prefixes and TLS 1.3 supported_versions (`transport/vless/vision/filter.go:11-14`), padding header 21, commands 0/1/2, buffer limit 8192 - 21 (`transport/vless/vision/padding.go:15-20`, `:47-50`). |
| `proxy::vmess::crypto::*` | VMess wire: version 1, write chunk 15000, max padding 64, cipher overhead 16, commands 1/2/3, request options 1/4/8/16 (sing-vmess v0.2.5 `protocol.go:25-29`, `:44-54`, `:73`), HMAC-SHA256 block 64 in the AEAD KDF (RFC 2104). |
| `proxy::wireguard::amnezia::mac::*` | WireGuard protocol cookie lifetime 120 s (whitepaper §5.4.7), wireguard-go CookieRefreshTime (metacubex wireguard-go `device/constants.go:24`; amneziawg-go `device/constants.go:24`); WireGuard cookie reply 64 bytes, amneziawg-go `device/noise-protocol.go:68`; WireGuard handshake initiation 148 bytes, amneziawg-go `device/noise-protocol.go:66`; WireGuard mac1/mac2 16 bytes (keyed BLAKE2s-128), WireGuard whitepaper §5.4.4; WireGuard handshake response 92 bytes, amneziawg-go `device/noise-protocol.go:67` |
| `proxy::wireguard::transport::*` | WireGuard message header: 1 type byte + 3 reserved bytes, whitepaper §5.4; reserved bytes rewritten as in mihomo/sing-wireguard reserved option |
| `rules::geo::dat::*` | v2ray geosite Domain.Type Domain = 2 (mihomo `component/geodata/router/config.pb.go:32`); v2ray geosite Domain.Type Full = 3 (mihomo `component/geodata/router/config.pb.go:34`); v2ray geosite Domain.Type Plain = 0 (mihomo `component/geodata/router/config.pb.go:28`); v2ray geosite Domain.Type Regex = 1 (mihomo `component/geodata/router/config.pb.go:30`) |
| `rules::index::*` | FNV-1a 64-bit offset basis 0xcbf29ce484222325 (FNV hash algorithm, draft-eastlake-fnv); FNV 64-bit prime 0x100000001b3 (FNV hash algorithm, draft-eastlake-fnv) |
| `tls::ciphers::*` | AEAD key usage limit, RFC 8446 §5.5 (AES-GCM 2^24.5 records); value as rustls provider `crypto/ring/tls13.rs:48` confidentiality_limit 1 << 24; AEAD key usage limit, RFC 8446 §5.5 (ChaCha20-Poly1305 effectively unbounded); value as rustls provider `crypto/ring/tls13.rs:28` confidentiality_limit u64::MAX; TLS 1.2 AES-GCM explicit nonce 8 bytes, RFC 5288 §3; AEAD nonce 12 bytes, RFC 5116 §5.1 / RFC 8446 §5.3; AEAD tag 16 bytes, RFC 5116 §5.1 / RFC 8439 §2.8 |
| `tls::fingerprints::*` | RFC 8879 §3 cert compression algorithm brotli = 2; metacubex/utls `u_common.go:131`; RFC 8879 §3 cert compression algorithm zlib = 1; metacubex/utls `u_common.go:130`; RFC 8701 GREASE codepoint 0x0a0a; metacubex/utls `u_common.go:715` GREASE_PLACEHOLDER; TLS named group secp256r1 = 23 (RFC 8446 §4.2.7); metacubex/utls `common.go:150`; TLS named group x25519 = 29 (RFC 8446 §4.2.7); metacubex/utls `common.go:153`; TLS named group X25519MLKEM768 = 0x11ec (IANA, draft-ietf-tls-ecdhe-mlkem); metacubex/utls `common.go:154` |
| `tls::options::*` | REALITY protocol short ID max 8 bytes; mihomo `component/tls/reality.go:29` RealityMaxShortIDLen = 8 |
| `tls::reality::hello::*` | ClientHello legacy_session_id 32 bytes, RFC 8446 §4.1.2; Offset of legacy_session_id in the ClientHello handshake message: 4 header + 2 version + 32 random + 1 length (RFC 8446 §4.1.2) |
| `tls::reality::schedule::*` | RFC 8446 §5.1 ContentType alert = 21; RFC 8446 §5.1 ContentType application_data = 23; RFC 8446 §5.1 ContentType handshake = 22; TLS 1.3 record overhead: 5-byte header + 1 inner content type + 16 tag (RFC 8446 §5.2); AEAD tag 16 bytes, RFC 5116 §5.1; RFC 8446 §B.4 cipher suite 0x1301; RFC 8446 §B.4 cipher suite 0x1302; RFC 8446 §B.4 cipher suite 0x1303 |
| `tls::record_io::*` | RFC 5246 §6.2.3 maximum TLSCiphertext length 2^14 + 2048 (0x4800); RFC 8446 §5.1 TLS record header 5 bytes |
| `transport::shadowtls::*` | ShadowTLS v3 wire format: TLS record header 5, content types 21/22/23, max plaintext 16384, ServerHello 2, random 32, session id 32 at 1+3+2+32+1, HMAC 4, alert record 31; mihomo `transport/shadowtls/protocol.go:12-28`, `v3.go:19`, `v3.go:319`. SHA-1 output 20 (FIPS 180-4). |
| `transport::simple_obfs::*` | obfs-tls wraps each chunk as a fake TLS application-data record, so at most 2^14 (RFC 8446 §5.1); mihomo `transport/simple-obfs/tls.go:15` chunkSize 1 << 14 |
| `transport::singmux::padding::*` | sing-mux padding protocol: first 16 frames each way carry padding, both peers must agree; metacubex/sing-mux v0.3.12 `padding.go:16` kFirstPaddings = 16; sing-mux padded frame length is a uint16, so payload chunks are at most 65535; metacubex/sing-mux v0.3.12 `padding.go:95` |
| `transport::xhttp::browser::*` | Browser-masquerade table (Safari minor version by 15-day period), format data copied from mihomo `transport/xhttp/browser.go:24` safariMinorMap; Client-hint order permutations, format data copied from mihomo `transport/xhttp/browser.go:63` clientHintShuffle3; Client-hint order permutations, format data copied from mihomo `transport/xhttp/browser.go:64` clientHintShuffle4 |
| `common::dns_relay::servfail::*` | DNS header bits and codes: QR 0x80, RD 0x01, Opcode mask 0x78, RA 0x80, RCODE SERVFAIL 2 (RFC 1035 §4.1.1). |
| `tun::route::*` | Route and WFP format values: uid end u32::MAX-1 ((uid_t)-1 is invalid), WFP filter weights 13/12/11/10 as sing-tun orders them (`tun_windows.go:264`, `:293`, `:375`, `:413`), ICMPv6 types 133/135/136 (RFC 4861 §4), IPPROTO_ICMPV6 58, ff02::2 (RFC 4291 §2.7.1), RPC_C_AUTHN_DEFAULT (rpcdce.h). |
| `tunnel::sniff::hpack::*` | HPACK Huffman decoding trie built from the RFC 7541 Appendix B code; LEAF is the trie's leaf marker bit. Fixed algorithm table. |
| `tunnel::sniff::hpack_tables::*` | HPACK Huffman code and length tables (RFC 7541 Appendix B) and static table (Appendix A). |
| `tunnel::sniff::http::*` | HTTP/2 frame header 9 bytes, frame types HEADERS 1 / SETTINGS 4 / CONTINUATION 9, flags ACK/END_HEADERS/PADDED/PRIORITY, default max frame 16384 and header table 4096 (RFC 9113 §4.1, §6, §6.5.2). |
| `tunnel::sniff::tls::*` | TLS record header 5, handshake header 4, record type handshake 22, ClientHello type 1, max plaintext 2^14 (RFC 8446 §5.1, §4). |
| `android::platform::IPPROTO_TCP`, `android::platform::IPPROTO_UDP`, `android::platform::PROCFS_FROM_SDK` | IPPROTO_TCP from netinet/in.h, as passed to Android ConnectivityManager.getConnectionOwnerUid; IPPROTO_UDP from netinet/in.h, as passed to Android ConnectivityManager.getConnectionOwnerUid; Android API level 29 (Android 10), from which /proc/net is unreadable to apps and getConnectionOwnerUid applies (Android platform API) |
| `dns::doh::MAX_BODY` | Largest DNS message, 65535 bytes (16-bit length, RFC 1035 §4.2.2); mihomo `dns/util.go:23` MaxMsgSize 65535 |
| `engine::ntp::NANOS`, `engine::ntp::NTP_UNIX_GAP_SECS`, `engine::ntp::PACKET_LEN` | Unit conversion (nanoseconds per second); sing `common/ntp/message.go:40` nanoPerSec; NTP era offset 1900-01-01 to 1970-01-01 in seconds (RFC 5905 §6); NTP packet header length 48 bytes (RFC 5905 §7.3) |
| `group::health::NOT_ALIVE` | mihomo API sentinel delay for a dead proxy, max uint16 0xffff (`adapter/adapter.go:119`) |
| `inbound::socks4::CMD_CONNECT`, `inbound::socks4::GRANTED`, `inbound::socks4::IDENTD_MISMATCHED` | SOCKS4 protocol command code CONNECT = 1; SOCKS4 reply code 90 request granted; SOCKS4 reply code 93 identd user-id mismatch |
| `ipc::auth::NONCE_LEN`, `ipc::auth::PROOF_LEN`, `ipc::auth::TOKEN_LEN` | Concord's own host IPC handshake wire format: nonce length; HMAC-SHA256 output length, 32 bytes (RFC 2104 with SHA-256, FIPS 180-4), in Concord's IPC handshake wire format; Concord's own host IPC handshake wire format: token length |
| `mitm::ca::MAX_COMMON_NAME` | X.509 upper bound ub-common-name = 64 (RFC 5280 Appendix A.1) |
| `mitm::clienthello::EXTENSION_ALPN`, `mitm::clienthello::EXTENSION_SERVER_NAME`, `mitm::clienthello::HANDSHAKE_HEADER_LEN`, `mitm::clienthello::HANDSHAKE_TYPE_CLIENT_HELLO`, `mitm::clienthello::RECORD_HEADER_LEN`, `mitm::clienthello::RECORD_TYPE_HANDSHAKE` | TLS extension code application_layer_protocol_negotiation = 16 (RFC 7301 §3.1); TLS extension code server_name = 0 (RFC 6066 §3); TLS handshake header length 4 (type + 24-bit length, RFC 8446 §4); TLS HandshakeType client_hello = 1 (RFC 8446 §4); TLS record header length 5 (RFC 8446 §5.1); TLS ContentType handshake = 22 (RFC 8446 §5.1) |
| `mitm::limits::PRESSURE_NONE`, `mitm::limits::PRESSURE_NO_BODIES`, `mitm::limits::PRESSURE_NO_SCRIPTS`, `mitm::limits::PRESSURE_RELAY` | Concord's own host wire format: memory-pressure level code set through core.setPressure |
| `netstack::frag::MAX_PAYLOAD` | IPv4 Total Length is 16 bits (RFC 791 §3.1): reassembled payload at most 65535 minus the 20-byte header |
| `netstack::tcp::send::MAX_HEAD` | Largest TCP/IP header: IPv6 header 40 + TCP header 20 + 40 bytes of TCP options (RFC 8200 §3, RFC 9293 §3.1) |
| `platform::udp_batch::MAX_MESSAGE` | Largest IPv4 UDP payload 65535 - 20 - 8 = 65507 (RFC 791, RFC 768); sing-tun uses the same bound (`stack_go_socket_linux.go:168`) |
| `platform::utun::PREFIX` | macOS utun 4-byte address-family prefix; sing-tun PacketOffset = 4 (`tun_darwin.go:27`) |
| `proto::PROTOCOL_VERSION` | Concord's own host RPC wire format version |
| `proxy::anytls::UOT_VERSION` | UDP-over-TCP protocol version 2 requested by AnyTLS UDP, mihomo `adapter/outbound/anytls.go:67` (`uot.RequestDestination(2)`) |
| `proxy::hysteria::CLOSE_AUTH`, `proxy::hysteria::CLOSE_PROTOCOL`, `proxy::hysteria::MBPS` | Hysteria v1 QUIC close code auth error 2: mihomo `transport/hysteria/core/protocol.go:17`; Hysteria v1 QUIC close code protocol error 1: mihomo `transport/hysteria/core/protocol.go:16`; unit conversion Mbps to bytes/s (125000), mihomo `adapter/outbound/hysteria.go:33` (`mbpsToBps = 125000`) |
| `proxy::hysteria2::AUTH_OK` | Hysteria2 HTTP/3 auth success status 233: sing-quic `hysteria2/internal/protocol/http.go:18` (`StatusAuthOK = 233`) |
| `proxy::hysteria2::realm::DEFAULT_STUN_PORT` | STUN default port 3478, RFC 5389 §9; also sing-quic `hysteria2/realm/stun.go:26` |
| `proxy::hysteria2::realm::punch::BODY`, `proxy::hysteria2::realm::punch::MAGIC`, `proxy::hysteria2::realm::punch::MAX_PADDING`, `proxy::hysteria2::realm::punch::NONCE`, `proxy::hysteria2::realm::punch::SALT` | Realm punch body length magic 8 + type 1 + nonce 16: sing-quic `hysteria2/realm/punch.go:38` (`minBodySize`); Realm punch magic HYRLMv1\0: sing-quic `hysteria2/realm/punch.go:43` (`punchMagic`); Realm punch packet padding up to 1024 bytes: sing-quic `hysteria2/realm/punch.go:39` (`maxPadding = 1024`), packet format; Realm punch nonce length 16: sing-quic `hysteria2/realm/punch.go:37` (`nonceLength = 16`); Realm punch salt length 8: sing-quic `hysteria2/realm/punch.go:35` (`saltLength = 8`) |
| `proxy::hysteria2::realm::stun::BINDING_REQUEST`, `proxy::hysteria2::realm::stun::COOKIE`, `proxy::hysteria2::realm::stun::HEADER`, `proxy::hysteria2::realm::stun::XOR_MAPPED_ADDRESS` | STUN Binding request method 0x0001, RFC 5389 §18.1; STUN magic cookie 0x2112A442, RFC 5389 §6; STUN message header 20 bytes, RFC 5389 §6; STUN XOR-MAPPED-ADDRESS attribute 0x0020, RFC 5389 §15.2 |
| `proxy::hysteria2::udp::HEADROOM` | Max Hysteria2 UDP message header: fixed 8 + varint addr length 2 + 255-byte domain + ":65535" 6, sing-quic `hysteria2/packet.go` message format |
| `proxy::hysteria2::wire::FRAME_TCP_REQUEST`, `proxy::hysteria2::wire::MAX_MESSAGE`, `proxy::hysteria2::wire::MAX_PADDING`, `proxy::hysteria2::wire::MAX_RESPONSE_HEAD`, `proxy::hysteria2::wire::MAX_UDP` | Hysteria2 TCP request frame type 0x401: sing-quic `hysteria2/internal/protocol/proxy.go:17`; Hysteria2 max address/message length 2048: sing-quic `hysteria2/internal/protocol/proxy.go:21-22`; Hysteria2 max padding length 4096: sing-quic `hysteria2/internal/protocol/proxy.go:23`; Max TCP response head derived from protocol limits: status 1 + varint 8 + message 2048 + varint 8 + padding 4096 (sing-quic `hysteria2/internal/protocol/proxy.go:22-23`); Hysteria2 max UDP size 4096: sing-quic `hysteria2/internal/protocol/proxy.go:25` (`MaxUDPSize = 4096`) |
| `proxy::mieru::CONNECT`, `proxy::mieru::MAX_CREDENTIAL`, `proxy::mieru::UDP_ASSOCIATE` | SOCKS5 CONNECT command code 1 carried in mieru's SOCKS5 request, RFC 1928 §4; mieru user name length limit 64 (also bounds password): mieru `apis/constant/user.go:19` (`MaxUserNameLen = 64`); SOCKS5 UDP ASSOCIATE command code 3, RFC 1928 §4 |
| `proxy::mieru::packet::MAX_PADDING`, `proxy::mieru::packet::NON_HEADER`, `proxy::mieru::packet::PACKET_OVERHEAD` | mieru padding length cap 255 (one-byte length field): mieru `pkg/protocol/padding.go:98`, `:105`; mieru packet non-header position nonce + metadata + tag: mieru `pkg/protocol/underlay_packet.go:38` (`packetNonHeaderPosition`); mieru packet overhead nonce + metadata + 2 tags: mieru `pkg/protocol/underlay_packet.go:37` (`packetOverhead`) |
| `proxy::mieru::session::MAX_OPEN_PAYLOAD` | Alias of meta::MAX_OPEN_PAYLOAD, mieru max session-open payload 1024 (`pkg/protocol/metadata.go:102`) |
| `proxy::mieru::underlay::STREAM_OVERHEAD` | mieru stream segment overhead metadata + 2 tags (stream underlay segment format, `pkg/protocol/underlay_stream.go`) |
| `proxy::quic::obfs::FRAGMENT_FLAG`, `proxy::quic::obfs::GECKO_HEADER`, `proxy::quic::obfs::GECKO_MAX_CHUNKS`, `proxy::quic::obfs::GECKO_MAX_ON_WIRE`, `proxy::quic::obfs::GECKO_MIN_CHUNKS`, `proxy::quic::obfs::MASK_LEN`, `proxy::quic::obfs::SALT_LEN`, `proxy::quic::obfs::WECHAT_HEADER`, `proxy::quic::obfs::XPLUS_SALT` | Gecko obfs fragment flag 0x80: sing-quic `hysteria2/gecko.go:17` (`geckoFragmentFlag`); Gecko fragment header length 5: sing-quic `hysteria2/gecko.go:18` (`geckoHeaderLen = 5`); Gecko max fragments per packet 8 (receiver rejects more): sing-quic `hysteria2/gecko.go:20` (`geckoMaxChunks = 8`); Gecko max on-wire packet size 2048: sing-quic `hysteria2/gecko.go:21` (`geckoMaxOnWireSize = 2048`); Gecko min fragments per packet 2 (receiver rejects fewer): sing-quic `hysteria2/gecko.go:19` (`geckoMinChunks = 2`); Salamander BLAKE2b-256 mask length 32: sing-quic `hysteria2/salamander.go:37` (`blake2b.Sum256`); Salamander salt length 8: sing-quic `hysteria2/salamander.go:13` (`salamanderSaltLen = 8`); Hysteria 1 wechat-video obfs header bytes: mihomo `transport/hysteria/conns/wechat/obfs.go:60-70`; Hysteria 1 XPlus obfs salt length 16: mihomo `transport/hysteria/obfs/xplus.go:10` (`saltLen = 16`) |
| `proxy::gost_relay::wire::*` | gost relay version 1, CONNECT 1, CONNECT with UDP flag 0x81; authentication/address/network feature types 1/2/4; TCP/UDP network values 0/1; mihomo `transport/gost/relay.go:23-49,231-285` |
| `proxy::snell::CONNECT`, `proxy::snell::CONNECT_V2`, `proxy::snell::PROTOCOL`, `proxy::snell::UDP` | Snell CommandConnect 1, mihomo `transport/snell/snell.go:31`; Snell CommandConnectV2 5, mihomo `transport/snell/snell.go:32`; Snell request version byte 1, mihomo `transport/snell/snell.go:40`; Snell CommandUDP 6, mihomo `transport/snell/snell.go:33` |
| `proxy::snell::stream::REPLY_ERROR`, `proxy::snell::stream::REPLY_TUNNEL` | Snell reply CommandError 2, mihomo `transport/snell/snell.go:38`; Snell reply CommandTunnel 0, mihomo `transport/snell/snell.go:36` |
| `proxy::snell::udp::FORWARD` | Snell CommondUDPForward 1, mihomo `transport/snell/snell.go:34` |
| `proxy::ssr::obfs::MAX_RECORD`, `proxy::ssr::obfs::Tls::flight_len::CHANGE_CIPHER_SPEC` | TLS record plaintext limit 2^14 for application_data records held before the tls1.2_ticket_auth handshake, RFC 5246 §6.2.1; TLS ContentType change_cipher_spec(20), RFC 5246 §6.2.1 |
| `proxy::vmess::NETWORK_UDP`, `proxy::vmess::STATUS_END`, `proxy::vmess::STATUS_KEEP`, `proxy::vmess::STATUS_KEEP_ALIVE`, `proxy::vmess::STATUS_NEW` | VMess mux NetworkUDP 2, sing-vmess v0.2.5 `protocol.go:84`; VMess mux StatusEnd 3, sing-vmess v0.2.5 `protocol.go:79`; VMess mux StatusKeep 2, sing-vmess v0.2.5 `protocol.go:78`; VMess mux StatusKeepAlive 4, sing-vmess v0.2.5 `protocol.go:80`; VMess mux StatusNew 1, sing-vmess v0.2.5 `protocol.go:77` |
| `proxy::wireguard::amnezia::COOKIE`, `proxy::wireguard::amnezia::INIT`, `proxy::wireguard::amnezia::MAX_DATAGRAM`, `proxy::wireguard::amnezia::NONCE`, `proxy::wireguard::amnezia::REPLY`, `proxy::wireguard::amnezia::SIZES`, `proxy::wireguard::amnezia::TRANSPORT`, `proxy::wireguard::amnezia::TRANSPORT_HEADER` | Index of the cookie-reply message kind (WireGuard type 3), amneziawg-go `device/noise-protocol.go:61`; Index of the handshake-initiation message kind (WireGuard message type 1, zero-based), amneziawg-go `device/noise-protocol.go:59` MessageInitiationType; Largest UDP datagram 65535, amneziawg-go `device/queueconstants_default.go:17` MaxSegmentSize; AmneziaWG header-protection ChaCha20 nonce 12 bytes, amneziawg-go `device/noise-types.go:23` HeaderCipherNonceSize; Index of the handshake-response message kind (WireGuard type 2), amneziawg-go `device/noise-protocol.go:60`; WireGuard message sizes 148/92/64 and 32-byte minimal transport (16 header + 16 tag), amneziawg-go `device/noise-protocol.go:66-70`; Index of the transport message kind (WireGuard type 4), amneziawg-go `device/noise-protocol.go:62`; WireGuard transport header 16 bytes, amneziawg-go `device/noise-protocol.go:69` MessageTransportHeaderSize |
| `proxy::wireguard::amnezia::template::MAX_PACKET` | Largest UDP datagram 65535, amneziawg-go `device/queueconstants_default.go:17` |
| `proxy::wireguard::config::MIN_MTU` | IPv6 minimum link MTU 1280, RFC 8200 §5 (also mihomo mipstack ipv6MinimumMTU `stack.go:38`) |
| `rules::domain_set::COMPLEX_WILDCARD`, `rules::domain_set::STEP`, `rules::domain_set::WILDCARD` | Clash domain-pattern syntax '+' (mihomo `component/trie/domain.go:14` complexWildcard); Clash domain-pattern label separator '.' (mihomo `component/trie/domain.go:15` domainStep); Clash domain-pattern syntax '*' (mihomo `component/trie/domain.go:12` wildcard) |
| `rules::mrs::MAGIC` | mihomo MRS rule-set file magic 'MRS' + version 1 (mihomo `rules/provider/mrs_reader.go:13`) |
| `tls::fuzzing::CHUNK_SIZES`, `tls::fuzzing::CLIENT_SECRET`, `tls::fuzzing::KEY_UPDATE`, `tls::fuzzing::MAX_PLAINTEXT`, `tls::fuzzing::READ_SIZES`, `tls::fuzzing::SERVER_SECRET`, `tls::fuzzing::TLS12_SUITE` | Fuzz-harness fixture, not a tunable: boundary write sizes for the libFuzzer target (1448 MSS, 16389 = record + header, over-record 70000); Fuzz-harness fixture, not a tunable: fixed test traffic secret; RFC 8446 §4 handshake type key_update = 24; RFC 8446 §5.1 maximum record plaintext 2^14; Fuzz-harness fixture, not a tunable: boundary read sizes for the libFuzzer target; IANA TLS cipher suite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f (RFC 5289 §3) |
| `tls::reality::handshake::HELLO_RETRY_RANDOM`, `tls::reality::handshake::HS_CERTIFICATE`, `tls::reality::handshake::HS_CERTIFICATE_VERIFY`, `tls::reality::handshake::HS_COMPRESSED_CERTIFICATE`, `tls::reality::handshake::HS_ENCRYPTED_EXTENSIONS`, `tls::reality::handshake::HS_FINISHED`, `tls::reality::handshake::HS_SERVER_HELLO`, `tls::reality::handshake::MLKEM768_CIPHERTEXT_LEN`, `tls::reality::handshake::SCHEME_ED25519` | RFC 8446 §4.1.3 HelloRetryRequest special Random; metacubex/utls `common.go:219`; RFC 8446 §4 handshake type certificate = 11; RFC 8446 §4 handshake type certificate_verify = 15; RFC 8879 §4 handshake type compressed_certificate = 25; RFC 8446 §4 handshake type encrypted_extensions = 8; RFC 8446 §4 handshake type finished = 20; RFC 8446 §4 handshake type server_hello = 2; ML-KEM-768 ciphertext 1088 bytes, FIPS 203 §8 Table 3; RFC 8446 §4.2.3 signature scheme ed25519 = 0x0807 |
| `tls::record::ALERT_CLOSE_NOTIFY`, `tls::record::ALERT_LEVEL_WARNING`, `tls::record::ALERT_USER_CANCELED`, `tls::record::KEY_UPDATE_NOT_REQUESTED`, `tls::record::KEY_UPDATE_REQUESTED`, `tls::record::MAX_CIPHERTEXT`, `tls::record::MAX_PLAINTEXT`, `tls::record::MAX_WIRE_RECORD` | RFC 8446 §6 AlertDescription close_notify = 0; RFC 8446 §6 AlertLevel warning = 1; RFC 8446 §6 AlertDescription user_canceled = 90; RFC 8446 §4.6.3 KeyUpdateRequest update_not_requested = 0; RFC 8446 §4.6.3 KeyUpdateRequest update_requested = 1; RFC 5246 §6.2.3 maximum TLSCiphertext 2^14 + 2048; RFC 8446 §5.1 maximum record plaintext 2^14; 5-byte record header + RFC 5246 §6.2.3 maximum ciphertext |
| `transport::gun::frame::FRONT_HEADROOM` | gRPC message prefix 5 + protobuf tag 1 + max uvarint 10 = 16; mihomo `transport/gun/gun.go:186` FrontHeadroom 6 + binary.MaxVarintLen64 |
| `transport::singmux::smux::FIRST_STREAM_ID` | smux client first stream ID = 3; metacubex/smux `session.go:149,184-185` and sing-box sagernet/smux v1.5.50-sing-box-mod.1 `session.go:148,183-184` initialize nextStreamID = 1 then add 2 before opening. Both servers accept the received SYN stream ID without requiring it to start at 3 (`session.go:423-435`). |
| `transport::singmux::single::FIRST_STREAM_ID` | smux client stream ID starts at 3: metacubex/smux `session.go:149` initializes nextStreamID = 1, then `session.go:184-185` adds 2 before opening the first stream |
| `transport::singmux::smux::CMD_FIN`, `transport::singmux::smux::CMD_NOP`, `transport::singmux::smux::CMD_PSH`, `transport::singmux::smux::CMD_SYN`, `transport::singmux::smux::CMD_UPD`, `transport::singmux::smux::VERSION` | smux frame cmdFIN = 1; metacubex/smux `frame.go:33`; smux frame cmdNOP = 3; metacubex/smux `frame.go:35`; smux frame cmdPSH = 2; metacubex/smux `frame.go:34`; smux frame cmdSYN = 0; metacubex/smux `frame.go:32`; smux v2 frame cmdUPD = 4; metacubex/smux `frame.go:39`; smux protocol version byte 1; metacubex/smux `mux.go:64` DefaultConfig Version 1 |
| `transport::singmux::wire::FLAG_ADDR`, `transport::singmux::wire::FLAG_UDP`, `transport::singmux::wire::STATUS_ERROR` | sing-mux stream request flagAddr = 2; metacubex/sing-mux v0.3.12 `protocol.go:105`; sing-mux stream request flagUDP = 1; metacubex/sing-mux v0.3.12 `protocol.go:104`; sing-mux stream response statusError = 1; metacubex/sing-mux v0.3.12 `protocol.go:107` |
| `transport::singmux::yamux::FLAG_ACK`, `transport::singmux::yamux::FLAG_FIN`, `transport::singmux::yamux::FLAG_RST`, `transport::singmux::yamux::FLAG_SYN`, `transport::singmux::yamux::PEER_ASSUMED_WINDOW`, `transport::singmux::yamux::TYPE_DATA`, `transport::singmux::yamux::TYPE_GO_AWAY`, `transport::singmux::yamux::TYPE_PING`, `transport::singmux::yamux::TYPE_WINDOW_UPDATE` | yamux header flag ACK = 2; metacubex/yamux `const.go:168`; yamux header flag FIN = 4; metacubex/yamux `const.go:172`; yamux header flag RST = 8; metacubex/yamux `const.go:175`; yamux header flag SYN = 1; metacubex/yamux `const.go:164`; yamux protocol initial stream window 256 KiB both sides assume; metacubex/yamux `spec.md:120-125`, `const.go:181` initialStreamWindow; yamux message type Data = 0; metacubex/yamux `const.go:144`; yamux message type GoAway = 3; metacubex/yamux `const.go:158`; yamux message type Ping = 2; metacubex/yamux `const.go:154`; yamux message type WindowUpdate = 1; metacubex/yamux `const.go:149` |
| `transport::v2ray_plugin::OPTION_DATA`, `transport::v2ray_plugin::STATUS_END`, `transport::v2ray_plugin::STATUS_KEEP`, `transport::v2ray_plugin::STATUS_KEEP_ALIVE`, `transport::v2ray_plugin::STATUS_NEW` | mux.cool option Data = 0x01; mihomo `transport/v2ray-plugin/mux.go:23`; mux.cool session status End = 0x03; mihomo `transport/v2ray-plugin/mux.go:17`; mux.cool session status Keep = 0x02; mihomo `transport/v2ray-plugin/mux.go:16`; mux.cool session status KeepAlive = 0x04; mihomo `transport/v2ray-plugin/mux.go:18`; mux.cool session status New = 0x01; mihomo `transport/v2ray-plugin/mux.go:15` |
| `transport::ws::frame::MAX_CONTROL`, `transport::ws::frame::OP_BINARY`, `transport::ws::frame::OP_CLOSE`, `transport::ws::frame::OP_PING`, `transport::ws::frame::OP_PONG` | RFC 6455 §5.5 control frame payload at most 125 bytes; RFC 6455 §5.2 opcode binary = 0x2; RFC 6455 §5.2 opcode close = 0x8; RFC 6455 §5.2 opcode ping = 0x9; RFC 6455 §5.2 opcode pong = 0xA |
| `transport::xhttp::padding::HUFFMAN_CODE_LEN` | RFC 7541 Appendix B HPACK Huffman code lengths (fixed algorithm table) |
| `tun::device::Device::BATCH` | Default for a device without a batch API: one read()/write() on a TUN fd moves one packet (OS TUN API); devices with recvmsg_x/sendmsg_x override it |
| `common::dns_relay::HEADER_LEN` | DNS message header is 12 bytes (RFC 1035 §4.1.1) |
| `tun::stack::driver::MAX_FRAME`, `tun::stack::driver::TAG_DNS`, `tun::stack::driver::TAG_FLOW` | Largest IP packet: IPv4/IPv6 16-bit length field, 65535 (RFC 791 §3.1, RFC 8200 §3); Internal discriminant tagging an accepted packet as DNS hijack; not a quantity; Internal discriminant tagging an accepted packet as a flow; not a quantity |
| `tun::vnet::F_NEEDS_CSUM`, `tun::vnet::GSO_ECN`, `tun::vnet::GSO_TCPV4`, `tun::vnet::GSO_TCPV6`, `tun::vnet::GSO_UDP_L4`, `tun::vnet::HEADER_LEN`, `tun::vnet::IPV4_HEADER`, `tun::vnet::IPV6_HEADER`, `tun::vnet::MERGED_LIMIT`, `tun::vnet::PROTO_TCP`, `tun::vnet::PROTO_UDP`, `tun::vnet::UDP_HEADER` | VIRTIO_NET_HDR_F_NEEDS_CSUM = 1 (linux/virtio_net.h); VIRTIO_NET_HDR_GSO_ECN = 0x80 (linux/virtio_net.h); VIRTIO_NET_HDR_GSO_TCPV4 = 1 (linux/virtio_net.h); VIRTIO_NET_HDR_GSO_TCPV6 = 4 (linux/virtio_net.h); VIRTIO_NET_HDR_GSO_UDP_L4 = 5 (linux/virtio_net.h); sing-tun goUDPGSOType = 5 (`stack_go_udp.go:23`); sizeof(struct virtio_net_hdr) = 10 (linux/virtio_net.h); IPv4 header without options, 20 bytes (RFC 791 §3.1); IPv6 fixed header, 40 bytes (RFC 8200 §3); IP 16-bit total length, 65535; sing-tun stops a merged UDP frame at the same limit (`stack_go_io_linux.go:543`); IANA protocol number 6 (IPPROTO_TCP); IANA protocol number 17 (IPPROTO_UDP); UDP header, 8 bytes (RFC 768) |
| `tunnel::sniff::quic::FRAME_ACK`, `tunnel::sniff::quic::FRAME_ACK_WITH_ECN`, `tunnel::sniff::quic::FRAME_CONNECTION_CLOSE`, `tunnel::sniff::quic::FRAME_CRYPTO`, `tunnel::sniff::quic::FRAME_PADDING`, `tunnel::sniff::quic::FRAME_PING` | QUIC ACK frame type 0x02 (RFC 9000 §19.3); QUIC ACK frame with ECN type 0x03 (RFC 9000 §19.3); QUIC CONNECTION_CLOSE frame type 0x1c (RFC 9000 §19.19); QUIC CRYPTO frame type 0x06 (RFC 9000 §19.6); QUIC PADDING frame type 0x00 (RFC 9000 §19.1); QUIC PING frame type 0x01 (RFC 9000 §19.2) |
| `proxy::snell::v6_frame::*` | Snell v6 payload 65535, header 7, tag/salt 16; AES-128-GCM with little-endian nonce, Argon2id as v4; mihomo Alpha `3c0d10a5` `transport/snell/v6.go:59-70`, `:252-285`. |
| `proxy::snell::v6_profile::*` | Snell v6 PSK-derived profile constants, BLAKE2b seed, PRF, padding generators, salt shuffle and record sizing; mihomo Alpha `3c0d10a5` `transport/snell/v6_profile.go:20-108`, `:128-650`. These wire values determine ciphertext layout and authenticated padding. |
| `proxy::snell::v6_profile::label::*` | Snell v6 profile PRF labels 0–39, including aliases for salt and first chunk cap; mihomo Alpha `3c0d10a5` `transport/snell/v6_profile.go:22-62`. |
