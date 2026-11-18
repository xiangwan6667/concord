# Concord

Concord is a proxy core written in Rust. It reads Clash profiles and routes each connection by rules through proxy
groups to an outbound protocol. It runs on its own from a profile, or inside an application that drives
it through an API.

## Highlights

- **Your existing configuration.** Clash profiles with their rules, groups, providers and DNS. A node
  Concord does not support is set aside with a warning instead of failing the whole profile.
- **Broad protocol coverage.** Shadowsocks, ShadowsocksR, VMess, VLESS with REALITY, Trojan, AnyTLS, Snell, Hysteria,
  Hysteria2, TUIC, ShadowQUIC, mieru, WireGuard, SSH, SOCKS5 and HTTP; over WebSocket, gRPC, HTTP/2, xhttp, ShadowTLS
  and sing-mux; with ECH and browser TLS fingerprints.
- **Built-in TUN** on macOS, Linux, Windows and Android, beside mixed, HTTP, SOCKS, redirect and TProxy listeners.
- **HTTPS interception.** Optional MITM for listed hosts, with rewrite rules and scripts.
- **A control API.** JSON-RPC 2.0 with live streams, described by [`schema/api.json`](schema/api.json), and the Clash
  REST API for dashboards.

## Platforms

| Platform | Architectures | Form |
|---|---|---|
| macOS | arm64, x86_64 | Executable `concord` |
| Linux | arm64, x86_64 | Executable `concord` |
| Windows | arm64, x86_64 | Executable `concord.exe` |
| Android | arm64, armv7, x86_64 | Library `libconcord.so` |

## Build And Run

```sh
git clone https://github.com/chen08209/concord
cd concord
cargo build --release -p concord-desktop
target/release/concord run -c config.yaml
```

| Option | Meaning |
|---|---|
| `-c`, `--config <file>` | The Clash profile to run (default: `config.yaml` in the home directory) |
| `-d`, `--directory <dir>` | The home directory (default: `~/.config/concord`) |
| `-h`, `--help` | Print the options |

[docs/usage.md](docs/usage.md) covers building on Windows, the home directory, geodata, reloading and dashboards.

Applications can also embed Concord, as a child process on desktop or as `libconcord.so` on Android, and drive it
through the JSON-RPC API. [FlClash](https://github.com/chen08209/FlClash) is built this way.

## Performance

Against upstream mihomo `v1.19.33` on a Linux arm64 VM: both as the SOCKS5 client in front of the same mihomo server
over loopback, every process pinned to its own CPUs, six rounds of fresh processes. Figures are Concord relative to
mihomo; higher is better for throughput and connections, lower for CPU and memory, and "tie" means no significant
difference.

| Case | Download | Upload | CPU per GB, download | New connections/s | Peak memory, download |
|---|---|---|---|---|---|
| `direct` | tie (+1.5%) | tie (+2.7%) | -5.1% | +36.7% | -40.3% |
| `ss-aes128` | +30.7% | +2.2% | -20.2% | +23.7% | -49.4% |
| `trojan-tls` | +44.0% | tie (+2.2%) | -31.4% | +41.3% | -48.5% |
| `vmess-grpc-tls` | +5.1% | +16.9% | -21.2% | +13.3% | -52.5% |
| `hysteria2` | tie (+7.2%) | tie (-0.3%) | -38.5% | tie (+2.5%) | -52.3% |

[docs/performance.md](docs/performance.md) has the method, every metric, the macOS results and how to reproduce them.

## Compatibility

[docs/compatibility.md](docs/compatibility.md) lists where Concord differs from mihomo.

## License

GPL-3.0-or-later; see [LICENSE](LICENSE). Code and designs taken from other projects are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
