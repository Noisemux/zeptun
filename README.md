# Zeptun

[![ci](https://github.com/Noisemux/zeptun/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Noisemux/zeptun/actions/workflows/ci.yml)

A userspace network engine for TUN devices, written in Zig with no dependencies. It turns the packets an operating system routes into a tunnel interface back into TCP, UDP and ICMP flows, and forwards them through a SOCKS5 proxy, directly, or to the embedding application.

## Features

* IPv4 and IPv6, dual stack, fragment reassembly.
* TCP through a userspace terminator, through kernel NAT, or both at once.
* UDP with full-cone NAT by default, plus address and address-port modes.
* Segmentation offload in both directions: TSO, USO, `UDP_SEGMENT` and `UDP_GRO`, through SOCKS5 as well.
* Multi-queue TUN with elastic workers: queues are attached and detached under load, and live connections migrate between them without loss.
* SOCKS5 with a warm connection pool, pipelined handshakes, optimistic data, UDP ASSOCIATE and UDP over TCP.
* Fake-IP DNS, DNS hijacking, and DNS handover to systemd-resolved.
* Automatic routing: policy rules, prefix include and exclude lists, UID, interface and Android package rules, strict route, nftables auto-redirect.
* ICMP echo forwarding, ICMP time exceeded for expired packets, and upstream ICMP errors translated back to the client.
* The interface can live in its own network namespace while upstream sockets stay outside.
* io_uring or epoll on Linux, kqueue on BSD and macOS, IOCP on Windows.
* C ABI, TOML and JSON configuration, per-flow verdict callback.
* Linux, Android, Windows, macOS, iOS and FreeBSD.

## Benchmarks

Measured by the [benchmark workflow](.github/workflows/benchmark.yml) on a GitHub-hosted runner, against four other engines over the same SOCKS5 server.

<img src="docs/bench/summary-throughput.svg" width="420" alt="throughput">
<img src="docs/bench/summary-cpu.svg" width="420" alt="cpu">
<img src="docs/bench/summary-transactions.svg" width="420" alt="transactions">
<img src="docs/bench/summary-memory.svg" width="420" alt="memory">

The second memory bar is read after the load stops: the packet pool hands idle
pages back to the kernel instead of holding them for the life of the process.

Method, runner specification, latency, UDP, memory and the raw tables: [docs/bench](docs/bench).

## Build

Zig 0.16.0 is the only requirement.

### Unix

```sh
git clone https://github.com/Noisemux/zeptun
cd zeptun
make
sudo make install
```

`make install` places `zeptun` in `/usr/local/bin`, `libzeptun.a` and `zeptun.h` beside it, `conf/zeptun.toml` in `/etc/zeptun` if no configuration exists yet, and a systemd unit in `/usr/local/lib/systemd/system`.

### Android

```sh
ANDROID_NDK_HOME=/path/to/ndk sh scripts/build_android.sh
```

This builds `libzeptun.so` and `libzeptun.a` for `armeabi-v7a`, `arm64-v8a`, `x86` and `x86_64`, then `libzeptun-jni.so` from `src/jni/zeptun_jni.c`. All load segments are aligned to 16 KB, as Android 15 and later require. Without the NDK the script stops after the Zig libraries.

### iOS and macOS

```sh
sh scripts/make_xcframework.sh
```

This produces `zig-out/Zeptun.xcframework` with the iOS device, iOS simulator and macOS slices. `Package.swift` exposes it to SwiftPM.

### Windows

```sh
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseFast
make wintun
```

The tunnel uses Wintun, which is vendored in `third-part/wintun` with its licence and header, so no download is needed: `make wintun` copies the right `wintun.dll` next to the executable (`WINTUN_ARCH=arm64` for arm64). The released Windows archives already contain it.

### Library

```sh
zig build -Doptimize=ReleaseFast
```

This writes `zig-out/lib/libzeptun.a`, the shared library and `zig-out/include/zeptun.h`. Other targets: `make TARGET=aarch64-linux-musl`, or `zig build cross` for the whole matrix.

## Use

### Configuration

```toml
preset = "desktop"
log_level = "warn"
stats_interval_s = 0

[tun]
name = "zeptun0"
mtu = 8500
queues = 0
address = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]

[stack]
mode = "userspace"
udp_nat = "endpoint_independent"
icmp = "auto"

[handler]
kind = "socks5"

[handler.socks5]
server = "127.0.0.1:1080"
udp_mode = "udp"
pool_size = 4

[route]
auto_route = true
exclude = ["192.168.0.0/16"]

[dns]
fake_ip = false
hijack = false
systemd_resolved = true
```

`conf/zeptun.toml` carries every key with its default. The same document is accepted as JSON. Unknown keys are rejected instead of ignored.

| Section | Keys |
|---|---|
| top level | `preset` (`desktop`, `server`, `mobile`), `log_level`, `log_file`, `pid_file`, `stats_interval_s`, `post_up_script`, `pre_down_script` |
| `[tun]` | `name`, `fd`, `mtu`, `queues`, `offload`, `multi_queue`, `persist`, `napi`, `jumbo`, `txqueuelen`, `configure`, `netns`, `guid`, `address` |
| `[stack]` | `mode` (`userspace`, `hybrid`, `system`), `tcp_rx_window`, `tcp_tx_buffer`, `tcp_mss_clamp`, `tcp_initial_cwnd`, `congestion`, `sack`, `timestamps`, `window_scaling`, `tcp_connect_timeout_ms`, `tcp_idle_timeout_ms`, `tcp_delayed_ack_ms`, `tcp_early_accept`, `udp_idle_timeout_ms`, `udp`, `udp_nat`, `icmp`, `max_tcp_sessions`, `max_udp_sessions`, `nat_port_base`, `nat_port_limit` |
| `[handler]` | `kind` (`socks5`, `direct`, `passthrough`), `tcp_fastopen`, `preserve_dscp` |
| `[handler.socks5]` | `server`, `username`, `password`, `udp`, `udp_mode` (`udp`, `tcp`), `udp_address`, `pipeline`, `optimistic_data`, `pool_size`, `pool_idle_ms` |
| `[handler.direct]` | `fwmark`, `bind_interface` |
| `[route]` | `auto_route`, `table`, `rule_priority`, `fwmark`, `include`, `exclude`, `include_file`, `exclude_file`, `strict`, `allow_app`, `auto_redirect`, `redirect_port`, `include_uid`, `exclude_uid`, `include_interface`, `exclude_interface`, `include_package`, `exclude_package`, `android_user` |
| `[io]` | `backend` (`auto`, `io_uring`, `epoll`), `workers`, `elastic` (`auto`, `on`, `off`), `rx_parallel`, `tx_slots`, `multishot_rx`, `busy_poll_us`, `pin_cpus`, `monitor_network` |
| `[dns]` | `fake_ip`, `fake_ranges`, `cache_size`, `ttl`, `address`, `hijack`, `upstream`, `systemd_resolved` |
| `[memory]` | `budget_bytes`, `buffers_per_worker` |

### Run

```sh
sudo zeptun run -c /etc/zeptun/zeptun.toml
```

Every key has a flag as well, so the file is optional:

```sh
sudo zeptun run --tun zeptun0 --mtu 8500 --socks5 127.0.0.1:1080 --auto-route
```

With `--auto-route` the engine installs the addresses, routes and policy rules itself and removes them when it stops, on Linux, macOS, FreeBSD and Windows. Upstream sockets carry a firewall mark, so proxy traffic never re-enters the tunnel. Without it nothing outside the interface is touched.

`zeptun help` lists every flag. The ones that matter most:

| Flag | Default | Meaning |
|---|---|---|
| `--stack` | `userspace` | `userspace`, `hybrid` or `system` |
| `--queues` | CPUs | upper bound for TUN queues and worker threads |
| `--elastic` | `auto` | attach and detach queues by load; `off` keeps them all attached |
| `--mtu` | 1500 | use 8500 or more with offloads |
| `--socks5 ADDR:PORT` | | proxy address; also `--socks5-user`, `--socks5-pass`, `--socks5-udp-mode`, `--socks5-pool` |
| `--handler` | `socks5` | `socks5`, `direct` or `passthrough` |
| `--auto-route` | off | install addresses, routes and policy rules |
| `--auto-redirect` | off | Linux: redirect TCP into a kernel socket with nftables |
| `--strict-route` | off | refuse traffic for an address family the tunnel does not carry |
| `--exclude CIDR` | | keep a prefix off the tunnel; also `--route`, `--route-file`, `--exclude-file` |
| `--netns NAME` | | create the interface inside a network namespace |
| `--udp-nat MODE` | `endpoint-independent` | `address` and `address-port` restrict the NAT |
| `--fake-ip` | off | answer A and AAAA from a private pool and dial by domain |
| `--dns-hijack` | off | capture DNS sent to any address |
| `--systemd-resolved` | `auto` | hand DNS to the tunnel through `resolvectl` |
| `--icmp` | `auto` | `forward`, `local` or `drop` echo requests |
| `--io` | `auto` | `io_uring` or `epoll` |
| `--stats N` | 0 | print counters every N seconds |

### Container

```sh
docker run --rm --device /dev/net/tun --cap-add NET_ADMIN --cap-add NET_RAW \
  -e SOCKS5_ADDR=172.17.0.1 -e SOCKS5_PORT=1080 ghcr.io/noisemux/zeptun
```

```yaml
services:
  tun:
    image: ghcr.io/noisemux/zeptun
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      TUN: zeptun0
      MTU: 8500
      IPV4: 172.19.0.1/30
      IPV6: fdfe:dcba:9876::1/126
      HANDLER: socks5
      SOCKS5_ADDR: a.b.c.d
      SOCKS5_PORT: 1080
      SOCKS5_USERNAME: user
      SOCKS5_PASSWORD: pass
      SOCKS5_UDP_MODE: udp
      AUTO_ROUTE: 1
      EXCLUDED_ROUTES: a.b.c.d/32
      LOG_LEVEL: warn

  client:
    image: alpine
    tty: true
    network_mode: "service:tun"
    depends_on:
      - tun
```

`docker/entrypoint.sh` turns the environment into `/run/zeptun.toml`. Set `CONFIG` to point at your own file instead, or pass arguments to run any subcommand.

## API

### C

```c
#include <zeptun.h>

ZeptunConfig config;
zeptun_config_init(&config, ZEPTUN_PRESET_DESKTOP);
config.handler_kind = ZEPTUN_HANDLER_SOCKS5;
config.auto_route = 1;
snprintf(config.socks5_server, sizeof config.socks5_server, "127.0.0.1:1080");

Zeptun *tun = NULL;
if (zeptun_create(&config, &tun) != ZEPTUN_OK) return 1;
zeptun_start(tun);
...
zeptun_stop(tun);
zeptun_destroy(tun);
```

| Function | Purpose |
|---|---|
| `zeptun_config_init(config, preset)` | fill the configuration struct with the defaults of a preset |
| `zeptun_create(config, out)` | create an engine from the struct |
| `zeptun_create_from_toml(text, len, out)` | create an engine from a TOML document |
| `zeptun_create_from_json(text, len, out)` | the same document as JSON |
| `zeptun_start(tun)` | spawn the workers and return once the tunnel is up |
| `zeptun_run(tun)` | run one worker on the calling thread until `zeptun_stop` |
| `zeptun_stop(tun)` | stop the engine from any thread, including from a callback |
| `zeptun_destroy(tun)` | join the workers, remove routes and free the engine |
| `zeptun_set_device_fd(tun, fd)` | use an existing TUN file descriptor |
| `zeptun_set_adapter_guid(tun, guid)` | pin the Wintun adapter GUID on Windows, so the adapter keeps one identity across reinstalls |
| `zeptun_set_read_callback(tun, cb, ctx)` | receive the packets that leave the engine |
| `zeptun_write_packets(tun, packets, count)` | inject packets into the engine |
| `zeptun_set_protect_callback(tun, cb, ctx)` | approve every upstream socket before it connects |
| `zeptun_set_flow_callback(tun, cb, ctx)` | decide per flow: proxy, direct, drop or reject |
| `zeptun_stats(tun, stats)` | lock-free snapshot of the counters |
| `zeptun_memory(tun, memory)` | packet pool usage and how much memory has been returned to the kernel |
| `zeptun_network_changed(tun, index)` | tell the engine that the default route moved |
| `zeptun_strerror(code)` | message for an error code |

Callbacks run on worker threads and must not block. Every setter except `zeptun_stop`, `zeptun_stats`, `zeptun_memory` and the packet functions must be called before `zeptun_start`.

### Kotlin

`libzeptun-jni.so` registers its methods on the class `dev.zeptun.Zeptun`:

```kotlin
package dev.zeptun

import android.net.VpnService

object Zeptun {
    external fun nativeStart(service: Any?, fd: Int, config: String?): Int
    external fun nativeStop()
    external fun nativeVersion(): String
    external fun nativeCounter(index: Int): Long

    init {
        System.loadLibrary("zeptun-jni")
    }
}

class ZeptunService : VpnService() {
    fun start(fd: Int, config: String) {
        val rc = Zeptun.nativeStart(this, fd, config)
        if (rc != 0) throw IllegalStateException("zeptun start failed: $rc")
    }

    override fun onDestroy() {
        Zeptun.nativeStop()
        super.onDestroy()
    }
}
```

`nativeStart` takes the descriptor from `VpnService.Builder.establish()` and an optional TOML document; `null` uses the mobile preset. The service object is held as a global reference and its `protect(int)` method is called for every upstream socket. Change `ZEPTUN_JNI_CLASS` in `src/jni/zeptun_jni.c` to register on another class.

### Swift

```swift
import Zeptun

var config = ZeptunConfig()
zeptun_config_init(&config, UInt32(ZEPTUN_PRESET_MOBILE))
config.device_kind = UInt32(ZEPTUN_DEVICE_FD)
config.tun_fd = tunnelFileDescriptor
```

On iOS take the descriptor from `NEPacketTunnelProvider`, or use `ZEPTUN_DEVICE_EXTERNAL` with the packet callbacks to stay inside the NetworkExtension API.

## Stacks

| Mode | TCP | UDP | Notes |
|---|---|---|---|
| `userspace` | own terminator | own sessions | works everywhere, keeps no kernel state, required for elastic queues |
| `system` | kernel sockets behind NAT | kernel sockets | Linux only, lowest CPU for bulk transfer |
| `hybrid` | kernel NAT with a userspace fallback | own sessions | default where the system stack exists |

Elastic queues start with a single worker and add a queue only while it raises throughput, then release it when the load drops. Connections and sessions move between workers without dropping a packet, so the idle footprint stays small on a busy machine.

## Testing

| Command | Scope |
|---|---|
| `zig build test` | unit tests and the deterministic TCP simulation |
| `zig build test-netns` | unit tests inside a user and network namespace with real TUN devices |
| `zig build test-ffi` | `tests/ffi_smoke.c` compiled with `-Wall -Wextra -Werror` against `libzeptun.a` |
| `zig build test-integration` | 189 end-to-end checks through a real TUN device between two namespaces |
| `zig build bench` | hot-path microbenchmarks with a regression gate |

Full documentation lives in the [wiki](../../wiki): [Building](../../wiki/Building), [Configuration](../../wiki/Configuration), [Command line](../../wiki/Command-line), [Routing](../../wiki/Routing), [Stacks](../../wiki/Stacks), [C API](../../wiki/C-API), [Android](../../wiki/Android), [Apple](../../wiki/Apple), [Container](../../wiki/Container), [Benchmarks](../../wiki/Benchmarks), [Testing](../../wiki/Testing).

The integration suite covers every stack mode, both io backends, one and four queues, direct and SOCKS5, offloads on and off, UDP over TCP, fake-IP, strict routing, auto-redirect, elastic queue rotation under load, and the network namespace mode. The TCP simulation drives the real terminator against a model peer over lossy, reordering links and verifies every byte, leaving no buffers, timers or completions behind.

## Platform support

| Platform | Device | Event loop | Routing |
|---|---|---|---|
| Linux | `/dev/net/tun`, multi-queue, vnet header | io_uring or epoll | rtnetlink, policy rules, nftables |
| Android | VpnService descriptor, or `/dev/tun` with root | epoll | package and UID rules with root |
| Windows | Wintun | IOCP | IP Helper, WFP filters |
| macOS, iOS | utun, NetworkExtension | kqueue | route socket |
| FreeBSD | tun | kqueue | route socket |

## License

MIT
