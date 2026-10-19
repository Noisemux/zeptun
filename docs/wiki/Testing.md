# Testing

| Command | Scope |
|---|---|
| `zig build test` | unit tests and the deterministic TCP simulation |
| `zig build test-netns` | unit tests inside a user and network namespace, where real TUN devices can be created |
| `zig build test-ffi` | `tests/ffi_smoke.c` compiled with `-Wall -Wextra -Werror` against `libzeptun.a` |
| `zig build test-integration` | 189 end-to-end checks through a real TUN device between two namespaces |
| `zig build test-compile -Dtarget=...` | compiles the tests for another target without running them |
| `zig build bench` | hot-path microbenchmarks with a regression gate |

## Unit tests

Parsers, checksums (scalar against SIMD), the buffer pool, flow tables, the timer wheel, NAT rewriting, GSO segmentation and coalescing, SOCKS5 parsing, route message layouts, the TOML and JSON documents, the C ABI and the engine with an external device. Parsers and tables also carry fuzz entry points.

## TCP simulation

`src/tests/tcp_sim.zig` runs the real terminator, packet pool and timer wheel against a simulated event loop, handler and clock. A model peer transfers data through an echo upstream over links with loss, duplication, reordering and delay, while its receive window changes and the upstream socket stalls. Every byte is verified in both directions, the engine may never exceed the advertised window, and the connection must finish within 240 virtual seconds leaving no buffers, timers or completions behind. A chaos mode injects random segments and upstream errors.

```sh
ZEPTUN_SIM_SEEDS=10000:50000 zig build test -Doptimize=safe -Dtest-filter="tcp simulation seeded"
```

## Integration suite

`scripts/netns_integration.sh` builds a client and a server namespace joined by a veth pair and runs the CLI in every stack mode, over io_uring and epoll, with one and four queues, direct and through SOCKS5, with and without offloads, with and without the proxy pool, with UDP over TCP, with strict routing and a route file, and with automatic redirect.

Each case checks upload, download, four streams, a 64 MiB echo integrity test, request/response latency, 500 concurrent connections, UDP echo, GSO bursts verified datagram by datagram, a clean exit, and that no policy rule or nftables table is left behind. Elastic cases rotate between one and four queues every 1.5 s while two 1.5 GB transfers run, and every byte must still arrive. Fake-IP cases resolve names through the in-tunnel and hijacked resolvers. The namespace case checks that the interface, addresses and rules appear inside the target namespace and nowhere else.

## Allocation invariant

An engine test counts every allocator call and fails if steady-state TCP traffic performs a single heap allocation after setup.

## Packet replay

```sh
zeptun-bench replay --pcap capture.pcap --loops 10
```

Reads raw IP, Ethernet with VLAN tags, Linux cooked v1 and v2, and BSD loopback captures, completes partial checksums, rewrites every packet through NAT, then coalesces and segments the flows again while verifying checksums and payload lengths.
