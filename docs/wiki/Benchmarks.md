# Benchmarks

Every number here is produced by the `benchmark` workflow in the repository, on a GitHub-hosted runner, against hev-socks5-tunnel, sing-box and tun2socks over the same SOCKS5 server.

## Machine

| property | value |
|---|---|
| runner image | ubuntu24 20260927.320.1 |
| cpu | AMD EPYC 9V74 80-Core Processor |
| cpu cores | 4 |
| memory | 15.6 GB |
| kernel | Linux 6.17.0-1022-azure |
| zig | 0.16.0 |
| date | 2026-10-04 |

## Method

Two network namespaces joined by a veth pair. Traffic enters the tunnel device (MTU 8500), leaves through the same SOCKS5 server (hev-socks5-server) for every engine, and reaches the servers in the second namespace. Engines are interleaved: each round starts every engine once and runs every scenario against it, so background noise spreads evenly. CPU comes from `/proc/<pid>/stat` and memory from `VmRSS`, summed over all processes of an engine.

Duration 8 s per scenario, 2 rounds, 4 queues. Memory is read twice: the highest sample while the scenario runs, and again after 5 s of idle, which shows whether an engine gives the memory back.

## Throughput

![throughput](res/throughput.svg)

## CPU

![cpu](res/cpu.svg)

## Request and response

![transactions](res/transactions.svg)

![latency](res/latency.svg)

## UDP

![udp](res/udp.svg)

## Memory

Memory is read twice per scenario: the highest sample while the load runs, and
again after a few seconds of idle. The second reading is what shows whether an
engine hands the memory back or keeps it for the life of the process.

![memory](res/memory.svg)

## Scenarios

| Scenario | What it measures |
|---|---|
| `tcp-up-1`, `tcp-up-10` | bulk upload over one and ten streams |
| `tcp-down-1`, `tcp-down-10` | the same downstream |
| `rr` | request and response on a held connection, one at a time |
| `rr-8x1k` | eight connections exchanging 1 KB messages |
| `crr` | connect, exchange, close, repeatedly |
| `udp-100k` | 100k datagrams per second, echoed |
| `udp-gso-100k` | the same with segmentation offload on the client |

## Raw results

| engine | scenario | median | cpu % | max rss MB | rss after idle MB |
|---|---|---:|---:|---:|---:|
| zeptun-userspace | tcp-up-1 | 24.745 Gbit/s | 89 | 8.7 | 7.4 |
| zeptun-userspace | tcp-up-10 | 29.703 Gbit/s | 130 | 17.4 | 10.4 |
| zeptun-userspace | tcp-down-1 | 15.111 Gbit/s | 99 | 10.5 | 10.4 |
| zeptun-userspace | tcp-down-10 | 27.839 Gbit/s | 175 | 14.4 | 10.5 |
| zeptun-userspace | rr | 11699 tps p50=80us p99=160us p99.9=186us  | 35 | 10.6 | 10.5 |
| zeptun-userspace | rr-8x1k | 50997 tps p50=148us p99=312us p99.9=500us  | 97 | 12.6 | 12.5 |
| zeptun-userspace | crr | 2491 tps p50=384us p99=480us p99.9=600us  | 42 | 14.4 | 14.1 |
| zeptun-userspace | udp-100k | 99797 echo pps (99.8% of 99988 sent)  | 61 | 15.0 | 14.1 |
| zeptun-userspace | udp-gso-100k | 99904 echo pps (99.9% of 99988 sent)  | 46 | 15.0 | 14.0 |
| hev | tcp-up-1 | 8.283 Gbit/s | 96 | 15.2 | 15.1 |
| hev | tcp-up-10 | 18.430 Gbit/s | 217 | 16.7 | 15.8 |
| hev | tcp-down-1 | 8.052 Gbit/s | 99 | 16.0 | 15.8 |
| hev | tcp-down-10 | 15.210 Gbit/s | 211 | 16.6 | 15.8 |
| hev | rr | 11354 tps p50=82us p99=164us p99.9=190us  | 39 | 15.9 | 15.8 |
| hev | rr-8x1k | 43916 tps p50=168us p99=428us p99.9=584us  | 125 | 16.4 | 15.8 |
| hev | crr | 2300 tps p50=420us p99=496us p99.9=560us  | 62 | 16.1 | 15.8 |
| hev | udp-100k | 99888 echo pps (99.9% of 99992 sent)  | 95 | 18.4 | 18.4 |
| hev | udp-gso-100k | 99752 echo pps (99.8% of 99984 sent)  | 94 | 20.9 | 20.9 |
| zeptun-hybrid | tcp-up-1 | 15.403 Gbit/s | 99 | 6.0 | 5.8 |
| zeptun-hybrid | tcp-up-10 | 26.430 Gbit/s | 187 | 11.5 | 10.6 |
| zeptun-hybrid | tcp-down-1 | 16.640 Gbit/s | 99 | 10.9 | 10.4 |
| zeptun-hybrid | tcp-down-10 | 29.351 Gbit/s | 201 | 11.5 | 14.5 |
| zeptun-hybrid | rr | 10645 tps p50=88us p99=168us p99.9=186us  | 41 | 14.5 | 18.3 |
| zeptun-hybrid | rr-8x1k | 45554 tps p50=168us p99=332us p99.9=424us  | 146 | 20.3 | 20.0 |
| zeptun-hybrid | crr | 2059 tps p50=476us p99=568us p99.9=624us  | 63 | 24.9 | 24.6 |
| zeptun-hybrid | udp-100k | 99611 echo pps (99.6% of 99988 sent)  | 81 | 30.2 | 29.8 |
| zeptun-hybrid | udp-gso-100k | 99942 echo pps (100.0% of 99984 sent)  | 45 | 32.4 | 31.9 |
| singbox-system | tcp-up-1 | 7.334 Gbit/s | 139 | 63.7 | 63.8 |
| singbox-system | tcp-up-10 | 5.847 Gbit/s | 168 | 64.3 | 64.4 |
| singbox-system | tcp-down-1 | 6.244 Gbit/s | 148 | 64.4 | 64.2 |
| singbox-system | tcp-down-10 | 4.946 Gbit/s | 135 | 64.3 | 64.3 |
| singbox-system | rr | 9235 tps p50=101us p99=186us p99.9=206us  | 61 | 64.3 | 64.1 |
| singbox-system | rr-8x1k | 31547 tps p50=238us p99=528us p99.9=1024us  | 145 | 64.4 | 64.4 |
| singbox-system | crr | 1760 tps p50=552us p99=640us p99.9=1088us  | 95 | 75.3 | 75.3 |
| singbox-system | udp-100k | 0 echo pps (0.0% of 99988 sent)  | 65 | 75.6 | 75.6 |
| singbox-system | udp-gso-100k | 0 echo pps (0.0% of 99984 sent)  | 60 | 75.7 | 75.3 |
| tun2socks | tcp-up-1 | 6.999 Gbit/s | 179 | 21.2 | 20.8 |
| tun2socks | tcp-up-10 | 10.681 Gbit/s | 264 | 38.4 | 37.5 |
| tun2socks | tcp-down-1 | 4.047 Gbit/s | 159 | 44.5 | 27.1 |
| tun2socks | tcp-down-10 | 8.552 Gbit/s | 254 | 136.1 | 136.1 |
| tun2socks | rr | 7538 tps p50=122us p99=228us p99.9=256us  | 68 | 142.7 | 142.7 |
| tun2socks | rr-8x1k | 28385 tps p50=264us p99=600us p99.9=1040us  | 155 | 147.3 | 25.4 |
| tun2socks | crr | 1602 tps p50=608us p99=728us p99.9=1824us  | 89 | 39.2 | 43.2 |
| tun2socks | udp-100k | 65192 echo pps (65.2% of 99976 sent)  | 205 | 41.6 | 47.1 |
| tun2socks | udp-gso-100k | 69263 echo pps (69.3% of 99988 sent)  | 214 | 59.8 | 59.1 |
| singbox-gvisor | tcp-up-1 | 13.382 Gbit/s | 159 | 69.8 | 69.8 |
| singbox-gvisor | tcp-up-10 | 20.834 Gbit/s | 199 | 82.0 | 82.0 |
| singbox-gvisor | tcp-down-1 | 4.606 Gbit/s | 178 | 82.4 | 82.4 |
| singbox-gvisor | tcp-down-10 | 8.536 Gbit/s | 239 | 86.6 | 85.6 |
| singbox-gvisor | rr | 6990 tps p50=132us p99=246us p99.9=568us  | 75 | 85.6 | 71.3 |
| singbox-gvisor | rr-8x1k | 27646 tps p50=276us p99=544us p99.9=840us  | 158 | 73.0 | 72.4 |
| singbox-gvisor | crr | 1638 tps p50=600us p99=696us p99.9=1360us  | 101 | 76.8 | 76.8 |
| singbox-gvisor | udp-100k | 0 echo pps (0.0% of 99986 sent)  | 150 | 77.2 | 77.2 |
| singbox-gvisor | udp-gso-100k | 0  | 0 | 77.2 | 77.2 |

zeptun: startup 3 ms, idle 836 KB, 5 wakeups in 20 s | tcp 1000: 4040 KB (conns: 1000/1000 established, 0 failed, 2413 conn/s) | udp 1000: 4260 KB (udp flows: 1000/1000 answered, 10268 flows/s)
hev: startup 3 ms, idle 2224 KB, 2 wakeups in 20 s | tcp 1000: 78789 KB (conns: 1000/1000 established, 0 failed, 2450 conn/s) | udp 1000: 27325 KB (udp flows: 1000/1000 answered, 9932 flows/s)
singbox-system: startup 39 ms, idle 57480 KB, 6 wakeups in 20 s | tcp 1000: 75335 KB (conns: 1000/1000 established, 0 failed, 1699 conn/s) | udp 1000: 69051 KB (udp flows: 0/1000 answered, 0 flows/s)
singbox-gvisor: startup 40 ms, idle 61876 KB, 66 wakeups in 20 s | tcp 1000: 95423 KB (conns: 1000/1000 established, 0 failed, 1719 conn/s) | udp 1000: 104911 KB (udp flows: 0/1000 answered, 0 flows/s)
tun2socks: startup 4 ms, idle 15840 KB, 157 wakeups in 20 s | tcp 1000: 109232 KB (conns: 1000/1000 established, 0 failed, 1535 conn/s) | udp 1000: 183884 KB (udp flows: 1000/1000 answered, 8002 flows/s)

## Reproducing

```sh
gh workflow run benchmark.yml --repo Noisemux/zeptun -f duration=8 -f repeat=2
```
