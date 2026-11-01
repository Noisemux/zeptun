# Benchmarks

Every number here is produced by the `benchmark` workflow in the repository, on a GitHub-hosted runner, against hev-socks5-tunnel, sing-box and tun2socks over the same SOCKS5 server.

## Machine

| property | value |
|---|---|
| runner image | ubuntu24 20261026.354.1 |
| cpu | AMD EPYC 7763 64-Core Processor |
| cpu cores | 4 |
| memory | 15.6 GB |
| kernel | Linux 7.0.0-1017-azure |
| zig | 0.17.0 |
| date | 2026-11-01 |

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
| zeptun-userspace | tcp-up-1 | 18.114 Gbit/s | 80 | 2.8 | 1.4 |
| zeptun-userspace | tcp-up-10 | 22.116 Gbit/s | 139 | 9.2 | 2.4 |
| zeptun-userspace | tcp-down-1 | 11.781 Gbit/s | 99 | 2.5 | 2.4 |
| zeptun-userspace | tcp-down-10 | 21.231 Gbit/s | 189 | 6.4 | 2.6 |
| zeptun-userspace | rr | 9428 tps p50=101us p99=150us p99.9=164us  | 37 | 2.7 | 2.6 |
| zeptun-userspace | rr-8x1k | 35318 tps p50=216us p99=428us p99.9=560us  | 109 | 2.7 | 2.6 |
| zeptun-userspace | crr | 2000 tps p50=484us p99=560us p99.9=648us  | 49 | 4.5 | 4.4 |
| zeptun-userspace | udp-100k | 99976 echo pps (100.0% of 99988 sent)  | 63 | 5.5 | 4.5 |
| zeptun-userspace | udp-gso-100k | 99974 echo pps (100.0% of 99992 sent)  | 42 | 6.0 | 4.3 |
| hev | tcp-up-1 | 12.408 Gbit/s | 95 | 8.3 | 8.1 |
| hev | tcp-up-10 | 21.407 Gbit/s | 178 | 10.0 | 8.3 |
| hev | tcp-down-1 | 11.783 Gbit/s | 99 | 8.4 | 8.3 |
| hev | tcp-down-10 | 22.051 Gbit/s | 201 | 8.9 | 8.3 |
| hev | rr | 9168 tps p50=104us p99=152us p99.9=170us  | 41 | 8.3 | 8.3 |
| hev | rr-8x1k | 31719 tps p50=240us p99=492us p99.9=632us  | 127 | 8.4 | 8.3 |
| hev | crr | 1849 tps p50=528us p99=600us p99.9=696us  | 63 | 8.3 | 8.3 |
| hev | udp-100k | 99598 echo pps (99.6% of 99988 sent)  | 75 | 8.6 | 8.6 |
| hev | udp-gso-100k | 98688 echo pps (98.7% of 99992 sent)  | 70 | 8.8 | 8.7 |
| zeptun-hybrid | tcp-up-1 | 11.597 Gbit/s | 99 | 2.0 | 1.8 |
| zeptun-hybrid | tcp-up-10 | 20.809 Gbit/s | 189 | 3.6 | 2.7 |
| zeptun-hybrid | tcp-down-1 | 13.048 Gbit/s | 99 | 2.9 | 2.6 |
| zeptun-hybrid | tcp-down-10 | 22.906 Gbit/s | 217 | 3.6 | 2.7 |
| zeptun-hybrid | rr | 8525 tps p50=111us p99=164us p99.9=180us  | 43 | 2.7 | 2.4 |
| zeptun-hybrid | rr-8x1k | 30327 tps p50=250us p99=528us p99.9=688us  | 148 | 2.5 | 2.2 |
| zeptun-hybrid | crr | 1604 tps p50=608us p99=720us p99.9=832us  | 72 | 5.3 | 5.0 |
| zeptun-hybrid | udp-100k | 99960 echo pps (100.0% of 99992 sent)  | 75 | 5.9 | 5.2 |
| zeptun-hybrid | udp-gso-100k | 99969 echo pps (100.0% of 99984 sent)  | 43 | 5.7 | 5.3 |
| singbox-system | tcp-up-1 | 6.216 Gbit/s | 142 | 57.7 | 57.7 |
| singbox-system | tcp-up-10 | 4.657 Gbit/s | 171 | 60.0 | 59.5 |
| singbox-system | tcp-down-1 | 5.401 Gbit/s | 149 | 59.7 | 59.4 |
| singbox-system | tcp-down-10 | 4.047 Gbit/s | 135 | 59.4 | 59.5 |
| singbox-system | rr | 7080 tps p50=138us p99=184us p99.9=206us  | 63 | 59.5 | 59.5 |
| singbox-system | rr-8x1k | 23226 tps p50=328us p99=672us p99.9=952us  | 157 | 59.5 | 59.5 |
| singbox-system | crr | 1318 tps p50=744us p99=848us p99.9=1472us  | 105 | 69.9 | 69.9 |
| singbox-system | udp-100k | 0 echo pps (0.0% of 100000 sent)  | 89 | 71.5 | 70.8 |
| singbox-system | udp-gso-100k | 0 echo pps (0.0% of 99996 sent)  | 76 | 71.2 | 70.8 |
| tun2socks | tcp-up-1 | 5.121 Gbit/s | 175 | 17.2 | 17.1 |
| tun2socks | tcp-up-10 | 7.599 Gbit/s | 270 | 36.7 | 36.4 |
| tun2socks | tcp-down-1 | 2.633 Gbit/s | 170 | 38.9 | 23.3 |
| tun2socks | tcp-down-10 | 5.944 Gbit/s | 272 | 128.2 | 128.2 |
| tun2socks | rr | 5231 tps p50=188us p99=246us p99.9=324us  | 77 | 130.5 | 130.5 |
| tun2socks | rr-8x1k | 18815 tps p50=404us p99=848us p99.9=1184us  | 170 | 144.2 | 144.2 |
| tun2socks | crr | 1216 tps p50=792us p99=1008us p99.9=2208us  | 96 | 144.2 | 31.1 |
| tun2socks | udp-100k | 42271 echo pps (42.3% of 99976 sent)  | 223 | 36.0 | 31.5 |
| tun2socks | udp-gso-100k | 45114 echo pps (45.1% of 99959 sent)  | 236 | 34.8 | 34.0 |
| singbox-gvisor | tcp-up-1 | 9.126 Gbit/s | 161 | 64.8 | 64.8 |
| singbox-gvisor | tcp-up-10 | 15.218 Gbit/s | 209 | 75.9 | 75.9 |
| singbox-gvisor | tcp-down-1 | 3.176 Gbit/s | 181 | 75.9 | 67.7 |
| singbox-gvisor | tcp-down-10 | 5.804 Gbit/s | 264 | 82.4 | 82.4 |
| singbox-gvisor | rr | 4980 tps p50=196us p99=300us p99.9=520us  | 81 | 82.4 | 66.9 |
| singbox-gvisor | rr-8x1k | 17918 tps p50=428us p99=832us p99.9=1216us  | 172 | 68.8 | 68.3 |
| singbox-gvisor | crr | 1139 tps p50=856us p99=1024us p99.9=1872us  | 105 | 71.9 | 71.9 |
| singbox-gvisor | udp-100k | 0 echo pps (0.0% of 99993 sent)  | 169 | 72.2 | 71.9 |
| singbox-gvisor | udp-gso-100k | 0  | 0 | 71.9 | 71.9 |

zeptun: startup 3 ms, idle 864 KB, 5 wakeups in 20 s | tcp 1000: 2832 KB (conns: 1000/1000 established, 0 failed, 1997 conn/s) | udp 1000: 2432 KB (udp flows: 1000/1000 answered, 8827 flows/s)
hev: startup 3 ms, idle 531 KB, 2 wakeups in 20 s | tcp 1000: 9294 KB (conns: 1000/1000 established, 0 failed, 2015 conn/s) | udp 1000: 9182 KB (udp flows: 1000/1000 answered, 7626 flows/s)
singbox-system: startup 51 ms, idle 54329 KB, 6 wakeups in 20 s | tcp 1000: 70868 KB (conns: 1000/1000 established, 0 failed, 1349 conn/s) | udp 1000: 64576 KB (udp flows: 0/1000 answered, 0 flows/s)
singbox-gvisor: startup 51 ms, idle 55117 KB, 125 wakeups in 20 s | tcp 1000: 93300 KB (conns: 1000/1000 established, 0 failed, 1204 conn/s) | udp 1000: 97408 KB (udp flows: 0/1000 answered, 0 flows/s)
tun2socks: startup 5 ms, idle 11008 KB, 253 wakeups in 20 s | tcp 1000: 59112 KB (conns: 1000/1000 established, 0 failed, 1205 conn/s) | udp 1000: 114268 KB (udp flows: 1000/1000 answered, 4548 flows/s)

## Reproducing

```sh
gh workflow run benchmark.yml --repo Noisemux/zeptun -f duration=8 -f repeat=2
```
