# Benchmarks

Every number here is produced by the `benchmark` workflow in the repository, on a GitHub-hosted runner, against hev-socks5-tunnel, sing-box and tun2socks over the same SOCKS5 server.

## Machine

| property | value |
|---|---|
| runner image | ubuntu24 20260927.320.1 |
| cpu | AMD EPYC 7763 64-Core Processor |
| cpu cores | 4 |
| memory | 15.6 GB |
| kernel | Linux 6.17.0-1022-azure |
| zig | 0.16.0 |
| date | 2026-10-07 |

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
| zeptun-userspace | tcp-up-1 | 18.642 Gbit/s | 83 | 10.8 | 9.4 |
| zeptun-userspace | tcp-up-10 | 22.283 Gbit/s | 129 | 16.1 | 9.9 |
| zeptun-userspace | tcp-down-1 | 11.921 Gbit/s | 99 | 12.2 | 12.1 |
| zeptun-userspace | tcp-down-10 | 20.182 Gbit/s | 178 | 18.3 | 14.5 |
| zeptun-userspace | rr | 7291 tps p50=130us p99=168us p99.9=186us  | 36 | 14.6 | 14.5 |
| zeptun-userspace | rr-8x1k | 33539 tps p50=226us p99=460us p99.9=592us  | 95 | 14.6 | 14.5 |
| zeptun-userspace | crr | 1993 tps p50=488us p99=544us p99.9=608us  | 44 | 15.4 | 15.3 |
| zeptun-userspace | udp-100k | 79156 echo pps (79.2% of 99988 sent)  | 72 | 16.3 | 15.3 |
| zeptun-userspace | udp-gso-100k | 80158 echo pps (80.2% of 99988 sent)  | 54 | 16.2 | 15.2 |
| hev | tcp-up-1 | 5.976 Gbit/s | 96 | 14.8 | 14.6 |
| hev | tcp-up-10 | 13.462 Gbit/s | 222 | 16.2 | 15.3 |
| hev | tcp-down-1 | 6.554 Gbit/s | 99 | 15.5 | 15.3 |
| hev | tcp-down-10 | 10.933 Gbit/s | 213 | 16.1 | 15.3 |
| hev | rr | 6975 tps p50=142us p99=172us p99.9=200us  | 39 | 15.4 | 15.3 |
| hev | rr-8x1k | 31294 tps p50=240us p99=520us p99.9=664us  | 130 | 15.9 | 15.3 |
| hev | crr | 1760 tps p50=552us p99=624us p99.9=672us  | 65 | 15.5 | 15.3 |
| hev | udp-100k | 75990 echo pps (76.0% of 99992 sent)  | 99 | 18.0 | 18.0 |
| hev | udp-gso-100k | 75414 echo pps (75.4% of 99992 sent)  | 98 | 18.0 | 18.0 |
| zeptun-hybrid | tcp-up-1 | 11.611 Gbit/s | 99 | 6.0 | 5.8 |
| zeptun-hybrid | tcp-up-10 | 20.393 Gbit/s | 174 | 11.5 | 10.5 |
| zeptun-hybrid | tcp-down-1 | 12.882 Gbit/s | 100 | 10.8 | 10.3 |
| zeptun-hybrid | tcp-down-10 | 23.388 Gbit/s | 200 | 11.6 | 10.7 |
| zeptun-hybrid | rr | 6424 tps p50=150us p99=184us p99.9=206us  | 41 | 12.6 | 14.4 |
| zeptun-hybrid | rr-8x1k | 31267 tps p50=248us p99=448us p99.9=576us  | 141 | 14.5 | 16.2 |
| zeptun-hybrid | crr | 1562 tps p50=624us p99=728us p99.9=792us  | 68 | 23.1 | 23.0 |
| zeptun-hybrid | udp-100k | 81275 echo pps (81.3% of 99988 sent)  | 95 | 27.2 | 30.0 |
| zeptun-hybrid | udp-gso-100k | 79082 echo pps (79.1% of 99992 sent)  | 55 | 32.6 | 32.1 |
| singbox-system | tcp-up-1 | 6.128 Gbit/s | 136 | 61.5 | 61.5 |
| singbox-system | tcp-up-10 | 4.605 Gbit/s | 171 | 62.2 | 62.0 |
| singbox-system | tcp-down-1 | 5.307 Gbit/s | 152 | 62.0 | 61.7 |
| singbox-system | tcp-down-10 | 3.842 Gbit/s | 138 | 62.1 | 62.1 |
| singbox-system | rr | 5676 tps p50=172us p99=200us p99.9=226us  | 62 | 62.1 | 62.1 |
| singbox-system | rr-8x1k | 21824 tps p50=348us p99=704us p99.9=1008us  | 154 | 62.2 | 61.9 |
| singbox-system | crr | 1277 tps p50=768us p99=880us p99.9=1600us  | 101 | 72.9 | 72.9 |
| singbox-system | udp-100k | 0 echo pps (0.0% of 99992 sent)  | 87 | 75.4 | 75.0 |
| singbox-system | udp-gso-100k | 0 echo pps (0.0% of 99992 sent)  | 76 | 75.1 | 75.1 |
| tun2socks | tcp-up-1 | 5.000 Gbit/s | 174 | 21.6 | 21.1 |
| tun2socks | tcp-up-10 | 7.636 Gbit/s | 259 | 38.5 | 38.5 |
| tun2socks | tcp-down-1 | 2.602 Gbit/s | 171 | 40.6 | 26.3 |
| tun2socks | tcp-down-10 | 6.264 Gbit/s | 261 | 130.0 | 130.0 |
| tun2socks | rr | 4579 tps p50=218us p99=250us p99.9=568us  | 72 | 130.0 | 130.0 |
| tun2socks | rr-8x1k | 18395 tps p50=416us p99=832us p99.9=1088us  | 167 | 142.8 | 142.8 |
| tun2socks | crr | 1177 tps p50=816us p99=1024us p99.9=2656us  | 91 | 142.8 | 41.6 |
| tun2socks | udp-100k | 40018 echo pps (40.0% of 99988 sent)  | 218 | 47.7 | 52.2 |
| tun2socks | udp-gso-100k | 42519 echo pps (42.5% of 99988 sent)  | 229 | 58.9 | 58.4 |
| singbox-gvisor | tcp-up-1 | 9.293 Gbit/s | 158 | 70.8 | 70.8 |
| singbox-gvisor | tcp-up-10 | 15.214 Gbit/s | 197 | 82.0 | 81.8 |
| singbox-gvisor | tcp-down-1 | 3.251 Gbit/s | 183 | 82.1 | 81.9 |
| singbox-gvisor | tcp-down-10 | 5.864 Gbit/s | 247 | 88.2 | 88.2 |
| singbox-gvisor | rr | 4404 tps p50=226us p99=296us p99.9=364us  | 80 | 88.2 | 84.0 |
| singbox-gvisor | rr-8x1k | 17602 tps p50=436us p99=832us p99.9=1232us  | 168 | 75.7 | 74.0 |
| singbox-gvisor | crr | 1156 tps p50=848us p99=1024us p99.9=1840us  | 104 | 77.9 | 77.9 |
| singbox-gvisor | udp-100k | 0 echo pps (0.0% of 99989 sent)  | 168 | 78.1 | 77.9 |
| singbox-gvisor | udp-gso-100k | 0  | 0 | 77.9 | 77.9 |

zeptun: startup 3 ms, idle 844 KB, 5 wakeups in 20 s | tcp 1000: 6088 KB (conns: 1000/1000 established, 0 failed, 1820 conn/s) | udp 1000: 4232 KB (udp flows: 1000/1000 answered, 8466 flows/s)
hev: startup 3 ms, idle 2221 KB, 2 wakeups in 20 s | tcp 1000: 78794 KB (conns: 1000/1000 established, 0 failed, 1909 conn/s) | udp 1000: 27330 KB (udp flows: 1000/1000 answered, 7504 flows/s)
singbox-system: startup 50 ms, idle 58157 KB, 6 wakeups in 20 s | tcp 1000: 75464 KB (conns: 1000/1000 established, 0 failed, 1357 conn/s) | udp 1000: 70512 KB (udp flows: 0/1000 answered, 0 flows/s)
singbox-gvisor: startup 42 ms, idle 58601 KB, 124 wakeups in 20 s | tcp 1000: 95020 KB (conns: 1000/1000 established, 0 failed, 1241 conn/s) | udp 1000: 103352 KB (udp flows: 0/1000 answered, 0 flows/s)
tun2socks: startup 5 ms, idle 13784 KB, 277 wakeups in 20 s | tcp 1000: 109240 KB (conns: 1000/1000 established, 0 failed, 1161 conn/s) | udp 1000: 183864 KB (udp flows: 1000/1000 answered, 5832 flows/s)

## Reproducing

```sh
gh workflow run benchmark.yml --repo Noisemux/zeptun -f duration=8 -f repeat=2
```
