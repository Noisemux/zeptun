# Benchmarks

Every number here is produced by the `benchmark` workflow in the repository, on a GitHub-hosted runner, against hev-socks5-tunnel, sing-box and tun2socks over the same SOCKS5 server.

## Machine

| property | value |
|---|---|
| runner image | ubuntu24 20261012.334.1 |
| cpu | AMD EPYC 7763 64-Core Processor |
| cpu cores | 4 |
| memory | 15.6 GB |
| kernel | Linux 6.17.0-1022-azure |
| zig | 0.16.0 |
| date | 2026-10-18 |

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
| zeptun-userspace | tcp-up-1 | 18.267 Gbit/s | 83 | 6.9 | 5.4 |
| zeptun-userspace | tcp-up-10 | 22.290 Gbit/s | 134 | 15.1 | 8.4 |
| zeptun-userspace | tcp-down-1 | 11.806 Gbit/s | 99 | 8.5 | 8.4 |
| zeptun-userspace | tcp-down-10 | 20.006 Gbit/s | 174 | 12.1 | 8.5 |
| zeptun-userspace | rr | 7154 tps p50=136us p99=168us p99.9=182us  | 36 | 8.6 | 8.5 |
| zeptun-userspace | rr-8x1k | 33137 tps p50=232us p99=448us p99.9=568us  | 100 | 8.7 | 8.6 |
| zeptun-userspace | crr | 1942 tps p50=500us p99=576us p99.9=648us  | 46 | 10.5 | 10.4 |
| zeptun-userspace | udp-100k | 97816 echo pps (97.8% of 99996 sent)  | 64 | 13.0 | 12.4 |
| zeptun-userspace | udp-gso-100k | 99810 echo pps (99.8% of 100000 sent)  | 47 | 13.2 | 12.3 |
| hev | tcp-up-1 | 12.088 Gbit/s | 95 | 8.1 | 7.9 |
| hev | tcp-up-10 | 20.962 Gbit/s | 172 | 10.0 | 8.3 |
| hev | tcp-down-1 | 12.102 Gbit/s | 98 | 8.4 | 8.3 |
| hev | tcp-down-10 | 21.206 Gbit/s | 190 | 9.0 | 8.3 |
| hev | rr | 7092 tps p50=134us p99=174us p99.9=190us  | 39 | 8.3 | 8.3 |
| hev | rr-8x1k | 31793 tps p50=228us p99=560us p99.9=696us  | 130 | 8.4 | 8.3 |
| hev | crr | 1799 tps p50=536us p99=632us p99.9=736us  | 60 | 8.3 | 8.3 |
| hev | udp-100k | 97578 echo pps (97.6% of 99988 sent)  | 78 | 8.8 | 8.8 |
| hev | udp-gso-100k | 98067 echo pps (98.1% of 99992 sent)  | 74 | 9.2 | 9.2 |
| zeptun-hybrid | tcp-up-1 | 11.589 Gbit/s | 99 | 6.0 | 5.8 |
| zeptun-hybrid | tcp-up-10 | 20.274 Gbit/s | 188 | 11.6 | 10.6 |
| zeptun-hybrid | tcp-down-1 | 12.766 Gbit/s | 99 | 10.9 | 10.4 |
| zeptun-hybrid | tcp-down-10 | 21.723 Gbit/s | 196 | 11.6 | 10.7 |
| zeptun-hybrid | rr | 6655 tps p50=144us p99=184us p99.9=204us  | 40 | 12.5 | 14.2 |
| zeptun-hybrid | rr-8x1k | 29260 tps p50=256us p99=536us p99.9=672us  | 138 | 18.2 | 17.9 |
| zeptun-hybrid | crr | 1577 tps p50=616us p99=728us p99.9=784us  | 69 | 23.5 | 23.3 |
| zeptun-hybrid | udp-100k | 98940 echo pps (98.9% of 99992 sent)  | 86 | 27.9 | 29.7 |
| zeptun-hybrid | udp-gso-100k | 99702 echo pps (99.7% of 99988 sent)  | 46 | 32.6 | 32.6 |
| singbox-system | tcp-up-1 | 6.227 Gbit/s | 144 | 62.4 | 62.0 |
| singbox-system | tcp-up-10 | 4.574 Gbit/s | 172 | 62.7 | 62.7 |
| singbox-system | tcp-down-1 | 5.304 Gbit/s | 151 | 62.7 | 62.3 |
| singbox-system | tcp-down-10 | 3.871 Gbit/s | 138 | 62.8 | 62.8 |
| singbox-system | rr | 5652 tps p50=174us p99=204us p99.9=228us  | 61 | 62.8 | 62.8 |
| singbox-system | rr-8x1k | 21989 tps p50=344us p99=696us p99.9=1000us  | 155 | 64.6 | 64.6 |
| singbox-system | crr | 1294 tps p50=760us p99=864us p99.9=1344us  | 101 | 73.5 | 73.5 |
| singbox-system | udp-100k | 0 echo pps (0.0% of 99992 sent)  | 86 | 75.7 | 75.3 |
| singbox-system | udp-gso-100k | 0 echo pps (0.0% of 99988 sent)  | 76 | 75.3 | 74.8 |
| tun2socks | tcp-up-1 | 5.078 Gbit/s | 174 | 19.4 | 18.7 |
| tun2socks | tcp-up-10 | 7.841 Gbit/s | 259 | 38.5 | 38.1 |
| tun2socks | tcp-down-1 | 2.629 Gbit/s | 171 | 40.6 | 25.8 |
| tun2socks | tcp-down-10 | 6.274 Gbit/s | 263 | 123.7 | 123.7 |
| tun2socks | rr | 4630 tps p50=216us p99=248us p99.9=324us  | 72 | 123.7 | 123.7 |
| tun2socks | rr-8x1k | 18582 tps p50=408us p99=832us p99.9=1104us  | 167 | 134.5 | 134.5 |
| tun2socks | crr | 1201 tps p50=800us p99=1024us p99.9=2208us  | 92 | 134.8 | 46.1 |
| tun2socks | udp-100k | 42962 echo pps (43.0% of 99984 sent)  | 224 | 45.9 | 53.5 |
| tun2socks | udp-gso-100k | 45524 echo pps (45.5% of 99996 sent)  | 235 | 64.6 | 61.8 |
| singbox-gvisor | tcp-up-1 | 9.195 Gbit/s | 161 | 70.7 | 70.7 |
| singbox-gvisor | tcp-up-10 | 15.103 Gbit/s | 199 | 82.0 | 82.0 |
| singbox-gvisor | tcp-down-1 | 3.233 Gbit/s | 183 | 82.1 | 82.1 |
| singbox-gvisor | tcp-down-10 | 5.821 Gbit/s | 249 | 88.2 | 87.3 |
| singbox-gvisor | rr | 4431 tps p50=224us p99=280us p99.9=348us  | 80 | 87.3 | 85.1 |
| singbox-gvisor | rr-8x1k | 17579 tps p50=440us p99=824us p99.9=1168us  | 169 | 74.6 | 73.3 |
| singbox-gvisor | crr | 1162 tps p50=840us p99=1008us p99.9=1808us  | 103 | 76.9 | 76.9 |
| singbox-gvisor | udp-100k | 0 echo pps (0.0% of 99991 sent)  | 169 | 77.4 | 77.1 |
| singbox-gvisor | udp-gso-100k | 0  | 0 | 77.1 | 77.1 |

zeptun: startup 3 ms, idle 844 KB, 5 wakeups in 20 s | tcp 1000: 4048 KB (conns: 1000/1000 established, 0 failed, 1898 conn/s) | udp 1000: 8248 KB (udp flows: 1000/1000 answered, 8241 flows/s)
hev: startup 3 ms, idle 525 KB, 2 wakeups in 20 s | tcp 1000: 9286 KB (conns: 1000/1000 established, 0 failed, 1931 conn/s) | udp 1000: 9218 KB (udp flows: 1000/1000 answered, 7472 flows/s)
singbox-system: startup 49 ms, idle 58189 KB, 6 wakeups in 20 s | tcp 1000: 73440 KB (conns: 1000/1000 established, 0 failed, 1350 conn/s) | udp 1000: 69664 KB (udp flows: 0/1000 answered, 0 flows/s)
singbox-gvisor: startup 50 ms, idle 58245 KB, 122 wakeups in 20 s | tcp 1000: 94576 KB (conns: 1000/1000 established, 0 failed, 1270 conn/s) | udp 1000: 103720 KB (udp flows: 0/1000 answered, 0 flows/s)
tun2socks: startup 5 ms, idle 13784 KB, 256 wakeups in 20 s | tcp 1000: 109316 KB (conns: 1000/1000 established, 0 failed, 1208 conn/s) | udp 1000: 183732 KB (udp flows: 1000/1000 answered, 6000 flows/s)

## Reproducing

```sh
gh workflow run benchmark.yml --repo Noisemux/zeptun -f duration=8 -f repeat=2
```
