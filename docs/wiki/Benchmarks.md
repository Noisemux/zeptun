# Benchmarks

Every number here is produced by the `benchmark` workflow in the repository, on a GitHub-hosted runner, against hev-socks5-tunnel, sing-box and tun2socks over the same SOCKS5 server.

## Machine

| property | value |
|---|---|
| runner image | ubuntu24 20261004.327.1 |
| cpu | AMD EPYC 7763 64-Core Processor |
| cpu cores | 4 |
| memory | 15.6 GB |
| kernel | Linux 6.17.0-1022-azure |
| zig | 0.16.0 |
| date | 2026-10-11 |

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
| zeptun-userspace | tcp-up-1 | 18.775 Gbit/s | 83 | 8.9 | 7.4 |
| zeptun-userspace | tcp-up-10 | 22.605 Gbit/s | 137 | 17.4 | 10.4 |
| zeptun-userspace | tcp-down-1 | 11.400 Gbit/s | 99 | 12.2 | 12.1 |
| zeptun-userspace | tcp-down-10 | 19.661 Gbit/s | 178 | 15.9 | 12.4 |
| zeptun-userspace | rr | 7170 tps p50=134us p99=172us p99.9=194us  | 36 | 12.5 | 12.5 |
| zeptun-userspace | rr-8x1k | 33289 tps p50=230us p99=440us p99.9=560us  | 102 | 12.6 | 12.5 |
| zeptun-userspace | crr | 1903 tps p50=508us p99=592us p99.9=720us  | 45 | 13.6 | 13.6 |
| zeptun-userspace | udp-100k | 80268 echo pps (80.3% of 99992 sent)  | 74 | 15.1 | 14.3 |
| zeptun-userspace | udp-gso-100k | 79367 echo pps (79.4% of 99996 sent)  | 54 | 17.2 | 16.2 |
| hev | tcp-up-1 | 5.997 Gbit/s | 96 | 14.6 | 14.6 |
| hev | tcp-up-10 | 13.394 Gbit/s | 219 | 15.4 | 15.1 |
| hev | tcp-down-1 | 6.721 Gbit/s | 99 | 15.2 | 15.1 |
| hev | tcp-down-10 | 11.112 Gbit/s | 210 | 15.8 | 15.1 |
| hev | rr | 7160 tps p50=136us p99=172us p99.9=348us  | 39 | 15.1 | 15.1 |
| hev | rr-8x1k | 32082 tps p50=238us p99=480us p99.9=600us  | 128 | 15.3 | 15.1 |
| hev | crr | 1749 tps p50=552us p99=664us p99.9=776us  | 59 | 15.2 | 15.1 |
| hev | udp-100k | 74921 echo pps (74.9% of 99988 sent)  | 99 | 17.8 | 17.8 |
| hev | udp-gso-100k | 74967 echo pps (75.0% of 99988 sent)  | 99 | 20.6 | 20.6 |
| zeptun-hybrid | tcp-up-1 | 12.016 Gbit/s | 99 | 7.9 | 7.7 |
| zeptun-hybrid | tcp-up-10 | 19.994 Gbit/s | 186 | 15.4 | 14.5 |
| zeptun-hybrid | tcp-down-1 | 12.668 Gbit/s | 100 | 14.8 | 14.4 |
| zeptun-hybrid | tcp-down-10 | 22.394 Gbit/s | 199 | 15.5 | 14.6 |
| zeptun-hybrid | rr | 6346 tps p50=152us p99=194us p99.9=428us  | 41 | 14.6 | 14.4 |
| zeptun-hybrid | rr-8x1k | 30570 tps p50=242us p99=528us p99.9=640us  | 146 | 14.5 | 18.0 |
| zeptun-hybrid | crr | 1544 tps p50=632us p99=752us p99.9=888us  | 68 | 19.4 | 20.6 |
| zeptun-hybrid | udp-100k | 80814 echo pps (80.8% of 99988 sent)  | 97 | 26.6 | 26.3 |
| zeptun-hybrid | udp-gso-100k | 79446 echo pps (79.4% of 99996 sent)  | 55 | 30.8 | 30.3 |
| singbox-system | tcp-up-1 | 6.217 Gbit/s | 140 | 61.7 | 61.7 |
| singbox-system | tcp-up-10 | 4.611 Gbit/s | 171 | 63.7 | 63.7 |
| singbox-system | tcp-down-1 | 5.380 Gbit/s | 152 | 63.7 | 63.5 |
| singbox-system | tcp-down-10 | 3.849 Gbit/s | 138 | 63.7 | 63.7 |
| singbox-system | rr | 5620 tps p50=172us p99=206us p99.9=234us  | 61 | 63.7 | 63.7 |
| singbox-system | rr-8x1k | 22166 tps p50=344us p99=688us p99.9=936us  | 155 | 63.7 | 63.4 |
| singbox-system | crr | 1282 tps p50=760us p99=880us p99.9=1472us  | 100 | 72.5 | 72.5 |
| singbox-system | udp-100k | 0 echo pps (0.0% of 99992 sent)  | 86 | 75.1 | 75.1 |
| singbox-system | udp-gso-100k | 0 echo pps (0.0% of 99988 sent)  | 76 | 75.1 | 75.0 |
| tun2socks | tcp-up-1 | 5.125 Gbit/s | 174 | 21.2 | 21.0 |
| tun2socks | tcp-up-10 | 7.874 Gbit/s | 260 | 38.5 | 38.2 |
| tun2socks | tcp-down-1 | 2.609 Gbit/s | 171 | 40.5 | 27.6 |
| tun2socks | tcp-down-10 | 6.293 Gbit/s | 263 | 129.6 | 129.9 |
| tun2socks | rr | 4613 tps p50=214us p99=256us p99.9=640us  | 73 | 130.0 | 130.0 |
| tun2socks | rr-8x1k | 18382 tps p50=416us p99=840us p99.9=1168us  | 168 | 142.7 | 142.7 |
| tun2socks | crr | 1182 tps p50=816us p99=1040us p99.9=2432us  | 91 | 144.4 | 47.5 |
| tun2socks | udp-100k | 39921 echo pps (39.9% of 99984 sent)  | 217 | 49.2 | 55.8 |
| tun2socks | udp-gso-100k | 43447 echo pps (43.4% of 99996 sent)  | 232 | 56.0 | 64.9 |
| singbox-gvisor | tcp-up-1 | 9.222 Gbit/s | 159 | 69.6 | 69.6 |
| singbox-gvisor | tcp-up-10 | 14.769 Gbit/s | 199 | 80.9 | 80.9 |
| singbox-gvisor | tcp-down-1 | 3.178 Gbit/s | 183 | 81.0 | 82.0 |
| singbox-gvisor | tcp-down-10 | 5.755 Gbit/s | 249 | 89.4 | 88.9 |
| singbox-gvisor | rr | 4378 tps p50=226us p99=324us p99.9=560us  | 80 | 88.9 | 73.0 |
| singbox-gvisor | rr-8x1k | 17484 tps p50=440us p99=856us p99.9=1344us  | 169 | 74.9 | 74.5 |
| singbox-gvisor | crr | 1146 tps p50=848us p99=1040us p99.9=1856us  | 104 | 77.9 | 77.9 |
| singbox-gvisor | udp-100k | 0 echo pps (0.0% of 99995 sent)  | 168 | 79.0 | 78.3 |
| singbox-gvisor | udp-gso-100k | 0  | 0 | 78.3 | 78.3 |

zeptun: startup 4 ms, idle 2876 KB, 5 wakeups in 20 s | tcp 1000: 6128 KB (conns: 1000/1000 established, 0 failed, 1891 conn/s) | udp 1000: 8264 KB (udp flows: 1000/1000 answered, 6422 flows/s)
hev: startup 3 ms, idle 2221 KB, 2 wakeups in 20 s | tcp 1000: 14774 KB (conns: 1000/1000 established, 0 failed, 1888 conn/s) | udp 1000: 19314 KB (udp flows: 1000/1000 answered, 7418 flows/s)
singbox-system: startup 51 ms, idle 57489 KB, 6 wakeups in 20 s | tcp 1000: 73608 KB (conns: 1000/1000 established, 0 failed, 1301 conn/s) | udp 1000: 68740 KB (udp flows: 0/1000 answered, 0 flows/s)
singbox-gvisor: startup 42 ms, idle 60853 KB, 122 wakeups in 20 s | tcp 1000: 94980 KB (conns: 1000/1000 established, 0 failed, 1246 conn/s) | udp 1000: 96724 KB (udp flows: 0/1000 answered, 0 flows/s)
tun2socks: startup 5 ms, idle 15836 KB, 201 wakeups in 20 s | tcp 1000: 109324 KB (conns: 1000/1000 established, 0 failed, 1213 conn/s) | udp 1000: 185852 KB (udp flows: 1000/1000 answered, 5762 flows/s)

## Reproducing

```sh
gh workflow run benchmark.yml --repo Noisemux/zeptun -f duration=8 -f repeat=2
```
