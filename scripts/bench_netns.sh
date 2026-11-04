#!/bin/sh
set -eu

if [ "${ZEPTUN_BENCH_INNER:-}" != "1" ]; then
    export ZEPTUN_BENCH_INNER=1
    exec unshare --user --map-root-user --net --fork -- sh "$0" "$@"
fi

SCRIPT_DIR=$(dirname "$(realpath "$0")")
. "$SCRIPT_DIR/netns_lib.sh"

ZEPTUN=$(realpath "${ZEPTUN:-zig-out/bin/zeptun}")
BENCH=$(realpath "${BENCH:-zig-out/bin/zeptun-bench}")
IPERF3=${IPERF3:-$(command -v iperf3 || true)}
HEV=${HEV:-}
TUN2SOCKS=${TUN2SOCKS:-}
SINGBOX=${SINGBOX:-}
SOCKS_SERVER=${SOCKS_SERVER:-}
DURATION=${DURATION:-10}
REPEAT=${REPEAT:-3}
QUEUES=${QUEUES:-$(nproc)}
MTU=${MTU:-8500}
SETTLE=${SETTLE:-5}
ENGINES=${ENGINES:-"zeptun-hybrid zeptun-userspace hev"}
SCENARIOS=${SCENARIOS:-"tcp-up-1 tcp-up-10 tcp-down-1 rr rr-8x1k"}
ZEPTUN_ARGS=${ZEPTUN_ARGS:-}
OUT_DIR=${OUT_DIR:-bench-results}
mkdir -p "$OUT_DIR"
OUT_DIR=$(realpath "$OUT_DIR")
RESULTS="$OUT_DIR/results.jsonl"
: > "$RESULTS"

ns_setup
for knob in "net.ipv4.tcp_tw_reuse=1" "net.ipv4.ip_local_port_range=1024 65000"; do
    sysctl -qw "$knob" 2> /dev/null || true
    in_server sysctl -qw "$knob" 2> /dev/null || true
done
cleanup() {
    for pid in ${ENGINE_PIDS:-}; do kill "$pid" 2> /dev/null || true; done
    ns_teardown
}
trap cleanup EXIT INT TERM

if [ -n "$IPERF3" ]; then
    bg_server "$IPERF3" -s -B "$SERVER_ADDR" -p 5201
else
    bg_server "$BENCH" tcp-server --listen "$SERVER_ADDR:5201"
fi
bg_server "$BENCH" tcp-server --listen "$SERVER_ADDR:5203"
bg_server "$BENCH" udp-server --listen "$SERVER_ADDR:5202" --echo
if [ -n "$SOCKS_SERVER" ]; then
    printf "main:\n  workers: %s\n  port: 1080\n  listen-address: '%s'\n" "$(nproc)" "$VETH_SERVER" > "$OUT_DIR/socks5-server.yml"
    bg_server "$SOCKS_SERVER" "$OUT_DIR/socks5-server.yml"
else
    bg_server "$BENCH" socks5-server --listen "$VETH_SERVER:1080"
fi
wait_port 5201
wait_port 5203
wait_port 5202
wait_port 1080

ENGINE_PIDS=""

install_routes() {
    ip route replace default dev "$1" table 2022 || return 1
    ip rule add pref 9000 lookup main suppress_prefixlength 0 || return 1
    ip rule add pref 9001 lookup 2022 || return 1
}

remove_routes() {
    ip rule del pref 9001 lookup 2022 2> /dev/null || true
    ip rule del pref 9000 lookup main suppress_prefixlength 0 2> /dev/null || true
    ip route flush table 2022 2> /dev/null || true
}

start_engine() {
    engine=$1
    ENGINE_PIDS=""
    case "$engine" in
        zeptun-*)
            spec=${engine#zeptun-}
            mode=${spec%%+*}
            extra=""
            if [ "$spec" != "$mode" ]; then
                for flag in $(printf "%s" "${spec#*+}" | tr '+' ' '); do
                    case "$flag" in
                        *=*) extra="$extra --${flag%%=*} ${flag#*=}" ;;
                        *) extra="$extra --$flag" ;;
                    esac
                done
            fi
            "$ZEPTUN" run --tun zep0 --mtu "$MTU" --queues "$QUEUES" --stack "$mode" --socks5 "$VETH_SERVER:1080" --auto-route --log-level warn $extra $ZEPTUN_ARGS > "$OUT_DIR/$engine.log" 2>&1 &
            ENGINE_PIDS=$!
            TUN_NAME=zep0
            wait_tun || return 1
            ;;
        tun2socks)
            [ -n "$TUN2SOCKS" ] || return 1
            "$TUN2SOCKS" -d tun://t2s0 -p "socks5://$VETH_SERVER:1080" --mtu "$MTU" --loglevel error > "$OUT_DIR/tun2socks.log" 2>&1 &
            ENGINE_PIDS=$!
            for _ in $(seq 1 50); do ip -o link show t2s0 > /dev/null 2>&1 && break; sleep 0.1; done
            ip -o link show t2s0 > /dev/null 2>&1 || return 1
            ip addr add 198.18.0.1/15 dev t2s0
            ip link set t2s0 up
            TUN_NAME=t2s0
            install_routes t2s0 || return 1
            wait_tun || return 1
            ;;
        singbox-*)
            [ -n "$SINGBOX" ] || return 1
            stack=${engine#singbox-}
            printf '{"log":{"level":"error"},"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"sb0","address":["172.18.0.1/30"],"mtu":%s,"auto_route":false,"stack":"%s"}],"outbounds":[{"type":"socks","tag":"proxy","server":"%s","server_port":1080}],"route":{"final":"proxy"}}' "$MTU" "$stack" "$VETH_SERVER" > "$OUT_DIR/singbox.json"
            "$SINGBOX" run -c "$OUT_DIR/singbox.json" > "$OUT_DIR/$engine.log" 2>&1 &
            ENGINE_PIDS=$!
            TUN_NAME=sb0
            install_routes sb0 || return 1
            wait_tun || return 1
            ;;
        hev)
            [ -n "$HEV" ] || return 1
            if [ "$QUEUES" -gt 1 ]; then multi=true; else multi=false; fi
            printf "tunnel:\n  name: hev0\n  mtu: %s\n  multi-queue: %s\n  ipv4: 198.18.0.1\nsocks5:\n  port: 1080\n  address: %s\n  udp: 'udp'\n  pipeline: true\nmisc:\n  log-level: error\n" "$MTU" "$multi" "$VETH_SERVER" > "$OUT_DIR/hev.yml"
            i=0
            while [ "$i" -lt "$QUEUES" ]; do
                "$HEV" "$OUT_DIR/hev.yml" > "$OUT_DIR/hev-$i.log" 2>&1 &
                ENGINE_PIDS="$ENGINE_PIDS $!"
                i=$((i + 1))
                sleep 0.2
            done
            for _ in $(seq 1 50); do
                ip -o link show hev0 2> /dev/null | grep -q UP && break
                sleep 0.1
            done
            TUN_NAME=hev0
            install_routes hev0 || return 1
            wait_tun || return 1
            ;;
    esac
    sleep 1
    verify_path || return 1
}

stop_engine() {
    for pid in $ENGINE_PIDS; do kill -INT "$pid" 2> /dev/null || true; done
    for pid in $ENGINE_PIDS; do
        for _ in $(seq 1 50); do kill -0 "$pid" 2> /dev/null || break; sleep 0.1; done
        kill -9 "$pid" 2> /dev/null || true
        wait "$pid" 2> /dev/null || true
    done
    case "$1" in hev|tun2socks|singbox-*) remove_routes ;; esac
    ENGINE_PIDS=""
    sleep 0.5
}

engine_memory() {
    mem_rss=0
    mem_pss=0
    for pid in $ENGINE_PIDS; do
        r=$(awk '/^VmRSS:/ {print $2}' /proc/"$pid"/status 2> /dev/null || echo 0)
        p=$(awk '/^Pss:/ {s += $2} END {printf "%d", s}' /proc/"$pid"/smaps_rollup 2> /dev/null || echo 0)
        mem_rss=$((mem_rss + ${r:-0}))
        mem_pss=$((mem_pss + ${p:-0}))
    done
    printf '%s %s\n' "$mem_rss" "$mem_pss"
}

monitor_engine() {
    tag=$1
    MON_PIDS=""
    for pid in $ENGINE_PIDS; do
        "$BENCH" monitor --pid "$pid" --seconds "$DURATION" --interval-ms 500 --json "$OUT_DIR/mon-$tag-$pid.json" > /dev/null 2>&1 &
        MON_PIDS="$MON_PIDS $!"
    done
}

summarize_monitor() {
    python3 - "$OUT_DIR" "$1" << 'PY'
import glob, json, sys
out, tag = sys.argv[1], sys.argv[2]
cpu = 0.0
rss = 0
pss = 0
for f in glob.glob(f"{out}/mon-{tag}-*.json"):
    try:
        m = json.load(open(f))
    except Exception:
        continue
    cpu += m.get("avg_cpu_pct", 0.0)
    rss += m.get("max_rss_kb", 0)
    pss += m.get("max_pss_kb", 0)
print(f"{cpu:.1f} {rss} {pss}")
PY
}

run_scenario() {
    engine=$1
    scenario=$2
    rep=$3
    tag="$engine-$scenario-$rep"
    rm -f "$OUT_DIR"/mon-"$tag"-*.json
    monitor_engine "$tag"
    value=""
    unit=""
    case "$scenario" in
        tcp-up-*|tcp-down-*)
            streams=${scenario##*-}
            reverse=""
            case "$scenario" in tcp-down-*) reverse=1 ;; esac
            if [ -n "$IPERF3" ]; then
                "$IPERF3" -c "$SERVER_ADDR" -p 5201 -t "$DURATION" -P "$streams" ${reverse:+-R} -J > "$OUT_DIR/$tag.json" 2> /dev/null || true
                value=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('%.3f' % (d['end']['sum_received']['bits_per_second']/1e9))" "$OUT_DIR/$tag.json" 2> /dev/null || echo 0)
            else
                "$BENCH" tcp-client --connect "$SERVER_ADDR:5201" --seconds "$DURATION" --streams "$streams" ${reverse:+--reverse} --json "$OUT_DIR/$tag.json" > /dev/null 2>&1 || true
                value=$(python3 -c "import json,sys; print('%.3f' % json.load(open(sys.argv[1]))['gbps'])" "$OUT_DIR/$tag.json" 2> /dev/null || echo 0)
            fi
            unit=Gbit/s
            ;;
        rr|rr-8x1k|crr|rr-bulk-*|*-at-*)
            conns=1
            size=64
            extra=""
            bulk=""
            case "$scenario" in *-at-*) extra="--rate ${scenario##*-at-}" ;; esac
            case "$scenario" in
                rr-8x1k|rr-8x1k-at-*) conns=8; size=1024 ;;
                crr|crr-at-*) extra="$extra --crr" ;;
                rr-bulk-*)
                    "$BENCH" tcp-client --connect "$SERVER_ADDR:5203" --seconds $((DURATION + 3)) --streams 4 --mbps "${scenario#rr-bulk-}" --json "$OUT_DIR/$tag-bulk.json" > /dev/null 2>&1 &
                    bulk=$!
                    sleep 1
                    ;;
            esac
            "$BENCH" rr-client --connect "$SERVER_ADDR:5203" --seconds "$DURATION" --conns "$conns" --size "$size" $extra --json "$OUT_DIR/$tag.json" > /dev/null 2>&1 || true
            if [ -n "$bulk" ]; then wait "$bulk" 2> /dev/null || true; fi
            value=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('%.0f tps p50=%.0fus p99=%.0fus p99.9=%.0fus%s' % (d['tps'], d['p50_us'], d['p99_us'], d.get('p999_us', 0), (' errors=%d' % d['errors']) if d.get('errors') else ''))" "$OUT_DIR/$tag.json" 2> /dev/null || echo 0)
            unit=""
            ;;
        udp|udp-*)
            size=512
            pps=0
            gso=""
            case "$scenario" in
                udp-gso-*) gso="--gso"; size=1200; pps=${scenario#udp-gso-} ;;
                udp-*) size=1200; pps=${scenario#udp-} ;;
            esac
            case "$pps" in *k) pps=$((${pps%k} * 1000)) ;; esac
            "$BENCH" udp-client --connect "$SERVER_ADDR:5202" --seconds "$DURATION" --size "$size" --pps "$pps" --echo $gso --json "$OUT_DIR/$tag.json" > /dev/null 2>&1 || true
            value=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('%.0f echo pps (%.1f%% of %.0f sent)' % (d['received']/d['seconds'], 100.0*d['received']/max(d['sent'],1), d['sent']/d['seconds']))" "$OUT_DIR/$tag.json" 2> /dev/null || echo 0)
            unit=""
            ;;
    esac
    for mp in $MON_PIDS; do wait "$mp" 2> /dev/null || true; done
    set -- $(summarize_monitor "$tag")
    cpu_pct=$1
    peak_rss=$2
    peak_pss=$3
    sleep "$SETTLE"
    set -- $(engine_memory)
    printf '{"engine":"%s","scenario":"%s","rep":%s,"value":"%s","unit":"%s","cpu_pct":%s,"rss_kb":%s,"pss_kb":%s,"rss_after_kb":%s,"pss_after_kb":%s,"settle_s":%s,"mtu":%s,"queues":%s}\n' "$engine" "$scenario" "$rep" "$value" "$unit" "$cpu_pct" "$peak_rss" "$peak_pss" "$1" "$2" "$SETTLE" "$MTU" "$QUEUES" >> "$RESULTS"
    printf "  %-18s %-12s rep %s: %s %s cpu %s%% rss %s KB, %s KB after %ss idle\n" "$engine" "$scenario" "$rep" "$value" "$unit" "$cpu_pct" "$peak_rss" "$1" "$SETTLE"
}

rep=1
while [ "$rep" -le "$REPEAT" ]; do
    for engine in $ENGINES; do
        case "$engine" in
            hev) [ -n "$HEV" ] || continue ;;
            tun2socks) [ -n "$TUN2SOCKS" ] || continue ;;
            singbox-*) [ -n "$SINGBOX" ] || continue ;;
        esac
        printf "round %s engine %s\n" "$rep" "$engine"
        if ! start_engine "$engine"; then
            printf "  failed to start %s\n" "$engine"
            stop_engine "$engine"
            continue
        fi
        for scenario in $SCENARIOS; do
            run_scenario "$engine" "$scenario" "$rep"
        done
        stop_engine "$engine"
    done
    rep=$((rep + 1))
done

python3 - "$RESULTS" "$OUT_DIR/summary.md" << 'PY'
import json, statistics, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
groups = {}
for r in rows:
    groups.setdefault((r["engine"], r["scenario"]), []).append(r)
lines = ["| engine | scenario | median | cpu % | max rss MB | rss after idle MB |", "|---|---|---:|---:|---:|---:|"]
for (engine, scenario), rs in groups.items():
    def num(v):
        try:
            return float(str(v).split()[0])
        except ValueError:
            return 0.0
    vals = sorted(rs, key=lambda r: num(r["value"]))
    mid = vals[len(vals) // 2]
    cpu = statistics.median(r["cpu_pct"] for r in rs)
    rss = max(r["rss_kb"] for r in rs) / 1024
    after = max(r.get("rss_after_kb", 0) for r in rs) / 1024
    lines.append(f"| {engine} | {scenario} | {mid['value']} {mid['unit']} | {cpu:.0f} | {rss:.1f} | {after:.1f} |")
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
