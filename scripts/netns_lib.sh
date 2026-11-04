SERVER_ADDR=10.99.0.1
SERVER_ADDR6=fd99::1
VETH_CLIENT=192.168.77.1
VETH_SERVER=192.168.77.2
VETH_MTU=${VETH_MTU:-9000}
TUN_NAME=${TUN_NAME:-zep0}
SERVER_PID=""
BG_PIDS=""

in_server() {
    nsenter --target "$SERVER_PID" --net -- "$@"
}

ns_setup() {
    unshare --net -- sleep 1000000 &
    SERVER_PID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if [ "$(readlink /proc/$SERVER_PID/ns/net)" != "$(readlink /proc/self/ns/net)" ]; then break; fi
        sleep 0.1
    done
    ip link set lo up
    ip link add veth0 mtu "$VETH_MTU" type veth peer name veth1 mtu "$VETH_MTU"
    ip link set veth1 netns "$SERVER_PID"
    ip addr add "$VETH_CLIENT/24" dev veth0
    ip link set veth0 up
    ip route add default via "$VETH_SERVER"
    in_server ip link set lo up
    in_server ip addr add "$VETH_SERVER/24" dev veth1
    in_server ip link set veth1 up
    in_server ip addr add "$SERVER_ADDR/32" dev lo
    in_server ip route add default via "$VETH_CLIENT"
    if [ "${WAN_DELAY_MS:-0}" != "0" ]; then
        tc qdisc add dev veth0 root netem delay "${WAN_DELAY_MS}ms" limit 100000
        in_server tc qdisc add dev veth1 root netem delay "${WAN_DELAY_MS}ms" limit 100000
    fi
}

bg_server() {
    nsenter --target "$SERVER_PID" --net -- "$@" > /dev/null 2>&1 &
    BG_PIDS="$BG_PIDS $!"
}

ns_teardown() {
    for pid in $BG_PIDS; do kill "$pid" 2> /dev/null || true; done
    if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2> /dev/null || true; fi
    wait 2> /dev/null || true
}

wait_tun() {
    for _ in $(seq 1 100); do
        if ip -o link show "$TUN_NAME" 2> /dev/null | grep -q "UP"; then
            if ip rule show | grep -q "lookup 2022"; then return 0; fi
        fi
        sleep 0.05
    done
    printf '  %s never came up, or no rule points at table 2022\n' "$TUN_NAME" >&2
    return 1
}

# Says whether traffic to the benchmark servers really leaves through $TUN_NAME.
#
# Without this an engine that failed to start is not noticed: its table stays empty, the main
# table still holds a default route through the veth, and every scenario then measures the bare
# veth. That reads as line rate at no CPU cost, which looks like a result and is not one.
verify_path() {
    got=$(ip route get "$SERVER_ADDR" 2> /dev/null | head -1)
    case "$got" in
        *"dev $TUN_NAME"*) return 0 ;;
    esac
    printf '  %s does not carry the traffic: `ip route get %s` says `%s`\n' \
        "$TUN_NAME" "$SERVER_ADDR" "$got" >&2
    return 1
}

wait_port() {
    for _ in $(seq 1 100); do
        if in_server ss -Hltn "sport = :$1" | grep -q LISTEN; then return 0; fi
        if in_server ss -Hlun "sport = :$1" | grep -q UNCONN; then return 0; fi
        sleep 0.05
    done
    return 1
}
