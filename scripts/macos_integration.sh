#!/bin/sh
set -eu

ZEPTUN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
LOG_DIR=${LOG_DIR:-$(mktemp -d)}
TUN_NAME=${TUN_NAME:-utun9}
TUN_ADDR=${TUN_ADDR:-172.19.0.1}
HTTP_TARGET=${HTTP_TARGET:-1.1.1.1}
DNS_TARGET=${DNS_TARGET:-8.8.8.8}

PASSED=0
FAILED=0
FAILURES=""

check() {
    label=$1
    shift
    if "$@" > "$LOG_DIR/step.log" 2>&1; then
        PASSED=$((PASSED + 1))
        printf "  ok    %-46s %s\n" "$label" "$(tail -n 1 "$LOG_DIR/step.log")"
    else
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES\n  $label"
        printf "  FAIL  %s\n" "$label"
        sed 's/^/        /' "$LOG_DIR/step.log" | tail -n 8
    fi
}

baseline=$(curl -s -m 20 -o /dev/null -w "%{http_code}" "http://$HTTP_TARGET" || echo 000)
printf "baseline http %s\n" "$baseline"

"$ZEPTUN" run --tun "$TUN_NAME" --handler direct --mtu 1500 \
    --address "$TUN_ADDR/30" \
    --route "$HTTP_TARGET/32" --route "$DNS_TARGET/32" \
    --icmp forward --log-level debug > "$LOG_DIR/zeptun.log" 2>&1 &
engine=$!

i=0
while [ $i -lt 100 ]; do
    ifconfig "$TUN_NAME" 2> /dev/null | grep -q "$TUN_ADDR" && break
    i=$((i + 1))
    sleep 0.2
done

if ! ifconfig "$TUN_NAME" 2> /dev/null | grep -q "$TUN_ADDR"; then
    printf "  FAIL  the tunnel did not come up\n"
    sed 's/^/        /' "$LOG_DIR/zeptun.log" | tail -n 20
    kill "$engine" 2> /dev/null || true
    exit 1
fi

printf "case macos-utun\n"
check "interface carries the tunnel address" sh -c "ifconfig $TUN_NAME | grep -q $TUN_ADDR"
check "route points at the tunnel" sh -c "route -n get $HTTP_TARGET | grep -q $TUN_NAME"
check "tcp through the tunnel" sh -c "curl -s -m 25 -o /dev/null -w 'http %{http_code} in %{time_total}s' http://$HTTP_TARGET | grep -qE 'http (200|301|302)'"
check "dns over udp through the tunnel" sh -c "dig +time=5 +tries=2 @$DNS_TARGET example.com A | grep -q 'ANSWER SECTION'"
check "dns over udp keeps working under repetition" sh -c "for i in 1 2 3 4 5; do dig +time=5 +tries=1 @$DNS_TARGET example.com A | grep -q 'ANSWER SECTION' || exit 1; done"
check "icmp through the tunnel" ping -c 3 -t 5 "$HTTP_TARGET"
check "a destination outside the tunnel still works" sh -c "curl -s -m 25 -o /dev/null -w '%{http_code}' https://api.github.com | grep -qE '200|401|403'"

# A plain `wait` here hangs for as long as the engine takes to go, and a job that hangs is a job
# that tells you nothing when it is killed. This is the wait `bench_netns.sh` already uses.
kill -INT "$engine"
for _ in $(seq 1 50); do kill -0 "$engine" 2> /dev/null || break; sleep 0.1; done
kill -9 "$engine" 2> /dev/null || true
wait "$engine" 2> /dev/null || true
sleep 1

check "interface removed on exit" sh -c "! ifconfig $TUN_NAME 2> /dev/null | grep -q $TUN_ADDR"
check "route removed on exit" sh -c "! route -n get $HTTP_TARGET 2> /dev/null | grep -q $TUN_NAME"
check "connectivity intact after teardown" sh -c "curl -s -m 25 -o /dev/null -w '%{http_code}' http://$HTTP_TARGET | grep -qE '200|301|302'"

printf "\nmacos integration: %d passed, %d failed\n" "$PASSED" "$FAILED"
if [ "$FAILED" -ne 0 ]; then
    printf "failures:$FAILURES\n"
    printf "engine log:\n"
    sed 's/^/    /' "$LOG_DIR/zeptun.log" | tail -n 40
    exit 1
fi
