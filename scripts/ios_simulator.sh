#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEVICE=${DEVICE:-iPhone 16}
OUT=${OUT:-$ROOT/zig-out/ios-sim}
ARCH=${ARCH:-$(uname -m)}

case "$ARCH" in
    arm64 | aarch64) SLICE=ios-arm64-simulator; CLANG_ARCH=arm64 ;;
    *) SLICE=ios-x86_64-simulator; CLANG_ARCH=x86_64 ;;
esac

cd "$ROOT"
zig build ios -Doptimize=small
mkdir -p "$OUT"

xcrun --sdk iphonesimulator clang \
    -arch "$CLANG_ARCH" \
    -mios-simulator-version-min=15.0 \
    -std=c11 -Wall -Wextra -Werror \
    -I"$ROOT/include" \
    "$ROOT/tests/ffi_smoke.c" \
    "$ROOT/zig-out/ios/$SLICE/libzeptun.a" \
    -o "$OUT/ffi-smoke"

udid=$(xcrun simctl list devices available -j | python3 -c "
import json, sys
data = json.load(sys.stdin)
name = '''$DEVICE'''
for runtime, devices in data['devices'].items():
    for device in devices:
        if device.get('isAvailable') and (device['name'] == name or not name):
            print(device['udid'])
            raise SystemExit
for runtime, devices in data['devices'].items():
    for device in devices:
        if device.get('isAvailable'):
            print(device['udid'])
            raise SystemExit
")

if [ -z "$udid" ]; then
    printf 'ios_simulator: no available simulator device\n' >&2
    exit 1
fi

state=$(xcrun simctl list devices -j | python3 -c "
import json, sys
data = json.load(sys.stdin)
for runtime, devices in data['devices'].items():
    for device in devices:
        if device['udid'] == '''$udid''':
            print(device['state'])
            raise SystemExit
")

if [ "$state" != "Booted" ]; then
    xcrun simctl boot "$udid"
    xcrun simctl bootstatus "$udid" -b
fi

printf 'ios_simulator: running the c abi test on %s\n' "$udid"
xcrun simctl spawn "$udid" "$OUT/ffi-smoke"
