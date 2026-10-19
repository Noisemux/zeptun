#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

OPTIMIZE=${OPTIMIZE:-small}
OUT=${OUT:-zig-out/Zeptun.xcframework}
WORK=${WORK:-zig-out/xcframework-work}

for tool in zig lipo xcodebuild; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        printf "make_xcframework: %s is required (run on macOS with Xcode command line tools)\n" "$tool" >&2
        exit 1
    fi
done

rm -rf "$OUT" "$WORK"
mkdir -p "$WORK/headers" "$WORK/ios-simulator" "$WORK/macos"

zig build ios -Doptimize="$OPTIMIZE"
zig build -Dtarget=aarch64-macos -Doptimize="$OPTIMIZE" -Dstrip=true --prefix "$WORK/macos-arm64"
zig build -Dtarget=x86_64-macos -Doptimize="$OPTIMIZE" -Dstrip=true --prefix "$WORK/macos-x86_64"

cp include/zeptun.h include/module.modulemap "$WORK/headers/"

lipo -create \
    zig-out/ios/ios-arm64-simulator/libzeptun.a \
    zig-out/ios/ios-x86_64-simulator/libzeptun.a \
    -output "$WORK/ios-simulator/libzeptun.a"

lipo -create \
    "$WORK/macos-arm64/lib/libzeptun.a" \
    "$WORK/macos-x86_64/lib/libzeptun.a" \
    -output "$WORK/macos/libzeptun.a"

xcodebuild -create-xcframework \
    -library zig-out/ios/ios-arm64/libzeptun.a -headers "$WORK/headers" \
    -library "$WORK/ios-simulator/libzeptun.a" -headers "$WORK/headers" \
    -library "$WORK/macos/libzeptun.a" -headers "$WORK/headers" \
    -output "$OUT"

printf "%s\n" "$OUT"
