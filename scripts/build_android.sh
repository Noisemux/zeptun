#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-"$ROOT/zig-out/android"}
ZIG=${ZIG:-zig}
NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
ABIS=${ABIS:-"armeabi-v7a arm64-v8a x86 x86_64"}

cd "$ROOT"
"$ZIG" build android -Doptimize=small

if [ -z "$NDK" ]; then
    printf 'zeptun: libzeptun.so and libzeptun.a per ABI are in %s\n' "$OUT"
    printf 'zeptun: set ANDROID_NDK_HOME to also build libzeptun-jni.so with ndk-build\n'
    exit 0
fi

rm -rf "$ROOT/jni"
ln -sf . "$ROOT/jni"
trap 'rm -f "$ROOT/jni"' EXIT

"$NDK/ndk-build" \
    NDK_PROJECT_PATH="$ROOT" \
    NDK_APPLICATION_MK="$ROOT/Application.mk" \
    APP_BUILD_SCRIPT="$ROOT/Android.mk" \
    APP_ABI="$ABIS" \
    NDK_LIBS_OUT="$OUT/ndk-libs" \
    NDK_OUT="$OUT/ndk-obj" \
    -j"$(nproc 2> /dev/null || echo 4)"

for abi in $ABIS; do
    mkdir -p "$OUT/jniLibs/$abi"
    cp "$OUT/ndk-libs/$abi/libzeptun-jni.so" "$OUT/jniLibs/$abi/"
done

printf 'zeptun: jniLibs ready in %s\n' "$OUT/jniLibs"
