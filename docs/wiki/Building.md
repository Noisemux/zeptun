# Building

Zig 0.17.0 is the only requirement. There are no submodules and no vendored C libraries.

## Unix

```sh
git clone https://github.com/Noisemux/zeptun
cd zeptun
make
sudo make install
```

| Path | Content |
|---|---|
| `$(PREFIX)/bin/zeptun` | command line tool |
| `$(PREFIX)/lib/libzeptun.a` | static library |
| `$(PREFIX)/include/zeptun.h` | public header |
| `/etc/zeptun/zeptun.toml` | sample configuration, never overwritten |
| `$(PREFIX)/lib/systemd/system/zeptun.service` | hardened unit |

`PREFIX`, `DESTDIR`, `OPTIMIZE`, `TARGET` and `CPU` are honoured: `make TARGET=aarch64-linux-musl OPTIMIZE=small`.

## Zig directly

```sh
zig build -Doptimize=fast
zig build cross
```

| Step | Result |
|---|---|
| `zig build` | CLI, bench tool, static and shared library, header |
| `zig build cross` | libraries for the whole target matrix in `zig-out/cross/<triple>` |
| `zig build android` | `zig-out/android/jniLibs/<abi>/libzeptun.so` and static libraries for the NDK |
| `zig build ios` | small slices for the XCFramework |

Feature flags trim the binary: `-Dipv6=false`, `-Dsocks5=false`, `-Droute=false`, `-Dicmp=false`, `-Dfragments=false`, `-Dsystem-stack=false`, `-Duserspace-tcp=false`, `-Dmobile=true`, `-Dstrip=true`.

## Android

```sh
ANDROID_NDK_HOME=/path/to/ndk sh scripts/build_android.sh
```

Builds `libzeptun.so` and `libzeptun.a` for `armeabi-v7a`, `arm64-v8a`, `x86` and `x86_64`, then `libzeptun-jni.so` from `src/jni/zeptun_jni.c`. Load segments are aligned to 16 KB for Android 15 and later. Without the NDK the script stops after the Zig libraries. See [Android](Android).

## iOS and macOS

```sh
sh scripts/make_xcframework.sh
```

Produces `zig-out/Zeptun.xcframework` with iOS device, iOS simulator and macOS slices. `Package.swift` exposes it to SwiftPM. The slices target macOS 15.0 and iOS 18.0, the oldest versions Zig 0.17 supports. See [Apple](Apple).

## Windows

```sh
zig build -Dtarget=x86_64-windows-gnu -Doptimize=fast
make wintun
```

The tunnel uses Wintun. The library ships with the source in `third-part/wintun`, together with its licence, README and header, for `amd64`, `arm64`, `x86` and `arm`:

```
third-part/wintun/
    LICENSE.txt
    README.md
    VERSION
    bin/<arch>/wintun.dll
    include/wintun.h
```

`make wintun` copies the matching library and its licence into `zig-out/bin`, next to the executable, which is where the loader looks first (`LOAD_LIBRARY_SEARCH_APPLICATION_DIR`). Pass `WINTUN_ARCH=arm64` for arm64 hosts, or call `scripts/fetch_wintun.sh ARCH DIR` for any other directory. Released archives already contain the library, so a downloaded release needs no extra step.

`scripts/fetch_wintun.sh --vendor` refreshes the vendored copy: it downloads the official distribution from wintun.net, checks it against the SHA-256 pinned in the script, and replaces the tree. Set `WINTUN_VERSION` and `WINTUN_SHA256` to move to a new release.

Wintun is not modified, and its prebuilt binaries licence permits redistribution alongside software that uses only the documented API, which is what `src/device/wintun.zig` does through `LoadLibraryEx` and `GetProcAddress`.

MSVC targets build as well: `-Dtarget=x86_64-windows-msvc`.

The adapter GUID can be pinned so the device keeps one identity across reinstalls, which keeps its firewall profile and DNS settings and stops duplicate adapters from piling up: `--tun-guid "{24198F4C-7895-434C-AD35-9E29A92DDC51}"` on the command line, `guid` under `[tun]` in the configuration, or `zeptun_set_adapter_guid` from the C API. It is only used when the adapter is created; an existing adapter is opened as before.

## Container

```sh
docker build -t zeptun .
```

The image builds from source with Zig on Alpine and ships a single static binary. See [Container](Container).

## Released binaries

The `release` workflow publishes, for every tagged release: thirteen Linux architectures as static musl binaries, a macOS universal binary, Windows x86_64 and arm64 archives, FreeBSD x86_64, the Android `jniLibs` archive, the XCFramework, a source tarball and `SHA256SUMS`, plus a multi-architecture image on `ghcr.io/noisemux/zeptun`.
