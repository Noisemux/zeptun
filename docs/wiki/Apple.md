# Apple

## XCFramework

```sh
sh scripts/make_xcframework.sh
```

Produces `zig-out/Zeptun.xcframework` with three slices: iOS device (`arm64`), iOS simulator (`arm64`, `x86_64`) and macOS. `Package.swift` exposes the framework as a binary target, so a Swift package or an Xcode project can depend on the repository directly. The slices target macOS 15.0 and iOS 18.0, the oldest versions Zig 0.17 supports.

```swift
.binaryTarget(name: "Zeptun", path: "zig-out/Zeptun.xcframework")
```

The header is exported through `include/module.modulemap`, so `import Zeptun` gives the full [C API](C-API) in Swift.

## NetworkExtension

```swift
import NetworkExtension
import Zeptun

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var tunnel: OpaquePointer?

    override func startTunnel(options: [String: NSObject]?) async throws {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "172.19.0.1")
        settings.mtu = 8500
        settings.ipv4Settings = NEIPv4Settings(addresses: ["172.19.0.1"], subnetMasks: ["255.255.255.252"])
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        try await setTunnelNetworkSettings(settings)

        var config = ZeptunConfig()
        zeptun_config_init(&config, UInt32(ZEPTUN_PRESET_MOBILE))
        config.device_kind = UInt32(ZEPTUN_DEVICE_FD)
        config.handler_kind = UInt32(ZEPTUN_HANDLER_SOCKS5)
        config.tun_fd = tunnelFileDescriptor

        var handle: OpaquePointer?
        guard zeptun_create(&config, &handle) == ZEPTUN_OK else { throw ProviderError.start }
        tunnel = handle
        zeptun_start(handle)
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        if let handle = tunnel {
            zeptun_stop(handle)
            zeptun_destroy(handle)
            tunnel = nil
        }
    }
}
```

`tunnelFileDescriptor` is the `utun` descriptor of the extension; it can be found by walking the open descriptors for the one whose socket name starts with `utun`. Where the descriptor is not reachable, use `ZEPTUN_DEVICE_EXTERNAL` instead and move packets with `zeptun_set_read_callback` and `zeptun_write_packets`, which keeps everything inside `packetFlow`.

## Memory limit

A packet tunnel extension has a tight memory limit. The mobile preset keeps one queue, no offload and small windows; `[memory] budget_bytes` bounds the rest. `ZEPTUN_PRESET_MOBILE` is the right starting point on both iOS and macOS extensions.

## macOS command line

On macOS the tool creates a `utun` device, installs split default routes, sends exclusions through the previous gateway and binds upstream sockets with `IP_BOUND_IF`:

```sh
sudo zeptun run --mtu 8500 --socks5 127.0.0.1:1080 --auto-route
```
