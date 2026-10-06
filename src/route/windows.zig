const std = @import("std");
const build_options = @import("build_options");
const config = @import("../config.zig");
const addr = @import("../addr.zig");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");

const win = sys.windows;
const kernel32 = win.kernel32;

pub const supported = sys.is_windows;
const wfp = @import("wfp.zig");

pub const NET_LUID = extern struct {
    Value: u64,
};

pub const SOCKADDR_IN = extern struct {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8,
};

pub const SOCKADDR_IN6 = extern struct {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [16]u8,
    sin6_scope_id: u32,
};

pub const SOCKADDR_INET = extern union {
    Ipv4: SOCKADDR_IN,
    Ipv6: SOCKADDR_IN6,
    si_family: u16,
};

pub const IP_ADDRESS_PREFIX = extern struct {
    Prefix: SOCKADDR_INET,
    PrefixLength: u8,
};

pub const MIB_UNICASTIPADDRESS_ROW = extern struct {
    Address: SOCKADDR_INET,
    InterfaceLuid: NET_LUID,
    InterfaceIndex: u32,
    PrefixOrigin: i32,
    SuffixOrigin: i32,
    ValidLifetime: u32,
    PreferredLifetime: u32,
    OnLinkPrefixLength: u8,
    SkipAsSource: u8,
    DadState: i32,
    ScopeId: u32,
    CreationTimeStamp: i64,
};

pub const MIB_IPFORWARD_ROW2 = extern struct {
    InterfaceLuid: NET_LUID,
    InterfaceIndex: u32,
    DestinationPrefix: IP_ADDRESS_PREFIX,
    NextHop: SOCKADDR_INET,
    SitePrefixLength: u8,
    ValidLifetime: u32,
    PreferredLifetime: u32,
    Metric: u32,
    Protocol: i32,
    Loopback: u8,
    AutoconfigureAddress: u8,
    Publish: u8,
    Immortal: u8,
    Age: u32,
    Origin: i32,
};

pub const MIB_IPINTERFACE_ROW = extern struct {
    Family: u16,
    InterfaceLuid: NET_LUID,
    InterfaceIndex: u32,
    MaxReassemblySize: u32,
    InterfaceIdentifier: u64,
    MinRouterAdvertisementInterval: u32,
    MaxRouterAdvertisementInterval: u32,
    AdvertisingEnabled: u8,
    ForwardingEnabled: u8,
    WeakHostSend: u8,
    WeakHostReceive: u8,
    UseAutomaticMetric: u8,
    UseNeighborUnreachabilityDetection: u8,
    ManagedAddressConfigurationSupported: u8,
    OtherStatefulConfigurationSupported: u8,
    AdvertiseDefaultRoute: u8,
    RouterDiscoveryBehavior: i32,
    DadTransmits: u32,
    BaseReachableTime: u32,
    RetransmitTime: u32,
    PathMtuDiscoveryTimeout: u32,
    LinkLocalAddressBehavior: i32,
    LinkLocalAddressTimeout: u32,
    ZoneIndices: [16]u32,
    SitePrefixLength: u32,
    Metric: u32,
    NlMtu: u32,
    Connected: u8,
    SupportsWakeUpPatterns: u8,
    SupportsNeighborDiscovery: u8,
    SupportsRouterDiscovery: u8,
    ReachableTime: u32,
    TransmitOffload: u8,
    ReceiveOffload: u8,
    DisableDefaultRoutes: u8,
};

pub const DNS_INTERFACE_SETTINGS = extern struct {
    Version: u32,
    Flags: u64,
    Domain: ?[*:0]u16,
    NameServer: ?[*:0]u16,
    SearchList: ?[*:0]u16,
    RegistrationEnabled: u32,
    RegisterAdapterName: u32,
    EnableLLMNR: u32,
    QueryAdapterName: u32,
    ProfileNameServer: ?[*:0]u16,
};

comptime {
    if (sys.is_windows) {
        std.debug.assert(@sizeOf(NET_LUID) == 8);
        std.debug.assert(@sizeOf(SOCKADDR_IN) == 16);
        std.debug.assert(@sizeOf(SOCKADDR_IN6) == 28);
        std.debug.assert(@sizeOf(SOCKADDR_INET) == 28);
        std.debug.assert(@alignOf(SOCKADDR_INET) == 4);
        std.debug.assert(@sizeOf(IP_ADDRESS_PREFIX) == 32);
        std.debug.assert(@offsetOf(IP_ADDRESS_PREFIX, "PrefixLength") == 28);
        std.debug.assert(@sizeOf(MIB_UNICASTIPADDRESS_ROW) == 80);
        std.debug.assert(@offsetOf(MIB_UNICASTIPADDRESS_ROW, "InterfaceLuid") == 32);
        std.debug.assert(@offsetOf(MIB_UNICASTIPADDRESS_ROW, "OnLinkPrefixLength") == 60);
        std.debug.assert(@offsetOf(MIB_UNICASTIPADDRESS_ROW, "DadState") == 64);
        std.debug.assert(@offsetOf(MIB_UNICASTIPADDRESS_ROW, "CreationTimeStamp") == 72);
        std.debug.assert(@sizeOf(MIB_IPFORWARD_ROW2) == 104);
        std.debug.assert(@offsetOf(MIB_IPFORWARD_ROW2, "DestinationPrefix") == 12);
        std.debug.assert(@offsetOf(MIB_IPFORWARD_ROW2, "NextHop") == 44);
        std.debug.assert(@offsetOf(MIB_IPFORWARD_ROW2, "SitePrefixLength") == 72);
        std.debug.assert(@offsetOf(MIB_IPFORWARD_ROW2, "Metric") == 84);
        std.debug.assert(@offsetOf(MIB_IPFORWARD_ROW2, "Loopback") == 92);
        std.debug.assert(@offsetOf(MIB_IPFORWARD_ROW2, "Origin") == 100);
        std.debug.assert(@sizeOf(MIB_IPINTERFACE_ROW) == 168);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "InterfaceLuid") == 8);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "InterfaceIdentifier") == 24);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "RouterDiscoveryBehavior") == 52);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "ZoneIndices") == 80);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "SitePrefixLength") == 144);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "NlMtu") == 152);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "ReachableTime") == 160);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "DisableDefaultRoutes") == 166);
        std.debug.assert(@sizeOf(DNS_INTERFACE_SETTINGS) == 64);
        std.debug.assert(@offsetOf(DNS_INTERFACE_SETTINGS, "NameServer") == 24);
    }
}

pub const iphlpapi = struct {
    pub extern "iphlpapi" fn InitializeUnicastIpAddressEntry(Row: *MIB_UNICASTIPADDRESS_ROW) callconv(.winapi) void;
    pub extern "iphlpapi" fn CreateUnicastIpAddressEntry(Row: *const MIB_UNICASTIPADDRESS_ROW) callconv(.winapi) u32;
    pub extern "iphlpapi" fn DeleteUnicastIpAddressEntry(Row: *const MIB_UNICASTIPADDRESS_ROW) callconv(.winapi) u32;
    pub extern "iphlpapi" fn InitializeIpInterfaceEntry(Row: *MIB_IPINTERFACE_ROW) callconv(.winapi) void;
    pub extern "iphlpapi" fn GetIpInterfaceEntry(Row: *MIB_IPINTERFACE_ROW) callconv(.winapi) u32;
    pub extern "iphlpapi" fn SetIpInterfaceEntry(Row: *MIB_IPINTERFACE_ROW) callconv(.winapi) u32;
    pub extern "iphlpapi" fn InitializeIpForwardEntry(Row: *MIB_IPFORWARD_ROW2) callconv(.winapi) void;
    pub extern "iphlpapi" fn CreateIpForwardEntry2(Row: *const MIB_IPFORWARD_ROW2) callconv(.winapi) u32;
    pub extern "iphlpapi" fn DeleteIpForwardEntry2(Row: *const MIB_IPFORWARD_ROW2) callconv(.winapi) u32;
    pub extern "iphlpapi" fn GetBestRoute2(InterfaceLuid: ?*NET_LUID, InterfaceIndex: u32, SourceAddress: ?*const SOCKADDR_INET, DestinationAddress: *const SOCKADDR_INET, AddressSortOptions: u32, BestRoute: *MIB_IPFORWARD_ROW2, BestSourceAddress: *SOCKADDR_INET) callconv(.winapi) u32;
    pub extern "iphlpapi" fn ConvertInterfaceLuidToIndex(InterfaceLuid: *const NET_LUID, InterfaceIndex: *u32) callconv(.winapi) u32;
    pub extern "iphlpapi" fn ConvertInterfaceIndexToLuid(InterfaceIndex: u32, InterfaceLuid: *NET_LUID) callconv(.winapi) u32;
    pub extern "iphlpapi" fn ConvertInterfaceLuidToGuid(InterfaceLuid: *const NET_LUID, InterfaceGuid: *win.GUID) callconv(.winapi) u32;
    pub extern "iphlpapi" fn NotifyRouteChange2(Family: u16, Callback: RouteChangeCallback, CallerContext: ?*anyopaque, InitialNotification: u8, NotificationHandle: *?*anyopaque) callconv(.winapi) u32;
    pub extern "iphlpapi" fn NotifyIpInterfaceChange(Family: u16, Callback: InterfaceChangeCallback, CallerContext: ?*anyopaque, InitialNotification: u8, NotificationHandle: *?*anyopaque) callconv(.winapi) u32;
    pub extern "iphlpapi" fn CancelMibChangeNotify2(NotificationHandle: ?*anyopaque) callconv(.winapi) u32;
};

pub const RouteChangeCallback = *const fn (CallerContext: ?*anyopaque, Row: ?*MIB_IPFORWARD_ROW2, NotificationType: u32) callconv(.winapi) void;
pub const InterfaceChangeCallback = *const fn (CallerContext: ?*anyopaque, Row: ?*MIB_IPINTERFACE_ROW, NotificationType: u32) callconv(.winapi) void;

pub const ChangeNotifications = struct {
    route: ?*anyopaque = null,
    interface: ?*anyopaque = null,
    dirty: std.atomic.Value(bool) = .init(false),
    event: ?win.HANDLE = null,

    fn signal(ctx: ?*anyopaque) void {
        const n: *ChangeNotifications = @ptrCast(@alignCast(ctx.?));
        n.dirty.store(true, .release);
        if (n.event) |e| _ = kernel32.SetEvent(e);
    }

    fn onRoute(ctx: ?*anyopaque, row: ?*MIB_IPFORWARD_ROW2, kind: u32) callconv(.winapi) void {
        _ = row;
        _ = kind;
        signal(ctx);
    }

    fn onInterface(ctx: ?*anyopaque, row: ?*MIB_IPINTERFACE_ROW, kind: u32) callconv(.winapi) void {
        _ = row;
        _ = kind;
        signal(ctx);
    }

    pub fn register(n: *ChangeNotifications) !void {
        if (!supported) return error.NotSupported;
        n.event = kernel32.CreateEventW(null, 0, 0, null) orelse return error.SystemResources;
        errdefer n.unregister();
        if (iphlpapi.NotifyRouteChange2(0, onRoute, n, 0, &n.route) != win.ERROR_SUCCESS) return error.SystemResources;
        if (iphlpapi.NotifyIpInterfaceChange(0, onInterface, n, 0, &n.interface) != win.ERROR_SUCCESS) return error.SystemResources;
    }

    pub fn wait(n: *ChangeNotifications, timeout_ms: ?u32) bool {
        if (!supported) return false;
        const e = n.event orelse return false;
        _ = kernel32.WaitForSingleObject(e, timeout_ms orelse win.INFINITE);
        return n.dirty.swap(false, .acquire);
    }

    pub fn wake(n: *ChangeNotifications) void {
        if (n.event) |e| _ = kernel32.SetEvent(e);
    }

    pub fn unregister(n: *ChangeNotifications) void {
        if (n.route) |h| _ = iphlpapi.CancelMibChangeNotify2(h);
        if (n.interface) |h| _ = iphlpapi.CancelMibChangeNotify2(h);
        n.route = null;
        n.interface = null;
        if (n.event) |e| _ = kernel32.CloseHandle(e);
        n.event = null;
    }
};

pub fn networkIdentity(tun_index: u32) struct { index4: u32, index6: u32, hash: u64 } {
    var out: @TypeOf(networkIdentity(0)) = .{ .index4 = 0, .index6 = 0, .hash = 0 };
    if (!supported) return out;
    var hasher = std.hash.Wyhash.init(0x7a65);
    const probes = [_]addr.Address{ addr.Address.v4(.{ 192, 0, 2, 1 }), addr.Address.v6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }) };
    for (probes) |probe| {
        const destination = sockaddrInet(probe);
        var best: MIB_IPFORWARD_ROW2 = undefined;
        var source: SOCKADDR_INET = undefined;
        if (iphlpapi.GetBestRoute2(null, 0, null, &destination, 0, &best, &source) != win.ERROR_SUCCESS) continue;
        if (best.InterfaceIndex == tun_index) continue;
        hasher.update(std.mem.asBytes(&best.InterfaceIndex));
        hasher.update(std.mem.asBytes(&best.NextHop));
        hasher.update(std.mem.asBytes(&source));
        if (probe.family == .v4) out.index4 = best.InterfaceIndex else out.index6 = best.InterfaceIndex;
    }
    out.hash = hasher.final();
    return out;
}

const SetInterfaceDnsSettings = *const fn (Interface: win.GUID, Settings: *const DNS_INTERFACE_SETTINGS) callconv(.winapi) u32;

const ip_dad_state_preferred: i32 = 4;
const mib_ipproto_netmgmt: i32 = 3;
const dns_interface_settings_version1: u32 = 1;
const dns_setting_ipv6: u64 = 0x0001;
const dns_setting_nameserver: u64 = 0x0002;
const iphlpapi_name = std.unicode.utf8ToUtf16LeStringLiteral("iphlpapi.dll");

const interface_wait_attempts = 100;
const interface_wait_ms = 50;

pub const max_addresses = 4;
pub const max_routes = 2 * config.max_prefixes + 8;

pub const Applied = struct {
    ifindex: u32 = 0,
    luid: NET_LUID = .{ .Value = 0 },
    addresses: [max_addresses]MIB_UNICASTIPADDRESS_ROW = undefined,
    address_count: u8 = 0,
    routes: [max_routes]MIB_IPFORWARD_ROW2 = undefined,
    route_count: u8 = 0,
    ipv4: bool = false,
    ipv6: bool = false,
    dns4: bool = false,
    dns6: bool = false,
    firewall: wfp.Handle = .{},
};

const split4 = [2]addr.Prefix{
    .{ .addr = addr.Address.v4(.{ 0, 0, 0, 0 }), .bits = 1 },
    .{ .addr = addr.Address.v4(.{ 128, 0, 0, 0 }), .bits = 1 },
};

const split6 = [2]addr.Prefix{
    .{ .addr = addr.Address.v6(@splat(0)), .bits = 1 },
    .{ .addr = addr.Address.v6(.{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }), .bits = 1 },
};

pub fn luidToIndex(luid: NET_LUID) !u32 {
    var index: u32 = 0;
    const rc = iphlpapi.ConvertInterfaceLuidToIndex(&luid, &index);
    if (rc != win.ERROR_SUCCESS) {
        log.err("route: interface luid 0x{x} has no index (error {d})", .{ luid.Value, rc });
        return error.DeviceNotFound;
    }
    return index;
}

fn familyCode(family: addr.Family) u16 {
    return if (family == .v4) win.AF_INET else win.AF_INET6;
}

fn sockaddrInet(a: addr.Address) SOCKADDR_INET {
    var sa = std.mem.zeroes(SOCKADDR_INET);
    if (a.family == .v4) {
        sa.Ipv4.sin_family = win.AF_INET;
        @memcpy(&sa.Ipv4.sin_addr, a.bytes[0..4]);
    } else {
        sa.Ipv6.sin6_family = win.AF_INET6;
        sa.Ipv6.sin6_addr = a.bytes;
    }
    return sa;
}

fn unspecified(family: addr.Family) addr.Address {
    return if (family == .v4) addr.Address.v4(@splat(0)) else addr.Address.v6(@splat(0));
}

fn isLoopback(a: addr.Address) bool {
    if (a.family == .v4) return a.bytes[0] == 127;
    return std.mem.eql(u8, &a.bytes, &addr.Address.v6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }).bytes);
}

pub fn defaultInterfaceIndex(family: addr.Family) u32 {
    if (!supported) return 0;
    const probe = if (family == .v4) addr.Address.v4(.{ 192, 0, 2, 1 }) else addr.Address.v6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    const destination = sockaddrInet(probe);
    var best: MIB_IPFORWARD_ROW2 = undefined;
    var source: SOCKADDR_INET = undefined;
    if (iphlpapi.GetBestRoute2(null, 0, null, &destination, 0, &best, &source) != win.ERROR_SUCCESS) return 0;
    return best.InterfaceIndex;
}

fn routed(cfg: *const config.Config, applied: *const Applied, family: addr.Family) bool {
    return switch (family) {
        .v4 => cfg.device.address4 != null and applied.ipv4,
        .v6 => cfg.device.address6 != null and build_options.enable_ipv6 and applied.ipv6,
    };
}

pub fn configure(cfg: *const config.Config, ifindex: u32, addresses: []const addr.Prefix) !Applied {
    var applied: Applied = .{ .ifindex = ifindex };
    errdefer teardown(&applied);
    const rc = iphlpapi.ConvertInterfaceIndexToLuid(ifindex, &applied.luid);
    if (rc != win.ERROR_SUCCESS) {
        log.err("route: interface index {d} not found (error {d})", .{ ifindex, rc });
        return error.RouteError;
    }
    var present: [2]?u32 = .{ null, null };
    for (addresses) |p| {
        const slot = &present[@intFromBool(p.addr.family == .v6)];
        if (slot.* == null) slot.* = waitForInterface(&applied, familyCode(p.addr.family));
        const status = slot.*.?;
        if (status != win.ERROR_SUCCESS) {
            if (p.addr.family == .v4) {
                log.err("route: ipv4 is not available on interface {d} (error {d})", .{ ifindex, status });
                return error.RouteError;
            }
            log.warn("route: ipv6 is not available on interface {d} (error {d}), skipping {f}/{d}", .{ ifindex, status, p.addr, p.bits });
            continue;
        }
        if (p.addr.family == .v4) applied.ipv4 = true else applied.ipv6 = true;
        try addAddress(&applied, p);
    }
    const mtu4 = setMtu(&applied, win.AF_INET, cfg.device.mtu);
    if (mtu4 != win.ERROR_SUCCESS and mtu4 != win.ERROR_NOT_FOUND) {
        log.err("route: setting ipv4 mtu {d} on interface {d} failed (error {d})", .{ cfg.device.mtu, ifindex, mtu4 });
        return error.RouteError;
    }
    if (build_options.enable_ipv6) {
        const mtu6 = setMtu(&applied, win.AF_INET6, cfg.device.mtu);
        if (mtu6 != win.ERROR_SUCCESS and mtu6 != win.ERROR_NOT_FOUND) {
            log.warn("route: setting ipv6 mtu {d} on interface {d} failed (error {d})", .{ cfg.device.mtu, ifindex, mtu6 });
        }
    }
    return applied;
}

fn addAddress(applied: *Applied, p: addr.Prefix) !void {
    if (applied.address_count == max_addresses) return error.LimitExceeded;
    var row: MIB_UNICASTIPADDRESS_ROW = undefined;
    iphlpapi.InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = applied.luid;
    row.InterfaceIndex = applied.ifindex;
    row.Address = sockaddrInet(p.addr);
    row.OnLinkPrefixLength = p.bits;
    row.DadState = ip_dad_state_preferred;
    switch (iphlpapi.CreateUnicastIpAddressEntry(&row)) {
        win.ERROR_SUCCESS => {},
        win.ERROR_OBJECT_ALREADY_EXISTS => return,
        else => |rc| {
            log.err("route: adding address {f}/{d} failed (error {d})", .{ p.addr, p.bits, rc });
            return error.RouteError;
        },
    }
    applied.addresses[applied.address_count] = row;
    applied.address_count += 1;
}

fn waitForInterface(applied: *const Applied, family: u16) u32 {
    var row: MIB_IPINTERFACE_ROW = undefined;
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        iphlpapi.InitializeIpInterfaceEntry(&row);
        row.Family = family;
        row.InterfaceLuid = applied.luid;
        const rc = iphlpapi.GetIpInterfaceEntry(&row);
        if (rc != win.ERROR_NOT_FOUND or attempt == interface_wait_attempts) return rc;
        sys.sleepMs(interface_wait_ms);
    }
}

fn setMtu(applied: *const Applied, family: u16, mtu: u32) u32 {
    var row: MIB_IPINTERFACE_ROW = undefined;
    iphlpapi.InitializeIpInterfaceEntry(&row);
    row.Family = family;
    row.InterfaceLuid = applied.luid;
    const rc = iphlpapi.GetIpInterfaceEntry(&row);
    if (rc != win.ERROR_SUCCESS) return rc;
    row.NlMtu = mtu;
    if (family == win.AF_INET) row.SitePrefixLength = 0;
    return iphlpapi.SetIpInterfaceEntry(&row);
}

pub fn applyRoutes(cfg: *const config.Config, applied: *Applied) !void {
    if (!cfg.route.auto_route) return;
    var bypass: [config.max_prefixes + 1]MIB_IPFORWARD_ROW2 = undefined;
    var bypass_count: usize = 0;
    for (cfg.route.exclude.slice()) |p| {
        if (!routed(cfg, applied, p.addr.family)) continue;
        if (bypassRoute(applied, p)) |row| {
            bypass[bypass_count] = row;
            bypass_count += 1;
        }
    }
    if (cfg.handler.kind == .socks5 and build_options.enable_socks5) {
        const server = cfg.handler.socks5.server.addr;
        if (routed(cfg, applied, server.family) and !server.isUnspecified() and !isLoopback(server)) {
            const host: addr.Prefix = .{ .addr = server, .bits = if (server.family == .v4) 32 else 128 };
            if (bypassRoute(applied, host)) |row| {
                bypass[bypass_count] = row;
                bypass_count += 1;
            }
        }
    }
    families: for ([2]addr.Family{ .v4, .v6 }) |family| {
        if (!routed(cfg, applied, family)) continue;
        var included = false;
        for (cfg.route.include.slice()) |p| {
            if (p.addr.family != family) continue;
            included = true;
            addRoute(applied, &tunnelRoute(applied, p)) catch |err| if (family == .v6) continue :families else return err;
        }
        if (included) continue;
        for (if (family == .v4) &split4 else &split6) |p| {
            addRoute(applied, &tunnelRoute(applied, p)) catch |err| if (family == .v6) continue :families else return err;
        }
    }
    for (bypass[0..bypass_count]) |*row| try addRoute(applied, row);
    if (cfg.route.dns.len > 0) applyDns(cfg, applied);
    if (cfg.route.strict and applied.firewall.engine == null) {
        applied.firewall = try wfp.install(.{
            .tun_index = applied.ifindex,
            .ipv4 = routed(cfg, applied, .v4),
            .ipv6 = routed(cfg, applied, .v6),
            .block_dns = cfg.dns.hijack,
            .allow_apps = cfg.route.allow_apps,
        });
    }
}

fn tunnelRoute(applied: *const Applied, p: addr.Prefix) MIB_IPFORWARD_ROW2 {
    const masked = p.masked();
    var row: MIB_IPFORWARD_ROW2 = undefined;
    iphlpapi.InitializeIpForwardEntry(&row);
    row.InterfaceLuid = applied.luid;
    row.InterfaceIndex = applied.ifindex;
    row.DestinationPrefix = .{ .Prefix = sockaddrInet(masked.addr), .PrefixLength = masked.bits };
    row.NextHop = sockaddrInet(unspecified(masked.addr.family));
    row.Metric = 0;
    row.Protocol = mib_ipproto_netmgmt;
    return row;
}

fn bypassRoute(applied: *const Applied, p: addr.Prefix) ?MIB_IPFORWARD_ROW2 {
    const masked = p.masked();
    const destination = sockaddrInet(masked.addr);
    var best: MIB_IPFORWARD_ROW2 = undefined;
    var source: SOCKADDR_INET = undefined;
    const rc = iphlpapi.GetBestRoute2(null, 0, null, &destination, 0, &best, &source);
    if (rc != win.ERROR_SUCCESS) {
        log.warn("route: no existing route for excluded prefix {f}/{d} (error {d})", .{ masked.addr, masked.bits, rc });
        return null;
    }
    if (best.InterfaceLuid.Value == applied.luid.Value) return null;
    var row: MIB_IPFORWARD_ROW2 = undefined;
    iphlpapi.InitializeIpForwardEntry(&row);
    row.InterfaceLuid = best.InterfaceLuid;
    row.InterfaceIndex = best.InterfaceIndex;
    row.DestinationPrefix = .{ .Prefix = destination, .PrefixLength = masked.bits };
    row.NextHop = best.NextHop;
    row.Metric = 0;
    row.Protocol = mib_ipproto_netmgmt;
    return row;
}

fn addRoute(applied: *Applied, row: *const MIB_IPFORWARD_ROW2) !void {
    if (applied.route_count == max_routes) return error.LimitExceeded;
    switch (iphlpapi.CreateIpForwardEntry2(row)) {
        win.ERROR_SUCCESS => {},
        win.ERROR_OBJECT_ALREADY_EXISTS => return,
        else => |rc| {
            log.err("route: adding route on interface {d} failed (error {d})", .{ row.InterfaceIndex, rc });
            return error.RouteError;
        },
    }
    applied.routes[applied.route_count] = row.*;
    applied.route_count += 1;
}

fn dnsSetter() ?struct { library: win.HMODULE, set: SetInterfaceDnsSettings } {
    const library = kernel32.LoadLibraryExW(iphlpapi_name, null, win.LOAD_LIBRARY_SEARCH_SYSTEM32) orelse return null;
    const proc = kernel32.GetProcAddress(library, "SetInterfaceDnsSettings") orelse {
        _ = kernel32.FreeLibrary(library);
        return null;
    };
    return .{ .library = library, .set = @ptrCast(@alignCast(proc)) };
}

fn nameServers(servers: []const addr.Prefix, family: addr.Family, out: []u16) usize {
    var len: usize = 0;
    for (servers) |p| {
        if (p.addr.family != family) continue;
        var text: [64]u8 = undefined;
        const s = std.fmt.bufPrint(&text, "{f}", .{p.addr}) catch continue;
        if (len + s.len + 2 > out.len) break;
        if (len > 0) {
            out[len] = ',';
            len += 1;
        }
        for (s) |ch| {
            out[len] = ch;
            len += 1;
        }
    }
    out[len] = 0;
    return len;
}

fn applyDns(cfg: *const config.Config, applied: *Applied) void {
    const setter = dnsSetter() orelse {
        log.warn("route: SetInterfaceDnsSettings is unavailable, dns servers not applied", .{});
        return;
    };
    defer _ = kernel32.FreeLibrary(setter.library);
    var guid: win.GUID = undefined;
    if (iphlpapi.ConvertInterfaceLuidToGuid(&applied.luid, &guid) != win.ERROR_SUCCESS) return;
    for ([2]addr.Family{ .v4, .v6 }) |family| {
        var list: [config.max_prefixes * 48:0]u16 = undefined;
        if (nameServers(cfg.route.dns.slice(), family, &list) == 0) continue;
        var settings = std.mem.zeroes(DNS_INTERFACE_SETTINGS);
        settings.Version = dns_interface_settings_version1;
        settings.Flags = dns_setting_nameserver | (if (family == .v6) dns_setting_ipv6 else 0);
        settings.NameServer = &list;
        const rc = setter.set(guid, &settings);
        if (rc != win.ERROR_SUCCESS) {
            log.warn("route: setting dns servers failed (error {d})", .{rc});
            continue;
        }
        if (family == .v4) applied.dns4 = true else applied.dns6 = true;
    }
}

fn clearDns(applied: *Applied) void {
    if (!applied.dns4 and !applied.dns6) return;
    defer {
        applied.dns4 = false;
        applied.dns6 = false;
    }
    const setter = dnsSetter() orelse return;
    defer _ = kernel32.FreeLibrary(setter.library);
    var guid: win.GUID = undefined;
    if (iphlpapi.ConvertInterfaceLuidToGuid(&applied.luid, &guid) != win.ERROR_SUCCESS) return;
    var empty: [0:0]u16 = .{};
    for ([2]bool{ applied.dns4, applied.dns6 }, 0..) |set, i| {
        if (!set) continue;
        var settings = std.mem.zeroes(DNS_INTERFACE_SETTINGS);
        settings.Version = dns_interface_settings_version1;
        settings.Flags = dns_setting_nameserver | (if (i == 1) dns_setting_ipv6 else 0);
        settings.NameServer = &empty;
        _ = setter.set(guid, &settings);
    }
}

fn removeRoutes(applied: *Applied) void {
    while (applied.route_count > 0) {
        applied.route_count -= 1;
        _ = iphlpapi.DeleteIpForwardEntry2(&applied.routes[applied.route_count]);
    }
}

pub fn refreshRoutes(cfg: *const config.Config, applied: *Applied) !void {
    if (!supported or !cfg.route.auto_route) return;
    removeRoutes(applied);
    try applyRoutes(cfg, applied);
}

pub fn teardown(applied: *Applied) void {
    wfp.close(&applied.firewall);
    clearDns(applied);
    removeRoutes(applied);
    while (applied.address_count > 0) {
        applied.address_count -= 1;
        _ = iphlpapi.DeleteUnicastIpAddressEntry(&applied.addresses[applied.address_count]);
    }
}
