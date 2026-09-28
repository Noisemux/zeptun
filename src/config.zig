const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const addr = @import("addr.zig");
const log = @import("log.zig");

pub const StackMode = enum(u8) { system = 0, userspace = 1, hybrid = 2 };
pub const HandlerKind = enum(u8) { direct = 0, socks5 = 1, passthrough = 2 };
pub const IoBackend = enum(u8) { auto = 0, io_uring = 1, epoll = 2, kqueue = 3, iocp = 4 };
pub const DeviceKind = enum(u8) { tun = 0, fd = 1, external = 2 };
pub const Preset = enum(u8) { desktop = 0, mobile = 1, server = 2 };
pub const Congestion = enum(u8) { cubic = 0, newreno = 1 };
pub const IcmpMode = enum(u8) { local = 0, drop = 1, forward = 2, auto = 3 };
pub const UdpMode = enum(u8) { enabled = 0, disabled = 1 };
pub const NatMode = enum(u8) { endpoint_independent = 0, address = 1, address_port = 2 };
pub const PipelineMode = enum(u8) { auto = 0, on = 1, off = 2 };
pub const Socks5UdpMode = enum(u8) { udp = 0, tcp = 1 };
pub const AutoMode = enum(u8) { auto = 0, on = 1, off = 2 };
pub const ElasticMode = enum(u8) { auto = 0, on = 1, off = 2, rotate = 3 };

pub const Name = struct {
    buf: [256]u8 = @splat(0),
    len: u16 = 0,

    pub fn init(s: []const u8) Name {
        var n: Name = .{};
        const l = @min(s.len, n.buf.len);
        @memcpy(n.buf[0..l], s[0..l]);
        n.len = @intCast(l);
        return n;
    }

    pub inline fn slice(n: *const Name) []const u8 {
        return n.buf[0..n.len];
    }

    pub inline fn isEmpty(n: *const Name) bool {
        return n.len == 0;
    }
};

pub const max_prefixes = 32;

pub const PrefixList = struct {
    items: [max_prefixes]addr.Prefix = undefined,
    len: u8 = 0,

    pub fn append(l: *PrefixList, p: addr.Prefix) !void {
        if (l.len == max_prefixes) return error.LimitExceeded;
        l.items[l.len] = p;
        l.len += 1;
    }

    pub inline fn slice(l: *const PrefixList) []const addr.Prefix {
        return l.items[0..l.len];
    }
};

pub const UidRange = struct {
    start: u32,
    end: u32,

    pub fn parse(text: []const u8) !UidRange {
        const sep = std.mem.indexOfAny(u8, text, "-:");
        const a = std.fmt.parseInt(u32, if (sep) |s| text[0..s] else text, 0) catch return error.InvalidArgument;
        const b = if (sep) |s| std.fmt.parseInt(u32, text[s + 1 ..], 0) catch return error.InvalidArgument else a;
        if (b < a) return error.InvalidArgument;
        return .{ .start = a, .end = b };
    }
};

pub const max_uid_ranges = 64;

pub const PackageList = struct {
    buf: [2048]u8 = undefined,
    len: u16 = 0,

    pub fn append(l: *PackageList, name: []const u8) !void {
        if (name.len == 0 or std.mem.indexOfAny(u8, name, " \n\t") != null) return error.InvalidArgument;
        if (l.len + name.len + 1 > l.buf.len) return error.LimitExceeded;
        @memcpy(l.buf[l.len..][0..name.len], name);
        l.buf[l.len + name.len] = '\n';
        l.len += @intCast(name.len + 1);
    }

    pub fn iterator(l: *const PackageList) std.mem.TokenIterator(u8, .scalar) {
        return std.mem.tokenizeScalar(u8, l.buf[0..l.len], '\n');
    }

    pub fn isEmpty(l: *const PackageList) bool {
        return l.len == 0;
    }
};

pub const UidList = struct {
    items: [max_uid_ranges]UidRange = undefined,
    len: u8 = 0,

    pub fn append(l: *UidList, r: UidRange) !void {
        if (l.len == max_uid_ranges) return error.LimitExceeded;
        l.items[l.len] = r;
        l.len += 1;
    }

    pub inline fn slice(l: *const UidList) []const UidRange {
        return l.items[0..l.len];
    }
};

pub const max_interfaces = 8;

pub const InterfaceList = struct {
    names: [max_interfaces][16]u8 = undefined,
    lens: [max_interfaces]u8 = undefined,
    len: u8 = 0,

    pub fn append(l: *InterfaceList, name: []const u8) !void {
        if (name.len == 0 or name.len >= 16) return error.InvalidArgument;
        if (l.len == max_interfaces) return error.LimitExceeded;
        @memset(&l.names[l.len], 0);
        @memcpy(l.names[l.len][0..name.len], name);
        l.lens[l.len] = @intCast(name.len);
        l.len += 1;
    }

    pub fn get(l: *const InterfaceList, i: usize) []const u8 {
        return l.names[i][0..l.lens[i]];
    }
};

pub fn excludedUids(include: []const UidRange, exclude: []const UidRange, out: []UidRange) []UidRange {
    const max_uid: u32 = 0xffff_fffe;
    var allowed: [2 * max_uid_ranges + 2]UidRange = undefined;
    var n: usize = 0;
    if (include.len == 0) {
        for (exclude) |r| {
            allowed[n] = r;
            n += 1;
        }
        return mergeRanges(allowed[0..n], out);
    }
    var inc: [max_uid_ranges]UidRange = undefined;
    const merged_inc = mergeRanges(include, &inc);
    var exc: [max_uid_ranges]UidRange = undefined;
    const merged_exc = mergeRanges(exclude, &exc);
    for (merged_inc) |r| {
        var pieces: [max_uid_ranges + 1]UidRange = undefined;
        var pn: usize = 1;
        pieces[0] = r;
        for (merged_exc) |x| {
            var next: [max_uid_ranges + 1]UidRange = undefined;
            var nn: usize = 0;
            for (pieces[0..pn]) |p| {
                if (x.end < p.start or x.start > p.end) {
                    next[nn] = p;
                    nn += 1;
                    continue;
                }
                if (x.start > p.start and nn < next.len) {
                    next[nn] = .{ .start = p.start, .end = x.start - 1 };
                    nn += 1;
                }
                if (x.end < p.end and nn < next.len) {
                    next[nn] = .{ .start = x.end + 1, .end = p.end };
                    nn += 1;
                }
            }
            pieces = next;
            pn = nn;
        }
        for (pieces[0..pn]) |p| {
            if (n == allowed.len) break;
            allowed[n] = p;
            n += 1;
        }
    }
    var sorted: [2 * max_uid_ranges + 2]UidRange = undefined;
    const ok = mergeRanges(allowed[0..n], &sorted);
    var o: usize = 0;
    var cursor: u64 = 0;
    for (ok) |r| {
        if (r.start > cursor and o < out.len) {
            out[o] = .{ .start = @intCast(cursor), .end = r.start - 1 };
            o += 1;
        }
        cursor = @as(u64, r.end) + 1;
    }
    if (cursor <= max_uid and o < out.len) {
        out[o] = .{ .start = @intCast(cursor), .end = max_uid };
        o += 1;
    }
    return out[0..o];
}

fn mergeRanges(in: []const UidRange, out: []UidRange) []UidRange {
    var tmp: [2 * max_uid_ranges + 2]UidRange = undefined;
    const n = @min(in.len, tmp.len);
    @memcpy(tmp[0..n], in[0..n]);
    std.sort.insertion(UidRange, tmp[0..n], {}, struct {
        fn lt(_: void, a: UidRange, b: UidRange) bool {
            return a.start < b.start;
        }
    }.lt);
    var o: usize = 0;
    for (tmp[0..n]) |r| {
        if (o > 0 and @as(u64, r.start) <= @as(u64, out[o - 1].end) + 1) {
            out[o - 1].end = @max(out[o - 1].end, r.end);
        } else if (o < out.len) {
            out[o] = r;
            o += 1;
        }
    }
    return out[0..o];
}

test "uid range exclusion" {
    var out: [40]UidRange = undefined;
    const ex = excludedUids(&.{}, &.{ .{ .start = 10, .end = 20 }, .{ .start = 15, .end = 30 } }, &out);
    try std.testing.expectEqual(@as(usize, 1), ex.len);
    try std.testing.expectEqual(@as(u32, 30), ex[0].end);
    const inc = excludedUids(&.{.{ .start = 1000, .end = 1999 }}, &.{.{ .start = 1500, .end = 1500 }}, &out);
    try std.testing.expectEqual(@as(usize, 3), inc.len);
    try std.testing.expectEqual(UidRange{ .start = 0, .end = 999 }, inc[0]);
    try std.testing.expectEqual(UidRange{ .start = 1500, .end = 1500 }, inc[1]);
    try std.testing.expectEqual(UidRange{ .start = 2000, .end = 0xffff_fffe }, inc[2]);
    try std.testing.expectEqual(UidRange{ .start = 5, .end = 9 }, try UidRange.parse("5-9"));
}

pub const Guid = extern struct {
    d1: u32 = 0,
    d2: u16 = 0,
    d3: u16 = 0,
    d4: [8]u8 = @splat(0),

    pub fn parse(text: []const u8) !Guid {
        var body = text;
        if (body.len >= 2 and body[0] == '{' and body[body.len - 1] == '}') body = body[1 .. body.len - 1];
        if (body.len != 36) return error.InvalidArgument;
        for ([_]usize{ 8, 13, 18, 23 }) |i| {
            if (body[i] != '-') return error.InvalidArgument;
        }
        var g: Guid = .{};
        g.d1 = std.fmt.parseInt(u32, body[0..8], 16) catch return error.InvalidArgument;
        g.d2 = std.fmt.parseInt(u16, body[9..13], 16) catch return error.InvalidArgument;
        g.d3 = std.fmt.parseInt(u16, body[14..18], 16) catch return error.InvalidArgument;
        var i: usize = 0;
        while (i < 2) : (i += 1) {
            g.d4[i] = std.fmt.parseInt(u8, body[19 + i * 2 ..][0..2], 16) catch return error.InvalidArgument;
        }
        while (i < 8) : (i += 1) {
            g.d4[i] = std.fmt.parseInt(u8, body[24 + (i - 2) * 2 ..][0..2], 16) catch return error.InvalidArgument;
        }
        return g;
    }
};

pub const DeviceConfig = struct {
    kind: DeviceKind = .tun,
    name: Name = .init("zeptun0"),
    netns: Name = .{},
    guid: ?Guid = null,
    fd: i32 = -1,
    mtu: u32 = 1500,
    queues: u16 = 0,
    offload: bool = true,
    multi_queue: bool = true,
    persist: bool = false,
    napi: bool = false,
    jumbo: bool = true,
    txqueuelen: u32 = 0,
    address4: ?addr.Prefix = addr.Prefix.parse("172.19.0.1/30") catch unreachable,
    address6: ?addr.Prefix = addr.Prefix.parse("fdfe:dcba:9876::1/126") catch unreachable,
    extra_addresses: PrefixList = .{},
    configure: bool = true,
};

pub const StackConfig = struct {
    mode: StackMode = if (build_options.enable_userspace_tcp or !build_options.enable_system_stack) .userspace else .hybrid,
    tcp_rx_window: u32 = 512 << 10,
    tcp_tx_buffer: u32 = 256 << 10,
    tcp_rx_budget: u32 = 1 << 20,
    tcp_tx_budget: u32 = 16 << 20,
    tcp_mss_clamp: u16 = 0,
    tcp_initial_cwnd: u16 = 10,
    tcp_congestion: Congestion = .cubic,
    tcp_sack: bool = true,
    tcp_timestamps: bool = true,
    tcp_window_scaling: bool = true,
    tcp_connect_timeout_ms: u32 = 10_000,
    tcp_idle_timeout_ms: u32 = 7_200_000,
    tcp_linger_ms: u32 = 2_000,
    tcp_min_rto_ms: u32 = 200,
    tcp_delayed_ack_ms: u16 = 1,
    tcp_max_rto_ms: u32 = 60_000,
    tcp_early_accept: AutoMode = .auto,
    udp_idle_timeout_ms: u32 = 60_000,
    udp: UdpMode = .enabled,
    udp_nat: NatMode = .endpoint_independent,
    icmp: IcmpMode = .auto,
    icmp_idle_timeout_ms: u32 = 10_000,
    max_tcp_sessions: u32 = 65536,
    max_udp_sessions: u32 = 16384,
    max_reassembly: u32 = 256,
    reassembly_timeout_ms: u32 = 10_000,
    listen_port_base: u16 = 0,
    nat_port_base: u16 = 20000,
    nat_port_limit: u16 = 65000,
    verify_checksums: bool = false,
};

pub const IoConfig = struct {
    backend: IoBackend = .auto,
    ring_entries: u16 = 512,
    sqpoll: bool = false,
    workers: u16 = 0,
    pin_cpus: bool = false,
    rx_parallel: u16 = 8,
    tx_slots: u16 = 1024,
    busy_poll_us: u32 = 0,
    multishot_rx: bool = true,
    monitor_network: AutoMode = .auto,
    elastic: ElasticMode = .auto,
};

pub const MemoryConfig = struct {
    budget_bytes: u64 = 0,
    buffers_per_worker: u32 = 0,
    buffer_size: u32 = 0,
};

pub const Socks5Config = struct {
    server: addr.Endpoint = .{},
    username: Name = .{},
    password: Name = .{},
    udp: UdpMode = .enabled,
    udp_mode: Socks5UdpMode = .udp,
    udp_address: ?addr.Address = null,
    pipeline: PipelineMode = .auto,
    optimistic_data: bool = true,
    pool_size: u16 = 4,
    pool_idle_ms: u32 = 3_000,
};

pub const DirectConfig = struct {
    fwmark: u32 = 0,
    bind_interface: Name = .{},
    bind4: ?addr.Address = null,
    bind6: ?addr.Address = null,
};

pub const HandlerConfig = struct {
    kind: HandlerKind = .direct,
    socks5: Socks5Config = .{},
    direct: DirectConfig = .{},
    passthrough_gso: bool = false,
    tcp_fastopen: bool = false,
    preserve_dscp: bool = true,
};

pub const RouteConfig = struct {
    auto_route: bool = false,
    table: u32 = 2022,
    rule_priority: u32 = 9000,
    fwmark: u32 = if (builtin.abi.isAndroid()) 0x200000 else 0x2022,
    fwmark_mask: u32 = if (builtin.abi.isAndroid()) 0x200000 else 0xffff_ffff,
    include_packages: PackageList = .{},
    exclude_packages: PackageList = .{},
    android_users: UidList = .{},
    include: PrefixList = .{},
    exclude: PrefixList = .{},
    include_extra: []const addr.Prefix = &.{},
    exclude_extra: []const addr.Prefix = &.{},
    dns: PrefixList = .{},
    strict: bool = false,
    auto_redirect: bool = false,
    redirect_port: u16 = 0,
    include_uids: UidList = .{},
    exclude_uids: UidList = .{},
    include_interfaces: InterfaceList = .{},
    exclude_interfaces: InterfaceList = .{},
};

pub const DnsConfig = struct {
    fake_ip: bool = false,
    hijack: bool = false,
    address4: ?addr.Address = null,
    address6: ?addr.Address = null,
    upstream: ?addr.Endpoint = null,
    fake_range4: ?addr.Prefix = addr.Prefix.parse("198.18.0.0/15") catch unreachable,
    fake_range6: ?addr.Prefix = addr.Prefix.parse("fc00::/18") catch unreachable,
    cache_size: u32 = 16384,
    ttl: u32 = 1,
};

pub const Config = struct {
    pub fn dnsAddress4(c: *const Config) ?addr.Address {
        if (c.dns.address4) |a| return a;
        const p = c.device.address4 orelse return null;
        if (p.bits > 30) return null;
        return p.host(2);
    }

    pub fn dnsAddress6(c: *const Config) ?addr.Address {
        if (c.dns.address6) |a| return a;
        const p = c.device.address6 orelse return null;
        if (p.bits > 126) return null;
        return p.host(2);
    }

    pub fn dnsActive(c: *const Config) bool {
        return c.dns.fake_ip or (c.dns.hijack and c.dns.upstream != null);
    }

    pub fn monitorNetwork(c: *const Config) bool {
        return switch (c.io.monitor_network) {
            .on => true,
            .off => false,
            .auto => c.device.kind == .tun and c.device.configure and !builtin.abi.isAndroid(),
        };
    }

    pub fn icmpForward(c: *const Config) bool {
        return switch (c.stack.icmp) {
            .forward => true,
            .auto => c.handler.kind == .direct,
            .local, .drop => false,
        };
    }

    pub fn earlyAccept(c: *const Config) bool {
        return switch (c.stack.tcp_early_accept) {
            .on => true,
            .off => false,
            .auto => c.handler.kind == .socks5,
        };
    }

    preset: Preset = .desktop,
    device: DeviceConfig = .{},
    stack: StackConfig = .{},
    io: IoConfig = .{},
    memory: MemoryConfig = .{},
    handler: HandlerConfig = .{},
    route: RouteConfig = .{},
    dns: DnsConfig = .{},
    dns_resolved: AutoMode = .auto,
    log_level: log.Level = .info,
    stats_interval_ms: u32 = 0,

    pub fn fromPreset(p: Preset) Config {
        var c: Config = .{ .preset = p };
        switch (p) {
            .desktop => {},
            .server => {
                c.device.mtu = 9000;
                c.stack.max_tcp_sessions = 262144;
                c.stack.max_udp_sessions = 65536;
                c.stack.tcp_rx_window = 4 << 20;
                c.stack.tcp_tx_buffer = 4 << 20;
                c.stack.tcp_tx_budget = 64 << 20;
                c.io.ring_entries = 4096;
                c.io.rx_parallel = 32;
            },
            .mobile => {
                c.device.mtu = 1500;
                c.device.offload = false;
                c.device.multi_queue = false;
                c.device.queues = 1;
                c.stack.mode = .userspace;
                c.stack.tcp_rx_window = 64 << 10;
                c.stack.tcp_tx_buffer = 128 << 10;
                c.stack.tcp_tx_budget = 4 << 20;
                c.stack.tcp_timestamps = false;
                c.stack.max_tcp_sessions = 1200;
                c.stack.max_udp_sessions = 512;
                c.stack.max_reassembly = 16;
                c.stack.tcp_idle_timeout_ms = 600_000;
                c.stack.udp_idle_timeout_ms = 30_000;
                c.io.backend = .auto;
                c.io.workers = 1;
                c.io.pin_cpus = false;
                c.io.rx_parallel = 4;
                c.io.tx_slots = 128;
                c.io.ring_entries = 256;
                c.memory.budget_bytes = 24 << 20;
            },
        }
        return c;
    }

    pub fn validate(c: *const Config) !void {
        if (c.device.mtu < 576 or c.device.mtu > 65535) return error.InvalidArgument;
        if (c.device.kind == .fd and c.device.fd < 0) return error.InvalidArgument;
        if (c.stack.max_tcp_sessions == 0 or c.stack.max_udp_sessions == 0) return error.InvalidArgument;
        if (c.stack.nat_port_limit <= c.stack.nat_port_base) return error.InvalidArgument;
        if (c.handler.kind == .socks5 and c.handler.socks5.server.port == 0) return error.InvalidArgument;
        if (c.stack.mode != .userspace and !build_options.enable_system_stack) return error.NotSupported;
        if (c.stack.mode == .userspace and !build_options.enable_userspace_tcp) return error.NotSupported;
        if (c.handler.kind == .socks5 and !build_options.enable_socks5) return error.NotSupported;
        if (c.handler.kind == .direct and !build_options.enable_direct) return error.NotSupported;
        if (c.handler.kind == .passthrough and !build_options.enable_passthrough) return error.NotSupported;
        if (c.stack.mode != .userspace and c.device.kind == .external) return error.InvalidArgument;
        if (c.stack.mode != .userspace and c.device.address4 == null and c.device.address6 == null) return error.InvalidArgument;
        if (c.route.auto_redirect and (!c.route.auto_route or c.device.kind != .tun)) return error.InvalidArgument;
        if (c.route.auto_redirect and builtin.os.tag != .linux) return error.NotSupported;
        if (c.route.auto_redirect and !build_options.enable_system_stack) return error.NotSupported;
        if (c.dns.fake_ip and c.handler.kind != .socks5) return error.InvalidArgument;
        if (c.dns.fake_ip and c.dns.fake_range4 == null and c.dns.fake_range6 == null) return error.InvalidArgument;
        if (c.stack.icmp == .forward and c.handler.kind == .socks5) {
            log.err("icmp.forward cannot be combined with a socks5 handler: echo requests would leave from the host's real address, bypassing the proxy. Use icmp.local, icmp.drop, or the direct handler", .{});
            return error.InvalidArgument;
        }
    }
};

pub const Sizing = struct {
    workers: u16,
    buffers_per_worker: u32,
    buffer_size: u32,
    tcp_sessions_per_worker: u32,
    udp_sessions_per_worker: u32,
};

pub const min_buffers_per_worker: u32 = 1024;

pub fn size(c: *const Config, workers: u16, buffer_size: u32, min_buffer_size: u32, session_bytes: u32) Sizing {
    const w: u32 = @max(1, workers);
    var s: Sizing = .{
        .workers = @intCast(w),
        .buffer_size = if (c.memory.buffer_size != 0) c.memory.buffer_size else buffer_size,
        .buffers_per_worker = 0,
        .tcp_sessions_per_worker = @max(16, c.stack.max_tcp_sessions / w),
        .udp_sessions_per_worker = @max(16, c.stack.max_udp_sessions / w),
    };
    if (c.memory.buffers_per_worker != 0) {
        s.buffers_per_worker = c.memory.buffers_per_worker;
    } else if (c.memory.budget_bytes != 0) {
        const session_cost: u64 = @as(u64, s.tcp_sessions_per_worker + s.udp_sessions_per_worker) * session_bytes * w;
        const remaining: u64 = if (c.memory.budget_bytes > session_cost) c.memory.budget_bytes - session_cost else c.memory.budget_bytes / 2;
        const per_worker = remaining / w;
        if (c.memory.buffer_size == 0) {
            const floor = @max(min_buffer_size, 2048);
            while (s.buffer_size > floor and per_worker / s.buffer_size < min_buffers_per_worker) {
                s.buffer_size = @max(floor, s.buffer_size / 2);
            }
        }
        s.buffers_per_worker = @intCast(std.math.clamp(per_worker / s.buffer_size, 64, 1 << 15));
    } else {
        s.buffers_per_worker = std.math.clamp(@as(u32, @intCast(@min((256 << 20) / @as(u64, s.buffer_size), 1 << 15))), 256, 1 << 15);
    }
    return s;
}

test "presets validate" {
    var d = Config.fromPreset(.desktop);
    try d.validate();
    const m = Config.fromPreset(.mobile);
    try m.validate();
    const s = size(&m, 1, 4096, 4096, 1024);
    try std.testing.expect(s.buffers_per_worker * 4096 <= 24 << 20);
    d.handler.kind = .socks5;
    try std.testing.expectError(error.InvalidArgument, d.validate());
}

test "guid parsing accepts both spellings" {
    const plain = try Guid.parse("24198F4C-7895-434C-AD35-9E29A92DDC51");
    const braced = try Guid.parse("{24198f4c-7895-434c-ad35-9e29a92ddc51}");
    try std.testing.expectEqual(@as(u32, 0x24198F4C), plain.d1);
    try std.testing.expectEqual(@as(u16, 0x7895), plain.d2);
    try std.testing.expectEqual(@as(u16, 0x434C), plain.d3);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAD, 0x35, 0x9E, 0x29, 0xA9, 0x2D, 0xDC, 0x51 }, &plain.d4);
    try std.testing.expectEqual(plain.d1, braced.d1);
    try std.testing.expectEqualSlices(u8, &plain.d4, &braced.d4);
    try std.testing.expectError(error.InvalidArgument, Guid.parse("nope"));
    try std.testing.expectError(error.InvalidArgument, Guid.parse("24198F4C78954 34C-AD35-9E29A92DDC51"));
}

test "icmp forward with a socks5 handler is rejected" {
    var cfg = Config.fromPreset(.desktop);
    cfg.handler.kind = .socks5;
    cfg.handler.socks5.server = addr.Endpoint.parse("127.0.0.1:1080") catch unreachable;
    cfg.stack.icmp = .forward;
    try std.testing.expectError(error.InvalidArgument, cfg.validate());

    cfg.stack.icmp = .auto;
    try std.testing.expect(!cfg.icmpForward());
    try cfg.validate();

    cfg.handler.kind = .direct;
    cfg.stack.icmp = .forward;
    try std.testing.expect(cfg.icmpForward());
    try cfg.validate();
}
