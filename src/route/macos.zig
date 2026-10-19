const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const config = @import("../config.zig");
const addr = @import("../addr.zig");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");
const bsd = @import("../device/bsd.zig");

const libc = std.c;
const os = builtin.target.os.tag;
const native_endian = builtin.target.cpu.arch.endian();

pub const supported = sys.is_darwin or os == .freebsd;

pub const PF_ROUTE: c_uint = 17;
pub const AF_LINK: u8 = 18;
pub const RTM_VERSION: u8 = 5;
pub const RTM_ADD: u8 = 0x1;
pub const RTM_DELETE: u8 = 0x2;
pub const RTM_GET: u8 = 0x4;
pub const RTF_UP: i32 = 0x1;
pub const RTF_GATEWAY: i32 = 0x2;
pub const RTF_HOST: i32 = 0x4;
pub const RTF_STATIC: i32 = 0x800;
pub const RTA_DST: i32 = 0x1;
pub const RTA_GATEWAY: i32 = 0x2;
pub const RTA_NETMASK: i32 = 0x4;
pub const RTA_IFP: i32 = 0x10;
pub const RTAX_GATEWAY = 1;
pub const RTAX_IFP = 4;
pub const RTAX_MAX = 8;
pub const IN6_IFF_NODAD: i32 = 0x20;
pub const ND6_INFINITE_LIFETIME: u32 = 0xffffffff;

pub const sa_align: usize = if (sys.is_darwin) @sizeOf(u32) else @sizeOf(c_long);
const dl_data_len = if (os == .freebsd) 46 else 12;

pub const SIOCAIFADDR = if (os == .freebsd) bsd.iow('i', 43, @sizeOf(IfAliasReq)) else bsd.iow('i', 26, @sizeOf(IfAliasReq));
pub const SIOCAIFADDR_IN6 = if (os == .freebsd) bsd.iow('i', 27, @sizeOf(In6AliasReq)) else bsd.iow('i', 26, @sizeOf(In6AliasReq));

pub const SockaddrIn = extern struct {
    len: u8 = 16,
    family: u8 = @intCast(sys.AF_INET),
    port: u16 = 0,
    addr: [4]u8 = @splat(0),
    zero: [8]u8 = @splat(0),
};

pub const SockaddrIn6 = extern struct {
    len: u8 = 28,
    family: u8 = @intCast(sys.AF_INET6),
    port: u16 = 0,
    flowinfo: u32 = 0,
    addr: [16]u8 = @splat(0),
    scope_id: u32 = 0,
};

pub const SockaddrDl = extern struct {
    len: u8 = 8 + dl_data_len,
    family: u8 = AF_LINK,
    index: u16 = 0,
    kind: u8 = 0,
    nlen: u8 = 0,
    alen: u8 = 0,
    slen: u8 = 0,
    data: [dl_data_len]u8 = @splat(0),
};

pub const IfAliasReq = if (os == .freebsd) extern struct {
    name: [16]u8 = @splat(0),
    addr: SockaddrIn = .{},
    dstaddr: SockaddrIn = .{},
    mask: SockaddrIn = .{},
    vhid: i32 = 0,
} else extern struct {
    name: [16]u8 = @splat(0),
    addr: SockaddrIn = .{},
    dstaddr: SockaddrIn = .{},
    mask: SockaddrIn = .{},
};

pub const AddrLifetime = extern struct {
    expire: libc.time_t = 0,
    preferred: libc.time_t = 0,
    vltime: u32 = ND6_INFINITE_LIFETIME,
    pltime: u32 = ND6_INFINITE_LIFETIME,
};

pub const In6AliasReq = if (os == .freebsd) extern struct {
    name: [16]u8 = @splat(0),
    addr: SockaddrIn6 = .{},
    dstaddr: SockaddrIn6 = .{ .len = 0, .family = 0 },
    prefixmask: SockaddrIn6 = .{},
    flags: i32 = 0,
    lifetime: AddrLifetime = .{},
    vhid: i32 = 0,
} else extern struct {
    name: [16]u8 = @splat(0),
    addr: SockaddrIn6 = .{},
    dstaddr: SockaddrIn6 = .{ .len = 0, .family = 0 },
    prefixmask: SockaddrIn6 = .{},
    flags: i32 = 0,
    lifetime: AddrLifetime = .{},
};

pub const RtMsgHdr = if (os == .freebsd) extern struct {
    msglen: u16 = 0,
    version: u8 = RTM_VERSION,
    kind: u8 = 0,
    index: u16 = 0,
    spare: u16 = 0,
    flags: i32 = 0,
    addrs: i32 = 0,
    pid: i32 = 0,
    seq: i32 = 0,
    err: i32 = 0,
    fmask: i32 = 0,
    inits: c_ulong = 0,
    rmx: [14]c_ulong = @splat(0),
} else extern struct {
    msglen: u16 = 0,
    version: u8 = RTM_VERSION,
    kind: u8 = 0,
    index: u16 = 0,
    flags: i32 = 0,
    addrs: i32 = 0,
    pid: i32 = 0,
    seq: i32 = 0,
    err: i32 = 0,
    use: i32 = 0,
    inits: u32 = 0,
    rmx: [14]u32 = @splat(0),
};

comptime {
    if (sys.is_darwin and @sizeOf(usize) == 8) {
        std.debug.assert(@sizeOf(RtMsgHdr) == 92);
        std.debug.assert(@offsetOf(RtMsgHdr, "flags") == 8);
        std.debug.assert(@sizeOf(IfAliasReq) == 64);
        std.debug.assert(@sizeOf(In6AliasReq) == 128);
        std.debug.assert(@offsetOf(In6AliasReq, "lifetime") == 104);
        std.debug.assert(@sizeOf(SockaddrDl) == 20);
        std.debug.assert(SIOCAIFADDR == 0x8040691a);
        std.debug.assert(SIOCAIFADDR_IN6 == 0x8080691a);
    }
    if (os == .freebsd and @sizeOf(usize) == 8) {
        std.debug.assert(@sizeOf(RtMsgHdr) == 152);
        std.debug.assert(@sizeOf(IfAliasReq) == 68);
        std.debug.assert(@sizeOf(In6AliasReq) == 136);
        std.debug.assert(SIOCAIFADDR == 0x8044692b);
        std.debug.assert(SIOCAIFADDR_IN6 == 0x8088691b);
    }
}

pub const sockaddr_capacity = 64;

pub const RawSockaddr = struct {
    bytes: [sockaddr_capacity]u8 = @splat(0),
    len: u8 = 0,

    pub fn from(sa: []const u8) ?RawSockaddr {
        if (sa.len == 0 or sa.len > sockaddr_capacity) return null;
        var r: RawSockaddr = .{ .len = @intCast(sa.len) };
        @memcpy(r.bytes[0..sa.len], sa);
        return r;
    }

    pub fn of(value: anytype) RawSockaddr {
        return from(std.mem.asBytes(value)).?;
    }

    pub inline fn slice(r: *const RawSockaddr) []const u8 {
        return r.bytes[0..r.len];
    }
};

pub const Route = struct {
    dst: addr.Prefix = .{},
    gateway: RawSockaddr = .{},
    ifp: RawSockaddr = .{},
    flags: i32 = 0,
    index: u32 = 0,
};

pub const max_routes = config.max_prefixes * 2 + 8;

pub const Applied = struct {
    configured: bool = false,
    name: [16]u8 = @splat(0),
    index: u32 = 0,
    routes: [max_routes]Route = undefined,
    route_count: u16 = 0,
    default4: ?Route = null,
    default6: ?Route = null,
    link_routes: u16 = 0,

    pub fn defaultIndex(a: *const Applied, family: addr.Family) u32 {
        const r = switch (family) {
            .v4 => a.default4,
            .v6 => a.default6,
        };
        return if (r) |d| d.index else 0;
    }

    fn record(a: *Applied, r: Route) void {
        if (a.route_count == max_routes) {
            log.warn("route: route table full, {f} will not be removed on teardown", .{r.dst});
            return;
        }
        a.routes[a.route_count] = r;
        a.route_count += 1;
    }
};

pub fn saSpace(len: usize) usize {
    if (len == 0) return sa_align;
    return std.mem.alignForward(usize, len, sa_align);
}

pub fn maxBits(family: addr.Family) u8 {
    return if (family == .v4) 32 else 128;
}

pub fn maskOf(family: addr.Family, bits: u8) addr.Address {
    var m: addr.Address = .{ .family = family };
    var remaining = bits;
    for (m.bytes[0..m.len()]) |*b| {
        const take = @min(remaining, 8);
        b.* = @truncate(@as(u16, 0xff00) >> @intCast(take));
        remaining -= take;
    }
    return m;
}

pub fn sockaddrOf(a: addr.Address) RawSockaddr {
    return switch (a.family) {
        .v4 => RawSockaddr.of(&SockaddrIn{ .addr = a.bytes[0..4].* }),
        .v6 => RawSockaddr.of(&SockaddrIn6{ .addr = a.bytes }),
    };
}

pub fn linkSockaddr(index: u32, name: []const u8) RawSockaddr {
    var dl: SockaddrDl = .{ .index = @truncate(index) };
    const n = @min(name.len, dl.data.len);
    @memcpy(dl.data[0..n], name[0..n]);
    dl.nlen = @intCast(n);
    return RawSockaddr.of(&dl);
}

pub fn splitDefault(family: addr.Family) [2]addr.Prefix {
    const low: addr.Prefix = .{ .addr = .{ .family = family }, .bits = 1 };
    var high = low;
    high.addr.bytes[0] = 0x80;
    return .{ low, high };
}

pub fn parseSockaddrs(msg: []const u8, addrs: i32) [RTAX_MAX]?[]const u8 {
    var out: [RTAX_MAX]?[]const u8 = @splat(null);
    var off: usize = @sizeOf(RtMsgHdr);
    for (0..RTAX_MAX) |i| {
        if (addrs & (@as(i32, 1) << @intCast(i)) == 0) continue;
        if (off >= msg.len) break;
        const l: usize = msg[off];
        if (off + l > msg.len) break;
        out[i] = msg[off .. off + l];
        off += saSpace(l);
    }
    return out;
}

fn routeError(e: libc.E) anyerror {
    return switch (e) {
        .EXIST => error.Exists,
        .SRCH => error.NotFound,
        .NETUNREACH => error.NetworkUnreachable,
        else => sys.errnoError(sys.mapErrno(e)),
    };
}

pub const Message = struct {
    buf: [1024]u8 = @splat(0),
    len: usize = @sizeOf(RtMsgHdr),
    addrs: i32 = 0,

    pub fn add(m: *Message, rta: i32, sa: []const u8) void {
        m.addrs |= rta;
        @memcpy(m.buf[m.len..][0..sa.len], sa);
        m.len += saSpace(sa.len);
    }

    pub fn finish(m: *Message, kind: u8, flags: i32, seq: i32, pid: i32) []const u8 {
        const h: RtMsgHdr = .{
            .msglen = @intCast(m.len),
            .kind = kind,
            .flags = flags,
            .addrs = m.addrs,
            .pid = pid,
            .seq = seq,
        };
        @memcpy(m.buf[0..@sizeOf(RtMsgHdr)], std.mem.asBytes(&h));
        return m.buf[0..m.len];
    }
};

const RouteSocket = struct {
    fd: sys.fd_t,
    pid: i32,
    seq: i32 = 0,

    fn open() !RouteSocket {
        const fd = libc.socket(PF_ROUTE, libc.SOCK.RAW, 0);
        if (fd < 0) return sys.errnoError(sys.mapErrno(libc.errno(fd)));
        _ = libc.fcntl(fd, libc.F.SETFD, @as(c_int, libc.FD_CLOEXEC));
        return .{ .fd = fd, .pid = libc.getpid() };
    }

    fn close(rt: *RouteSocket) void {
        sys.close(rt.fd);
    }

    fn muteReplies(rt: *RouteSocket) void {
        _ = sys.shutdown(rt.fd, .read);
    }

    fn send(rt: *RouteSocket, m: *Message, kind: u8, flags: i32) !i32 {
        rt.seq += 1;
        const bytes = m.finish(kind, flags, rt.seq, rt.pid);
        const rc = libc.write(rt.fd, bytes.ptr, bytes.len);
        if (rc < 0) return routeError(libc.errno(rc));
        return rt.seq;
    }

    fn receive(rt: *RouteSocket, buf: []u8, kind: u8, seq: i32) ![]const u8 {
        const deadline = sys.monotonicMs() + 2000;
        while (true) {
            const now = sys.monotonicMs();
            if (now >= deadline) return error.Timeout;
            var pfd = [1]libc.pollfd{.{ .fd = rt.fd, .events = libc.POLL.IN, .revents = 0 }};
            const pr = libc.poll(&pfd, 1, @intCast(deadline - now));
            if (pr < 0) {
                if (libc.errno(pr) == .INTR) continue;
                return sys.errnoError(sys.mapErrno(libc.errno(pr)));
            }
            if (pr == 0) return error.Timeout;
            const n = libc.read(rt.fd, buf.ptr, buf.len);
            if (n < 0) switch (libc.errno(n)) {
                .INTR, .AGAIN, .NOBUFS => continue,
                else => |e| return sys.errnoError(sys.mapErrno(e)),
            };
            const len: usize = @intCast(n);
            if (len < @sizeOf(RtMsgHdr)) continue;
            const h = std.mem.bytesToValue(RtMsgHdr, buf[0..@sizeOf(RtMsgHdr)]);
            if (h.version != RTM_VERSION or h.kind != kind or h.pid != rt.pid or h.seq != seq) continue;
            if (h.err > 0 and h.err <= std.math.maxInt(u16)) return routeError(@fromBackingInt(@intCast(@as(u16, @intCast(h.err)))));
            return buf[0..@min(len, h.msglen)];
        }
    }

    fn change(rt: *RouteSocket, kind: u8, r: *const Route) !void {
        var m: Message = .{};
        const family = r.dst.addr.family;
        const host = r.dst.bits >= maxBits(family);
        m.add(RTA_DST, sockaddrOf(r.dst.masked().addr).slice());
        if (r.gateway.len > 0) m.add(RTA_GATEWAY, r.gateway.slice());
        if (!host) m.add(RTA_NETMASK, sockaddrOf(maskOf(family, r.dst.bits)).slice());
        if (kind == RTM_ADD and r.ifp.len > 0) m.add(RTA_IFP, r.ifp.slice());
        var flags = RTF_STATIC | r.flags;
        if (kind == RTM_ADD) flags |= RTF_UP;
        if (host) flags |= RTF_HOST;
        _ = try rt.send(&m, kind, flags);
    }

    fn defaultRoute(rt: *RouteSocket, family: addr.Family) !?Route {
        var m: Message = .{};
        const zero = sockaddrOf(.{ .family = family });
        m.add(RTA_DST, zero.slice());
        m.add(RTA_NETMASK, zero.slice());
        m.add(RTA_IFP, RawSockaddr.of(&SockaddrDl{}).slice());
        const seq = rt.send(&m, RTM_GET, RTF_UP | RTF_GATEWAY | RTF_STATIC) catch |err| switch (err) {
            error.NotFound, error.NetworkUnreachable => return null,
            else => return err,
        };
        var buf: [2048]u8 = undefined;
        const reply = rt.receive(&buf, RTM_GET, seq) catch |err| switch (err) {
            error.NotFound, error.NetworkUnreachable => return null,
            else => return err,
        };
        const h = std.mem.bytesToValue(RtMsgHdr, reply[0..@sizeOf(RtMsgHdr)]);
        const sas = parseSockaddrs(reply, h.addrs);
        const gateway = RawSockaddr.from(sas[RTAX_GATEWAY] orelse return null) orelse return null;
        var r: Route = .{
            .dst = .{ .addr = .{ .family = family }, .bits = 0 },
            .gateway = gateway,
            .flags = h.flags & RTF_GATEWAY,
            .index = h.index,
        };
        if (sas[RTAX_IFP]) |ifp| {
            if (RawSockaddr.from(ifp)) |raw| {
                r.ifp = raw;
                if (r.index == 0 and raw.len >= 4) r.index = std.mem.readInt(u16, raw.bytes[2..4], native_endian);
            }
        }
        return r;
    }
};

fn installTunnel(rt: *RouteSocket, applied: *Applied, dst: addr.Prefix, gateway: RawSockaddr) !void {
    const r: Route = .{ .dst = dst.masked(), .gateway = gateway, .index = applied.index };
    rt.change(RTM_ADD, &r) catch |err| switch (err) {
        error.Exists => {
            const stale: Route = .{ .dst = r.dst };
            rt.change(RTM_DELETE, &stale) catch {};
            try rt.change(RTM_ADD, &r);
        },
        else => return err,
    };
    applied.record(r);
}

fn installExclude(rt: *RouteSocket, applied: *Applied, dst: addr.Prefix, via: *const Route) !void {
    const r: Route = .{
        .dst = dst.masked(),
        .gateway = via.gateway,
        .ifp = if (via.flags & RTF_GATEWAY != 0) via.ifp else .{},
        .flags = via.flags,
        .index = via.index,
    };
    rt.change(RTM_ADD, &r) catch |err| switch (err) {
        error.Exists => {
            log.info("route: {f} already has a route, leaving it in place", .{r.dst});
            return;
        },
        else => return err,
    };
    applied.record(r);
}

fn addAddress4(ifname: []const u8, p: addr.Prefix) !void {
    var req: IfAliasReq = .{};
    @memcpy(req.name[0..ifname.len], ifname);
    req.addr.addr = p.addr.bytes[0..4].*;
    req.dstaddr.addr = p.addr.bytes[0..4].*;
    req.mask.addr = maskOf(.v4, p.bits).bytes[0..4].*;
    try bsd.interfaceIoctl(sys.AF_INET, SIOCAIFADDR, @intFromPtr(&req));
}

fn addAddress6(ifname: []const u8, p: addr.Prefix) !void {
    var req: In6AliasReq = .{};
    @memcpy(req.name[0..ifname.len], ifname);
    req.addr.addr = p.addr.bytes;
    req.prefixmask.addr = maskOf(.v6, p.bits).bytes;
    req.flags = IN6_IFF_NODAD;
    if (p.bits >= 128) req.dstaddr = .{ .addr = p.host(1).bytes };
    try bsd.interfaceIoctl(sys.AF_INET6, SIOCAIFADDR_IN6, @intFromPtr(&req));
}

pub fn configure(cfg: *const config.Config, ifname: []const u8, addresses: []const addr.Prefix) !Applied {
    if (!supported) return error.NotSupported;
    var applied: Applied = .{};
    if (ifname.len == 0 or ifname.len >= applied.name.len) return error.InvalidArgument;
    @memcpy(applied.name[0..ifname.len], ifname);
    try bsd.setMtu(ifname, cfg.device.mtu);
    for (addresses) |p| {
        switch (p.addr.family) {
            .v4 => addAddress4(ifname, p) catch |err| {
                log.err("route: assigning {f} to {s} failed: {t}", .{ p, ifname, err });
                return err;
            },
            .v6 => addAddress6(ifname, p) catch |err| {
                log.err("route: assigning {f} to {s} failed: {t}", .{ p, ifname, err });
                return err;
            },
        }
    }
    try bsd.setUp(ifname);
    applied.index = bsd.interfaceIndex(ifname);
    if (applied.index == 0) return error.DeviceNotFound;
    var rt = try RouteSocket.open();
    defer rt.close();
    rt.muteReplies();
    const gateway = linkSockaddr(applied.index, ifname);
    for (addresses) |p| {
        if (p.addr.family != .v4 or p.bits >= 32) continue;
        installTunnel(&rt, &applied, p, gateway) catch |err| {
            log.warn("route: adding {f} on {s} failed: {t}", .{ p.masked(), ifname, err });
        };
    }
    applied.configured = true;
    applied.link_routes = applied.route_count;
    return applied;
}

pub fn applyRoutes(cfg: *const config.Config, ifname: []const u8, applied: *Applied) !void {
    if (!supported) return error.NotSupported;
    if (!cfg.route.auto_route) return;
    if (applied.index == 0) applied.index = bsd.interfaceIndex(ifname);
    if (applied.index == 0) return error.DeviceNotFound;
    var rt = try RouteSocket.open();
    defer rt.close();
    const families = [_]addr.Family{ .v4, .v6 };
    const enabled = [_]bool{
        cfg.device.address4 != null,
        cfg.device.address6 != null and build_options.enable_ipv6,
    };
    var defaults: [2]?Route = .{ null, null };
    for (families, enabled, &defaults) |family, on, *slot| {
        if (!on) continue;
        slot.* = rt.defaultRoute(family) catch |err| blk: {
            log.warn("route: looking up the {t} default route failed: {t}", .{ family, err });
            break :blk null;
        };
        if (slot.*) |d| {
            if (d.index == applied.index) slot.* = null;
        }
    }
    applied.default4 = defaults[0];
    applied.default6 = defaults[1];
    rt.muteReplies();
    for (families, enabled, defaults) |family, on, default_route| {
        if (!on) continue;
        for (cfg.route.exclude.slice()) |p| {
            if (p.addr.family != family) continue;
            const via = default_route orelse {
                log.warn("route: no {t} default route to exclude {f} through", .{ family, p });
                continue;
            };
            installExclude(&rt, applied, p, &via) catch |err| {
                log.err("route: excluding {f} failed: {t}", .{ p, err });
                return err;
            };
        }
    }
    const gateway = linkSockaddr(applied.index, ifname);
    for (families, enabled) |family, on| {
        if (!on) continue;
        var any_include = false;
        for (cfg.route.include.slice()) |p| {
            if (p.addr.family != family) continue;
            any_include = true;
            installTunnel(&rt, applied, p, gateway) catch |err| {
                log.err("route: routing {f} into {s} failed: {t}", .{ p, ifname, err });
                return err;
            };
        }
        if (any_include) continue;
        for (splitDefault(family)) |p| {
            installTunnel(&rt, applied, p, gateway) catch |err| {
                if (family == .v6) {
                    log.warn("route: routing {f} into {s} failed: {t}", .{ p, ifname, err });
                    break;
                }
                log.err("route: routing {f} into {s} failed: {t}", .{ p, ifname, err });
                return err;
            };
        }
    }
}

pub fn defaultInterfaceIndex(family: addr.Family) u32 {
    if (!supported) return 0;
    var rt = RouteSocket.open() catch return 0;
    defer rt.close();
    const r = (rt.defaultRoute(family) catch return 0) orelse return 0;
    return r.index;
}

fn removeRoutes(applied: *Applied, keep: u16) void {
    if (applied.route_count <= keep) return;
    var rt = RouteSocket.open() catch return;
    defer rt.close();
    rt.muteReplies();
    var i = applied.route_count;
    while (i > keep) {
        i -= 1;
        const r = &applied.routes[i];
        const stale: Route = .{ .dst = r.dst, .gateway = r.gateway, .flags = r.flags };
        rt.change(RTM_DELETE, &stale) catch |err| switch (err) {
            error.NotFound => {},
            else => log.warn("route: removing {f} failed: {t}", .{ r.dst, err }),
        };
    }
    applied.route_count = keep;
}

pub fn teardown(applied: *Applied) void {
    defer applied.configured = false;
    removeRoutes(applied, 0);
}

pub fn refreshRoutes(cfg: *const config.Config, ifname: []const u8, applied: *Applied) !void {
    if (!supported or !cfg.route.auto_route) return;
    removeRoutes(applied, applied.link_routes);
    try applyRoutes(cfg, ifname, applied);
}

pub fn openMonitorSocket() !sys.fd_t {
    if (!supported) return error.NotSupported;
    const fd = libc.socket(PF_ROUTE, libc.SOCK.RAW, 0);
    if (fd < 0) return sys.errnoError(sys.mapErrno(libc.errno(fd)));
    _ = libc.fcntl(fd, libc.F.SETFD, @as(c_int, libc.FD_CLOEXEC));
    try sys.setNonblocking(fd);
    return fd;
}

pub fn networkIdentity(tun_index: u32) struct { index4: u32, index6: u32, hash: u64 } {
    var out: @TypeOf(networkIdentity(0)) = .{ .index4 = 0, .index6 = 0, .hash = 0 };
    if (!supported) return out;
    var rt = RouteSocket.open() catch return out;
    defer rt.close();
    var hasher = std.hash.Wyhash.init(0x7a65);
    const families = [_]addr.Family{ .v4, .v6 };
    for (families) |family| {
        const r = (rt.defaultRoute(family) catch null) orelse continue;
        if (r.index == tun_index) continue;
        hasher.update(std.mem.asBytes(&r.index));
        hasher.update(r.gateway.slice());
        if (family == .v4) out.index4 = r.index else out.index6 = r.index;
    }
    out.hash = hasher.final();
    return out;
}

test "route message layout" {
    var m: Message = .{};
    const dst = sockaddrOf(try addr.Address.parse("10.0.0.0"));
    m.add(RTA_DST, dst.slice());
    m.add(RTA_GATEWAY, linkSockaddr(7, "utun3").slice());
    m.add(RTA_NETMASK, sockaddrOf(maskOf(.v4, 8)).slice());
    const bytes = m.finish(RTM_ADD, RTF_UP | RTF_STATIC, 1, 42);
    const h = std.mem.bytesToValue(RtMsgHdr, bytes[0..@sizeOf(RtMsgHdr)]);
    try std.testing.expectEqual(@as(usize, h.msglen), bytes.len);
    try std.testing.expectEqual(RTA_DST | RTA_GATEWAY | RTA_NETMASK, h.addrs);
    const sas = parseSockaddrs(bytes, h.addrs);
    try std.testing.expectEqualSlices(u8, dst.slice(), sas[0].?);
    try std.testing.expectEqual(@as(u16, 7), std.mem.readInt(u16, sas[1].?[2..4], native_endian));
    try std.testing.expectEqualSlices(u8, &.{ 255, 0, 0, 0 }, sas[2].?[4..8]);
    try std.testing.expectEqual(sa_align, saSpace(0));
    try std.testing.expectEqual(std.mem.alignForward(usize, 28, sa_align), saSpace(28));
    const split = splitDefault(.v6);
    try std.testing.expectEqual(@as(u8, 0x80), split[1].addr.bytes[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xfc }, maskOf(.v4, 30).slice());
}
