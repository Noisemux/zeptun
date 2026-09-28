const std = @import("std");
const builtin = @import("builtin");
const addr = @import("../addr.zig");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");

const linux = std.os.linux;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_GETADDR: u16 = 22;
pub const RTA_PREFSRC: u16 = 7;
pub const NLM_F_DUMP: u16 = 0x300;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

pub const IFLA_MTU: u16 = 4;
pub const IFLA_TXQLEN: u16 = 13;
pub const IFLA_IFNAME: u16 = 3;
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_FLAGS: u16 = 8;
pub const IFA_F_NODAD: u32 = 0x02;
pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_TABLE: u16 = 15;
pub const FRA_IIFNAME: u16 = 3;
pub const FRA_GOTO: u16 = 4;
pub const FRA_PRIORITY: u16 = 6;
pub const FRA_FWMARK: u16 = 10;
pub const FRA_TABLE: u16 = 15;
pub const FRA_FWMASK: u16 = 16;
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
pub const FRA_UID_RANGE: u16 = 20;
pub const FRA_DPORT_RANGE: u16 = 24;
pub const FIB_RULE_INVERT: u32 = 0x02;
pub const FR_ACT_UNSPEC: u8 = 0;
pub const FR_ACT_TO_TBL: u8 = 1;
pub const FR_ACT_GOTO: u8 = 2;
pub const FR_ACT_NOP: u8 = 3;
pub const FR_ACT_UNREACHABLE: u8 = 7;
pub const RT_TABLE_UNSPEC: u8 = 0;
pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_BOOT: u8 = 3;
pub const RTPROT_STATIC: u8 = 4;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RTN_UNICAST: u8 = 1;
pub const RTN_THROW: u8 = 9;
pub const IFF_UP: u32 = 0x1;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const NlMsgHdr = extern struct {
    len: u32,
    kind: u16,
    flags: u16,
    seq: u32,
    pid: u32,
};

const IfInfoMsg = extern struct {
    family: u8 = 0,
    pad: u8 = 0,
    kind: u16 = 0,
    index: i32 = 0,
    flags: u32 = 0,
    change: u32 = 0,
};

const IfAddrMsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8 = 0,
    scope: u8 = 0,
    index: u32,
};

const RtMsg = extern struct {
    family: u8,
    dst_len: u8,
    src_len: u8 = 0,
    tos: u8 = 0,
    table: u8,
    protocol: u8,
    scope: u8,
    kind: u8,
    flags: u32 = 0,
};

const FibRuleHdr = extern struct {
    family: u8,
    dst_len: u8 = 0,
    src_len: u8 = 0,
    tos: u8 = 0,
    table: u8 = 0,
    res1: u8 = 0,
    res2: u8 = 0,
    action: u8 = FR_ACT_TO_TBL,
    flags: u32 = 0,
};

pub const Error = error{ NetlinkError, PermissionDenied, NotSupported, Exists, NotFound, InvalidArgument, SystemResources };

const Builder = struct {
    buf: [1024]u8 align(4) = undefined,
    len: usize = 0,

    fn begin(b: *Builder, kind: u16, flags: u16, seq: u32) void {
        b.len = @sizeOf(NlMsgHdr);
        const h: NlMsgHdr = .{ .len = 0, .kind = kind, .flags = flags | NLM_F_REQUEST | NLM_F_ACK, .seq = seq, .pid = 0 };
        @memcpy(b.buf[0..@sizeOf(NlMsgHdr)], std.mem.asBytes(&h));
    }

    fn body(b: *Builder, value: anytype) void {
        const bytes = std.mem.asBytes(&value);
        @memcpy(b.buf[b.len..][0..bytes.len], bytes);
        b.len = std.mem.alignForward(usize, b.len + bytes.len, 4);
    }

    fn attr(b: *Builder, kind: u16, data: []const u8) void {
        const total = 4 + data.len;
        std.mem.writeInt(u16, b.buf[b.len..][0..2], @intCast(total), builtin.cpu.arch.endian());
        std.mem.writeInt(u16, b.buf[b.len + 2 ..][0..2], kind, builtin.cpu.arch.endian());
        @memcpy(b.buf[b.len + 4 ..][0..data.len], data);
        const aligned = std.mem.alignForward(usize, b.len + total, 4);
        @memset(b.buf[b.len + total .. aligned], 0);
        b.len = aligned;
    }

    fn attrU32(b: *Builder, kind: u16, v: u32) void {
        b.attr(kind, std.mem.asBytes(&v));
    }

    fn finish(b: *Builder) []const u8 {
        std.mem.writeInt(u32, b.buf[0..4], @intCast(b.len), builtin.cpu.arch.endian());
        return b.buf[0..b.len];
    }
};

pub const Netlink = struct {
    fd: i32,
    seq: u32 = 1,

    pub fn open() Error!Netlink {
        const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
        const r = sys.linuxResult(rc);
        if (r < 0) return switch (sys.toErrno(r)) {
            .acces, .perm => error.PermissionDenied,
            .afnosupport => error.NotSupported,
            else => error.NetlinkError,
        };
        var sa: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        if (sys.linuxResult(linux.bind(r, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl))) < 0) {
            sys.close(r);
            return error.NetlinkError;
        }
        return .{ .fd = r };
    }

    pub fn close(n: *Netlink) void {
        sys.close(n.fd);
    }

    fn transact(n: *Netlink, msg: []const u8) Error!void {
        const seq = n.seq;
        n.seq += 1;
        var dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        const sent = sys.linuxResult(linux.sendto(n.fd, msg.ptr, msg.len, 0, @ptrCast(&dst), @sizeOf(linux.sockaddr.nl)));
        if (sent < 0) return error.NetlinkError;
        var rbuf: [4096]u8 align(4) = undefined;
        var attempts: u32 = 0;
        while (attempts < 64) : (attempts += 1) {
            const got = sys.linuxResult(linux.recvfrom(n.fd, &rbuf, rbuf.len, 0, null, null));
            if (got < 0) {
                if (sys.toErrno(got) == .again or sys.toErrno(got) == .intr) continue;
                return error.NetlinkError;
            }
            var off: usize = 0;
            const total: usize = @intCast(got);
            while (off + @sizeOf(NlMsgHdr) <= total) {
                const h = std.mem.bytesToValue(NlMsgHdr, rbuf[off..][0..@sizeOf(NlMsgHdr)]);
                if (h.len < @sizeOf(NlMsgHdr) or off + h.len > total) return error.NetlinkError;
                if (h.kind == NLMSG_ERROR and h.seq == seq) {
                    const code = std.mem.readInt(i32, rbuf[off + @sizeOf(NlMsgHdr) ..][0..4], builtin.cpu.arch.endian());
                    if (code == 0) return;
                    const e: linux.E = @enumFromInt(-code);
                    return switch (e) {
                        .PERM, .ACCES => error.PermissionDenied,
                        .EXIST => error.Exists,
                        .NOENT, .SRCH, .NODEV, .ADDRNOTAVAIL => error.NotFound,
                        .INVAL => error.InvalidArgument,
                        .OPNOTSUPP, .AFNOSUPPORT => error.NotSupported,
                        .NOMEM, .NOBUFS => error.SystemResources,
                        else => error.NetlinkError,
                    };
                }
                off += std.mem.alignForward(usize, h.len, 4);
            }
        }
        return error.NetlinkError;
    }

    pub fn setLink(n: *Netlink, index: u32, up: ?bool, mtu: ?u32, txqlen: ?u32) Error!void {
        var b: Builder = .{};
        b.begin(RTM_NEWLINK, 0, n.seq);
        var info: IfInfoMsg = .{ .index = @intCast(index) };
        if (up) |u| {
            info.change = IFF_UP;
            info.flags = if (u) IFF_UP else 0;
        }
        b.body(info);
        if (mtu) |m| b.attrU32(IFLA_MTU, m);
        if (txqlen) |q| b.attrU32(IFLA_TXQLEN, q);
        return n.transact(b.finish());
    }

    pub fn address(n: *Netlink, index: u32, prefix: addr.Prefix, add: bool) Error!void {
        var b: Builder = .{};
        const v6 = prefix.addr.family == .v6;
        b.begin(if (add) RTM_NEWADDR else RTM_DELADDR, if (add) NLM_F_CREATE | NLM_F_REPLACE else 0, n.seq);
        b.body(IfAddrMsg{ .family = if (v6) AF_INET6 else AF_INET, .prefixlen = prefix.bits, .index = index });
        b.attr(IFA_LOCAL, prefix.addr.slice());
        b.attr(IFA_ADDRESS, prefix.addr.slice());
        if (v6) b.attrU32(IFA_FLAGS, IFA_F_NODAD);
        return n.transact(b.finish());
    }

    pub const RouteSpec = struct {
        dst: addr.Prefix,
        index: ?u32 = null,
        gateway: ?addr.Address = null,
        table: u32 = RT_TABLE_MAIN,
        metric: ?u32 = null,
        throw: bool = false,
    };

    pub fn route(n: *Netlink, spec: RouteSpec, add: bool) Error!void {
        var b: Builder = .{};
        const v6 = spec.dst.addr.family == .v6;
        const masked = spec.dst.masked();
        b.begin(if (add) RTM_NEWROUTE else RTM_DELROUTE, if (add) NLM_F_CREATE | NLM_F_REPLACE else 0, n.seq);
        b.body(RtMsg{
            .family = if (v6) AF_INET6 else AF_INET,
            .dst_len = spec.dst.bits,
            .table = if (spec.table < 256) @intCast(spec.table) else RT_TABLE_UNSPEC,
            .protocol = RTPROT_STATIC,
            .scope = if (spec.throw or spec.gateway != null) RT_SCOPE_UNIVERSE else RT_SCOPE_LINK,
            .kind = if (spec.throw) RTN_THROW else RTN_UNICAST,
        });
        if (spec.dst.bits > 0) b.attr(RTA_DST, masked.addr.slice());
        if (spec.index) |i| b.attrU32(RTA_OIF, i);
        if (spec.gateway) |g| b.attr(RTA_GATEWAY, g.slice());
        if (spec.metric) |m| b.attrU32(RTA_PRIORITY, m);
        b.attrU32(RTA_TABLE, spec.table);
        return n.transact(b.finish());
    }

    pub const RuleSpec = struct {
        v6: bool,
        priority: u32,
        table: u32 = 0,
        action: u8 = FR_ACT_TO_TBL,
        goto_priority: u32 = 0,
        fwmark: ?u32 = null,
        fwmask: u32 = 0xffff_ffff,
        invert: bool = false,
        suppress_prefixlen: ?u32 = null,
        uid_range: ?[2]u32 = null,
        iif: ?[]const u8 = null,
        dport: ?u16 = null,
    };

    pub fn rule(n: *Netlink, spec: RuleSpec, add: bool) Error!void {
        var b: Builder = .{};
        b.begin(if (add) RTM_NEWRULE else RTM_DELRULE, if (add) NLM_F_CREATE | NLM_F_EXCL else 0, n.seq);
        b.body(FibRuleHdr{
            .family = if (spec.v6) AF_INET6 else AF_INET,
            .table = if (spec.action == FR_ACT_TO_TBL and spec.table < 256) @intCast(spec.table) else RT_TABLE_UNSPEC,
            .action = spec.action,
            .flags = if (spec.invert) FIB_RULE_INVERT else 0,
        });
        b.attrU32(FRA_PRIORITY, spec.priority);
        if (spec.action == FR_ACT_TO_TBL and spec.table != 0) b.attrU32(FRA_TABLE, spec.table);
        if (spec.action == FR_ACT_GOTO) b.attrU32(FRA_GOTO, spec.goto_priority);
        if (spec.fwmark) |m| {
            b.attrU32(FRA_FWMARK, m);
            b.attrU32(FRA_FWMASK, spec.fwmask);
        }
        if (spec.suppress_prefixlen) |s| b.attrU32(FRA_SUPPRESS_PREFIXLEN, s);
        if (spec.uid_range) |r| {
            const e = encodeUidRange(r);
            b.attr(FRA_UID_RANGE, &e);
        }
        if (spec.iif) |name| {
            var z: [17]u8 = @splat(0);
            const l = @min(name.len, 15);
            @memcpy(z[0..l], name[0..l]);
            b.attr(FRA_IIFNAME, z[0 .. l + 1]);
        }
        if (spec.dport) |p| {
            const e = encodeDport(p);
            b.attr(FRA_DPORT_RANGE, &e);
        }
        return n.transact(b.finish());
    }

    pub fn encodeDport(p: u16) [4]u8 {
        return .{ @truncate(p >> 8), @truncate(p), @truncate(p >> 8), @truncate(p) };
    }

    pub fn encodeUidRange(r: [2]u32) [8]u8 {
        var out: [8]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], r[0], .big);
        std.mem.writeInt(u32, out[4..8], r[1], .big);
        return out;
    }

    pub fn flushThrowRoutes(n: *Netlink, table: u32) void {
        if (table == 0 or (table >= 253 and table <= 255)) return;
        const families = [_]u8{ AF_INET, AF_INET6 };
        for (families) |family| {
            var rounds: u32 = 0;
            while (rounds < 64) : (rounds += 1) {
                var victims: [128]addr.Prefix = undefined;
                const count = n.dumpThrows(family, table, &victims) catch return;
                for (victims[0..count]) |p| n.route(.{ .dst = p, .table = table, .throw = true }, false) catch {};
                if (count < victims.len) break;
            }
        }
    }

    fn dump(n: *Netlink, kind: u16, body: []const u8, ctx: anytype, comptime onMessage: fn (@TypeOf(ctx), u16, []const u8) void) Error!void {
        const seq = n.seq;
        n.seq += 1;
        var b: Builder = .{};
        b.begin(kind, NLM_F_DUMP, seq);
        std.mem.writeInt(u16, b.buf[6..8], NLM_F_REQUEST | NLM_F_DUMP, builtin.cpu.arch.endian());
        @memcpy(b.buf[b.len..][0..body.len], body);
        b.len = std.mem.alignForward(usize, b.len + body.len, 4);
        const msg = b.finish();
        var dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        if (sys.linuxResult(linux.sendto(n.fd, msg.ptr, msg.len, 0, @ptrCast(&dst), @sizeOf(linux.sockaddr.nl))) < 0) return error.NetlinkError;
        var rbuf: [32768]u8 align(4) = undefined;
        while (true) {
            const got = sys.linuxResult(linux.recvfrom(n.fd, &rbuf, rbuf.len, 0, null, null));
            if (got < 0) {
                if (sys.toErrno(got) == .intr) continue;
                return error.NetlinkError;
            }
            var off: usize = 0;
            const total: usize = @intCast(got);
            while (off + @sizeOf(NlMsgHdr) <= total) {
                const h = std.mem.bytesToValue(NlMsgHdr, rbuf[off..][0..@sizeOf(NlMsgHdr)]);
                if (h.len < @sizeOf(NlMsgHdr) or off + h.len > total) return error.NetlinkError;
                if (h.seq == seq) {
                    if (h.kind == NLMSG_DONE) return;
                    if (h.kind == NLMSG_ERROR) return error.NetlinkError;
                    onMessage(ctx, h.kind, rbuf[off + @sizeOf(NlMsgHdr) .. off + h.len]);
                }
                off += std.mem.alignForward(usize, h.len, 4);
            }
        }
    }

    const ThrowCollector = struct {
        family: u8,
        table: u32,
        out: []addr.Prefix,
        count: usize = 0,

        fn onMessage(c: *ThrowCollector, kind: u16, body: []const u8) void {
            if (kind != RTM_NEWROUTE or body.len < @sizeOf(RtMsg)) return;
            const rt = std.mem.bytesToValue(RtMsg, body[0..@sizeOf(RtMsg)]);
            var info = routeAttrs(rt, body);
            if (info.table == c.table and rt.kind == RTN_THROW and rt.protocol == RTPROT_STATIC and c.count < c.out.len) {
                var p: addr.Prefix = .{ .bits = rt.dst_len, .addr = if (c.family == AF_INET6) addr.Address.v6(@splat(0)) else addr.Address.v4(@splat(0)) };
                if (info.dst) |d| {
                    if (d.len == 4 or d.len == 16) p.addr = addr.Address.fromSlice(d);
                }
                c.out[c.count] = p;
                c.count += 1;
            }
            _ = &info;
        }
    };

    fn dumpThrows(n: *Netlink, family: u8, table: u32, out: []addr.Prefix) Error!usize {
        var collector: ThrowCollector = .{ .family = family, .table = table, .out = out };
        const hdr: RtMsg = .{ .family = family, .dst_len = 0, .table = 0, .protocol = 0, .scope = 0, .kind = 0 };
        try n.dump(RTM_GETROUTE, std.mem.asBytes(&hdr), &collector, ThrowCollector.onMessage);
        return collector.count;
    }

    pub fn deleteRulesAt(n: *Netlink, v6: bool, priority: u32) void {
        var i: u32 = 0;
        while (i < 256) : (i += 1) {
            n.rule(.{ .v6 = v6, .priority = priority, .action = FR_ACT_UNSPEC }, false) catch return;
        }
    }
};

const RouteAttrs = struct {
    table: u32,
    dst: ?[]const u8 = null,
    gateway: ?[]const u8 = null,
    oif: u32 = 0,
    priority: u32 = 0,
    prefsrc: ?[]const u8 = null,
};

fn routeAttrs(rt: RtMsg, body: []const u8) RouteAttrs {
    var info: RouteAttrs = .{ .table = rt.table };
    var a: usize = std.mem.alignForward(usize, @sizeOf(RtMsg), 4);
    while (a + 4 <= body.len) {
        const alen = std.mem.readInt(u16, body[a..][0..2], builtin.cpu.arch.endian());
        const akind = std.mem.readInt(u16, body[a + 2 ..][0..2], builtin.cpu.arch.endian()) & 0x3fff;
        if (alen < 4 or a + alen > body.len) break;
        const data = body[a + 4 .. a + alen];
        switch (akind) {
            RTA_TABLE => if (data.len >= 4) {
                info.table = std.mem.readInt(u32, data[0..4], builtin.cpu.arch.endian());
            },
            RTA_DST => info.dst = data,
            RTA_GATEWAY => info.gateway = data,
            RTA_OIF => if (data.len >= 4) {
                info.oif = std.mem.readInt(u32, data[0..4], builtin.cpu.arch.endian());
            },
            RTA_PRIORITY => if (data.len >= 4) {
                info.priority = std.mem.readInt(u32, data[0..4], builtin.cpu.arch.endian());
            },
            RTA_PREFSRC => info.prefsrc = data,
            else => {},
        }
        a += std.mem.alignForward(usize, alen, 4);
    }
    return info;
}

const DefaultRoute = struct {
    exclude: u32,
    found: bool = false,
    oif: u32 = 0,
    priority: u32 = 0,
    gateway: [16]u8 = @splat(0),

    fn onMessage(d: *DefaultRoute, kind: u16, body: []const u8) void {
        if (kind != RTM_NEWROUTE or body.len < @sizeOf(RtMsg)) return;
        const rt = std.mem.bytesToValue(RtMsg, body[0..@sizeOf(RtMsg)]);
        if (rt.dst_len != 0 or rt.kind != RTN_UNICAST) return;
        const info = routeAttrs(rt, body);
        if (info.table != RT_TABLE_MAIN or info.oif == 0 or info.oif == d.exclude) return;
        if (d.found and info.priority >= d.priority) return;
        d.found = true;
        d.oif = info.oif;
        d.priority = info.priority;
        d.gateway = @splat(0);
        if (info.gateway) |g| @memcpy(d.gateway[0..@min(g.len, 16)], g[0..@min(g.len, 16)]);
    }
};

const AddressHash = struct {
    index: u32,
    hash: std.hash.Wyhash,

    fn onMessage(h: *AddressHash, kind: u16, body: []const u8) void {
        if (kind != RTM_NEWADDR or body.len < @sizeOf(IfAddrMsg)) return;
        const msg = std.mem.bytesToValue(IfAddrMsg, body[0..@sizeOf(IfAddrMsg)]);
        if (msg.index != h.index) return;
        var a: usize = std.mem.alignForward(usize, @sizeOf(IfAddrMsg), 4);
        while (a + 4 <= body.len) {
            const alen = std.mem.readInt(u16, body[a..][0..2], builtin.cpu.arch.endian());
            const akind = std.mem.readInt(u16, body[a + 2 ..][0..2], builtin.cpu.arch.endian());
            if (alen < 4 or a + alen > body.len) break;
            if (akind == IFA_LOCAL) h.hash.update(body[a + 4 .. a + alen]);
            a += std.mem.alignForward(usize, alen, 4);
        }
    }
};

pub const Identity = struct {
    index4: u32 = 0,
    index6: u32 = 0,
    hash: u64 = 0,
};

pub fn networkIdentity(tun_index: u32) Identity {
    var nl = Netlink.open() catch return .{};
    defer nl.close();
    var id: Identity = .{};
    var hasher = std.hash.Wyhash.init(0x7a65);
    const families = [_]u8{ AF_INET, AF_INET6 };
    for (families) |family| {
        var d: DefaultRoute = .{ .exclude = tun_index };
        const hdr: RtMsg = .{ .family = family, .dst_len = 0, .table = 0, .protocol = 0, .scope = 0, .kind = 0 };
        nl.dump(RTM_GETROUTE, std.mem.asBytes(&hdr), &d, DefaultRoute.onMessage) catch {};
        hasher.update(std.mem.asBytes(&d.oif));
        hasher.update(&d.gateway);
        if (family == AF_INET) id.index4 = d.oif else id.index6 = d.oif;
        if (family == AF_INET and d.oif != 0) {
            var ah: AddressHash = .{ .index = d.oif, .hash = std.hash.Wyhash.init(1) };
            const ahdr: IfAddrMsg = .{ .family = AF_INET, .prefixlen = 0, .index = 0 };
            nl.dump(RTM_GETADDR, std.mem.asBytes(&ahdr), &ah, AddressHash.onMessage) catch {};
            const v = ah.hash.final();
            hasher.update(std.mem.asBytes(&v));
        }
    }
    id.hash = hasher.final();
    return id;
}

pub fn openMonitorSocket() Error!i32 {
    const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, linux.NETLINK.ROUTE);
    const r = sys.linuxResult(rc);
    if (r < 0) return error.NetlinkError;
    const groups: u32 = 0x1 | 0x10 | 0x40 | 0x100 | 0x400;
    var sa: linux.sockaddr.nl = .{ .pid = 0, .groups = groups };
    if (sys.linuxResult(linux.bind(r, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl))) < 0) {
        sys.close(r);
        return error.PermissionDenied;
    }
    return r;
}

pub fn interfaceIndex(name: []const u8) Error!u32 {
    if (name.len >= 16) return error.InvalidArgument;
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    const fd = sys.linuxResult(rc);
    if (fd < 0) return error.SystemResources;
    defer sys.close(fd);
    var req: extern struct { name: [16]u8, index: i32, pad: [20]u8 } = .{ .name = @splat(0), .index = 0, .pad = @splat(0) };
    @memcpy(req.name[0..name.len], name);
    const r = sys.linuxResult(linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&req)));
    if (r < 0) return error.NotFound;
    return @intCast(req.index);
}

pub const rule_span = 10;

pub const AutoRoute = struct {
    table: u32 = 2022,
    rule_priority: u32 = 9000,
    fwmark: u32 = 0x2022,
    fwmask: u32 = 0xffff_ffff,
    ipv4: bool = true,
    ipv6: bool = true,
    include: []const addr.Prefix = &.{},
    exclude: []const addr.Prefix = &.{},
    include_extra: []const addr.Prefix = &.{},
    exclude_extra: []const addr.Prefix = &.{},
    strict: bool = false,
    dns_to_tunnel: bool = false,
    excluded_uids: []const [2]u32 = &.{},
    include_interfaces: []const []const u8 = &.{},
    exclude_interfaces: []const []const u8 = &.{},
};

pub const InterfaceSetup = struct {
    name: []const u8,
    mtu: u32,
    txqlen: ?u32 = null,
    addresses: []const addr.Prefix = &.{},
    auto_route: ?AutoRoute = null,
};

pub const Applied = struct {
    index: u32 = 0,
    routes_v4: bool = false,
    routes_v6: bool = false,
    auto: ?AutoRoute = null,
    exclude_count: usize = 0,
};

pub fn configure(setup: InterfaceSetup) Error!Applied {
    var applied = try configureLink(setup);
    if (setup.auto_route) |ar| try configureAutoRoute(&applied, ar);
    return applied;
}

fn relaxReversePathFilter(name: []const u8) void {
    var path: [64]u8 = undefined;
    const file = std.fmt.bufPrint(&path, "/proc/sys/net/ipv4/conf/{s}/rp_filter", .{name}) catch return;
    const fd = sys.linuxResult(std.os.linux.open(@ptrCast(path[0..file.len].ptr), .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0));
    if (fd < 0) return;
    defer sys.close(fd);
    var buf: [8]u8 = undefined;
    const n = sys.read(fd, &buf);
    if (n <= 0) return;
    const value = std.fmt.parseInt(u8, std.mem.trim(u8, buf[0..@intCast(n)], " \n\r\t"), 10) catch return;
    if (value != 1) return;
    _ = sys.linuxResult(std.os.linux.pwrite(fd, "2", 1, 0));
}

pub fn configureLink(setup: InterfaceSetup) Error!Applied {
    var nl = try Netlink.open();
    defer nl.close();
    const index = try interfaceIndex(setup.name);
    try nl.setLink(index, null, setup.mtu, setup.txqlen);
    if (!sys.is_android) relaxReversePathFilter(setup.name);
    for (setup.addresses) |p| {
        nl.address(index, p, true) catch |err| switch (err) {
            error.Exists => {},
            else => return err,
        };
    }
    try nl.setLink(index, true, null, null);
    return .{ .index = index };
}

pub fn configureAutoRoute(applied: *Applied, ar: AutoRoute) Error!void {
    var nl = try Netlink.open();
    defer nl.close();
    var kept = ar;
    kept.excluded_uids = &.{};
    kept.include_interfaces = &.{};
    kept.exclude_interfaces = &.{};
    applied.auto = kept;
    try installAutoRoute(&nl, applied.index, ar, applied);
}

fn addRule(nl: *Netlink, spec: Netlink.RuleSpec) Error!void {
    nl.rule(spec, true) catch |err| switch (err) {
        error.Exists => {},
        else => return err,
    };
}

fn clearRules(nl: *Netlink, base: u32) void {
    const families = [_]bool{ false, true };
    for (families) |v6| {
        var p = base;
        while (p < base + rule_span) : (p += 1) nl.deleteRulesAt(v6, p);
    }
}

fn installAutoRoute(nl: *Netlink, index: u32, ar: AutoRoute, applied: *Applied) Error!void {
    clearRules(nl, ar.rule_priority);
    nl.flushThrowRoutes(ar.table);
    const base = ar.rule_priority;
    const nop = base + rule_span - 1;
    const families = [_]bool{ false, true };
    for (families) |v6| {
        const enabled = if (v6) ar.ipv6 else ar.ipv4;
        if (!enabled and !ar.strict) {
            log.warn("route: {s} is not being tunnelled and strict_route is off, so it leaves by the physical interface", .{if (v6) "ipv6" else "ipv4"});
            continue;
        }
        var routed = enabled;
        if (enabled) {
            var any_include = false;
            const lists = [_][]const addr.Prefix{ ar.include, ar.include_extra };
            for (lists) |list| for (list) |p| {
                if (p.addr.isV6() != v6) continue;
                any_include = true;
                try nl.route(.{ .dst = p, .index = index, .table = ar.table }, true);
            };
            if (!any_include) {
                const default_prefix: addr.Prefix = .{ .addr = if (v6) addr.Address.v6(@splat(0)) else addr.Address.v4(@splat(0)), .bits = 0 };
                nl.route(.{ .dst = default_prefix, .index = index, .table = ar.table }, true) catch |err| switch (err) {
                    error.NotSupported, error.InvalidArgument => if (v6) {
                        routed = false;
                    } else return err,
                    else => return err,
                };
            }
            if (routed) {
                const excludes = [_][]const addr.Prefix{ ar.exclude, ar.exclude_extra };
                for (excludes) |list| for (list) |p| {
                    if (p.addr.isV6() != v6) continue;
                    try nl.route(.{ .dst = p, .table = ar.table, .throw = true }, true);
                };
            }
        }
        if (!routed and !ar.strict) continue;
        try addRule(nl, .{ .v6 = v6, .priority = nop, .action = FR_ACT_NOP });
        for (ar.excluded_uids) |r| {
            try addRule(nl, .{ .v6 = v6, .priority = base, .action = FR_ACT_GOTO, .goto_priority = nop, .uid_range = r });
        }
        for (ar.exclude_interfaces) |name| {
            try addRule(nl, .{ .v6 = v6, .priority = base, .action = FR_ACT_GOTO, .goto_priority = nop, .iif = name });
        }
        if (ar.include_interfaces.len > 0) {
            try addRule(nl, .{ .v6 = v6, .priority = base + 3, .action = FR_ACT_NOP });
            for (ar.include_interfaces) |name| {
                try addRule(nl, .{ .v6 = v6, .priority = base + 1, .action = FR_ACT_GOTO, .goto_priority = base + 3, .iif = name });
            }
            try addRule(nl, .{ .v6 = v6, .priority = base + 2, .action = FR_ACT_GOTO, .goto_priority = nop });
        }
        if (routed) {
            if (ar.dns_to_tunnel) {
                try addRule(nl, .{ .v6 = v6, .priority = base + 4, .table = RT_TABLE_MAIN, .suppress_prefixlen = 0, .dport = 53, .invert = true });
            } else {
                try addRule(nl, .{ .v6 = v6, .priority = base + 4, .table = RT_TABLE_MAIN, .suppress_prefixlen = 0 });
            }
            try addRule(nl, .{ .v6 = v6, .priority = base + 5, .table = ar.table, .fwmark = ar.fwmark, .fwmask = ar.fwmask, .invert = true });
        } else {
            try addRule(nl, .{ .v6 = v6, .priority = base + 5, .action = FR_ACT_GOTO, .goto_priority = nop, .fwmark = ar.fwmark, .fwmask = ar.fwmask });
            try addRule(nl, .{ .v6 = v6, .priority = base + 6, .action = FR_ACT_UNREACHABLE });
        }
        if (v6) applied.routes_v6 = true else applied.routes_v4 = true;
    }
}

pub fn teardown(applied: Applied) void {
    const ar = applied.auto orelse return;
    var nl = Netlink.open() catch return;
    defer nl.close();
    clearRules(&nl, ar.rule_priority);
    const families = [_]bool{ false, true };
    for (families) |v6| {
        if (v6 and !applied.routes_v6) continue;
        if (!v6 and !applied.routes_v4) continue;
        const excludes = [_][]const addr.Prefix{ ar.exclude, ar.exclude_extra };
        for (excludes) |list| for (list) |p| {
            if (p.addr.isV6() != v6) continue;
            nl.route(.{ .dst = p, .table = ar.table, .throw = true }, false) catch {};
        };
    }
}

test "netlink message layout" {
    var b: Builder = .{};
    b.begin(RTM_NEWADDR, NLM_F_CREATE, 7);
    b.body(IfAddrMsg{ .family = AF_INET, .prefixlen = 30, .index = 3 });
    b.attr(IFA_LOCAL, &[_]u8{ 172, 19, 0, 1 });
    const msg = b.finish();
    try std.testing.expectEqual(@as(usize, 16 + 8 + 8), msg.len);
    try std.testing.expectEqual(@as(u32, 32), std.mem.readInt(u32, msg[0..4], builtin.cpu.arch.endian()));
    try std.testing.expectEqual(@as(u16, 8), std.mem.readInt(u16, msg[24..26], builtin.cpu.arch.endian()));
    try std.testing.expectEqual(@sizeOf(RtMsg), 12);
    try std.testing.expectEqual(@sizeOf(FibRuleHdr), 12);
    try std.testing.expectEqual(@sizeOf(IfInfoMsg), 16);
}

fn kernelReadsBe16(b: [2]u8) u16 {
    return std.mem.readInt(u16, &b, .big);
}

fn kernelReadsBe32(b: [4]u8) u32 {
    return std.mem.readInt(u32, &b, .big);
}

test "rule port and uid ranges are encoded big endian, the way the kernel reads them" {
    const ports = [_]u16{ 53, 443, 853, 1, 65535 };
    for (ports) |p| {
        const e = Netlink.encodeDport(p);
        try std.testing.expectEqual(p, kernelReadsBe16(e[0..2].*));
        try std.testing.expectEqual(p, kernelReadsBe16(e[2..4].*));
    }
    try std.testing.expectEqual([4]u8{ 0x00, 0x35, 0x00, 0x35 }, Netlink.encodeDport(53));

    const port: u16 = 53;
    const as_written_before = std.mem.asBytes(&port);
    try std.testing.expectEqual(@as(u16, 13568), std.mem.readInt(u16, as_written_before, .big));
    const v: u16 = 0x1234;
    try std.testing.expectEqual(@as(u16, 0x3412), std.mem.readInt(u16, std.mem.asBytes(&v), .big));
    const vbytes = Netlink.encodeDport(v);
    try std.testing.expectEqual(v, kernelReadsBe16(.{ vbytes[0], vbytes[1] }));

    const ranges = [_][2]u32{ .{ 0, 0 }, .{ 1000, 1999 }, .{ 0x0100_0000, 0x7fff_ffff } };
    for (ranges) |r| {
        const e = Netlink.encodeUidRange(r);
        try std.testing.expectEqual(r[0], kernelReadsBe32(e[0..4].*));
        try std.testing.expectEqual(r[1], kernelReadsBe32(e[4..8].*));
    }
}
