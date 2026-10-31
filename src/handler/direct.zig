const std = @import("std");
const builtin = @import("builtin");
const addr = @import("../addr.zig");
const sys = @import("../io/sys.zig");
const config = @import("../config.zig");

pub const Protect = struct {
    fwmark: u32 = 0,
    bind_interface: config.Name = .{},
    bind_index: u32 = 0,
    index_ref: ?*std.atomic.Value(u32) = null,
    bind4: ?addr.Address = null,
    bind6: ?addr.Address = null,
    android_fn: ?*const fn (ctx: ?*anyopaque, fd: c_int) callconv(.c) bool = null,
    android_ctx: ?*anyopaque = null,

    pub fn resolve(p: *Protect) void {
        if (p.bind_interface.isEmpty()) return;
        if (sys.is_linux) {
            p.bind_index = @import("../route/linux.zig").interfaceIndex(p.bind_interface.slice()) catch 0;
        } else if (sys.is_darwin or sys.is_bsd) {
            var name: [64]u8 = @splat(0);
            const n = @min(p.bind_interface.len, name.len - 1);
            @memcpy(name[0..n], p.bind_interface.slice()[0..n]);
            const idx = std.c.if_nametoindex(@ptrCast(&name));
            p.bind_index = if (idx > 0) @intCast(idx) else 0;
        }
    }

    pub fn currentIndex(p: *const Protect) u32 {
        if (p.index_ref) |r| {
            const v = r.load(.acquire);
            if (v != 0) return v;
        }
        return p.bind_index;
    }

    pub fn apply(p: *const Protect, fd: sys.fd_t, family: addr.Family) !void {
        if (p.android_fn) |f| {
            if (!f(p.android_ctx, @intCast(fd))) return error.PermissionDenied;
        }
        if (sys.is_linux) {
            const linux = std.os.linux;
            if (p.fwmark != 0) {
                const r = sys.setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.MARK, @bitCast(p.fwmark));
                if (r < 0 and sys.toErrno(r) != .perm) return sys.errnoError(sys.toErrno(r));
            }
            if (!p.bind_interface.isEmpty()) {
                _ = sys.setsockopt(fd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, p.bind_interface.slice());
            }
        } else if (sys.is_darwin) {
            const index = p.currentIndex();
            if (index != 0) {
                if (family == .v4) {
                    _ = sys.setsockoptInt(fd, 0, 25, @intCast(index));
                } else {
                    _ = sys.setsockoptInt(fd, 41, 125, @intCast(index));
                }
            }
        } else if (sys.is_windows) {
            const index = p.currentIndex();
            if (index != 0) {
                if (family == .v4) {
                    const be: u32 = std.mem.nativeToBig(u32, index);
                    _ = sys.setsockopt(fd, 0, 31, std.mem.asBytes(&be));
                } else {
                    _ = sys.setsockoptInt(fd, 41, 31, @intCast(index));
                }
            }
        }
        const bind_addr = if (family == .v4) p.bind4 else p.bind6;
        if (bind_addr) |a| {
            var sa = sys.Sockaddr.fromEndpoint(.{ .addr = a, .port = 0 });
            const r = sys.bind(fd, &sa);
            if (r < 0) return sys.errnoError(sys.toErrno(r));
        }
    }
};

pub fn tuneTcp(fd: sys.fd_t) void {
    if (sys.is_linux) {
        const linux = std.os.linux;
        _ = sys.setsockoptInt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, 1);
    } else {
        _ = sys.setsockoptInt(fd, 6, 1, 1);
    }
}

pub fn setDscp(fd: sys.fd_t, family: addr.Family, tos: u8) void {
    const dscp: c_int = tos & 0xfc;
    if (dscp == 0 or sys.is_windows) return;
    if (sys.is_linux) {
        const linux = std.os.linux;
        if (family == .v4) {
            _ = sys.setsockoptInt(fd, linux.IPPROTO.IP, linux.IP.TOS, dscp);
        } else {
            _ = sys.setsockoptInt(fd, linux.IPPROTO.IPV6, linux.IPV6.TCLASS, dscp);
        }
        return;
    }
    if (family == .v4) {
        _ = sys.setsockoptInt(fd, 0, 3, dscp);
    } else {
        _ = sys.setsockoptInt(fd, 41, 36, dscp);
    }
}

pub fn quickAck(fd: sys.fd_t) void {
    if (!sys.is_linux) return;
    const linux = std.os.linux;
    _ = sys.setsockoptInt(fd, linux.IPPROTO.TCP, linux.TCP.QUICKACK, 1);
}

pub fn tcpRttUs(fd: sys.fd_t) ?u32 {
    if (comptime !sys.is_linux) return null;
    const linux = std.os.linux;
    var info: [104]u8 = undefined;
    var len: linux.socklen_t = info.len;
    const r = sys.linuxResult(linux.getsockopt(@intCast(fd), linux.IPPROTO.TCP, linux.TCP.INFO, &info, &len));
    if (r < 0 or len < 76) return null;
    return std.mem.readInt(u32, info[68..72], builtin.target.cpu.arch.endian());
}

pub fn fastOpen(fd: sys.fd_t) void {
    if (!sys.is_linux) return;
    const linux = std.os.linux;
    _ = sys.setsockoptInt(fd, linux.IPPROTO.TCP, linux.TCP.FASTOPEN_CONNECT, 1);
}

pub fn alive(fd: sys.fd_t) bool {
    var probe: [1]u8 = undefined;
    const peek: u32 = if (sys.is_linux) std.os.linux.MSG.PEEK else if (sys.is_windows) 2 else 2;
    const r = sys.recv(fd, &probe, peek | sys.msg_dontwait);
    if (r >= 0) return false;
    const e = sys.toErrno(r);
    return e == .again;
}

pub fn recvErrors(fd: sys.fd_t, family: addr.Family) bool {
    if (!sys.is_linux) return false;
    const linux = std.os.linux;
    if (family == .v6) return sys.setsockoptInt(fd, linux.IPPROTO.IPV6, linux.IPV6.RECVERR, 1) == 0;
    return sys.setsockoptInt(fd, linux.IPPROTO.IP, linux.IP.RECVERR, 1) == 0;
}

pub fn tuneUdp(fd: sys.fd_t) bool {
    if (sys.is_linux) {
        const linux = std.os.linux;
        return sys.setsockoptInt(fd, linux.IPPROTO.UDP, linux.UDP.GRO, 1) == 0;
    }
    return false;
}

pub const udp_segment_cmsg_len = if (sys.is_linux) std.mem.alignForward(usize, @sizeOf(std.os.linux.cmsghdr) + 2, @sizeOf(usize)) else 0;

pub fn writeUdpSegmentCmsg(buf: []u8, gso_size: u16) usize {
    const linux = std.os.linux;
    const hdr_len = @sizeOf(linux.cmsghdr);
    const h: linux.cmsghdr = .{ .len = hdr_len + 2, .level = linux.IPPROTO.UDP, .type = linux.UDP.SEGMENT };
    @memcpy(buf[0..hdr_len], std.mem.asBytes(&h));
    std.mem.writeInt(u16, buf[hdr_len..][0..2], gso_size, builtin.target.cpu.arch.endian());
    const total = std.mem.alignForward(usize, hdr_len + 2, @sizeOf(usize));
    @memset(buf[hdr_len + 2 .. total], 0);
    return total;
}

pub fn readUdpGro(control: []const u8) u16 {
    if (!sys.is_linux) return 0;
    const linux = std.os.linux;
    const hdr_len = @sizeOf(linux.cmsghdr);
    var off: usize = 0;
    while (off + hdr_len <= control.len) {
        const h = std.mem.bytesToValue(linux.cmsghdr, control[off..][0..hdr_len]);
        if (h.len < hdr_len or off + h.len > control.len) break;
        if (h.level == linux.IPPROTO.UDP and h.type == linux.UDP.GRO and h.len >= hdr_len + 4) {
            const v = std.mem.readInt(i32, control[off + hdr_len ..][0..4], builtin.target.cpu.arch.endian());
            return @intCast(std.math.clamp(v, 0, 0xffff));
        }
        off += std.mem.alignForward(usize, h.len, @sizeOf(usize));
    }
    return 0;
}

test "cmsg roundtrip" {
    if (!sys.is_linux) return error.SkipZigTest;
    var buf: [64]u8 = undefined;
    const n = writeUdpSegmentCmsg(&buf, 1400);
    try std.testing.expect(n >= 18);
    const linux = std.os.linux;
    const hdr_len = @sizeOf(linux.cmsghdr);
    var gro: [64]u8 = @splat(0);
    const h: linux.cmsghdr = .{ .len = hdr_len + 4, .level = linux.IPPROTO.UDP, .type = linux.UDP.GRO };
    @memcpy(gro[0..hdr_len], std.mem.asBytes(&h));
    std.mem.writeInt(i32, gro[hdr_len..][0..4], 1200, builtin.target.cpu.arch.endian());
    try std.testing.expectEqual(@as(u16, 1200), readUdpGro(&gro));
}
