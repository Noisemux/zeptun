const std = @import("std");
const builtin = @import("builtin");
const device = @import("device.zig");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");

const libc = std.c;
const os = builtin.target.os.tag;
const native_endian = builtin.target.cpu.arch.endian();

pub const supported = sys.is_bsd;

pub const OpenOptions = struct {
    name: []const u8,
    mtu: u32,
};

pub const max_units = 16;

pub fn ioc(direction: u32, group: u8, num: u8, len: usize) u32 {
    return direction | (@as(u32, @intCast(len & 0x1fff)) << 16) | (@as(u32, group) << 8) | num;
}

pub fn iow(group: u8, num: u8, len: usize) u32 {
    return ioc(0x80000000, group, num, len);
}

pub fn iowr(group: u8, num: u8, len: usize) u32 {
    return ioc(0xc0000000, group, num, len);
}

pub const ifreq_size: usize = if (os == .netbsd) 144 else 32;
pub const SIOCSIFFLAGS = iow('i', 16, ifreq_size);
pub const SIOCGIFFLAGS = iowr('i', 17, ifreq_size);
pub const SIOCSIFMTU = iow('i', if (os == .openbsd or os == .netbsd) 127 else 52, ifreq_size);
pub const SIOCIFDESTROY = iow('i', 121, ifreq_size);
pub const TUNSIFHEAD = iow('t', if (os == .netbsd) 66 else 96, @sizeOf(c_int));
pub const IFF_UP: u16 = 0x1;

pub const IfReq = extern struct {
    name: [16]u8 = @splat(0),
    ifru: [ifreq_size - 16]u8 = @splat(0),

    pub fn init(name: []const u8) !IfReq {
        if (name.len == 0 or name.len >= 16) return error.InvalidArgument;
        var req: IfReq = .{};
        @memcpy(req.name[0..name.len], name);
        return req;
    }
};

pub fn controlSocket(family: u16) !sys.fd_t {
    const fd = libc.socket(family, libc.SOCK.DGRAM, 0);
    if (fd < 0) return sys.errnoError(sys.mapErrno(libc.errno(fd)));
    _ = libc.fcntl(fd, libc.F.SETFD, @as(c_int, libc.FD_CLOEXEC));
    return fd;
}

pub fn interfaceIoctl(family: u16, request: u32, arg: usize) !void {
    const s = try controlSocket(family);
    defer sys.close(s);
    const r = sys.ioctl(s, request, arg);
    if (r < 0) return sys.errnoError(sys.toErrno(r));
}

pub fn interfaceIndex(name: []const u8) u32 {
    var buf: [17]u8 = @splat(0);
    if (name.len == 0 or name.len >= buf.len) return 0;
    @memcpy(buf[0..name.len], name);
    const idx = libc.if_nametoindex(@ptrCast(&buf));
    return if (idx > 0) @intCast(idx) else 0;
}

pub fn setMtu(name: []const u8, mtu: u32) !void {
    var req = try IfReq.init(name);
    std.mem.writeInt(i32, req.ifru[0..4], @intCast(mtu), native_endian);
    try interfaceIoctl(sys.AF_INET, SIOCSIFMTU, @intFromPtr(&req));
}

pub fn setUp(name: []const u8) !void {
    const s = try controlSocket(sys.AF_INET);
    defer sys.close(s);
    var req = try IfReq.init(name);
    const g = sys.ioctl(s, SIOCGIFFLAGS, @intFromPtr(&req));
    if (g < 0) return sys.errnoError(sys.toErrno(g));
    const flags = std.mem.readInt(u16, req.ifru[0..2], native_endian);
    if (flags & IFF_UP != 0) return;
    std.mem.writeInt(u16, req.ifru[0..2], flags | IFF_UP, native_endian);
    const r = sys.ioctl(s, SIOCSIFFLAGS, @intFromPtr(&req));
    if (r < 0) return sys.errnoError(sys.toErrno(r));
}

pub fn destroyInterface(name: []const u8) void {
    var req = IfReq.init(name) catch return;
    interfaceIoctl(sys.AF_INET, SIOCIFDESTROY, @intFromPtr(&req)) catch {};
}

pub fn unitFromName(prefix: []const u8, name: []const u8) ?u32 {
    if (name.len <= prefix.len or name.len > prefix.len + 5 or !std.mem.startsWith(u8, name, prefix)) return null;
    for (name[prefix.len..]) |ch| {
        if (!std.ascii.isDigit(ch)) return null;
    }
    return std.fmt.parseInt(u32, name[prefix.len..], 10) catch null;
}

const freebsd_c = struct {
    extern "c" fn fdevname_r(fd: c_int, buf: [*]u8, len: c_int) ?[*:0]u8;
};

const dragonfly_c = struct {
    extern "c" fn fdevname(fd: c_int) ?[*:0]const u8;
};

fn deviceName(fd: sys.fd_t, buf: *[64]u8) ?[]const u8 {
    const ptr: ?[*:0]const u8 = switch (os) {
        .freebsd => freebsd_c.fdevname_r(fd, buf, buf.len),
        .dragonfly => dragonfly_c.fdevname(fd),
        else => null,
    };
    return std.mem.span(ptr orelse return null);
}

pub const Tun = struct {
    fd: sys.fd_t = sys.invalid_fd,
    name: [16]u8 = @splat(0),
    index: u32 = 0,
    caps: device.Capabilities = .{ .af_prefix = true },
    created: bool = false,

    const open_flags: libc.O = .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true };

    pub fn open(options: OpenOptions) !Tun {
        if (!supported) return error.NotSupported;
        var t: Tun = .{};
        errdefer t.close();
        if (unitFromName("tun", options.name)) |unit| {
            try t.openUnit(unit);
        } else switch (os) {
            .freebsd, .dragonfly => try t.openClone(),
            else => try t.openFree(),
        }
        if (os != .openbsd) {
            var one: c_int = 1;
            const r = sys.ioctl(t.fd, TUNSIFHEAD, @intFromPtr(&one));
            if (r < 0) return sys.errnoError(sys.toErrno(r));
        }
        try sys.setNonblocking(t.fd);
        _ = libc.fcntl(t.fd, libc.F.SETFD, @as(c_int, libc.FD_CLOEXEC));
        const name = t.nameSlice();
        t.index = interfaceIndex(name);
        setMtu(name, options.mtu) catch |err| switch (err) {
            error.PermissionDenied => log.warn("tun: not permitted to set mtu {d} on {s}", .{ options.mtu, name }),
            else => return err,
        };
        setUp(name) catch |err| switch (err) {
            error.PermissionDenied => log.warn("tun: not permitted to bring {s} up", .{name}),
            else => return err,
        };
        t.caps = .{ .af_prefix = true, .mtu = options.mtu, .queues = 1 };
        if (options.name.len > 0 and !std.mem.eql(u8, options.name, name)) {
            log.info("tun: requested {s}, opened {s}", .{ options.name, name });
        }
        return t;
    }

    fn openUnit(t: *Tun, unit: u32) !void {
        var path_buf: [32]u8 = undefined;
        const path = std.mem.printSentinel(&path_buf, "/dev/tun{d}", .{unit}, 0) catch return error.InvalidArgument;
        var name: [16]u8 = @splat(0);
        const n = std.mem.print(&name, "tun{d}", .{unit}) catch return error.InvalidArgument;
        const existed = interfaceIndex(n) != 0;
        const fd = libc.open(path, open_flags);
        if (fd < 0) return sys.errnoError(sys.mapErrno(libc.errno(fd)));
        t.fd = fd;
        t.name = name;
        t.created = !existed;
    }

    fn openFree(t: *Tun) !void {
        var busy = false;
        var unit: u32 = 0;
        while (unit < max_units) : (unit += 1) {
            t.openUnit(unit) catch |err| switch (err) {
                error.DeviceBusy => {
                    busy = true;
                    continue;
                },
                error.DeviceNotFound, error.Unexpected => continue,
                else => return err,
            };
            return;
        }
        return if (busy) error.DeviceBusy else error.DeviceNotFound;
    }

    fn openClone(t: *Tun) !void {
        const fd = libc.open("/dev/tun", open_flags);
        if (fd < 0) return sys.errnoError(sys.mapErrno(libc.errno(fd)));
        t.fd = fd;
        t.created = true;
        var buf: [64]u8 = @splat(0);
        const dev = deviceName(fd, &buf) orelse return error.DeviceNotFound;
        if (dev.len == 0 or dev.len >= t.name.len) return error.DeviceNotFound;
        @memcpy(t.name[0..dev.len], dev);
    }

    pub fn nameSlice(t: *const Tun) []const u8 {
        return std.mem.sliceTo(&t.name, 0);
    }

    pub fn close(t: *Tun) void {
        sys.close(t.fd);
        t.fd = sys.invalid_fd;
        if (t.created and t.name[0] != 0) destroyInterface(t.nameSlice());
        t.created = false;
    }
};

test "bsd ioctl encodings" {
    try std.testing.expectEqual(@as(u32, 0x80047460), iow('t', 96, @sizeOf(c_int)));
    try std.testing.expectEqual(@as(u32, 0x80206934), iow('i', 52, 32));
    try std.testing.expectEqual(@as(u32, 0xc0206911), iowr('i', 17, 32));
    try std.testing.expectEqual(@as(u32, 0x8090697f), iow('i', 127, 144));
    try std.testing.expectEqual(@as(?u32, 7), unitFromName("tun", "tun7"));
    try std.testing.expectEqual(@as(?u32, null), unitFromName("tun", "tun"));
    try std.testing.expectEqual(@as(?u32, null), unitFromName("tun", "zeptun0"));
    try std.testing.expectEqual(@as(?u32, null), unitFromName("tun", "tun1_0"));
}
