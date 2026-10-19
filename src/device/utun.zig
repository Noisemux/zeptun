const std = @import("std");
const builtin = @import("builtin");
const device = @import("device.zig");
const bsd = @import("bsd.zig");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");

const libc = std.c;

pub const supported = sys.is_darwin and builtin.target.os.tag == .macos;

pub const OpenOptions = struct {
    name: []const u8,
    mtu: u32,
};

pub const PF_SYSTEM: c_uint = 32;
pub const AF_SYSTEM: u8 = 32;
pub const AF_SYS_CONTROL: u16 = 2;
pub const SYSPROTO_CONTROL: c_uint = 2;
pub const UTUN_OPT_IFNAME: u32 = 2;
pub const CTLIOCGINFO: u32 = 0xc0644e03;
pub const control_name = "com.apple.net.utun_control";

pub const CtlInfo = extern struct {
    ctl_id: u32 = 0,
    ctl_name: [96]u8 = @splat(0),
};

pub const SockaddrCtl = extern struct {
    sc_len: u8 = 32,
    sc_family: u8 = AF_SYSTEM,
    ss_sysaddr: u16 = AF_SYS_CONTROL,
    sc_id: u32 = 0,
    sc_unit: u32 = 0,
    sc_reserved: [5]u32 = @splat(0),
};

pub fn unitFromName(name: []const u8) u32 {
    const n = bsd.unitFromName("utun", name) orelse return 0;
    return n + 1;
}

pub const Utun = struct {
    fd: sys.fd_t = sys.invalid_fd,
    name: [16]u8 = @splat(0),
    index: u32 = 0,
    caps: device.Capabilities = .{ .af_prefix = true },

    pub fn open(options: OpenOptions) !Utun {
        if (!supported) return error.NotSupported;
        const fd = libc.socket(PF_SYSTEM, libc.SOCK.DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) return sys.errnoError(sys.mapErrno(libc.errno(fd)));
        var u: Utun = .{ .fd = fd };
        errdefer u.close();
        var info: CtlInfo = .{};
        @memcpy(info.ctl_name[0..control_name.len], control_name);
        const ir = sys.ioctl(fd, CTLIOCGINFO, @intFromPtr(&info));
        if (ir < 0) return sys.errnoError(sys.toErrno(ir));
        const sc: SockaddrCtl = .{ .sc_id = info.ctl_id, .sc_unit = unitFromName(options.name) };
        const cr = sys.libcResult(libc.connect(fd, @ptrCast(&sc), @sizeOf(SockaddrCtl)));
        if (cr < 0) return sys.errnoError(sys.toErrno(cr));
        var len: libc.socklen_t = u.name.len;
        const gr = sys.libcResult(libc.getsockopt(fd, @intCast(SYSPROTO_CONTROL), UTUN_OPT_IFNAME, &u.name, &len));
        if (gr < 0) return sys.errnoError(sys.toErrno(gr));
        u.name[u.name.len - 1] = 0;
        try sys.setNonblocking(fd);
        _ = libc.fcntl(fd, libc.F.SETFD, @as(c_int, libc.FD_CLOEXEC));
        const name = u.nameSlice();
        u.index = bsd.interfaceIndex(name);
        bsd.setMtu(name, options.mtu) catch |err| switch (err) {
            error.PermissionDenied => log.warn("utun: not permitted to set mtu {d} on {s}", .{ options.mtu, name }),
            else => return err,
        };
        u.caps = .{ .af_prefix = true, .mtu = options.mtu, .queues = 1 };
        if (options.name.len > 0 and !std.mem.eql(u8, options.name, name)) {
            log.info("utun: requested {s}, kernel assigned {s}", .{ options.name, name });
        }
        return u;
    }

    pub fn nameSlice(u: *const Utun) []const u8 {
        return std.mem.sliceTo(&u.name, 0);
    }

    pub fn close(u: *Utun) void {
        sys.close(u.fd);
        u.fd = sys.invalid_fd;
    }
};

test "utun control layouts" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(SockaddrCtl));
    try std.testing.expectEqual(@as(usize, 100), @sizeOf(CtlInfo));
    try std.testing.expectEqual(bsd.iowr('N', 3, @sizeOf(CtlInfo)), CTLIOCGINFO);
    try std.testing.expectEqual(@as(u32, 0), unitFromName("zeptun0"));
    try std.testing.expectEqual(@as(u32, 0), unitFromName("utun"));
    try std.testing.expectEqual(@as(u32, 5), unitFromName("utun4"));
}
