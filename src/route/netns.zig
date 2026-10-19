const std = @import("std");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");

pub const supported = sys.is_linux;

const clone_newnet: u32 = 0x40000000;
const dirs = [_][]const u8{ "/run/netns/", "/var/run/netns/" };

pub const Scope = struct {
    saved: sys.fd_t = sys.invalid_fd,

    pub fn leave(s: *Scope) void {
        if (comptime !supported) return;
        if (s.saved == sys.invalid_fd) return;
        const r = sys.linuxResult(std.os.linux.setns(s.saved, clone_newnet));
        if (r < 0) log.warn("netns: cannot return to the original namespace", .{});
        sys.close(s.saved);
        s.saved = sys.invalid_fd;
    }
};

pub const Handle = struct {
    fd: sys.fd_t = sys.invalid_fd,

    pub inline fn active(h: *const Handle) bool {
        return supported and h.fd != sys.invalid_fd;
    }

    pub fn enter(h: *const Handle) Scope {
        if (comptime !supported) return .{};
        if (!h.active()) return .{};
        const saved = openPath("/proc/self/ns/net") catch return .{};
        if (sys.linuxResult(std.os.linux.setns(h.fd, clone_newnet)) < 0) {
            sys.close(saved);
            return .{};
        }
        return .{ .saved = saved };
    }

    pub fn close(h: *Handle) void {
        if (comptime !supported) return;
        if (h.fd == sys.invalid_fd) return;
        sys.close(h.fd);
        h.fd = sys.invalid_fd;
    }
};

fn openPath(path: [:0]const u8) !sys.fd_t {
    const r = sys.linuxResult(std.os.linux.open(path.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0));
    if (r < 0) return sys.errnoError(sys.toErrno(r));
    return r;
}

pub fn open(name: []const u8) !Handle {
    if (comptime !supported) return error.NotSupported;
    if (name.len == 0) return .{};
    var buf: [512]u8 = undefined;
    if (std.mem.findScalar(u8, name, '/') != null) {
        const path = std.mem.printSentinel(&buf, "{s}", .{name}, 0) catch return error.InvalidArgument;
        return .{ .fd = try openPath(path) };
    }
    for (dirs) |dir| {
        const path = std.mem.printSentinel(&buf, "{s}{s}", .{ dir, name }, 0) catch continue;
        const fd = openPath(path) catch continue;
        return .{ .fd = fd };
    }
    return error.NotFound;
}

test "netns paths need a name" {
    if (comptime !supported) return;
    const h = try open("");
    try std.testing.expect(!h.active());
    try std.testing.expectError(error.NotFound, open("zeptun-missing-namespace"));
}
