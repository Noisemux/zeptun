const std = @import("std");
const builtin = @import("builtin");
const addr = @import("../addr.zig");

pub const os = builtin.os.tag;
pub const is_linux = os == .linux;
pub const is_windows = os == .windows;
pub const is_darwin = switch (os) {
    .macos, .ios, .tvos, .visionos, .watchos, .maccatalyst => true,
    else => false,
};
pub const is_bsd = switch (os) {
    .freebsd, .openbsd, .netbsd, .dragonfly => true,
    else => false,
};
pub const is_android = builtin.abi.isAndroid();
pub const is_posix_libc = is_darwin or is_bsd;

const linux = std.os.linux;
const c = std.c;

pub const fd_t = if (is_windows) usize else i32;
pub const invalid_fd: fd_t = if (is_windows) std.math.maxInt(usize) else -1;

pub const Errno = enum(u16) {
    success = 0,
    again,
    intr,
    inval,
    badf,
    nomem,
    nobufs,
    connrefused,
    connreset,
    connaborted,
    netunreach,
    hostunreach,
    netdown,
    timedout,
    pipe,
    notconn,
    inprogress,
    already,
    isconn,
    addrinuse,
    addrnotavail,
    acces,
    perm,
    noent,
    msgsize,
    afnosupport,
    opnotsupp,
    canceled,
    nodev,
    nosys,
    fault,
    exist,
    busy,
    io,
    proto,
    notsock,
    mfile,
    other,

    pub inline fn result(e: Errno) i32 {
        return -@as(i32, @intFromEnum(e));
    }
};

pub inline fn toErrno(r: i32) Errno {
    if (r >= 0) return .success;
    return std.enums.fromInt(Errno, @as(u16, @intCast(-r))) orelse .other;
}

pub fn mapErrno(e: anytype) Errno {
    return switch (e) {
        .SUCCESS => .success,
        .AGAIN => .again,
        .INTR => .intr,
        .INVAL => .inval,
        .BADF => .badf,
        .NOMEM => .nomem,
        .NOBUFS => .nobufs,
        .CONNREFUSED => .connrefused,
        .CONNRESET => .connreset,
        .CONNABORTED => .connaborted,
        .NETUNREACH => .netunreach,
        .HOSTUNREACH => .hostunreach,
        .NETDOWN => .netdown,
        .TIMEDOUT => .timedout,
        .PIPE => .pipe,
        .NOTCONN => .notconn,
        .INPROGRESS => .inprogress,
        .ALREADY => .already,
        .ISCONN => .isconn,
        .ADDRINUSE => .addrinuse,
        .ADDRNOTAVAIL => .addrnotavail,
        .ACCES => .acces,
        .PERM => .perm,
        .NOENT => .noent,
        .MSGSIZE => .msgsize,
        .AFNOSUPPORT => .afnosupport,
        .OPNOTSUPP => .opnotsupp,
        .CANCELED => .canceled,
        .NODEV => .nodev,
        .NOSYS => .nosys,
        .FAULT => .fault,
        .EXIST => .exist,
        .BUSY => .busy,
        .IO => .io,
        .PROTO => .proto,
        .NOTSOCK => .notsock,
        .MFILE => .mfile,
        else => .other,
    };
}

pub inline fn linuxResult(rc: usize) i32 {
    const e = linux.errno(rc);
    if (e != .SUCCESS) return mapErrno(e).result();
    return @intCast(@min(rc, std.math.maxInt(i32)));
}

pub inline fn libcResult(rc: anytype) i32 {
    if (rc == -1) return mapErrno(c.errno(rc)).result();
    return @intCast(@min(rc, std.math.maxInt(i32)));
}

pub const iovec = extern struct {
    base: [*]u8,
    len: usize,
};

pub const iovec_const = extern struct {
    base: [*]const u8,
    len: usize,
};

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = switch (os) {
    .linux => 10,
    .windows => 23,
    .macos, .ios, .tvos, .visionos, .watchos, .maccatalyst => 30,
    .freebsd, .dragonfly => 28,
    .openbsd, .netbsd => 24,
    else => 10,
};

pub const sa_has_len = is_darwin or is_bsd;

pub const Sockaddr = extern struct {
    storage: [128]u8 align(8) = @splat(0),
    len: u32 = 0,

    pub fn fromEndpoint(ep: addr.Endpoint) Sockaddr {
        var sa: Sockaddr = .{};
        const fam: u16 = if (ep.addr.family == .v4) AF_INET else AF_INET6;
        const size: u32 = if (ep.addr.family == .v4) 16 else 28;
        if (sa_has_len) {
            sa.storage[0] = @intCast(size);
            sa.storage[1] = @intCast(fam);
        } else {
            std.mem.writeInt(u16, sa.storage[0..2], fam, builtin.cpu.arch.endian());
        }
        std.mem.writeInt(u16, sa.storage[2..4], ep.port, .big);
        if (ep.addr.family == .v4) {
            @memcpy(sa.storage[4..8], ep.addr.bytes[0..4]);
        } else {
            @memcpy(sa.storage[8..24], ep.addr.bytes[0..16]);
        }
        sa.len = size;
        return sa;
    }

    pub fn family(sa: *const Sockaddr) u16 {
        if (sa_has_len) return sa.storage[1];
        return std.mem.readInt(u16, sa.storage[0..2], builtin.cpu.arch.endian());
    }

    pub fn toEndpoint(sa: *const Sockaddr) ?addr.Endpoint {
        const fam = sa.family();
        const port = std.mem.readInt(u16, sa.storage[2..4], .big);
        if (fam == AF_INET) {
            return .{ .addr = addr.Address.v4(sa.storage[4..8].*), .port = port };
        }
        if (fam == AF_INET6) {
            const b = sa.storage[8..24].*;
            if (std.mem.eql(u8, b[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                return .{ .addr = addr.Address.v4(b[12..16].*), .port = port };
            }
            return .{ .addr = addr.Address.v6(b), .port = port };
        }
        return null;
    }

    pub inline fn ptr(sa: *const Sockaddr) *const anyopaque {
        return @ptrCast(&sa.storage);
    }

    pub inline fn mutPtr(sa: *Sockaddr) *anyopaque {
        return @ptrCast(&sa.storage);
    }
};

pub const Protocol = enum { tcp, udp, icmp4, icmp6, icmp4_raw, icmp6_raw };

pub const SocketOptions = struct {
    nonblocking: bool = true,
};

pub fn monotonicNs() u64 {
    if (is_windows) return windows.monotonicNs();
    var ts: std.posix.timespec = undefined;
    if (is_linux) {
        _ = linux.clock_gettime(.MONOTONIC, &ts);
    } else {
        _ = c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub inline fn monotonicMs() u64 {
    return monotonicNs() / std.time.ns_per_ms;
}

pub fn cpuCount() u32 {
    const n = std.Thread.getCpuCount() catch 1;
    return @intCast(@max(1, @min(n, 1024)));
}

pub fn randomBytes(buf: []u8) bool {
    if (buf.len == 0) return true;
    if (is_linux) {
        var i: usize = 0;
        while (i < buf.len) {
            const r = linux.getrandom(buf[i..].ptr, buf.len - i, 0);
            switch (linux.errno(r)) {
                .SUCCESS => i += r,
                .INTR => continue,
                else => return false,
            }
        }
        return true;
    }
    if (is_darwin or is_bsd) {
        c.arc4random_buf(buf.ptr, buf.len);
        return true;
    }
    if (is_windows) return windows.randomBytes(buf);
    return false;
}

pub fn pageSize() usize {
    return std.heap.pageSize();
}

pub fn keepPagesSmall(mem: []u8) void {
    if (!is_linux) return;
    const page = pageSize();
    const start = std.mem.alignForward(usize, @intFromPtr(mem.ptr), page);
    const end = std.mem.alignBackward(usize, @intFromPtr(mem.ptr) + mem.len, page);
    if (end <= start) return;
    _ = linux.madvise(@ptrFromInt(start), end - start, linux.MADV.NOHUGEPAGE);
}

pub fn releasePages(mem: []u8) bool {
    const page = pageSize();
    const start = std.mem.alignForward(usize, @intFromPtr(mem.ptr), page);
    const end = std.mem.alignBackward(usize, @intFromPtr(mem.ptr) + mem.len, page);
    if (end <= start) return false;
    const len = end - start;
    if (is_linux) return linuxResult(linux.madvise(@ptrFromInt(start), len, linux.MADV.DONTNEED)) == 0;
    if (is_windows) return windows.discardPages(@ptrFromInt(start), len);
    if (is_posix_libc) return c.madvise(@ptrFromInt(start), len, c.MADV.FREE) == 0;
    return false;
}

fn accessible(path: [:0]const u8, mode: u32) bool {
    if (is_linux) return linuxResult(linux.faccessat(linux.AT.FDCWD, path.ptr, mode, 0)) == 0;
    if (is_windows) return false;
    return c.access(path.ptr, @intCast(mode)) == 0;
}

pub fn fileExists(path: [:0]const u8) bool {
    return accessible(path, 0);
}

pub fn fileExecutable(path: [:0]const u8) bool {
    return accessible(path, 1);
}

pub fn pinCurrentThread(cpu: u32) bool {
    if (is_linux) {
        var set: linux.cpu_set_t = @splat(0);
        const bits = @bitSizeOf(usize);
        if (cpu >= set.len * bits) return false;
        set[cpu / bits] |= @as(usize, 1) << @intCast(cpu % bits);
        linux.sched_setaffinity(0, &set) catch return false;
        return true;
    }
    return false;
}

pub fn sleepMs(ms: u64) void {
    if (is_windows) return windows.sleepMs(ms);
    const ts: std.posix.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    if (is_linux) {
        _ = linux.nanosleep(&ts, null);
    } else {
        _ = c.nanosleep(&ts, null);
    }
}

pub fn close(fd: fd_t) void {
    if (fd == invalid_fd) return;
    if (is_linux) {
        _ = linux.close(fd);
    } else if (is_windows) {
        windows.closeSocket(fd);
    } else {
        _ = c.close(fd);
    }
}

pub fn read(fd: fd_t, buf: []u8) i32 {
    if (is_linux) return linuxResult(linux.read(fd, buf.ptr, buf.len));
    if (is_windows) return windows.recv(fd, buf, 0);
    return libcResult(c.read(fd, buf.ptr, buf.len));
}

pub fn write(fd: fd_t, buf: []const u8) i32 {
    if (is_linux) return linuxResult(linux.write(fd, buf.ptr, buf.len));
    if (is_windows) return windows.send(fd, buf, 0);
    return libcResult(c.write(fd, buf.ptr, buf.len));
}

pub fn readv(fd: fd_t, iov: []const iovec) i32 {
    if (is_linux) return linuxResult(linux.readv(fd, @ptrCast(iov.ptr), iov.len));
    return libcResult(c.readv(fd, @ptrCast(iov.ptr), @intCast(iov.len)));
}

pub fn writev(fd: fd_t, iov: []const iovec_const) i32 {
    if (is_windows) return windows.writev(fd, iov);
    if (is_linux) return linuxResult(linux.writev(fd, @ptrCast(iov.ptr), iov.len));
    return libcResult(c.writev(fd, @ptrCast(iov.ptr), @intCast(iov.len)));
}

pub fn sendvNow(fd: fd_t, iov: []const iovec_const) i32 {
    if (is_linux) {
        const msg: linux.msghdr_const = .{ .name = null, .namelen = 0, .iov = @ptrCast(iov.ptr), .iovlen = iov.len, .control = null, .controllen = 0, .flags = 0 };
        return linuxResult(linux.sendmsg(fd, &msg, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL));
    }
    return writev(fd, iov);
}

pub fn socket(family: addr.Family, proto: Protocol) !fd_t {
    if (is_windows) return windows.socket(family, proto);
    const af: u32 = if (family == .v4) AF_INET else AF_INET6;
    if (is_linux) {
        const kind: u32 = switch (proto) {
            .tcp => linux.SOCK.STREAM,
            .udp, .icmp4, .icmp6 => linux.SOCK.DGRAM,
            .icmp4_raw, .icmp6_raw => linux.SOCK.RAW,
        };
        const p: u32 = switch (proto) {
            .tcp => linux.IPPROTO.TCP,
            .udp => linux.IPPROTO.UDP,
            .icmp4, .icmp4_raw => linux.IPPROTO.ICMP,
            .icmp6, .icmp6_raw => linux.IPPROTO.ICMPV6,
        };
        const rc = linux.socket(af, kind | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, p);
        const r = linuxResult(rc);
        if (r < 0) return errnoError(toErrno(r));
        return r;
    }
    const kind: c_uint = switch (proto) {
        .tcp => c.SOCK.STREAM,
        .icmp4_raw, .icmp6_raw => c.SOCK.RAW,
        else => c.SOCK.DGRAM,
    };
    const p: c_uint = switch (proto) {
        .tcp => 6,
        .udp => 17,
        .icmp4, .icmp4_raw => 1,
        .icmp6, .icmp6_raw => 58,
    };
    const fd = c.socket(af, kind, p);
    if (fd < 0) return errnoError(mapErrno(c.errno(fd)));
    errdefer _ = c.close(fd);
    try setNonblocking(fd);
    _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
    if (is_darwin) {
        const one: c_int = 1;
        _ = c.setsockopt(fd, c.SOL.SOCKET, 0x1022, &one, @sizeOf(c_int));
    }
    return fd;
}

pub fn setNonblocking(fd: fd_t) !void {
    if (is_windows) return windows.setNonblocking(fd);
    if (is_linux) {
        const flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(flags) != .SUCCESS) return error.Unexpected;
        const nb: usize = 1 << @bitOffsetOf(linux.O, "NONBLOCK");
        if (linuxResult(linux.fcntl(fd, linux.F.SETFL, flags | nb)) < 0) return error.Unexpected;
        return;
    }
    const flags = c.fcntl(fd, c.F.GETFL);
    if (flags < 0) return error.Unexpected;
    const nb: c_int = @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })));
    if (c.fcntl(fd, c.F.SETFL, flags | nb) < 0) return error.Unexpected;
}

pub fn setsockopt(fd: fd_t, level: i32, opt: u32, value: []const u8) i32 {
    if (is_linux) return linuxResult(linux.setsockopt(fd, level, opt, value.ptr, @intCast(value.len)));
    if (is_windows) return windows.setsockopt(fd, level, opt, value);
    return libcResult(c.setsockopt(fd, level, opt, value.ptr, @intCast(value.len)));
}

pub fn setsockoptInt(fd: fd_t, level: i32, opt: u32, value: c_int) i32 {
    return setsockopt(fd, level, opt, std.mem.asBytes(&value));
}

pub fn getsockoptInt(fd: fd_t, level: i32, opt: u32) i32 {
    var v: c_int = 0;
    if (is_linux) {
        var len: linux.socklen_t = @sizeOf(c_int);
        const r = linuxResult(linux.getsockopt(fd, level, opt, @ptrCast(&v), &len));
        if (r < 0) return r;
        return v;
    }
    if (is_windows) return windows.getsockoptInt(fd, level, opt);
    var len: c.socklen_t = @sizeOf(c_int);
    const r = libcResult(c.getsockopt(fd, level, opt, @ptrCast(&v), &len));
    if (r < 0) return r;
    return v;
}

pub fn socketError(fd: fd_t) Errno {
    const sol: i32 = if (is_linux) linux.SOL.SOCKET else if (is_windows) 0xffff else c.SOL.SOCKET;
    const so_error: u32 = if (is_linux) linux.SO.ERROR else if (is_windows) 0x1007 else 0x1007;
    const r = getsockoptInt(fd, sol, so_error);
    if (r < 0) return toErrno(r);
    if (r == 0) return .success;
    if (is_windows) return windows.mapWsaError(r);
    if (is_linux) return mapErrno(@as(linux.E, @enumFromInt(r)));
    return mapErrno(@as(c.E, @enumFromInt(r)));
}

pub fn connect(fd: fd_t, sa: *const Sockaddr) i32 {
    if (is_linux) return linuxResult(linux.connect(fd, sa.ptr(), sa.len));
    if (is_windows) return windows.connect(fd, sa);
    return libcResult(c.connect(fd, @ptrCast(@alignCast(sa.ptr())), sa.len));
}

pub fn bind(fd: fd_t, sa: *const Sockaddr) i32 {
    if (is_linux) return linuxResult(linux.bind(fd, @ptrCast(@alignCast(sa.ptr())), sa.len));
    if (is_windows) return windows.bind(fd, sa);
    return libcResult(c.bind(fd, @ptrCast(@alignCast(sa.ptr())), sa.len));
}

pub fn listen(fd: fd_t, backlog: u32) i32 {
    if (is_linux) return linuxResult(linux.listen(fd, backlog));
    if (is_windows) return windows.listen(fd, backlog);
    return libcResult(c.listen(fd, backlog));
}

pub fn accept(fd: fd_t, peer: ?*Sockaddr) i32 {
    if (is_linux) {
        var len: linux.socklen_t = 128;
        const sa_ptr: ?*linux.sockaddr = if (peer) |p| @ptrCast(@alignCast(p.mutPtr())) else null;
        const r = linuxResult(linux.accept4(fd, sa_ptr, if (peer != null) &len else null, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC));
        if (r >= 0) {
            if (peer) |p| p.len = len;
        }
        return r;
    }
    if (is_windows) return windows.accept(fd, peer);
    var len: c.socklen_t = 128;
    const sa_ptr: ?*c.sockaddr = if (peer) |p| @ptrCast(@alignCast(p.mutPtr())) else null;
    const r = libcResult(c.accept(fd, sa_ptr, if (peer != null) &len else null));
    if (r >= 0) {
        if (peer) |p| p.len = len;
        setNonblocking(r) catch {};
        if (is_darwin) {
            const one: c_int = 1;
            _ = c.setsockopt(r, c.SOL.SOCKET, 0x1022, &one, @sizeOf(c_int));
        }
    }
    return r;
}

pub const msg_nosignal: u32 = if (is_linux) linux.MSG.NOSIGNAL else 0;
pub const msg_dontwait: u32 = if (is_linux) linux.MSG.DONTWAIT else if (is_windows) 0 else 0x80;

pub fn recv(fd: fd_t, buf: []u8, flags: u32) i32 {
    if (is_linux) return linuxResult(linux.recvfrom(fd, buf.ptr, buf.len, flags, null, null));
    if (is_windows) return windows.recv(fd, buf, flags);
    return libcResult(c.recv(fd, buf.ptr, buf.len, @intCast(flags)));
}

pub fn send(fd: fd_t, buf: []const u8, flags: u32) i32 {
    if (is_linux) return linuxResult(linux.sendto(fd, buf.ptr, buf.len, flags | msg_nosignal, null, 0));
    if (is_windows) return windows.send(fd, buf, flags);
    return libcResult(c.send(fd, buf.ptr, buf.len, flags));
}

pub fn sendto(fd: fd_t, buf: []const u8, flags: u32, sa: *const Sockaddr) i32 {
    if (is_linux) return linuxResult(linux.sendto(fd, buf.ptr, buf.len, flags | msg_nosignal, @ptrCast(@alignCast(sa.ptr())), sa.len));
    if (is_windows) return windows.sendto(fd, buf, sa);
    return libcResult(c.sendto(fd, buf.ptr, buf.len, flags, @ptrCast(@alignCast(sa.ptr())), sa.len));
}

pub fn recvfrom(fd: fd_t, buf: []u8, flags: u32, sa: *Sockaddr) i32 {
    if (is_linux) {
        var len: linux.socklen_t = 128;
        const r = linuxResult(linux.recvfrom(fd, buf.ptr, buf.len, flags, @ptrCast(@alignCast(sa.mutPtr())), &len));
        if (r >= 0) sa.len = len;
        return r;
    }
    if (is_windows) return windows.recvfrom(fd, buf, sa);
    var len: c.socklen_t = 128;
    const r = libcResult(c.recvfrom(fd, buf.ptr, buf.len, flags, @ptrCast(@alignCast(sa.mutPtr())), &len));
    if (r >= 0) sa.len = len;
    return r;
}

pub const Shutdown = enum(u8) { read = 0, write = 1, both = 2 };

pub fn shutdown(fd: fd_t, how: Shutdown) i32 {
    if (is_linux) return linuxResult(linux.shutdown(fd, @intFromEnum(how)));
    if (is_windows) return windows.shutdown(fd, @intFromEnum(how));
    return libcResult(c.shutdown(fd, @intFromEnum(how)));
}

pub fn getsockname(fd: fd_t, sa: *Sockaddr) i32 {
    if (is_linux) {
        var len: linux.socklen_t = 128;
        const r = linuxResult(linux.getsockname(fd, @ptrCast(@alignCast(sa.mutPtr())), &len));
        sa.len = len;
        return r;
    }
    if (is_windows) return windows.getsockname(fd, sa);
    var len: c.socklen_t = 128;
    const r = libcResult(c.getsockname(fd, @ptrCast(@alignCast(sa.mutPtr())), &len));
    sa.len = len;
    return r;
}

pub fn originalDestination(fd: fd_t, family: addr.Family) ?addr.Endpoint {
    if (!is_linux) return null;
    var sa: Sockaddr = .{};
    var len: linux.socklen_t = 128;
    const level: i32 = if (family == .v4) linux.SOL.IP else linux.SOL.IPV6;
    const r = linuxResult(linux.getsockopt(fd, level, 80, @ptrCast(@alignCast(sa.mutPtr())), &len));
    if (r < 0) return null;
    sa.len = len;
    return sa.toEndpoint();
}

pub fn getpeername(fd: fd_t, sa: *Sockaddr) i32 {
    if (is_linux) {
        var len: linux.socklen_t = 128;
        const r = linuxResult(linux.getpeername(fd, @ptrCast(@alignCast(sa.mutPtr())), &len));
        sa.len = len;
        return r;
    }
    if (is_windows) return windows.getpeername(fd, sa);
    var len: c.socklen_t = 128;
    const r = libcResult(c.getpeername(fd, @ptrCast(@alignCast(sa.mutPtr())), &len));
    sa.len = len;
    return r;
}

pub fn ioctl(fd: fd_t, request: u32, arg: usize) i32 {
    if (is_linux) return linuxResult(linux.ioctl(fd, request, arg));
    if (is_windows) return Errno.nosys.result();
    return libcResult(c.ioctl(fd, @bitCast(request), arg));
}

pub fn pipe() ![2]fd_t {
    if (is_linux) {
        var fds: [2]i32 = undefined;
        const flags: linux.O = .{ .NONBLOCK = true, .CLOEXEC = true };
        const r = linuxResult(linux.pipe2(&fds, flags));
        if (r < 0) return errnoError(toErrno(r));
        return fds;
    }
    if (is_windows) return error.NotSupported;
    var fds: [2]c.fd_t = undefined;
    if (c.pipe(&fds) != 0) return error.SystemResources;
    for (fds) |fd| {
        try setNonblocking(fd);
        _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
    }
    return fds;
}

pub fn errnoError(e: Errno) anyerror {
    return switch (e) {
        .acces, .perm => error.PermissionDenied,
        .nomem, .nobufs => error.SystemResources,
        .mfile => error.ProcessFdQuotaExceeded,
        .addrinuse => error.AddressInUse,
        .addrnotavail => error.AddressNotAvailable,
        .afnosupport, .opnotsupp, .nosys => error.NotSupported,
        .noent, .nodev => error.DeviceNotFound,
        .busy => error.DeviceBusy,
        .inval => error.InvalidArgument,
        .again => error.WouldBlock,
        .connrefused => error.ConnectionRefused,
        .timedout => error.Timeout,
        else => error.Unexpected,
    };
}

pub const windows = @import("windows.zig");

test "sockaddr roundtrip" {
    const ep = try addr.Endpoint.parse("[fdfe:dcba:9876::1]:443");
    const sa = Sockaddr.fromEndpoint(ep);
    try std.testing.expect(sa.toEndpoint().?.eql(ep));
    const ep4 = try addr.Endpoint.parse("10.1.2.3:53");
    const sa4 = Sockaddr.fromEndpoint(ep4);
    try std.testing.expect(sa4.toEndpoint().?.eql(ep4));
    try std.testing.expectEqual(@as(u32, 16), sa4.len);
}

test "socket connect loopback" {
    if (!is_linux) return error.SkipZigTest;
    const lfd = try socket(.v4, .tcp);
    defer close(lfd);
    var sa = Sockaddr.fromEndpoint(try addr.Endpoint.parse("127.0.0.1:0"));
    try std.testing.expect(bind(lfd, &sa) == 0);
    try std.testing.expect(listen(lfd, 16) == 0);
    try std.testing.expect(getsockname(lfd, &sa) == 0);
    const cfd = try socket(.v4, .tcp);
    defer close(cfd);
    const r = connect(cfd, &sa);
    try std.testing.expect(r == 0 or toErrno(r) == .inprogress);
    var peer: Sockaddr = .{};
    var afd: i32 = -1;
    var tries: u32 = 0;
    while (afd < 0 and tries < 100) : (tries += 1) {
        afd = accept(lfd, &peer);
        if (afd < 0) sleepMs(1);
    }
    try std.testing.expect(afd >= 0);
    defer close(afd);
    try std.testing.expect(peer.toEndpoint() != null);
    try std.testing.expectEqual(Errno.success, socketError(cfd));
    try std.testing.expectEqual(@as(i32, 5), send(cfd, "hello", 0));
    var buf: [16]u8 = undefined;
    var n: i32 = -1;
    tries = 0;
    while (n < 0 and tries < 100) : (tries += 1) {
        n = recv(afd, &buf, 0);
        if (n < 0) sleepMs(1);
    }
    try std.testing.expectEqual(@as(i32, 5), n);
}

test "random bytes come from the operating system" {
    var a: [32]u8 = @splat(0);
    var b: [32]u8 = @splat(0);
    try std.testing.expect(randomBytes(&a));
    try std.testing.expect(randomBytes(&b));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    try std.testing.expect(!std.mem.allEqual(u8, &a, 0));
}
