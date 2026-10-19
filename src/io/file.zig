const std = @import("std");
const sys = @import("sys.zig");

const linux = std.os.linux;
const c = std.c;
const win = sys.windows;

pub const Error = error{ FileError, FileTooLarge, OutOfMemory, NameTooLong };

pub const Handle = if (sys.is_windows) win.HANDLE else i32;

pub const Mode = enum { read, create, append };

pub const Std = enum { out, err };

const max_path = 4096;

fn pathZ(buf: *[max_path]u8, path: []const u8) Error![*:0]const u8 {
    if (path.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0].ptr;
}

fn pathW(buf: *[max_path]u16, path: []const u8) Error![*:0]const u16 {
    if (path.len >= buf.len) return error.NameTooLong;
    const n = std.unicode.wtf8ToWtf16Le(buf[0 .. buf.len - 1], path) catch return error.FileError;
    buf[n] = 0;
    return buf[0..n :0].ptr;
}

pub fn open(path: []const u8, mode: Mode) Error!Handle {
    if (sys.is_windows) {
        var wbuf: [max_path]u16 = undefined;
        const p = try pathW(&wbuf, path);
        const access: u32 = switch (mode) {
            .read => win.GENERIC_READ,
            .create => win.GENERIC_WRITE,
            .append => win.FILE_APPEND_DATA,
        };
        const disposition: u32 = switch (mode) {
            .read => win.OPEN_EXISTING,
            .create => win.CREATE_ALWAYS,
            .append => win.OPEN_ALWAYS,
        };
        const h = win.kernel32.CreateFileW(p, access, win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE, null, disposition, win.FILE_ATTRIBUTE_NORMAL, null);
        if (h == win.INVALID_HANDLE_VALUE) return error.FileError;
        return h;
    }
    var buf: [max_path]u8 = undefined;
    const p = try pathZ(&buf, path);
    if (sys.is_linux) {
        var flags: linux.O = .{ .CLOEXEC = true };
        switch (mode) {
            .read => {},
            .create => {
                flags.ACCMODE = .WRONLY;
                flags.CREAT = true;
                flags.TRUNC = true;
            },
            .append => {
                flags.ACCMODE = .WRONLY;
                flags.CREAT = true;
                flags.APPEND = true;
            },
        }
        const rc = sys.linuxResult(linux.openat(linux.AT.FDCWD, p, flags, 0o644));
        if (rc < 0) return error.FileError;
        return rc;
    }
    var flags: c.O = .{ .CLOEXEC = true };
    switch (mode) {
        .read => {},
        .create => {
            flags.ACCMODE = .WRONLY;
            flags.CREAT = true;
            flags.TRUNC = true;
        },
        .append => {
            flags.ACCMODE = .WRONLY;
            flags.CREAT = true;
            flags.APPEND = true;
        },
    }
    const fd = c.open(p, flags, @as(c_uint, 0o644));
    if (fd < 0) return error.FileError;
    return fd;
}

pub fn close(h: Handle) void {
    if (sys.is_windows) {
        _ = win.kernel32.CloseHandle(h);
    } else if (sys.is_linux) {
        _ = linux.close(h);
    } else {
        _ = c.close(h);
    }
}

pub fn read(h: Handle, buf: []u8) Error!usize {
    if (sys.is_windows) {
        var got: u32 = 0;
        if (win.kernel32.ReadFile(h, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(u32))), &got, null) == 0) return error.FileError;
        return got;
    }
    while (true) {
        const rc = if (sys.is_linux) sys.linuxResult(linux.read(h, buf.ptr, buf.len)) else sys.libcResult(c.read(h, buf.ptr, buf.len));
        if (rc >= 0) return @intCast(rc);
        if (sys.toErrno(rc) != .intr) return error.FileError;
    }
}

pub fn writeAll(h: Handle, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const chunk = bytes[off..];
        if (sys.is_windows) {
            var put: u32 = 0;
            if (win.kernel32.WriteFile(h, chunk.ptr, @intCast(@min(chunk.len, std.math.maxInt(u32))), &put, null) == 0) return error.FileError;
            off += put;
            continue;
        }
        const rc = if (sys.is_linux) sys.linuxResult(linux.write(h, chunk.ptr, chunk.len)) else sys.libcResult(c.write(h, chunk.ptr, chunk.len));
        if (rc < 0) {
            if (sys.toErrno(rc) == .intr) continue;
            return error.FileError;
        }
        if (rc == 0) return error.FileError;
        off += @intCast(rc);
    }
}

pub fn readAlloc(allocator: std.mem.Allocator, path: []const u8, limit: usize) Error![]u8 {
    const h = try open(path, .read);
    defer close(h);
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    while (true) {
        if (list.items.len > limit) return error.FileTooLarge;
        try list.ensureUnusedCapacity(allocator, 16 * 1024);
        const n = try read(h, list.unusedCapacitySlice());
        if (n == 0) break;
        list.items.len += n;
    }
    if (list.items.len > limit) return error.FileTooLarge;
    return list.toOwnedSlice(allocator);
}

pub fn writeFile(path: []const u8, bytes: []const u8) Error!void {
    const h = try open(path, .create);
    defer close(h);
    try writeAll(h, bytes);
}

pub fn remove(path: []const u8) void {
    if (sys.is_windows) {
        var wbuf: [max_path]u16 = undefined;
        const p = pathW(&wbuf, path) catch return;
        _ = win.kernel32.DeleteFileW(p);
        return;
    }
    var buf: [max_path]u8 = undefined;
    const p = pathZ(&buf, path) catch return;
    if (sys.is_linux) {
        _ = linux.unlinkat(linux.AT.FDCWD, p, 0);
    } else {
        _ = c.unlink(p);
    }
}

pub fn writeStd(which: Std, bytes: []const u8) void {
    if (sys.is_windows) {
        const h = win.kernel32.GetStdHandle(if (which == .out) win.STD_OUTPUT_HANDLE else win.STD_ERROR_HANDLE) orelse return;
        if (h == win.INVALID_HANDLE_VALUE) return;
        writeAll(h, bytes) catch {};
        return;
    }
    writeAll(if (which == .out) 1 else 2, bytes) catch {};
}

pub fn print(which: Std, comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    w.print(fmt, args) catch {};
    writeStd(which, w.buffered());
}

test "file round trip" {
    if (sys.is_windows) return error.SkipZigTest;
    var name_buf: [64]u8 = undefined;
    const name = try std.mem.print(&name_buf, ".zeptun-file-test-{d}", .{sys.monotonicNs()});
    try writeFile(name, "first\n");
    defer remove(name);
    const h = try open(name, .append);
    try writeAll(h, "second\n");
    close(h);
    const bytes = try readAlloc(std.testing.allocator, name, 1024);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("first\nsecond\n", bytes);
    try std.testing.expectError(error.FileTooLarge, readAlloc(std.testing.allocator, name, 4));
    remove(name);
    try std.testing.expectError(error.FileError, open(name, .read));
}
