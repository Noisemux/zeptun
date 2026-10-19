const std = @import("std");
const build_options = @import("build_options");

pub const Level = enum(u8) { err = 0, warn = 1, info = 2, debug = 3, trace = 4 };

pub const Sink = *const fn (ctx: ?*anyopaque, level: Level, message: []const u8) void;

var sink: ?Sink = null;
var sink_ctx: ?*anyopaque = null;
var max_level: std.atomic.Value(u8) = .init(@backingInt(Level.info));

pub fn setSink(s: ?Sink, ctx: ?*anyopaque) void {
    sink = s;
    sink_ctx = ctx;
}

pub fn setLevel(level: Level) void {
    max_level.store(@backingInt(level), .release);
}

pub inline fn enabled(level: Level) bool {
    if (@backingInt(level) > build_options.max_log_level) return false;
    return @backingInt(level) <= max_level.load(.unordered);
}

pub fn emit(level: Level, comptime fmt: []const u8, args: anytype) void {
    if (!enabled(level)) return;
    const s = sink orelse return;
    var buf: [1024]u8 = undefined;
    const msg = std.mem.print(&buf, fmt, args) catch blk: {
        buf[buf.len - 3 ..].* = "...".*;
        break :blk buf[0..];
    };
    s(sink_ctx, level, msg);
}

pub inline fn err(comptime fmt: []const u8, args: anytype) void {
    emit(.err, fmt, args);
}

pub inline fn warn(comptime fmt: []const u8, args: anytype) void {
    emit(.warn, fmt, args);
}

pub inline fn info(comptime fmt: []const u8, args: anytype) void {
    emit(.info, fmt, args);
}

pub inline fn debug(comptime fmt: []const u8, args: anytype) void {
    emit(.debug, fmt, args);
}

pub inline fn trace(comptime fmt: []const u8, args: anytype) void {
    if (!build_options.enable_tracing) return;
    emit(.trace, fmt, args);
}
