const std = @import("std");
const addr = @import("../addr.zig");

pub const Action = enum(u32) {
    proxy = 0,
    direct = 1,
    drop = 2,
    reject = 3,
};

pub const Flow = extern struct {
    protocol: u8,
    family: u8,
    source: [16]u8,
    destination: [16]u8,
    source_port: u16,
    destination_port: u16,
};

pub const Fn = *const fn (ctx: ?*anyopaque, flow: *const Flow) callconv(.c) u32;

pub const Judge = struct {
    call: ?Fn = null,
    ctx: ?*anyopaque = null,

    pub inline fn active(j: *const Judge) bool {
        return j.call != null;
    }

    pub fn ask(j: *const Judge, proto: u8, v6: bool, src: []const u8, src_port: u16, dst: []const u8, dst_port: u16) Action {
        const f = j.call orelse return .proxy;
        var flow: Flow = .{
            .protocol = proto,
            .family = if (v6) 6 else 4,
            .source = @splat(0),
            .destination = @splat(0),
            .source_port = src_port,
            .destination_port = dst_port,
        };
        const al = @min(src.len, flow.source.len);
        @memcpy(flow.source[0..al], src[0..al]);
        @memcpy(flow.destination[0..al], dst[0..al]);
        const v = f(j.ctx, &flow);
        return switch (v) {
            0 => .proxy,
            1 => .direct,
            2 => .drop,
            3 => .reject,
            else => .proxy,
        };
    }
};

test "judge maps verdicts and passes the flow" {
    const Seen = struct {
        var last: Flow = undefined;
        fn answer(ctx: ?*anyopaque, flow: *const Flow) callconv(.c) u32 {
            last = flow.*;
            return @intCast(@intFromPtr(ctx));
        }
    };
    var j: Judge = .{};
    try std.testing.expectEqual(Action.proxy, j.ask(6, false, &[_]u8{ 10, 0, 0, 2 }, 1234, &[_]u8{ 1, 1, 1, 1 }, 443));
    j = .{ .call = Seen.answer, .ctx = @ptrFromInt(3) };
    try std.testing.expectEqual(Action.reject, j.ask(17, false, &[_]u8{ 10, 0, 0, 2 }, 1234, &[_]u8{ 1, 1, 1, 1 }, 53));
    try std.testing.expectEqual(@as(u8, 17), Seen.last.protocol);
    try std.testing.expectEqual(@as(u16, 53), Seen.last.destination_port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 2 }, Seen.last.source[0..4]);
    j.ctx = @ptrFromInt(9);
    try std.testing.expectEqual(Action.proxy, j.ask(6, true, &@as([16]u8, @splat(0)), 1, &@as([16]u8, @splat(0)), 2));
    try std.testing.expectEqual(@as(u8, 6), Seen.last.family);
}
