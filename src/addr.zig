const std = @import("std");
const IpAddress = std.Io.net.IpAddress;

pub const Family = enum(u8) { v4 = 4, v6 = 6 };

pub const Address = struct {
    family: Family = .v4,
    bytes: [16]u8 = @splat(0),

    pub fn v4(b: [4]u8) Address {
        var a: Address = .{ .family = .v4 };
        @memcpy(a.bytes[0..4], &b);
        return a;
    }

    pub fn v6(b: [16]u8) Address {
        return .{ .family = .v6, .bytes = b };
    }

    pub fn fromSlice(s: []const u8) Address {
        return switch (s.len) {
            4 => v4(s[0..4].*),
            else => v6(s[0..16].*),
        };
    }

    pub inline fn len(a: Address) usize {
        return if (a.family == .v4) 4 else 16;
    }

    pub inline fn slice(a: *const Address) []const u8 {
        return a.bytes[0..a.len()];
    }

    pub inline fn isV6(a: Address) bool {
        return a.family == .v6;
    }

    pub fn eql(a: Address, b: Address) bool {
        return a.family == b.family and std.mem.eql(u8, a.slice(), b.slice());
    }

    pub fn isUnspecified(a: Address) bool {
        return std.mem.allEqual(u8, a.slice(), 0);
    }

    pub fn parse(text: []const u8) !Address {
        const ip = IpAddress.parse(text, 0) catch return error.InvalidAddress;
        return switch (ip) {
            .ip4 => |x| v4(x.bytes),
            .ip6 => |x| v6(x.bytes),
        };
    }

    pub fn format(a: Address, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (a.family) {
            .v4 => try w.print("{d}.{d}.{d}.{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] }),
            .v6 => {
                var words: [8]u16 = undefined;
                for (&words, 0..) |*wd, i| wd.* = std.mem.readInt(u16, a.bytes[i * 2 ..][0..2], .big);
                var best_start: usize = 8;
                var best_len: usize = 0;
                var i: usize = 0;
                while (i < 8) {
                    if (words[i] != 0) {
                        i += 1;
                        continue;
                    }
                    var j = i;
                    while (j < 8 and words[j] == 0) j += 1;
                    if (j - i > best_len and j - i >= 2) {
                        best_start = i;
                        best_len = j - i;
                    }
                    i = j;
                }
                i = 0;
                while (i < 8) {
                    if (i == best_start) {
                        try w.writeAll("::");
                        i += best_len;
                        continue;
                    }
                    if (i != 0 and i != best_start + best_len) try w.writeByte(':');
                    try w.print("{x}", .{words[i]});
                    i += 1;
                }
            },
        }
    }
};

pub const Endpoint = struct {
    addr: Address = .{},
    port: u16 = 0,

    pub fn parse(text: []const u8) !Endpoint {
        const ip = IpAddress.parseLiteral(text) catch return error.InvalidAddress;
        return switch (ip) {
            .ip4 => |x| .{ .addr = Address.v4(x.bytes), .port = x.port },
            .ip6 => |x| .{ .addr = Address.v6(x.bytes), .port = x.port },
        };
    }

    pub fn format(e: Endpoint, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (e.addr.family == .v6) {
            try w.print("[{f}]:{d}", .{ e.addr, e.port });
        } else {
            try w.print("{f}:{d}", .{ e.addr, e.port });
        }
    }

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        return a.port == b.port and a.addr.eql(b.addr);
    }
};

pub const Prefix = struct {
    addr: Address = .{},
    bits: u8 = 0,

    pub fn parse(text: []const u8) !Prefix {
        const slash = std.mem.findScalar(u8, text, '/');
        const a = try Address.parse(if (slash) |s| text[0..s] else text);
        const max: u8 = if (a.family == .v4) 32 else 128;
        const bits = if (slash) |s| std.fmt.parseInt(u8, text[s + 1 ..], 10) catch return error.InvalidPrefix else max;
        if (bits > max) return error.InvalidPrefix;
        return .{ .addr = a, .bits = bits };
    }

    pub fn contains(p: Prefix, a: Address) bool {
        if (p.addr.family != a.family) return false;
        var remaining: u8 = p.bits;
        var i: usize = 0;
        while (remaining >= 8) : (i += 1) {
            if (p.addr.bytes[i] != a.bytes[i]) return false;
            remaining -= 8;
        }
        if (remaining == 0) return true;
        const mask: u8 = @truncate(@as(u16, 0xff00) >> @intCast(remaining));
        return (p.addr.bytes[i] & mask) == (a.bytes[i] & mask);
    }

    pub fn masked(p: Prefix) Prefix {
        var out = p;
        var i: usize = p.bits / 8;
        if (i < 16) {
            const rem: u8 = p.bits % 8;
            if (rem != 0) {
                out.addr.bytes[i] &= @truncate(@as(u16, 0xff00) >> @intCast(rem));
                i += 1;
            }
            @memset(out.addr.bytes[i..], 0);
        }
        return out;
    }

    pub fn host(p: Prefix, n: u32) Address {
        var out = p.masked().addr;
        const l = out.len();
        var carry: u64 = n;
        var i: usize = l;
        while (i > 0 and carry != 0) {
            i -= 1;
            const s = @as(u64, out.bytes[i]) + (carry & 0xff);
            out.bytes[i] = @truncate(s);
            carry = (carry >> 8) + (s >> 8);
        }
        return out;
    }

    pub fn format(p: Prefix, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{f}/{d}", .{ p.addr, p.bits });
    }
};

test "address parse and format" {
    var buf: [64]u8 = undefined;
    const a = try Address.parse("172.19.0.1");
    try std.testing.expectEqualStrings("172.19.0.1", try std.mem.print(&buf, "{f}", .{a}));
    const b = try Address.parse("fdfe:dcba:9876::1");
    try std.testing.expectEqualStrings("fdfe:dcba:9876::1", try std.mem.print(&buf, "{f}", .{b}));
    const e = try Endpoint.parse("[::1]:1080");
    try std.testing.expectEqual(@as(u16, 1080), e.port);
    try std.testing.expectEqualStrings("[::1]:1080", try std.mem.print(&buf, "{f}", .{e}));
    const e4 = try Endpoint.parse("127.0.0.1:9000");
    try std.testing.expect(e4.addr.family == .v4 and e4.port == 9000);
}

test "prefix contains and host" {
    const p = try Prefix.parse("172.19.0.1/30");
    try std.testing.expect(p.contains(try Address.parse("172.19.0.2")));
    try std.testing.expect(!p.contains(try Address.parse("172.19.0.5")));
    try std.testing.expect(p.host(2).eql(try Address.parse("172.19.0.2")));
    const p6 = try Prefix.parse("fdfe:dcba:9876::1/126");
    try std.testing.expect(p6.host(2).eql(try Address.parse("fdfe:dcba:9876::2")));
    try std.testing.expect(p6.contains(try Address.parse("fdfe:dcba:9876::3")));
    try std.testing.expectError(error.InvalidPrefix, Prefix.parse("10.0.0.0/33"));
}
