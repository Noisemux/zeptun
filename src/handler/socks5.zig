const std = @import("std");
const addr = @import("../addr.zig");

pub const version: u8 = 0x05;
pub const max_handshake = 800;
pub const max_udp_header = 262;

pub const Method = enum(u8) { none = 0x00, gssapi = 0x01, password = 0x02, unacceptable = 0xff, _ };
pub const Command = enum(u8) { connect = 0x01, bind = 0x02, udp_associate = 0x03, fwd_udp = 0x05 };

pub const max_frame_header = 3 + 259;

pub fn encodeFrameHeader(buf: []u8, dst: Target, payload_len: usize) usize {
    const al = dst.encode(buf[3..]);
    std.mem.writeInt(u16, buf[0..2], @intCast(payload_len), .big);
    buf[2] = @intCast(3 + al);
    return 3 + al;
}

pub const FrameParse = struct {
    src: ?addr.Endpoint,
    port: u16,
    header_len: usize,
    total: usize,
};

pub fn parseFrame(data: []const u8) Error!FrameParse {
    if (data.len < 3) return error.NeedMore;
    const datlen = std.mem.readInt(u16, data[0..2], .big);
    const hl: usize = data[2];
    if (hl < 5 or hl > max_frame_header) return error.Protocol;
    const total = hl + datlen;
    if (data.len < hl) return error.NeedMore;
    const a = parseAddress(data[3..hl]) catch return error.Protocol;
    if (3 + a.len != hl) return error.Protocol;
    return .{ .src = a.endpoint, .port = if (a.endpoint) |ep| ep.port else a.port, .header_len = hl, .total = total };
}

test "udp in tcp frames" {
    var buf: [300]u8 = undefined;
    const dst = try addr.Endpoint.parse("10.1.2.3:4444");
    const hl = encodeFrameHeader(&buf, .{ .ip = dst }, 5);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 5, 10, 1, 10, 1, 2, 3, 0x11, 0x5c }, buf[0..hl]);
    @memcpy(buf[hl..][0..5], "hello");
    const f = try parseFrame(buf[0 .. hl + 5]);
    try std.testing.expect(f.src.?.eql(dst));
    try std.testing.expectEqual(hl + 5, f.total);
    try std.testing.expectError(error.NeedMore, parseFrame(buf[0..2]));
    buf[2] = 4;
    try std.testing.expectError(error.Protocol, parseFrame(buf[0 .. hl + 5]));
}
pub const Atyp = enum(u8) { ipv4 = 0x01, domain = 0x03, ipv6 = 0x04, _ };

pub const Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_not_supported = 0x08,
    _,
};

pub const Error = error{ Protocol, NoAcceptableMethod, AuthFailed, Refused, Unreachable, NotAllowed, Failure, NeedMore, TooLong };

pub fn encodeGreeting(buf: []u8, with_password: bool) []u8 {
    buf[0] = version;
    if (with_password) {
        buf[1] = 2;
        buf[2] = @backingInt(Method.none);
        buf[3] = @backingInt(Method.password);
        return buf[0..4];
    }
    buf[1] = 1;
    buf[2] = @backingInt(Method.none);
    return buf[0..3];
}

pub fn parseMethodReply(data: []const u8) Error!Method {
    if (data.len < 2) return error.NeedMore;
    if (data[0] != version) return error.Protocol;
    const m: Method = @fromBackingInt(@intCast(data[1]));
    return switch (m) {
        .none, .password => m,
        else => error.NoAcceptableMethod,
    };
}

pub fn encodePasswordAuth(buf: []u8, username: []const u8, password: []const u8) Error![]u8 {
    if (username.len > 255 or password.len > 255) return error.TooLong;
    if (buf.len < 3 + username.len + password.len) return error.TooLong;
    buf[0] = 0x01;
    buf[1] = @intCast(username.len);
    @memcpy(buf[2..][0..username.len], username);
    buf[2 + username.len] = @intCast(password.len);
    @memcpy(buf[3 + username.len ..][0..password.len], password);
    return buf[0 .. 3 + username.len + password.len];
}

pub fn parseAuthReply(data: []const u8) Error!void {
    if (data.len < 2) return error.NeedMore;
    if (data[0] != 0x01) return error.Protocol;
    if (data[1] != 0x00) return error.AuthFailed;
}

pub fn encodeAddress(buf: []u8, ep: addr.Endpoint) usize {
    switch (ep.addr.family) {
        .v4 => {
            buf[0] = @backingInt(Atyp.ipv4);
            @memcpy(buf[1..5], ep.addr.bytes[0..4]);
            std.mem.writeInt(u16, buf[5..7], ep.port, .big);
            return 7;
        },
        .v6 => {
            buf[0] = @backingInt(Atyp.ipv6);
            @memcpy(buf[1..17], ep.addr.bytes[0..16]);
            std.mem.writeInt(u16, buf[17..19], ep.port, .big);
            return 19;
        },
    }
}

pub const Target = union(enum) {
    ip: addr.Endpoint,
    host: struct { name: []const u8, port: u16 },

    pub fn encode(t: Target, buf: []u8) usize {
        switch (t) {
            .ip => |ep| return encodeAddress(buf, ep),
            .host => |h| {
                buf[0] = @backingInt(Atyp.domain);
                buf[1] = @intCast(h.name.len);
                @memcpy(buf[2..][0..h.name.len], h.name);
                std.mem.writeInt(u16, buf[2 + h.name.len ..][0..2], h.port, .big);
                return 4 + h.name.len;
            },
        }
    }
};

pub fn encodeRequest(buf: []u8, cmd: Command, target: addr.Endpoint) []u8 {
    return encodeRequestTo(buf, cmd, .{ .ip = target });
}

pub fn encodeRequestTo(buf: []u8, cmd: Command, target: Target) []u8 {
    buf[0] = version;
    buf[1] = @backingInt(cmd);
    buf[2] = 0;
    const n = target.encode(buf[3..]);
    return buf[0 .. 3 + n];
}

pub const AddressParse = struct {
    endpoint: ?addr.Endpoint,
    len: usize,
    name: []const u8 = &.{},
    port: u16 = 0,
};

pub fn parseAddress(data: []const u8) Error!AddressParse {
    if (data.len < 1) return error.NeedMore;
    switch (@as(Atyp, @fromBackingInt(@intCast(data[0])))) {
        .ipv4 => {
            if (data.len < 7) return error.NeedMore;
            return .{ .endpoint = .{ .addr = addr.Address.v4(data[1..5].*), .port = std.mem.readInt(u16, data[5..7], .big) }, .len = 7 };
        },
        .ipv6 => {
            if (data.len < 19) return error.NeedMore;
            return .{ .endpoint = .{ .addr = addr.Address.v6(data[1..17].*), .port = std.mem.readInt(u16, data[17..19], .big) }, .len = 19 };
        },
        .domain => {
            if (data.len < 2) return error.NeedMore;
            const l: usize = data[1];
            if (data.len < 2 + l + 2) return error.NeedMore;
            return .{ .endpoint = null, .len = 2 + l + 2, .name = data[2..][0..l], .port = std.mem.readInt(u16, data[2 + l ..][0..2], .big) };
        },
        _ => return error.Protocol,
    }
}

pub const ReplyParse = struct {
    bound: ?addr.Endpoint,
    len: usize,
};

pub fn parseReply(data: []const u8) Error!ReplyParse {
    if (data.len < 4) return error.NeedMore;
    if (data[0] != version or data[2] != 0) return error.Protocol;
    const a = try parseAddress(data[3..]);
    const rep: Reply = @fromBackingInt(@intCast(data[1]));
    switch (rep) {
        .succeeded => {},
        .connection_refused => return error.Refused,
        .network_unreachable, .host_unreachable, .ttl_expired => return error.Unreachable,
        .not_allowed => return error.NotAllowed,
        else => return error.Failure,
    }
    return .{ .bound = a.endpoint, .len = 3 + a.len };
}

pub fn encodeUdpHeader(buf: []u8, dst: addr.Endpoint) usize {
    return encodeUdpHeaderTo(buf, .{ .ip = dst });
}

pub fn encodeUdpHeaderTo(buf: []u8, dst: Target) usize {
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0;
    return 3 + dst.encode(buf[3..]);
}

pub inline fn udpHeaderLen(dst: addr.Endpoint) usize {
    return if (dst.addr.family == .v4) 10 else 22;
}

pub const UdpParse = struct {
    src: ?addr.Endpoint,
    header_len: usize,
    name: []const u8 = &.{},
    port: u16 = 0,
};

pub fn parseUdpHeader(data: []const u8) Error!UdpParse {
    if (data.len < 4) return error.Protocol;
    if (data[0] != 0 or data[1] != 0) return error.Protocol;
    if (data[2] != 0) return error.Protocol;
    const a = parseAddress(data[3..]) catch return error.Protocol;
    return .{ .src = a.endpoint, .header_len = 3 + a.len, .name = a.name, .port = if (a.endpoint) |ep| ep.port else a.port };
}

pub fn encodeHandshake(buf: []u8, target: Target, cmd: Command, username: []const u8, password: []const u8, pipeline: bool) Error![]u8 {
    const auth = username.len > 0;
    var n = encodeGreeting(buf, auth).len;
    if (!pipeline) return buf[0..n];
    if (auth) n += (try encodePasswordAuth(buf[n..], username, password)).len;
    if (buf.len < n + 262) return error.TooLong;
    n += encodeRequestTo(buf[n..], cmd, target).len;
    return buf[0..n];
}

test "domain request encoding" {
    var buf: [600]u8 = undefined;
    const msg = try encodeHandshake(&buf, .{ .host = .{ .name = "example.com", .port = 443 } }, .connect, "", "", true);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 1, 0, 5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187 }, msg);
    var hdr: [300]u8 = undefined;
    const hl = encodeUdpHeaderTo(&hdr, .{ .host = .{ .name = "a.b", .port = 53 } });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 3, 3, 'a', '.', 'b', 0, 53 }, hdr[0..hl]);
}

test "greeting and method" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 1, 0 }, encodeGreeting(&buf, false));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 2, 0, 2 }, encodeGreeting(&buf, true));
    try std.testing.expectEqual(Method.none, try parseMethodReply(&[_]u8{ 5, 0 }));
    try std.testing.expectError(error.NoAcceptableMethod, parseMethodReply(&[_]u8{ 5, 0xff }));
    try std.testing.expectError(error.NeedMore, parseMethodReply(&[_]u8{5}));
}

test "request and reply roundtrip" {
    var buf: [64]u8 = undefined;
    const target = try addr.Endpoint.parse("[2001:db8::1]:443");
    const req = encodeRequest(&buf, .connect, target);
    try std.testing.expectEqual(@as(usize, 22), req.len);
    const reply = [_]u8{ 5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90 };
    const r = try parseReply(&reply);
    try std.testing.expectEqual(@as(usize, 10), r.len);
    try std.testing.expectEqual(@as(u16, 8080), r.bound.?.port);
    try std.testing.expectError(error.NeedMore, parseReply(reply[0..8]));
    try std.testing.expectError(error.Refused, parseReply(&[_]u8{ 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }));
    const auth = try encodePasswordAuth(&buf, "user", "pw");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 4, 'u', 's', 'e', 'r', 2, 'p', 'w' }, auth);
}

test "udp header roundtrip" {
    var buf: [32]u8 = undefined;
    const dst = try addr.Endpoint.parse("8.8.8.8:53");
    const n = encodeUdpHeader(&buf, dst);
    try std.testing.expectEqual(udpHeaderLen(dst), n);
    const p = try parseUdpHeader(buf[0..n]);
    try std.testing.expect(p.src.?.eql(dst));
    try std.testing.expectEqual(n, p.header_len);
}

fn fuzzParsers(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    const n = smith.slice(&buf);
    const data = buf[0..n];
    if (parseReply(data)) |r| try std.testing.expect(r.len <= data.len) else |_| {}
    if (parseUdpHeader(data)) |u| try std.testing.expect(u.header_len <= data.len) else |_| {}
    _ = parseMethodReply(data) catch {};
    _ = parseAuthReply(data) catch {};
}

test "fuzz socks5 parsers" {
    try std.testing.fuzz({}, fuzzParsers, .{});
}
