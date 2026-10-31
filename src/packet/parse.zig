const std = @import("std");
const checksum = @import("checksum.zig");

pub const proto = struct {
    pub const hopopts: u8 = 0;
    pub const icmp: u8 = 1;
    pub const tcp: u8 = 6;
    pub const udp: u8 = 17;
    pub const ipv6_route: u8 = 43;
    pub const ipv6_frag: u8 = 44;
    pub const esp: u8 = 50;
    pub const ah: u8 = 51;
    pub const icmpv6: u8 = 58;
    pub const ipv6_none: u8 = 59;
    pub const ipv6_dstopts: u8 = 60;
    pub const mobility: u8 = 135;
};

pub const Error = error{
    Truncated,
    BadVersion,
    BadHeaderLength,
    BadTotalLength,
    BadExtension,
};

pub inline fn be16(data: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, data[off..][0..2], .big);
}

pub inline fn be32(data: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, data[off..][0..4], .big);
}

pub inline fn setBe16(data: []u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, data[off..][0..2], v, .big);
}

pub inline fn setBe32(data: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, data[off..][0..4], v, .big);
}

pub const TcpFlags = packed struct(u8) {
    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    ece: bool = false,
    cwr: bool = false,

    pub inline fn bits(f: TcpFlags) u8 {
        return @bitCast(f);
    }
};

pub const Ip = struct {
    version: u8,
    header_len: u16,
    total_len: u32,
    next: u8,
    ttl: u8,
    tos: u8,
    flow_label: u32 = 0,
    frag_id: u32 = 0,
    frag_offset: u16 = 0,
    frag_more: bool = false,
    dont_fragment: bool = false,
    frag_header_off: u16 = 0,

    pub inline fn isV6(ip: Ip) bool {
        return ip.version == 6;
    }

    pub inline fn addrLen(ip: Ip) usize {
        return if (ip.version == 6) 16 else 4;
    }

    pub inline fn srcOff(ip: Ip) usize {
        return if (ip.version == 6) 8 else 12;
    }

    pub inline fn dstOff(ip: Ip) usize {
        return if (ip.version == 6) 24 else 16;
    }

    pub inline fn isFragment(ip: Ip) bool {
        return ip.frag_more or ip.frag_offset != 0;
    }

    pub inline fn src(ip: Ip, data: []const u8) []const u8 {
        return data[ip.srcOff()..][0..ip.addrLen()];
    }

    pub inline fn dst(ip: Ip, data: []const u8) []const u8 {
        return data[ip.dstOff()..][0..ip.addrLen()];
    }
};

pub const Tcp = struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    header_len: u16,
    flags: TcpFlags,
    window: u16,
    urgent: u16,
};

pub const Udp = struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

pub const Icmp = struct {
    kind: u8,
    code: u8,
    rest: u32,
};

pub const L4 = union(enum) {
    tcp: Tcp,
    udp: Udp,
    icmp: Icmp,
    other: void,
};

pub const Packet = struct {
    ip: Ip,
    l4_off: u16,
    l4: L4,
    payload_off: u32,
    payload_len: u32,

    pub inline fn l4Len(p: Packet) u32 {
        return p.ip.total_len - p.l4_off;
    }

    pub inline fn srcPort(p: Packet) u16 {
        return switch (p.l4) {
            .tcp => |t| t.src_port,
            .udp => |u| u.src_port,
            else => 0,
        };
    }

    pub inline fn dstPort(p: Packet) u16 {
        return switch (p.l4) {
            .tcp => |t| t.dst_port,
            .udp => |u| u.dst_port,
            else => 0,
        };
    }
};

pub fn version(data: []const u8) u8 {
    if (data.len == 0) return 0;
    return data[0] >> 4;
}

pub fn parseIpv4(data: []const u8) Error!Ip {
    if (data.len < 20) return error.Truncated;
    if (data[0] >> 4 != 4) return error.BadVersion;
    const ihl: u16 = @as(u16, data[0] & 0x0f) * 4;
    if (ihl < 20) return error.BadHeaderLength;
    if (data.len < ihl) return error.Truncated;
    const tot = be16(data, 2);
    var total: u32 = tot;
    if (total < ihl) {
        if (tot == 0 and data.len > 65535) {
            total = @intCast(data.len);
        } else return error.BadTotalLength;
    }
    if (total > data.len) return error.Truncated;
    const frag = be16(data, 6);
    return .{
        .version = 4,
        .header_len = ihl,
        .total_len = total,
        .next = data[9],
        .ttl = data[8],
        .tos = data[1],
        .frag_id = be16(data, 4),
        .frag_offset = frag & 0x1fff,
        .frag_more = frag & 0x2000 != 0,
        .dont_fragment = frag & 0x4000 != 0,
    };
}

pub fn parseIpv6(data: []const u8) Error!Ip {
    if (data.len < 40) return error.Truncated;
    if (data[0] >> 4 != 6) return error.BadVersion;
    const plen = be16(data, 4);
    var total: u32 = @as(u32, plen) + 40;
    if (plen == 0 and data.len > 40) total = @intCast(@min(data.len, std.math.maxInt(u32)));
    if (total > data.len) return error.Truncated;
    var ip: Ip = .{
        .version = 6,
        .header_len = 40,
        .total_len = total,
        .next = data[6],
        .ttl = data[7],
        .tos = @truncate((be16(data, 0) >> 4) & 0xff),
        .flow_label = be32(data, 0) & 0x000f_ffff,
    };
    var off: u32 = 40;
    var next = data[6];
    var guard: u8 = 0;
    while (guard < 12) : (guard += 1) {
        switch (next) {
            proto.hopopts, proto.ipv6_route, proto.ipv6_dstopts, proto.mobility => {
                if (off + 8 > total) return error.Truncated;
                const len: u32 = (@as(u32, data[off + 1]) + 1) * 8;
                if (off + len > total) return error.BadExtension;
                next = data[off];
                off += len;
            },
            proto.ipv6_frag => {
                if (off + 8 > total) return error.Truncated;
                const fo = be16(data, off + 2);
                ip.frag_header_off = @intCast(off);
                ip.frag_offset = fo >> 3;
                ip.frag_more = fo & 1 != 0;
                ip.frag_id = be32(data, off + 4);
                next = data[off];
                off += 8;
            },
            proto.ah => {
                if (off + 8 > total) return error.Truncated;
                const len: u32 = (@as(u32, data[off + 1]) + 2) * 4;
                if (off + len > total) return error.BadExtension;
                next = data[off];
                off += len;
            },
            else => break,
        }
    } else return error.BadExtension;
    if (off > 0xffff) return error.BadExtension;
    ip.header_len = @intCast(off);
    ip.next = next;
    return ip;
}

pub fn parseIp(data: []const u8) Error!Ip {
    if (data.len == 0) return error.Truncated;
    return switch (data[0] >> 4) {
        4 => parseIpv4(data),
        6 => parseIpv6(data),
        else => error.BadVersion,
    };
}

pub fn parse(data: []const u8) Error!Packet {
    const ip = try parseIp(data);
    const l4_off: u32 = ip.header_len;
    var pkt: Packet = .{
        .ip = ip,
        .l4_off = @intCast(l4_off),
        .l4 = .other,
        .payload_off = l4_off,
        .payload_len = ip.total_len - l4_off,
    };
    if (ip.frag_offset != 0) return pkt;
    const avail = ip.total_len - l4_off;
    switch (ip.next) {
        proto.tcp => {
            if (avail < 20) return if (ip.frag_more) pkt else error.Truncated;
            const hl: u16 = @as(u16, data[l4_off + 12] >> 4) * 4;
            if (hl < 20) return error.BadHeaderLength;
            if (hl > avail) return error.Truncated;
            pkt.l4 = .{ .tcp = .{
                .src_port = be16(data, l4_off),
                .dst_port = be16(data, l4_off + 2),
                .seq = be32(data, l4_off + 4),
                .ack = be32(data, l4_off + 8),
                .header_len = hl,
                .flags = @bitCast(data[l4_off + 13]),
                .window = be16(data, l4_off + 14),
                .urgent = be16(data, l4_off + 18),
            } };
            pkt.payload_off = l4_off + hl;
            pkt.payload_len = avail - hl;
        },
        proto.udp => {
            if (avail < 8) return if (ip.frag_more) pkt else error.Truncated;
            pkt.l4 = .{ .udp = .{
                .src_port = be16(data, l4_off),
                .dst_port = be16(data, l4_off + 2),
                .length = be16(data, l4_off + 4),
                .checksum = be16(data, l4_off + 6),
            } };
            pkt.payload_off = l4_off + 8;
            pkt.payload_len = avail - 8;
        },
        proto.icmp, proto.icmpv6 => {
            if ((ip.next == proto.icmp) != (ip.version == 4)) return pkt;
            if (avail < 8) return if (ip.frag_more) pkt else error.Truncated;
            pkt.l4 = .{ .icmp = .{
                .kind = data[l4_off],
                .code = data[l4_off + 1],
                .rest = be32(data, l4_off + 4),
            } };
            pkt.payload_off = l4_off + 8;
            pkt.payload_len = avail - 8;
        },
        else => {},
    }
    return pkt;
}

pub const SackBlock = struct {
    left: u32,
    right: u32,
};

pub const TcpOptions = struct {
    mss: u16 = 0,
    wscale: u8 = 0,
    has_wscale: bool = false,
    sack_permitted: bool = false,
    has_timestamp: bool = false,
    ts_val: u32 = 0,
    ts_ecr: u32 = 0,
    sack_count: u8 = 0,
    sack: [4]SackBlock = undefined,
};

pub fn parseTcpOptions(opts: []const u8) TcpOptions {
    var o: TcpOptions = .{};
    var i: usize = 0;
    while (i < opts.len) {
        const kind = opts[i];
        switch (kind) {
            0 => break,
            1 => {
                i += 1;
                continue;
            },
            else => {},
        }
        if (i + 1 >= opts.len) break;
        const len = opts[i + 1];
        if (len < 2 or i + len > opts.len) break;
        const body = opts[i + 2 .. i + len];
        switch (kind) {
            2 => if (len == 4) {
                o.mss = be16(body, 0);
            },
            3 => if (len == 3) {
                o.wscale = @min(body[0], 14);
                o.has_wscale = true;
            },
            4 => if (len == 2) {
                o.sack_permitted = true;
            },
            5 => {
                var n: usize = 0;
                while (n < 4 and (n + 1) * 8 <= body.len) : (n += 1) {
                    o.sack[n] = .{ .left = be32(body, n * 8), .right = be32(body, n * 8 + 4) };
                }
                o.sack_count = @intCast(n);
            },
            8 => if (len == 10) {
                o.has_timestamp = true;
                o.ts_val = be32(body, 0);
                o.ts_ecr = be32(body, 4);
            },
            else => {},
        }
        i += len;
    }
    return o;
}

pub const FlowKey = extern struct {
    src: [16]u8 = @splat(0),
    dst: [16]u8 = @splat(0),
    src_port: u16 = 0,
    dst_port: u16 = 0,
    proto: u8 = 0,
    v6: u8 = 0,
    pad: [2]u8 = @splat(0),

    pub fn fromPacket(data: []const u8, pkt: Packet) FlowKey {
        var k: FlowKey = .{ .proto = pkt.ip.next, .v6 = @intFromBool(pkt.ip.isV6()) };
        const al = pkt.ip.addrLen();
        @memcpy(k.src[0..al], data[pkt.ip.srcOff()..][0..al]);
        @memcpy(k.dst[0..al], data[pkt.ip.dstOff()..][0..al]);
        k.src_port = pkt.srcPort();
        k.dst_port = pkt.dstPort();
        return k;
    }

    pub fn reversed(k: FlowKey) FlowKey {
        return .{
            .src = k.dst,
            .dst = k.src,
            .src_port = k.dst_port,
            .dst_port = k.src_port,
            .proto = k.proto,
            .v6 = k.v6,
        };
    }

    pub inline fn words(k: *const FlowKey) [5]u64 {
        const b: *const [40]u8 = @ptrCast(k);
        return .{
            std.mem.readInt(u64, b[0..8], .little),
            std.mem.readInt(u64, b[8..16], .little),
            std.mem.readInt(u64, b[16..24], .little),
            std.mem.readInt(u64, b[24..32], .little),
            std.mem.readInt(u64, b[32..40], .little),
        };
    }

    pub fn hash(k: *const FlowKey) u64 {
        const w = k.words();
        return mix5(w[0], w[1], w[2], w[3], w[4]);
    }

    pub fn symmetricHash(k: *const FlowKey) u64 {
        const w = k.words();
        const a = w[0] ^ w[2];
        const b = w[1] ^ w[3];
        const ports = @as(u64, k.src_port ^ k.dst_port) | (@as(u64, k.proto) << 32) | (@as(u64, k.v6) << 40);
        return mix5(a, b, a +% b, ports, @as(u64, k.src_port) +% k.dst_port);
    }

    pub inline fn eql(a: *const FlowKey, b: *const FlowKey) bool {
        const x = a.words();
        const y = b.words();
        return ((x[0] ^ y[0]) | (x[1] ^ y[1]) | (x[2] ^ y[2]) | (x[3] ^ y[3]) | (x[4] ^ y[4])) == 0;
    }
};

comptime {
    std.debug.assert(@sizeOf(FlowKey) == 40);
    std.debug.assert(@alignOf(FlowKey) <= 8);
}

inline fn mum(a: u64, b: u64) u64 {
    const r = @as(u128, a) * b;
    return @as(u64, @truncate(r)) ^ @as(u64, @truncate(r >> 64));
}

pub inline fn mix5(a: u64, b: u64, c: u64, d: u64, e: u64) u64 {
    const k0: u64 = 0xa076_1d64_78bd_642f;
    const k1: u64 = 0xe703_7ed1_a0b4_28db;
    const k2: u64 = 0x8ebc_6af0_9c88_c6e3;
    const k3: u64 = 0x5899_65cc_7537_4cc3;
    const h1 = mum(a ^ k0, b ^ k1);
    const h2 = mum(c ^ k2, d ^ k3);
    return mum(h1 ^ e, h2 ^ k1);
}

pub fn l4ChecksumValid(data: []const u8, pkt: Packet) bool {
    const l4 = data[pkt.l4_off..pkt.ip.total_len];
    const v6 = pkt.ip.isV6();
    const acc = checksum.pseudo(v6, pkt.ip.src(data), pkt.ip.dst(data), pkt.ip.next, @intCast(l4.len));
    return checksum.fold(checksum.sum(l4, acc)) == 0xffff;
}

fn buildV4Tcp(buf: []u8, payload: []const u8, flags: u8, opts: []const u8) []u8 {
    const hl: usize = 20 + ((opts.len + 3) / 4) * 4;
    const total = 20 + hl + payload.len;
    @memset(buf[0..total], 0);
    buf[0] = 0x45;
    setBe16(buf, 2, @intCast(total));
    setBe16(buf, 4, 0x1234);
    buf[6] = 0x40;
    buf[8] = 64;
    buf[9] = proto.tcp;
    @memcpy(buf[12..16], &[_]u8{ 10, 0, 0, 1 });
    @memcpy(buf[16..20], &[_]u8{ 93, 184, 216, 34 });
    checksum.ipv4Header(buf[0..20]);
    setBe16(buf, 20, 40000);
    setBe16(buf, 22, 443);
    setBe32(buf, 24, 1000);
    setBe32(buf, 28, 2000);
    buf[32] = @intCast(hl << 2);
    buf[33] = flags;
    setBe16(buf, 34, 65535);
    @memcpy(buf[40..][0..opts.len], opts);
    @memcpy(buf[20 + hl ..][0..payload.len], payload);
    const acc = checksum.pseudoV4(buf[12..16], buf[16..20], proto.tcp, @intCast(hl + payload.len));
    checksum.writeNative16(buf[36..38], checksum.finish(checksum.sum(buf[20..total], acc)));
    return buf[0..total];
}

test "parse ipv4 tcp with options" {
    var buf: [256]u8 = undefined;
    const opts = [_]u8{ 2, 4, 0x05, 0xb4, 1, 3, 3, 7, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0 };
    const pkt_bytes = buildV4Tcp(&buf, "hello", 0x02, &opts);
    const p = try parse(pkt_bytes);
    try std.testing.expectEqual(@as(u8, 4), p.ip.version);
    try std.testing.expect(checksum.verifyIpv4Header(pkt_bytes[0..20]));
    try std.testing.expect(l4ChecksumValid(pkt_bytes, p));
    const t = p.l4.tcp;
    try std.testing.expectEqual(@as(u16, 40000), t.src_port);
    try std.testing.expect(t.flags.syn and !t.flags.ack);
    try std.testing.expectEqualStrings("hello", pkt_bytes[p.payload_off..][0..p.payload_len]);
    const o = parseTcpOptions(pkt_bytes[p.l4_off + 20 .. p.payload_off]);
    try std.testing.expectEqual(@as(u16, 1460), o.mss);
    try std.testing.expect(o.has_wscale and o.wscale == 7);
    try std.testing.expect(o.sack_permitted and o.has_timestamp and o.ts_val == 1);
    const k = FlowKey.fromPacket(pkt_bytes, p);
    const r = k.reversed();
    try std.testing.expect(k.symmetricHash() == r.symmetricHash());
    try std.testing.expect(!FlowKey.eql(&k, &r));
    try std.testing.expect(FlowKey.eql(&k, &r.reversed()));
}

test "parse ipv6 with extension and fragment headers" {
    var buf: [128]u8 = @splat(0);
    buf[0] = 0x60;
    buf[6] = proto.hopopts;
    buf[7] = 64;
    buf[8] = 0xfd;
    buf[23] = 1;
    buf[24] = 0xfd;
    buf[39] = 2;
    buf[40] = proto.ipv6_frag;
    buf[41] = 0;
    buf[48] = proto.udp;
    setBe16(&buf, 50, 0x0001);
    setBe32(&buf, 52, 0xabcdef01);
    setBe16(&buf, 56, 5353);
    setBe16(&buf, 58, 53);
    setBe16(&buf, 60, 12);
    const plen: u16 = 8 + 8 + 12;
    setBe16(&buf, 4, plen);
    const p = try parse(buf[0 .. 40 + plen]);
    try std.testing.expectEqual(@as(u16, 56), p.ip.header_len);
    try std.testing.expect(p.ip.frag_more and p.ip.frag_offset == 0 and p.ip.frag_id == 0xabcdef01);
    try std.testing.expectEqual(@as(u16, 5353), p.l4.udp.src_port);
    try std.testing.expectEqual(@as(u32, 4), p.payload_len);
}

test "parse rejects truncated and malformed" {
    try std.testing.expectError(error.Truncated, parse(&[_]u8{0x45}));
    try std.testing.expectError(error.BadVersion, parse(&([_]u8{0x55} ++ @as([39]u8, @splat(0)))));
    var b: [40]u8 = @splat(0);
    b[0] = 0x44;
    try std.testing.expectError(error.BadHeaderLength, parse(&b));
    b[0] = 0x45;
    setBe16(&b, 2, 60);
    try std.testing.expectError(error.Truncated, parse(&b));
}

fn fuzzParse(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [2048]u8 = undefined;
    const n = smith.slice(&buf);
    const data = buf[0..n];
    const p = parse(data) catch return;
    try std.testing.expect(p.ip.total_len <= data.len);
    try std.testing.expect(p.l4_off <= p.ip.total_len);
    try std.testing.expect(p.payload_off + p.payload_len <= p.ip.total_len);
    switch (p.l4) {
        .tcp => |t| {
            const o = parseTcpOptions(data[p.l4_off + 20 .. p.l4_off + t.header_len]);
            try std.testing.expect(o.sack_count <= 4);
        },
        else => {},
    }
    _ = FlowKey.fromPacket(data, p).hash();
}

test "fuzz parse" {
    try std.testing.fuzz({}, fuzzParse, .{});
}
