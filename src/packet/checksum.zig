const std = @import("std");
const builtin = @import("builtin");

pub const native_endian = builtin.target.cpu.arch.endian();

pub const Impl = enum { scalar, simd };

pub const default_impl: Impl = if (std.simd.suggestVectorLength(u16)) |len| (if (len >= 8) .simd else .scalar) else .scalar;

pub inline fn readNative16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, native_endian);
}

pub inline fn writeNative16(bytes: *[2]u8, value: u16) void {
    std.mem.writeInt(u16, bytes, value, native_endian);
}

inline fn addCarry(a: u64, b: u64) u64 {
    const r = @addWithOverflow(a, b);
    return r[0] +% r[1];
}

pub fn sumScalar(data: []const u8, initial: u64) u64 {
    var acc: u64 = initial;
    var i: usize = 0;
    const n = data.len;
    while (i + 32 <= n) : (i += 32) {
        acc = addCarry(acc, std.mem.readInt(u64, data[i..][0..8], native_endian));
        acc = addCarry(acc, std.mem.readInt(u64, data[i + 8 ..][0..8], native_endian));
        acc = addCarry(acc, std.mem.readInt(u64, data[i + 16 ..][0..8], native_endian));
        acc = addCarry(acc, std.mem.readInt(u64, data[i + 24 ..][0..8], native_endian));
    }
    while (i + 8 <= n) : (i += 8) {
        acc = addCarry(acc, std.mem.readInt(u64, data[i..][0..8], native_endian));
    }
    return tail(data[i..], acc);
}

inline fn tail(rest: []const u8, initial: u64) u64 {
    var acc = initial;
    var i: usize = 0;
    while (i + 2 <= rest.len) : (i += 2) {
        acc = addCarry(acc, std.mem.readInt(u16, rest[i..][0..2], native_endian));
    }
    if (i < rest.len) {
        const pad = [2]u8{ rest[i], 0 };
        acc = addCarry(acc, std.mem.readInt(u16, &pad, native_endian));
    }
    return acc;
}

const block_bytes = 64;
const block_words = block_bytes / 2;
const max_blocks_per_round = 65536;

pub fn sumSimd(data: []const u8, initial: u64) u64 {
    var acc: u64 = initial;
    var i: usize = 0;
    const n = data.len;
    while (i + block_bytes <= n) {
        var lanes: @Vector(block_words, u32) = @splat(0);
        var blocks: usize = 0;
        while (i + block_bytes <= n and blocks < max_blocks_per_round) : ({
            i += block_bytes;
            blocks += 1;
        }) {
            const words: @Vector(block_words, u16) = @bitCast(data[i..][0..block_bytes].*);
            lanes += @as(@Vector(block_words, u32), words);
        }
        const wide: @Vector(block_words, u64) = lanes;
        acc = addCarry(acc, @reduce(.Add, wide));
    }
    while (i + 8 <= n) : (i += 8) {
        acc = addCarry(acc, std.mem.readInt(u64, data[i..][0..8], native_endian));
    }
    return tail(data[i..], acc);
}

pub fn sumWith(comptime impl: Impl, data: []const u8, initial: u64) u64 {
    return switch (impl) {
        .scalar => sumScalar(data, initial),
        .simd => sumSimd(data, initial),
    };
}

pub inline fn sum(data: []const u8, initial: u64) u64 {
    return sumWith(default_impl, data, initial);
}

pub fn sumChunks(chunks: []const []const u8, initial: u64) u64 {
    var acc = initial;
    var carry: ?u8 = null;
    for (chunks) |chunk| {
        var data = chunk;
        if (data.len == 0) continue;
        if (carry) |cb| {
            const pair = [2]u8{ cb, data[0] };
            acc = addCarry(acc, std.mem.readInt(u16, &pair, native_endian));
            data = data[1..];
            carry = null;
        }
        const even = data.len & ~@as(usize, 1);
        acc = sum(data[0..even], acc);
        if (data.len & 1 == 1) carry = data[data.len - 1];
    }
    if (carry) |cb| {
        const pair = [2]u8{ cb, 0 };
        acc = addCarry(acc, std.mem.readInt(u16, &pair, native_endian));
    }
    return acc;
}

pub inline fn fold(acc: u64) u16 {
    var s = acc;
    s = (s & 0xffff_ffff) + (s >> 32);
    s = (s & 0xffff_ffff) + (s >> 32);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    return @truncate(s);
}

pub inline fn finish(acc: u64) u16 {
    return ~fold(acc);
}

pub inline fn finishUdp(acc: u64) u16 {
    const c = ~fold(acc);
    return if (c == 0) 0xffff else c;
}

pub inline fn compute(data: []const u8) u16 {
    return finish(sum(data, 0));
}

pub inline fn word(value: u16) u64 {
    var be: [2]u8 = undefined;
    std.mem.writeInt(u16, &be, value, .big);
    return std.mem.readInt(u16, &be, native_endian);
}

pub fn pseudoV4(src: *const [4]u8, dst: *const [4]u8, proto: u8, len: u32) u64 {
    var acc: u64 = 0;
    acc += std.mem.readInt(u32, src, native_endian);
    acc += std.mem.readInt(u32, dst, native_endian);
    acc += word(proto);
    acc += word(@truncate(len));
    acc += word(@truncate(len >> 16));
    return acc;
}

pub fn pseudoV6(src: *const [16]u8, dst: *const [16]u8, proto: u8, len: u32) u64 {
    var acc: u64 = 0;
    acc = addCarry(acc, std.mem.readInt(u64, src[0..8], native_endian));
    acc = addCarry(acc, std.mem.readInt(u64, src[8..16], native_endian));
    acc = addCarry(acc, std.mem.readInt(u64, dst[0..8], native_endian));
    acc = addCarry(acc, std.mem.readInt(u64, dst[8..16], native_endian));
    acc = addCarry(acc, word(proto));
    acc = addCarry(acc, word(@truncate(len)));
    acc = addCarry(acc, word(@truncate(len >> 16)));
    return acc;
}

pub fn pseudo(v6: bool, src: []const u8, dst: []const u8, proto: u8, len: u32) u64 {
    if (v6) return pseudoV6(src[0..16], dst[0..16], proto, len);
    return pseudoV4(src[0..4], dst[0..4], proto, len);
}

inline fn fold32(s: u32) u16 {
    var t = s;
    t = (t & 0xffff) + (t >> 16);
    t = (t & 0xffff) + (t >> 16);
    return @truncate(t);
}

pub inline fn update16(hc: u16, old: u16, new: u16) u16 {
    return ~fold32(@as(u32, ~hc) + @as(u32, ~old) + @as(u32, new));
}

pub inline fn updateFolded(hc: u16, old_sum: u16, new_sum: u16) u16 {
    return update16(hc, old_sum, new_sum);
}

pub fn updateBytes(hc: u16, old: []const u8, new: []const u8) u16 {
    return update16(hc, fold(sum(old, 0)), fold(sum(new, 0)));
}

pub inline fn updatePartial16(s: u16, old: u16, new: u16) u16 {
    return fold32(@as(u32, s) + @as(u32, ~old) + @as(u32, new));
}

pub fn updatePartialBytes(s: u16, old: []const u8, new: []const u8) u16 {
    return updatePartial16(s, fold(sum(old, 0)), fold(sum(new, 0)));
}

pub fn ipv4Header(hdr: []u8) void {
    hdr[10] = 0;
    hdr[11] = 0;
    writeNative16(hdr[10..12], compute(hdr));
}

pub fn verifyIpv4Header(hdr: []const u8) bool {
    return fold(sum(hdr, 0)) == 0xffff;
}

fn referenceChecksum(data: []const u8) u16 {
    var acc: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        acc += (@as(u32, data[i]) << 8) | data[i + 1];
    }
    if (i < data.len) acc += @as(u32, data[i]) << 8;
    while (acc >> 16 != 0) acc = (acc & 0xffff) + (acc >> 16);
    return ~@as(u16, @truncate(acc));
}

fn networkValue(native_value: u16) u16 {
    var b: [2]u8 = undefined;
    writeNative16(&b, native_value);
    return std.mem.readInt(u16, &b, .big);
}

test "rfc1071 example" {
    const data = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    try std.testing.expectEqual(@as(u16, 0xddf2), networkValue(fold(sum(&data, 0))));
}

test "scalar and simd match reference" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    var buf: [70000]u8 = undefined;
    r.bytes(&buf);
    const lengths = [_]usize{ 0, 1, 2, 3, 7, 8, 9, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1499, 1500, 9000, 65535, 70000 };
    for (lengths) |len| {
        const expected = referenceChecksum(buf[0..len]);
        try std.testing.expectEqual(expected, networkValue(finish(sumScalar(buf[0..len], 0))));
        try std.testing.expectEqual(expected, networkValue(finish(sumSimd(buf[0..len], 0))));
        for (1..4) |off| {
            if (len < off) continue;
            const e2 = referenceChecksum(buf[off..len]);
            try std.testing.expectEqual(e2, networkValue(finish(sumSimd(buf[off..len], 0))));
            try std.testing.expectEqual(e2, networkValue(finish(sumScalar(buf[off..len], 0))));
        }
    }
}

test "incremental update matches recompute" {
    var prng = std.Random.DefaultPrng.init(42);
    const r = prng.random();
    var pkt: [128]u8 = undefined;
    for (0..200) |_| {
        r.bytes(&pkt);
        pkt[16] = 0;
        pkt[17] = 0;
        const hc = compute(&pkt);
        writeNative16(pkt[16..18], hc);
        try std.testing.expectEqual(@as(u16, 0xffff), fold(sum(&pkt, 0)));
        const off = (r.uintLessThan(usize, 30) + 10) * 2;
        const old: [16]u8 = pkt[off..][0..16].*;
        var new: [16]u8 = undefined;
        r.bytes(&new);
        const len = (r.uintLessThan(usize, 8) + 1) * 2;
        const updated = updateBytes(readNative16(pkt[16..18]), old[0..len], new[0..len]);
        @memcpy(pkt[off..][0..len], new[0..len]);
        writeNative16(pkt[16..18], updated);
        try std.testing.expectEqual(@as(u16, 0xffff), fold(sum(&pkt, 0)));
    }
}

test "partial checksum update tracks pseudo header" {
    const src_a = [4]u8{ 10, 0, 0, 1 };
    const dst_a = [4]u8{ 192, 168, 1, 7 };
    const src_b = [4]u8{ 172, 19, 0, 2 };
    const dst_b = [4]u8{ 172, 19, 0, 1 };
    const s = fold(pseudoV4(&src_a, &dst_a, 6, 1234));
    var t = updatePartialBytes(s, &src_a, &src_b);
    t = updatePartialBytes(t, &dst_a, &dst_b);
    const expected = fold(pseudoV4(&src_b, &dst_b, 6, 1234));
    try std.testing.expect(t == expected or (t == 0 and expected == 0xffff) or (t == 0xffff and expected == 0));
}

test "pseudo header matches manual layout" {
    const src = [16]u8{ 0xfd, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
    const dst = [16]u8{ 0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var manual: [40]u8 = @splat(0);
    @memcpy(manual[0..16], &src);
    @memcpy(manual[16..32], &dst);
    std.mem.writeInt(u32, manual[32..36], 70000, .big);
    manual[39] = 17;
    try std.testing.expectEqual(fold(sum(&manual, 0)), fold(pseudoV6(&src, &dst, 17, 70000)));
    const s4 = [4]u8{ 1, 2, 3, 4 };
    const d4 = [4]u8{ 5, 6, 7, 8 };
    var m4: [12]u8 = @splat(0);
    @memcpy(m4[0..4], &s4);
    @memcpy(m4[4..8], &d4);
    m4[9] = 6;
    std.mem.writeInt(u16, m4[10..12], 40, .big);
    try std.testing.expectEqual(fold(sum(&m4, 0)), fold(pseudoV4(&s4, &d4, 6, 40)));
}

test "chunked sum matches contiguous sum" {
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    var buf: [3000]u8 = undefined;
    r.bytes(&buf);
    for (0..100) |_| {
        const a = r.uintLessThan(usize, 1000);
        const b = a + r.uintLessThan(usize, 1000);
        const chunks = [_][]const u8{ buf[0..a], buf[a..b], buf[b..] };
        try std.testing.expectEqual(fold(sum(&buf, 0)), fold(sumChunks(&chunks, 0)));
    }
}

fn fuzzChecksum(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    const n = smith.slice(&buf);
    const data = buf[0..n];
    try std.testing.expectEqual(referenceChecksum(data), networkValue(finish(sumSimd(data, 0))));
    try std.testing.expectEqual(referenceChecksum(data), networkValue(finish(sumScalar(data, 0))));
}

test "fuzz checksum implementations" {
    try std.testing.fuzz({}, fuzzChecksum, .{});
}
