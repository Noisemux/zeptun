const std = @import("std");
const zeptun = @import("zeptun");

const parse = zeptun.packet.parse;
const checksum = zeptun.packet.checksum;
const gso = zeptun.packet.gso;
const pool = zeptun.packet.pool;
const nat = zeptun.flow.nat;
const sys = zeptun.io.sys;

pub const LinkType = enum(u32) {
    null_bsd = 0,
    ethernet = 1,
    raw_legacy = 12,
    raw = 101,
    linux_sll = 113,
    ipv4 = 228,
    ipv6 = 229,
    linux_sll2 = 276,
    _,
};

pub const Reader = struct {
    data: []const u8,
    pos: usize,
    endian: std.lang.Endian,
    link: LinkType,

    pub const Record = struct {
        captured: []const u8,
        original_len: u32,
    };

    pub fn init(data: []const u8) !Reader {
        if (data.len < 24) return error.Truncated;
        const endian: std.lang.Endian = switch (std.mem.readInt(u32, data[0..4], .little)) {
            0xa1b2c3d4, 0xa1b23c4d => .little,
            0xd4c3b2a1, 0x4d3cb2a1 => .big,
            else => return error.NotPcap,
        };
        const link = std.mem.readInt(u32, data[20..24], endian) & 0x0fff_ffff;
        return .{ .data = data, .pos = 24, .endian = endian, .link = @fromBackingInt(@intCast(link)) };
    }

    pub fn next(r: *Reader) !?Record {
        if (r.pos == r.data.len) return null;
        if (r.data.len - r.pos < 16) return error.Truncated;
        const hdr = r.data[r.pos..][0..16];
        const captured_len = std.mem.readInt(u32, hdr[8..12], r.endian);
        const original_len = std.mem.readInt(u32, hdr[12..16], r.endian);
        r.pos += 16;
        if (r.data.len - r.pos < captured_len) return error.Truncated;
        const captured = r.data[r.pos..][0..captured_len];
        r.pos += captured_len;
        return .{ .captured = captured, .original_len = original_len };
    }

    pub fn ipPacket(r: *const Reader, frame: []const u8) ?[]const u8 {
        return switch (r.link) {
            .raw, .raw_legacy, .ipv4, .ipv6 => frame,
            .null_bsd => if (frame.len > 4) frame[4..] else null,
            .ethernet => blk: {
                if (frame.len < 14) break :blk null;
                var off: usize = 12;
                var ethertype = std.mem.readInt(u16, frame[12..14], .big);
                while (ethertype == 0x8100 or ethertype == 0x88a8) {
                    off += 4;
                    if (frame.len < off + 2) break :blk null;
                    ethertype = std.mem.readInt(u16, frame[off..][0..2], .big);
                }
                if (ethertype != 0x0800 and ethertype != 0x86dd) break :blk null;
                break :blk frame[off + 2 ..];
            },
            .linux_sll => blk: {
                if (frame.len < 16) break :blk null;
                const proto = std.mem.readInt(u16, frame[14..16], .big);
                if (proto != 0x0800 and proto != 0x86dd) break :blk null;
                break :blk frame[16..];
            },
            .linux_sll2 => blk: {
                if (frame.len < 20) break :blk null;
                const proto = std.mem.readInt(u16, frame[0..2], .big);
                if (proto != 0x0800 and proto != 0x86dd) break :blk null;
                break :blk frame[20..];
            },
            _ => null,
        };
    }
};

pub const Stats = struct {
    records: u64 = 0,
    bytes: u64 = 0,
    tcp: u64 = 0,
    udp: u64 = 0,
    icmp: u64 = 0,
    other: u64 = 0,
    truncated: u64 = 0,
    malformed: u64 = 0,
    bad_checksum: u64 = 0,
    repaired: u64 = 0,
    rewrites: u64 = 0,
    coalesced: u64 = 0,
    segments: u64 = 0,
    failures: u64 = 0,
    seconds: f64 = 0,
};

const Replayer = struct {
    pool: pool.Pool,
    coal: gso.Coalescer(64) = .{},
    stats: Stats = .{},
    scratch: [pool.max_super_packet + 256]u8 = undefined,
    payload_in: u64 = 0,
    payload_out: u64 = 0,

    fn flush(rp: *Replayer) void {
        for (rp.coal.items[0..rp.coal.count]) |*it| {
            const vh = gso.Coalescer(64).finalize(it);
            rp.verifySegments(it.buf.bytes(), vh);
            rp.pool.put(it.buf);
        }
        rp.coal.reset();
    }

    fn verifySegments(rp: *Replayer, pkt: []const u8, vh: gso.VirtioNetHdr) void {
        var seg = gso.Segmenter.init(pkt, vh, true) catch {
            rp.stats.failures += 1;
            return;
        };
        while (true) {
            const out = seg.next(&rp.scratch) catch {
                rp.stats.failures += 1;
                return;
            } orelse return;
            const p = parse.parse(out) catch {
                rp.stats.failures += 1;
                return;
            };
            if (!parse.l4ChecksumValid(out, p)) rp.stats.failures += 1;
            if (p.ip.version == 4 and !checksum.verifyIpv4Header(out[0..p.ip.header_len])) rp.stats.failures += 1;
            rp.payload_out += p.payload_len;
            rp.stats.segments += 1;
        }
    }

    fn rewriteCheck(rp: *Replayer, data: []const u8, pkt: parse.Packet) void {
        const copy = rp.scratch[0..data.len];
        @memcpy(copy, data);
        const al = pkt.ip.addrLen();
        var src: [16]u8 = @splat(0x5a);
        var dst: [16]u8 = @splat(0xa5);
        src[0] = 10;
        dst[0] = 172;
        nat.rewrite(copy, pkt, .{ .src = src[0..al], .dst = dst[0..al], .src_port = 20001, .dst_port = 7000 }, false);
        const p2 = parse.parse(copy) catch {
            rp.stats.failures += 1;
            return;
        };
        if (!parse.l4ChecksumValid(copy, p2)) rp.stats.failures += 1;
        if (p2.ip.version == 4 and !checksum.verifyIpv4Header(copy[0..p2.ip.header_len])) rp.stats.failures += 1;
        rp.stats.rewrites += 1;
    }

    fn feed(rp: *Replayer, data: []const u8) void {
        const first = parse.parse(data) catch {
            rp.stats.malformed += 1;
            return;
        };
        switch (first.l4) {
            .tcp => rp.stats.tcp += 1,
            .udp => rp.stats.udp += 1,
            .icmp => {
                rp.stats.icmp += 1;
                return;
            },
            .other => {
                rp.stats.other += 1;
                return;
            },
        }
        if (first.ip.isFragment()) return;
        const b = rp.pool.get() orelse {
            rp.flush();
            return;
        };
        if (data.len > b.tailroom()) {
            rp.pool.put(b);
            return;
        }
        @memcpy(b.tail()[0..data.len], data);
        b.len = @intCast(data.len);
        const bytes = b.bytes();
        const pkt = parse.parse(bytes) catch unreachable;
        if (!parse.l4ChecksumValid(bytes, pkt)) {
            rp.stats.bad_checksum += 1;
            const field = pkt.l4_off + @as(usize, if (pkt.l4 == .tcp) 16 else 6);
            gso.setFullChecksum(bytes, pkt.ip, pkt.ip.next, field);
            if (pkt.ip.version == 4) checksum.ipv4Header(bytes[0..pkt.ip.header_len]);
            if (!parse.l4ChecksumValid(bytes, pkt)) {
                rp.stats.failures += 1;
                rp.pool.put(b);
                return;
            }
            rp.stats.repaired += 1;
        }
        rp.rewriteCheck(bytes, pkt);
        rp.payload_in += pkt.payload_len;
        while (true) {
            switch (rp.coal.add(&rp.pool, b)) {
                .merged => {
                    rp.stats.coalesced += 1;
                    return;
                },
                .inserted => return,
                .full => rp.flush(),
                .rejected => {
                    rp.verifySegments(b.bytes(), .{});
                    rp.pool.put(b);
                    return;
                },
            }
        }
    }
};

pub fn run(allocator: std.mem.Allocator, data: []const u8, loops: u32) !Stats {
    const rp = try allocator.create(Replayer);
    defer allocator.destroy(rp);
    rp.* = .{ .pool = try pool.Pool.init(allocator, .{ .count = 256, .buffer_size = pool.max_super_packet + pool.default_headroom + 1 }) };
    defer rp.pool.deinit();
    const start = sys.monotonicNs();
    var loop: u32 = 0;
    while (loop < @max(loops, 1)) : (loop += 1) {
        var reader = try Reader.init(data);
        while (try reader.next()) |rec| {
            rp.stats.records += 1;
            rp.stats.bytes += rec.captured.len;
            const ip = reader.ipPacket(rec.captured) orelse {
                rp.stats.other += 1;
                continue;
            };
            if (rec.original_len > rec.captured.len) {
                rp.stats.truncated += 1;
                continue;
            }
            rp.feed(ip);
        }
        rp.flush();
    }
    rp.stats.seconds = @as(f64, @floatFromInt(sys.monotonicNs() - start)) / 1e9;
    if (rp.payload_in != rp.payload_out) rp.stats.failures += 1;
    return rp.stats;
}

fn appendRecord(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame: []const u8) !void {
    var hdr: [16]u8 = @splat(0);
    std.mem.writeInt(u32, hdr[8..12], @intCast(frame.len), .little);
    std.mem.writeInt(u32, hdr[12..16], @intCast(frame.len), .little);
    try list.appendSlice(allocator, &hdr);
    try list.appendSlice(allocator, frame);
}

fn tcpPacket(buf: []u8, seq: u32, payload: []const u8) []u8 {
    const total = 40 + payload.len;
    @memset(buf[0..40], 0);
    buf[0] = 0x45;
    parse.setBe16(buf, 2, @intCast(total));
    buf[6] = 0x40;
    buf[8] = 64;
    buf[9] = parse.proto.tcp;
    @memcpy(buf[12..16], &[_]u8{ 192, 168, 7, 2 });
    @memcpy(buf[16..20], &[_]u8{ 93, 184, 216, 34 });
    checksum.ipv4Header(buf[0..20]);
    parse.setBe16(buf, 20, 51000);
    parse.setBe16(buf, 22, 443);
    parse.setBe32(buf, 24, seq);
    parse.setBe32(buf, 28, 77);
    buf[32] = 0x50;
    buf[33] = 0x10;
    parse.setBe16(buf, 34, 4096);
    @memcpy(buf[40..total], payload);
    const ip = parse.parseIp(buf[0..total]) catch unreachable;
    gso.setFullChecksum(buf[0..total], ip, parse.proto.tcp, 36);
    return buf[0..total];
}

test "pcap reader handles ethernet and raw link types and replay verifies gso roundtrip" {
    const allocator = std.testing.allocator;
    var payload: [1400]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    for ([_]LinkType{ .raw, .ethernet, .linux_sll }) |link| {
        var file: std.ArrayList(u8) = .empty;
        defer file.deinit(allocator);
        var global: [24]u8 = @splat(0);
        std.mem.writeInt(u32, global[0..4], 0xa1b2c3d4, .little);
        std.mem.writeInt(u16, global[4..6], 2, .little);
        std.mem.writeInt(u16, global[6..8], 4, .little);
        std.mem.writeInt(u32, global[16..20], 65535, .little);
        std.mem.writeInt(u32, global[20..24], @backingInt(link), .little);
        try file.appendSlice(allocator, &global);
        var seq: u32 = 1000;
        var i: usize = 0;
        while (i < 6) : (i += 1) {
            var buf: [1600]u8 = undefined;
            const pkt = tcpPacket(&buf, seq, &payload);
            seq +%= payload.len;
            var frame: [1700]u8 = undefined;
            const prefix: usize = switch (link) {
                .ethernet => 14,
                .linux_sll => 16,
                else => 0,
            };
            @memset(frame[0..prefix], 0);
            if (link == .ethernet) std.mem.writeInt(u16, frame[12..14], 0x0800, .big);
            if (link == .linux_sll) std.mem.writeInt(u16, frame[14..16], 0x0800, .big);
            @memcpy(frame[prefix..][0..pkt.len], pkt);
            try appendRecord(&file, allocator, frame[0 .. prefix + pkt.len]);
        }
        const stats = try run(allocator, file.items, 2);
        try std.testing.expectEqual(@as(u64, 12), stats.records);
        try std.testing.expectEqual(@as(u64, 12), stats.tcp);
        try std.testing.expectEqual(@as(u64, 0), stats.failures);
        try std.testing.expectEqual(@as(u64, 0), stats.malformed);
        try std.testing.expectEqual(@as(u64, 10), stats.coalesced);
        try std.testing.expectEqual(@as(u64, 12), stats.segments);
        try std.testing.expectEqual(@as(u64, 12), stats.rewrites);
    }
    try std.testing.expectError(error.NotPcap, Reader.init(&@as([24]u8, @splat(0))));
}
