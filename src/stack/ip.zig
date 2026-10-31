const std = @import("std");
const checksum = @import("../packet/checksum.zig");
const parse = @import("../packet/parse.zig");
const pool = @import("../packet/pool.zig");
const table = @import("../flow/table.zig");
const timeouts = @import("../flow/timeouts.zig");

pub const default_ttl: u8 = 64;

pub inline fn headerLen(v6: bool) u16 {
    return if (v6) 40 else 20;
}

pub fn writeIpv4(dst: []u8, src_addr: []const u8, dst_addr: []const u8, next: u8, payload_len: u32, ttl: u8, tos: u8, id: u16) void {
    dst[0] = 0x45;
    dst[1] = tos;
    parse.setBe16(dst, 2, @intCast(20 + payload_len));
    parse.setBe16(dst, 4, id);
    dst[6] = 0x40;
    dst[7] = 0;
    dst[8] = ttl;
    dst[9] = next;
    dst[10] = 0;
    dst[11] = 0;
    @memcpy(dst[12..16], src_addr[0..4]);
    @memcpy(dst[16..20], dst_addr[0..4]);
    checksum.writeNative16(dst[10..12], checksum.compute(dst[0..20]));
}

pub fn writeIpv6(dst: []u8, src_addr: []const u8, dst_addr: []const u8, next: u8, payload_len: u32, hop: u8, tclass: u8, flow_label: u32) void {
    parse.setBe32(dst, 0, (@as(u32, 6) << 28) | (@as(u32, tclass) << 20) | (flow_label & 0x000f_ffff));
    parse.setBe16(dst, 4, @intCast(@min(payload_len, 0xffff)));
    dst[6] = next;
    dst[7] = hop;
    @memcpy(dst[8..24], src_addr[0..16]);
    @memcpy(dst[24..40], dst_addr[0..16]);
}

pub fn writeHeader(dst: []u8, v6: bool, src_addr: []const u8, dst_addr: []const u8, next: u8, payload_len: u32, id: u16) u16 {
    if (v6) {
        writeIpv6(dst, src_addr, dst_addr, next, payload_len, default_ttl, 0, 0);
        return 40;
    }
    writeIpv4(dst, src_addr, dst_addr, next, payload_len, default_ttl, 0, id);
    return 20;
}

pub const FragKey = extern struct {
    src: [16]u8 = @splat(0),
    dst: [16]u8 = @splat(0),
    id: u32 = 0,
    proto: u8 = 0,
    v6: u8 = 0,
    pad: [2]u8 = @splat(0),

    pub fn hash(k: *const FragKey) u64 {
        const b: *const [40]u8 = @ptrCast(k);
        return parse.mix5(
            std.mem.readInt(u64, b[0..8], .little),
            std.mem.readInt(u64, b[8..16], .little),
            std.mem.readInt(u64, b[16..24], .little),
            std.mem.readInt(u64, b[24..32], .little),
            std.mem.readInt(u64, b[32..40], .little),
        );
    }
};

const FragContext = struct {
    pub fn hash(k: *const FragKey) u64 {
        return k.hash();
    }
    pub fn eql(a: *const FragKey, b: *const FragKey) bool {
        return std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b));
    }
};

pub const max_pieces = 48;
pub const max_datagram: u32 = 65535;

pub const Datagram = struct {
    buf: ?*pool.Buffer = null,
    header_len: u16 = 0,
    next_hdr_off: u16 = 0,
    total: u32 = 0,
    have_last: bool = false,
    have_first: bool = false,
    ranges: [max_pieces]Range = undefined,
    range_count: u8 = 0,
    timer: timeouts.Timer = .{},

    const Range = struct { start: u32, end: u32 };

    fn addRange(d: *Datagram, start: u32, end: u32) bool {
        var s = start;
        var e = end;
        var out: [max_pieces]Range = undefined;
        var n: usize = 0;
        var inserted = false;
        for (d.ranges[0..d.range_count]) |r| {
            if (r.end < s) {
                out[n] = r;
                n += 1;
            } else if (r.start > e) {
                if (!inserted) {
                    if (n == max_pieces) return false;
                    out[n] = .{ .start = s, .end = e };
                    n += 1;
                    inserted = true;
                }
                if (n == max_pieces) return false;
                out[n] = r;
                n += 1;
            } else {
                s = @min(s, r.start);
                e = @max(e, r.end);
            }
        }
        if (!inserted) {
            if (n == max_pieces) return false;
            out[n] = .{ .start = s, .end = e };
            n += 1;
        }
        @memcpy(d.ranges[0..n], out[0..n]);
        d.range_count = @intCast(n);
        return true;
    }

    fn complete(d: *const Datagram) bool {
        return d.have_last and d.have_first and d.range_count == 1 and d.ranges[0].start == 0 and d.ranges[0].end == d.total;
    }
};

pub const Stats = struct {
    completed: u64 = 0,
    dropped: u64 = 0,
    evicted: u64 = 0,
};

pub const Reassembler = struct {
    datagrams: table.Table(FragKey, Datagram, FragContext),
    big_pool: ?pool.Pool,
    timeout_ms: u32,
    stats: Stats = .{},

    pub fn init(allocator: std.mem.Allocator, max: u32, worker_buffer_size: u32, timeout_ms: u32) !Reassembler {
        const needs_big = worker_buffer_size < max_datagram + pool.default_headroom + 64;
        return .{
            .datagrams = try table.Table(FragKey, Datagram, FragContext).init(allocator, @max(max, 1)),
            .big_pool = if (needs_big) try pool.Pool.init(allocator, .{ .count = @max(max, 1), .buffer_size = max_datagram + pool.default_headroom + 64 }) else null,
            .timeout_ms = timeout_ms,
        };
    }

    pub fn deinit(r: *Reassembler, allocator: std.mem.Allocator, p: *pool.Pool) void {
        var it = r.datagrams.iterator();
        while (it.next()) |i| {
            if (r.datagrams.value(i).buf) |b| p.put(b);
        }
        r.datagrams.deinit(allocator);
        if (r.big_pool) |*bp| bp.deinit();
    }

    fn release(r: *Reassembler, wheel: *timeouts.Wheel, p: *pool.Pool, index: table.Index) void {
        const d = r.datagrams.value(index);
        wheel.cancel(&d.timer);
        if (d.buf) |b| p.put(b);
        d.buf = null;
        r.datagrams.remove(index);
    }

    pub fn expire(r: *Reassembler, p: *pool.Pool, t: *timeouts.Timer) void {
        const d: *Datagram = @alignCast(@fieldParentPtr("timer", t));
        const index = r.datagrams.indexOfValue(d);
        if (d.buf) |b| p.put(b);
        d.buf = null;
        r.datagrams.remove(index);
        r.stats.dropped += 1;
    }

    pub fn owner(t: *timeouts.Timer) *Datagram {
        return @alignCast(@fieldParentPtr("timer", t));
    }

    fn v6NextHeaderOffset(data: []const u8, frag_off: usize) ?u16 {
        var ptr: usize = 6;
        var off: usize = 40;
        var next = data[6];
        var guard: u8 = 0;
        while (off < frag_off and guard < 12) : (guard += 1) {
            if (off + 2 > data.len) return null;
            const len: usize = switch (next) {
                parse.proto.ah => (@as(usize, data[off + 1]) + 2) * 4,
                else => (@as(usize, data[off + 1]) + 1) * 8,
            };
            ptr = off;
            next = data[off];
            off += len;
        }
        if (off != frag_off or next != parse.proto.ipv6_frag) return null;
        return @intCast(ptr);
    }

    pub fn insert(r: *Reassembler, wheel: *timeouts.Wheel, p: *pool.Pool, now_ms: u64, b: *pool.Buffer, pkt: parse.Packet, timer_kind: u8) ?*pool.Buffer {
        defer p.put(b);
        const data = b.bytes();
        const ip = pkt.ip;
        const v6 = ip.isV6();
        var key: FragKey = .{ .id = ip.frag_id, .proto = ip.next, .v6 = @intFromBool(v6) };
        const al = ip.addrLen();
        @memcpy(key.src[0..al], ip.src(data));
        @memcpy(key.dst[0..al], ip.dst(data));
        const unfrag_len: u32 = if (v6) ip.frag_header_off else ip.header_len;
        const payload_off: u32 = ip.header_len;
        const payload_len: u32 = ip.total_len - payload_off;
        const start: u32 = @as(u32, ip.frag_offset) * 8;
        const end: u32 = start + payload_len;
        if (end + unfrag_len > max_datagram + 40 or (ip.frag_more and payload_len % 8 != 0) or payload_len == 0) {
            r.stats.dropped += 1;
            return null;
        }
        const index = r.datagrams.find(&key) orelse blk: {
            if (r.datagrams.isFull()) {
                if (r.datagrams.oldest()) |old| {
                    r.release(wheel, p, old);
                    r.stats.evicted += 1;
                }
            }
            const i = r.datagrams.insert(key, .{}) catch {
                r.stats.dropped += 1;
                return null;
            };
            const d = r.datagrams.value(i);
            d.timer = .{ .kind = timer_kind };
            wheel.schedule(&d.timer, now_ms + r.timeout_ms);
            break :blk i;
        };
        const d = r.datagrams.value(index);
        if (d.buf == null) {
            const nb = (if (r.big_pool) |*bp| bp.get() else p.get()) orelse {
                r.release(wheel, p, index);
                r.stats.dropped += 1;
                return null;
            };
            d.buf = nb;
        }
        const buf = d.buf.?;
        const base = buf.headroom();
        const limit = buf.cap - base;
        if (ip.frag_offset == 0) {
            if (d.have_first and d.header_len != unfrag_len) {
                r.release(wheel, p, index);
                r.stats.dropped += 1;
                return null;
            }
            if (d.have_first == false and d.range_count > 0 and d.header_len != unfrag_len) {
                const shift_len = d.ranges[d.range_count - 1].end;
                if (unfrag_len + shift_len > limit) {
                    r.release(wheel, p, index);
                    return null;
                }
                @memmove(buf.ptr[base + unfrag_len ..][0..shift_len], buf.ptr[base + d.header_len ..][0..shift_len]);
            }
            @memcpy(buf.ptr[base..][0..unfrag_len], data[0..unfrag_len]);
            d.header_len = @intCast(unfrag_len);
            d.have_first = true;
            if (v6) {
                d.next_hdr_off = v6NextHeaderOffset(data, ip.frag_header_off) orelse {
                    r.release(wheel, p, index);
                    r.stats.dropped += 1;
                    return null;
                };
            }
        } else if (!d.have_first and d.header_len == 0) {
            d.header_len = @intCast(unfrag_len);
        }
        if (d.header_len + end > limit) {
            r.release(wheel, p, index);
            r.stats.dropped += 1;
            return null;
        }
        @memcpy(buf.ptr[base + d.header_len + start ..][0..payload_len], data[payload_off..][0..payload_len]);
        if (!ip.frag_more) {
            if (d.have_last and d.total != end) {
                r.release(wheel, p, index);
                r.stats.dropped += 1;
                return null;
            }
            d.have_last = true;
            d.total = end;
        }
        if (!d.addRange(start, end)) {
            r.release(wheel, p, index);
            r.stats.dropped += 1;
            return null;
        }
        if (!d.complete()) return null;
        const out = buf;
        d.buf = null;
        const hl = d.header_len;
        const total = d.total;
        const next_off = d.next_hdr_off;
        r.release(wheel, p, index);
        out.off = base;
        out.len = hl + total;
        const bytes = out.bytes();
        if (v6) {
            bytes[next_off] = key.proto;
            parse.setBe16(bytes, 4, @intCast(@min(out.len - 40, 0xffff)));
        } else {
            parse.setBe16(bytes, 2, @intCast(out.len));
            parse.setBe16(bytes, 6, 0);
            checksum.ipv4Header(bytes[0..hl]);
        }
        r.stats.completed += 1;
        return out;
    }
};

fn makeV4Fragment(buf: []u8, id: u16, off8: u16, more: bool, payload: []const u8) []u8 {
    const total = 20 + payload.len;
    writeIpv4(buf, &[_]u8{ 10, 0, 0, 1 }, &[_]u8{ 10, 0, 0, 2 }, parse.proto.udp, @intCast(payload.len), 64, 0, id);
    parse.setBe16(buf, 6, (off8 & 0x1fff) | (if (more) @as(u16, 0x2000) else 0));
    checksum.ipv4Header(buf[0..20]);
    @memcpy(buf[20..total], payload);
    return buf[0..total];
}

test "reassemble out of order ipv4 fragments" {
    var p = try pool.Pool.init(std.testing.allocator, .{ .count = 16, .buffer_size = 2048 });
    defer p.deinit();
    var r = try Reassembler.init(std.testing.allocator, 4, 2048, 5000);
    defer r.deinit(std.testing.allocator, &p);
    var wheel = timeouts.Wheel.init(0);
    var prng = std.Random.DefaultPrng.init(5);
    var payload: [3000]u8 = undefined;
    prng.random().bytes(&payload);
    parse.setBe16(&payload, 4, 3000);
    const pieces = [_]struct { off: usize, len: usize }{ .{ .off = 1480, .len = 1480 }, .{ .off = 2960, .len = 40 }, .{ .off = 0, .len = 1480 } };
    var result: ?*pool.Buffer = null;
    for (pieces) |pc| {
        const b = p.get().?;
        const frag = makeV4Fragment(b.tail(), 77, @intCast(pc.off / 8), pc.off + pc.len < 3000, payload[pc.off..][0..pc.len]);
        b.len = @intCast(frag.len);
        const pk = try parse.parse(b.bytes());
        try std.testing.expect(pk.ip.isFragment());
        result = r.insert(&wheel, &p, 0, b, pk, 9);
    }
    const out = result.?;
    defer p.put(out);
    const full = try parse.parse(out.bytes());
    try std.testing.expect(!full.ip.isFragment());
    try std.testing.expectEqual(@as(u32, 3020), full.ip.total_len);
    try std.testing.expect(checksum.verifyIpv4Header(out.bytes()[0..20]));
    try std.testing.expectEqualSlices(u8, &payload, out.bytes()[20..3020]);
    try std.testing.expectEqual(@as(u32, 0), r.datagrams.len);
    try std.testing.expectEqual(@as(usize, 0), wheel.count);
}

test "fragment timeout releases buffers" {
    var p = try pool.Pool.init(std.testing.allocator, .{ .count = 16, .buffer_size = 2048 });
    defer p.deinit();
    var r = try Reassembler.init(std.testing.allocator, 2, 2048, 1000);
    defer r.deinit(std.testing.allocator, &p);
    var wheel = timeouts.Wheel.init(0);
    const b = p.get().?;
    var payload: [800]u8 = @splat(1);
    const frag = makeV4Fragment(b.tail(), 5, 0, true, &payload);
    b.len = @intCast(frag.len);
    const pk = try parse.parse(b.bytes());
    try std.testing.expect(r.insert(&wheel, &p, 0, b, pk, 9) == null);
    try std.testing.expectEqual(@as(u32, 1), r.datagrams.len);
    const Ctx = struct {
        r: *Reassembler,
        w: *timeouts.Wheel,
        p: *pool.Pool,
        fn onExpire(self: *@This(), t: *timeouts.Timer) void {
            self.r.expire(self.p, t);
        }
    };
    var ctx: Ctx = .{ .r = &r, .w = &wheel, .p = &p };
    wheel.advance(2000, &ctx, Ctx.onExpire);
    try std.testing.expectEqual(@as(u32, 0), r.datagrams.len);
    try std.testing.expectEqual(@as(u32, 0), p.in_use);
}
