const std = @import("std");
const addr = @import("../addr.zig");
const sys = @import("../io/sys.zig");
const checksum = @import("../packet/checksum.zig");
const parse = @import("../packet/parse.zig");
const pool = @import("../packet/pool.zig");
const gso = @import("../packet/gso.zig");
const ip = @import("ip.zig");

pub const max_name = 253;
pub const port: u16 = 53;

const nil: u32 = std.math.maxInt(u32);
const chunk_len = 256;

const type_a: u16 = 1;
const type_aaaa: u16 = 28;
const class_in: u16 = 1;

const SpinLock = struct {
    locked: std.atomic.Value(bool) = .init(false),

    fn lock(l: *SpinLock) void {
        var spins: u32 = 0;
        while (l.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            spins += 1;
            if (spins < 64) {
                std.atomic.spinLoopHint();
            } else {
                spins = 0;
                std.Thread.yield() catch {};
            }
        }
    }

    fn unlock(l: *SpinLock) void {
        l.locked.store(false, .release);
    }
};

pub const Mapping = struct {
    index: u32,
    gen: u32,
};

pub const Table = struct {
    const Entry = struct {
        name: [max_name]u8 = undefined,
        len: u8 = 0,
        gen: u32 = 0,
        hash: u32 = 0,
        prev: u32 = nil,
        next: u32 = nil,
    };

    lock: SpinLock = .{},
    allocator: std.mem.Allocator,
    range4: ?addr.Prefix,
    range6: ?addr.Prefix,
    capacity: u32,
    ttl: u32,
    chunks: []?*[chunk_len]Entry,
    slots: []u32,
    used: u32 = 0,
    head: u32 = nil,
    tail: u32 = nil,

    pub fn init(allocator: std.mem.Allocator, range4: ?addr.Prefix, range6: ?addr.Prefix, cache_size: u32, ttl: u32) !*Table {
        if (range4 == null and range6 == null) return error.InvalidArgument;
        var cap: u64 = @max(cache_size, 16);
        if (range4) |r| {
            if (r.bits > 30) return error.InvalidArgument;
            cap = @min(cap, (@as(u64, 1) << @intCast(32 - r.bits)) - 2);
        }
        if (range6) |r| {
            if (r.bits > 126) return error.InvalidArgument;
            if (128 - r.bits < 40) cap = @min(cap, (@as(u64, 1) << @intCast(128 - r.bits)) - 2);
        }
        cap = @min(cap, 1 << 22);
        const t = try allocator.create(Table);
        errdefer allocator.destroy(t);
        const nchunks = (cap + chunk_len - 1) / chunk_len;
        const chunks = try allocator.alloc(?*[chunk_len]Entry, @intCast(nchunks));
        errdefer allocator.free(chunks);
        @memset(chunks, null);
        const nslots = std.math.ceilPowerOfTwo(u64, cap * 2) catch return error.OutOfMemory;
        const slots = try allocator.alloc(u32, @intCast(nslots));
        @memset(slots, 0);
        t.* = .{
            .allocator = allocator,
            .range4 = if (range4) |r| r.masked() else null,
            .range6 = if (range6) |r| r.masked() else null,
            .capacity = @intCast(cap),
            .ttl = ttl,
            .chunks = chunks,
            .slots = slots,
        };
        return t;
    }

    pub fn deinit(t: *Table) void {
        for (t.chunks) |c| if (c) |p| t.allocator.destroy(p);
        t.allocator.free(t.chunks);
        t.allocator.free(t.slots);
        t.allocator.destroy(t);
    }

    inline fn entry(t: *Table, i: u32) *Entry {
        return &t.chunks[i / chunk_len].?[i % chunk_len];
    }

    fn unlink(t: *Table, i: u32) void {
        const e = t.entry(i);
        if (e.prev != nil) t.entry(e.prev).next = e.next else t.head = e.next;
        if (e.next != nil) t.entry(e.next).prev = e.prev else t.tail = e.prev;
        e.prev = nil;
        e.next = nil;
    }

    fn pushTail(t: *Table, i: u32) void {
        const e = t.entry(i);
        e.prev = t.tail;
        e.next = nil;
        if (t.tail != nil) t.entry(t.tail).next = i else t.head = i;
        t.tail = i;
    }

    fn touch(t: *Table, i: u32) void {
        if (t.tail == i) return;
        t.unlink(i);
        t.pushTail(i);
    }

    fn hashName(name: []const u8) u32 {
        return @truncate(std.hash.Wyhash.hash(0x7a65_7074_756e, name));
    }

    fn findSlot(t: *Table, name: []const u8, h: u32) ?usize {
        const mask = t.slots.len - 1;
        var s: usize = h & mask;
        while (t.slots[s] != 0) : (s = (s + 1) & mask) {
            const i = t.slots[s] - 1;
            const e = t.entry(i);
            if (e.hash == h and e.len == name.len and std.mem.eql(u8, e.name[0..e.len], name)) return s;
        }
        return null;
    }

    fn insertSlot(t: *Table, i: u32, h: u32) void {
        const mask = t.slots.len - 1;
        var s: usize = h & mask;
        while (t.slots[s] != 0) s = (s + 1) & mask;
        t.slots[s] = i + 1;
    }

    fn removeSlot(t: *Table, slot: usize) void {
        const mask = t.slots.len - 1;
        var hole = slot;
        var s = (slot + 1) & mask;
        while (t.slots[s] != 0) : (s = (s + 1) & mask) {
            const home = t.entry(t.slots[s] - 1).hash & mask;
            if (((hole -% home) & mask) < ((s -% home) & mask)) {
                t.slots[hole] = t.slots[s];
                hole = s;
            }
        }
        t.slots[hole] = 0;
    }

    pub fn resolve(t: *Table, name: []const u8) ?Mapping {
        if (name.len == 0 or name.len > max_name) return null;
        const h = hashName(name);
        t.lock.lock();
        defer t.lock.unlock();
        if (t.findSlot(name, h)) |s| {
            const i = t.slots[s] - 1;
            t.touch(i);
            return .{ .index = i, .gen = t.entry(i).gen };
        }
        var i: u32 = undefined;
        if (t.used < t.capacity) {
            i = t.used;
            const ci = i / chunk_len;
            if (t.chunks[ci] == null) {
                const c = t.allocator.create([chunk_len]Entry) catch return null;
                for (c) |*e| {
                    e.len = 0;
                    e.gen = 0;
                    e.hash = 0;
                    e.prev = nil;
                    e.next = nil;
                }
                t.chunks[ci] = c;
            }
            t.used += 1;
        } else {
            i = t.head;
            const old = t.entry(i);
            const old_slot = t.findSlot(old.name[0..old.len], old.hash) orelse unreachable;
            t.removeSlot(old_slot);
            t.unlink(i);
        }
        const e = t.entry(i);
        @memcpy(e.name[0..name.len], name);
        e.len = @intCast(name.len);
        e.hash = h;
        e.gen +%= 1;
        t.insertSlot(i, h);
        t.pushTail(i);
        return .{ .index = i, .gen = e.gen };
    }

    pub fn contains(t: *const Table, a: addr.Address) bool {
        if (a.family == .v4) return if (t.range4) |r| r.contains(a) else false;
        return if (t.range6) |r| r.contains(a) else false;
    }

    pub fn indexOf(t: *const Table, a: addr.Address) ?u32 {
        const r = (if (a.family == .v4) t.range4 else t.range6) orelse return null;
        if (!r.contains(a)) return null;
        const base: u128 = if (a.family == .v4) std.mem.readInt(u32, r.addr.bytes[0..4], .big) else std.mem.readInt(u128, &r.addr.bytes, .big);
        const value: u128 = if (a.family == .v4) std.mem.readInt(u32, a.bytes[0..4], .big) else std.mem.readInt(u128, &a.bytes, .big);
        const off = value - base;
        if (off == 0 or off > t.capacity) return null;
        return @intCast(off - 1);
    }

    pub fn address(t: *const Table, family: addr.Family, index: u32) ?addr.Address {
        const r = (if (family == .v4) t.range4 else t.range6) orelse return null;
        return r.host(index + 1);
    }

    pub fn mappingOf(t: *Table, a: addr.Address) ?Mapping {
        const i = t.indexOf(a) orelse return null;
        t.lock.lock();
        defer t.lock.unlock();
        if (i >= t.used) return null;
        const e = t.entry(i);
        if (e.len == 0) return null;
        t.touch(i);
        return .{ .index = i, .gen = e.gen };
    }

    pub fn nameOf(t: *Table, a: addr.Address, out: *[max_name]u8) ?[]const u8 {
        const i = t.indexOf(a) orelse return null;
        t.lock.lock();
        defer t.lock.unlock();
        if (i >= t.used) return null;
        const e = t.entry(i);
        if (e.len == 0) return null;
        @memcpy(out[0..e.len], e.name[0..e.len]);
        return out[0..e.len];
    }

    pub fn copyName(t: *Table, m: Mapping, out: *[max_name]u8) ?[]const u8 {
        t.lock.lock();
        defer t.lock.unlock();
        if (m.index >= t.used) return null;
        const e = t.entry(m.index);
        if (e.gen != m.gen or e.len == 0) return null;
        @memcpy(out[0..e.len], e.name[0..e.len]);
        return out[0..e.len];
    }
};

pub const Outcome = union(enum) {
    reply: usize,
    forward,
    drop,
};

inline fn be16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .big);
}

inline fn putBe16(b: []u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, b[off..][0..2], v, .big);
}

fn finishHeader(out: []u8, query_flags: u16, rcode: u16, answers: u16) void {
    const flags: u16 = 0x8000 | (query_flags & 0x7900) | 0x0080 | rcode;
    putBe16(out, 2, flags);
    putBe16(out, 4, 1);
    putBe16(out, 6, answers);
    putBe16(out, 8, 0);
    putBe16(out, 10, 0);
}

pub fn answer(t: *Table, query: []const u8, out: []u8, can_forward: bool) Outcome {
    if (query.len < 12 or out.len < 12) return .drop;
    const flags = be16(query, 2);
    if (flags & 0x8000 != 0) return .drop;
    const opcode = (flags >> 11) & 0xf;
    if (opcode != 0 or be16(query, 4) != 1) return if (can_forward) .forward else .drop;
    var name: [max_name]u8 = undefined;
    var nlen: usize = 0;
    var off: usize = 12;
    var bad = false;
    while (true) {
        if (off >= query.len) return .drop;
        const l = query[off];
        off += 1;
        if (l == 0) break;
        if (l & 0xc0 != 0) return .drop;
        if (off + l > query.len) return .drop;
        if (nlen != 0) {
            if (nlen >= max_name) return .drop;
            name[nlen] = '.';
            nlen += 1;
        }
        if (nlen + l > max_name) return .drop;
        for (query[off..][0..l]) |ch| {
            if (ch == '.' or ch == 0) bad = true;
            name[nlen] = std.ascii.toLower(ch);
            nlen += 1;
        }
        off += l;
    }
    if (off + 4 > query.len) return .drop;
    const qtype = be16(query, off);
    const qclass = be16(query, off + 2);
    const qend = off + 4;
    if (out.len < qend + 28) return .drop;
    const want4 = qtype == type_a and t.range4 != null;
    const want6 = qtype == type_aaaa and t.range6 != null;
    const mapped = qclass == class_in and (want4 or want6) and nlen > 0 and !bad;
    if (!mapped and can_forward and !(qclass == class_in and (qtype == type_a or qtype == type_aaaa))) return .forward;
    @memcpy(out[0..qend], query[0..qend]);
    if (!mapped) {
        finishHeader(out, flags, if (bad) 1 else 0, 0);
        return .{ .reply = qend };
    }
    const m = t.resolve(name[0..nlen]) orelse {
        finishHeader(out, flags, 2, 0);
        return .{ .reply = qend };
    };
    const family: addr.Family = if (want4) .v4 else .v6;
    const a = t.address(family, m.index).?;
    var p = qend;
    putBe16(out, p, 0xc00c);
    putBe16(out, p + 2, qtype);
    putBe16(out, p + 4, class_in);
    std.mem.writeInt(u32, out[p + 6 ..][0..4], t.ttl, .big);
    putBe16(out, p + 10, @intCast(a.len()));
    @memcpy(out[p + 12 ..][0..a.len()], a.slice());
    p += 12 + a.len();
    finishHeader(out, flags, 0, 1);
    return .{ .reply = p };
}

pub fn reply(w: anytype, t: *Table, b: *pool.Buffer, pkt: parse.Packet, can_forward: bool) Outcome {
    const data = b.bytes();
    const query = data[pkt.payload_off..][0..pkt.payload_len];
    const nb = w.pool.get() orelse return .drop;
    const v6 = pkt.ip.isV6();
    const ip_hlen: u16 = ip.headerLen(v6);
    const room = nb.cap - nb.headroom();
    const outcome = answer(t, query, nb.ptr[nb.headroom()..][0..room], can_forward);
    const n = switch (outcome) {
        .reply => |len| len,
        else => {
            w.pool.put(nb);
            return outcome;
        },
    };
    if (nb.headroom() < ip_hlen + 8 + gso.VirtioNetHdr.size) {
        w.pool.put(nb);
        return .drop;
    }
    nb.off = nb.headroom();
    nb.len = @intCast(n);
    const udp_len: u32 = @intCast(n + 8);
    const uh_in = pkt.l4.udp;
    const hdr = nb.prepend(ip_hlen + 8);
    _ = ip.writeHeader(hdr, v6, pkt.ip.dst(data), pkt.ip.src(data), parse.proto.udp, udp_len, 0);
    const uh = hdr[ip_hlen..];
    parse.setBe16(uh, 0, uh_in.dst_port);
    parse.setBe16(uh, 2, uh_in.src_port);
    parse.setBe16(uh, 4, @intCast(udp_len));
    uh[6] = 0;
    uh[7] = 0;
    const acc = checksum.pseudo(v6, pkt.ip.dst(data), pkt.ip.src(data), parse.proto.udp, udp_len);
    if (w.caps().vnet_hdr) {
        checksum.writeNative16(uh[6..8], checksum.fold(acc));
        w.transmit(nb, gso.VirtioNetHdr.udp(ip_hlen, 0));
    } else {
        checksum.writeNative16(uh[6..8], checksum.finishUdp(checksum.sum(nb.bytes()[ip_hlen..], acc)));
        w.transmit(nb, .{});
    }
    return outcome;
}

fn buildQuery(buf: []u8, id: u16, name: []const u8, qtype: u16) []u8 {
    putBe16(buf, 0, id);
    putBe16(buf, 2, 0x0100);
    putBe16(buf, 4, 1);
    putBe16(buf, 6, 0);
    putBe16(buf, 8, 0);
    putBe16(buf, 10, 0);
    var off: usize = 12;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        buf[off] = @intCast(label.len);
        @memcpy(buf[off + 1 ..][0..label.len], label);
        off += 1 + label.len;
    }
    buf[off] = 0;
    putBe16(buf, off + 1, qtype);
    putBe16(buf, off + 3, class_in);
    return buf[0 .. off + 5];
}

test "fake dns answers A and AAAA and maps back" {
    const t = try Table.init(std.testing.allocator, try addr.Prefix.parse("198.18.0.0/15"), try addr.Prefix.parse("fc00::/18"), 1000, 1);
    defer t.deinit();
    var q: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const qa = buildQuery(&q, 0x1234, "Example.COM", type_a);
    const r = answer(t, qa, &out, false);
    const n = r.reply;
    try std.testing.expectEqual(@as(usize, qa.len + 16), n);
    try std.testing.expectEqual(@as(u16, 0x1234), be16(&out, 0));
    try std.testing.expectEqual(@as(u16, 1), be16(&out, 6));
    try std.testing.expect(be16(&out, 2) & 0x8000 != 0);
    const a4 = addr.Address.v4(out[n - 4 ..][0..4].*);
    try std.testing.expect(a4.eql(try addr.Address.parse("198.18.0.1")));
    const qaaaa = buildQuery(&q, 7, "example.com", type_aaaa);
    const r6 = answer(t, qaaaa, &out, false).reply;
    const a6 = addr.Address.v6(out[r6 - 16 ..][0..16].*);
    try std.testing.expect(a6.eql(try addr.Address.parse("fc00::1")));
    const m = t.mappingOf(a4).?;
    var name: [max_name]u8 = undefined;
    try std.testing.expectEqualStrings("example.com", t.copyName(m, &name).?);
    try std.testing.expect(t.mappingOf(try addr.Address.parse("198.18.0.9")) == null);
    try std.testing.expect(t.mappingOf(try addr.Address.parse("198.18.0.0")) == null);
    const qmx = buildQuery(&q, 9, "example.com", 15);
    try std.testing.expect(answer(t, qmx, &out, true) == .forward);
    const nodata = answer(t, qmx, &out, false).reply;
    try std.testing.expectEqual(@as(u16, 0), be16(&out, 6));
    try std.testing.expectEqual(qmx.len, nodata);
}

test "fake dns evicts least recently used names" {
    const t = try Table.init(std.testing.allocator, try addr.Prefix.parse("10.64.0.0/24"), null, 16, 1);
    defer t.deinit();
    var names: [20][16]u8 = undefined;
    var maps: [20]Mapping = undefined;
    for (0..20) |i| {
        const s = try std.mem.print(&names[i], "host{d}.test", .{i});
        maps[i] = t.resolve(s).?;
        if (i == 5) _ = t.resolve("host0.test").?;
    }
    var buf: [max_name]u8 = undefined;
    try std.testing.expect(t.copyName(maps[0], &buf) != null);
    try std.testing.expect(t.copyName(maps[1], &buf) == null);
    try std.testing.expectEqualStrings("host19.test", t.copyName(maps[19], &buf).?);
    const again = t.resolve("host19.test").?;
    try std.testing.expectEqual(maps[19].index, again.index);
    var seen: usize = 0;
    for (0..20) |i| {
        const s = try std.mem.print(&names[i], "host{d}.test", .{i});
        if (t.findSlot(s, Table.hashName(s)) != null) seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 16), seen);
}

fn fuzzAnswer(_: void, smith: *std.testing.Smith) anyerror!void {
    const t = try Table.init(std.testing.allocator, try addr.Prefix.parse("198.18.0.0/15"), try addr.Prefix.parse("fc00::/18"), 64, 1);
    defer t.deinit();
    var buf: [600]u8 = undefined;
    var out: [700]u8 = undefined;
    const n = smith.slice(&buf);
    switch (answer(t, buf[0..n], &out, smith.value(bool))) {
        .reply => |len| try std.testing.expect(len <= out.len),
        else => {},
    }
}

test "fuzz fake dns" {
    try std.testing.fuzz({}, fuzzAnswer, .{});
}
