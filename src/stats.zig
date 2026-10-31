const std = @import("std");

pub const Counter = enum(u8) {
    rx_packets,
    rx_bytes,
    tx_packets,
    tx_bytes,
    rx_dropped,
    tx_dropped,
    parse_errors,
    pool_exhausted,
    gso_rx_packets,
    gso_tx_packets,
    gso_segments,
    gro_merged,
    tcp_active,
    tcp_opened,
    tcp_closed,
    tcp_reset,
    tcp_retransmits,
    tcp_connect_failed,
    tcp_evicted,
    udp_active,
    udp_opened,
    udp_closed,
    udp_evicted,
    udp_dropped,
    icmp_echo,
    icmp_time_exceeded,
    nat_active,
    handoffs,
    upstream_rx_bytes,
    upstream_tx_bytes,
    fragments_reassembled,
    timeouts,
    socks5_pool_hits,
    socks5_pool_retries,
    dns_fake_answers,
    dns_hijacked,
    tcp_migrated,
    udp_migrated,
};

pub const count = @typeInfo(Counter).@"enum".field_names.len;

pub const wide_atomics = @bitSizeOf(usize) >= 64;

pub const Cell = if (wide_atomics) std.atomic.Value(u64) else extern struct {
    raw: u64,

    pub fn init(v: u64) @This() {
        return .{ .raw = v };
    }
};

pub inline fn cellOwnerLoad(c: *const Cell) u64 {
    if (wide_atomics) return c.load(.unordered);
    return c.raw;
}

pub inline fn cellStore(c: *Cell, v: u64) void {
    if (wide_atomics) {
        c.store(v, .release);
    } else {
        c.raw = v;
    }
}

pub fn cellRead(c: *const Cell) u64 {
    if (wide_atomics) return c.load(.acquire);
    var a = c.raw;
    while (true) {
        const b = c.raw;
        if (a == b) return a;
        a = b;
    }
}

pub const Counters = struct {
    values: [count]Cell align(std.atomic.cache_line) = @splat(.init(0)),

    pub inline fn add(c: *Counters, comptime which: Counter, n: u64) void {
        const v = &c.values[@backingInt(which)];
        cellStore(v, cellOwnerLoad(v) +% n);
    }

    pub inline fn inc(c: *Counters, comptime which: Counter) void {
        c.add(which, 1);
    }

    pub inline fn dec(c: *Counters, comptime which: Counter) void {
        const v = &c.values[@backingInt(which)];
        cellStore(v, cellOwnerLoad(v) -% 1);
    }

    pub inline fn get(c: *const Counters, which: Counter) u64 {
        return cellRead(&c.values[@backingInt(which)]);
    }

    pub fn snapshotInto(c: *const Counters, s: *Snapshot) void {
        const a = @typeInfo(Counter).@"enum";
        inline for (a.field_names, a.field_values) |name, value| {
            @field(s, name) +%= cellRead(&c.values[@as(usize, @intCast(value))]);
        }
    }
};

pub const Snapshot = blk: {
    var names: [count + 2][]const u8 = undefined;
    var types: [count + 2]type = undefined;
    var attrs: [count + 2]std.lang.Type.Struct.FieldAttributes = undefined;
    names[0] = "version";
    types[0] = u32;
    attrs[0] = .{ .default_value_ptr = &@as(u32, 3) };
    names[1] = "workers";
    types[1] = u32;
    attrs[1] = .{ .default_value_ptr = &@as(u32, 0) };
    for (@typeInfo(Counter).@"enum".field_names, 0..) |name, i| {
        names[i + 2] = name;
        types[i + 2] = u64;
        attrs[i + 2] = .{ .default_value_ptr = &@as(u64, 0) };
    }
    break :blk @Struct(.@"extern", null, &names, &types, &attrs);
};

pub const Gauges = struct {
    buffers: Cell align(std.atomic.cache_line) = .init(0),
    in_use: Cell = .init(0),
    resident: Cell = .init(0),
    released: Cell = .init(0),
    starved: Cell = .init(0),
    exhausted: Cell = .init(0),

    pub fn publish(g: *Gauges, m: Memory) void {
        cellStore(&g.buffers, m.buffers);
        cellStore(&g.in_use, m.in_use);
        cellStore(&g.resident, m.resident_bytes);
        cellStore(&g.released, m.released_bytes);
        cellStore(&g.starved, m.starved_flows);
        cellStore(&g.exhausted, m.exhausted);
    }

    pub fn read(g: *const Gauges) Memory {
        return .{
            .buffers = cellRead(&g.buffers),
            .in_use = cellRead(&g.in_use),
            .resident_bytes = cellRead(&g.resident),
            .released_bytes = cellRead(&g.released),
            .starved_flows = cellRead(&g.starved),
            .exhausted = cellRead(&g.exhausted),
        };
    }
};

pub const Memory = extern struct {
    version: u32 = 1,
    workers: u32 = 0,
    buffers: u64 = 0,
    in_use: u64 = 0,
    resident_bytes: u64 = 0,
    released_bytes: u64 = 0,
    starved_flows: u64 = 0,
    exhausted: u64 = 0,
};

pub fn mergeMemory(out: *Memory, all: []const Gauges) void {
    out.* = .{};
    out.workers = @intCast(all.len);
    for (all) |*g| {
        const m = g.read();
        out.buffers += m.buffers;
        out.in_use += m.in_use;
        out.resident_bytes += m.resident_bytes;
        out.released_bytes += m.released_bytes;
        out.starved_flows += m.starved_flows;
        out.exhausted += m.exhausted;
    }
}

pub fn merge(out: *Snapshot, all: []const Counters) void {
    out.* = .{};
    out.workers = @intCast(all.len);
    for (all) |*c| c.snapshotInto(out);
}

test "counters and snapshot" {
    var cs: [2]Counters = .{ .{}, .{} };
    cs[0].add(.rx_bytes, 100);
    cs[1].add(.rx_bytes, 50);
    cs[1].inc(.tcp_active);
    cs[1].dec(.tcp_active);
    cs[0].inc(.tcp_active);
    var s: Snapshot = .{};
    merge(&s, &cs);
    try std.testing.expectEqual(@as(u64, 150), s.rx_bytes);
    try std.testing.expectEqual(@as(u64, 1), s.tcp_active);
    try std.testing.expectEqual(@as(u32, 2), s.workers);
    try std.testing.expectEqual(@as(usize, 8 + count * 8), @sizeOf(Snapshot));
}
