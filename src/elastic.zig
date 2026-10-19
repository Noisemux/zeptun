const std = @import("std");
const sys = @import("io/sys.zig");

const pool = @import("packet/pool.zig");

pub const tick_ms: u64 = 250;
pub const max_workers = 64;
pub const drain_limit_ms: u64 = 5_000;
pub const forward_ttl_ms: u64 = 3_000;
pub const move_capacity = 32;

pub const Role = enum(u8) { active, draining, detached };

pub const Control = enum(u64) { tcp_transfer = 1, tcp_ack = 2, udp_transfer = 3, udp_ack = 4, _ };

pub fn record(comptime T: type, b: *pool.Buffer) ?*T {
    const base = @intFromPtr(b.ptr);
    const at = std.mem.alignForward(usize, base, @alignOf(T));
    if (at - base + @sizeOf(T) > b.cap) return null;
    return @ptrFromInt(at);
}

pub inline fn meterEpoch(now_ms: u64) u8 {
    return @truncate(now_ms >> 10);
}

pub fn meterAdd(meter: *u32, epoch: *u8, now_ms: u64, n: u32) void {
    const e = meterEpoch(now_ms);
    if (epoch.* != e) {
        meter.* = if (epoch.* +% 1 == e) meter.* / 2 else 0;
        epoch.* = e;
    }
    meter.* +|= n;
}

pub fn meterRecent(meter: u32, epoch: u8, now_ms: u64) u64 {
    const e = meterEpoch(now_ms);
    if (epoch == e or epoch +% 1 == e) return meter;
    return 0;
}

pub const Decision = enum { none, grow, shrink };

pub const Sample = struct {
    now_ms: u64,
    attached: u16,
    max: u16,
    busiest: u32,
    total: u32,
    idle: ?u32,
    rate: u64,
    flows: u32 = 2,
};

pub const Policy = struct {
    spare: u32 = 200,
    spare_after_gain: u32 = 100,
    high: u32 = 700,
    low: u32 = 450,
    grow_after: u8 = 4,
    shrink_after: u8 = 16,
    settle_ms: u64 = 1000,
    measure_ms: u64 = 1500,
    min_gain: u64 = 1100,
    backoff_min_ms: u64 = 15_000,
    backoff_max_ms: u64 = 300_000,
    keep_ms: u64 = 5_000,

    hot: u8 = 0,
    cold: u8 = 0,
    rates: [4]u64 = @splat(0),
    rate_count: u8 = 0,
    probing: bool = false,
    probe_at: u64 = 0,
    probe_base: u64 = 0,
    probe_sum: u64 = 0,
    probe_samples: u32 = 0,
    retry_at: u64 = 0,
    backoff_ms: u64 = 0,
    keep_until: u64 = 0,
    gain_milli: u64 = 0,
    momentum: bool = false,
    probe_flows: u32 = 0,
    failed_flows: u32 = 0,

    fn baseline(p: *const Policy) u64 {
        const n = @min(p.rate_count, p.rates.len);
        if (n == 0) return 0;
        var sum: u64 = 0;
        for (p.rates[0..n]) |r| sum += r;
        return sum / n;
    }

    pub fn step(p: *Policy, s: Sample) Decision {
        if (p.probing) {
            if (s.now_ms < p.probe_at + p.settle_ms) return .none;
            p.probe_sum += s.rate;
            p.probe_samples += 1;
            if (s.now_ms < p.probe_at + p.settle_ms + p.measure_ms) return .none;
            p.probing = false;
            p.hot = 0;
            p.cold = 0;
            p.rate_count = 0;
            const avg = p.probe_sum / @max(p.probe_samples, 1);
            p.gain_milli = if (p.probe_base == 0) 0 else avg * 1000 / p.probe_base;
            if (avg * 1000 >= p.probe_base * p.min_gain) {
                p.backoff_ms = 0;
                p.keep_until = s.now_ms + p.keep_ms;
                p.momentum = true;
                return .none;
            }
            p.momentum = false;
            p.failed_flows = p.probe_flows;
            p.backoff_ms = std.math.clamp(p.backoff_ms * 2, p.backoff_min_ms, p.backoff_max_ms);
            p.retry_at = s.now_ms + p.backoff_ms;
            return .shrink;
        }
        p.rates[p.rate_count % p.rates.len] = s.rate;
        p.rate_count +%= 1;
        const spare_ok = if (s.idle) |idle| idle >= (if (p.momentum) p.spare_after_gain else p.spare) else true;
        const hot = s.attached < s.max and s.busiest >= p.high and s.flows >= 2 and spare_ok;
        p.hot = if (hot) p.hot +| 1 else 0;
        const workload_changed = p.failed_flows != 0 and s.flows >= p.failed_flows * 2;
        const cold = s.attached > 1 and s.total <= @as(u32, s.attached - 1) * p.low;
        p.cold = if (cold) p.cold +| 1 else 0;
        if (cold) p.momentum = false;
        if (p.hot >= p.grow_after and (s.now_ms >= p.retry_at or workload_changed)) {
            if (workload_changed) {
                p.backoff_ms = 0;
                p.failed_flows = 0;
            }
            p.probing = true;
            p.probe_flows = s.flows;
            p.probe_at = s.now_ms;
            p.probe_base = p.baseline();
            p.probe_sum = 0;
            p.probe_samples = 0;
            p.hot = 0;
            p.cold = 0;
            return .grow;
        }
        if (p.cold >= p.shrink_after and s.now_ms >= p.keep_until) {
            p.cold = 0;
            return .shrink;
        }
        return .none;
    }
};

pub const Rotation = struct {
    period_ms: u64 = 1500,
    next_at: u64 = 0,
    rising: bool = true,

    pub fn step(r: *Rotation, now_ms: u64, attached: u16, max: u16) Decision {
        if (now_ms < r.next_at) return .none;
        r.next_at = now_ms + r.period_ms;
        if (r.rising and attached >= max) r.rising = false;
        if (!r.rising and attached <= 1) r.rising = true;
        return if (r.rising) .grow else .shrink;
    }
};

pub fn threadCpuNs(tid: i32) ?u64 {
    if (!sys.is_linux or tid <= 0) return null;
    const linux = std.os.linux;
    const id: u32 = (~@as(u32, @bitCast(tid)) << 3) | 6;
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(@fromBackingInt(@intCast(id)), &ts)) != .SUCCESS) return null;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn currentTid() i32 {
    if (!sys.is_linux) return 0;
    return std.os.linux.gettid();
}

pub const CpuStat = struct {
    fd: sys.fd_t = sys.invalid_fd,
    idle: u64 = 0,
    total: u64 = 0,
    primed: bool = false,
    failed: bool = false,

    pub fn close(s: *CpuStat) void {
        if (s.fd != sys.invalid_fd) sys.close(s.fd);
        s.fd = sys.invalid_fd;
    }

    pub fn idleMilli(s: *CpuStat, cpus: u32) ?u32 {
        if (comptime !sys.is_linux) return null;
        if (s.failed) return null;
        const linux = std.os.linux;
        if (s.fd == sys.invalid_fd) {
            const r = sys.linuxResult(linux.open("/proc/stat", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0));
            if (r < 0) {
                s.failed = true;
                return null;
            }
            s.fd = r;
        }
        var buf: [256]u8 = undefined;
        const n = sys.linuxResult(linux.pread(s.fd, &buf, buf.len, 0));
        if (n <= 0) return null;
        const parsed = parseCpuLine(buf[0..@intCast(n)]) orelse return null;
        defer {
            s.idle = parsed.idle;
            s.total = parsed.total;
            s.primed = true;
        }
        if (!s.primed or parsed.total <= s.total) return null;
        const di = parsed.idle -| s.idle;
        const dt = parsed.total - s.total;
        return @intCast(@min(@as(u64, cpus) * 1000 * di / dt, @as(u64, cpus) * 1000));
    }
};

const CpuTimes = struct { idle: u64, total: u64 };

fn parseCpuLine(text: []const u8) ?CpuTimes {
    if (!std.mem.startsWith(u8, text, "cpu ")) return null;
    const end = std.mem.findScalar(u8, text, '\n') orelse text.len;
    var it = std.mem.tokenizeScalar(u8, text[4..end], ' ');
    var fields: [8]u64 = @splat(0);
    var i: usize = 0;
    while (i < fields.len) : (i += 1) {
        const tok = it.next() orelse break;
        fields[i] = std.fmt.parseInt(u64, tok, 10) catch return null;
    }
    if (i < 5) return null;
    var total: u64 = 0;
    for (fields) |f| total += f;
    return .{ .idle = fields[3] + fields[4], .total = total };
}

test "cpu line parsing" {
    const t = parseCpuLine("cpu  100 5 50 1000 20 1 2 3 0 0\ncpu0 1 2 3\n").?;
    try std.testing.expectEqual(@as(u64, 1020), t.idle);
    try std.testing.expectEqual(@as(u64, 1181), t.total);
    try std.testing.expect(parseCpuLine("intr 1 2") == null);
}

test "thread cpu clock reads the calling thread" {
    if (!sys.is_linux) return error.SkipZigTest;
    const tid = currentTid();
    const a = threadCpuNs(tid) orelse return error.SkipZigTest;
    var x: u64 = 0;
    var i: u64 = 0;
    while (i < 3_000_000) : (i += 1) x +%= i *% 2654435761;
    std.mem.doNotOptimizeAway(x);
    const b = threadCpuNs(tid).?;
    try std.testing.expect(b > a);
}

test "policy keeps a queue only when throughput grows" {
    var p: Policy = .{};
    var now: u64 = 0;
    var d: Decision = .none;
    var ticks: u32 = 0;
    while (ticks < 8) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 1, .max = 4, .busiest = 980, .total = 980, .idle = 1200, .rate = 1000 });
        if (d != .none) break;
    }
    try std.testing.expectEqual(Decision.grow, d);
    ticks = 0;
    d = .none;
    while (ticks < 20 and d == .none) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 2, .max = 4, .busiest = 600, .total = 1200, .idle = 1500, .rate = 1030 });
    }
    try std.testing.expectEqual(Decision.shrink, d);
    try std.testing.expect(p.retry_at > now);
    now += tick_ms;
    try std.testing.expectEqual(Decision.none, p.step(.{ .now_ms = now, .attached = 1, .max = 4, .busiest = 990, .total = 990, .idle = 2500, .rate = 1000 }));
    now = p.retry_at;
    ticks = 0;
    d = .none;
    while (ticks < 8 and d == .none) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 1, .max = 4, .busiest = 990, .total = 990, .idle = 2500, .rate = 1000 });
    }
    try std.testing.expectEqual(Decision.grow, d);
    ticks = 0;
    d = .none;
    while (ticks < 20) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 2, .max = 4, .busiest = 600, .total = 1200, .idle = 1000, .rate = 1700 });
        try std.testing.expectEqual(Decision.none, d);
    }
    try std.testing.expect(!p.probing);
    try std.testing.expect(p.momentum);
    ticks = 0;
    d = .none;
    while (ticks < 8 and d == .none) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 2, .max = 4, .busiest = 850, .total = 1700, .idle = 300, .rate = 1700 });
    }
    try std.testing.expectEqual(Decision.grow, d);
}

test "policy needs spare cpus and sheds idle queues" {
    var p: Policy = .{};
    var now: u64 = 0;
    var ticks: u32 = 0;
    while (ticks < 40) : (ticks += 1) {
        now += tick_ms;
        try std.testing.expectEqual(Decision.none, p.step(.{ .now_ms = now, .attached = 1, .max = 4, .busiest = 990, .total = 990, .idle = 100, .rate = 1000 }));
    }
    ticks = 0;
    var d: Decision = .none;
    while (ticks < 40 and d == .none) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 3, .max = 4, .busiest = 300, .total = 700, .idle = 3000, .rate = 10 });
    }
    try std.testing.expectEqual(Decision.shrink, d);
    try std.testing.expectEqual(@as(u32, 16), ticks);
}

test "policy never probes a single flow" {
    var p: Policy = .{};
    var now: u64 = 0;
    var ticks: u32 = 0;
    while (ticks < 40) : (ticks += 1) {
        now += tick_ms;
        try std.testing.expectEqual(Decision.none, p.step(.{ .now_ms = now, .attached = 1, .max = 4, .busiest = 990, .total = 990, .idle = 3000, .rate = 1000, .flows = 1 }));
    }
}

test "policy probes again when the flow count doubles" {
    var p: Policy = .{};
    var now: u64 = 0;
    var d: Decision = .none;
    var ticks: u32 = 0;
    while (ticks < 8 and d == .none) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 1, .max = 4, .busiest = 990, .total = 990, .idle = 3000, .rate = 1000, .flows = 2 });
    }
    try std.testing.expectEqual(Decision.grow, d);
    d = .none;
    ticks = 0;
    while (ticks < 20 and d == .none) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 2, .max = 4, .busiest = 600, .total = 1200, .idle = 3000, .rate = 1000, .flows = 2 });
    }
    try std.testing.expectEqual(Decision.shrink, d);
    try std.testing.expect(p.retry_at > now + tick_ms * 8);
    ticks = 0;
    while (ticks < 6) : (ticks += 1) {
        now += tick_ms;
        try std.testing.expectEqual(Decision.none, p.step(.{ .now_ms = now, .attached = 1, .max = 4, .busiest = 990, .total = 990, .idle = 3000, .rate = 1000, .flows = 2 }));
    }
    d = .none;
    ticks = 0;
    while (ticks < 8 and d == .none) : (ticks += 1) {
        now += tick_ms;
        d = p.step(.{ .now_ms = now, .attached = 1, .max = 4, .busiest = 990, .total = 990, .idle = 3000, .rate = 1000, .flows = 10 });
    }
    try std.testing.expectEqual(Decision.grow, d);
    try std.testing.expect(now < p.retry_at);
}

test "rotation walks up and down" {
    var r: Rotation = .{ .period_ms = 10 };
    var attached: u16 = 1;
    var seen_max = false;
    var now: u64 = 0;
    var steps: u32 = 0;
    while (steps < 20) : (steps += 1) {
        now += 10;
        switch (r.step(now, attached, 3)) {
            .grow => attached += 1,
            .shrink => attached -= 1,
            .none => {},
        }
        try std.testing.expect(attached >= 1 and attached <= 3);
        if (attached == 3) seen_max = true;
    }
    try std.testing.expect(seen_max);
}
