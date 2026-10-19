const std = @import("std");
const builtin = @import("builtin");
const zeptun = @import("zeptun");

const sys = zeptun.io.sys;
const addr = zeptun.addr;
const linux = std.os.linux;

pub const magic = [4]u8{ 'Z', 'E', 'P', 'B' };

pub const Mode = enum(u8) { upload = 0, download = 1, echo = 2, rr = 3 };

fn sock(family: addr.Family, udp: bool) !i32 {
    const af: u32 = if (family == .v4) linux.AF.INET else linux.AF.INET6;
    const kind: u32 = if (udp) linux.SOCK.DGRAM else linux.SOCK.STREAM;
    const r = sys.linuxResult(linux.socket(af, kind | linux.SOCK.CLOEXEC, 0));
    if (r < 0) return sys.errnoError(sys.toErrno(r));
    return r;
}

fn readFull(fd: i32, buf: []u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const n = sys.linuxResult(linux.read(fd, buf[off..].ptr, buf.len - off));
        if (n <= 0) {
            if (n < 0 and sys.toErrno(n) == .intr) continue;
            return false;
        }
        off += @intCast(n);
    }
    return true;
}

fn writeFull(fd: i32, buf: []const u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const n = sys.linuxResult(linux.sendto(fd, buf[off..].ptr, buf.len - off, linux.MSG.NOSIGNAL, null, 0));
        if (n <= 0) {
            if (n < 0 and sys.toErrno(n) == .intr) continue;
            return false;
        }
        off += @intCast(n);
    }
    return true;
}

pub fn listenTcp(ep: addr.Endpoint, backlog: u32) !i32 {
    const fd = try sock(ep.addr.family, false);
    _ = sys.setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, 1);
    var sa = sys.Sockaddr.fromEndpoint(ep);
    if (sys.bind(fd, &sa) < 0) return error.BindFailed;
    if (sys.listen(fd, backlog) < 0) return error.ListenFailed;
    return fd;
}

pub fn connectTcp(ep: addr.Endpoint) !i32 {
    const fd = try sock(ep.addr.family, false);
    var sa = sys.Sockaddr.fromEndpoint(ep);
    const r = sys.connect(fd, &sa);
    if (r < 0) {
        sys.close(fd);
        return sys.errnoError(sys.toErrno(r));
    }
    _ = sys.setsockoptInt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, 1);
    return fd;
}

pub fn tcpServer(ep: addr.Endpoint) !void {
    const lfd = try listenTcp(ep, 4096);
    std.debug.print("tcp-server listening on {f}\n", .{ep});
    while (true) {
        const fd = sys.linuxResult(linux.accept4(lfd, null, null, linux.SOCK.CLOEXEC));
        if (fd < 0) continue;
        const t = std.Thread.spawn(.{ .stack_size = 1 << 20 }, serveTcp, .{fd}) catch {
            sys.close(fd);
            continue;
        };
        t.detach();
    }
}

fn serveTcp(fd: i32) void {
    defer sys.close(fd);
    var hdr: [8]u8 = undefined;
    if (!readFull(fd, &hdr) or !std.mem.eql(u8, hdr[0..4], &magic)) return;
    const mode: Mode = std.enums.fromInt(Mode, hdr[4]) orelse return;
    const rr_size = std.mem.readInt(u16, hdr[6..8], .big);
    var buf: [256 * 1024]u8 = undefined;
    switch (mode) {
        .upload => while (true) {
            const n = sys.linuxResult(linux.read(fd, &buf, buf.len));
            if (n <= 0) return;
        },
        .download => {
            @memset(&buf, 0x5a);
            while (writeFull(fd, &buf)) {}
        },
        .echo => while (true) {
            const n = sys.linuxResult(linux.read(fd, &buf, buf.len));
            if (n <= 0) return;
            if (!writeFull(fd, buf[0..@intCast(n)])) return;
        },
        .rr => {
            const sz = @max(@min(rr_size, 16384), 1);
            while (readFull(fd, buf[0..sz])) {
                if (!writeFull(fd, buf[0..sz])) return;
            }
        },
    }
}

pub const StreamResult = struct {
    bytes: u64,
    seconds: f64,
    gbps: f64,
    streams: u32,
    reverse: bool,
};

const Counter = if (@bitSizeOf(usize) >= 64) u64 else u32;

const StreamCtx = struct {
    ep: addr.Endpoint,
    reverse: bool,
    deadline: u64,
    bytes_per_s: u64 = 0,
    bytes: std.atomic.Value(Counter) = .init(0),
    failed: std.atomic.Value(bool) = .init(false),

    fn run(c: *StreamCtx) void {
        const fd = connectTcp(c.ep) catch {
            c.failed.store(true, .release);
            return;
        };
        defer sys.close(fd);
        var hdr = magic ++ [4]u8{ @backingInt(if (c.reverse) Mode.download else Mode.upload), 0, 0, 0 };
        if (!writeFull(fd, &hdr)) {
            c.failed.store(true, .release);
            return;
        }
        var buf: [128 * 1024]u8 = undefined;
        @memset(&buf, 0xa5);
        const start = sys.monotonicNs();
        const chunk: usize = if (c.bytes_per_s != 0) @min(buf.len, @max(c.bytes_per_s / 100, 1024)) else buf.len;
        while (sys.monotonicNs() < c.deadline) {
            if (c.bytes_per_s != 0) {
                const allowed = (sys.monotonicNs() - start) * c.bytes_per_s / std.time.ns_per_s;
                if (c.bytes.load(.monotonic) >= allowed) {
                    sys.sleepMs(1);
                    continue;
                }
            }
            const n = if (c.reverse)
                sys.linuxResult(linux.read(fd, &buf, buf.len))
            else
                sys.linuxResult(linux.sendto(fd, &buf, chunk, linux.MSG.NOSIGNAL, null, 0));
            if (n <= 0) {
                if (n < 0 and sys.toErrno(n) == .intr) continue;
                c.failed.store(true, .release);
                return;
            }
            _ = c.bytes.fetchAdd(@intCast(n), .monotonic);
        }
    }
};

pub fn tcpStream(allocator: std.mem.Allocator, ep: addr.Endpoint, streams: u32, seconds: u32, reverse: bool, mbps: u64) !StreamResult {
    const ctxs = try allocator.alloc(StreamCtx, streams);
    defer allocator.free(ctxs);
    const threads = try allocator.alloc(std.Thread, streams);
    defer allocator.free(threads);
    const start = sys.monotonicNs();
    const deadline = start + @as(u64, seconds) * std.time.ns_per_s;
    for (ctxs, threads) |*c, *t| {
        c.* = .{ .ep = ep, .reverse = reverse, .deadline = deadline, .bytes_per_s = mbps * 125_000 / @max(streams, 1) };
        t.* = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, StreamCtx.run, .{c});
    }
    var last: u64 = 0;
    var tick: u32 = 1;
    while (sys.monotonicNs() < deadline) {
        sys.sleepMs(100);
        const elapsed = sys.monotonicNs() - start;
        if (elapsed >= @as(u64, tick) * std.time.ns_per_s) {
            var total: u64 = 0;
            for (ctxs) |*c| total += c.bytes.load(.acquire);
            std.debug.print("  [{d:>3}s] {d:>8.2} Gbit/s\n", .{ tick, @as(f64, @floatFromInt(total - last)) * 8.0 / 1e9 });
            last = total;
            tick += 1;
        }
    }
    for (threads) |t| t.join();
    const elapsed_s = @as(f64, @floatFromInt(sys.monotonicNs() - start)) / 1e9;
    var total: u64 = 0;
    var failed = false;
    for (ctxs) |*c| {
        total += c.bytes.load(.acquire);
        if (c.failed.load(.acquire)) failed = true;
    }
    if (failed and total == 0) return error.StreamFailed;
    return .{ .bytes = total, .seconds = elapsed_s, .gbps = @as(f64, @floatFromInt(total)) * 8.0 / 1e9 / elapsed_s, .streams = streams, .reverse = reverse };
}

pub fn udpServer(ep: addr.Endpoint, echo: bool) !void {
    const fd = try sock(ep.addr.family, true);
    var sa = sys.Sockaddr.fromEndpoint(ep);
    if (sys.bind(fd, &sa) < 0) return error.BindFailed;
    _ = sys.setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, 8 << 20);
    std.debug.print("udp-server listening on {f}\n", .{ep});
    const batch = 64;
    const bufs = try std.heap.page_allocator.alloc([65536]u8, batch);
    defer std.heap.page_allocator.free(bufs);
    var iovs: [batch]std.posix.iovec = undefined;
    var names: [batch]sys.Sockaddr = undefined;
    var msgs: [batch]linux.mmsghdr = undefined;
    var packets: u64 = 0;
    var bytes: u64 = 0;
    var last_report = sys.monotonicNs();
    var last_packets: u64 = 0;
    var last_bytes: u64 = 0;
    const tv: linux.timespec = .{ .sec = 1, .nsec = 0 };
    while (true) {
        for (0..batch) |i| {
            iovs[i] = .{ .base = &bufs[i], .len = bufs[i].len };
            msgs[i] = .{ .hdr = .{ .name = @ptrCast(@alignCast(names[i].mutPtr())), .namelen = 128, .iov = @ptrCast(&iovs[i]), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
        }
        var timeout = tv;
        const r = sys.linuxResult(linux.recvmmsg(fd, &msgs, batch, linux.MSG.WAITFORONE, &timeout));
        if (r > 0) {
            const n: usize = @intCast(r);
            packets += n;
            for (msgs[0..n]) |m| bytes += m.len;
            if (echo) {
                for (msgs[0..n], 0..) |*m, i| {
                    iovs[i].len = m.len;
                    m.hdr.iovlen = 1;
                }
                _ = linux.sendmmsg(fd, &msgs, @intCast(n), 0);
            }
        }
        const now = sys.monotonicNs();
        if (now - last_report >= std.time.ns_per_s) {
            const dt = @as(f64, @floatFromInt(now - last_report)) / 1e9;
            std.debug.print("udp-server: {d:>10.0} pps {d:>8.2} Mbit/s total {d} packets\n", .{ @as(f64, @floatFromInt(packets - last_packets)) / dt, @as(f64, @floatFromInt(bytes - last_bytes)) * 8.0 / 1e6 / dt, packets });
            last_report = now;
            last_packets = packets;
            last_bytes = bytes;
        }
    }
}

pub const UdpResult = struct {
    sent: u64,
    received: u64,
    corrupt: u64,
    seconds: f64,
    pps: f64,
    size: u32,
};

fn stampDatagram(buf: []u8, seq: u64) void {
    std.mem.writeInt(u64, buf[0..8], seq, .little);
    std.mem.writeInt(u32, buf[8..12], @intCast(buf.len), .little);
    for (buf[12..], 12..) |*b, i| b.* = @truncate(seq *% 31 +% i);
}

fn datagramIntact(buf: []const u8) bool {
    if (buf.len < 12) return false;
    if (std.mem.readInt(u32, buf[8..12], .little) != buf.len) return false;
    const seq = std.mem.readInt(u64, buf[0..8], .little);
    for (buf[12..], 12..) |b, i| {
        if (b != @as(u8, @truncate(seq *% 31 +% i))) return false;
    }
    return true;
}

test "udp datagram stamps detect corruption" {
    var buf: [64]u8 = undefined;
    stampDatagram(&buf, 77);
    try std.testing.expect(datagramIntact(&buf));
    buf[40] ^= 1;
    try std.testing.expect(!datagramIntact(&buf));
    try std.testing.expect(!datagramIntact(buf[0..63]));
}

pub fn udpClient(ep: addr.Endpoint, seconds: u32, size: u32, pps: u64, expect_echo: bool, gso: bool) !UdpResult {
    const fd = try sock(ep.addr.family, true);
    defer sys.close(fd);
    var sa = sys.Sockaddr.fromEndpoint(ep);
    if (sys.connect(fd, &sa) < 0) return error.ConnectFailed;
    _ = sys.setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.SNDBUF, 8 << 20);
    _ = sys.setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, 8 << 20);
    const batch = 32;
    const len = std.math.clamp(size, 16, 65000);
    const segments: u32 = if (gso) std.math.clamp(64000 / len, 1, batch) else 1;
    const slots: u32 = if (gso and segments > 1) segments else batch;
    const storage = try std.heap.page_allocator.alloc(u8, @as(usize, len) * slots);
    defer std.heap.page_allocator.free(storage);
    var iovs: [batch]std.posix.iovec_const = undefined;
    var msgs: [batch]linux.mmsghdr = undefined;
    for (0..slots) |i| {
        iovs[i] = .{ .base = storage[i * len ..].ptr, .len = len };
        msgs[i] = .{ .hdr = .{ .name = null, .namelen = 0, .iov = @ptrCast(&iovs[i]), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
    }
    var control: [32]u8 align(8) = undefined;
    const clen = zeptun.handler.direct.writeUdpSegmentCmsg(&control, @intCast(len));
    var gso_iov = [1]std.posix.iovec_const{.{ .base = storage.ptr, .len = @as(usize, len) * segments }};
    const gso_msg: linux.msghdr_const = .{ .name = null, .namelen = 0, .iov = @ptrCast(&gso_iov), .iovlen = 1, .control = &control, .controllen = clen, .flags = 0 };
    const use_gso = gso and segments > 1;
    const start = sys.monotonicNs();
    const deadline = start + @as(u64, seconds) * std.time.ns_per_s;
    var sent: u64 = 0;
    var received: u64 = 0;
    var corrupt: u64 = 0;
    var rbuf: [65535]u8 = undefined;
    while (true) {
        const now = sys.monotonicNs();
        if (now >= deadline) break;
        if (pps != 0) {
            const due = @as(u64, @intFromFloat(@as(f64, @floatFromInt(now - start)) / 1e9 * @as(f64, @floatFromInt(pps))));
            if (sent >= due) {
                sys.sleepMs(1);
                continue;
            }
        }
        for (0..slots) |i| stampDatagram(storage[i * len ..][0..len], sent + i);
        if (use_gso) {
            const r = sys.linuxResult(linux.sendmsg(fd, &gso_msg, 0));
            if (r > 0) {
                sent += segments;
            } else if (sys.toErrno(r) != .again and sys.toErrno(r) != .nobufs) {
                return error.GsoUnsupported;
            }
        } else {
            const r = sys.linuxResult(linux.sendmmsg(fd, &msgs, slots, 0));
            if (r > 0) sent += @intCast(r);
        }
        if (expect_echo) {
            while (true) {
                const n = sys.linuxResult(linux.recvfrom(fd, &rbuf, rbuf.len, linux.MSG.DONTWAIT, null, null));
                if (n <= 0) break;
                received += 1;
                if (!datagramIntact(rbuf[0..@intCast(n)])) corrupt += 1;
            }
        }
    }
    const elapsed = @as(f64, @floatFromInt(sys.monotonicNs() - start)) / 1e9;
    return .{ .sent = sent, .received = received, .corrupt = corrupt, .seconds = elapsed, .pps = @as(f64, @floatFromInt(sent)) / elapsed, .size = len };
}

pub const Histogram = struct {
    const linear = 128;
    const per_octave = 64;
    const slots = 2048;

    buckets: [slots]u64 = @splat(0),
    count: u64 = 0,
    sum_ns: u64 = 0,

    fn bucketOf(ns: u64) usize {
        const us = ns / 1000;
        if (us < linear) return @intCast(us);
        const log2: u6 = @intCast(63 - @clz(us));
        const sub: usize = @intCast((us >> (log2 - 6)) & (per_octave - 1));
        return @min(linear + (@as(usize, log2) - 7) * per_octave + sub, slots - 1);
    }

    fn bucketValueUs(i: usize) f64 {
        if (i < linear) return @floatFromInt(i);
        const group = (i - linear) / per_octave;
        const sub = (i - linear) % per_octave;
        return @as(f64, @floatFromInt(per_octave + sub)) * std.math.pow(f64, 2.0, @floatFromInt(group + 1));
    }

    pub fn add(h: *Histogram, ns: u64) void {
        h.buckets[bucketOf(ns)] += 1;
        h.count += 1;
        h.sum_ns += ns;
    }

    pub fn merge(h: *Histogram, o: *const Histogram) void {
        for (&h.buckets, o.buckets) |*a, b| a.* += b;
        h.count += o.count;
        h.sum_ns += o.sum_ns;
    }

    pub fn percentileUs(h: *const Histogram, p: f64) f64 {
        if (h.count == 0) return 0;
        const target: u64 = @intFromFloat(@ceil(@as(f64, @floatFromInt(h.count)) * p));
        var acc: u64 = 0;
        for (h.buckets, 0..) |b, i| {
            acc += b;
            if (acc >= target) return bucketValueUs(i);
        }
        return bucketValueUs(slots - 1);
    }
};

test "histogram buckets cover microseconds to seconds" {
    var h: Histogram = .{};
    h.add(50 * std.time.ns_per_us);
    h.add(200 * std.time.ns_per_us);
    h.add(20 * std.time.ns_per_ms);
    h.add(3 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(f64, 50), h.percentileUs(0.25));
    try std.testing.expectEqual(@as(f64, 200), h.percentileUs(0.5));
    try std.testing.expect(@abs(h.percentileUs(0.75) - 20000) < 20000 * 0.02);
    try std.testing.expect(@abs(h.percentileUs(1.0) - 3_000_000) < 3_000_000 * 0.02);
}

pub const RrResult = struct {
    transactions: u64,
    seconds: f64,
    tps: f64,
    p50_us: f64,
    p90_us: f64,
    p99_us: f64,
    p999_us: f64,
    max_us: f64,
    mean_us: f64,
    conns: u32,
    size: u32,
    errors: u64 = 0,
};

pub fn connectVia(ep: addr.Endpoint, socks: ?addr.Endpoint) !i32 {
    const proxy = socks orelse return connectTcp(ep);
    const fd = try connectTcp(proxy);
    errdefer sys.close(fd);
    var reply: [2]u8 = undefined;
    if (!writeFull(fd, &[_]u8{ 5, 1, 0 }) or !readFull(fd, &reply) or reply[0] != 5 or reply[1] != 0) return error.HandshakeFailed;
    var req: [22]u8 = undefined;
    req[0] = 5;
    req[1] = 1;
    req[2] = 0;
    var n: usize = 3;
    if (ep.addr.family == .v4) {
        req[n] = 1;
        @memcpy(req[n + 1 ..][0..4], ep.addr.bytes[0..4]);
        n += 5;
    } else {
        req[n] = 4;
        @memcpy(req[n + 1 ..][0..16], &ep.addr.bytes);
        n += 17;
    }
    std.mem.writeInt(u16, req[n..][0..2], ep.port, .big);
    n += 2;
    if (!writeFull(fd, req[0..n])) return error.HandshakeFailed;
    var head: [4]u8 = undefined;
    if (!readFull(fd, &head) or head[1] != 0) return error.HandshakeFailed;
    var rest: [18]u8 = undefined;
    const tail: usize = switch (head[3]) {
        1 => 6,
        4 => 18,
        else => return error.HandshakeFailed,
    };
    if (!readFull(fd, rest[0..tail])) return error.HandshakeFailed;
    return fd;
}

const RrCtx = struct {
    ep: addr.Endpoint,
    socks: ?addr.Endpoint = null,
    size: u16,
    deadline: u64,
    reconnect: bool = false,
    interval_ns: u64 = 0,
    next_ns: u64 = 0,
    hist: Histogram = .{},
    failed: bool = false,
    errors: u64 = 0,

    fn pace(c: *RrCtx) u64 {
        const now = sys.monotonicNs();
        if (c.interval_ns == 0) return now;
        if (c.next_ns == 0) c.next_ns = now;
        const due = c.next_ns;
        c.next_ns += c.interval_ns;
        if (now < due) {
            const wait = due - now;
            const ts: linux.timespec = .{ .sec = @intCast(wait / std.time.ns_per_s), .nsec = @intCast(wait % std.time.ns_per_s) };
            _ = linux.nanosleep(&ts, null);
            return sys.monotonicNs();
        }
        if (now - due > c.interval_ns * 8) c.next_ns = now + c.interval_ns;
        return now;
    }

    fn once(c: *RrCtx, buf: []u8) bool {
        const t0 = c.pace();
        const fd = connectVia(c.ep, c.socks) catch return false;
        defer sys.close(fd);
        var hdr: [8]u8 = magic ++ [4]u8{ @backingInt(Mode.rr), 0, 0, 0 };
        std.mem.writeInt(u16, hdr[6..8], c.size, .big);
        const sz: usize = c.size;
        if (!writeFull(fd, &hdr) or !writeFull(fd, buf[0..sz]) or !readFull(fd, buf[0..sz])) return false;
        c.hist.add(sys.monotonicNs() - t0);
        return true;
    }

    fn run(c: *RrCtx) void {
        if (c.reconnect) {
            var buf: [16384]u8 = undefined;
            @memset(&buf, 0x22);
            while (sys.monotonicNs() < c.deadline) {
                if (!c.once(&buf)) {
                    c.errors += 1;
                    sys.sleepMs(1);
                }
            }
            return;
        }
        const fd = connectVia(c.ep, c.socks) catch {
            c.failed = true;
            return;
        };
        defer sys.close(fd);
        var hdr: [8]u8 = magic ++ [4]u8{ @backingInt(Mode.rr), 0, 0, 0 };
        std.mem.writeInt(u16, hdr[6..8], c.size, .big);
        if (!writeFull(fd, &hdr)) {
            c.failed = true;
            return;
        }
        var buf: [16384]u8 = undefined;
        @memset(&buf, 0x11);
        const sz: usize = c.size;
        while (sys.monotonicNs() < c.deadline) {
            const t0 = c.pace();
            if (!writeFull(fd, buf[0..sz]) or !readFull(fd, buf[0..sz])) {
                c.failed = true;
                return;
            }
            c.hist.add(sys.monotonicNs() - t0);
        }
    }
};

pub fn rrClient(allocator: std.mem.Allocator, ep: addr.Endpoint, socks: ?addr.Endpoint, conns: u32, seconds: u32, size: u16, reconnect: bool, rate: u64) !RrResult {
    const ctxs = try allocator.alloc(RrCtx, conns);
    defer allocator.free(ctxs);
    const threads = try allocator.alloc(std.Thread, conns);
    defer allocator.free(threads);
    const start = sys.monotonicNs();
    const deadline = start + @as(u64, seconds) * std.time.ns_per_s;
    for (ctxs, threads) |*c, *t| {
        c.* = .{ .ep = ep, .socks = socks, .size = @max(size, 1), .deadline = deadline, .reconnect = reconnect, .interval_ns = if (rate > 0) @as(u64, conns) * std.time.ns_per_s / rate else 0 };
        t.* = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, RrCtx.run, .{c});
    }
    for (threads) |t| t.join();
    var total: Histogram = .{};
    var errors: u64 = 0;
    for (ctxs) |*c| {
        total.merge(&c.hist);
        errors += c.errors;
    }
    const elapsed = @as(f64, @floatFromInt(sys.monotonicNs() - start)) / 1e9;
    return .{
        .transactions = total.count,
        .seconds = elapsed,
        .tps = @as(f64, @floatFromInt(total.count)) / elapsed,
        .p50_us = total.percentileUs(0.50),
        .p90_us = total.percentileUs(0.90),
        .p99_us = total.percentileUs(0.99),
        .p999_us = total.percentileUs(0.999),
        .max_us = total.percentileUs(1.0),
        .mean_us = if (total.count > 0) @as(f64, @floatFromInt(total.sum_ns)) / @as(f64, @floatFromInt(total.count)) / 1000.0 else 0,
        .conns = conns,
        .size = size,
        .errors = errors,
    };
}

pub const ConnsResult = struct {
    requested: u32,
    established: u32,
    failed: u32,
    connect_seconds: f64,
    rate: f64,
};

pub fn connScale(allocator: std.mem.Allocator, ep: addr.Endpoint, count: u32, hold_ms: u32) !ConnsResult {
    const fds = try allocator.alloc(i32, count);
    defer allocator.free(fds);
    @memset(fds, -1);
    const start = sys.monotonicNs();
    var ok: u32 = 0;
    var failed: u32 = 0;
    const hdr = magic ++ [4]u8{ @backingInt(Mode.echo), 0, 0, 0 };
    for (fds) |*fd| {
        const f = connectTcp(ep) catch {
            failed += 1;
            continue;
        };
        var probe: [4]u8 = "ping".*;
        if (!writeFull(f, &hdr) or !writeFull(f, &probe) or !readFull(f, &probe)) {
            sys.close(f);
            failed += 1;
            continue;
        }
        fd.* = f;
        ok += 1;
    }
    const elapsed = @as(f64, @floatFromInt(sys.monotonicNs() - start)) / 1e9;
    sys.sleepMs(hold_ms);
    for (fds) |fd| {
        if (fd >= 0) sys.close(fd);
    }
    return .{ .requested = count, .established = ok, .failed = failed, .connect_seconds = elapsed, .rate = @as(f64, @floatFromInt(ok)) / @max(elapsed, 1e-9) };
}

pub const FlowsResult = struct {
    requested: u32,
    answered: u32,
    seconds: f64,
    rate: f64,
};

pub fn udpFlows(allocator: std.mem.Allocator, ep: addr.Endpoint, count: u32, hold_ms: u32) !FlowsResult {
    const fds = try allocator.alloc(i32, count);
    defer allocator.free(fds);
    const done = try allocator.alloc(bool, count);
    defer allocator.free(done);
    @memset(fds, -1);
    @memset(done, false);
    const sa = sys.Sockaddr.fromEndpoint(ep);
    const probe = "zeptun-udp-flow";
    var buf: [64]u8 = undefined;
    var answered: u32 = 0;
    const start = sys.monotonicNs();
    const batch = 128;
    var first: u32 = 0;
    while (first < count) {
        const last = @min(first + batch, count);
        for (fds[first..last]) |*fd| {
            const f = sock(ep.addr.family, true) catch continue;
            if (sys.connect(f, &sa) < 0) {
                sys.close(f);
                continue;
            }
            _ = sys.send(f, probe, 0);
            fd.* = f;
        }
        var round: u32 = 0;
        while (round < 200) : (round += 1) {
            var waiting: u32 = 0;
            for (fds[first..last], done[first..last]) |fd, *d| {
                if (d.* or fd < 0) continue;
                if (sys.recv(fd, &buf, sys.msg_dontwait) > 0) {
                    d.* = true;
                    answered += 1;
                } else {
                    waiting += 1;
                }
            }
            if (waiting == 0) break;
            if (round % 50 == 49) {
                for (fds[first..last], done[first..last]) |fd, d| {
                    if (!d and fd >= 0) _ = sys.send(fd, probe, 0);
                }
            }
            sys.sleepMs(1);
        }
        first = last;
    }
    const elapsed = @as(f64, @floatFromInt(sys.monotonicNs() - start)) / 1e9;
    sys.sleepMs(hold_ms);
    for (fds) |fd| {
        if (fd >= 0) sys.close(fd);
    }
    return .{ .requested = count, .answered = answered, .seconds = elapsed, .rate = @as(f64, @floatFromInt(answered)) / @max(elapsed, 1e-9) };
}

pub const VerifyResult = struct {
    bytes: u64,
    seconds: f64,
    gbps: f64,
    ok: bool,
};

const Xorshift = struct {
    s: u64,
    word: u64 = 0,
    left: u8 = 0,

    fn fill(x: *Xorshift, buf: []u8) void {
        for (buf) |*b| {
            if (x.left == 0) {
                x.s ^= x.s << 13;
                x.s ^= x.s >> 7;
                x.s ^= x.s << 17;
                x.word = x.s;
                x.left = 8;
            }
            b.* = @truncate(x.word);
            x.word >>= 8;
            x.left -= 1;
        }
    }
};

test "xorshift stream is independent of chunking" {
    var a: Xorshift = .{ .s = 12345 };
    var b: Xorshift = .{ .s = 12345 };
    var one: [1000]u8 = undefined;
    a.fill(&one);
    var parts: [1000]u8 = undefined;
    b.fill(parts[0..3]);
    b.fill(parts[3..500]);
    b.fill(parts[500..]);
    try std.testing.expectEqualSlices(u8, &one, &parts);
}

const VerifySender = struct {
    fd: i32,
    total: u64,
    seed: u64,
    ok: bool = true,

    fn run(s: *VerifySender) void {
        var rng: Xorshift = .{ .s = s.seed };
        var buf: [65536]u8 = undefined;
        var sent: u64 = 0;
        while (sent < s.total) {
            const n: usize = @intCast(@min(buf.len, s.total - sent));
            rng.fill(buf[0..n]);
            if (!writeFull(s.fd, buf[0..n])) {
                s.ok = false;
                return;
            }
            sent += n;
        }
        _ = sys.shutdown(s.fd, .write);
    }
};

pub fn verifyEcho(ep: addr.Endpoint, total: u64, seed: u64) !VerifyResult {
    const fd = try connectTcp(ep);
    defer sys.close(fd);
    const hdr = magic ++ [4]u8{ @backingInt(Mode.echo), 0, 0, 0 };
    if (!writeFull(fd, &hdr)) return error.HandshakeFailed;
    const start = sys.monotonicNs();
    var sender: VerifySender = .{ .fd = fd, .total = total, .seed = seed };
    const t = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, VerifySender.run, .{&sender});
    var rng: Xorshift = .{ .s = seed };
    var expect: [65536]u8 = undefined;
    var got: [65536]u8 = undefined;
    var received: u64 = 0;
    var ok = true;
    while (received < total) {
        const n = sys.linuxResult(linux.read(fd, &got, @intCast(@min(got.len, total - received))));
        if (n <= 0) {
            ok = false;
            break;
        }
        const len: usize = @intCast(n);
        rng.fill(expect[0..len]);
        if (ok and !std.mem.eql(u8, expect[0..len], got[0..len])) ok = false;
        received += len;
    }
    t.join();
    const elapsed = @as(f64, @floatFromInt(sys.monotonicNs() - start)) / 1e9;
    return .{ .bytes = received, .seconds = elapsed, .gbps = @as(f64, @floatFromInt(received)) * 8.0 / 1e9 / elapsed, .ok = ok and sender.ok and received == total };
}

pub const Sample = struct {
    cpu_pct: f64,
    rss_kb: u64,
    hwm_kb: u64,
    pss_kb: u64,
};

pub const MonitorResult = struct {
    samples: u32,
    avg_cpu_pct: f64,
    max_cpu_pct: f64,
    max_rss_kb: u64,
    peak_hwm_kb: u64,
    max_pss_kb: u64,
};

fn readProcFile(path: []const u8, buf: []u8) ?[]const u8 {
    var pbuf: [128]u8 = undefined;
    const z = std.mem.printSentinel(&pbuf, "{s}", .{path}, 0) catch return null;
    const fd_rc = linux.open(z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const fd = sys.linuxResult(fd_rc);
    if (fd < 0) return null;
    defer sys.close(fd);
    var off: usize = 0;
    while (off < buf.len) {
        const n = sys.linuxResult(linux.read(fd, buf[off..].ptr, buf.len - off));
        if (n <= 0) break;
        off += @intCast(n);
    }
    return buf[0..off];
}

fn cpuTicks(pid: i32) ?u64 {
    var path: [64]u8 = undefined;
    var buf: [4096]u8 = undefined;
    const p = std.mem.print(&path, "/proc/{d}/stat", .{pid}) catch return null;
    const text = readProcFile(p, &buf) orelse return null;
    const close = std.mem.findScalarLast(u8, text, ')') orelse return null;
    var it = std.mem.tokenizeScalar(u8, text[close + 1 ..], ' ');
    var field: usize = 2;
    var utime: u64 = 0;
    var stime: u64 = 0;
    while (it.next()) |tok| : (field += 1) {
        if (field == 13) utime = std.fmt.parseInt(u64, tok, 10) catch 0;
        if (field == 14) {
            stime = std.fmt.parseInt(u64, tok, 10) catch 0;
            break;
        }
    }
    return utime + stime;
}

fn statusKb(pid: i32, key: []const u8, file: []const u8) u64 {
    var path: [64]u8 = undefined;
    var buf: [16384]u8 = undefined;
    const p = std.mem.print(&path, "/proc/{d}/{s}", .{ pid, file }) catch return 0;
    const text = readProcFile(p, &buf) orelse return 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        var toks = std.mem.tokenizeAny(u8, line[key.len..], " \t:");
        const num = toks.next() orelse return 0;
        return std.fmt.parseInt(u64, num, 10) catch 0;
    }
    return 0;
}

pub fn monitor(pid: i32, seconds: u32, interval_ms: u32) !MonitorResult {
    const hz: f64 = 100.0;
    var prev = cpuTicks(pid) orelse return error.NoSuchProcess;
    var prev_ns = sys.monotonicNs();
    const deadline = prev_ns + @as(u64, seconds) * std.time.ns_per_s;
    var r: MonitorResult = .{ .samples = 0, .avg_cpu_pct = 0, .max_cpu_pct = 0, .max_rss_kb = 0, .peak_hwm_kb = 0, .max_pss_kb = 0 };
    var cpu_sum: f64 = 0;
    while (sys.monotonicNs() < deadline) {
        sys.sleepMs(interval_ms);
        const ticks = cpuTicks(pid) orelse break;
        const now = sys.monotonicNs();
        const dt = @as(f64, @floatFromInt(now - prev_ns)) / 1e9;
        const cpu = @as(f64, @floatFromInt(ticks - prev)) / hz / dt * 100.0;
        prev = ticks;
        prev_ns = now;
        const rss = statusKb(pid, "VmRSS", "status");
        const hwm = statusKb(pid, "VmHWM", "status");
        const pss = statusKb(pid, "Pss", "smaps_rollup");
        r.samples += 1;
        cpu_sum += cpu;
        r.max_cpu_pct = @max(r.max_cpu_pct, cpu);
        r.max_rss_kb = @max(r.max_rss_kb, rss);
        r.peak_hwm_kb = @max(r.peak_hwm_kb, hwm);
        r.max_pss_kb = @max(r.max_pss_kb, pss);
        std.debug.print("  cpu {d:>6.1}% rss {d:>7} KB pss {d:>7} KB hwm {d:>7} KB\n", .{ cpu, rss, pss, hwm });
    }
    r.avg_cpu_pct = if (r.samples > 0) cpu_sum / @as(f64, @floatFromInt(r.samples)) else 0;
    return r;
}

pub const DnsResult = struct {
    answer: ?addr.Address = null,
    rcode: u8 = 0,
    queries: u32 = 0,
    replies: u32 = 0,
    mean_us: f64 = 0,
    p50_us: f64 = 0,
    p99_us: f64 = 0,
};

pub fn dnsClient(server: addr.Endpoint, name: []const u8, aaaa: bool, count: u32) !DnsResult {
    const fd = try sock(server.addr.family, true);
    defer sys.close(fd);
    var sa = sys.Sockaddr.fromEndpoint(server);
    if (sys.connect(fd, &sa) < 0) return error.ConnectFailed;
    var q: [300]u8 = undefined;
    if (name.len > 253) return error.InvalidArgument;
    var off: usize = 12;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.InvalidArgument;
        q[off] = @intCast(label.len);
        @memcpy(q[off + 1 ..][0..label.len], label);
        off += 1 + label.len;
    }
    q[off] = 0;
    std.mem.writeInt(u16, q[off + 1 ..][0..2], if (aaaa) 28 else 1, .big);
    std.mem.writeInt(u16, q[off + 3 ..][0..2], 1, .big);
    const qlen = off + 5;
    var r: DnsResult = .{};
    var h: Histogram = .{};
    var total_ns: u64 = 0;
    var i: u32 = 0;
    while (i < @max(count, 1)) : (i += 1) {
        const id: u16 = @truncate(i *% 40503 +% 1);
        std.mem.writeInt(u16, q[0..2], id, .big);
        std.mem.writeInt(u16, q[2..4], 0x0100, .big);
        std.mem.writeInt(u16, q[4..6], 1, .big);
        @memset(q[6..12], 0);
        const t0 = sys.monotonicNs();
        if (sys.send(fd, q[0..qlen], 0) < 0) return error.SendFailed;
        r.queries += 1;
        var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        var buf: [1500]u8 = undefined;
        while (true) {
            if (sys.linuxResult(linux.poll(&pfd, 1, 2000)) <= 0) break;
            const n = sys.recv(fd, &buf, 0);
            if (n < 12) break;
            const resp = buf[0..@intCast(n)];
            if (std.mem.readInt(u16, resp[0..2], .big) != id) continue;
            const dt = sys.monotonicNs() - t0;
            total_ns += dt;
            h.add(dt / 1000);
            r.replies += 1;
            r.rcode = resp[3] & 0xf;
            if (std.mem.readInt(u16, resp[6..8], .big) > 0 and qlen + 12 <= resp.len) {
                const rdlen = std.mem.readInt(u16, resp[qlen + 10 ..][0..2], .big);
                if (qlen + 12 + rdlen <= resp.len) {
                    const rd = resp[qlen + 12 ..][0..rdlen];
                    if (rdlen == 4) r.answer = addr.Address.v4(rd[0..4].*);
                    if (rdlen == 16) r.answer = addr.Address.v6(rd[0..16].*);
                }
            }
            break;
        }
    }
    if (r.replies > 0) {
        r.mean_us = @as(f64, @floatFromInt(total_ns)) / @as(f64, @floatFromInt(r.replies)) / 1000.0;
        r.p50_us = h.percentileUs(0.5);
        r.p99_us = h.percentileUs(0.99);
    }
    return r;
}

test "histogram percentiles are monotonic" {
    var h: Histogram = .{};
    var i: u64 = 1;
    while (i <= 10000) : (i += 1) h.add(i * 1000);
    const p50 = h.percentileUs(0.5);
    const p99 = h.percentileUs(0.99);
    try std.testing.expect(p50 > 3000 and p50 < 7000);
    try std.testing.expect(p99 > p50 and p99 <= 10400);
}
