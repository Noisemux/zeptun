const std = @import("std");
const device = @import("device.zig");
const gso = @import("../packet/gso.zig");
const pool = @import("../packet/pool.zig");
const parse = @import("../packet/parse.zig");
const queue = @import("../queue.zig");

pub const Packet = extern struct {
    data: [*]const u8,
    len: usize,
};

pub const OutputFn = *const fn (ctx: ?*anyopaque, packets: [*]const Packet, count: usize) callconv(.c) void;
pub const WakeFn = *const fn (ctx: ?*anyopaque) void;

pub const InjectError = error{ TooLarge, Full, Closed };

pub const Shared = struct {
    allocator: std.mem.Allocator,
    inbound: queue.Mpsc(*pool.Buffer),
    input_pool: pool.Pool,
    lock: queue.SpinLock = .{},
    output: ?OutputFn = null,
    output_ctx: ?*anyopaque = null,
    wake: ?WakeFn = null,
    wake_ctx: ?*anyopaque = null,
    closed: std.atomic.Value(bool) = .init(false),
    mtu: u32,
    dropped: std.atomic.Value(usize) = .init(0),

    pub fn init(allocator: std.mem.Allocator, mtu: u32, capacity: u32) !*Shared {
        const s = try allocator.create(Shared);
        errdefer allocator.destroy(s);
        const buffer_size: u32 = @intCast(std.mem.alignForward(usize, pool.default_headroom + mtu + 64, 1024));
        s.* = .{
            .allocator = allocator,
            .inbound = try queue.Mpsc(*pool.Buffer).init(allocator, capacity),
            .input_pool = try pool.Pool.init(allocator, .{ .count = capacity, .buffer_size = buffer_size }),
            .mtu = mtu,
        };
        return s;
    }

    pub fn deinit(s: *Shared) void {
        while (s.inbound.pop()) |b| s.input_pool.putRemote(b);
        s.inbound.deinit(s.allocator);
        s.input_pool.deinit();
        s.allocator.destroy(s);
    }

    pub fn setOutput(s: *Shared, f: ?OutputFn, ctx: ?*anyopaque) void {
        s.output_ctx = ctx;
        s.output = f;
    }

    pub fn inject(s: *Shared, data: []const u8) InjectError!void {
        if (s.closed.load(.acquire)) return error.Closed;
        if (data.len == 0 or data.len > s.input_pool.buffer_size - pool.default_headroom) return error.TooLarge;
        s.lock.lock();
        const maybe = s.input_pool.get();
        s.lock.unlock();
        const b = maybe orelse {
            _ = s.dropped.fetchAdd(1, .monotonic);
            return error.Full;
        };
        @memcpy(b.tail()[0..data.len], data);
        b.len = @intCast(data.len);
        if (!s.inbound.push(b)) {
            s.input_pool.putRemote(b);
            _ = s.dropped.fetchAdd(1, .monotonic);
            return error.Full;
        }
        return;
    }

    pub fn injectBatch(s: *Shared, packets: []const Packet) usize {
        var n: usize = 0;
        for (packets) |p| {
            s.inject(p.data[0..p.len]) catch break;
            n += 1;
        }
        if (n > 0) s.notify();
        return n;
    }

    pub fn notify(s: *Shared) void {
        if (s.wake) |w| w(s.wake_ctx);
    }
};

pub const max_batch = 128;

pub fn Queue(comptime W: type) type {
    return struct {
        const Self = @This();

        worker: *W,
        shared: *Shared,
        caps: device.Capabilities,
        out: [max_batch]*pool.Buffer = undefined,
        out_desc: [max_batch]Packet = undefined,
        out_count: usize = 0,
        running: bool = false,

        pub fn init(q: *Self, w: *W, shared: *Shared) void {
            q.* = .{
                .worker = w,
                .shared = shared,
                .caps = .{ .mtu = shared.mtu, .queues = 1 },
            };
        }

        pub fn deinit(q: *Self) void {
            q.releaseOut();
        }

        pub fn start(q: *Self) !void {
            q.running = true;
        }

        pub fn stop(q: *Self) void {
            q.running = false;
            q.flush();
        }

        pub fn idle(q: *const Self) bool {
            _ = q;
            return true;
        }

        pub fn refill(q: *Self) void {
            _ = q;
        }

        pub fn poll(q: *Self) usize {
            var n: usize = 0;
            while (n < 1024) : (n += 1) {
                const b = q.shared.inbound.pop() orelse break;
                q.worker.counters.inc(.rx_packets);
                q.worker.counters.add(.rx_bytes, b.len);
                W.onDevicePacket(q.worker, b, .{});
            }
            return n;
        }

        fn push(q: *Self, b: *pool.Buffer) void {
            if (q.out_count == max_batch) q.flush();
            q.out[q.out_count] = b;
            q.out_count += 1;
        }

        pub fn send(q: *Self, b: *pool.Buffer, vh: gso.VirtioNetHdr) void {
            const w = q.worker;
            if (vh.isGso()) {
                defer w.pool.put(b);
                var seg = gso.Segmenter.init(b.bytes(), vh, true) catch {
                    w.counters.inc(.tx_dropped);
                    return;
                };
                while (true) {
                    const nb = w.pool.get() orelse {
                        w.counters.inc(.tx_dropped);
                        return;
                    };
                    const out = seg.next(nb.tail()) catch {
                        w.pool.put(nb);
                        w.counters.inc(.tx_dropped);
                        return;
                    } orelse {
                        w.pool.put(nb);
                        return;
                    };
                    nb.len = @intCast(out.len);
                    w.counters.inc(.gso_segments);
                    q.push(nb);
                }
            }
            if (vh.needsCsum()) gso.completeChecksum(b.bytes(), vh) catch {};
            q.push(b);
        }

        pub fn sendParts(q: *Self, header: []const u8, vh: gso.VirtioNetHdr, parts: []const device.PayloadRef) void {
            const w = q.worker;
            var total: usize = header.len;
            for (parts) |p| total += p.len;
            const b = w.pool.get() orelse {
                w.counters.inc(.tx_dropped);
                return;
            };
            if (b.tailroom() < total) {
                w.pool.put(b);
                w.counters.inc(.tx_dropped);
                return;
            }
            const dst = b.tail();
            @memcpy(dst[0..header.len], header);
            var off = header.len;
            for (parts) |p| {
                @memcpy(dst[off..][0..p.len], p.buf.ptr[p.off..][0..p.len]);
                off += p.len;
            }
            b.len = @intCast(total);
            q.send(b, vh);
        }

        pub fn sendCoalesced(q: *Self, b: *pool.Buffer) void {
            q.send(b, .{});
        }

        pub fn flush(q: *Self) void {
            if (q.out_count == 0) return;
            const w = q.worker;
            var bytes: u64 = 0;
            for (q.out[0..q.out_count], 0..) |b, i| {
                q.out_desc[i] = .{ .data = b.bytes().ptr, .len = b.len };
                bytes += b.len;
            }
            if (q.shared.output) |f| {
                f(q.shared.output_ctx, &q.out_desc, q.out_count);
                w.counters.add(.tx_packets, q.out_count);
                w.counters.add(.tx_bytes, bytes);
            } else {
                w.counters.add(.tx_dropped, q.out_count);
            }
            q.releaseOut();
        }

        fn releaseOut(q: *Self) void {
            for (q.out[0..q.out_count]) |b| q.worker.pool.put(b);
            q.out_count = 0;
        }
    };
}

test "inject and drain through shared queue" {
    var s = try Shared.init(std.testing.allocator, 1500, 8);
    defer s.deinit();
    try s.inject("abc");
    try std.testing.expectError(error.TooLarge, s.inject(&@as([4000]u8, @splat(0))));
    const b = s.inbound.pop().?;
    try std.testing.expectEqualStrings("abc", b.bytes());
    var worker_pool = try pool.Pool.init(std.testing.allocator, .{ .count = 1, .buffer_size = 256 });
    defer worker_pool.deinit();
    worker_pool.put(b);
    try std.testing.expectEqual(@as(u32, 1), s.input_pool.drainRemote());
}
