const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const config = @import("../config.zig");
const addr = @import("../addr.zig");
const sys = @import("../io/sys.zig");
const io = @import("../io/io.zig");
const pool = @import("../packet/pool.zig");
const timeouts = @import("../flow/timeouts.zig");
const log = @import("../log.zig");
const dns = @import("../stack/dns.zig");
const slab = @import("../flow/slab.zig");
pub const direct = @import("direct.zig");
pub const socks5 = @import("socks5.zig");
pub const passthrough = @import("passthrough.zig");

pub const Owner = enum(u8) { tcp, system, udp, redirect };

pub const early_iov = 8;

pub fn Dial(comptime W: type) type {
    return struct {
        const Self = @This();

        pub const Phase = enum(u8) { idle, connecting, sending, receiving, done };
        pub const Expect = enum(u8) { method, auth, reply };

        fd: sys.fd_t = sys.invalid_fd,
        buf: ?*DialBuf(W) = null,
        bypass: bool = false,
        target: addr.Endpoint = .{},
        bound: ?addr.Endpoint = null,
        owner: Owner = .tcp,
        phase: Phase = .idle,
        expect: Expect = .method,
        cmd: socks5.Command = .connect,
        pipelined: bool = false,
        pooled: bool = false,
        retried: bool = false,
        streaming: bool = false,
        has_fake: bool = false,
        tos: u8 = 0,
        fake: dns.Mapping = .{ .index = 0, .gen = 0 },
        timed_out: bool = false,
        aborted: bool = false,
        slen: u16 = 0,
        soff: u16 = 0,
        rlen: u16 = 0,
        rparsed: u16 = 0,
        niov: u8 = 0,
        early_len: u32 = 0,
        early_sent: u32 = 0,

        pub inline fn busy(d: *const Self) bool {
            return d.phase != .idle and d.phase != .done;
        }

        pub inline fn completionActive(d: *const Self) bool {
            return if (d.buf) |b| b.c.isActive() else false;
        }

        pub inline fn idle(d: *const Self) bool {
            return !d.completionActive();
        }

        pub fn leftover(d: *Self) []const u8 {
            const b = d.buf orelse return &.{};
            if (d.rlen <= d.rparsed) return &.{};
            const extra = b.rbuf[d.rparsed..d.rlen];
            d.rparsed = d.rlen;
            return extra;
        }
    };
}

pub fn DialBuf(comptime W: type) type {
    return struct {
        const Self = @This();

        c: W.Loop.Completion = .{},
        timer: timeouts.Timer = .{ .kind = @intFromEnum(timeouts.Kind.dial_timeout) },
        owner: ?*Dial(W) = null,
        next: ?*Self = null,
        sa: sys.Sockaddr = .{},
        iov: [early_iov + 1]sys.iovec_const = undefined,
        rbuf: [320]u8 = undefined,
        sbuf: [socks5.max_handshake]u8 = undefined,

        pub fn fromTimer(t: *timeouts.Timer) *Self {
            return @alignCast(@fieldParentPtr("timer", t));
        }
    };
}

pub const warm_capacity = 16;
pub const warm_min_rtt_us: u32 = 500;

pub const WarmKind = enum(u8) { tcp = 0, udp = 1 };

pub fn Warm(comptime W: type) type {
    return struct {
        const Self = @This();

        pub const State = enum(u8) { free, connecting, sending, receiving, ready };
        pub const Stage = enum(u8) { greet, auth, request };

        fd: sys.fd_t = sys.invalid_fd,
        udp_fd: sys.fd_t = sys.invalid_fd,
        c: W.Loop.Completion = .{},
        sa: sys.Sockaddr = .{},
        relay: sys.Sockaddr = .{},
        kind: WarmKind = .tcp,
        state: State = .free,
        stage: Stage = .greet,
        expired: bool = false,
        buf: [socks5.max_handshake]u8 = undefined,
        len: u16 = 0,
        off: u16 = 0,
        rbuf: [64]u8 = undefined,
        rlen: u16 = 0,
        timer: timeouts.Timer = .{ .kind = @intFromEnum(timeouts.Kind.pool_expire) },

        pub fn fromTimer(t: *timeouts.Timer) *Self {
            return @alignCast(@fieldParentPtr("timer", t));
        }
    };
}

pub const Demand = struct {
    start: u64 = 0,
    count: u32 = 0,
    prev: u32 = 0,
    last: u64 = 0,
};

pub const Taken = struct {
    fd: sys.fd_t,
    udp_fd: sys.fd_t,
    relay: sys.Sockaddr,
};

pub const Pending = struct {
    buf: *pool.Buffer,
    dst: addr.Endpoint,
    off: u32,
    len: u32,
    gso: u16,
};

pub const PendingQueue = struct {
    items: [16]Pending,
};

const tx_batch = 64;

pub const TxItem = struct {
    buf: *pool.Buffer,
    off: u32,
    len: u32,
    dst: addr.Endpoint,
};

pub const TxQueue = struct {
    items: [tx_batch]TxItem,
};

const TxSpan = struct {
    first: u8,
    count: u8,
};

const TxPlan = struct {
    msgs: [tx_batch]std.os.linux.mmsghdr = undefined,
    iovs: [2 * tx_batch]sys.iovec_const = undefined,
    names: [tx_batch]sys.Sockaddr = undefined,
    controls: [tx_batch][32]u8 align(8) = undefined,
    hdrs: [tx_batch][socks5.max_udp_header]u8 = undefined,
    spans: [tx_batch]TxSpan = undefined,
    count: usize = 0,
};

const RecvScratch = struct {
    name: sys.Sockaddr = .{},
    iov: [1]sys.iovec = undefined,
    msg: io.MsgHdr = undefined,
    control: [64]u8 align(8) = undefined,
};

const recv_batch = 16;
const gso_batch = 64;
const coalesce_limit: u32 = 64000;

const RecvBatch = struct {
    names: [recv_batch]sys.Sockaddr = undefined,
    iovs: [recv_batch]sys.iovec = undefined,
    msgs: [recv_batch]std.os.linux.mmsghdr = undefined,
    controls: [recv_batch][64]u8 align(8) = undefined,
    bufs: [recv_batch]*pool.Buffer = undefined,
};

pub fn UdpState(comptime W: type) type {
    return struct {
        const Self = @This();

        fd: sys.fd_t = sys.invalid_fd,
        family: addr.Family = .v4,
        rx_c: W.Loop.Completion = .{},
        rx_buf: ?*pool.Buffer = null,
        ctrl: if (build_options.enable_socks5) Dial(W) else void = if (build_options.enable_socks5) .{ .owner = .udp, .cmd = .udp_associate } else {},
        ctrl_c: W.Loop.Completion = .{},
        ctrl_byte: [4]u8 = undefined,
        fake_dst: ?addr.Endpoint = null,
        tos: u8 = 0,
        ready: bool = false,
        closing: bool = false,
        gro: bool = false,
        err_queue: bool = false,
        stream: bool = false,
        acc: ?*pool.Buffer = null,
        skip: u32 = 0,
        tx_c: W.Loop.Completion = .{},
        tx_buf: ?*pool.Buffer = null,
        pending: ?*PendingQueue = null,
        pending_count: u8 = 0,
        migrating: bool = false,
        tx_queued: bool = false,
        tx_count: u8 = 0,
        txq: ?*TxQueue = null,
        tx_next: ?*Self = null,

        pub fn idle(s: *const Self) bool {
            if (s.rx_c.isActive() or s.ctrl_c.isActive() or s.tx_c.isActive()) return false;
            if (build_options.enable_socks5 and s.ctrl.completionActive()) return false;
            return true;
        }
    };
}

const warm_backoff_min_ms: u32 = 1000;
const warm_backoff_max_ms: u32 = 30_000;

fn proxyRefused(e: sys.Errno) bool {
    return switch (e) {
        .connrefused, .connreset, .connaborted, .timedout, .pipe, .nobufs, .hostunreach, .netunreach, .netdown => true,
        else => false,
    };
}

pub fn Handler(comptime W: type) type {
    return struct {
        const Self = @This();
        const Loop = W.Loop;
        const D = Dial(W);
        const B = DialBuf(W);
        const U = UdpState(W);
        const Wc = Warm(W);
        const buf_chunk = 16;
        const Chunk = struct {
            next: ?*Chunk,
            items: [buf_chunk]B,
        };

        kind: config.HandlerKind,
        cfg: *const config.Config,
        protect: direct.Protect,
        connect_timeout_ms: u32,
        warm: []Wc = &.{},
        warm_size: u16,
        warm_idle_ms: u32,
        warm_ready: [2]u16 = .{ 0, 0 },
        warm_pending: [2]u16 = .{ 0, 0 },
        warm_backoff: u64 = 0,
        warm_backoff_ms: u32 = 0,
        demand: [2]Demand = .{ .{}, .{} },
        stopping: bool = false,
        fake: ?*dns.Table = null,
        allocator: std.mem.Allocator,
        free_bufs: ?*B = null,
        chunks: ?*Chunk = null,
        pending_queues: slab.Slab(PendingQueue, 32) = .{},
        tx_queues: slab.Slab(TxQueue, 4) = .{},
        tx_head: ?*U = null,
        udp_gso: bool = true,
        proxy_rtt_us: u32 = 0,
        proxy_rtt_known: bool = false,

        pub fn init(allocator: std.mem.Allocator, cfg: *const config.Config, protect: direct.Protect, fake: ?*dns.Table) !Self {
            var p = protect;
            p.resolve();
            const socks = cfg.handler.kind == .socks5 and build_options.enable_socks5;
            const size: u16 = if (socks) @min(cfg.handler.socks5.pool_size, warm_capacity) else 0;
            const warm = try allocator.alloc(Wc, 2 * @as(usize, size));
            for (warm) |*s| s.* = .{};
            return .{
                .allocator = allocator,
                .kind = cfg.handler.kind,
                .cfg = cfg,
                .protect = p,
                .fake = if (socks) fake else null,
                .connect_timeout_ms = cfg.stack.tcp_connect_timeout_ms,
                .warm = warm,
                .warm_size = size,
                .warm_idle_ms = @max(cfg.handler.socks5.pool_idle_ms, 100),
            };
        }

        pub fn deinit(h: *Self) void {
            var it = h.chunks;
            while (it) |chunk| {
                it = chunk.next;
                h.allocator.destroy(chunk);
            }
            h.chunks = null;
            h.free_bufs = null;
            h.pending_queues.deinit(h.allocator);
            h.tx_queues.deinit(h.allocator);
            h.allocator.free(h.warm);
            h.warm = &.{};
        }

        fn takeBuf(h: *Self, d: *D) bool {
            const b = h.free_bufs orelse blk: {
                const chunk = h.allocator.create(Chunk) catch return false;
                chunk.next = h.chunks;
                h.chunks = chunk;
                for (chunk.items[1..]) |*item| {
                    item.next = h.free_bufs;
                    h.free_bufs = item;
                }
                chunk.items[0].next = null;
                break :blk &chunk.items[0];
            };
            if (b == h.free_bufs) h.free_bufs = b.next;
            b.c = .{ .userdata = d, .callback = onDial };
            b.timer = .{ .kind = @intFromEnum(timeouts.Kind.dial_timeout) };
            b.owner = d;
            b.next = null;
            d.buf = b;
            return true;
        }

        fn putBuf(h: *Self, b: *B) void {
            b.owner = null;
            b.next = h.free_bufs;
            h.free_bufs = b;
        }

        inline fn workerOf(loop: *Loop) *W {
            return @alignCast(@fieldParentPtr("loop", loop));
        }

        inline fn socksMode(h: *const Self) bool {
            return h.kind == .socks5 and build_options.enable_socks5;
        }

        fn openSocket(h: *Self, w: *W, family: addr.Family, out: *sys.fd_t) sys.Errno {
            const fd = sys.socket(family, .tcp) catch |err| {
                log.debug("dial socket failed: {t}", .{err});
                return .mfile;
            };
            h.protect.apply(fd, family) catch {
                sys.close(fd);
                return .perm;
            };
            direct.tuneTcp(fd);
            if (h.cfg.handler.tcp_fastopen) direct.fastOpen(fd);
            w.loop.register(fd) catch {
                sys.close(fd);
                return .badf;
            };
            out.* = fd;
            return .success;
        }

        fn openFresh(h: *Self, w: *W, d: *D) sys.Errno {
            const b = d.buf.?;
            const server = if (h.socksMode() and !d.bypass) h.cfg.handler.socks5.server else d.target;
            const e = h.openSocket(w, server.addr.family, &d.fd);
            if (e != .success) return e;
            if (h.cfg.handler.preserve_dscp) direct.setDscp(d.fd, server.addr.family, d.tos);
            b.sa = sys.Sockaddr.fromEndpoint(server);
            d.phase = .connecting;
            b.c.op = .{ .connect = .{ .fd = d.fd, .addr = &b.sa } };
            return .success;
        }

        pub fn dialTcp(h: *Self, w: *W, d: *D, target: addr.Endpoint, owner: Owner) void {
            d.owner = owner;
            d.target = target;
            d.bound = null;
            d.timed_out = false;
            d.aborted = false;
            d.pooled = false;
            d.retried = false;
            d.streaming = false;
            d.rlen = 0;
            d.rparsed = 0;
            d.slen = 0;
            d.soff = 0;
            d.early_len = 0;
            d.early_sent = 0;
            d.has_fake = false;
            d.cmd = if (owner != .udp) .connect else if (h.cfg.handler.socks5.udp_mode == .tcp) .fwd_udp else .udp_associate;
            if (!h.takeBuf(d)) return h.finish(w, d, .nobufs);
            const b = d.buf.?;
            if (owner != .udp) {
                if (h.fake) |t| {
                    if (t.indexOf(target.addr) != null) {
                        d.fake = t.mappingOf(target.addr) orelse return h.finish(w, d, .hostunreach);
                        d.has_fake = true;
                    }
                }
                if (!d.has_fake and target.port == dns.port) {
                    if (h.cfg.dns.upstream) |up| {
                        const local = addrEql(h.cfg.dnsAddress4(), target.addr) or addrEql(h.cfg.dnsAddress6(), target.addr);
                        if (h.cfg.dns.hijack or local) {
                            d.target = up;
                            w.counters.inc(.dns_hijacked);
                        }
                    }
                }
            }
            if (h.socksMode() and !d.bypass and h.warm_size > 0 and owner != .udp) {
                h.noteDemand(.tcp, w.now());
                if (h.takeWarm(w, .tcp)) |taken| {
                    const fd = taken.fd;
                    w.counters.inc(.socks5_pool_hits);
                    if (h.cfg.handler.preserve_dscp) direct.setDscp(fd, h.cfg.handler.socks5.server.addr.family, d.tos);
                    d.fd = fd;
                    d.pooled = true;
                    d.pipelined = true;
                    if (!h.beginRequest(w, d, &b.c)) {
                        w.loop.unregister(fd);
                        sys.close(fd);
                        d.fd = sys.invalid_fd;
                        return h.finish(w, d, .hostunreach);
                    }
                    w.loop.submit(&b.c);
                    w.wheel.schedule(&b.timer, w.now() + h.connect_timeout_ms);
                    if (h.warm_ready[@intFromEnum(WarmKind.tcp)] == 0) h.refill(w);
                    return;
                }
            }
            const e = h.openFresh(w, d);
            if (e != .success) return h.finish(w, d, e);
            w.loop.submit(&b.c);
            w.wheel.schedule(&b.timer, w.now() + h.connect_timeout_ms);
            if (h.socksMode() and !d.bypass and h.warm_size > 0 and owner != .udp) h.refill(w);
        }

        fn addrEql(a: ?addr.Address, b: addr.Address) bool {
            return if (a) |x| x.eql(b) else false;
        }

        fn requestTarget(h: *Self, d: *const D, name: *[dns.max_name]u8) ?socks5.Target {
            if (d.cmd == .udp_associate or d.cmd == .fwd_udp) return .{ .ip = .{ .addr = if (d.target.addr.family == .v4) addr.Address.v4(@splat(0)) else addr.Address.v6(@splat(0)), .port = 0 } };
            if (d.has_fake) {
                const t = h.fake orelse return null;
                const n = t.copyName(d.fake, name) orelse return null;
                return .{ .host = .{ .name = n, .port = d.target.port } };
            }
            return .{ .ip = d.target };
        }

        fn beginRequest(h: *Self, w: *W, d: *D, c: *Loop.Completion) bool {
            var name: [dns.max_name]u8 = undefined;
            const target = h.requestTarget(d, &name) orelse return false;
            const msg = socks5.encodeRequestTo(&d.buf.?.sbuf, d.cmd, target);
            d.slen = @intCast(msg.len);
            d.soff = 0;
            d.expect = .reply;
            h.sendWithEarly(w, d, c);
            return true;
        }

        fn sendWithEarly(h: *Self, w: *W, d: *D, c: *Loop.Completion) void {
            d.early_len = 0;
            d.early_sent = 0;
            if ((d.pipelined or d.expect == .reply) and h.cfg.handler.socks5.optimistic_data and d.cmd == .connect) {
                const b = d.buf.?;
                const early = W.dialEarlyData(w, d, b.iov[1..]);
                if (early > 0) {
                    b.iov[0] = .{ .base = &b.sbuf, .len = d.slen };
                    d.early_len = early;
                    d.phase = .sending;
                    c.op = .{ .writev = .{ .fd = d.fd, .iov = b.iov[0..d.niov] } };
                    return;
                }
            }
            h.startSend(d, c);
        }

        fn onSent(h: *Self, w: *W, d: *D, c: *Loop.Completion, sent: u32) void {
            if (d.early_len > 0) {
                if (sent >= d.slen) {
                    d.early_sent = @min(sent - d.slen, d.early_len);
                    d.soff = d.slen;
                } else {
                    d.soff = @intCast(sent);
                }
                d.early_len = 0;
            } else {
                d.soff += @intCast(sent);
            }
            const b = d.buf.?;
            if (d.soff < d.slen) {
                c.op = .{ .send = .{ .fd = d.fd, .buf = b.sbuf[d.soff..d.slen] } };
                return;
            }
            d.phase = .receiving;
            d.streaming = d.cmd == .connect and h.cfg.handler.socks5.optimistic_data and (d.pipelined or d.expect == .reply);
            if (d.streaming) W.dialStream(w, d);
            c.op = .{ .recv = .{ .fd = d.fd, .buf = b.rbuf[d.rlen..] } };
        }

        fn noteDemand(h: *Self, kind: WarmKind, now: u64) void {
            const d = &h.demand[@intFromEnum(kind)];
            if (now -% d.start >= h.warm_idle_ms) {
                d.prev = if (now -% d.start >= 2 * @as(u64, h.warm_idle_ms)) 0 else d.count;
                d.count = 0;
                d.start = now;
            }
            d.count += 1;
            d.last = now;
        }

        fn noteProxyRtt(h: *Self, fd: sys.fd_t) void {
            const rtt = direct.tcpRttUs(fd) orelse return;
            const was_near = h.proxyNear();
            if (!h.proxy_rtt_known) {
                h.proxy_rtt_us = rtt;
                h.proxy_rtt_known = true;
            } else {
                h.proxy_rtt_us = h.proxy_rtt_us - h.proxy_rtt_us / 8 + rtt / 8;
            }
            if (was_near != h.proxyNear()) log.debug("socks5: proxy round trip {d} us, connection pool {s}", .{ h.proxy_rtt_us, if (h.proxyNear()) "paused" else "active" });
        }

        fn proxyNear(h: *const Self) bool {
            return h.proxy_rtt_known and h.proxy_rtt_us < warm_min_rtt_us;
        }

        fn warmTarget(h: *const Self, kind: WarmKind, now: u64) u16 {
            const d = h.demand[@intFromEnum(kind)];
            if (h.stopping or d.last == 0 or now -% d.last > 3 * @as(u64, h.warm_idle_ms)) return 0;
            if (h.proxyNear()) return 0;
            if (now < h.warm_backoff) return 0;
            if (kind == .udp and h.cfg.handler.socks5.udp == .disabled) return 0;
            const want = @max(@max(d.count, d.prev), 1);
            return @intCast(@min(want, h.warm_size));
        }

        fn refill(h: *Self, w: *W) void {
            if (!build_options.enable_socks5) return;
            const kinds = [_]WarmKind{ .tcp, .udp };
            for (kinds) |kind| {
                const k = @intFromEnum(kind);
                const target = h.warmTarget(kind, w.now());
                while (h.warm_ready[k] + h.warm_pending[k] < target) {
                    if (!h.startWarm(w, kind)) break;
                }
            }
        }

        fn takeWarm(h: *Self, w: *W, kind: WarmKind) ?Taken {
            if (!build_options.enable_socks5) return null;
            const k = @intFromEnum(kind);
            while (h.warm_ready[k] > 0) {
                var best: ?*Wc = null;
                for (h.warm) |*s| {
                    if (s.state != .ready or s.kind != kind) continue;
                    if (best == null or s.timer.deadline > best.?.timer.deadline) best = s;
                }
                const s = best orelse return null;
                w.wheel.cancel(&s.timer);
                h.warm_ready[k] -= 1;
                const taken: Taken = .{ .fd = s.fd, .udp_fd = s.udp_fd, .relay = s.relay };
                s.fd = sys.invalid_fd;
                s.udp_fd = sys.invalid_fd;
                s.state = .free;
                if (direct.alive(taken.fd)) return taken;
                w.loop.unregister(taken.fd);
                sys.close(taken.fd);
                if (taken.udp_fd != sys.invalid_fd) {
                    w.loop.unregister(taken.udp_fd);
                    sys.close(taken.udp_fd);
                }
            }
            return null;
        }

        fn proxyBusy(h: *Self, w: *W) void {
            if (!build_options.enable_socks5) return;
            const next = if (h.warm_backoff_ms == 0) warm_backoff_min_ms else @min(h.warm_backoff_ms * 2, warm_backoff_max_ms);
            h.warm_backoff_ms = next;
            h.warm_backoff = w.now() + next;
            for (h.warm) |*s| {
                if (s.state == .ready) h.dropWarm(w, s, false);
            }
        }

        fn proxyHealthy(h: *Self) void {
            h.warm_backoff_ms = 0;
        }

        fn startWarm(h: *Self, w: *W, kind: WarmKind) bool {
            const slot = for (h.warm) |*s| {
                if (s.state == .free and !s.c.isActive()) break s;
            } else return false;
            const server = h.cfg.handler.socks5.server;
            var fd: sys.fd_t = sys.invalid_fd;
            if (h.openSocket(w, server.addr.family, &fd) != .success) {
                h.proxyBusy(w);
                return false;
            }
            slot.* = .{ .fd = fd, .kind = kind, .state = .connecting, .sa = sys.Sockaddr.fromEndpoint(server) };
            slot.c = .{ .op = .{ .connect = .{ .fd = fd, .addr = &slot.sa } }, .userdata = slot, .callback = onWarm };
            h.warm_pending[@intFromEnum(kind)] += 1;
            w.loop.submit(&slot.c);
            w.wheel.schedule(&slot.timer, w.now() + h.warm_idle_ms);
            return true;
        }

        fn dropWarm(h: *Self, w: *W, s: *Wc, failed: bool) void {
            const k = @intFromEnum(s.kind);
            if (s.state == .ready) {
                h.warm_ready[k] -= 1;
            } else if (s.state != .free) {
                h.warm_pending[k] -= 1;
            }
            w.wheel.cancel(&s.timer);
            if (s.fd != sys.invalid_fd) {
                w.loop.unregister(s.fd);
                sys.close(s.fd);
            }
            if (s.udp_fd != sys.invalid_fd) {
                w.loop.unregister(s.udp_fd);
                sys.close(s.udp_fd);
            }
            s.fd = sys.invalid_fd;
            s.udp_fd = sys.invalid_fd;
            s.state = .free;
            if (failed) h.proxyBusy(w);
        }

        pub fn onWarmExpire(h: *Self, w: *W, s: *Wc) void {
            if (!build_options.enable_socks5) return;
            switch (s.state) {
                .free => {},
                .ready => {
                    h.dropWarm(w, s, false);
                    h.refill(w);
                },
                else => {
                    s.expired = true;
                    if (s.c.isActive()) w.loop.cancel(&s.c);
                },
            }
        }

        fn warmSend(s: *Wc, c: *Loop.Completion, msg_len: usize) io.Disposition {
            s.len = @intCast(msg_len);
            s.off = 0;
            s.state = .sending;
            c.op = .{ .send = .{ .fd = s.fd, .buf = s.buf[0..s.len] } };
            return .rearm;
        }

        fn warmReady(h: *Self, s: *Wc) io.Disposition {
            h.proxyHealthy();
            const k = @intFromEnum(s.kind);
            s.state = .ready;
            h.warm_pending[k] -= 1;
            h.warm_ready[k] += 1;
            return .disarm;
        }

        fn warmGreeted(h: *Self, w: *W, s: *Wc, c: *Loop.Completion) io.Disposition {
            if (s.kind == .tcp) return h.warmReady(s);
            const server = h.cfg.handler.socks5.server;
            const cmd: socks5.Command = if (h.cfg.handler.socks5.udp_mode == .tcp) .fwd_udp else .udp_associate;
            const zero: addr.Endpoint = .{ .addr = if (server.addr.family == .v4) addr.Address.v4(@splat(0)) else addr.Address.v6(@splat(0)), .port = 0 };
            s.stage = .request;
            _ = w;
            return warmSend(s, c, socks5.encodeRequest(&s.buf, cmd, zero).len);
        }

        fn warmAssociated(h: *Self, w: *W, s: *Wc, bound: ?addr.Endpoint) io.Disposition {
            if (h.cfg.handler.socks5.udp_mode == .tcp) return h.warmReady(s);
            const server = h.cfg.handler.socks5.server;
            var relay = bound orelse server;
            if (relay.addr.isUnspecified()) relay.addr = server.addr;
            if (h.cfg.handler.socks5.udp_address) |ua| {
                if (ua.family == relay.addr.family) relay.addr = ua;
            }
            const ufd = sys.socket(relay.addr.family, .udp) catch {
                h.dropWarm(w, s, true);
                return .disarm;
            };
            h.protect.apply(ufd, relay.addr.family) catch {
                sys.close(ufd);
                h.dropWarm(w, s, true);
                return .disarm;
            };
            s.relay = sys.Sockaddr.fromEndpoint(relay);
            if (sys.connect(ufd, &s.relay) < 0) {
                sys.close(ufd);
                h.dropWarm(w, s, true);
                return .disarm;
            }
            w.loop.register(ufd) catch {};
            s.udp_fd = ufd;
            return h.warmReady(s);
        }

        fn onWarm(ud: ?*anyopaque, loop: *Loop, c: *Loop.Completion, result: i32) io.Disposition {
            const s: *Wc = @ptrCast(@alignCast(ud.?));
            const w = workerOf(loop);
            const h = &w.handler;
            if (s.expired or h.stopping) {
                h.dropWarm(w, s, false);
                if (!h.stopping) h.refill(w);
                return .disarm;
            }
            if (result < 0) {
                const e = sys.toErrno(result);
                if ((e == .again or e == .intr) and s.state != .connecting) return .rearm;
                h.dropWarm(w, s, true);
                return .disarm;
            }
            const s5 = &h.cfg.handler.socks5;
            switch (s.state) {
                .connecting => {
                    h.noteProxyRtt(s.fd);
                    s.stage = .greet;
                    return warmSend(s, c, socks5.encodeGreeting(&s.buf, !s5.username.isEmpty()).len);
                },
                .sending => {
                    s.off += @intCast(result);
                    if (s.off < s.len) {
                        c.op = .{ .send = .{ .fd = s.fd, .buf = s.buf[s.off..s.len] } };
                        return .rearm;
                    }
                    s.state = .receiving;
                    s.rlen = 0;
                    c.op = .{ .recv = .{ .fd = s.fd, .buf = &s.rbuf } };
                    return .rearm;
                },
                .receiving => {
                    if (result == 0) {
                        h.dropWarm(w, s, true);
                        return .disarm;
                    }
                    s.rlen += @intCast(result);
                    const data = s.rbuf[0..s.rlen];
                    switch (s.stage) {
                        .greet => {
                            const m = socks5.parseMethodReply(data) catch |err| {
                                if (err == error.NeedMore) {
                                    c.op = .{ .recv = .{ .fd = s.fd, .buf = s.rbuf[s.rlen..] } };
                                    return .rearm;
                                }
                                h.dropWarm(w, s, true);
                                return .disarm;
                            };
                            if (m == .password) {
                                const msg = socks5.encodePasswordAuth(&s.buf, s5.username.slice(), s5.password.slice()) catch {
                                    h.dropWarm(w, s, true);
                                    return .disarm;
                                };
                                s.stage = .auth;
                                return warmSend(s, c, msg.len);
                            }
                            return h.warmGreeted(w, s, c);
                        },
                        .auth => {
                            socks5.parseAuthReply(data) catch |err| {
                                if (err == error.NeedMore) {
                                    c.op = .{ .recv = .{ .fd = s.fd, .buf = s.rbuf[s.rlen..] } };
                                    return .rearm;
                                }
                                h.dropWarm(w, s, true);
                                return .disarm;
                            };
                            return h.warmGreeted(w, s, c);
                        },
                        .request => {
                            const r = socks5.parseReply(data) catch |err| {
                                if (err == error.NeedMore and s.rlen < s.rbuf.len) {
                                    c.op = .{ .recv = .{ .fd = s.fd, .buf = s.rbuf[s.rlen..] } };
                                    return .rearm;
                                }
                                h.dropWarm(w, s, true);
                                return .disarm;
                            };
                            return h.warmAssociated(w, s, r.bound);
                        },
                    }
                },
                .free, .ready => return .disarm,
            }
        }

        pub fn stop(h: *Self, w: *W) void {
            h.stopping = true;
            h.dropPool(w);
        }

        pub fn dropPool(h: *Self, w: *W) void {
            if (!build_options.enable_socks5) return;
            for (h.warm) |*s| {
                switch (s.state) {
                    .free => {},
                    .ready => h.dropWarm(w, s, false),
                    else => {
                        s.expired = true;
                        if (s.c.isActive()) w.loop.cancel(&s.c);
                    },
                }
            }
        }

        pub fn idle(h: *const Self) bool {
            if (!build_options.enable_socks5) return true;
            for (h.warm) |*s| {
                if (s.c.isActive()) return false;
            }
            return true;
        }

        pub fn abortDial(h: *Self, w: *W, d: *D) void {
            _ = h;
            if (!d.busy()) return;
            d.aborted = true;
            if (d.buf) |b| {
                if (b.c.isActive()) w.loop.cancel(&b.c);
            }
        }

        pub fn onDialTimeout(h: *Self, w: *W, b: *B) void {
            _ = h;
            const d = b.owner orelse return;
            if (!d.busy()) return;
            d.timed_out = true;
            if (b.c.isActive()) w.loop.cancel(&b.c);
        }

        fn finish(h: *Self, w: *W, d: *D, result: sys.Errno) void {
            if (result == .success) h.proxyHealthy();
            const held = d.buf;
            if (held) |b| w.wheel.cancel(&b.timer);
            if (d.pooled and d.owner != .udp and !h.stopping) h.refill(w);
            if (result != .success) {
                if (d.fd != sys.invalid_fd) {
                    w.loop.unregister(d.fd);
                    sys.close(d.fd);
                }
                d.fd = sys.invalid_fd;
                d.phase = .idle;
            } else {
                d.phase = .done;
            }
            W.onDialDone(w, d, result);
            if (held) |b| {
                if (d.buf == b) d.buf = null;
                h.putBuf(b);
            }
        }

        fn onDial(ud: ?*anyopaque, loop: *Loop, c: *Loop.Completion, result: i32) io.Disposition {
            const d: *D = @ptrCast(@alignCast(ud.?));
            const w = workerOf(loop);
            const h = &w.handler;
            if (d.aborted) {
                h.finish(w, d, .canceled);
                return .disarm;
            }
            if (d.timed_out) {
                h.finish(w, d, .timedout);
                return .disarm;
            }
            if (result < 0) {
                const e = sys.toErrno(result);
                if ((e == .again or e == .intr) and d.phase != .connecting) return .rearm;
                if (h.socksMode() and !d.bypass and proxyRefused(e)) h.proxyBusy(w);
                if (h.canRetry(d)) return h.retryFresh(w, d);
                h.finish(w, d, e);
                return .disarm;
            }
            switch (d.phase) {
                .connecting => {
                    if (!h.socksMode() or d.bypass) {
                        h.finish(w, d, .success);
                        return .disarm;
                    }
                    h.noteProxyRtt(d.fd);
                    const s5 = &h.cfg.handler.socks5;
                    d.pipelined = switch (s5.pipeline) {
                        .on => true,
                        .off => false,
                        .auto => s5.username.slice().len == 0,
                    };
                    var name: [dns.max_name]u8 = undefined;
                    const target = h.requestTarget(d, &name) orelse {
                        h.finish(w, d, .hostunreach);
                        return .disarm;
                    };
                    const msg = socks5.encodeHandshake(&d.buf.?.sbuf, target, d.cmd, s5.username.slice(), s5.password.slice(), d.pipelined) catch {
                        h.finish(w, d, .inval);
                        return .disarm;
                    };
                    d.slen = @intCast(msg.len);
                    d.soff = 0;
                    d.expect = .method;
                    h.sendWithEarly(w, d, c);
                    return .rearm;
                },
                .sending => {
                    h.onSent(w, d, c, @intCast(result));
                    return .rearm;
                },
                .receiving => {
                    if (result == 0) {
                        if (h.canRetry(d)) return h.retryFresh(w, d);
                        h.finish(w, d, .connreset);
                        return .disarm;
                    }
                    d.rlen += @intCast(result);
                    direct.quickAck(d.fd);
                    return h.progress(w, d, c);
                },
                .idle, .done => return .disarm,
            }
        }

        fn canRetry(h: *const Self, d: *const D) bool {
            _ = h;
            return d.pooled and !d.retried and d.rlen == 0 and !d.aborted and !d.timed_out;
        }

        fn retryFresh(h: *Self, w: *W, d: *D) io.Disposition {
            w.counters.inc(.socks5_pool_retries);
            w.loop.unregister(d.fd);
            sys.close(d.fd);
            d.fd = sys.invalid_fd;
            d.pooled = false;
            d.retried = true;
            d.streaming = false;
            d.early_len = 0;
            d.early_sent = 0;
            d.rlen = 0;
            d.rparsed = 0;
            h.proxyBusy(w);
            const e = h.openFresh(w, d);
            if (e != .success) {
                h.finish(w, d, e);
                return .disarm;
            }
            return .rearm;
        }

        fn startSend(h: *Self, d: *D, c: *Loop.Completion) void {
            _ = h;
            d.phase = .sending;
            c.op = .{ .send = .{ .fd = d.fd, .buf = d.buf.?.sbuf[d.soff..d.slen] } };
        }

        fn progress(h: *Self, w: *W, d: *D, c: *Loop.Completion) io.Disposition {
            const s5 = &h.cfg.handler.socks5;
            const b = d.buf.?;
            while (true) {
                const data = b.rbuf[d.rparsed..d.rlen];
                switch (d.expect) {
                    .method => {
                        const m = socks5.parseMethodReply(data) catch |err| return h.handshakeError(w, d, c, err);
                        d.rparsed += 2;
                        if (m == .password) {
                            if (s5.username.isEmpty()) return h.handshakeError(w, d, c, error.NoAcceptableMethod);
                            d.expect = .auth;
                            if (!d.pipelined) {
                                const msg = socks5.encodePasswordAuth(&b.sbuf, s5.username.slice(), s5.password.slice()) catch return h.handshakeError(w, d, c, error.TooLong);
                                d.slen = @intCast(msg.len);
                                d.soff = 0;
                                h.startSend(d, c);
                                return .rearm;
                            }
                        } else {
                            d.expect = .reply;
                            if (!d.pipelined) {
                                if (!h.beginRequest(w, d, c)) {
                                    h.finish(w, d, .hostunreach);
                                    return .disarm;
                                }
                                return .rearm;
                            }
                        }
                    },
                    .auth => {
                        socks5.parseAuthReply(data) catch |err| return h.handshakeError(w, d, c, err);
                        d.rparsed += 2;
                        d.expect = .reply;
                        if (!d.pipelined) {
                            if (!h.beginRequest(w, d, c)) {
                                h.finish(w, d, .hostunreach);
                                return .disarm;
                            }
                            return .rearm;
                        }
                    },
                    .reply => {
                        const r = socks5.parseReply(data) catch |err| return h.handshakeError(w, d, c, err);
                        d.rparsed += @intCast(r.len);
                        d.bound = r.bound;
                        h.finish(w, d, .success);
                        return .disarm;
                    },
                }
            }
        }

        fn handshakeError(h: *Self, w: *W, d: *D, c: *Loop.Completion, err: socks5.Error) io.Disposition {
            if (err == error.NeedMore) {
                const b = d.buf.?;
                if (d.rlen >= b.rbuf.len) {
                    h.finish(w, d, .proto);
                    return .disarm;
                }
                c.op = .{ .recv = .{ .fd = d.fd, .buf = b.rbuf[d.rlen..] } };
                return .rearm;
            }
            const e: sys.Errno = switch (err) {
                error.Refused => .connrefused,
                error.Unreachable => .hostunreach,
                error.NotAllowed, error.AuthFailed, error.NoAcceptableMethod => .acces,
                else => .proto,
            };
            h.finish(w, d, e);
            return .disarm;
        }

        pub fn udpOpen(h: *Self, w: *W, s: *U, family: addr.Family, tos: u8, bypass: bool) bool {
            s.* = .{ .family = family, .tos = if (h.cfg.handler.preserve_dscp) tos else 0 };
            if (h.kind == .socks5 and !bypass and build_options.enable_socks5) {
                if (h.cfg.handler.socks5.udp == .disabled) return false;
                s.ctrl.tos = s.tos;
                if (h.warm_size > 0) {
                    h.noteDemand(.udp, w.now());
                    const taken = h.takeWarm(w, .udp);
                    defer h.refill(w);
                    if (taken) |t| {
                        w.counters.inc(.socks5_pool_hits);
                        h.adoptAssociation(w, s, t);
                        return true;
                    }
                }
                h.dialTcp(w, &s.ctrl, .{ .addr = h.cfg.handler.socks5.server.addr, .port = 0 }, .udp);
                return true;
            }
            const fd = sys.socket(family, .udp) catch return false;
            h.protect.apply(fd, family) catch {
                sys.close(fd);
                return false;
            };
            direct.setDscp(fd, family, s.tos);
            s.gro = direct.tuneUdp(fd);
            s.err_queue = direct.recvErrors(fd, family);
            w.loop.register(fd) catch {
                sys.close(fd);
                return false;
            };
            s.fd = fd;
            s.ready = true;
            h.armRecv(w, s);
            return true;
        }

        pub fn onUdpControlReady(h: *Self, w: *W, s: *U, result: sys.Errno) void {
            if (result != .success or s.closing) {
                h.dropPending(w, s);
                W.onUdpClosed(w, s);
                return;
            }
            if (s.ctrl.cmd == .fwd_udp) {
                s.fd = s.ctrl.fd;
                s.ctrl.fd = sys.invalid_fd;
                s.stream = true;
                s.ready = true;
                const extra = s.ctrl.leftover();
                if (extra.len > 0) {
                    if (w.pool.get()) |acc| {
                        acc.reset(0);
                        @memcpy(acc.ptr[0..extra.len], extra);
                        acc.len = @intCast(extra.len);
                        s.acc = acc;
                        if (!h.parseFrames(w, s)) {
                            W.onUdpUpstreamGone(w, s);
                            return;
                        }
                    }
                }
                h.flushPending(w, s);
                h.armRecv(w, s);
                return;
            }
            var relay = s.ctrl.bound orelse h.cfg.handler.socks5.server;
            if (relay.addr.isUnspecified()) relay.addr = h.cfg.handler.socks5.server.addr;
            if (h.cfg.handler.socks5.udp_address) |ua| {
                if (ua.family == relay.addr.family) relay.addr = ua;
            }
            const fd = sys.socket(relay.addr.family, .udp) catch {
                h.dropPending(w, s);
                W.onUdpClosed(w, s);
                return;
            };
            h.protect.apply(fd, relay.addr.family) catch {
                sys.close(fd);
                h.dropPending(w, s);
                W.onUdpClosed(w, s);
                return;
            };
            direct.setDscp(fd, relay.addr.family, s.tos);
            s.gro = direct.tuneUdp(fd);
            const relay_sa = sys.Sockaddr.fromEndpoint(relay);
            if (sys.connect(fd, &relay_sa) < 0) {
                sys.close(fd);
                h.dropPending(w, s);
                W.onUdpClosed(w, s);
                return;
            }
            w.loop.register(fd) catch {};
            s.fd = fd;
            s.ready = true;
            s.ctrl_c = .{ .op = .{ .recv = .{ .fd = s.ctrl.fd, .buf = &s.ctrl_byte } }, .userdata = s, .callback = onUdpControl };
            w.loop.submit(&s.ctrl_c);
            h.flushPending(w, s);
            h.armRecv(w, s);
        }

        fn adoptAssociation(h: *Self, w: *W, s: *U, t: Taken) void {
            const s5 = &h.cfg.handler.socks5;
            const family = s5.server.addr.family;
            if (h.cfg.handler.preserve_dscp) direct.setDscp(t.fd, family, s.tos);
            s.ctrl.phase = .done;
            s.ctrl.target = .{ .addr = s5.server.addr, .port = 0 };
            if (s5.udp_mode == .tcp) {
                s.ctrl.cmd = .fwd_udp;
                s.fd = t.fd;
                s.stream = true;
                s.ready = true;
                h.armRecv(w, s);
                return;
            }
            s.ctrl.cmd = .udp_associate;
            s.ctrl.fd = t.fd;
            s.fd = t.udp_fd;
            s.gro = direct.tuneUdp(t.udp_fd);
            if (h.cfg.handler.preserve_dscp) direct.setDscp(t.udp_fd, if (t.relay.toEndpoint()) |ep| ep.addr.family else family, s.tos);
            s.ready = true;
            s.ctrl_c = .{ .op = .{ .recv = .{ .fd = s.ctrl.fd, .buf = &s.ctrl_byte } }, .userdata = s, .callback = onUdpControl };
            w.loop.submit(&s.ctrl_c);
            h.armRecv(w, s);
        }

        fn flushPending(h: *Self, w: *W, s: *U) void {
            const q = s.pending orelse return;
            const count = s.pending_count;
            s.pending = null;
            s.pending_count = 0;
            for (q.items[0..count]) |p| {
                if (!s.closing) h.udpSend(w, s, p.dst, p.buf, p.off, p.len, p.gso);
                w.pool.put(p.buf);
            }
            h.pending_queues.put(q);
        }

        fn sourceFor(h: *Self, s: *U, src: ?addr.Endpoint, port: u16) ?addr.Endpoint {
            if (s.fake_dst) |fd| {
                const mapped = if (src) |ep| ep.port == fd.port and (ep.addr.family != fd.addr.family or h.fake.?.indexOf(ep.addr) == null) else port == fd.port;
                if (mapped) return fd;
            }
            return src;
        }

        fn parseFrames(h: *Self, w: *W, s: *U) bool {
            const acc = s.acc orelse return true;
            const coalesce = coalescing(w);
            var run: Run = .{};
            defer run.flush(w, s);
            while (true) {
                if (s.skip > 0) {
                    const n = @min(s.skip, acc.len);
                    acc.trimFront(n);
                    s.skip -= n;
                    if (s.skip > 0) break;
                }
                const data = acc.bytes();
                const f = socks5.parseFrame(data) catch |err| switch (err) {
                    error.NeedMore => break,
                    else => return false,
                };
                if (f.total > acc.cap) {
                    w.counters.inc(.udp_dropped);
                    s.skip = @intCast(f.total);
                    continue;
                }
                if (data.len < f.total) break;
                const payload = data[f.header_len..f.total];
                if (h.sourceFor(s, f.src, f.port)) |src| {
                    if (run.addBytes(w, s, src, payload, coalesce)) {
                        w.counters.add(.upstream_rx_bytes, payload.len);
                    } else {
                        w.counters.inc(.udp_dropped);
                    }
                }
                acc.trimFront(@intCast(f.total));
                if (s.closing) break;
            }
            if (acc.len == 0) {
                acc.reset(0);
            } else if (acc.off > 0 and acc.tailroom() < acc.cap / 4) {
                std.mem.copyForwards(u8, acc.ptr[0..acc.len], acc.ptr[acc.off..][0..acc.len]);
                acc.off = 0;
            }
            return true;
        }

        fn streamRead(h: *Self, w: *W, s: *U) bool {
            var budget: u32 = 32;
            while (budget > 0 and !s.closing) : (budget -= 1) {
                const acc = s.acc orelse blk: {
                    const nb = w.pool.get() orelse return true;
                    nb.reset(0);
                    s.acc = nb;
                    break :blk nb;
                };
                if (acc.tailroom() == 0) {
                    if (acc.off > 0) {
                        std.mem.copyForwards(u8, acc.ptr[0..acc.len], acc.ptr[acc.off..][0..acc.len]);
                        acc.off = 0;
                    } else {
                        return false;
                    }
                }
                const n = sys.recv(s.fd, acc.tail(), sys.msg_dontwait);
                if (n == 0) return false;
                if (n < 0) {
                    const e = sys.toErrno(n);
                    if (e == .again) return true;
                    if (e == .intr) continue;
                    return false;
                }
                acc.len += @intCast(n);
                if (!h.parseFrames(w, s)) return false;
            }
            return true;
        }

        fn streamSend(h: *Self, w: *W, s: *U, target: socks5.Target, payload: []const u8) void {
            _ = h;
            var hdr: [socks5.max_frame_header]u8 = undefined;
            const hl = socks5.encodeFrameHeader(&hdr, target, payload.len);
            const total = hl + payload.len;
            if (s.tx_buf) |tb| {
                if (tb.tailroom() < total) {
                    w.counters.inc(.udp_dropped);
                    return;
                }
                const t = tb.tail();
                @memcpy(t[0..hl], hdr[0..hl]);
                @memcpy(t[hl..][0..payload.len], payload);
                tb.len += @intCast(total);
                w.counters.add(.upstream_tx_bytes, payload.len);
                return;
            }
            var iov = [2]sys.iovec_const{ .{ .base = &hdr, .len = hl }, .{ .base = payload.ptr, .len = payload.len } };
            const r = sys.sendvNow(s.fd, &iov);
            if (r >= 0 and @as(usize, @intCast(r)) == total) {
                w.counters.add(.upstream_tx_bytes, payload.len);
                return;
            }
            if (r < 0 and sys.toErrno(r) != .again) {
                w.counters.inc(.udp_dropped);
                return;
            }
            const sent: usize = if (r > 0) @intCast(r) else 0;
            const tb = w.pool.get() orelse {
                if (sent == 0) {
                    w.counters.inc(.udp_dropped);
                } else {
                    W.onUdpUpstreamGone(w, s);
                }
                return;
            };
            tb.reset(0);
            if (total > tb.cap) {
                w.pool.put(tb);
                if (sent == 0) w.counters.inc(.udp_dropped) else W.onUdpUpstreamGone(w, s);
                return;
            }
            var len: usize = 0;
            if (sent < hl) {
                @memcpy(tb.ptr[0 .. hl - sent], hdr[sent..hl]);
                len = hl - sent;
                @memcpy(tb.ptr[len..][0..payload.len], payload);
                len += payload.len;
            } else {
                const off = sent - hl;
                @memcpy(tb.ptr[0 .. payload.len - off], payload[off..]);
                len = payload.len - off;
            }
            tb.len = @intCast(len);
            s.tx_buf = tb;
            w.counters.add(.upstream_tx_bytes, payload.len);
            s.tx_c = .{ .op = .{ .send = .{ .fd = s.fd, .buf = tb.bytes() } }, .userdata = s, .callback = onStreamSent };
            w.loop.submit(&s.tx_c);
        }

        fn onStreamSent(ud: ?*anyopaque, loop: *Loop, c: *Loop.Completion, result: i32) io.Disposition {
            const s: *U = @ptrCast(@alignCast(ud.?));
            const w = workerOf(loop);
            const tb = s.tx_buf.?;
            if (s.closing) {
                w.pool.put(tb);
                s.tx_buf = null;
                W.onUdpMaybeIdle(w, s);
                return .disarm;
            }
            if (result < 0) {
                const e = sys.toErrno(result);
                if (e == .again or e == .intr) return .rearm;
                w.pool.put(tb);
                s.tx_buf = null;
                W.onUdpUpstreamGone(w, s);
                return .disarm;
            }
            tb.trimFront(@intCast(result));
            if (tb.len == 0) {
                w.pool.put(tb);
                s.tx_buf = null;
                return .disarm;
            }
            c.op = .{ .send = .{ .fd = s.fd, .buf = tb.bytes() } };
            return .rearm;
        }

        fn onUdpControl(ud: ?*anyopaque, loop: *Loop, c: *Loop.Completion, result: i32) io.Disposition {
            _ = c;
            const s: *U = @ptrCast(@alignCast(ud.?));
            const w = workerOf(loop);
            if (s.migrating) return .disarm;
            if (result > 0 and !s.closing) return .rearm;
            if (sys.toErrno(result) == .again and !s.closing) return .rearm;
            if (!s.closing) W.onUdpUpstreamGone(w, s);
            return .disarm;
        }

        fn dropPending(h: *Self, w: *W, s: *U) void {
            const q = s.pending orelse return;
            var i: u8 = 0;
            while (i < s.pending_count) : (i += 1) w.pool.put(q.items[i].buf);
            s.pending_count = 0;
            s.pending = null;
            h.pending_queues.put(q);
        }

        fn armRecv(h: *Self, w: *W, s: *U) void {
            _ = h;
            if (s.rx_c.isActive() or s.closing or s.migrating) return;
            if (s.rx_buf) |b| w.pool.put(b);
            s.rx_buf = null;
            s.rx_c = .{
                .op = .{ .poll = .{ .fd = s.fd, .events = .{ .in = true } } },
                .userdata = s,
                .callback = onUdpReadable,
            };
            w.loop.submit(&s.rx_c);
        }

        fn recvDatagram(s: *U, b: *pool.Buffer, rs: *RecvScratch) i32 {
            rs.iov[0] = .{ .base = b.ptr + b.headroom(), .len = b.cap - b.headroom() };
            rs.msg = .{
                .name = @ptrCast(@alignCast(rs.name.mutPtr())),
                .namelen = 128,
                .iov = @ptrCast(&rs.iov),
                .iovlen = 1,
                .control = &rs.control,
                .controllen = rs.control.len,
                .flags = 0,
            };
            if (sys.is_linux) return sys.linuxResult(std.os.linux.recvmsg(s.fd, &rs.msg, std.os.linux.MSG.DONTWAIT));
            if (sys.is_windows) {
                const r = sys.recvfrom(s.fd, b.ptr[b.headroom()..b.cap], 0, &rs.name);
                rs.msg.controllen = 0;
                rs.msg.namelen = rs.name.len;
                return r;
            }
            return sys.libcResult(std.c.recvmsg(s.fd, &rs.msg, sys.msg_dontwait));
        }

        fn onUdpReadable(ud: ?*anyopaque, loop: *Loop, c: *Loop.Completion, result: i32) io.Disposition {
            _ = c;
            const s: *U = @ptrCast(@alignCast(ud.?));
            const w = workerOf(loop);
            const h = &w.handler;
            if (s.closing) {
                W.onUdpMaybeIdle(w, s);
                return .disarm;
            }
            if (s.migrating) return .disarm;
            if (result < 0) {
                const e = sys.toErrno(result);
                if (e == .again or e == .intr) {
                    h.armRecv(w, s);
                    return .disarm;
                }
                W.onUdpUpstreamGone(w, s);
                return .disarm;
            }
            if (s.stream) {
                if (!h.streamRead(w, s)) {
                    W.onUdpUpstreamGone(w, s);
                    return .disarm;
                }
                h.armRecv(w, s);
                return .disarm;
            }
            if (sys.is_linux) {
                if (!h.recvBatches(w, s)) {
                    W.onUdpUpstreamGone(w, s);
                    return .disarm;
                }
                h.armRecv(w, s);
                return .disarm;
            }
            var budget: u32 = 64;
            var rs: RecvScratch = .{};
            while (budget > 0 and !s.closing) : (budget -= 1) {
                const b = s.rx_buf orelse (w.pool.get() orelse break);
                s.rx_buf = b;
                const n = recvDatagram(s, b, &rs);
                if (n < 0) {
                    const e = sys.toErrno(n);
                    if (e == .again) break;
                    if (e == .intr or e == .connrefused or e == .msgsize) continue;
                    W.onUdpUpstreamGone(w, s);
                    return .disarm;
                }
                s.rx_buf = null;
                h.deliverDatagram(w, s, b, n, &rs);
            }
            h.armRecv(w, s);
            return .disarm;
        }

        const Run = struct {
            head: ?*pool.Buffer = null,
            src: addr.Endpoint = .{},
            seg: u32 = 0,
            closed: bool = false,

            fn accepts(run: *const Run, src: addr.Endpoint, len: usize, coalesce: bool) bool {
                const head = run.head orelse return false;
                return coalesce and !run.closed and len <= run.seg and head.len + len <= coalesce_limit and head.tailroom() >= len and src.eql(run.src);
            }

            fn append(run: *Run, bytes: []const u8) void {
                const head = run.head.?;
                @memcpy(head.tail()[0..bytes.len], bytes);
                head.len += @intCast(bytes.len);
                if (bytes.len < run.seg) run.closed = true;
            }

            fn add(run: *Run, w: *W, s: *U, src: addr.Endpoint, b: *pool.Buffer, coalesce: bool) void {
                if (run.accepts(src, b.len, coalesce)) {
                    run.append(b.bytes());
                    w.pool.put(b);
                    return;
                }
                run.flush(w, s);
                run.head = b;
                run.src = src;
                run.seg = b.len;
                run.closed = b.len == 0;
            }

            fn addBytes(run: *Run, w: *W, s: *U, src: addr.Endpoint, bytes: []const u8, coalesce: bool) bool {
                if (run.accepts(src, bytes.len, coalesce)) {
                    run.append(bytes);
                    return true;
                }
                const nb = w.pool.get() orelse return false;
                if (bytes.len > nb.cap - nb.headroom()) {
                    w.pool.put(nb);
                    return false;
                }
                @memcpy(nb.ptr[nb.headroom()..][0..bytes.len], bytes);
                nb.len = @intCast(bytes.len);
                run.add(w, s, src, nb, coalesce);
                return true;
            }

            fn flush(run: *Run, w: *W, s: *U) void {
                const head = run.head orelse return;
                run.head = null;
                const seg: u16 = if (head.len > run.seg) @intCast(run.seg) else 0;
                W.onUdpDatagram(w, s, run.src, head, seg);
            }
        };

        inline fn coalescing(w: *W) bool {
            const caps = w.caps();
            return caps.vnet_hdr and caps.uso;
        }

        fn recvBatches(h: *Self, w: *W, s: *U) bool {
            const linux = std.os.linux;
            var rb: RecvBatch = undefined;
            var budget: u32 = 64;
            while (budget > 0 and !s.closing) {
                var count: usize = 0;
                const want = @min(budget, recv_batch);
                while (count < want) : (count += 1) {
                    const b = w.pool.get() orelse break;
                    rb.bufs[count] = b;
                    rb.iovs[count] = .{ .base = b.ptr + b.headroom(), .len = b.cap - b.headroom() };
                    rb.msgs[count] = .{ .hdr = .{
                        .name = @ptrCast(@alignCast(rb.names[count].mutPtr())),
                        .namelen = 128,
                        .iov = @ptrCast(&rb.iovs[count]),
                        .iovlen = 1,
                        .control = &rb.controls[count],
                        .controllen = rb.controls[count].len,
                        .flags = 0,
                    }, .len = 0 };
                }
                if (count == 0) {
                    w.counters.inc(.pool_exhausted);
                    return true;
                }
                const r = sys.linuxResult(linux.recvmmsg(s.fd, &rb.msgs, @intCast(count), linux.MSG.DONTWAIT, null));
                const got: usize = if (r > 0) @intCast(r) else 0;
                for (rb.bufs[got..count]) |b| w.pool.put(b);
                if (r < 0) {
                    const e = sys.toErrno(r);
                    if (e == .again) return true;
                    if (e == .intr or e == .connrefused or e == .msgsize or e == .hostunreach or e == .netunreach) {
                        if (e != .intr) h.drainErrors(w, s);
                        budget -|= 1;
                        continue;
                    }
                    return false;
                }
                h.deliverBatch(w, s, &rb, got);
                budget -|= @intCast(got);
                if (got < count) return true;
            }
            return true;
        }

        fn drainErrors(h: *Self, w: *W, s: *U) void {
            _ = h;
            if (!s.err_queue or s.closing) return;
            const linux = std.os.linux;
            var rounds: u32 = 4;
            while (rounds > 0) : (rounds -= 1) {
                var name: sys.Sockaddr = .{};
                var body: [8]u8 = undefined;
                var iov = [_]std.posix.iovec{.{ .base = &body, .len = body.len }};
                var control: [128]u8 align(8) = undefined;
                var msg: linux.msghdr = .{
                    .name = @ptrCast(@alignCast(name.mutPtr())),
                    .namelen = 128,
                    .iov = &iov,
                    .iovlen = 1,
                    .control = &control,
                    .controllen = control.len,
                    .flags = 0,
                };
                const r = sys.linuxResult(linux.recvmsg(s.fd, &msg, linux.MSG.ERRQUEUE | linux.MSG.DONTWAIT));
                if (r < 0) return;
                const offender = name.toEndpoint() orelse continue;
                if (offender.port == 0) continue;
                W.onUdpUnreachable(w, s, offender);
            }
        }

        fn deliverBatch(h: *Self, w: *W, s: *U, rb: *RecvBatch, got: usize) void {
            const coalesce = coalescing(w);
            var run: Run = .{};
            for (rb.bufs[0..got], rb.msgs[0..got], 0..) |b, m, i| {
                b.off = b.headroom();
                b.len = m.len;
                if (s.closing) {
                    w.pool.put(b);
                    continue;
                }
                const gro: u16 = if (s.gro and m.hdr.controllen > 0) direct.readUdpGro(rb.controls[i][0..@min(m.hdr.controllen, rb.controls[i].len)]) else 0;
                if (h.kind == .socks5 and build_options.enable_socks5) {
                    if (gro != 0 and b.len > gro) {
                        run.flush(w, s);
                        h.splitSocksGro(w, s, b, gro, coalesce);
                        continue;
                    }
                    const p = socks5.parseUdpHeader(b.bytes()) catch {
                        w.pool.put(b);
                        continue;
                    };
                    const src = h.socksSource(s, p.src) orelse {
                        w.pool.put(b);
                        continue;
                    };
                    b.trimFront(@intCast(p.header_len));
                    w.counters.add(.upstream_rx_bytes, b.len);
                    run.add(w, s, src, b, coalesce);
                    continue;
                }
                w.counters.add(.upstream_rx_bytes, b.len);
                rb.names[i].len = @intCast(m.hdr.namelen);
                const src = rb.names[i].toEndpoint() orelse {
                    w.pool.put(b);
                    continue;
                };
                if (gro != 0 and b.len > gro) {
                    run.flush(w, s);
                    W.onUdpDatagram(w, s, src, b, gro);
                    continue;
                }
                run.add(w, s, src, b, coalesce);
            }
            run.flush(w, s);
        }

        fn socksSource(h: *Self, s: *U, src: ?addr.Endpoint) ?addr.Endpoint {
            if (s.fake_dst) |fd| {
                const mapped = if (src) |ep| ep.port == fd.port and (ep.addr.family != fd.addr.family or h.fake.?.indexOf(ep.addr) == null) else true;
                if (mapped) return fd;
            }
            return src;
        }

        fn splitSocksGro(h: *Self, w: *W, s: *U, b: *pool.Buffer, gro: u16, coalesce: bool) void {
            var run: Run = .{};
            var off: u32 = 0;
            const total = b.len;
            const base = b.off;
            while (off < total and !s.closing) {
                const end = @min(off + gro, total);
                const seg = b.ptr[base + off .. base + end];
                const p = socks5.parseUdpHeader(seg) catch break;
                const src = h.socksSource(s, p.src) orelse break;
                const payload = seg[p.header_len..];
                if (!run.addBytes(w, s, src, payload, coalesce)) break;
                w.counters.add(.upstream_rx_bytes, payload.len);
                off = end;
            }
            run.flush(w, s);
            w.pool.put(b);
        }

        fn deliverDatagram(h: *Self, w: *W, s: *U, b: *pool.Buffer, result: i32, rs: *RecvScratch) void {
            b.off = b.headroom();
            b.len = @intCast(result);
            var gso: u16 = 0;
            if (sys.is_linux and rs.msg.controllen > 0 and s.gro) gso = direct.readUdpGro(rs.control[0..@min(rs.msg.controllen, rs.control.len)]);
            rs.name.len = @intCast(rs.msg.namelen);
            var src: ?addr.Endpoint = null;
            if (h.kind == .socks5 and build_options.enable_socks5) {
                const p = socks5.parseUdpHeader(b.bytes()) catch {
                    w.pool.put(b);
                    return;
                };
                src = p.src;
                if (s.fake_dst) |fd| {
                    const mapped = if (p.src) |ep| ep.port == fd.port and (ep.addr.family != fd.addr.family or h.fake.?.indexOf(ep.addr) == null) else true;
                    if (mapped) src = fd;
                }
                b.trimFront(@intCast(p.header_len));
                gso = 0;
            } else {
                src = rs.name.toEndpoint();
            }
            w.counters.add(.upstream_rx_bytes, b.len);
            if (src) |ep| {
                W.onUdpDatagram(w, s, ep, b, gso);
            } else {
                w.pool.put(b);
            }
        }

        pub fn udpSend(h: *Self, w: *W, s: *U, dst: addr.Endpoint, b: *pool.Buffer, off: u32, len: u32, gso: u16) void {
            if (!s.ready) {
                const q = s.pending orelse blk: {
                    const nq = h.pending_queues.take(h.allocator) orelse {
                        w.counters.inc(.udp_dropped);
                        return;
                    };
                    s.pending = nq;
                    s.pending_count = 0;
                    break :blk nq;
                };
                if (s.pending_count < q.items.len) {
                    b.ref();
                    q.items[s.pending_count] = .{ .buf = b, .dst = dst, .off = off, .len = len, .gso = gso };
                    s.pending_count += 1;
                } else {
                    w.counters.inc(.udp_dropped);
                }
                return;
            }
            if (sys.is_linux and (gso == 0 or len <= gso) and h.queueTx(w, s, dst, b, off, len)) return;
            h.flushTx(w, s);
            const payload = b.ptr[off..][0..len];
            if (h.kind == .socks5 and build_options.enable_socks5) {
                var name: [dns.max_name]u8 = undefined;
                var target: socks5.Target = .{ .ip = dst };
                if (h.fake) |t| {
                    if (t.indexOf(dst.addr) != null) {
                        const n = t.nameOf(dst.addr, &name) orelse {
                            w.counters.inc(.udp_dropped);
                            return;
                        };
                        target = .{ .host = .{ .name = n, .port = dst.port } };
                        s.fake_dst = dst;
                    }
                }
                const seg: u32 = if (gso != 0) gso else len;
                if (s.stream) {
                    var spos: u32 = 0;
                    while (spos < len and !s.closing) {
                        const sn = @min(seg, len - spos);
                        h.streamSend(w, s, target, payload[spos..][0..sn]);
                        spos += sn;
                    }
                    return;
                }
                var hdr: [socks5.max_udp_header]u8 = undefined;
                const hl = socks5.encodeUdpHeaderTo(&hdr, target);
                var pos: u32 = 0;
                if (seg < len and h.udp_gso and sys.is_linux) pos = h.sendSegments(w, s, hdr[0..hl], payload, seg);
                while (pos < len) {
                    const n = @min(seg, len - pos);
                    var iov = [2]sys.iovec_const{ .{ .base = &hdr, .len = hl }, .{ .base = payload.ptr + pos, .len = n } };
                    const r = sys.writev(s.fd, &iov);
                    if (r < 0) w.counters.inc(.udp_dropped) else w.counters.add(.upstream_tx_bytes, n);
                    pos += n;
                }
                return;
            }
            var sa = sys.Sockaddr.fromEndpoint(dst);
            if (gso != 0 and len > gso and sys.is_linux) {
                const linux = std.os.linux;
                var control: [32]u8 align(8) = undefined;
                const clen = direct.writeUdpSegmentCmsg(&control, gso);
                var iov = [1]sys.iovec_const{.{ .base = payload.ptr, .len = len }};
                const msg: linux.msghdr_const = .{
                    .name = @ptrCast(@alignCast(sa.ptr())),
                    .namelen = sa.len,
                    .iov = @ptrCast(&iov),
                    .iovlen = 1,
                    .control = &control,
                    .controllen = clen,
                    .flags = 0,
                };
                const r = sys.linuxResult(linux.sendmsg(s.fd, &msg, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL));
                if (r >= 0) {
                    w.counters.add(.upstream_tx_bytes, len);
                    return;
                }
            }
            const seg: u32 = if (gso != 0) gso else len;
            var pos: u32 = 0;
            while (pos < len) {
                const n = @min(seg, len - pos);
                const r = sys.sendto(s.fd, payload[pos..][0..n], sys.msg_dontwait, &sa);
                if (r < 0) w.counters.inc(.udp_dropped) else w.counters.add(.upstream_tx_bytes, n);
                pos += n;
            }
        }

        fn queueTx(h: *Self, w: *W, s: *U, dst: addr.Endpoint, b: *pool.Buffer, off: u32, len: u32) bool {
            if (s.stream or h.kind == .passthrough or len > 65507) return false;
            if (s.tx_count == tx_batch) h.flushTx(w, s);
            const q = s.txq orelse blk: {
                const nq = h.tx_queues.take(h.allocator) orelse return false;
                s.txq = nq;
                break :blk nq;
            };
            b.ref();
            q.items[s.tx_count] = .{ .buf = b, .off = off, .len = len, .dst = dst };
            s.tx_count += 1;
            if (!s.tx_queued) {
                s.tx_queued = true;
                s.tx_next = h.tx_head;
                h.tx_head = s;
            }
            return true;
        }

        pub fn flushUdp(h: *Self, w: *W) void {
            var list = h.tx_head;
            h.tx_head = null;
            while (list) |s| {
                list = s.tx_next;
                s.tx_next = null;
                s.tx_queued = false;
                h.flushTx(w, s);
            }
        }

        fn unlinkTx(h: *Self, s: *U) void {
            if (!s.tx_queued) return;
            var link = &h.tx_head;
            while (link.*) |cur| : (link = &cur.tx_next) {
                if (cur == s) {
                    link.* = s.tx_next;
                    break;
                }
            }
            s.tx_next = null;
            s.tx_queued = false;
        }

        fn dropTx(h: *Self, w: *W, s: *U) void {
            h.unlinkTx(s);
            const q = s.txq orelse return;
            for (q.items[0..s.tx_count]) |it| w.pool.put(it.buf);
            if (s.tx_count > 0) w.counters.add(.udp_dropped, s.tx_count);
            s.tx_count = 0;
            s.txq = null;
            h.tx_queues.put(q);
        }

        fn udpTarget(h: *Self, s: *U, dst: addr.Endpoint, name: *[dns.max_name]u8) ?socks5.Target {
            if (h.fake) |t| {
                if (t.indexOf(dst.addr) != null) {
                    const n = t.nameOf(dst.addr, name) orelse return null;
                    s.fake_dst = dst;
                    return .{ .host = .{ .name = n, .port = dst.port } };
                }
            }
            return .{ .ip = dst };
        }

        pub fn flushTx(h: *Self, w: *W, s: *U) void {
            if (comptime !sys.is_linux) return;
            const q = s.txq orelse return;
            const n: usize = s.tx_count;
            s.tx_count = 0;
            s.txq = null;
            defer h.tx_queues.put(q);
            const items = q.items[0..n];
            defer for (items) |it| w.pool.put(it.buf);
            if (n == 0) return;
            if (s.closing or s.fd == sys.invalid_fd) {
                w.counters.add(.udp_dropped, n);
                return;
            }
            const socks = h.kind == .socks5 and build_options.enable_socks5;
            var plan: TxPlan = .{};
            var name: [dns.max_name]u8 = undefined;
            var v: usize = 0;
            var i: usize = 0;
            while (i < n) {
                const first = items[i];
                const m = plan.count;
                var hl: usize = 0;
                if (socks) {
                    const target = h.udpTarget(s, first.dst, &name) orelse {
                        w.counters.inc(.udp_dropped);
                        i += 1;
                        continue;
                    };
                    hl = socks5.encodeUdpHeaderTo(&plan.hdrs[m], target);
                }
                var j = i + 1;
                var bytes: usize = hl + first.len;
                if (h.udp_gso) {
                    while (j < n and j - i < gso_batch and items[j].dst.eql(first.dst) and items[j - 1].len == first.len and items[j].len <= first.len and bytes + hl + items[j].len <= 0xffff) : (j += 1) {
                        bytes += hl + items[j].len;
                    }
                }
                const start = v;
                for (items[i..j]) |it| {
                    if (socks) {
                        plan.iovs[v] = .{ .base = &plan.hdrs[m], .len = hl };
                        v += 1;
                    }
                    plan.iovs[v] = .{ .base = it.buf.ptr + it.off, .len = it.len };
                    v += 1;
                }
                var clen: usize = 0;
                if (j - i > 1) clen = direct.writeUdpSegmentCmsg(&plan.controls[m], @intCast(hl + first.len));
                var name_ptr: ?*std.os.linux.sockaddr = null;
                var name_len: u32 = 0;
                if (!socks) {
                    plan.names[m] = sys.Sockaddr.fromEndpoint(first.dst);
                    name_ptr = @ptrCast(@alignCast(plan.names[m].mutPtr()));
                    name_len = plan.names[m].len;
                }
                plan.msgs[m] = .{ .hdr = .{
                    .name = name_ptr,
                    .namelen = name_len,
                    .iov = @ptrCast(@constCast(&plan.iovs[start])),
                    .iovlen = @intCast(v - start),
                    .control = if (clen > 0) &plan.controls[m] else null,
                    .controllen = clen,
                    .flags = 0,
                }, .len = 0 };
                plan.spans[m] = .{ .first = @intCast(i), .count = @intCast(j - i) };
                plan.count += 1;
                i = j;
            }
            h.sendPlan(w, s, &plan, items);
        }

        fn sendPlan(h: *Self, w: *W, s: *U, plan: *TxPlan, items: []const TxItem) void {
            const linux = std.os.linux;
            var start: usize = 0;
            while (start < plan.count) {
                const r = sys.linuxResult(linux.sendmmsg(s.fd, plan.msgs[start..].ptr, @intCast(plan.count - start), linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL));
                if (r > 0) {
                    for (plan.spans[start..][0..@intCast(r)]) |sp| {
                        for (items[sp.first..][0..sp.count]) |it| w.counters.add(.upstream_tx_bytes, it.len);
                    }
                    start += @intCast(r);
                    continue;
                }
                const sp = plan.spans[start];
                const e = if (r < 0) sys.toErrno(r) else sys.Errno.other;
                switch (e) {
                    .again, .nobufs => {
                        for (plan.spans[start..plan.count]) |rest| w.counters.add(.udp_dropped, rest.count);
                        return;
                    },
                    .msgsize, .inval, .opnotsupp, .io => {
                        if (sp.count > 1) {
                            if (e != .msgsize) h.udp_gso = false;
                            const m = &plan.msgs[start].hdr;
                            m.control = null;
                            m.controllen = 0;
                            const per: usize = m.iovlen / sp.count;
                            const iov0: [*]sys.iovec_const = @ptrCast(m.iov);
                            var k: usize = 0;
                            while (k < sp.count) : (k += 1) {
                                const one: linux.msghdr_const = .{ .name = m.name, .namelen = m.namelen, .iov = @ptrCast(iov0 + k * per), .iovlen = @intCast(per), .control = null, .controllen = 0, .flags = 0 };
                                const rr = sys.linuxResult(linux.sendmsg(s.fd, &one, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL));
                                if (rr < 0) w.counters.inc(.udp_dropped) else w.counters.add(.upstream_tx_bytes, items[sp.first + k].len);
                            }
                        } else {
                            w.counters.inc(.udp_dropped);
                        }
                    },
                    else => w.counters.add(.udp_dropped, sp.count),
                }
                start += 1;
            }
        }

        pub fn udpMovable(h: *const Self, s: *const U) bool {
            if (!s.ready or s.closing or s.migrating or s.pending != null or s.tx_buf != null or s.tx_c.isActive()) return false;
            if (build_options.enable_socks5 and h.kind == .socks5) {
                if (s.ctrl.busy() or s.ctrl.buf != null) return false;
            }
            return s.fd != sys.invalid_fd;
        }

        pub fn udpQuiesce(h: *Self, w: *W, s: *U) void {
            _ = h;
            s.migrating = true;
            if (s.rx_c.isActive()) w.loop.cancel(&s.rx_c);
            if (s.ctrl_c.isActive()) w.loop.cancel(&s.ctrl_c);
        }

        pub fn udpQuiet(h: *Self, w: *W, s: *U) bool {
            h.flushTx(w, s);
            return !s.rx_c.isActive() and !s.ctrl_c.isActive() and !s.tx_c.isActive() and s.tx_buf == null;
        }

        pub fn udpDetach(h: *Self, w: *W, s: *U) void {
            _ = h;
            if (s.rx_buf) |b| w.pool.put(b);
            s.rx_buf = null;
            if (s.fd != sys.invalid_fd) w.loop.unregister(s.fd);
            if (build_options.enable_socks5 and s.ctrl.fd != sys.invalid_fd) w.loop.unregister(s.ctrl.fd);
        }

        pub fn udpDisown(h: *Self, s: *U) void {
            _ = h;
            s.fd = sys.invalid_fd;
            s.acc = null;
            s.migrating = false;
            if (build_options.enable_socks5) s.ctrl.fd = sys.invalid_fd;
        }

        pub fn udpAdopt(h: *Self, w: *W, s: *U) void {
            s.migrating = false;
            s.tx_queued = false;
            s.tx_count = 0;
            s.txq = null;
            s.tx_next = null;
            s.rx_c = .{};
            s.ctrl_c = .{};
            s.tx_c = .{};
            s.rx_buf = null;
            w.loop.register(s.fd) catch {};
            if (build_options.enable_socks5 and h.kind == .socks5 and s.ctrl.fd != sys.invalid_fd) {
                w.loop.register(s.ctrl.fd) catch {};
                if (!s.stream) {
                    s.ctrl_c = .{ .op = .{ .recv = .{ .fd = s.ctrl.fd, .buf = &s.ctrl_byte } }, .userdata = s, .callback = onUdpControl };
                    w.loop.submit(&s.ctrl_c);
                }
            }
            h.armRecv(w, s);
        }

        pub fn udpResume(h: *Self, w: *W, s: *U) void {
            s.migrating = false;
            if (build_options.enable_socks5 and h.kind == .socks5 and s.ctrl.fd != sys.invalid_fd and !s.stream and !s.ctrl_c.isActive()) {
                s.ctrl_c = .{ .op = .{ .recv = .{ .fd = s.ctrl.fd, .buf = &s.ctrl_byte } }, .userdata = s, .callback = onUdpControl };
                w.loop.submit(&s.ctrl_c);
            }
            h.armRecv(w, s);
        }

        pub fn udpDiscard(h: *Self, w: *W, s: *U) void {
            _ = h;
            if (s.acc) |b| w.pool.put(b);
            s.acc = null;
            if (s.fd != sys.invalid_fd) sys.close(s.fd);
            s.fd = sys.invalid_fd;
            if (build_options.enable_socks5 and s.ctrl.fd != sys.invalid_fd) sys.close(s.ctrl.fd);
            if (build_options.enable_socks5) s.ctrl.fd = sys.invalid_fd;
        }

        fn sendSegments(h: *Self, w: *W, s: *U, hdr: []const u8, payload: []const u8, seg: u32) u32 {
            const linux = std.os.linux;
            const size = hdr.len + seg;
            if (size > 0xffff) return 0;
            var control: [32]u8 align(8) = undefined;
            const clen = direct.writeUdpSegmentCmsg(&control, @intCast(size));
            var iov: [2 * gso_batch]sys.iovec_const = undefined;
            var pos: u32 = 0;
            while (pos < payload.len) {
                var n: usize = 0;
                var bytes: usize = 0;
                var end = pos;
                while (end < payload.len and n < gso_batch) {
                    const chunk = @min(seg, @as(u32, @intCast(payload.len)) - end);
                    if (bytes + hdr.len + chunk > 0xffff) break;
                    iov[2 * n] = .{ .base = hdr.ptr, .len = hdr.len };
                    iov[2 * n + 1] = .{ .base = payload.ptr + end, .len = chunk };
                    n += 1;
                    bytes += hdr.len + chunk;
                    end += chunk;
                }
                if (n < 2) return pos;
                const msg: linux.msghdr_const = .{
                    .name = null,
                    .namelen = 0,
                    .iov = @ptrCast(&iov),
                    .iovlen = @intCast(2 * n),
                    .control = &control,
                    .controllen = clen,
                    .flags = 0,
                };
                const r = sys.linuxResult(linux.sendmsg(s.fd, &msg, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL));
                if (r >= 0) {
                    w.counters.add(.upstream_tx_bytes, end - pos);
                    pos = end;
                    continue;
                }
                switch (sys.toErrno(r)) {
                    .again, .nobufs => {
                        w.counters.add(.udp_dropped, n);
                        pos = end;
                    },
                    .msgsize => return pos,
                    .inval, .opnotsupp, .io, .other => {
                        h.udp_gso = false;
                        return pos;
                    },
                    else => {
                        w.counters.add(.udp_dropped, n);
                        pos = end;
                    },
                }
            }
            return pos;
        }

        pub fn udpClose(h: *Self, w: *W, s: *U) void {
            h.dropTx(w, s);
            s.closing = true;
            h.dropPending(w, s);
            if (build_options.enable_socks5 and h.kind == .socks5) {
                if (s.ctrl.busy()) h.abortDial(w, &s.ctrl);
                if (s.ctrl_c.isActive()) w.loop.cancel(&s.ctrl_c);
            }
            if (s.rx_c.isActive()) w.loop.cancel(&s.rx_c);
            if (s.tx_c.isActive()) w.loop.cancel(&s.tx_c);
        }

        pub fn udpFinalize(h: *Self, w: *W, s: *U) void {
            _ = h;
            if (s.rx_buf) |b| w.pool.put(b);
            s.rx_buf = null;
            if (s.acc) |b| w.pool.put(b);
            s.acc = null;
            if (s.tx_buf) |b| w.pool.put(b);
            s.tx_buf = null;
            if (s.fd != sys.invalid_fd) {
                w.loop.unregister(s.fd);
                sys.close(s.fd);
                s.fd = sys.invalid_fd;
            }
            if (build_options.enable_socks5 and s.ctrl.fd != sys.invalid_fd) {
                w.loop.unregister(s.ctrl.fd);
                sys.close(s.ctrl.fd);
                s.ctrl.fd = sys.invalid_fd;
            }
        }
    };
}
