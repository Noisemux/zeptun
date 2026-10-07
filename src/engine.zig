const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const config = @import("config.zig");
const addr = @import("addr.zig");
const log = @import("log.zig");
const stats = @import("stats.zig");
const queue = @import("queue.zig");
const io = @import("io/io.zig");
const sys = @import("io/sys.zig");
const device = @import("device/device.zig");
const pool = @import("packet/pool.zig");
const gso = @import("packet/gso.zig");
const timeouts = @import("flow/timeouts.zig");
const verdict = @import("flow/verdict.zig");
const stack = @import("stack/stack.zig");
const handler_mod = @import("handler/handler.zig");
const route = @import("route/route.zig");
const parse = @import("packet/parse.zig");
const elastic = @import("elastic.zig");

pub const State = enum(u8) { created, running, stopping, stopped };

const pool_trim_ms: u64 = 1000;
const starved_wait_ms: u64 = 5;

const session_bytes: u32 = 2048;
const idle_wait_ms: u64 = 30_000;
const drain_limit_ms = elastic.drain_limit_ms;
const drain_quiet_ms: u64 = 200;
const drain_quiet_packets: u64 = 4;

pub const Elastic = struct {
    mode: config.ElasticMode,
    cap: u16,
    cpus: u32,
    attached: std.atomic.Value(u16) = .init(1),
    lock: std.atomic.Value(bool) = .init(false),
    growing: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),
    next_tick: std.atomic.Value(usize) = .init(0),
    rebalance_seq: std.atomic.Value(u32) = .init(0),
    rebalance_to: std.atomic.Value(u16) = .init(0),
    tids: [elastic.max_workers]std.atomic.Value(i32) = @splat(.init(0)),
    roles: [elastic.max_workers]std.atomic.Value(elastic.Role) = @splat(.init(.active)),
    util: [elastic.max_workers]std.atomic.Value(u16) = @splat(.init(0)),
    threads: [elastic.max_workers]?std.Thread = @splat(null),
    cpu_ns: [elastic.max_workers]u64 = @splat(0),
    last_ns: u64 = 0,
    last_bytes: u64 = 0,
    policy: elastic.Policy = .{},
    rotation: elastic.Rotation = .{},
    stat: elastic.CpuStat = .{},
};

fn packMeta(vh: gso.VirtioNetHdr) u64 {
    return @as(u64, vh.flags) | (@as(u64, vh.gso_type) << 8) | (@as(u64, vh.gso_size) << 16) | (@as(u64, vh.csum_start) << 32) | (@as(u64, vh.csum_offset) << 48);
}

fn unpackMeta(m: u64) gso.VirtioNetHdr {
    return .{
        .flags = @truncate(m),
        .gso_type = @truncate(m >> 8),
        .gso_size = @truncate(m >> 16),
        .csum_start = @truncate(m >> 32),
        .csum_offset = @truncate(m >> 48),
    };
}

pub fn Worker(comptime L: type) type {
    return struct {
        const Self = @This();

        pub const Loop = L;
        pub const Handler = handler_mod.Handler(Self);
        pub const Dial = handler_mod.Dial(Self);
        pub const UdpState = handler_mod.UdpState(Self);
        pub const Tcp = stack.tcp.Tcp(Self);
        pub const Udp = stack.udp.Udp(Self);
        pub const Ping = stack.ping.Ping(Self);
        pub const System = stack.system.System(Self);
        pub const Redirect = stack.redirect.Redirect(Self);
        pub const Passthrough = handler_mod.passthrough.Passthrough(Self);
        pub const TunQueue = device.FdQueue(Self);
        pub const WintunQueue = device.wintun.Queue(Self);
        pub const ExternalQueue = device.external.Queue(Self);

        pub const has_system = build_options.enable_system_stack and sys.is_linux and !sys.is_android;
        pub const has_userspace_tcp = build_options.enable_userspace_tcp;
        pub const has_passthrough = build_options.enable_passthrough;
        pub const has_tun = !sys.is_windows;
        pub const has_wintun = device.wintun.supported;

        pub const DeviceQueue = union(enum) {
            none: void,
            tun: if (has_tun) TunQueue else void,
            wintun: if (has_wintun) WintunQueue else void,
            external: ExternalQueue,
        };

        id: u16,
        engine: *Engine,
        cfg: *const config.Config,
        allocator: std.mem.Allocator,
        loop: Loop,
        pool: pool.Pool,
        counters: *stats.Counters,
        gauges: *stats.Gauges,
        wheel: timeouts.Wheel,
        device: DeviceQueue,
        dev_caps: device.Capabilities,
        tcp: if (has_userspace_tcp) Tcp else void,
        udp: Udp,
        ping: Ping,
        system: if (has_system) ?System else void,
        redirect: if (has_system) ?Redirect else void,
        reasm: if (build_options.enable_fragments) stack.ip.Reassembler else void,
        handler: Handler,
        passthrough: if (has_passthrough) ?Passthrough else void,
        inbox: queue.Intrusive(pool.Buffer),
        wake_mask: u64 = 0,
        thread: ?std.Thread = null,
        network_epoch: u32 = 0,
        last_activity_ns: u64 = 0,
        activity_mark: u64 = 0,
        rebalance_seen: u32 = 0,
        trim_at_ms: u64 = 0,
        drain_since: u64 = 0,
        drain_scan_at: u64 = 0,
        drain_rx_mark: u64 = 0,
        drain_quiet_at: u64 = 0,

        pub fn create(engine: *Engine, id: u16) !*Self {
            const allocator = engine.allocator;
            const cfg = &engine.cfg;
            const sizing = engine.sizing;
            const w = try allocator.create(Self);
            errdefer allocator.destroy(w);
            w.id = id;
            w.engine = engine;
            w.cfg = cfg;
            w.allocator = allocator;
            w.counters = &engine.counters[id];
            w.gauges = &engine.gauges[id];
            w.wake_mask = 0;
            w.thread = null;
            w.network_epoch = engine.network_epoch.load(.acquire);
            w.last_activity_ns = 0;
            w.activity_mark = 0;
            w.rebalance_seen = if (engine.elastic) |el| el.rebalance_seq.load(.acquire) else 0;
            w.drain_since = 0;
            w.drain_scan_at = 0;
            w.drain_rx_mark = 0;
            w.drain_quiet_at = 0;
            w.dev_caps = engine.caps;
            w.loop = try Loop.init(allocator, .{
                .backend = engine.backend,
                .entries = cfg.io.ring_entries,
                .sqpoll = cfg.io.sqpoll,
                .max_fds_hint = 1024,
                .defer_enable = true,
            });
            errdefer w.loop.deinit();
            w.pool = try pool.Pool.init(allocator, .{ .count = sizing.buffers_per_worker, .buffer_size = sizing.buffer_size });
            w.pool.setReserve(@max(64, @as(u32, cfg.io.rx_parallel) * 4));
            errdefer w.pool.deinit();
            w.wheel = timeouts.Wheel.init(w.loop.now());
            if (has_userspace_tcp) {
                w.tcp = try Tcp.init(allocator, cfg, sizing.tcp_sessions_per_worker, sizing.buffer_size, engine.secret +% id);
                w.tcp.fitBudgets(&w.pool);
            }
            errdefer if (has_userspace_tcp) w.tcp.deinit(allocator);
            w.udp = try Udp.init(allocator, sizing.udp_sessions_per_worker, cfg.stack.udp_idle_timeout_ms, cfg.stack.udp == .enabled, cfg.stack.udp_nat);
            errdefer w.udp.deinit(allocator);
            w.ping = try Ping.init(allocator, cfg.stack.icmp_idle_timeout_ms);
            errdefer w.ping.deinit(allocator);
            if (has_system) {
                w.system = null;
                if (cfg.stack.mode != .userspace and engine.device_kind == .tun) {
                    w.system = try System.init(allocator, cfg, id, engine.worker_count, sizing.tcp_sessions_per_worker, &engine.listener_ports);
                }
            }
            errdefer if (has_system) {
                if (w.system) |*s| s.deinit();
            };
            if (has_system) {
                w.redirect = null;
                if (engine.redirect_port != 0) {
                    w.redirect = try Redirect.init(allocator, sizing.tcp_sessions_per_worker, engine.redirect_fds4[id], engine.redirect_fds6[id], engine.redirect_port);
                    engine.redirect_fds4[id] = sys.invalid_fd;
                    engine.redirect_fds6[id] = sys.invalid_fd;
                }
            }
            errdefer if (has_system) {
                if (w.redirect) |*r| {
                    r.finalizeUnregistered();
                    r.deinit();
                }
            };
            if (build_options.enable_fragments) {
                w.reasm = try stack.ip.Reassembler.init(allocator, @max(4, cfg.stack.max_reassembly / engine.worker_count), sizing.buffer_size, cfg.stack.reassembly_timeout_ms);
            }
            errdefer if (build_options.enable_fragments) w.reasm.deinit(allocator, &w.pool);
            w.handler = try Handler.init(allocator, cfg, engine.protect, engine.fake_dns);
            errdefer w.handler.deinit();
            if (has_passthrough) {
                w.passthrough = if (engine.passthrough_shared) |s| Passthrough.init(s, cfg.handler.passthrough_gso) else null;
            }
            w.inbox = .{};
            w.device = .none;
            switch (engine.device_kind) {
                .tun, .fd => {
                    if (has_wintun and engine.device_kind == .tun) {
                        w.device = .{ .wintun = undefined };
                        try w.device.wintun.init(w, engine.opened.?.native.wintun);
                    } else {
                        if (!has_tun) return error.NotSupported;
                        w.device = .{ .tun = undefined };
                        const opts: device.FdQueueOptions = if (engine.device_kind == .fd)
                            device.android.queueOptions(engine.device_fds[0], cfg.device.mtu)
                        else
                            .{
                                .fd = engine.device_fds[id],
                                .caps = engine.caps,
                                .rx_parallel = @max(2, cfg.io.rx_parallel / @max(1, engine.sizing.workers)),
                                .tx_slots = cfg.io.tx_slots,
                                .ring = cfg.io.multishot_rx,
                            };
                        try w.device.tun.init(allocator, w, opts);
                    }
                },
                .external => {
                    w.device = .{ .external = undefined };
                    w.device.external.init(w, engine.external.?);
                },
            }
            return w;
        }

        pub fn destroy(w: *Self) void {
            const allocator = w.allocator;
            w.drainInbox();
            switch (w.device) {
                .tun => |*q| if (has_tun) q.deinit(allocator),
                .wintun => |*q| if (has_wintun) q.deinit(),
                .external => |*q| q.deinit(),
                .none => {},
            }
            if (build_options.enable_fragments) w.reasm.deinit(allocator, &w.pool);
            if (has_system) {
                if (w.system) |*s| s.deinit();
                if (w.redirect) |*r| {
                    r.finalizeUnregistered();
                    r.deinit();
                }
            }
            w.ping.deinit(allocator);
            w.udp.deinit(allocator);
            if (has_userspace_tcp) w.tcp.deinit(allocator);
            w.handler.deinit();
            w.pool.deinit();
            w.loop.deinit();
            allocator.destroy(w);
        }

        pub inline fn now(w: *const Self) u64 {
            return w.loop.now();
        }

        pub inline fn judge(w: *const Self) *const verdict.Judge {
            return &w.engine.judge;
        }

        pub inline fn caps(w: *const Self) device.Capabilities {
            return w.dev_caps;
        }

        pub fn recvNow(w: *Self, fd: sys.fd_t, buf: []u8) i32 {
            _ = w;
            return sys.recv(fd, buf, sys.msg_dontwait);
        }

        pub fn transmit(w: *Self, b: *pool.Buffer, vh: gso.VirtioNetHdr) void {
            switch (w.device) {
                .tun => |*q| if (has_tun) q.send(b, vh) else unreachable,
                .wintun => |*q| if (has_wintun) q.send(b, vh) else unreachable,
                .external => |*q| q.send(b, vh),
                .none => w.pool.put(b),
            }
        }

        pub fn transmitParts(w: *Self, header: []const u8, vh: gso.VirtioNetHdr, parts: []const device.PayloadRef) void {
            switch (w.device) {
                .tun => |*q| if (has_tun) q.sendParts(header, vh, parts) else unreachable,
                .wintun => |*q| if (has_wintun) q.sendParts(header, vh, parts) else unreachable,
                .external => |*q| q.sendParts(header, vh, parts),
                .none => {},
            }
        }

        pub fn injectToDevice(w: *Self, b: *pool.Buffer) void {
            switch (w.device) {
                .tun => |*q| if (has_tun) q.sendCoalesced(b) else unreachable,
                .wintun => |*q| if (has_wintun) q.sendCoalesced(b) else unreachable,
                .external => |*q| q.sendCoalesced(b),
                .none => w.pool.put(b),
            }
        }

        pub fn onDevicePacket(w: *Self, b: *pool.Buffer, vh: gso.VirtioNetHdr) void {
            stack.dispatch(w, b, vh);
        }

        pub fn handoff(w: *Self, owner: u16, b: *pool.Buffer, vh: gso.VirtioNetHdr) void {
            const hops = b.flags & pool.hop_mask;
            if (hops == pool.hop_mask) {
                w.counters.inc(.rx_dropped);
                w.pool.put(b);
                return;
            }
            b.flags = (b.flags & ~pool.hop_mask) | (hops + 1);
            b.meta = packMeta(vh);
            w.counters.inc(.handoffs);
            w.post(owner, b);
        }

        pub fn sendControl(w: *Self, to: u16, b: *pool.Buffer, kind: elastic.Control) void {
            b.flags = pool.flag_control;
            b.meta = @intFromEnum(kind);
            w.post(to, b);
        }

        fn post(w: *Self, to: u16, b: *pool.Buffer) void {
            const target = w.engine.workerAs(Self, to);
            target.inbox.push(b);
            if (to < 64) {
                w.wake_mask |= @as(u64, 1) << @intCast(to);
            } else {
                target.loop.wakeup();
            }
        }

        fn drainInbox(w: *Self) void {
            var list = w.inbox.takeAll();
            while (list) |b| {
                list = b.next;
                b.next = null;
                if (b.flags & pool.flag_control != 0) {
                    w.dropControl(b);
                } else {
                    w.pool.put(b);
                }
            }
        }

        fn onControl(w: *Self, b: *pool.Buffer) void {
            switch (@as(elastic.Control, @enumFromInt(b.meta))) {
                .tcp_transfer => if (has_userspace_tcp) w.tcp.install(w, b) else w.pool.put(b),
                .tcp_ack => if (has_userspace_tcp) w.tcp.onTransferAck(w, b) else w.pool.put(b),
                .udp_transfer => w.udp.install(w, b),
                .udp_ack => w.udp.onTransferAck(w, b),
                _ => w.pool.put(b),
            }
        }

        fn dropControl(w: *Self, b: *pool.Buffer) void {
            switch (@as(elastic.Control, @enumFromInt(b.meta))) {
                .tcp_transfer => if (has_userspace_tcp) w.tcp.dropRecord(w, b) else w.pool.put(b),
                .udp_transfer => w.udp.dropRecord(w, b),
                else => w.pool.put(b),
            }
        }

        pub fn peerOwner(w: *Self, comptime proto: enum { tcp, udp }, key: *const parse.FlowKey) ?u16 {
            const live = w.engine.live.load(.acquire);
            if (live <= 1) return null;
            const list = w.engine.workerList(Self);
            var i: u16 = 0;
            while (i < live) : (i += 1) {
                if (i == w.id) continue;
                const peer = list[i];
                const hit = switch (proto) {
                    .tcp => has_userspace_tcp and peer.tcp.conns.containsShared(key),
                    .udp => peer.udp.sessions.containsShared(key),
                };
                if (hit) return i;
            }
            return null;
        }

        pub fn newFlowTarget(w: *Self, hash: u64) ?u16 {
            const el = w.engine.elastic orelse return null;
            const role = el.roles[w.id].load(.acquire);
            if (role == .active) return null;
            const attached = el.attached.load(.acquire);
            const choices: u16 = if (role == .draining) @min(w.id, attached) else attached;
            if (choices == 0) return null;
            return @intCast(hash % choices);
        }

        pub inline fn elasticLive(w: *const Self) bool {
            return w.engine.live.load(.unordered) > 1;
        }

        fn flushWakes(w: *Self) void {
            var mask = w.wake_mask;
            w.wake_mask = 0;
            while (mask != 0) {
                const i: u16 = @intCast(@ctz(mask));
                mask &= mask - 1;
                w.engine.workerAs(Self, i).loop.wakeup();
            }
        }

        pub fn dialEarlyData(w: *Self, d: *Dial, iovs: []sys.iovec_const) u32 {
            return switch (d.owner) {
                .tcp => if (has_userspace_tcp) w.tcp.earlyData(d, iovs) else 0,
                else => 0,
            };
        }

        pub fn dialStream(w: *Self, d: *Dial) void {
            switch (d.owner) {
                .tcp => if (has_userspace_tcp) w.tcp.streamEarly(d),
                else => {},
            }
        }

        pub fn onDialDone(w: *Self, d: *Dial, result: sys.Errno) void {
            switch (d.owner) {
                .tcp => if (has_userspace_tcp) w.tcp.onDialDone(w, d, result),
                .system => if (has_system) w.system.?.onDialDone(w, d, result),
                .redirect => if (has_system) w.redirect.?.onDialDone(w, d, result),
                .udp => if (build_options.enable_socks5) {
                    const st: *UdpState = @alignCast(@fieldParentPtr("ctrl", d));
                    w.handler.onUdpControlReady(w, st, result);
                },
            }
        }

        pub fn onUdpDatagram(w: *Self, st: *UdpState, src: addr.Endpoint, b: *pool.Buffer, seg: u16) void {
            w.udp.deliver(w, st, src, b, seg);
        }

        pub fn onUdpUnreachable(w: *Self, st: *UdpState, target: addr.Endpoint) void {
            w.udp.unreachable_(w, st, target);
        }

        pub fn onUdpClosed(w: *Self, st: *UdpState) void {
            w.udp.closeByHandler(w, st);
        }

        pub fn onUdpUpstreamGone(w: *Self, st: *UdpState) void {
            w.udp.closeByHandler(w, st);
        }

        pub fn onUdpMaybeIdle(w: *Self, st: *UdpState) void {
            w.udp.maybeRelease(w, st);
        }

        fn onTimer(w: *Self, t: *timeouts.Timer) void {
            switch (@as(timeouts.Kind, @enumFromInt(t.kind))) {
                .tcp_rto, .tcp_persist, .tcp_life, .tcp_delack => if (has_userspace_tcp) w.tcp.onTimer(w, t),
                .udp_idle => w.udp.onTimer(w, t),
                .icmp_idle => w.ping.onTimer(w, t),
                .frag_expire => if (build_options.enable_fragments) w.reasm.expire(&w.pool, t),
                .nat_expire => if (has_system) w.system.?.onTimer(w, t),
                .dial_timeout => w.handler.onDialTimeout(w, handler_mod.DialBuf(Self).fromTimer(t)),
                .pool_expire => w.handler.onWarmExpire(w, handler_mod.Warm(Self).fromTimer(t)),
                else => {},
            }
        }

        fn startDevice(w: *Self) !void {
            switch (w.device) {
                .tun => |*q| if (has_tun) try q.start(),
                .wintun => |*q| if (has_wintun) try q.start(),
                .external => |*q| try q.start(),
                .none => {},
            }
            if (has_system) {
                if (w.system) |*s| s.start(w) catch |err| {
                    log.warn("worker {d}: system stack listener failed: {t}", .{ w.id, err });
                };
                if (w.redirect) |*r| r.start(w) catch |err| {
                    log.warn("worker {d}: redirect listener failed: {t}", .{ w.id, err });
                };
            }
        }

        fn pollSources(w: *Self) bool {
            var worked = false;
            var list = w.inbox.takeAll();
            while (list) |b| {
                list = b.next;
                b.next = null;
                worked = true;
                if (b.flags & pool.flag_control != 0) {
                    w.onControl(b);
                } else {
                    stack.dispatch(w, b, unpackMeta(b.meta));
                }
            }
            switch (w.device) {
                .external => |*q| {
                    if (q.poll() > 0) worked = true;
                },
                .wintun => |*q| if (has_wintun) {
                    if (q.poll() > 0) worked = true;
                },
                else => {},
            }
            if (has_passthrough) {
                if (w.passthrough) |*p| p.poll(w);
            }
            if (w.pool.remote.load(.unordered) != null) _ = w.pool.drainRemote();
            return worked;
        }

        fn flushOutput(w: *Self) void {
            w.handler.flushUdp(w);
            if (has_userspace_tcp) w.tcp.flush(w);
            if (has_passthrough) {
                if (w.passthrough) |*p| p.flush(w);
            }
            switch (w.device) {
                .tun => |*q| if (has_tun) {
                    q.flush();
                    q.refill();
                },
                .wintun => |*q| if (has_wintun) q.flush(),
                .external => |*q| q.flush(),
                .none => {},
            }
            w.flushWakes();
        }

        fn hasImmediateWork(w: *Self) bool {
            if (has_userspace_tcp and w.tcp.dirty_head != null) return true;
            return false;
        }

        fn deviceStarved(w: *Self) bool {
            return switch (w.device) {
                .tun => |*q| has_tun and q.starved(),
                else => false,
            };
        }

        fn reclaimPending(w: *Self) bool {
            return switch (w.device) {
                .tun => |*q| has_tun and q.reclaimPending(),
                else => false,
            };
        }

        fn trimWaitMs(w: *Self, wait_ms: u64) u64 {
            if (has_userspace_tcp and w.tcp.hasStarved()) return @min(wait_ms, starved_wait_ms);
            if (w.deviceStarved()) return @min(wait_ms, starved_wait_ms);
            if (w.pool.trimPending() or w.reclaimPending()) return @min(wait_ms, pool_trim_ms);
            return wait_ms;
        }

        fn trimPool(w: *Self, now_ms: u64) void {
            if (now_ms < w.trim_at_ms) return;
            w.trim_at_ms = now_ms + pool_trim_ms;
            _ = w.pool.trim();
            switch (w.device) {
                .tun => |*q| if (has_tun) {
                    _ = q.reclaimIdle();
                },
                else => {},
            }
            w.gauges.publish(.{
                .buffers = w.pool.capacity(),
                .in_use = w.pool.in_use,
                .resident_bytes = w.pool.residentBytes(),
                .released_bytes = w.pool.released,
                .starved_flows = if (has_userspace_tcp) w.tcp.starvedCount() else 0,
                .exhausted = w.pool.exhausted,
            });
        }

        fn elasticWaitMs(w: *Self, wait_ms: u64) u64 {
            const el = w.engine.elastic orelse return wait_ms;
            if ((has_userspace_tcp and w.tcp.moving_len > 0) or w.udp.moving_len > 0) return @min(wait_ms, 1);
            if (el.roles[w.id].load(.unordered) == .draining) return @min(wait_ms, 20);
            if (w.id == 0 and el.attached.load(.unordered) > 1) return @min(wait_ms, elastic.tick_ms * 4);
            return wait_ms;
        }

        pub fn iterate(w: *Self, max_wait_ms: u64) void {
            const wait_ms: u64 = if (w.hasImmediateWork()) 0 else w.trimWaitMs(w.elasticWaitMs(w.wheel.timeoutMs(max_wait_ms)));
            w.loop.run(wait_ms * std.time.ns_per_ms) catch |err| {
                log.err("worker {d}: event loop failure: {t}", .{ w.id, err });
                w.engine.requestStop();
            };
            w.wheel.advance(w.loop.now(), w, onTimer);
            _ = w.pollSources();
            w.trimPool(w.loop.now());
            if (w.engine.elastic) |el| w.elasticStep(el);
            const epoch = w.engine.network_epoch.load(.acquire);
            if (epoch != w.network_epoch) {
                w.network_epoch = epoch;
                w.resetNetwork();
            }
            w.flushOutput();
        }

        fn elasticStep(w: *Self, el: *Elastic) void {
            const now_ms = w.loop.now();
            if (now_ms >= el.next_tick.load(.unordered)) w.engine.balance(Self, now_ms);
            if (has_userspace_tcp) {
                if (w.tcp.moving_len > 0) w.tcp.progressMigrations(w);
                if (w.tcp.fwd_len > 0) w.tcp.expireForwards(w, now_ms);
            }
            if (w.udp.moving_len > 0) w.udp.progressMigrations(w);
            if (w.udp.fwd_len > 0) w.udp.expireForwards(w, now_ms);
            const seq = el.rebalance_seq.load(.unordered);
            if (seq != w.rebalance_seen) {
                w.rebalance_seen = seq;
                w.donate(el);
            }
            if (el.roles[w.id].load(.unordered) == .draining) {
                w.drainStep(now_ms);
            } else {
                w.drain_since = 0;
            }
        }

        fn donate(w: *Self, el: *Elastic) void {
            const to = el.rebalance_to.load(.acquire);
            if (to == w.id or to >= w.engine.live.load(.acquire)) return;
            if (el.roles[w.id].load(.acquire) != .active) return;
            const attached = el.attached.load(.acquire);
            if (w.id >= attached) return;
            var fraction: u32 = 0;
            const by_count = el.mode == .rotate;
            if (by_count) {
                fraction = 1000 / @as(u32, attached);
            } else {
                var total: u32 = 0;
                var n: u32 = 0;
                var i: u16 = 0;
                while (i < attached) : (i += 1) {
                    if (el.roles[i].load(.acquire) != .active) continue;
                    total += el.util[i].load(.acquire);
                    n += 1;
                }
                const ideal = total / @max(n, 1);
                const mine: u32 = el.util[w.id].load(.acquire);
                if (mine <= ideal + 50) return;
                fraction = (mine - ideal) * 1000 / mine;
            }
            if (has_userspace_tcp) w.tcp.donate(w, to, fraction, by_count);
            w.udp.donate(w, to, fraction, by_count);
        }

        fn drainStep(w: *Self, now_ms: u64) void {
            if (w.drain_since == 0) {
                w.drain_since = now_ms;
                w.drain_quiet_at = now_ms;
                w.drain_rx_mark = w.counters.get(.rx_packets);
            }
            if (now_ms >= w.drain_scan_at) {
                w.drain_scan_at = now_ms + 50;
                if (has_userspace_tcp) w.tcp.drainOut(w);
                w.udp.drainOut(w);
            }
            if (now_ms -| w.drain_quiet_at >= drain_quiet_ms) {
                const rx = w.counters.get(.rx_packets);
                const busy = rx -% w.drain_rx_mark > drain_quiet_packets;
                w.drain_rx_mark = rx;
                w.drain_quiet_at = now_ms;
                if (busy and now_ms - w.drain_since < drain_limit_ms) return;
            } else if (now_ms - w.drain_since < drain_limit_ms) {
                return;
            }
            const tcp_left: u32 = if (has_userspace_tcp) w.tcp.localCount() else 0;
            const settled = (tcp_left == 0 and w.udp.localCount() == 0) or now_ms - w.drain_since >= drain_limit_ms;
            if (!settled) return;
            if ((has_userspace_tcp and w.tcp.moving_len > 0) or w.udp.moving_len > 0) return;
            w.engine.finishDrain(w.id);
        }

        fn resetNetwork(w: *Self) void {
            w.udp.shutdownAll(w);
            w.ping.shutdownAll(w);
            w.handler.dropPool(w);
        }

        pub fn bootstrap(engine: *Engine, id: u16) void {
            const el = engine.elastic.?;
            const w = boot(engine, id) catch |err| {
                log.warn("elastic: worker {d} failed to start: {t}", .{ id, err });
                el.failed.store(true, .release);
                el.growing.store(false, .release);
                return;
            };
            el.growing.store(false, .release);
            w.run();
        }

        fn boot(engine: *Engine, id: u16) !*Self {
            if (!sys.is_linux) return error.NotSupported;
            const el = engine.elastic.?;
            const tun = &engine.opened.?.native.linux;
            var scope = engine.netns.enter();
            defer scope.leave();
            const fd = try tun.addQueue();
            engine.device_fds[id] = fd;
            errdefer {
                tun.queue_count -= 1;
                tun.fds[tun.queue_count] = -1;
                engine.device_fds[id] = sys.invalid_fd;
                sys.close(fd);
            }
            const w = try Self.create(engine, id);
            engine.workerList(Self)[id] = w;
            el.roles[id].store(.active, .release);
            engine.live.store(id + 1, .release);
            el.attached.store(id + 1, .release);
            engine.startRebalance(id);
            log.info("elastic: queue {d} attached with a new worker", .{id});
            return w;
        }

        pub fn run(w: *Self) void {
            if (w.engine.elastic) |el| el.tids[w.id].store(elastic.currentTid(), .release);
            if (w.cfg.io.pin_cpus and w.engine.worker_cap > 1) _ = sys.pinCurrentThread(w.id % sys.cpuCount());
            w.loop.enable() catch |err| {
                log.err("worker {d}: enabling event loop failed: {t}", .{ w.id, err });
                w.engine.requestStop();
                return;
            };
            w.loop.updateTime();
            w.wheel.now = w.loop.now();
            w.startDevice() catch |err| {
                log.err("worker {d}: device start failed: {t}", .{ w.id, err });
                w.engine.failed.store(true, .release);
                w.engine.requestStop();
                return;
            };
            _ = w.engine.ready.fetchAdd(1, .acquire);
            const spin_ns: u64 = @as(u64, w.cfg.io.busy_poll_us) * std.time.ns_per_us;
            while (w.engine.state.load(.acquire) == .running) {
                const spinning = spin_ns != 0 and w.loop.nowNs() -% w.last_activity_ns < spin_ns;
                w.iterate(if (spinning) 0 else idle_wait_ms);
                if (spin_ns != 0) {
                    const mark = w.activity();
                    if (mark != w.activity_mark) {
                        w.activity_mark = mark;
                        w.last_activity_ns = w.loop.nowNs();
                    }
                }
            }
            w.teardown();
        }

        fn activity(w: *const Self) u64 {
            const c = w.counters;
            return c.get(.rx_packets) +% c.get(.tx_packets) +% c.get(.upstream_rx_bytes) +% c.get(.upstream_tx_bytes) +% c.get(.handoffs);
        }

        fn teardown(w: *Self) void {
            switch (w.device) {
                .tun => |*q| if (has_tun) q.stop(),
                .wintun => |*q| if (has_wintun) q.stop(),
                .external => |*q| q.stop(),
                .none => {},
            }
            if (has_system) {
                if (w.system) |*s| s.stop(w);
                if (w.redirect) |*r| r.stop(w);
            }
            w.handler.stop(w);
            if (has_userspace_tcp) w.tcp.shutdownAll(w);
            w.udp.shutdownAll(w);
            w.ping.shutdownAll(w);
            w.flushOutput();
            const deadline = sys.monotonicMs() + 2000;
            while (sys.monotonicMs() < deadline and !w.quiescent()) {
                w.loop.run(10 * std.time.ns_per_ms) catch break;
                w.wheel.advance(w.loop.now(), w, onTimer);
                _ = w.pollSources();
                w.flushOutput();
            }
            switch (w.device) {
                .tun => |*q| if (has_tun) q.finish(),
                else => {},
            }
            if (has_system) {
                if (w.system) |*s| s.finalize(w);
                if (w.redirect) |*r| r.finalize(w);
            }
        }

        fn quiescent(w: *Self) bool {
            if (has_userspace_tcp and w.tcp.activeCount() != 0) return false;
            if (w.udp.sessions.len != 0) return false;
            if (!w.ping.idle()) return false;
            if (!w.handler.idle()) return false;
            if (has_system) {
                if (w.system) |*s| if (!s.idle()) return false;
                if (w.redirect) |*r| if (!r.idle()) return false;
            }
            switch (w.device) {
                .tun => |*q| if (has_tun and !q.idle()) return false,
                .wintun => |*q| if (has_wintun and !q.idle()) return false,
                else => {},
            }
            return true;
        }
    };
}

pub fn txQueueLen(cfg: *const config.Config, caps: device.Capabilities) ?u32 {
    if (cfg.device.txqueuelen != 0) return cfg.device.txqueuelen;
    if (caps.vnet_hdr) return null;
    return std.math.clamp((8 << 20) / @max(cfg.device.mtu, 576), 1000, 4096);
}

pub fn autoWorkers(preset: config.Preset, cpus: u32) u16 {
    const n = if (preset == .server) cpus else cpus / 4;
    return @intCast(std.math.clamp(n, 1, 64));
}

test "automatic worker count" {
    try std.testing.expectEqual(@as(u16, 1), autoWorkers(.desktop, 4));
    try std.testing.expectEqual(@as(u16, 2), autoWorkers(.desktop, 8));
    try std.testing.expectEqual(@as(u16, 1), autoWorkers(.desktop, 1));
    try std.testing.expectEqual(@as(u16, 16), autoWorkers(.server, 16));
    try std.testing.expectEqual(@as(u16, 64), autoWorkers(.server, 256));
}

const uring_ready = io.IoUring != void;
const epoll_ready = io.Epoll != void;
const kqueue_ready = io.Kqueue != void and @hasDecl(io.Kqueue, "run");
const iocp_ready = io.Iocp != void and @hasDecl(io.Iocp, "run");

pub fn WorkerFor(comptime kind: io.BackendKind) type {
    return switch (kind) {
        .io_uring => if (uring_ready) Worker(io.IoUring) else void,
        .epoll => if (epoll_ready) Worker(io.Epoll) else void,
        .kqueue => if (kqueue_ready) Worker(io.Kqueue) else void,
        .iocp => if (iocp_ready) Worker(io.Iocp) else void,
    };
}

fn WorkerSlice(comptime kind: io.BackendKind) type {
    const W = WorkerFor(kind);
    return if (W == void) void else []*W;
}

pub fn backendCompiled(kind: io.BackendKind) bool {
    return WorkerFor(kind) != void;
}

pub const Workers = union(io.BackendKind) {
    io_uring: WorkerSlice(.io_uring),
    epoll: WorkerSlice(.epoll),
    kqueue: WorkerSlice(.kqueue),
    iocp: WorkerSlice(.iocp),
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    cfg: config.Config,
    state: std.atomic.Value(State) = .init(.created),
    backend: io.BackendKind = .epoll,
    device_kind: config.DeviceKind = .tun,
    worker_count: u16 = 0,
    worker_cap: u16 = 0,
    live: std.atomic.Value(u16) = .init(0),
    spawned: std.atomic.Value(u16) = .init(0),
    elastic: ?*Elastic = null,
    counters: []stats.Counters = &.{},
    gauges: []stats.Gauges = &.{},
    sizing: config.Sizing = undefined,
    caps: device.Capabilities = .{},
    opened: ?device.Opened = null,
    device_fds: [device.linux.max_queues]sys.fd_t = @splat(sys.invalid_fd),
    external: ?*device.external.Shared = null,
    passthrough_shared: ?*device.external.Shared = null,
    protect: handler_mod.direct.Protect = .{},
    judge: verdict.Judge = .{},
    route_state: route.State = .{},
    netns: route.netns.Handle = .{},
    workers: ?Workers = null,
    secret: u64 = 0,
    ifname: [16]u8 = @splat(0),
    ifindex: u32 = 0,
    setup_done: bool = false,
    ready: std.atomic.Value(u32) = .init(0),
    failed: std.atomic.Value(bool) = .init(false),
    stop_requested: std.atomic.Value(bool) = .init(false),
    listener_ports: @import("flow/nat.zig").ListenerPorts = .{},
    fake_dns: ?*stack.dns.Table = null,
    redirect_port: u16 = 0,
    monitor: route.monitor.Monitor = .{},
    network_epoch: std.atomic.Value(u32) = .init(0),
    bind_index_live: std.atomic.Value(u32) = .init(0),
    redirect_fds4: [device.linux.max_queues]sys.fd_t = @splat(sys.invalid_fd),
    redirect_fds6: [device.linux.max_queues]sys.fd_t = @splat(sys.invalid_fd),

    pub fn create(allocator: std.mem.Allocator, cfg: config.Config) !*Engine {
        try cfg.validate();
        const e = try allocator.create(Engine);
        errdefer allocator.destroy(e);
        e.* = .{ .allocator = allocator, .cfg = cfg, .device_kind = cfg.device.kind };
        if (cfg.dnsActive() and e.cfg.route.dns.len == 0) {
            if (cfg.dnsAddress4()) |a| e.cfg.route.dns.append(.{ .addr = a, .bits = 32 }) catch {};
            if (cfg.dnsAddress6()) |a| e.cfg.route.dns.append(.{ .addr = a, .bits = 128 }) catch {};
        }
        if (cfg.dns.fake_ip) {
            const range6 = if (build_options.enable_ipv6) cfg.dns.fake_range6 else null;
            e.fake_dns = try stack.dns.Table.init(allocator, cfg.dns.fake_range4, range6, cfg.dns.cache_size, cfg.dns.ttl);
        }
        errdefer if (e.fake_dns) |t| t.deinit();
        var seed: [8]u8 = undefined;
        fillRandom(&seed);
        e.secret = std.mem.readInt(u64, &seed, .little);
        if (cfg.device.kind == .external) {
            e.external = try device.external.Shared.init(allocator, cfg.device.mtu, 4096);
            e.external.?.wake = wakeFirst;
            e.external.?.wake_ctx = e;
        }
        if (cfg.handler.kind == .passthrough and build_options.enable_passthrough) {
            e.passthrough_shared = try device.external.Shared.init(allocator, 65535, 4096);
            e.passthrough_shared.?.wake = wakeFirst;
            e.passthrough_shared.?.wake_ctx = e;
        }
        e.protect.fwmark = if (cfg.handler.direct.fwmark != 0) cfg.handler.direct.fwmark else if (cfg.route.auto_route) cfg.route.fwmark else 0;
        e.protect.bind_interface = cfg.handler.direct.bind_interface;
        e.protect.bind4 = cfg.handler.direct.bind4;
        e.protect.bind6 = cfg.handler.direct.bind6;
        e.protect.index_ref = &e.bind_index_live;
        return e;
    }

    fn fillRandom(buf: []u8) void {
        if (sys.randomBytes(buf)) return;
        var anchor: u8 = 0;
        var state = std.hash.Wyhash.hash(sys.monotonicNs(), std.mem.asBytes(&@intFromPtr(&anchor)));
        for (buf) |*b| {
            state = std.hash.Wyhash.hash(state, std.mem.asBytes(&@intFromPtr(buf.ptr)));
            b.* = @truncate(state);
        }
    }

    fn wakeFirst(ctx: ?*anyopaque) void {
        const e: *Engine = @ptrCast(@alignCast(ctx.?));
        e.wakeWorker(0);
    }

    pub fn setJudge(e: *Engine, f: ?verdict.Fn, ctx: ?*anyopaque) void {
        e.judge = .{ .call = f, .ctx = ctx };
    }

    pub fn setProtect(e: *Engine, f: ?*const fn (ctx: ?*anyopaque, fd: c_int) callconv(.c) bool, ctx: ?*anyopaque) void {
        e.protect.android_fn = f;
        e.protect.android_ctx = ctx;
    }

    pub fn setAdapterGuid(e: *Engine, text: []const u8) !void {
        e.cfg.device.guid = try config.Guid.parse(text);
    }

    pub fn setDeviceFd(e: *Engine, fd: sys.fd_t) void {
        e.cfg.device.fd = @intCast(fd);
        if (fd >= 0) {
            e.cfg.device.kind = .fd;
            e.device_kind = .fd;
        }
    }

    pub fn workerAs(e: *Engine, comptime W: type, index: u16) *W {
        const ws = e.workers.?;
        switch (ws) {
            inline else => |list, tag| {
                if (comptime WorkerFor(tag) == W) return list[index];
            },
        }
        unreachable;
    }

    pub fn workerList(e: *Engine, comptime W: type) []*W {
        const ws = e.workers.?;
        switch (ws) {
            inline else => |list, tag| {
                if (comptime WorkerFor(tag) == W) return list;
            },
        }
        unreachable;
    }

    pub fn wakeWorker(e: *Engine, index: u16) void {
        const ws = e.workers orelse return;
        switch (ws) {
            inline else => |list, tag| {
                if (comptime WorkerFor(tag) != void) {
                    if (index < e.live.load(.acquire) and index < list.len) list[index].loop.wakeup();
                }
            },
        }
    }

    fn wakeAll(e: *Engine) void {
        var i: u16 = 0;
        while (i < e.live.load(.acquire)) : (i += 1) e.wakeWorker(i);
    }

    fn elasticWanted(cfg: *const config.Config, cap: u16) bool {
        if (cfg.io.elastic == .off or cap < 2 or @bitSizeOf(usize) < 64) return false;
        if (!sys.is_linux or !can_spawn_threads) return false;
        if (sys.is_android and cfg.io.elastic == .auto) return false;
        if (cfg.device.kind != .tun or !cfg.device.multi_queue) return false;
        if (cfg.stack.mode != .userspace or !build_options.enable_userspace_tcp) return false;
        if (cfg.handler.kind == .passthrough or cfg.route.auto_redirect) return false;
        return true;
    }

    fn initElastic(e: *Engine, cap: u16) !void {
        const el = try e.allocator.create(Elastic);
        el.* = .{ .mode = e.cfg.io.elastic, .cap = cap, .cpus = sys.cpuCount() };
        e.elastic = el;
    }

    fn startRebalance(e: *Engine, to: u16) void {
        const el = e.elastic.?;
        el.rebalance_to.store(to, .release);
        _ = el.rebalance_seq.fetchAdd(1, .release);
        e.wakeAll();
    }

    fn balance(e: *Engine, comptime W: type, now_ms: u64) void {
        const el = e.elastic.?;
        if (el.lock.cmpxchgStrong(false, true, .acquire, .acquire) != null) return;
        defer el.lock.store(false, .release);
        if (now_ms < el.next_tick.load(.acquire)) return;
        el.next_tick.store(@truncate(now_ms + elastic.tick_ms), .release);
        if (e.state.load(.acquire) != .running or el.growing.load(.acquire)) return;
        const live = e.live.load(.acquire);
        const attached = el.attached.load(.acquire);
        const now_ns = sys.monotonicNs();
        var bytes: u64 = 0;
        for (e.counters[0..live]) |*c| bytes +%= c.get(.rx_bytes) +% c.get(.tx_bytes);
        const dt = now_ns -% el.last_ns;
        const primed = el.last_ns != 0;
        el.last_ns = now_ns;
        const moved_bytes = bytes -% el.last_bytes;
        el.last_bytes = bytes;
        var busiest: u32 = 0;
        var busiest_flows: u32 = 0;
        var total: u32 = 0;
        var i: u16 = 0;
        while (i < live) : (i += 1) {
            const cpu = elastic.threadCpuNs(el.tids[i].load(.acquire)) orelse continue;
            const prev = el.cpu_ns[i];
            el.cpu_ns[i] = cpu;
            const util: u32 = if (!primed or prev == 0 or cpu < prev or dt == 0) 0 else @intCast(@min((cpu - prev) * 1000 / dt, 1000));
            el.util[i].store(@intCast(util), .release);
            if (i < attached and el.roles[i].load(.acquire) == .active) {
                if (util >= busiest) {
                    busiest = util;
                    const c = &e.counters[i];
                    busiest_flows = @intCast(@min(c.get(.tcp_active) +| c.get(.udp_active), std.math.maxInt(u32)));
                }
                total += util;
            }
        }
        if (!primed or dt < 50 * std.time.ns_per_ms) return;
        const idle = if (el.mode == .rotate or busiest >= el.policy.high) el.stat.idleMilli(el.cpus) else null;
        const rate = moved_bytes * std.time.ns_per_s / dt;
        log.debug("elastic: attached {d} busiest {d} flows {d} total {d} idle {?d} rate {d}", .{ attached, busiest, busiest_flows, total, idle, rate });
        const probing = el.policy.probing;
        const decision = switch (el.mode) {
            .rotate => el.rotation.step(now_ms, attached, el.cap),
            else => el.policy.step(.{ .now_ms = now_ms, .attached = attached, .max = el.cap, .busiest = busiest, .total = total, .idle = idle, .rate = rate, .flows = busiest_flows }),
        };
        if (probing and !el.policy.probing) {
            const gain: i64 = @as(i64, @intCast(@min(el.policy.gain_milli, 100_000))) - 1000;
            log.info("elastic: {d} queues changed throughput by {d}%, {s}", .{ attached, @divTrunc(gain, 10), if (decision == .shrink) "releasing the newest queue" else "keeping them" });
        }
        switch (decision) {
            .grow => e.grow(W),
            .shrink => e.shrink(),
            .none => {},
        }
    }

    fn grow(e: *Engine, comptime W: type) void {
        const el = e.elastic.?;
        const attached = el.attached.load(.acquire);
        const live = e.live.load(.acquire);
        if (attached == 0 or attached >= el.cap) return;
        if (el.roles[attached - 1].cmpxchgStrong(.draining, .active, .acquire, .acquire) == null) {
            e.wakeWorker(attached - 1);
            return;
        }
        if (attached < live) {
            e.setQueueAttached(attached, true) catch |err| {
                log.warn("elastic: attaching queue {d} failed: {t}", .{ attached, err });
                return;
            };
            el.roles[attached].store(.active, .release);
            el.attached.store(attached + 1, .release);
            e.startRebalance(attached);
            log.info("elastic: queue {d} attached", .{attached});
            return;
        }
        if (el.failed.load(.acquire) or live >= el.cap) return;
        el.growing.store(true, .release);
        e.spawned.store(live + 1, .release);
        el.threads[live] = std.Thread.spawn(.{ .stack_size = 4 << 20 }, W.bootstrap, .{ e, live }) catch |err| {
            log.warn("elastic: spawning worker {d} failed: {t}", .{ live, err });
            e.spawned.store(live, .release);
            el.failed.store(true, .release);
            el.growing.store(false, .release);
            return;
        };
    }

    fn setQueueAttached(e: *Engine, id: u16, attached: bool) !void {
        if (comptime !sys.is_linux) return error.NotSupported;
        return device.linux.Tun.setQueueAttached(@intCast(e.device_fds[id]), attached);
    }

    fn shrink(e: *Engine) void {
        const el = e.elastic.?;
        const attached = el.attached.load(.acquire);
        if (attached <= 1) return;
        if (el.roles[attached - 1].cmpxchgStrong(.active, .draining, .acquire, .acquire) != null) return;
        e.wakeWorker(attached - 1);
    }

    fn finishDrain(e: *Engine, id: u16) void {
        const el = e.elastic.?;
        if (el.lock.cmpxchgStrong(false, true, .acquire, .acquire) != null) return;
        defer el.lock.store(false, .release);
        if (el.growing.load(.acquire) or el.attached.load(.acquire) != id + 1) return;
        if (el.roles[id].cmpxchgStrong(.draining, .detached, .acquire, .acquire) != null) return;
        e.setQueueAttached(id, false) catch |err| {
            log.warn("elastic: detaching queue {d} failed: {t}", .{ id, err });
            el.roles[id].store(.active, .release);
            return;
        };
        el.attached.store(id, .release);
        log.info("elastic: queue {d} detached", .{id});
    }

    fn resolveBackend(e: *Engine) !io.BackendKind {
        return switch (e.cfg.io.backend) {
            .auto => blk: {
                if (uring_ready and io.available(.io_uring) and e.device_kind != .fd) break :blk .io_uring;
                if (epoll_ready) break :blk .epoll;
                if (kqueue_ready) break :blk .kqueue;
                if (iocp_ready) break :blk .iocp;
                if (uring_ready and io.available(.io_uring)) break :blk .io_uring;
                break :blk error.NotSupported;
            },
            .io_uring => if (uring_ready and io.available(.io_uring)) .io_uring else error.NotSupported,
            .epoll => if (epoll_ready) .epoll else error.NotSupported,
            .kqueue => if (kqueue_ready) .kqueue else error.NotSupported,
            .iocp => if (iocp_ready) .iocp else error.NotSupported,
        };
    }

    fn setup(e: *Engine) !void {
        if (e.setup_done) return;
        log.setLevel(e.cfg.log_level);
        const cfg = &e.cfg;
        const elastic_cap: u16 = @intCast(@min(if (cfg.io.workers != 0) cfg.io.workers else sys.cpuCount(), elastic.max_workers));
        const want_elastic = elasticWanted(cfg, elastic_cap);
        var workers: u16 = if (want_elastic) 1 else if (cfg.io.workers != 0) cfg.io.workers else autoWorkers(cfg.preset, sys.cpuCount());
        var cap: u16 = 0;
        if (build_options.enable_route and !cfg.device.netns.isEmpty()) {
            e.netns = route.netns.open(cfg.device.netns.slice()) catch |err| {
                log.err("netns {s} unavailable: {t}", .{ cfg.device.netns.slice(), err });
                return error.InvalidArgument;
            };
        }
        switch (cfg.device.kind) {
            .tun => {
                var scope = e.netns.enter();
                defer scope.leave();
                var o = try device.openTun(.{
                    .name = cfg.device.name.slice(),
                    .queues = workers,
                    .offload = cfg.device.offload,
                    .multi_queue = cfg.device.multi_queue and (workers > 1 or want_elastic),
                    .persist = cfg.device.persist,
                    .mtu = cfg.device.mtu,
                    .napi = cfg.device.napi,
                    .guid = cfg.device.guid,
                });
                errdefer o.close();
                workers = o.count;
                if (want_elastic and sys.is_linux and o.native == .linux and o.native.linux.multiQueue()) cap = elastic_cap;
                e.caps = o.caps;
                e.caps.mtu = cfg.device.mtu;
                e.caps.jumbo_tx = o.caps.jumbo_tx and cfg.device.jumbo;
                for (o.fds[0..o.count], 0..) |fd, i| e.device_fds[i] = fd;
                e.ifname = o.name;
                e.ifindex = o.index;
                e.opened = o;
                if (build_options.enable_route and cfg.device.configure) {
                    try route.applyLink(cfg, o.nameSlice(), o.index, txQueueLen(cfg, e.caps), &e.route_state);
                }
            },
            .fd => {
                if (!sys.is_linux and !sys.is_darwin) return error.NotSupported;
                workers = 1;
                try device.android.prepareFd(cfg.device.fd);
                e.device_fds[0] = cfg.device.fd;
                e.caps = device.android.capabilities(cfg.device.mtu);
                e.caps.jumbo_tx = e.caps.jumbo_tx and cfg.device.jumbo;
            },
            .external => {
                workers = 1;
                e.caps = .{ .mtu = cfg.device.mtu, .queues = 1 };
            },
        }
        if ((route.macos.supported or route.windows.supported) and cfg.device.kind == .tun and cfg.route.auto_route and cfg.handler.direct.bind_interface.isEmpty()) {
            const lookup = if (sys.is_windows) route.windows.defaultInterfaceIndex else route.macos.defaultInterfaceIndex;
            e.protect.bind_index = lookup(.v4);
            if (e.protect.bind_index == 0) e.protect.bind_index = lookup(.v6);
        }
        e.worker_count = workers;
        e.worker_cap = @max(workers, cap);
        if (cap > workers) try e.initElastic(cap);
        if (has_redirect and cfg.route.auto_redirect and cfg.device.kind == .tun) try e.openRedirectListeners(workers);
        e.backend = try e.resolveBackend();
        e.sizing = config.size(cfg, workers, e.caps.bufferSize(), e.caps.minBufferSize(), session_bytes);
        e.counters = try e.allocator.alloc(stats.Counters, e.worker_cap);
        for (e.counters) |*c| c.* = .{};
        e.gauges = try e.allocator.alloc(stats.Gauges, e.worker_cap);
        for (e.gauges) |*g| g.* = .{};
        try e.createWorkers();
        e.setup_done = true;
        log.info("engine: {d} worker(s), elastic up to {d}, backend {t}, device mtu {d}, vnet_hdr={} tso={} uso={}", .{ workers, if (e.elastic != null) cap else workers, e.backend, e.caps.mtu, e.caps.vnet_hdr, e.caps.tso, e.caps.uso });
    }

    const has_redirect = build_options.enable_system_stack and sys.is_linux and !sys.is_android;

    fn openRedirectListeners(e: *Engine, workers: u16) !void {
        const cfg = &e.cfg;
        const want6 = cfg.device.address6 != null and build_options.enable_ipv6;
        var attempt: u32 = 0;
        outer: while (attempt < 8) : (attempt += 1) {
            e.closeRedirectListeners();
            var port = cfg.route.redirect_port;
            var i: u16 = 0;
            while (i < workers) : (i += 1) {
                const fd4 = stack.redirect.openListener(.v4, port) catch |err| {
                    if (cfg.route.redirect_port == 0 and err == error.AddressInUse) continue :outer;
                    return err;
                };
                e.redirect_fds4[i] = fd4;
                if (port == 0) port = stack.redirect.boundPort(fd4) orelse return error.SystemResources;
                if (want6) {
                    e.redirect_fds6[i] = stack.redirect.openListener(.v6, port) catch |err| {
                        if (cfg.route.redirect_port == 0 and err == error.AddressInUse) continue :outer;
                        return err;
                    };
                }
            }
            e.redirect_port = port;
            return;
        }
        e.closeRedirectListeners();
        return error.AddressInUse;
    }

    fn closeRedirectListeners(e: *Engine) void {
        for (&e.redirect_fds4, &e.redirect_fds6) |*a, *b| {
            if (a.* != sys.invalid_fd) sys.close(a.*);
            if (b.* != sys.invalid_fd) sys.close(b.*);
            a.* = sys.invalid_fd;
            b.* = sys.invalid_fd;
        }
    }

    fn createWorkers(e: *Engine) !void {
        switch (e.backend) {
            inline else => |tag| {
                const W = comptime WorkerFor(tag);
                if (comptime W == void) return error.NotSupported;
                const list = try e.allocator.alloc(*W, e.worker_cap);
                errdefer e.allocator.free(list);
                var created: usize = 0;
                errdefer for (list[0..created]) |w| w.destroy();
                e.workers = @unionInit(Workers, @tagName(tag), list);
                errdefer e.workers = null;
                while (created < e.worker_count) : (created += 1) {
                    list[created] = try W.create(e, @intCast(created));
                }
                e.live.store(e.worker_count, .release);
                e.spawned.store(e.worker_count, .release);
            },
        }
    }

    fn needsRoutes(e: *const Engine) bool {
        return build_options.enable_route and e.cfg.device.configure and e.device_kind == .tun;
    }

    fn waitReady(e: *Engine, timeout_ms: u64) !void {
        const deadline = sys.monotonicMs() + timeout_ms;
        while (e.ready.load(.acquire) < e.worker_count) {
            if (e.failed.load(.acquire) or e.state.load(.acquire) != .running) return error.DeviceError;
            if (sys.monotonicMs() > deadline) return error.Timeout;
            sys.sleepMs(1);
        }
    }

    pub fn start(e: *Engine) !void {
        if (e.state.load(.acquire) != .created) return error.AlreadyRunning;
        try e.setup();
        e.enterRunning();
        errdefer {
            e.requestStop();
            e.wait();
        }
        switch (e.workers.?) {
            inline else => |list, tag| {
                if (comptime WorkerFor(tag) != void) try spawnAll(WorkerFor(tag), list[0..e.worker_count], 0);
            },
        }
        if (e.needsRoutes()) {
            e.waitReady(10_000) catch |err| {
                if (e.stop_requested.load(.acquire) and !e.failed.load(.acquire)) return;
                return err;
            };
            if (e.stop_requested.load(.acquire)) return;
            var scope = e.netns.enter();
            defer scope.leave();
            if (e.redirect_port != 0) {
                route.applyRedirect(&e.cfg, e.interfaceName(), e.redirect_port, &e.route_state) catch |err| {
                    log.warn("auto-redirect unavailable, tcp stays in the tunnel: {t}", .{err});
                };
            }
            try route.applyRoutes(&e.cfg, e.interfaceName(), &e.route_state);
        }
        e.startMonitor();
    }

    fn startMonitor(e: *Engine) void {
        if (!route.monitor.supported or !e.cfg.monitorNetwork() or e.device_kind != .tun) return;
        var scope = e.netns.enter();
        defer scope.leave();
        e.monitor.start(e.ifindex, e, onNetworkChange) catch |err| {
            log.warn("network monitor unavailable: {t}", .{err});
        };
    }

    fn onNetworkChange(ctx: ?*anyopaque, id: route.monitor.Identity) void {
        const e: *Engine = @ptrCast(@alignCast(ctx.?));
        if (e.cfg.handler.direct.bind_interface.isEmpty() and (route.macos.supported or route.windows.supported)) {
            const index = if (id.index4 != 0) id.index4 else id.index6;
            if (index != 0) e.bind_index_live.store(index, .release);
        }
        var scope = e.netns.enter();
        route.refreshRoutes(&e.cfg, e.interfaceName(), &e.route_state) catch |err| {
            log.warn("network: refreshing routes failed: {t}", .{err});
        };
        scope.leave();
        e.bumpNetworkEpoch();
    }

    pub fn networkChanged(e: *Engine, interface_index: u32) void {
        if (interface_index != 0) e.bind_index_live.store(interface_index, .release);
        e.bumpNetworkEpoch();
    }

    fn bumpNetworkEpoch(e: *Engine) void {
        _ = e.network_epoch.fetchAdd(1, .release);
        e.wakeAll();
    }

    pub fn run(e: *Engine) !void {
        if (e.state.load(.acquire) != .created) return error.AlreadyRunning;
        try e.setup();
        if (e.needsRoutes() and can_spawn_threads) {
            e.state.store(.created, .release);
            try e.start();
            e.wait();
            return;
        }
        e.enterRunning();
        switch (e.workers.?) {
            inline else => |list, tag| {
                if (comptime WorkerFor(tag) != void) {
                    try spawnAll(WorkerFor(tag), list[0..e.worker_count], 1);
                    list[0].run();
                }
            },
        }
        e.wait();
    }

    pub const can_spawn_threads = !(builtin.output_mode == .Lib and !builtin.link_libc and sys.is_linux);

    fn spawnAll(comptime W: type, list: []*W, first: usize) !void {
        if (list.len > first and !can_spawn_threads) return error.NotSupported;
        for (list[first..]) |w| {
            w.thread = try std.Thread.spawn(.{ .stack_size = 4 << 20 }, W.run, .{w});
        }
    }

    pub fn requestStop(e: *Engine) void {
        e.stop_requested.store(true, .release);
        if (e.state.cmpxchgStrong(.running, .stopping, .acquire, .acquire) != null) return;
        e.wakeAll();
    }

    fn enterRunning(e: *Engine) void {
        e.state.store(.running, .release);
        if (e.stop_requested.load(.acquire)) e.requestStop();
    }

    pub fn stop(e: *Engine) void {
        e.requestStop();
        if (e.external) |s| s.closed.store(true, .release);
    }

    pub fn wait(e: *Engine) void {
        const ws = e.workers orelse return;
        switch (ws) {
            inline else => |list, tag| {
                if (comptime WorkerFor(tag) != void) e.joinAll(WorkerFor(tag), list);
            },
        }
        e.monitor.stop();
        e.state.store(.stopped, .release);
    }

    fn joinAll(e: *Engine, comptime W: type, list: []*W) void {
        var i: u16 = 0;
        while (i < e.spawned.load(.acquire)) : (i += 1) {
            if (i < e.worker_count) {
                const w = list[i];
                if (w.thread) |t| {
                    t.join();
                    w.thread = null;
                }
            } else if (e.elastic) |el| {
                if (el.threads[i]) |t| {
                    t.join();
                    el.threads[i] = null;
                }
            }
        }
    }

    pub fn destroy(e: *Engine) void {
        if (e.state.load(.acquire) == .running) e.stop();
        e.wait();
        if (e.workers) |ws| {
            switch (ws) {
                inline else => |list, tag| {
                    if (comptime WorkerFor(tag) != void) destroyAll(WorkerFor(tag), e.allocator, list, e.live.load(.acquire));
                },
            }
        }
        if (e.elastic) |el| {
            el.stat.close();
            e.allocator.destroy(el);
        }
        {
            var scope = e.netns.enter();
            defer scope.leave();
            route.teardown(&e.route_state);
        }
        e.netns.close();
        e.closeRedirectListeners();
        if (e.opened) |*o| o.close();
        if (e.external) |s| s.deinit();
        if (e.passthrough_shared) |s| s.deinit();
        if (e.fake_dns) |t| t.deinit();
        if (e.counters.len > 0) e.allocator.free(e.counters);
        if (e.gauges.len > 0) e.allocator.free(e.gauges);
        e.allocator.destroy(e);
    }

    fn destroyAll(comptime W: type, allocator: std.mem.Allocator, list: []*W, live: u16) void {
        const made = list[0..live];
        for (made) |w| w.drainInbox();
        for (made) |w| _ = w.pool.drainRemote();
        for (made) |w| w.destroy();
        allocator.free(list);
    }

    pub fn snapshot(e: *const Engine, out: *stats.Snapshot) void {
        stats.merge(out, e.counters);
        out.workers = @max(1, e.live.load(.acquire));
    }

    pub fn memory(e: *const Engine, out: *stats.Memory) void {
        stats.mergeMemory(out, e.gauges);
        out.workers = @max(1, e.live.load(.acquire));
    }

    pub fn interfaceName(e: *const Engine) []const u8 {
        return std.mem.sliceTo(&e.ifname, 0);
    }

    pub fn isRunning(e: *const Engine) bool {
        return e.state.load(.acquire) == .running;
    }
};

test "meta packing roundtrip" {
    const vh = gso.VirtioNetHdr.tcp(true, 40, 32, 1440, false);
    const back = unpackMeta(packMeta(vh));
    try std.testing.expectEqual(vh.flags, back.flags);
    try std.testing.expectEqual(vh.gso_type, back.gso_type);
    try std.testing.expectEqual(vh.gso_size, back.gso_size);
    try std.testing.expectEqual(vh.csum_start, back.csum_start);
    try std.testing.expectEqual(vh.csum_offset, back.csum_offset);
}
