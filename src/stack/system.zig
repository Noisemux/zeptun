const std = @import("std");
const build_options = @import("build_options");
const addr = @import("../addr.zig");
const config = @import("../config.zig");
const parse = @import("../packet/parse.zig");
const pool = @import("../packet/pool.zig");
const gso = @import("../packet/gso.zig");
const nat = @import("../flow/nat.zig");
const timeouts = @import("../flow/timeouts.zig");
const io = @import("../io/io.zig");
const sys = @import("../io/sys.zig");
const handler_mod = @import("../handler/handler.zig");
const log = @import("../log.zig");

const relay_mod = @import("relay.zig");

const linux = std.os.linux;

pub fn System(comptime W: type) type {
    return struct {
        const Self = @This();
        const Loop = W.Loop;
        const Dial = handler_mod.Dial(W);

        pub const Relay = relay_mod.Relay(W);

        const Listener = struct {
            fd: sys.fd_t = sys.invalid_fd,
            c: Loop.Completion = .{},
            peer: sys.Sockaddr = .{},
        };

        nat_table: nat.Nat,
        relays: []Relay,
        listeners: [2]Listener = .{ .{}, .{} },
        local4: ?[4]u8 = null,
        local6: ?[16]u8 = null,
        nat4: [4]u8 = @splat(0),
        nat6: [16]u8 = @splat(0),
        listen_base: u16,
        listen_port4: u16 = 0,
        listen_port6: u16 = 0,
        ports: *nat.ListenerPorts,
        workers: u16,
        worker_id: u16,
        linger_ms: u32,
        syn_timeout_ms: u32,
        idle_ms: u32,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, cfg: *const config.Config, worker_id: u16, workers: u16, max_mappings: u32, ports: *nat.ListenerPorts) !Self {
            var n = try nat.Nat.init(allocator, .{
                .worker_id = worker_id,
                .workers = workers,
                .port_base = cfg.stack.nat_port_base,
                .port_limit = cfg.stack.nat_port_limit,
                .max_mappings = max_mappings,
            });
            errdefer n.deinit();
            const relays = try allocator.alloc(Relay, n.slots);
            var s: Self = .{
                .nat_table = n,
                .relays = relays,
                .listen_base = cfg.stack.listen_port_base,
                .ports = ports,
                .workers = workers,
                .worker_id = worker_id,
                .linger_ms = cfg.stack.tcp_linger_ms,
                .syn_timeout_ms = cfg.stack.tcp_connect_timeout_ms + 2000,
                .idle_ms = cfg.stack.tcp_idle_timeout_ms,
                .allocator = allocator,
            };
            if (cfg.device.address4) |p| {
                s.local4 = p.addr.bytes[0..4].*;
                s.nat4 = p.host(if (p.addr.bytes[3] & 3 == 2) 1 else 2).bytes[0..4].*;
                if (std.mem.eql(u8, &s.nat4, &s.local4.?)) s.nat4[3] +%= 1;
            }
            if (cfg.device.address6) |p| {
                s.local6 = p.addr.bytes;
                s.nat6 = p.host(2).bytes;
                if (std.mem.eql(u8, &s.nat6, &s.local6.?)) s.nat6[15] +%= 1;
            }
            return s;
        }

        pub fn deinit(sy: *Self) void {
            sy.allocator.free(sy.relays);
            sy.nat_table.deinit();
        }

        pub fn start(sy: *Self, w: *W) !void {
            if (sy.local4) |l| {
                sy.listen_port4 = sy.listenAny(w, 0, addr.Address.v4(l)) catch |err| blk: {
                    log.warn("system stack: ipv4 listener unavailable, tcp stays in userspace: {t}", .{err});
                    sy.local4 = null;
                    break :blk 0;
                };
            }
            if (sy.local6) |l| {
                sy.listen_port6 = sy.listenAny(w, 1, addr.Address.v6(l)) catch |err| blk: {
                    log.warn("system stack: ipv6 listener unavailable, tcp stays in userspace: {t}", .{err});
                    sy.local6 = null;
                    break :blk 0;
                };
            }
        }

        fn listenAny(sy: *Self, w: *W, index: usize, address: addr.Address) !u16 {
            if (sy.listen_base != 0) {
                if (sy.listen(w, index, .{ .addr = address, .port = sy.listen_base +% sy.worker_id })) |port| return port else |err| {
                    if (err != error.AddressInUse) return err;
                }
            }
            return sy.listen(w, index, .{ .addr = address, .port = 0 });
        }

        fn listen(sy: *Self, w: *W, index: usize, ep: addr.Endpoint) !u16 {
            const fd = try sys.socket(ep.addr.family, .tcp);
            errdefer sys.close(fd);
            _ = sys.setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, 1);
            if (ep.addr.family == .v6) {
                _ = sys.setsockoptInt(fd, linux.IPPROTO.IPV6, linux.IPV6.V6ONLY, 1);
                _ = sys.setsockoptInt(fd, linux.IPPROTO.IPV6, 63, 1);
            } else {
                _ = sys.setsockoptInt(fd, linux.IPPROTO.IP, linux.IP.FREEBIND, 1);
            }
            var sa = sys.Sockaddr.fromEndpoint(ep);
            const r = sys.bind(fd, &sa);
            if (r < 0) return sys.errnoError(sys.toErrno(r));
            if (sys.listen(fd, 4096) < 0) return error.SystemResources;
            var bound: sys.Sockaddr = .{};
            if (sys.getsockname(fd, &bound) < 0) return error.SystemResources;
            const port = (bound.toEndpoint() orelse return error.SystemResources).port;
            try w.loop.register(fd);
            const l = &sy.listeners[index];
            l.fd = fd;
            l.c = .{ .op = .{ .accept = .{ .fd = fd, .peer = &l.peer } }, .userdata = l, .callback = onAccept };
            w.loop.submit(&l.c);
            sy.ports.add(ep.addr.family == .v6, port);
            return port;
        }

        pub fn stop(sy: *Self, w: *W) void {
            for (&sy.listeners) |*l| {
                if (l.c.isActive()) w.loop.cancel(&l.c);
            }
            for (sy.relays[0..sy.nat_table.fresh]) |*r| {
                if (r.active and !r.closing) r.close(w, true);
            }
        }

        pub fn idle(sy: *const Self) bool {
            for (&sy.listeners) |*l| {
                if (l.c.isActive()) return false;
            }
            for (sy.relays[0..sy.nat_table.fresh]) |*r| {
                if (r.active) return false;
            }
            return true;
        }

        pub fn finalize(sy: *Self, w: *W) void {
            for (&sy.listeners) |*l| {
                if (l.fd != sys.invalid_fd) {
                    w.loop.unregister(l.fd);
                    sys.close(l.fd);
                    l.fd = sys.invalid_fd;
                }
            }
        }

        pub fn handles(sy: *const Self, v6: bool) bool {
            return if (v6) sy.local6 != null else sy.local4 != null;
        }

        pub fn input(sy: *Self, w: *W, b: *pool.Buffer, vh: gso.VirtioNetHdr, pkt: parse.Packet) bool {
            const data = b.bytes();
            const v6 = pkt.ip.isV6();
            const al = pkt.ip.addrLen();
            const local: []const u8 = if (v6) (if (sy.local6) |*l| l[0..16] else return false) else (if (sy.local4) |*l| l[0..4] else return false);
            const nat_ip: []const u8 = if (v6) sy.nat6[0..16] else sy.nat4[0..4];
            const th = pkt.l4.tcp;
            const partial = vh.needsCsum();
            const now = w.now();
            if (sy.ports.contains(v6, th.src_port) and std.mem.eql(u8, pkt.ip.src(data), local)) {
                if (!std.mem.eql(u8, pkt.ip.dst(data), nat_ip)) return false;
                const owner = nat.Nat.ownerOfPort(sy.nat_table.port_base, sy.workers, th.dst_port) orelse {
                    w.pool.put(b);
                    return true;
                };
                if (owner != sy.worker_id) {
                    W.handoff(w, owner, b, vh);
                    return true;
                }
                const m = sy.nat_table.byPort(th.dst_port) orelse {
                    w.pool.put(b);
                    return true;
                };
                m.last_active = now;
                if (th.flags.fin) m.fin_server = true;
                if (th.flags.rst) m.state = .closed;
                nat.rewrite(data, pkt, .{
                    .src = m.key.dst[0..al],
                    .dst = m.key.src[0..al],
                    .src_port = m.key.dst_port,
                    .dst_port = m.key.src_port,
                }, partial);
                w.transmit(b, vh);
                return true;
            }
            const key = parse.FlowKey.fromPacket(data, pkt);
            const owner: u16 = @intCast(key.symmetricHash() % sy.workers);
            if (owner != sy.worker_id) {
                W.handoff(w, owner, b, vh);
                return true;
            }
            const m = sy.nat_table.lookup(&key) orelse blk: {
                if (!(th.flags.syn and !th.flags.ack)) return false;
                const created = sy.nat_table.create(key, now) catch return false;
                sy.relays[sy.nat_table.slotOf(created)] = .{};
                created.timer = .{ .kind = @backingInt(timeouts.Kind.nat_expire) };
                w.wheel.schedule(&created.timer, now + sy.syn_timeout_ms);
                w.counters.inc(.nat_active);
                break :blk created;
            };
            m.last_active = now;
            if (th.flags.fin) m.fin_client = true;
            if (th.flags.rst) m.state = .closed;
            nat.rewrite(data, pkt, .{
                .src = nat_ip,
                .dst = local,
                .src_port = m.port,
                .dst_port = if (v6) sy.listen_port6 else sy.listen_port4,
            }, partial);
            w.transmit(b, vh);
            return true;
        }

        fn onAccept(ud: ?*anyopaque, loop: *Loop, c: *Loop.Completion, result: i32) io.Disposition {
            _ = c;
            const l: *Listener = @ptrCast(@alignCast(ud.?));
            const w: *W = @alignCast(@fieldParentPtr("loop", loop));
            const sy = &w.system.?;
            if (result < 0) {
                return switch (sys.toErrno(result)) {
                    .canceled, .badf, .inval => .disarm,
                    else => .rearm,
                };
            }
            const fd: sys.fd_t = result;
            const peer = l.peer.toEndpoint() orelse {
                sys.close(fd);
                return .rearm;
            };
            const m = sy.nat_table.byPort(peer.port) orelse {
                sys.close(fd);
                return .rearm;
            };
            const slot = sy.nat_table.slotOf(m);
            const r = &sy.relays[slot];
            if (m.accepted or r.active) {
                sys.close(fd);
                return .rearm;
            }
            m.accepted = true;
            m.state = .established;
            r.* = .{ .active = true, .on_release = onRelayReleased };
            r.client.fd = fd;
            w.loop.register(fd) catch {};
            handler_mod.direct.tuneTcp(fd);
            const al: usize = if (m.key.v6 != 0) 16 else 4;
            const target: addr.Endpoint = .{ .addr = addr.Address.fromSlice(m.key.dst[0..al]), .port = m.key.dst_port };
            w.counters.inc(.tcp_opened);
            w.counters.inc(.tcp_active);
            w.handler.dialTcp(w, &r.dial, target, .system);
            return .rearm;
        }

        pub fn onDialDone(sy: *Self, w: *W, d: *Dial, result: sys.Errno) void {
            _ = sy;
            Relay.fromDial(d).dialDone(w, d, result);
        }

        fn onRelayReleased(w: *W, r: *Relay) void {
            const sy = &w.system.?;
            const slot: u32 = @intCast((@intFromPtr(r) - @intFromPtr(sy.relays.ptr)) / @sizeOf(Relay));
            const m = &sy.nat_table.mappings[slot];
            if (m.state != .free) {
                m.state = .closed;
                w.wheel.schedule(&m.timer, w.now() + sy.linger_ms);
            }
        }

        pub fn onTimer(sy: *Self, w: *W, t: *timeouts.Timer) void {
            const m: *nat.Mapping = @alignCast(@fieldParentPtr("timer", t));
            if (m.state == .free) return;
            const slot = sy.nat_table.slotOf(m);
            const r = &sy.relays[slot];
            const now = w.now();
            if (r.active) {
                if (now - m.last_active >= sy.idle_ms) {
                    r.close(w, true);
                } else {
                    w.wheel.schedule(&m.timer, m.last_active + sy.idle_ms);
                }
                return;
            }
            if (!m.accepted and now - m.last_active < sy.syn_timeout_ms) {
                w.wheel.schedule(&m.timer, m.last_active + sy.syn_timeout_ms);
                return;
            }
            if (m.accepted and now - m.last_active < sy.linger_ms) {
                w.wheel.schedule(&m.timer, m.last_active + sy.linger_ms);
                return;
            }
            sy.nat_table.release(m);
            w.counters.dec(.nat_active);
        }
    };
}
