const std = @import("std");
const build_options = @import("build_options");
const addr = @import("../addr.zig");
const config = @import("../config.zig");
const checksum = @import("../packet/checksum.zig");
const parse = @import("../packet/parse.zig");
const pool = @import("../packet/pool.zig");
const gso = @import("../packet/gso.zig");
const table = @import("../flow/table.zig");
const timeouts = @import("../flow/timeouts.zig");
const slab = @import("../flow/slab.zig");
const device = @import("../device/device.zig");
const io = @import("../io/io.zig");
const sys = @import("../io/sys.zig");
const ip = @import("ip.zig");
const handler_mod = @import("../handler/handler.zig");
const log = @import("../log.zig");
const elastic = @import("../elastic.zig");

pub const State = enum(u8) { closed, connecting, syn_received, established, close_wait, last_ack, fin_wait_1, fin_wait_2, closing, time_wait };

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const ECE: u8 = 0x40;
pub const CWR: u8 = 0x80;

pub inline fn seqLt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}

pub inline fn seqLe(a: u32, b: u32) bool {
    return a == b or seqLt(a, b);
}

pub inline fn seqGt(a: u32, b: u32) bool {
    return seqLt(b, a);
}

pub inline fn seqGe(a: u32, b: u32) bool {
    return seqLe(b, a);
}

pub const rx_ring_capacity = 64;
pub const rx_ceiling_max: u64 = 64 << 20;
pub const ooo_capacity = 16;
pub const max_parts = device.max_iov - 1;
pub const upstream_iov = 16;
pub const max_retries = 15;
pub const initial_rto_ms: u32 = 1000;

const RxEntry = struct {
    buf: *pool.Buffer,
    off: u32,
    len: u32,
    copy: bool,
};

const OooEntry = struct {
    seq: u32,
    buf: *pool.Buffer,
    off: u32,
    len: u32,
};

pub const RxRing = struct {
    entries: [rx_ring_capacity]RxEntry,
    tx_iov: [upstream_iov]sys.iovec_const,
    tx_msg: io.MsgHdrConst,
};

pub const OooRing = struct {
    entries: [ooo_capacity]OooEntry,
    arena: ?*pool.Buffer,
};

const cubic_c: f64 = 0.4;
const cubic_beta: f64 = 0.7;

pub fn Tcp(comptime W: type) type {
    return struct {
        const Self = @This();
        const Loop = W.Loop;
        const Dial = handler_mod.Dial(W);
        const elastic_capable = @hasDecl(W, "sendControl");

        const Move = struct {
            c: *Conn,
            to: u16,
            since: u64,
        };

        const Transfer = struct {
            key: parse.FlowKey,
            conn: Conn,
            rx: [rx_ring_capacity]RxEntry,
            ooo: [ooo_capacity]OooEntry,
            arena: ?*pool.Buffer,
            deadlines: [4]u64,
            from: u16,
            accepted: bool,
        };

        pub const Upstream = struct {
            fd: sys.fd_t = sys.invalid_fd,
            dial: Dial = .{},
            rx_c: Loop.Completion = .{},
            rx_buf: ?*pool.Buffer = null,
            tx_c: Loop.Completion = .{},
            tx_len: u32 = 0,
            connected: bool = false,
            eof: bool = false,
            shut_wr: bool = false,
            starved: bool = false,
            bulk: bool = false,
            limited: bool = false,
            write_due: bool = false,
        };

        pub const Conn = struct {
            state: State = .closed,
            v6: bool = false,
            ip_hlen: u8 = 20,
            sack_ok: bool = false,
            ts_ok: bool = false,
            ws_ok: bool = false,
            dirty: bool = false,
            need_ack: bool = false,
            ack_delayed: bool = false,
            client_fin: bool = false,
            fin_sent: bool = false,
            tx_fin: bool = false,
            rtx_pending: bool = false,
            in_recovery: bool = false,
            rtt_timing: bool = false,
            releasing: bool = false,
            free_pending: bool = false,
            synack_early: bool = false,
            migrating: bool = false,
            moved: bool = false,
            meter_epoch: u8 = 0,
            move_to: u16 = 0,
            meter: u32 = 0,
            local: [16]u8 = @splat(0),
            remote: [16]u8 = @splat(0),
            local_port: u16 = 0,
            remote_port: u16 = 0,
            ip_id: u16 = 0,
            iss: u32 = 0,
            snd_una: u32 = 0,
            snd_nxt: u32 = 0,
            snd_max: u32 = 0,
            snd_wnd: u32 = 0,
            snd_wl1: u32 = 0,
            snd_wl2: u32 = 0,
            snd_wscale: u8 = 0,
            irs: u32 = 0,
            rcv_nxt: u32 = 0,
            rcv_adv: u32 = 0,
            rcv_cap: u32 = 65536,
            snd_cap: u32 = 65536,
            rcv_wscale: u8 = 0,
            peer_mss: u16 = 536,
            mss: u16 = 536,
            retries: u8 = 0,
            dupacks: u8 = 0,
            cwnd: u32 = 0,
            ssthresh: u32 = std.math.maxInt(u32),
            recover: u32 = 0,
            bytes_acked: u32 = 0,
            srtt: u32 = 0,
            rttvar: u32 = 0,
            rto: u32 = initial_rto_ms,
            rtt_seq: u32 = 0,
            rtt_start: u64 = 0,
            ts_recent: u32 = 0,
            ts_offset: u32 = 0,
            cubic_wmax: f64 = 0,
            cubic_last_wmax: f64 = 0,
            cubic_k: f64 = 0,
            cubic_epoch: u64 = 0,
            cwnd_frac: f64 = 0,
            tx: pool.Queue = .{},
            tx_bytes: u32 = 0,
            tx_head_off: u32 = 0,
            rx: ?*RxRing = null,
            rx_head: u8 = 0,
            rx_count: u8 = 0,
            rx_bytes: u32 = 0,
            ooo: ?*OooRing = null,
            ooo_count: u8 = 0,
            ooo_bytes: u32 = 0,
            sacks: [4]parse.SackBlock = undefined,
            sack_count: u8 = 0,
            rto_timer: timeouts.Timer = .{ .kind = @intFromEnum(timeouts.Kind.tcp_rto) },
            persist_timer: timeouts.Timer = .{ .kind = @intFromEnum(timeouts.Kind.tcp_persist) },
            life_timer: timeouts.Timer = .{ .kind = @intFromEnum(timeouts.Kind.tcp_life) },
            delack_timer: timeouts.Timer = .{ .kind = @intFromEnum(timeouts.Kind.tcp_delack) },
            last_active: u64 = 0,
            target: addr.Endpoint = .{},
            next_dirty: ?*Conn = null,
            next_starved: ?*Conn = null,
            up: Upstream = .{},

            inline fn dataOffset(c: *const Conn) u32 {
                return @min(c.snd_nxt -% c.snd_una, c.tx_bytes);
            }

            inline fn flight(c: *const Conn) u32 {
                return c.snd_max -% c.snd_una;
            }

            pub inline fn synchronized(c: *const Conn) bool {
                return switch (c.state) {
                    .established, .close_wait, .last_ack, .fin_wait_1, .fin_wait_2, .closing, .time_wait => true,
                    else => false,
                };
            }

            fn fromUpstream(up: *Upstream) *Conn {
                return @alignCast(@fieldParentPtr("up", up));
            }
        };

        pub const ConnTable = table.FlowTable(Conn);

        conns: ConnTable,
        allocator: std.mem.Allocator,
        rx_rings: slab.Slab(RxRing, 32) = .{},
        ooo_rings: slab.Slab(OooRing, 64) = .{},
        dirty_head: ?*Conn = null,
        starved_head: ?*Conn = null,
        starved_tail: ?*Conn = null,
        rcv_room: u32 = std.math.maxInt(u32),
        dirty_tail: ?*Conn = null,
        moving: [elastic.move_capacity]Move = undefined,
        moving_len: u8 = 0,
        fwd: [elastic.move_capacity]*Conn = undefined,
        fwd_len: u8 = 0,
        secret: u64,
        rx_window: u32,
        rx_initial: u32,
        rx_budget: u64,
        rx_grown: u64 = 0,
        tx_budget: u64,
        tx_grown: u64 = 0,
        rx_ceiling: u64 = std.math.maxInt(u64),
        tx_buffer: u32,
        rcv_wscale: u8,
        pin_threshold: u32,
        min_rto: u32,
        max_rto: u32,
        delack_ms: u32,
        congestion: config.Congestion,

        pub fn init(allocator: std.mem.Allocator, cfg: *const config.Config, max_conns: u32, buffer_size: u32, secret: u64) !Self {
            var wscale: u8 = 0;
            while (wscale < 14 and (cfg.stack.tcp_rx_window >> @intCast(wscale)) > 65535) wscale += 1;
            return .{
                .conns = try ConnTable.init(allocator, max_conns),
                .allocator = allocator,
                .secret = secret,
                .rx_window = @max(cfg.stack.tcp_rx_window, 4096),
                .rx_initial = @min(@max(cfg.stack.tcp_rx_window, 4096), 128 * 1024),
                .rx_budget = cfg.stack.tcp_rx_budget,
                .tx_budget = cfg.stack.tcp_tx_budget,
                .tx_buffer = @max(cfg.stack.tcp_tx_buffer, 4096),
                .rcv_wscale = if (cfg.stack.tcp_window_scaling) wscale else 0,
                .pin_threshold = @max(buffer_size / 4, 512),
                .min_rto = cfg.stack.tcp_min_rto_ms,
                .max_rto = cfg.stack.tcp_max_rto_ms,
                .delack_ms = cfg.stack.tcp_delayed_ack_ms,
                .congestion = cfg.stack.tcp_congestion,
            };
        }

        pub fn deinit(t: *Self, allocator: std.mem.Allocator) void {
            t.conns.deinit(allocator);
            t.rx_rings.deinit(allocator);
            t.ooo_rings.deinit(allocator);
        }

        fn releaseRx(t: *Self, c: *Conn) void {
            if (c.rx_count != 0 or c.up.tx_c.isActive()) return;
            const ring = c.rx orelse return;
            c.rx = null;
            c.rx_head = 0;
            t.rx_rings.put(ring);
        }

        fn releaseOoo(t: *Self, w: *W, c: *Conn) void {
            if (c.ooo_count != 0) return;
            const ring = c.ooo orelse return;
            if (ring.arena) |a| w.pool.put(a);
            c.ooo = null;
            t.ooo_rings.put(ring);
        }

        fn oooStore(t: *Self, w: *W, ring: *OooRing, b: *pool.Buffer, off: u32, len: u32) ?struct { buf: *pool.Buffer, off: u32 } {
            if (len < t.pin_threshold) {
                if (ring.arena) |a| {
                    if (a.tailroom() < len) {
                        w.pool.put(a);
                        ring.arena = null;
                    }
                }
                if (ring.arena == null) ring.arena = w.pool.get();
                if (ring.arena) |a| {
                    const at = a.off + a.len;
                    @memcpy(a.ptr[at..][0..len], b.ptr[off..][0..len]);
                    a.len += len;
                    a.ref();
                    return .{ .buf = a, .off = at };
                }
            }
            b.ref();
            return .{ .buf = b, .off = off };
        }

        pub fn activeCount(t: *const Self) u32 {
            return t.conns.len;
        }

        inline fn connIndex(t: *const Self, c: *const Conn) table.Index {
            return t.conns.indexOfValue(c);
        }

        fn markDirty(t: *Self, c: *Conn) void {
            if (c.dirty) return;
            c.dirty = true;
            c.next_dirty = null;
            if (t.dirty_tail) |tail| tail.next_dirty = c else t.dirty_head = c;
            t.dirty_tail = c;
        }

        fn markStarved(t: *Self, c: *Conn) void {
            if (c.up.starved) return;
            c.up.starved = true;
            c.next_starved = null;
            if (t.starved_tail) |tail| tail.next_starved = c else t.starved_head = c;
            t.starved_tail = c;
        }

        fn dropStarved(t: *Self, c: *Conn) void {
            if (!c.up.starved) return;
            c.up.starved = false;
            var prev: ?*Conn = null;
            var cur = t.starved_head;
            while (cur) |it| : ({
                prev = it;
                cur = it.next_starved;
            }) {
                if (it != c) continue;
                if (prev) |pv| pv.next_starved = c.next_starved else t.starved_head = c.next_starved;
                if (t.starved_tail == c) t.starved_tail = prev;
                break;
            }
            c.next_starved = null;
        }

        pub fn hasStarved(t: *const Self) bool {
            return t.starved_head != null;
        }

        pub fn starvedCount(t: *const Self) u64 {
            var n: u64 = 0;
            var cur = t.starved_head;
            while (cur) |c| : (cur = c.next_starved) n += 1;
            return n;
        }

        fn wakeStarved(t: *Self, w: *W) void {
            var quota = w.pool.available() -| poolReserve(&w.pool);
            while (quota > 0) : (quota -= 1) {
                const c = t.starved_head orelse return;
                t.starved_head = c.next_starved;
                if (t.starved_head == null) t.starved_tail = null;
                c.next_starved = null;
                c.up.starved = false;
                if (c.releasing or c.moved) continue;
                t.startRead(w, c);
            }
        }

        pub fn flush(t: *Self, w: *W) void {
            t.updateRoom(w);
            if (t.starved_head != null and w.pool.available() > poolReserve(&w.pool)) t.wakeStarved(w);
            var rounds: u32 = 0;
            while (t.dirty_head != null and rounds < 4) : (rounds += 1) {
                var list = t.dirty_head;
                t.dirty_head = null;
                t.dirty_tail = null;
                while (list) |c| {
                    list = c.next_dirty;
                    c.next_dirty = null;
                    c.dirty = false;
                    if (c.moved) {
                        if (c.free_pending) {
                            c.free_pending = false;
                            t.removeForward(c);
                        }
                        continue;
                    }
                    if (c.free_pending) {
                        c.free_pending = false;
                        t.tryFree(w, c);
                        continue;
                    }
                    if (c.releasing) continue;
                    if (c.up.write_due) {
                        c.up.write_due = false;
                        t.kickWrite(w, c);
                    }
                    t.output(w, c);
                }
            }
        }

        fn iss(t: *const Self, key: *const parse.FlowKey, now_ms: u64) u32 {
            const h = key.hash() ^ t.secret;
            return @truncate(parse.mix5(h, t.secret, now_ms, 0x6a09e667f3bcc908, 0) +% (now_ms * 250));
        }

        pub fn input(t: *Self, w: *W, b: *pool.Buffer, vh: gso.VirtioNetHdr, pkt: parse.Packet) void {
            const data = b.bytes();
            const key = parse.FlowKey.fromPacket(data, pkt);
            const idx = t.conns.find(&key) orelse {
                const f = pkt.l4.tcp.flags;
                const opening = f.syn and !f.ack and !f.rst;
                if (comptime elastic_capable) {
                    if (w.elasticLive()) {
                        if (w.peerOwner(.tcp, &key) orelse if (opening) w.newFlowTarget(key.hash()) else null) |owner| {
                            w.handoff(owner, b, vh);
                            return;
                        }
                    }
                }
                if (opening) {
                    t.passiveOpen(w, b, pkt, key);
                    return;
                }
                if (!f.rst) t.sendRstFor(w, data, pkt);
                w.pool.put(b);
                return;
            };
            const c = t.conns.value(idx);
            if (c.moved) {
                if (comptime elastic_capable) {
                    w.handoff(c.move_to, b, vh);
                } else {
                    w.pool.put(b);
                }
                return;
            }
            t.conns.touch(idx);
            t.segmentArrives(w, c, b, pkt);
            w.pool.put(b);
        }

        fn passiveOpen(t: *Self, w: *W, b: *pool.Buffer, pkt: parse.Packet, key: parse.FlowKey) void {
            defer w.pool.put(b);
            const data = b.bytes();
            var bypass = false;
            if (w.judge().active()) {
                const tcph0 = pkt.l4.tcp;
                switch (w.judge().ask(parse.proto.tcp, pkt.ip.isV6(), pkt.ip.src(data), tcph0.src_port, pkt.ip.dst(data), tcph0.dst_port)) {
                    .proxy => {},
                    .direct => bypass = true,
                    .drop => return,
                    .reject => {
                        t.sendRstFor(w, data, pkt);
                        return;
                    },
                }
            }
            if (t.conns.isFull()) {
                if (t.conns.oldest()) |old| {
                    const oc = t.conns.value(old);
                    w.counters.inc(.tcp_evicted);
                    if (oc.moved) {
                        t.dropForward(oc);
                    } else if (!oc.releasing) {
                        t.abort(w, oc, true);
                    }
                }
                if (t.conns.isFull()) {
                    w.counters.inc(.tcp_connect_failed);
                    return;
                }
            }
            const idx = t.conns.insert(key, .{}) catch return;
            const c = t.conns.value(idx);
            const tcph = pkt.l4.tcp;
            const opts = parse.parseTcpOptions(data[pkt.l4_off + 20 .. pkt.payload_off]);
            const cfg = w.cfg;
            const caps = w.caps();
            const v6 = pkt.ip.isV6();
            const now = w.now();
            c.* = .{
                .state = .connecting,
                .rcv_cap = t.capFloor(caps),
                .v6 = v6,
                .ip_hlen = if (v6) 40 else 20,
                .irs = tcph.seq,
                .rcv_nxt = tcph.seq +% 1,
                .snd_wnd = tcph.window,
                .snd_wl1 = tcph.seq,
                .last_active = now,
                .sack_ok = cfg.stack.tcp_sack and opts.sack_permitted,
                .ts_ok = cfg.stack.tcp_timestamps and opts.has_timestamp,
                .ws_ok = cfg.stack.tcp_window_scaling and opts.has_wscale,
                .ts_recent = opts.ts_val,
                .ts_offset = @truncate(parse.mix5(t.secret, key.hash(), 1, 2, 3)),
            };
            const al = pkt.ip.addrLen();
            @memcpy(c.local[0..al], data[pkt.ip.dstOff()..][0..al]);
            @memcpy(c.remote[0..al], data[pkt.ip.srcOff()..][0..al]);
            c.local_port = tcph.dst_port;
            c.remote_port = tcph.src_port;
            c.target = .{ .addr = addr.Address.fromSlice(c.local[0..al]), .port = tcph.dst_port };
            c.snd_wscale = if (c.ws_ok) opts.wscale else 0;
            c.rcv_wscale = if (c.ws_ok) t.rcv_wscale else 0;
            const hdr_overhead: u32 = @as(u32, c.ip_hlen) + 20;
            const mtu_mss: u32 = if (caps.mtu > hdr_overhead) caps.mtu - hdr_overhead else 536;
            const default_peer: u16 = if (v6) 1220 else 536;
            c.peer_mss = if (opts.mss != 0) opts.mss else default_peer;
            var eff: u32 = @min(@as(u32, c.peer_mss), mtu_mss);
            if (cfg.stack.tcp_mss_clamp != 0) eff = @min(eff, cfg.stack.tcp_mss_clamp);
            if (c.ts_ok) eff -= 12;
            c.mss = @intCast(@max(eff, 88));
            c.iss = t.iss(&key, now);
            c.snd_una = c.iss;
            c.snd_nxt = c.iss;
            c.snd_max = c.iss;
            c.cwnd = @as(u32, cfg.stack.tcp_initial_cwnd) * c.mss;
            c.snd_cap = t.sndFloor(c);
            t.setSndCap(c, c.cwnd * 2);
            w.counters.inc(.tcp_opened);
            w.counters.inc(.tcp_active);
            if (cfg.earlyAccept()) {
                c.synack_early = true;
                c.state = .syn_received;
                t.sendSynAck(w, c);
            }
            c.up.dial.tos = pkt.ip.tos;
            c.up.dial.bypass = bypass;
            w.handler.dialTcp(w, &c.up.dial, c.target, .tcp);
        }

        pub fn onDialDone(t: *Self, w: *W, d: *Dial, result: sys.Errno) void {
            const up: *Upstream = @alignCast(@fieldParentPtr("dial", d));
            const c = Conn.fromUpstream(up);
            if (result == .success) {
                up.fd = d.fd;
                d.fd = sys.invalid_fd;
            }
            if (c.releasing) {
                t.tryFree(w, c);
                return;
            }
            if (result != .success) {
                w.counters.inc(.tcp_connect_failed);
                log.debug("tcp dial failed: {t}", .{result});
                t.abort(w, c, true);
                return;
            }
            up.connected = true;
            if (d.early_sent > 0) {
                w.counters.add(.upstream_tx_bytes, d.early_sent);
                t.consumeRx(w, c, d.early_sent);
                d.early_sent = 0;
            }
            const extra = d.leftover();
            if (extra.len > 0) {
                const b = w.pool.get() orelse {
                    w.counters.inc(.pool_exhausted);
                    t.abort(w, c, true);
                    return;
                };
                @memcpy(b.tail()[0..extra.len], extra);
                b.len = @intCast(extra.len);
                c.tx.push(b);
                c.tx_bytes += b.len;
                w.counters.add(.upstream_rx_bytes, b.len);
                t.markDirty(c);
            }
            if (c.state == .connecting) {
                c.state = .syn_received;
                t.sendSynAck(w, c);
            }
            t.startRead(w, c);
            if (c.rx_count > 0) t.kickWrite(w, c);
        }

        pub fn earlyData(t: *Self, d: *Dial, iovs: []sys.iovec_const) u32 {
            _ = t;
            const up: *Upstream = @alignCast(@fieldParentPtr("dial", d));
            const c = Conn.fromUpstream(up);
            if (c.releasing or c.rx_count == 0) return 0;
            const ring = c.rx.?;
            var n: usize = 0;
            var total: u32 = 0;
            while (n < iovs.len and n < c.rx_count) : (n += 1) {
                const e = ring.entries[(c.rx_head + n) % rx_ring_capacity];
                iovs[n] = .{ .base = e.buf.ptr + e.off, .len = e.len };
                total += e.len;
            }
            d.niov = @intCast(n + 1);
            return total;
        }

        pub fn streamEarly(t: *Self, d: *Dial) void {
            _ = t;
            const up: *Upstream = @alignCast(@fieldParentPtr("dial", d));
            const c = Conn.fromUpstream(up);
            if (c.releasing or !d.streaming or d.fd == sys.invalid_fd or d.early_sent >= c.rx_bytes) return;
            const ring = c.rx orelse return;
            var iov: [upstream_iov]sys.iovec_const = undefined;
            var skip = d.early_sent;
            var n: usize = 0;
            var i: usize = 0;
            while (i < c.rx_count and n < iov.len) : (i += 1) {
                const e = ring.entries[(c.rx_head + i) % rx_ring_capacity];
                if (skip >= e.len) {
                    skip -= e.len;
                    continue;
                }
                iov[n] = .{ .base = e.buf.ptr + e.off + skip, .len = e.len - skip };
                skip = 0;
                n += 1;
            }
            if (n == 0) return;
            const r = sys.sendvNow(d.fd, iov[0..n]);
            if (r > 0) d.early_sent += @intCast(r);
        }

        fn sendSynAck(t: *Self, w: *W, c: *Conn) void {
            c.snd_nxt = c.iss;
            t.sendSegment(w, c, c.iss, SYN | ACK, &.{}, 0, true);
            c.snd_nxt = c.iss +% 1;
            if (seqLt(c.snd_max, c.snd_nxt)) c.snd_max = c.snd_nxt;
            if (!c.rto_timer.active) w.wheel.schedule(&c.rto_timer, w.now() + c.rto);
        }

        fn rcvSpace(t: *const Self, c: *const Conn) u32 {
            const used = c.rx_bytes + c.ooo_bytes;
            const space = if (used >= c.rcv_cap) 0 else c.rcv_cap - used;
            return @min(space, t.rcv_room);
        }

        fn updateRoom(t: *Self, w: *W) void {
            const spare: u64 = w.pool.available() -| poolReserve(&w.pool);
            const payload: u64 = w.pool.buffer_size - w.pool.headroom;
            const room = @min(spare * payload, t.rx_ceiling);
            t.rcv_room = @intCast(@min(room / @max(t.localCount(), 1), std.math.maxInt(u32)));
        }

        fn windowField(t: *const Self, c: *Conn, syn: bool) u16 {
            var space = t.rcvSpace(c);
            if (space < c.mss and space < c.rcv_cap / 4) space = 0;
            var right = c.rcv_nxt +% space;
            if (seqLt(right, c.rcv_adv)) right = c.rcv_adv;
            const wnd = right -% c.rcv_nxt;
            const shift: u5 = if (syn) 0 else @intCast(c.rcv_wscale);
            const field: u32 = @min(wnd >> shift, 65535);
            c.rcv_adv = c.rcv_nxt +% (field << shift);
            return @intCast(field);
        }

        fn writeOptions(t: *const Self, w: *W, c: *const Conn, syn: bool, out: *[40]u8) usize {
            _ = t;
            var n: usize = 0;
            if (syn) {
                const caps = w.caps();
                const hdr_overhead: u32 = @as(u32, c.ip_hlen) + 20;
                var adv: u32 = if (caps.mtu > hdr_overhead) caps.mtu - hdr_overhead else 536;
                if (w.cfg.stack.tcp_mss_clamp != 0) adv = @min(adv, w.cfg.stack.tcp_mss_clamp);
                out[0] = 2;
                out[1] = 4;
                std.mem.writeInt(u16, out[2..4], @intCast(@min(adv, 65535)), .big);
                n = 4;
                if (c.sack_ok and c.ts_ok) {
                    out[n] = 4;
                    out[n + 1] = 2;
                    n += 2;
                } else if (c.ts_ok) {
                    out[n] = 1;
                    out[n + 1] = 1;
                    n += 2;
                } else if (c.sack_ok) {
                    @memcpy(out[n..][0..4], &[_]u8{ 1, 1, 4, 2 });
                    n += 4;
                }
                if (c.ts_ok) {
                    out[n] = 8;
                    out[n + 1] = 10;
                    std.mem.writeInt(u32, out[n + 2 ..][0..4], @as(u32, @truncate(w.now())) +% c.ts_offset, .big);
                    std.mem.writeInt(u32, out[n + 6 ..][0..4], c.ts_recent, .big);
                    n += 10;
                }
                if (c.ws_ok) {
                    @memcpy(out[n..][0..4], &[_]u8{ 1, 3, 3, c.rcv_wscale });
                    n += 4;
                }
                return n;
            }
            if (c.ts_ok) {
                @memcpy(out[0..4], &[_]u8{ 1, 1, 8, 10 });
                std.mem.writeInt(u32, out[4..8], @as(u32, @truncate(w.now())) +% c.ts_offset, .big);
                std.mem.writeInt(u32, out[8..12], c.ts_recent, .big);
                n = 12;
            }
            if (c.sack_ok and c.ooo_count > 0) {
                var blocks: [4]parse.SackBlock = undefined;
                var nb: usize = 0;
                const max_blocks: usize = if (c.ts_ok) 3 else 4;
                for (c.ooo.?.entries[0..c.ooo_count]) |e| {
                    const end = e.seq +% e.len;
                    if (nb > 0 and blocks[nb - 1].right == e.seq) {
                        blocks[nb - 1].right = end;
                    } else if (nb < max_blocks) {
                        blocks[nb] = .{ .left = e.seq, .right = end };
                        nb += 1;
                    } else break;
                }
                if (nb > 0) {
                    out[n] = 1;
                    out[n + 1] = 1;
                    out[n + 2] = 5;
                    out[n + 3] = @intCast(2 + 8 * nb);
                    n += 4;
                    for (blocks[0..nb]) |blk| {
                        std.mem.writeInt(u32, out[n..][0..4], blk.left, .big);
                        std.mem.writeInt(u32, out[n + 4 ..][0..4], blk.right, .big);
                        n += 8;
                    }
                }
            }
            return n;
        }

        fn sendSegment(t: *Self, w: *W, c: *Conn, seq: u32, flags: u8, parts: []const device.PayloadRef, payload_len: u32, syn: bool) void {
            var hdr: [device.header_capacity - gso.VirtioNetHdr.size]u8 = undefined;
            var opts: [40]u8 = undefined;
            const opt_len = t.writeOptions(w, c, syn, &opts);
            const tcp_hlen: u16 = @intCast(20 + opt_len);
            const ip_hlen: u16 = c.ip_hlen;
            const l4_len: u32 = tcp_hlen + payload_len;
            const al: usize = if (c.v6) 16 else 4;
            _ = ip.writeHeader(&hdr, c.v6, c.local[0..al], c.remote[0..al], parse.proto.tcp, l4_len, c.ip_id);
            const segs: u16 = if (payload_len > c.mss) @intCast((payload_len + c.mss - 1) / c.mss) else 1;
            c.ip_id +%= segs;
            const th = hdr[ip_hlen..];
            parse.setBe16(th, 0, c.local_port);
            parse.setBe16(th, 2, c.remote_port);
            parse.setBe32(th, 4, seq);
            parse.setBe32(th, 8, if (flags & ACK != 0) c.rcv_nxt else 0);
            th[12] = @intCast(tcp_hlen << 2);
            th[13] = flags;
            parse.setBe16(th, 14, t.windowField(c, syn));
            th[16] = 0;
            th[17] = 0;
            th[18] = 0;
            th[19] = 0;
            @memcpy(th[20..][0..opt_len], opts[0..opt_len]);
            const caps = w.caps();
            const acc = checksum.pseudo(c.v6, c.local[0..al], c.remote[0..al], parse.proto.tcp, l4_len);
            var vh: gso.VirtioNetHdr = .{};
            if (caps.vnet_hdr) {
                checksum.writeNative16(th[16..18], checksum.fold(acc));
                vh = if (payload_len > c.mss and caps.tso)
                    gso.VirtioNetHdr.tcp(c.v6, ip_hlen, tcp_hlen, c.mss, false)
                else
                    gso.VirtioNetHdr.tcpCsumOnly(ip_hlen, tcp_hlen);
            } else {
                var chunks: [max_parts + 1][]const u8 = undefined;
                chunks[0] = th[0..tcp_hlen];
                for (parts, 1..) |p, i| chunks[i] = p.buf.ptr[p.off..][0..p.len];
                const full = checksum.sumChunks(chunks[0 .. parts.len + 1], acc);
                checksum.writeNative16(th[16..18], checksum.finish(full));
            }
            if (flags & ACK != 0) {
                c.need_ack = false;
                if (c.ack_delayed) {
                    c.ack_delayed = false;
                    w.wheel.cancel(&c.delack_timer);
                }
            }
            w.transmitParts(hdr[0 .. ip_hlen + tcp_hlen], vh, parts);
        }

        fn gather(c: *const Conn, seq: u32, len: u32, parts: *[max_parts]device.PayloadRef) struct { n: usize, len: u32 } {
            var rel: u32 = seq -% c.snd_una;
            var b = c.tx.head;
            var start: u32 = c.tx_head_off;
            while (b) |buf| {
                const avail = buf.len - start;
                if (rel < avail) break;
                rel -= avail;
                b = buf.next;
                start = 0;
            }
            var n: usize = 0;
            var remaining = len;
            var pos = start + rel;
            while (b) |buf| {
                if (remaining == 0 or n == max_parts) break;
                const take = @min(buf.len - pos, remaining);
                parts[n] = .{ .buf = buf, .off = buf.off + pos, .len = take };
                n += 1;
                remaining -= take;
                b = buf.next;
                pos = 0;
            }
            return .{ .n = n, .len = len - remaining };
        }

        fn gsoLimit(c: *const Conn) u32 {
            const hdr: u32 = @as(u32, c.ip_hlen) + 60;
            const limit = pool.max_super_packet - hdr;
            return limit - (limit % c.mss);
        }

        fn output(t: *Self, w: *W, c: *Conn) void {
            if (c.migrating) {
                if (c.need_ack) t.sendSegment(w, c, c.snd_nxt, ACK, &.{}, 0, false);
                return;
            }
            switch (c.state) {
                .closed, .connecting => return,
                .syn_received => {
                    if (c.need_ack) t.sendSynAck(w, c);
                    return;
                },
                .time_wait, .fin_wait_2 => {
                    if (c.need_ack) t.sendSegment(w, c, c.snd_nxt, ACK, &.{}, 0, false);
                    return;
                },
                else => {},
            }
            const caps = w.caps();
            const gso_ok = (caps.vnet_hdr and caps.tso) or caps.jumbo_tx;
            var parts: [max_parts]device.PayloadRef = undefined;
            if (c.rtx_pending and seqLt(c.snd_una, c.snd_max) and c.snd_wnd > 0) {
                c.rtx_pending = false;
                const outstanding = @min(@min(c.snd_max -% c.snd_una, c.tx_bytes), c.snd_wnd);
                if (outstanding > 0) {
                    var len = @min(outstanding, if (gso_ok) @min(gsoLimit(c), @max(c.cwnd, c.mss)) else c.mss);
                    for (c.sacks[0..c.sack_count]) |blk| {
                        if (seqGt(blk.left, c.snd_una) and seqLt(blk.left, c.snd_una +% len)) len = blk.left -% c.snd_una;
                    }
                    const g = gather(c, c.snd_una, len, &parts);
                    if (g.len > 0) {
                        var flags: u8 = ACK;
                        if (c.fin_sent and g.len == c.tx_bytes and seqLe(c.snd_max, c.snd_una +% g.len +% 1)) flags |= FIN;
                        t.sendSegment(w, c, c.snd_una, flags, parts[0..g.n], g.len, false);
                        w.counters.inc(.tcp_retransmits);
                    }
                } else if (c.fin_sent) {
                    t.sendSegment(w, c, c.snd_una, FIN | ACK, &.{}, 0, false);
                    w.counters.inc(.tcp_retransmits);
                }
                c.rtt_timing = false;
            }
            var budget: u32 = if (gso_ok) 32 else 256;
            while (budget > 0) : (budget -= 1) {
                const data_off = c.dataOffset();
                const unsent = c.tx_bytes - data_off;
                const fl = c.snd_nxt -% c.snd_una;
                const wnd = @min(c.cwnd, c.snd_wnd);
                const can_send = if (wnd > fl) wnd - fl else 0;
                if (unsent > 0) {
                    if (can_send == 0) {
                        if (c.snd_wnd == 0 and c.flight() == 0 and !c.persist_timer.active) {
                            w.wheel.schedule(&c.persist_timer, w.now() + c.rto);
                        }
                        break;
                    }
                    var len = @min(unsent, can_send);
                    len = @min(len, if (gso_ok) gsoLimit(c) else c.mss);
                    if (len < c.mss and unsent > len and fl > 0) break;
                    const g = gather(c, c.snd_nxt, len, &parts);
                    if (g.len == 0) break;
                    var flags: u8 = ACK;
                    const last = g.len == unsent;
                    if (last) flags |= PSH;
                    const with_fin = last and c.tx_fin and (c.state == .established or c.state == .close_wait);
                    if (with_fin) flags |= FIN;
                    t.sendSegment(w, c, c.snd_nxt, flags, parts[0..g.n], g.len, false);
                    if (!c.rtt_timing) {
                        c.rtt_timing = true;
                        c.rtt_seq = c.snd_nxt +% g.len;
                        c.rtt_start = w.now();
                    }
                    c.snd_nxt +%= g.len;
                    if (with_fin) t.finSent(c);
                    if (seqLt(c.snd_max, c.snd_nxt)) c.snd_max = c.snd_nxt;
                    if (!c.rto_timer.active) w.wheel.schedule(&c.rto_timer, w.now() + c.rto);
                    continue;
                }
                if (c.tx_fin and fl == c.tx_bytes and (c.state == .established or c.state == .close_wait or c.fin_sent)) {
                    if (!c.fin_sent or seqLt(c.snd_nxt, c.snd_max)) {
                        t.sendSegment(w, c, c.snd_nxt, FIN | ACK, &.{}, 0, false);
                        t.finSent(c);
                        if (seqLt(c.snd_max, c.snd_nxt)) c.snd_max = c.snd_nxt;
                        if (!c.rto_timer.active) w.wheel.schedule(&c.rto_timer, w.now() + c.rto);
                    }
                }
                break;
            }
            if (budget == 0) t.markDirty(c);
            if (c.need_ack) t.sendSegment(w, c, c.snd_nxt, ACK, &.{}, 0, false);
        }

        fn finSent(t: *Self, c: *Conn) void {
            _ = t;
            c.snd_nxt +%= 1;
            if (!c.fin_sent) {
                c.fin_sent = true;
                c.state = switch (c.state) {
                    .established => .fin_wait_1,
                    .close_wait => .last_ack,
                    else => c.state,
                };
            }
        }

        fn segmentArrives(t: *Self, w: *W, c: *Conn, b: *pool.Buffer, pkt: parse.Packet) void {
            const data = b.bytes();
            const th = pkt.l4.tcp;
            const f = th.flags;
            const now = w.now();
            c.last_active = now;
            const payload_len: u32 = pkt.payload_len;
            switch (c.state) {
                .closed => return,
                .connecting => {
                    if (f.rst) t.abort(w, c, false);
                    return;
                },
                .syn_received => {
                    if (f.rst) {
                        if (seqGe(th.seq, c.irs)) t.abort(w, c, false);
                        return;
                    }
                    if (f.syn) {
                        if (th.seq == c.irs) {
                            c.need_ack = true;
                            t.markDirty(c);
                        }
                        return;
                    }
                    if (!f.ack) return;
                    if (th.ack != c.iss +% 1) {
                        t.sendRstFor(w, data, pkt);
                        return;
                    }
                    c.state = .established;
                    c.snd_una = th.ack;
                    c.snd_wnd = @as(u32, th.window) << @intCast(c.snd_wscale);
                    c.snd_wl1 = th.seq;
                    c.snd_wl2 = th.ack;
                    c.retries = 0;
                    w.wheel.cancel(&c.rto_timer);
                    if (!c.rtt_timing) t.rttSample(c, 0);
                    w.wheel.schedule(&c.life_timer, now + w.cfg.stack.tcp_idle_timeout_ms);
                    if (c.tx_bytes > 0 or c.tx_fin) t.markDirty(c);
                },
                else => {},
            }
            var seg_len = payload_len;
            if (f.syn) seg_len += 1;
            if (f.fin) seg_len += 1;
            const space = c.rcv_adv -% c.rcv_nxt;
            const wnd: u32 = if (seqLt(c.rcv_adv, c.rcv_nxt)) 0 else space;
            const acceptable = if (seg_len == 0)
                seqLe(th.seq, c.rcv_nxt +% wnd)
            else
                (wnd > 0 and ((seqGe(th.seq, c.rcv_nxt) and seqLt(th.seq, c.rcv_nxt +% wnd)) or (seqGe(th.seq +% seg_len -% 1, c.rcv_nxt) and seqLt(th.seq +% seg_len -% 1, c.rcv_nxt +% wnd)))) or seqLt(th.seq, c.rcv_nxt);
            if (!acceptable) {
                if (f.rst) return;
                if (f.ack and !f.syn) {
                    const late_opts = if (th.header_len > 20) parse.parseTcpOptions(data[pkt.l4_off + 20 .. pkt.payload_off]) else parse.TcpOptions{};
                    if (!t.processAck(w, c, th, late_opts, payload_len)) return;
                }
                c.need_ack = true;
                t.markDirty(c);
                return;
            }
            if (f.rst) {
                if (th.seq == c.rcv_nxt) {
                    t.abort(w, c, false);
                } else {
                    c.need_ack = true;
                    t.markDirty(c);
                }
                return;
            }
            if (f.syn) {
                c.need_ack = true;
                t.markDirty(c);
                return;
            }
            if (!f.ack) return;
            const opts = if (th.header_len > 20) parse.parseTcpOptions(data[pkt.l4_off + 20 .. pkt.payload_off]) else parse.TcpOptions{};
            if (c.ts_ok and opts.has_timestamp and seqLe(th.seq, c.rcv_nxt)) c.ts_recent = opts.ts_val;
            if (!t.processAck(w, c, th, opts, payload_len)) return;
            var off: u32 = pkt.payload_off;
            var len: u32 = payload_len;
            var seq = th.seq;
            const accepts_data = c.state == .established or c.state == .fin_wait_1 or c.state == .fin_wait_2;
            var fin = f.fin;
            if (len > 0 and accepts_data) {
                if (seqLt(seq, c.rcv_nxt)) {
                    const skip = c.rcv_nxt -% seq;
                    if (skip >= len) {
                        len = 0;
                    } else {
                        off += skip;
                        len -= skip;
                    }
                    seq = c.rcv_nxt;
                }
                const advertised: u32 = if (seqGt(c.rcv_adv, c.rcv_nxt)) c.rcv_adv -% c.rcv_nxt else 0;
                const limit = @max(t.rcvSpace(c), advertised);
                const ahead = seq -% c.rcv_nxt;
                if (len > 0 and ahead + len > limit) {
                    if (ahead >= limit) {
                        len = 0;
                    } else {
                        len = limit - ahead;
                    }
                    fin = false;
                }
                var delayable = false;
                if (len > 0) {
                    elastic.meterAdd(&c.meter, &c.meter_epoch, now, len);
                    if (seq == c.rcv_nxt) {
                        const had_gap = c.ooo_count > 0;
                        if (t.appendRx(w, c, b, b.off + off, len)) {
                            c.rcv_nxt +%= len;
                            t.pullOoo(w, c);
                            c.up.write_due = true;
                            t.markDirty(c);
                            delayable = !had_gap and len == payload_len and len < c.mss;
                        } else {
                            fin = false;
                        }
                    } else {
                        t.insertOoo(w, c, b, b.off + off, len, seq);
                        fin = false;
                    }
                }
                if (delayable and !f.fin and t.delack_ms != 0 and !c.ack_delayed) {
                    c.ack_delayed = true;
                    w.wheel.schedule(&c.delack_timer, now + t.delack_ms);
                } else {
                    c.need_ack = true;
                }
            } else if (len > 0) {
                c.need_ack = true;
            }
            if (fin) {
                const fin_seq = th.seq +% payload_len;
                if (!c.client_fin and fin_seq == c.rcv_nxt) {
                    t.clientFin(w, c);
                } else if (c.client_fin) {
                    c.need_ack = true;
                    if (c.state == .time_wait) w.wheel.schedule(&c.life_timer, now + w.cfg.stack.tcp_linger_ms);
                }
            }
            if (c.need_ack or c.tx_bytes > c.dataOffset()) t.markDirty(c);
        }

        fn clientFin(t: *Self, w: *W, c: *Conn) void {
            if (c.client_fin) {
                c.need_ack = true;
                return;
            }
            c.client_fin = true;
            c.rcv_nxt +%= 1;
            c.need_ack = true;
            switch (c.state) {
                .established => c.state = .close_wait,
                .fin_wait_1 => c.state = .closing,
                .fin_wait_2 => t.enterTimeWait(w, c),
                else => {},
            }
            t.kickWrite(w, c);
            t.markDirty(c);
        }

        fn enterTimeWait(t: *Self, w: *W, c: *Conn) void {
            _ = t;
            c.state = .time_wait;
            w.wheel.cancel(&c.rto_timer);
            w.wheel.cancel(&c.persist_timer);
            w.wheel.schedule(&c.life_timer, w.now() + w.cfg.stack.tcp_linger_ms);
        }

        fn processAck(t: *Self, w: *W, c: *Conn, th: parse.Tcp, opts: parse.TcpOptions, payload_len: u32) bool {
            const ack = th.ack;
            if (seqGt(ack, c.snd_max)) {
                c.need_ack = true;
                t.markDirty(c);
                return false;
            }
            const new_wnd = @as(u32, th.window) << @intCast(c.snd_wscale);
            const window_changed = new_wnd != c.snd_wnd;
            if (seqGe(ack, c.snd_una) and (seqGt(ack, c.snd_una) or seqLt(c.snd_wl1, th.seq) or (c.snd_wl1 == th.seq and (new_wnd > c.snd_wnd or new_wnd == 0)))) {
                c.snd_wnd = new_wnd;
                c.snd_wl1 = th.seq;
                c.snd_wl2 = ack;
                if (new_wnd > 0 and c.persist_timer.active) {
                    w.wheel.cancel(&c.persist_timer);
                    t.markDirty(c);
                }
            }
            if (c.sack_ok and opts.sack_count > 0) t.updateSacks(c, opts);
            if (seqGt(ack, c.snd_una)) {
                const acked = ack -% c.snd_una;
                const data_acked = @min(acked, c.tx_bytes);
                const fin_acked = c.fin_sent and acked > c.tx_bytes;
                if (c.ts_ok and opts.has_timestamp and opts.ts_ecr != 0) {
                    const now32: u32 = @as(u32, @truncate(w.now())) +% c.ts_offset;
                    const r = now32 -% opts.ts_ecr;
                    if (r < 60_000) t.rttSample(c, r);
                } else if (c.rtt_timing and seqGe(ack, c.rtt_seq)) {
                    c.rtt_timing = false;
                    t.rttSample(c, @intCast(@min(w.now() - c.rtt_start, 60_000)));
                }
                t.freeTx(w, c, data_acked);
                c.snd_una = ack;
                if (seqLt(c.snd_nxt, c.snd_una)) c.snd_nxt = c.snd_una;
                c.dupacks = 0;
                c.retries = 0;
                if (c.in_recovery) {
                    if (seqGe(ack, c.recover)) {
                        c.in_recovery = false;
                        c.cwnd = @max(@min(c.ssthresh, c.flight() + c.mss), 2 * @as(u32, c.mss));
                    } else {
                        c.rtx_pending = true;
                        c.cwnd = if (c.cwnd > data_acked) c.cwnd - data_acked + c.mss else c.mss;
                    }
                } else {
                    t.ccOnAck(w, c, data_acked);
                }
                if (c.snd_una == c.snd_max) {
                    w.wheel.cancel(&c.rto_timer);
                } else {
                    w.wheel.schedule(&c.rto_timer, w.now() + c.rto);
                }
                if (fin_acked) {
                    switch (c.state) {
                        .fin_wait_1 => {
                            c.state = .fin_wait_2;
                            w.wheel.schedule(&c.life_timer, w.now() + @max(w.cfg.stack.tcp_linger_ms * 15, 30_000));
                        },
                        .closing => t.enterTimeWait(w, c),
                        .last_ack => {
                            c.state = .closed;
                            t.beginRelease(w, c);
                            return false;
                        },
                        else => {},
                    }
                }
                if (c.up.connected and !c.up.eof and !c.up.rx_c.isActive()) t.startRead(w, c);
                t.markDirty(c);
            } else if (ack == c.snd_una and payload_len == 0 and !window_changed and c.snd_max != c.snd_una and !th.flags.fin) {
                c.dupacks +|= 1;
                const sacked_loss = c.sack_ok and c.sack_count > 0 and t.sackedBytes(c) >= 3 * @as(u32, c.mss);
                if (!c.in_recovery and (c.dupacks == 3 or sacked_loss)) {
                    t.ccOnLoss(w, c);
                    c.cwnd = c.ssthresh + 3 * @as(u32, c.mss);
                    c.recover = c.snd_max;
                    c.in_recovery = true;
                    c.rtx_pending = true;
                    t.markDirty(c);
                } else if (c.in_recovery) {
                    c.cwnd += c.mss;
                    t.markDirty(c);
                }
            }
            return true;
        }

        fn updateSacks(t: *Self, c: *Conn, opts: parse.TcpOptions) void {
            _ = t;
            var n: u8 = 0;
            for (opts.sack[0..opts.sack_count]) |blk| {
                if (seqLe(blk.right, c.snd_una) or seqGt(blk.right, c.snd_max) or seqGe(blk.left, blk.right)) continue;
                c.sacks[n] = blk;
                n += 1;
            }
            c.sack_count = n;
        }

        fn sackedBytes(t: *const Self, c: *const Conn) u32 {
            _ = t;
            var total: u32 = 0;
            for (c.sacks[0..c.sack_count]) |blk| {
                if (seqGt(blk.right, c.snd_una)) total +%= blk.right -% (if (seqGt(blk.left, c.snd_una)) blk.left else c.snd_una);
            }
            return total;
        }

        fn rttSample(t: *Self, c: *Conn, rtt_ms: u32) void {
            const r = @max(rtt_ms, 1);
            if (c.srtt == 0) {
                c.srtt = r << 3;
                c.rttvar = r << 1;
            } else {
                const srtt = c.srtt >> 3;
                const delta = if (srtt > r) srtt - r else r - srtt;
                c.rttvar = c.rttvar - (c.rttvar >> 2) + delta;
                c.srtt = c.srtt - (c.srtt >> 3) + r;
            }
            const rto = (c.srtt >> 3) + @max(4 * (c.rttvar >> 2), 10);
            c.rto = std.math.clamp(rto, t.min_rto, t.max_rto);
        }

        fn ccOnAck(t: *Self, w: *W, c: *Conn, acked: u32) void {
            if (acked == 0) return;
            t.setSndCap(c, @min(c.cwnd, c.snd_wnd) *| 2);
            const cap = t.tx_buffer * 2 + 64 * @as(u32, c.mss);
            if (c.cwnd < c.ssthresh) {
                c.cwnd = @min(c.cwnd +| acked, @min(c.ssthresh +| c.mss, cap));
                return;
            }
            switch (t.congestion) {
                .newreno => {
                    c.bytes_acked += acked;
                    if (c.bytes_acked >= c.cwnd) {
                        c.bytes_acked -= c.cwnd;
                        c.cwnd = @min(c.cwnd + c.mss, cap);
                    }
                },
                .cubic => {
                    const now = w.now();
                    const mss_f: f64 = @floatFromInt(c.mss);
                    const cwnd_seg: f64 = @as(f64, @floatFromInt(c.cwnd)) / mss_f;
                    if (c.cubic_epoch == 0) {
                        c.cubic_epoch = now;
                        if (c.cubic_wmax < cwnd_seg) {
                            c.cubic_k = 0;
                            c.cubic_wmax = cwnd_seg;
                        } else {
                            c.cubic_k = std.math.cbrt((c.cubic_wmax - cwnd_seg) / cubic_c);
                        }
                    }
                    const rtt_s: f64 = @as(f64, @floatFromInt(@max(c.srtt >> 3, 1))) / 1000.0;
                    const t_s: f64 = @as(f64, @floatFromInt(now - c.cubic_epoch)) / 1000.0 + rtt_s;
                    const dt = t_s - c.cubic_k;
                    const target = cubic_c * dt * dt * dt + c.cubic_wmax;
                    const w_est = c.cubic_wmax * cubic_beta + (3.0 * (1.0 - cubic_beta) / (1.0 + cubic_beta)) * (t_s / rtt_s);
                    const goal = @max(target, w_est);
                    const acked_seg = @as(f64, @floatFromInt(acked)) / mss_f;
                    var inc: f64 = 0;
                    if (goal > cwnd_seg) {
                        inc = (goal - cwnd_seg) / cwnd_seg * acked_seg;
                    } else {
                        inc = acked_seg / (100.0 * cwnd_seg);
                    }
                    c.cwnd_frac += inc * mss_f;
                    if (c.cwnd_frac >= 1.0) {
                        const whole: u32 = @intFromFloat(@min(c.cwnd_frac, 1e9));
                        c.cwnd = @min(c.cwnd +| whole, cap);
                        c.cwnd_frac -= @floatFromInt(whole);
                    }
                },
            }
        }

        fn ccOnLoss(t: *Self, w: *W, c: *Conn) void {
            _ = w;
            const fl = c.flight();
            switch (t.congestion) {
                .newreno => c.ssthresh = @max(fl / 2, 2 * @as(u32, c.mss)),
                .cubic => {
                    const cwnd_seg = @as(f64, @floatFromInt(c.cwnd)) / @as(f64, @floatFromInt(c.mss));
                    if (cwnd_seg < c.cubic_last_wmax) {
                        c.cubic_last_wmax = cwnd_seg;
                        c.cubic_wmax = cwnd_seg * (1.0 + cubic_beta) / 2.0;
                    } else {
                        c.cubic_last_wmax = cwnd_seg;
                        c.cubic_wmax = cwnd_seg;
                    }
                    c.cubic_epoch = 0;
                    const reduced: u32 = @intFromFloat(@as(f64, @floatFromInt(c.cwnd)) * cubic_beta);
                    c.ssthresh = @max(reduced, 2 * @as(u32, c.mss));
                },
            }
            c.bytes_acked = 0;
        }

        fn freeTx(t: *Self, w: *W, c: *Conn, n: u32) void {
            _ = t;
            var remaining = n;
            while (remaining > 0) {
                const head = c.tx.peek() orelse break;
                const avail = head.len - c.tx_head_off;
                if (remaining >= avail) {
                    remaining -= avail;
                    _ = c.tx.pop();
                    w.pool.put(head);
                    c.tx_head_off = 0;
                } else {
                    c.tx_head_off += remaining;
                    remaining = 0;
                }
            }
            c.tx_bytes -= n - remaining;
        }

        fn appendRx(t: *Self, w: *W, c: *Conn, b: *pool.Buffer, off: u32, len: u32) bool {
            if (c.rx_count > 0) {
                const tail = &c.rx.?.entries[(c.rx_head + c.rx_count - 1) % rx_ring_capacity];
                if (tail.copy and tail.off + tail.len + len <= tail.buf.cap) {
                    @memcpy(tail.buf.ptr[tail.off + tail.len ..][0..len], b.ptr[off..][0..len]);
                    tail.len += len;
                    c.rx_bytes += len;
                    return true;
                }
            }
            if (c.rx_count == rx_ring_capacity) return false;
            const ring = c.rx orelse blk: {
                const r = t.rx_rings.take(t.allocator) orelse {
                    w.counters.inc(.pool_exhausted);
                    return false;
                };
                c.rx = r;
                c.rx_head = 0;
                break :blk r;
            };
            const slot = &ring.entries[(c.rx_head + c.rx_count) % rx_ring_capacity];
            if (len >= t.pin_threshold) {
                b.ref();
                slot.* = .{ .buf = b, .off = off, .len = len, .copy = false };
            } else {
                const nb = w.pool.get() orelse {
                    t.releaseRx(c);
                    return false;
                };
                @memcpy(nb.ptr[nb.headroom()..][0..len], b.ptr[off..][0..len]);
                slot.* = .{ .buf = nb, .off = nb.headroom(), .len = len, .copy = true };
            }
            c.rx_count += 1;
            c.rx_bytes += len;
            return true;
        }

        fn insertOoo(t: *Self, w: *W, c: *Conn, b: *pool.Buffer, off: u32, len: u32, seq: u32) void {
            if (c.ooo_bytes + len > t.rx_window) return;
            var s = seq;
            var o = off;
            var l = len;
            const ring = c.ooo orelse blk: {
                const r = t.ooo_rings.take(t.allocator) orelse return;
                r.arena = null;
                c.ooo = r;
                break :blk r;
            };
            defer t.releaseOoo(w, c);
            var pos: usize = 0;
            while (pos < c.ooo_count and seqLt(ring.entries[pos].seq, s)) : (pos += 1) {}
            if (pos > 0) {
                const prev = ring.entries[pos - 1];
                const prev_end = prev.seq +% prev.len;
                if (seqGe(prev_end, s +% l)) return;
                if (seqGt(prev_end, s)) {
                    const cut = prev_end -% s;
                    s +%= cut;
                    o += cut;
                    l -= cut;
                }
            }
            if (pos < c.ooo_count) {
                const next = ring.entries[pos];
                if (seqGe(s, next.seq)) return;
                if (seqGt(s +% l, next.seq)) l = next.seq -% s;
            }
            if (l == 0 or c.ooo_count == ooo_capacity) return;
            var i: usize = c.ooo_count;
            const stored = t.oooStore(w, ring, b, o, l) orelse return;
            while (i > pos) : (i -= 1) ring.entries[i] = ring.entries[i - 1];
            ring.entries[pos] = .{ .seq = s, .buf = stored.buf, .off = stored.off, .len = l };
            c.ooo_count += 1;
            c.ooo_bytes += l;
        }

        fn pullOoo(t: *Self, w: *W, c: *Conn) void {
            const ring = c.ooo orelse return;
            defer t.releaseOoo(w, c);
            while (c.ooo_count > 0 and seqLe(ring.entries[0].seq, c.rcv_nxt)) {
                const e = ring.entries[0];
                var i: usize = 1;
                while (i < c.ooo_count) : (i += 1) ring.entries[i - 1] = ring.entries[i];
                c.ooo_count -= 1;
                c.ooo_bytes -= e.len;
                const end = e.seq +% e.len;
                if (seqGt(end, c.rcv_nxt)) {
                    const skip = c.rcv_nxt -% e.seq;
                    if (t.appendRx(w, c, e.buf, e.off + skip, e.len - skip)) c.rcv_nxt = end;
                }
                w.pool.put(e.buf);
            }
        }

        fn consumeRx(t: *Self, w: *W, c: *Conn, n: u32) void {
            const before = t.rcvSpace(c);
            var remaining = n;
            while (remaining > 0 and c.rx_count > 0) {
                const e = &c.rx.?.entries[c.rx_head];
                if (e.len <= remaining) {
                    remaining -= e.len;
                    w.pool.put(e.buf);
                    c.rx_head = (c.rx_head + 1) % rx_ring_capacity;
                    c.rx_count -= 1;
                } else {
                    e.off += remaining;
                    e.len -= remaining;
                    remaining = 0;
                }
            }
            c.rx_bytes -= n - remaining;
            t.releaseRx(c);
            const after = t.rcvSpace(c);
            const adv_space = c.rcv_adv -% c.rcv_nxt;
            if (after > before and (before < c.mss or after -| adv_space >= @min(c.rcv_cap / 2, 2 * @as(u32, c.mss)))) {
                c.need_ack = true;
                t.markDirty(c);
            }
        }

        fn poolReserve(p: *const pool.Pool) u32 {
            return @max(p.capacity() / 8, 8);
        }

        fn startRead(t: *Self, w: *W, c: *Conn) void {
            const up = &c.up;
            if (!up.connected or up.eof or c.releasing or c.migrating or up.rx_c.isActive() or up.fd == sys.invalid_fd) return;
            if (c.tx_bytes >= c.snd_cap) return;
            const space = c.snd_cap - c.tx_bytes;
            if (space < 1024 and c.tx_bytes > 0) return;
            if (!up.bulk and up.rx_buf == null) {
                up.rx_c = .{
                    .op = .{ .poll = .{ .fd = up.fd, .events = .{ .in = true } } },
                    .userdata = up,
                    .callback = onUpstreamReadable,
                };
                w.loop.submit(&up.rx_c);
                return;
            }
            const b = t.readBuffer(w, c) orelse return;
            up.rx_c = .{
                .op = .{ .recv = .{ .fd = up.fd, .buf = b.ptr[b.headroom()..][0..@min(b.cap - b.headroom(), space)] } },
                .userdata = up,
                .callback = onUpstreamRecv,
            };
            w.loop.submit(&up.rx_c);
        }

        fn readBuffer(t: *Self, w: *W, c: *Conn) ?*pool.Buffer {
            const up = &c.up;
            if (up.rx_buf) |b| return b;
            const b = if (w.pool.available() > poolReserve(&w.pool)) w.pool.get() else null;
            up.rx_buf = b orelse {
                t.markStarved(c);
                w.counters.inc(.pool_exhausted);
                return null;
            };
            return b;
        }

        fn onUpstreamReadable(ud: ?*anyopaque, loop: *Loop, comp: *Loop.Completion, result: i32) io.Disposition {
            _ = comp;
            const up: *Upstream = @ptrCast(@alignCast(ud.?));
            const c = Conn.fromUpstream(up);
            const w: *W = @alignCast(@fieldParentPtr("loop", loop));
            const t = &w.tcp;
            if (c.releasing) {
                t.tryFree(w, c);
                return .disarm;
            }
            if (c.migrating) return .disarm;
            if (result < 0) {
                t.upstreamData(w, c, result);
                return .disarm;
            }
            if (c.tx_bytes >= c.snd_cap) return .disarm;
            const b = t.readBuffer(w, c) orelse return .disarm;
            const n = w.recvNow(up.fd, b.ptr[b.headroom()..][0..@min(b.cap - b.headroom(), c.snd_cap - c.tx_bytes)]);
            t.upstreamData(w, c, n);
            return .disarm;
        }

        fn onUpstreamRecv(ud: ?*anyopaque, loop: *Loop, comp: *Loop.Completion, result: i32) io.Disposition {
            _ = comp;
            const up: *Upstream = @ptrCast(@alignCast(ud.?));
            const c = Conn.fromUpstream(up);
            const w: *W = @alignCast(@fieldParentPtr("loop", loop));
            const t = &w.tcp;
            if (c.releasing) {
                if (up.rx_buf) |b| w.pool.put(b);
                up.rx_buf = null;
                t.tryFree(w, c);
                return .disarm;
            }
            if (c.migrating and result < 0 and sys.toErrno(result) == .canceled) {
                if (up.rx_buf) |b| w.pool.put(b);
                up.rx_buf = null;
                return .disarm;
            }
            t.upstreamData(w, c, result);
            return .disarm;
        }

        fn upstreamData(t: *Self, w: *W, c: *Conn, result: i32) void {
            const up = &c.up;
            if (result > 0) {
                const b = up.rx_buf.?;
                const n: u32 = @intCast(result);
                up.bulk = n >= (b.cap - b.headroom()) / 2;
                w.counters.add(.upstream_rx_bytes, n);
                elastic.meterAdd(&c.meter, &c.meter_epoch, w.now(), n);
                c.tx_bytes += n;
                const merged = if (c.tx.tail) |tail| n <= b.cap / 4 and tail.tailroom() >= n else false;
                if (merged) {
                    const tail = c.tx.tail.?;
                    @memcpy(tail.tail()[0..n], b.ptr[b.headroom()..][0..n]);
                    tail.len += n;
                    if (!up.bulk) {
                        up.rx_buf = null;
                        w.pool.put(b);
                    }
                } else {
                    up.rx_buf = null;
                    b.off = b.headroom();
                    b.len = n;
                    c.tx.push(b);
                }
                if (c.synchronized()) t.markDirty(c);
                t.startRead(w, c);
                return;
            }
            if (result == 0) {
                up.eof = true;
                if (up.rx_buf) |b| w.pool.put(b);
                up.rx_buf = null;
                c.tx_fin = true;
                if (c.state == .connecting) {
                    t.abort(w, c, true);
                } else if (c.synchronized()) {
                    t.markDirty(c);
                }
                return;
            }
            const e = sys.toErrno(result);
            if (e == .again or e == .intr) {
                if (!up.bulk) {
                    if (up.rx_buf) |b| w.pool.put(b);
                    up.rx_buf = null;
                }
                t.startRead(w, c);
                return;
            }
            if (up.rx_buf) |b| w.pool.put(b);
            up.rx_buf = null;
            t.abort(w, c, true);
        }

        fn capFloor(t: *const Self, caps: device.Capabilities) u32 {
            _ = caps;
            return t.rx_initial;
        }

        fn sndFloor(t: *const Self, c: *const Conn) u32 {
            return @min(t.tx_buffer, @max(4096, 2 * @as(u32, c.mss)));
        }

        fn sndShare(t: *const Self, floor: u32) u32 {
            const live: u64 = @max(t.localCount(), 1);
            return @max(floor, @as(u32, @intCast(@min(t.tx_budget / live, t.tx_buffer))));
        }

        fn setSndCap(t: *Self, c: *Conn, want: u32) void {
            const floor = t.sndFloor(c);
            const cap = std.math.clamp(want, floor, t.sndShare(floor));
            const old_extra: u64 = c.snd_cap -| floor;
            const new_extra: u64 = cap -| floor;
            if (new_extra > old_extra and t.tx_grown + (new_extra - old_extra) > t.tx_budget) return;
            t.tx_grown = t.tx_grown - old_extra + new_extra;
            c.snd_cap = cap;
        }

        fn releaseSndCap(t: *Self, c: *Conn) void {
            t.tx_grown -|= c.snd_cap -| t.sndFloor(c);
            c.snd_cap = t.sndFloor(c);
        }

        fn setRcvCap(t: *Self, w: *W, c: *Conn, want: u32) void {
            const floor = t.capFloor(w.caps());
            const cap = @max(want, floor);
            const old_extra: u64 = c.rcv_cap -| floor;
            const new_extra: u64 = cap -| floor;
            if (new_extra > old_extra and t.rx_grown + (new_extra - old_extra) > t.rx_budget) return;
            t.rx_grown = t.rx_grown - old_extra + new_extra;
            c.rcv_cap = cap;
        }

        fn kickWrite(t: *Self, w: *W, c: *Conn) void {
            const up = &c.up;
            if (!up.connected) {
                if (up.dial.streaming and !c.releasing) t.streamEarly(&up.dial);
                return;
            }
            if (c.releasing or c.migrating or up.tx_c.isActive() or up.fd == sys.invalid_fd) return;
            if (c.rx_count == 0) {
                if (c.client_fin and !up.shut_wr) {
                    up.shut_wr = true;
                    _ = sys.shutdown(up.fd, .write);
                }
                return;
            }
            const ring = c.rx.?;
            var n: usize = 0;
            var total: u32 = 0;
            while (n < upstream_iov and n < c.rx_count) : (n += 1) {
                const e = ring.entries[(c.rx_head + n) % rx_ring_capacity];
                ring.tx_iov[n] = .{ .base = e.buf.ptr + e.off, .len = e.len };
                total += e.len;
            }
            up.tx_len = total;
            up.limited = t.rcvSpace(c) < @max(c.rcv_cap / 4, c.mss);
            if (sys.is_windows) {
                up.tx_c = .{ .op = .{ .writev = .{ .fd = up.fd, .iov = ring.tx_iov[0..n] } }, .userdata = up, .callback = onUpstreamSend };
            } else {
                ring.tx_msg = std.mem.zeroes(io.MsgHdrConst);
                ring.tx_msg.iov = @ptrCast(&ring.tx_iov);
                ring.tx_msg.iovlen = @intCast(n);
                up.tx_c = .{ .op = .{ .sendmsg = .{ .fd = up.fd, .msg = &ring.tx_msg } }, .userdata = up, .callback = onUpstreamSend };
            }
            w.loop.submit(&up.tx_c);
        }

        fn onUpstreamSend(ud: ?*anyopaque, loop: *Loop, comp: *Loop.Completion, result: i32) io.Disposition {
            _ = comp;
            const up: *Upstream = @ptrCast(@alignCast(ud.?));
            const c = Conn.fromUpstream(up);
            const w: *W = @alignCast(@fieldParentPtr("loop", loop));
            const t = &w.tcp;
            if (c.releasing) {
                t.tryFree(w, c);
                return .disarm;
            }
            if (result >= 0) {
                const n: u32 = @intCast(result);
                w.counters.add(.upstream_tx_bytes, n);
                if (n < up.tx_len) {
                    t.consumeRx(w, c, n);
                    t.setRcvCap(w, c, c.rcv_cap / 2);
                } else {
                    t.consumeRx(w, c, n);
                    if (up.limited and c.rx_count == 0 and c.rcv_cap < t.rx_window) {
                        t.setRcvCap(w, c, @min(c.rcv_cap * 2, t.rx_window));
                    }
                }
                t.kickWrite(w, c);
                return .disarm;
            }
            const e = sys.toErrno(result);
            if (e == .again or e == .intr or (e == .canceled and c.migrating)) {
                t.kickWrite(w, c);
                return .disarm;
            }
            t.abort(w, c, true);
            return .disarm;
        }

        pub fn onTimer(t: *Self, w: *W, timer: *timeouts.Timer) void {
            switch (@as(timeouts.Kind, @enumFromInt(timer.kind))) {
                .tcp_rto => t.onRto(w, @alignCast(@fieldParentPtr("rto_timer", timer))),
                .tcp_persist => t.onPersist(w, @alignCast(@fieldParentPtr("persist_timer", timer))),
                .tcp_life => t.onLife(w, @alignCast(@fieldParentPtr("life_timer", timer))),
                .tcp_delack => {
                    const c: *Conn = @alignCast(@fieldParentPtr("delack_timer", timer));
                    if (c.releasing or !c.ack_delayed) return;
                    c.ack_delayed = false;
                    c.need_ack = true;
                    t.markDirty(c);
                },
                else => {},
            }
        }

        fn onRto(t: *Self, w: *W, c: *Conn) void {
            if (c.releasing) return;
            if (c.state == .syn_received) {
                c.retries += 1;
                if (c.retries > 5) return t.abort(w, c, true);
                c.rto = @min(c.rto * 2, t.max_rto);
                t.sendSynAck(w, c);
                return;
            }
            if (c.snd_una == c.snd_max) return;
            if (c.snd_wnd == 0) {
                if (!c.persist_timer.active) w.wheel.schedule(&c.persist_timer, w.now() + c.rto);
                w.wheel.schedule(&c.rto_timer, w.now() + @min(c.rto * 2, t.max_rto));
                return;
            }
            c.retries += 1;
            w.counters.inc(.timeouts);
            if (c.retries > max_retries) return t.abort(w, c, true);
            t.ccOnLoss(w, c);
            c.cwnd = c.mss;
            c.in_recovery = false;
            c.dupacks = 0;
            c.sack_count = 0;
            c.snd_nxt = c.snd_una;
            c.rtx_pending = true;
            c.rtt_timing = false;
            c.rto = @min(c.rto * 2, t.max_rto);
            w.wheel.schedule(&c.rto_timer, w.now() + c.rto);
            t.markDirty(c);
        }

        fn onPersist(t: *Self, w: *W, c: *Conn) void {
            if (c.releasing or c.snd_wnd != 0) return;
            if (c.tx_bytes > c.dataOffset() or c.snd_una != c.snd_max) {
                t.sendSegment(w, c, c.snd_una -% 1, ACK, &.{}, 0, false);
            }
            w.wheel.schedule(&c.persist_timer, w.now() + @min(c.rto * 2, t.max_rto));
        }

        fn onLife(t: *Self, w: *W, c: *Conn) void {
            if (c.releasing) return;
            switch (c.state) {
                .time_wait => {
                    c.state = .closed;
                    t.beginRelease(w, c);
                },
                .fin_wait_2 => t.abort(w, c, true),
                else => {
                    const idle = w.cfg.stack.tcp_idle_timeout_ms;
                    const now = w.now();
                    if (now - c.last_active >= idle) {
                        t.abort(w, c, true);
                    } else {
                        w.wheel.schedule(&c.life_timer, c.last_active + idle);
                    }
                },
            }
        }

        pub fn abort(t: *Self, w: *W, c: *Conn, send_rst: bool) void {
            if (c.releasing) return;
            if (send_rst and c.state != .closed) {
                const flags: u8 = RST | ACK;
                const seq = if (c.state == .connecting) 0 else c.snd_nxt;
                t.sendSegment(w, c, seq, flags, &.{}, 0, false);
                w.counters.inc(.tcp_reset);
            }
            c.state = .closed;
            t.beginRelease(w, c);
        }

        fn beginRelease(t: *Self, w: *W, c: *Conn) void {
            if (c.releasing) return;
            c.releasing = true;
            c.state = .closed;
            w.wheel.cancel(&c.rto_timer);
            w.wheel.cancel(&c.persist_timer);
            w.wheel.cancel(&c.life_timer);
            w.wheel.cancel(&c.delack_timer);
            const up = &c.up;
            if (up.dial.busy()) w.handler.abortDial(w, &up.dial);
            if (up.rx_c.isActive()) w.loop.cancel(&up.rx_c);
            if (up.tx_c.isActive()) w.loop.cancel(&up.tx_c);
            t.tryFree(w, c);
        }

        fn tryFree(t: *Self, w: *W, c: *Conn) void {
            if (!c.releasing) return;
            if (c.dirty) {
                c.free_pending = true;
                return;
            }
            const up = &c.up;
            if (up.dial.busy() or up.dial.completionActive() or up.rx_c.isActive() or up.tx_c.isActive()) return;
            if (up.fd != sys.invalid_fd) {
                w.loop.unregister(up.fd);
                sys.close(up.fd);
                up.fd = sys.invalid_fd;
            }
            if (up.rx_buf) |b| w.pool.put(b);
            up.rx_buf = null;
            while (c.rx_count > 0) {
                w.pool.put(c.rx.?.entries[c.rx_head].buf);
                c.rx_head = (c.rx_head + 1) % rx_ring_capacity;
                c.rx_count -= 1;
            }
            t.releaseRx(c);
            if (c.ooo) |ring| {
                for (ring.entries[0..c.ooo_count]) |e| w.pool.put(e.buf);
            }
            c.ooo_count = 0;
            t.releaseOoo(w, c);
            c.tx.releaseAll(&w.pool);
            c.tx_bytes = 0;
            t.dropStarved(c);
            t.rx_grown -|= c.rcv_cap -| t.capFloor(w.caps());
            c.rcv_cap = t.capFloor(w.caps());
            t.releaseSndCap(c);
            w.counters.dec(.tcp_active);
            w.counters.inc(.tcp_closed);
            t.conns.remove(t.connIndex(c));
        }

        pub fn sendRstFor(t: *Self, w: *W, data: []const u8, pkt: parse.Packet) void {
            _ = t;
            const th = pkt.l4.tcp;
            if (th.flags.rst) return;
            const v6 = pkt.ip.isV6();
            const al = pkt.ip.addrLen();
            var hdr: [80]u8 = undefined;
            const ip_hlen = ip.writeHeader(&hdr, v6, pkt.ip.dst(data), pkt.ip.src(data), parse.proto.tcp, 20, 0);
            const t_ = hdr[ip_hlen..];
            parse.setBe16(t_, 0, th.dst_port);
            parse.setBe16(t_, 2, th.src_port);
            var seg_len: u32 = pkt.payload_len;
            if (th.flags.syn) seg_len += 1;
            if (th.flags.fin) seg_len += 1;
            if (th.flags.ack) {
                parse.setBe32(t_, 4, th.ack);
                parse.setBe32(t_, 8, 0);
                t_[13] = RST;
            } else {
                parse.setBe32(t_, 4, 0);
                parse.setBe32(t_, 8, th.seq +% seg_len);
                t_[13] = RST | ACK;
            }
            t_[12] = 0x50;
            parse.setBe16(t_, 14, 0);
            t_[16] = 0;
            t_[17] = 0;
            t_[18] = 0;
            t_[19] = 0;
            const acc = checksum.pseudo(v6, hdr[if (v6) 8 else 12..][0..al], hdr[if (v6) 24 else 16..][0..al], parse.proto.tcp, 20);
            checksum.writeNative16(t_[16..18], checksum.finish(checksum.sum(t_[0..20], acc)));
            w.counters.inc(.tcp_reset);
            w.transmitParts(hdr[0 .. ip_hlen + 20], .{}, &.{});
        }

        pub fn shutdownAll(t: *Self, w: *W) void {
            var it = t.conns.iterator();
            while (it.next()) |i| {
                const c = t.conns.value(i);
                if (c.moved) {
                    t.dropForward(c);
                } else if (!c.releasing) {
                    t.abort(w, c, true);
                }
            }
        }

        pub fn fitBudgets(t: *Self, p: *const pool.Pool) void {
            const usable: u64 = @as(u64, p.capacity() -| p.reserve) * (p.buffer_size - p.headroom);
            t.tx_budget = @min(t.tx_budget, usable / 2);
            t.rx_budget = @min(t.rx_budget, usable / 4);
            t.rx_ceiling = @min(usable / 2, rx_ceiling_max);
        }

        pub fn localCount(t: *const Self) u32 {
            return t.conns.len - t.fwd_len;
        }

        fn movable(c: *const Conn) bool {
            if (c.releasing or c.moved or c.migrating) return false;
            if (c.state != .established and c.state != .close_wait) return false;
            const up = &c.up;
            return up.connected and up.fd != sys.invalid_fd and !up.dial.busy() and !up.dial.completionActive();
        }

        pub fn migrateOut(t: *Self, w: *W, c: *Conn, to: u16) bool {
            if (!movable(c)) return false;
            if (@as(usize, t.moving_len) + t.fwd_len >= elastic.move_capacity) return false;
            if (w.pool.buffer_size < @sizeOf(Transfer) + 16) return false;
            c.migrating = true;
            const up = &c.up;
            if (up.rx_c.isActive()) w.loop.cancel(&up.rx_c);
            if (up.tx_c.isActive()) w.loop.cancel(&up.tx_c);
            t.moving[t.moving_len] = .{ .c = c, .to = to, .since = w.now() };
            t.moving_len += 1;
            return true;
        }

        fn resumeConn(t: *Self, w: *W, c: *Conn) void {
            c.migrating = false;
            if (c.releasing) return;
            t.startRead(w, c);
            t.kickWrite(w, c);
            t.markDirty(c);
        }

        fn refsWithin(c: *const Conn, target: *const pool.Buffer) u32 {
            var n: u32 = 0;
            if (c.rx) |ring| {
                var i: usize = 0;
                while (i < c.rx_count) : (i += 1) {
                    if (ring.entries[(c.rx_head + i) % rx_ring_capacity].buf == target) n += 1;
                }
            }
            if (c.ooo) |ring| {
                for (ring.entries[0..c.ooo_count]) |e| {
                    if (e.buf == target) n += 1;
                }
                if (ring.arena == target) n += 1;
            }
            var b = c.tx.head;
            while (b) |buf| : (b = buf.next) {
                if (buf == target) n += 1;
            }
            return n;
        }

        fn exclusive(c: *const Conn) bool {
            var b = c.tx.head;
            while (b) |buf| : (b = buf.next) {
                if (buf.refs != refsWithin(c, buf)) return false;
            }
            if (c.rx) |ring| {
                var i: usize = 0;
                while (i < c.rx_count) : (i += 1) {
                    const e = ring.entries[(c.rx_head + i) % rx_ring_capacity];
                    if (e.buf.refs != refsWithin(c, e.buf)) return false;
                }
            }
            if (c.ooo) |ring| {
                for (ring.entries[0..c.ooo_count]) |e| {
                    if (e.buf.refs != refsWithin(c, e.buf)) return false;
                }
                if (ring.arena) |a| {
                    if (a.refs != refsWithin(c, a)) return false;
                }
            }
            return true;
        }

        pub fn progressMigrations(t: *Self, w: *W) void {
            const now = w.now();
            var i: usize = 0;
            while (i < t.moving_len) {
                const m = t.moving[i];
                const c = m.c;
                var done = true;
                if (c.releasing or !c.migrating or c.moved) {
                    c.migrating = false;
                } else if (!c.up.rx_c.isActive() and !c.up.tx_c.isActive() and exclusive(c)) {
                    if (!t.transfer(w, c, m.to)) t.resumeConn(w, c);
                } else if (now -| m.since > 1000) {
                    t.resumeConn(w, c);
                } else {
                    done = false;
                }
                if (done) {
                    t.moving_len -= 1;
                    t.moving[i] = t.moving[t.moving_len];
                } else {
                    i += 1;
                }
            }
        }

        fn timerList(c: *Conn) [4]*timeouts.Timer {
            return .{ &c.rto_timer, &c.persist_timer, &c.life_timer, &c.delack_timer };
        }

        fn resetTimers(c: *Conn) void {
            c.rto_timer = .{ .kind = @intFromEnum(timeouts.Kind.tcp_rto) };
            c.persist_timer = .{ .kind = @intFromEnum(timeouts.Kind.tcp_persist) };
            c.life_timer = .{ .kind = @intFromEnum(timeouts.Kind.tcp_life) };
            c.delack_timer = .{ .kind = @intFromEnum(timeouts.Kind.tcp_delack) };
        }

        fn transfer(t: *Self, w: *W, c: *Conn, to: u16) bool {
            if (comptime !elastic_capable) return false;
            const b = w.pool.get() orelse return false;
            const rec = elastic.record(Transfer, b) orelse {
                w.pool.put(b);
                return false;
            };
            const up = &c.up;
            if (up.rx_buf) |rb| w.pool.put(rb);
            up.rx_buf = null;
            rec.key = t.conns.entry(t.connIndex(c)).key;
            rec.conn = c.*;
            rec.from = w.id;
            rec.accepted = false;
            rec.arena = null;
            if (c.rx) |ring| {
                var i: usize = 0;
                while (i < c.rx_count) : (i += 1) rec.rx[i] = ring.entries[(c.rx_head + i) % rx_ring_capacity];
                c.rx = null;
                c.rx_head = 0;
                t.rx_rings.put(ring);
            }
            if (c.ooo) |ring| {
                @memcpy(rec.ooo[0..c.ooo_count], ring.entries[0..c.ooo_count]);
                rec.arena = ring.arena;
                ring.arena = null;
                c.ooo = null;
                t.ooo_rings.put(ring);
            }
            for (timerList(c), 0..) |tm, i| {
                rec.deadlines[i] = if (tm.active) @max(tm.deadline, 1) else 0;
                w.wheel.cancel(tm);
            }
            w.loop.unregister(up.fd);
            up.fd = sys.invalid_fd;
            c.rx_count = 0;
            c.rx_bytes = 0;
            c.ooo_count = 0;
            c.ooo_bytes = 0;
            c.tx = .{};
            c.tx_bytes = 0;
            c.tx_head_off = 0;
            c.ack_delayed = false;
            t.dropStarved(c);
            t.rx_grown -|= c.rcv_cap -| t.capFloor(w.caps());
            t.tx_grown -|= c.snd_cap -| t.sndFloor(c);
            c.migrating = false;
            c.moved = true;
            c.move_to = to;
            c.last_active = w.now();
            t.fwd[t.fwd_len] = c;
            t.fwd_len += 1;
            w.counters.dec(.tcp_active);
            w.counters.inc(.tcp_migrated);
            w.sendControl(to, b, .tcp_transfer);
            return true;
        }

        pub fn install(t: *Self, w: *W, b: *pool.Buffer) void {
            if (comptime !elastic_capable) return w.pool.put(b);
            const rec = elastic.record(Transfer, b).?;
            rec.accepted = t.adopt(w, rec);
            if (!rec.accepted) t.discardRecord(w, rec, true);
            w.sendControl(rec.from, b, .tcp_ack);
        }

        fn adopt(t: *Self, w: *W, rec: *Transfer) bool {
            if (w.engine.state.load(.acquire) != .running or t.conns.isFull()) return false;
            const rx_ring: ?*RxRing = if (rec.conn.rx_count > 0) (t.rx_rings.take(t.allocator) orelse return false) else null;
            const ooo_ring: ?*OooRing = if (rec.conn.ooo_count > 0 or rec.arena != null) (t.ooo_rings.take(t.allocator) orelse {
                if (rx_ring) |r| t.rx_rings.put(r);
                return false;
            }) else null;
            const idx = t.conns.insert(rec.key, .{}) catch {
                if (rx_ring) |r| t.rx_rings.put(r);
                if (ooo_ring) |r| t.ooo_rings.put(r);
                return false;
            };
            const c = t.conns.value(idx);
            c.* = rec.conn;
            c.dirty = false;
            c.next_dirty = null;
            c.next_starved = null;
            c.up.starved = false;
            c.free_pending = false;
            c.migrating = false;
            c.moved = false;
            resetTimers(c);
            c.up.rx_c = .{};
            c.up.tx_c = .{};
            c.up.rx_buf = null;
            c.rx = rx_ring;
            c.rx_head = 0;
            if (rx_ring) |r| @memcpy(r.entries[0..rec.conn.rx_count], rec.rx[0..rec.conn.rx_count]);
            c.ooo = ooo_ring;
            if (ooo_ring) |r| {
                @memcpy(r.entries[0..rec.conn.ooo_count], rec.ooo[0..rec.conn.ooo_count]);
                r.arena = rec.arena;
            }
            const now = w.now();
            for (timerList(c), rec.deadlines) |tm, d| {
                if (d != 0) w.wheel.schedule(tm, @max(d, now + 1));
            }
            w.loop.register(c.up.fd) catch {};
            t.rx_grown += c.rcv_cap -| t.capFloor(w.caps());
            t.tx_grown += c.snd_cap -| t.sndFloor(c);
            w.counters.inc(.tcp_active);
            t.markDirty(c);
            t.startRead(w, c);
            if (c.rx_count > 0) t.kickWrite(w, c);
            return true;
        }

        fn discardRecord(t: *Self, w: *W, rec: *Transfer, reset: bool) void {
            const c = &rec.conn;
            const rx_count = c.rx_count;
            const ooo_count = c.ooo_count;
            resetTimers(c);
            c.ack_delayed = false;
            c.rx = null;
            c.ooo = null;
            c.rx_count = 0;
            c.ooo_count = 0;
            if (reset) {
                t.sendSegment(w, c, c.snd_nxt, RST | ACK, &.{}, 0, false);
                w.counters.inc(.tcp_reset);
            }
            if (c.up.fd != sys.invalid_fd) sys.close(c.up.fd);
            c.up.fd = sys.invalid_fd;
            for (rec.rx[0..rx_count]) |e| w.pool.put(e.buf);
            for (rec.ooo[0..ooo_count]) |e| w.pool.put(e.buf);
            if (rec.arena) |a| w.pool.put(a);
            rec.arena = null;
            c.tx.releaseAll(&w.pool);
        }

        pub fn dropRecord(t: *Self, w: *W, b: *pool.Buffer) void {
            const rec = elastic.record(Transfer, b).?;
            t.discardRecord(w, rec, false);
            w.pool.put(b);
        }

        pub fn onTransferAck(t: *Self, w: *W, b: *pool.Buffer) void {
            const rec = elastic.record(Transfer, b).?;
            if (t.conns.find(&rec.key)) |idx| {
                const c = t.conns.value(idx);
                if (c.moved) t.dropForward(c);
            }
            w.pool.put(b);
        }

        fn dropForward(t: *Self, c: *Conn) void {
            if (c.dirty) {
                c.free_pending = true;
                return;
            }
            t.removeForward(c);
        }

        fn removeForward(t: *Self, c: *Conn) void {
            var i: usize = 0;
            while (i < t.fwd_len) : (i += 1) {
                if (t.fwd[i] == c) {
                    t.fwd_len -= 1;
                    t.fwd[i] = t.fwd[t.fwd_len];
                    break;
                }
            }
            c.moved = false;
            c.state = .closed;
            t.conns.remove(t.connIndex(c));
        }

        pub fn expireForwards(t: *Self, w: *W, now: u64) void {
            _ = w;
            var i: usize = t.fwd_len;
            while (i > 0) {
                i -= 1;
                const c = t.fwd[i];
                if (now -| c.last_active >= elastic.forward_ttl_ms and !c.free_pending) t.dropForward(c);
            }
        }

        pub fn donate(t: *Self, w: *W, to: u16, fraction: u32, by_count: bool) void {
            const Cand = struct { c: *Conn, weight: u64 };
            var cand: [elastic.move_capacity]Cand = undefined;
            var n: usize = 0;
            var total: u64 = 0;
            const now = w.now();
            var it = t.conns.iterator();
            while (it.next()) |i| {
                const c = t.conns.value(i);
                if (!movable(c)) continue;
                const weight: u64 = if (by_count) 1 else elastic.meterRecent(c.meter, c.meter_epoch, now);
                if (weight == 0) continue;
                total += weight;
                if (n < cand.len) {
                    cand[n] = .{ .c = c, .weight = weight };
                    n += 1;
                    continue;
                }
                var low: usize = 0;
                for (cand[1..], 1..) |x, j| {
                    if (x.weight < cand[low].weight) low = j;
                }
                if (weight > cand[low].weight) cand[low] = .{ .c = c, .weight = weight };
            }
            if (total == 0) return;
            std.sort.insertion(Cand, cand[0..n], {}, struct {
                fn heavier(_: void, a: Cand, b: Cand) bool {
                    return a.weight > b.weight;
                }
            }.heavier);
            var goal = if (by_count) (total * fraction + 999) / 1000 else total * fraction / 1000;
            for (cand[0..n]) |x| {
                if (goal == 0) break;
                if (!by_count and x.weight > goal + goal / 2) continue;
                if (t.migrateOut(w, x.c, to)) goal -|= x.weight;
            }
        }

        pub fn drainOut(t: *Self, w: *W) void {
            if (comptime !elastic_capable) return;
            var it = t.conns.iterator();
            while (it.next()) |i| {
                if (@as(usize, t.moving_len) + t.fwd_len >= elastic.move_capacity) return;
                const c = t.conns.value(i);
                if (!movable(c)) continue;
                const target = w.newFlowTarget(t.conns.entry(i).key.hash()) orelse return;
                _ = t.migrateOut(w, c, target);
            }
        }
    };
}
