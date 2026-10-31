const std = @import("std");
const config = @import("../config.zig");
const addr = @import("../addr.zig");
const stats = @import("../stats.zig");
const io = @import("../io/io.zig");
const sys = @import("../io/sys.zig");
const pool = @import("../packet/pool.zig");
const gso = @import("../packet/gso.zig");
const parse = @import("../packet/parse.zig");
const checksum = @import("../packet/checksum.zig");
const timeouts = @import("../flow/timeouts.zig");
const device = @import("../device/device.zig");
const tcp_mod = @import("../stack/tcp.zig");
const handler_mod = @import("../handler/handler.zig");
const verdict = @import("../flow/verdict.zig");
const helpers = @import("helpers.zig");

const seqLt = tcp_mod.seqLt;
const seqLe = tcp_mod.seqLe;
const seqGt = tcp_mod.seqGt;
const seqGe = tcp_mod.seqGe;

fn pattern(offset: u64) u8 {
    const x = offset *% 0x9e37_79b9_7f4a_7c15;
    return @truncate((x >> 29) ^ (offset >> 11) ^ 0x5a);
}

const SimLoop = struct {
    pub const completion_based = true;
    pub const Callback = *const fn (userdata: ?*anyopaque, loop: *SimLoop, c: *Completion, result: i32) io.Disposition;

    pub inline fn completionBased(_: *const SimLoop) bool {
        return completion_based;
    }

    pub const Completion = struct {
        op: io.Operation = .none,
        userdata: ?*anyopaque = null,
        callback: Callback = noopCallback,
        state: io.State = .idle,
        next: ?*Completion = null,

        pub inline fn isActive(c: *const Completion) bool {
            return c.state != .idle;
        }
    };

    allocator: std.mem.Allocator,
    pending: std.ArrayList(*Completion) = .empty,

    pub fn submit(l: *SimLoop, c: *Completion) void {
        std.debug.assert(c.state == .idle);
        c.state = .active;
        l.pending.append(l.allocator, c) catch @panic("simulated loop out of memory");
    }

    pub fn cancel(l: *SimLoop, c: *Completion) void {
        _ = l;
        if (c.state == .active) c.state = .canceling;
    }

    pub fn register(l: *SimLoop, fd: sys.fd_t) !void {
        _ = l;
        _ = fd;
    }

    pub fn unregister(l: *SimLoop, fd: sys.fd_t) void {
        _ = l;
        _ = fd;
    }

    fn finish(l: *SimLoop, index: usize, result: i32) void {
        const c = l.pending.orderedRemove(index);
        c.state = .idle;
        if (c.callback(c.userdata, l, c, result) == .rearm and c.state == .idle) l.submit(c);
    }
};

fn noopCallback(_: ?*anyopaque, _: *SimLoop, _: *SimLoop.Completion, _: i32) io.Disposition {
    return .disarm;
}

const SimHandler = struct {
    const PendingDial = struct { dial: *SimWorker.Dial, at: u64 };

    allocator: std.mem.Allocator,
    dials: std.ArrayList(PendingDial) = .empty,
    delay_ms: u64 = 0,
    refuse_pct: u8 = 0,

    pub fn dialTcp(hd: *SimHandler, w: *SimWorker, d: *SimWorker.Dial, target: addr.Endpoint, owner: handler_mod.Owner) void {
        d.owner = owner;
        d.target = target;
        d.aborted = false;
        d.timed_out = false;
        d.fd = sys.invalid_fd;
        d.phase = .connecting;
        hd.dials.append(hd.allocator, .{ .dial = d, .at = w.clock + hd.delay_ms }) catch @panic("simulated handler out of memory");
    }

    pub fn abortDial(hd: *SimHandler, w: *SimWorker, d: *SimWorker.Dial) void {
        _ = hd;
        _ = w;
        if (!d.busy()) return;
        d.aborted = true;
    }
};

const SimWorker = struct {
    pub const Loop = SimLoop;
    pub const Dial = handler_mod.Dial(SimWorker);
    pub const Tcp = tcp_mod.Tcp(SimWorker);

    allocator: std.mem.Allocator,
    loop: SimLoop,
    pool: pool.Pool,
    wheel: timeouts.Wheel,
    counters_storage: stats.Counters,
    counters: *stats.Counters,
    cfg: *const config.Config,
    tcp: Tcp,
    handler: SimHandler,
    clock: u64,
    sim: *Sim,

    pub inline fn now(w: *const SimWorker) u64 {
        return w.clock;
    }

    pub inline fn caps(w: *const SimWorker) device.Capabilities {
        return w.sim.caps;
    }

    pub inline fn judge(w: *const SimWorker) *const verdict.Judge {
        return &w.sim.judge;
    }

    pub fn transmitParts(w: *SimWorker, header: []const u8, vh: gso.VirtioNetHdr, parts: []const device.PayloadRef) void {
        w.sim.captureOutput(header, vh, parts);
    }

    pub fn recvNow(w: *SimWorker, fd: sys.fd_t, buf: []u8) i32 {
        return w.sim.recvNow(fd, buf);
    }

    fn onTimer(w: *SimWorker, t: *timeouts.Timer) void {
        switch (@as(timeouts.Kind, @fromBackingInt(@intCast(t.kind)))) {
            .tcp_rto, .tcp_persist, .tcp_life, .tcp_delack => w.tcp.onTimer(w, t),
            else => {},
        }
    }
};

const Packet = struct {
    at: u64,
    data: []u8,
};

const Link = struct {
    queue: std.ArrayList(Packet) = .empty,
    loss_pct: u8 = 0,
    dup_pct: u8 = 0,
    delay_ms: u32 = 0,
    jitter_ms: u32 = 0,

    fn send(l: *Link, allocator: std.mem.Allocator, rng: std.Random, now: u64, bytes: []const u8) !void {
        if (l.loss_pct > 0 and rng.uintLessThan(u8, 100) < l.loss_pct) return;
        const copies: usize = if (l.dup_pct > 0 and rng.uintLessThan(u8, 100) < l.dup_pct) 2 else 1;
        for (0..copies) |_| {
            const extra: u32 = if (l.jitter_ms > 0) rng.uintAtMost(u32, l.jitter_ms) else 0;
            const data = try allocator.dupe(u8, bytes);
            errdefer allocator.free(data);
            try l.queue.append(allocator, .{ .at = now + l.delay_ms + extra, .data = data });
        }
    }

    fn popDue(l: *Link, now: u64) ?Packet {
        for (l.queue.items, 0..) |p, i| {
            if (p.at <= now) return l.queue.orderedRemove(i);
        }
        return null;
    }

    fn deinit(l: *Link, allocator: std.mem.Allocator) void {
        for (l.queue.items) |p| allocator.free(p.data);
        l.queue.deinit(allocator);
    }

    fn calm(l: *Link) void {
        l.loss_pct = 0;
        l.dup_pct = 0;
        l.jitter_ms = 0;
    }
};

const Server = struct {
    fd: sys.fd_t = sys.invalid_fd,
    received: u64 = 0,
    unread: u64 = 0,
    echo_ready: u64 = 0,
    echoed: u64 = 0,
    cap: u64 = 1 << 20,
    rate: u64 = 1 << 20,
    chunk: u32 = 65536,
    eof_seen: bool = false,
    closed: bool = false,

    fn tick(s: *Server, dt: u64) void {
        const n = @min(s.unread, s.rate *| @max(dt, 1));
        s.unread -= n;
        s.echo_ready += n;
        if (s.eof_seen and s.unread == 0 and s.echoed == s.echo_ready) s.closed = true;
    }

    fn onSend(s: *Server, iov: anytype) !?i32 {
        var total: u64 = 0;
        for (iov) |v| total += v.len;
        if (total == 0) return 0;
        const room = if (s.cap > s.unread) s.cap - s.unread else 0;
        const accept = @min(total, room, @as(u64, std.math.maxInt(i32)));
        if (accept == 0) return null;
        var left = accept;
        for (iov) |v| {
            if (left == 0) break;
            const take = @min(left, v.len);
            for (v.base[0..take]) |byte| {
                if (byte != pattern(s.received)) return error.UpstreamCorruption;
                s.received += 1;
            }
            left -= take;
        }
        s.unread += accept;
        return @intCast(accept);
    }

    fn readable(s: *const Server) ?i32 {
        if (s.echo_ready > s.echoed or s.closed) return @bitCast(@as(u32, @bitCast(io.Events{ .in = true })));
        return null;
    }

    fn onRecv(s: *Server, buf: []u8) ?i32 {
        const avail = s.echo_ready - s.echoed;
        if (avail > 0) {
            const n: usize = @intCast(@min(avail, buf.len, s.chunk));
            for (buf[0..n], 0..) |*b, i| b.* = pattern(s.echoed + i);
            s.echoed += n;
            return @intCast(n);
        }
        if (s.closed) return 0;
        return null;
    }
};

const Range = struct { left: u32, right: u32 };

const Client = struct {
    const iss: u32 = 1000;
    const base_rto: u64 = 250;
    const State = enum { closed, syn_sent, established };

    ep: addr.Endpoint,
    server: addr.Endpoint,
    mss: u32,
    offer_sack: bool,
    offer_ts: bool,
    offer_ws: bool,
    ws_shift: u8,
    byte_probes: bool,
    total: u32,
    recv_cap: u32,
    read_rate: u32,
    ack_every: u8,

    state: State = .closed,
    snd_una: u32 = iss,
    snd_nxt: u32 = iss,
    snd_max: u32 = iss,
    peer_wnd: u32 = 0,
    peer_ws: u8 = 0,
    eff_mss: u32 = 536,
    sack_ok: bool = false,
    ts_ok: bool = false,
    ws_ok: bool = false,
    cwnd: u32 = 0,
    ssthresh: u32 = std.math.maxInt(u32),
    dupacks: u8 = 0,
    rto: u64 = base_rto,
    rto_at: ?u64 = null,
    persist_at: ?u64 = null,
    fin_sent: bool = false,
    irs: u32 = 0,
    rcv_nxt: u32 = 0,
    delivered: u64 = 0,
    unread: u32 = 0,
    ooo: [16]Range = undefined,
    ooo_count: u8 = 0,
    right_edge: u32 = 0,
    syn_window: u32 = 0,
    got_fin: bool = false,
    ts_recent: u32 = 0,
    unacked_segs: u8 = 0,
    ack_due: bool = false,
    delack_at: ?u64 = null,
    resets: u32 = 0,
    buf: [70000]u8 = undefined,

    fn dataEnd(cl: *const Client) u32 {
        return iss +% 1 +% cl.total;
    }

    fn finAcked(cl: *const Client) bool {
        return cl.fin_sent and seqGt(cl.snd_una, cl.dataEnd());
    }

    fn oooBytes(cl: *const Client) u32 {
        var n: u32 = 0;
        for (cl.ooo[0..cl.ooo_count]) |r| n += r.right -% r.left;
        return n;
    }

    fn windowField(cl: *Client) u16 {
        const used = cl.unread + cl.oooBytes();
        var wnd: u32 = if (cl.recv_cap > used) cl.recv_cap - used else 0;
        if (cl.state == .established and seqLt(cl.rcv_nxt +% wnd, cl.right_edge)) wnd = cl.right_edge -% cl.rcv_nxt;
        const shift: u5 = if (cl.ws_ok) @intCast(cl.ws_shift) else 0;
        const field: u32 = @min(wnd >> shift, 65535);
        if (cl.state == .established) {
            const edge = cl.rcv_nxt +% (field << shift);
            if (seqGt(edge, cl.right_edge)) cl.right_edge = edge;
        }
        return @intCast(field);
    }

    fn options(cl: *Client, sim: *Sim, syn: bool, out: *[40]u8) []const u8 {
        var n: usize = 0;
        if (syn) {
            out[0] = 2;
            out[1] = 4;
            std.mem.writeInt(u16, out[2..4], @intCast(cl.mss), .big);
            n = 4;
            if (cl.offer_sack) {
                out[n] = 4;
                out[n + 1] = 2;
                n += 2;
            }
            if (cl.offer_ws) {
                out[n] = 3;
                out[n + 1] = 3;
                out[n + 2] = cl.ws_shift;
                n += 3;
            }
            if (cl.offer_ts) {
                out[n] = 8;
                out[n + 1] = 10;
                std.mem.writeInt(u32, out[n + 2 ..][0..4], @truncate(sim.w.clock), .big);
                std.mem.writeInt(u32, out[n + 6 ..][0..4], 0, .big);
                n += 10;
            }
            return out[0..n];
        }
        if (cl.ts_ok) {
            out[0] = 8;
            out[1] = 10;
            std.mem.writeInt(u32, out[2..6], @truncate(sim.w.clock), .big);
            std.mem.writeInt(u32, out[6..10], cl.ts_recent, .big);
            n = 10;
        }
        if (cl.sack_ok and cl.ooo_count > 0) {
            const room: usize = (40 - n - 2) / 8;
            const blocks: usize = @min(@as(usize, cl.ooo_count), room, @as(usize, 3));
            out[n] = 5;
            out[n + 1] = @intCast(2 + 8 * blocks);
            n += 2;
            for (cl.ooo[0..blocks]) |r| {
                std.mem.writeInt(u32, out[n..][0..4], r.left, .big);
                std.mem.writeInt(u32, out[n + 4 ..][0..4], r.right, .big);
                n += 8;
            }
        }
        return out[0..n];
    }

    fn emit(cl: *Client, sim: *Sim, seq: u32, flags: u8, payload: []const u8) !void {
        var opts: [40]u8 = undefined;
        const syn = flags & tcp_mod.SYN != 0;
        const o = cl.options(sim, syn, &opts);
        const window = cl.windowField();
        if (syn) cl.syn_window = window;
        const ack: u32 = if (flags & tcp_mod.ACK != 0) cl.rcv_nxt else 0;
        const pkt = helpers.buildTcp4(&cl.buf, cl.ep, cl.server, .{ .seq = seq, .ack = ack, .flags = flags, .window = window, .options = o, .payload = payload });
        sim.tracePacket("client>", pkt);
        try sim.to_engine.send(sim.allocator, sim.rng.random(), sim.w.clock, pkt);
        if (flags & tcp_mod.ACK != 0) {
            cl.ack_due = false;
            cl.unacked_segs = 0;
            cl.delack_at = null;
        }
    }

    fn sendData(cl: *Client, sim: *Sim) !void {
        var budget: u32 = 96;
        const end = cl.dataEnd();
        while (budget > 0) : (budget -= 1) {
            const limit = cl.snd_una +% @min(cl.peer_wnd, cl.cwnd);
            if (seqLt(cl.snd_nxt, end)) {
                if (!seqLt(cl.snd_nxt, limit)) break;
                const len = @min(cl.eff_mss, end -% cl.snd_nxt, limit -% cl.snd_nxt, 60000);
                var payload: [60000]u8 = undefined;
                const off: u64 = cl.snd_nxt -% (iss +% 1);
                for (payload[0..len], 0..) |*b, i| b.* = pattern(off + i);
                try cl.emit(sim, cl.snd_nxt, tcp_mod.ACK | tcp_mod.PSH, payload[0..len]);
                cl.snd_nxt +%= len;
                if (seqGt(cl.snd_nxt, cl.snd_max)) cl.snd_max = cl.snd_nxt;
                if (cl.rto_at == null) cl.rto_at = sim.w.clock + cl.rto;
                continue;
            }
            if (cl.snd_nxt == end and (!cl.fin_sent or seqLe(cl.snd_una, end))) {
                try cl.emit(sim, end, tcp_mod.ACK | tcp_mod.FIN, &.{});
                cl.fin_sent = true;
                cl.snd_nxt = end +% 1;
                if (seqGt(cl.snd_nxt, cl.snd_max)) cl.snd_max = cl.snd_nxt;
                if (cl.rto_at == null) cl.rto_at = sim.w.clock + cl.rto;
            }
            break;
        }
    }

    fn tick(cl: *Client, sim: *Sim, dt: u64) !void {
        const now = sim.w.clock;
        switch (cl.state) {
            .closed => {
                try cl.emit(sim, iss, tcp_mod.SYN, &.{});
                cl.state = .syn_sent;
                cl.snd_nxt = iss +% 1;
                cl.snd_max = cl.snd_nxt;
                cl.rto_at = now + cl.rto;
                return;
            },
            .syn_sent => {
                if (cl.rto_at) |at| {
                    if (now >= at) {
                        try cl.emit(sim, iss, tcp_mod.SYN, &.{});
                        cl.rto = @min(cl.rto * 2, 4000);
                        cl.rto_at = now + cl.rto;
                    }
                }
                return;
            },
            .established => {},
        }
        if (cl.unread > 0) {
            const before = cl.recv_cap -| (cl.unread + cl.oooBytes());
            const n: u32 = @intCast(@min(@as(u64, cl.unread), @as(u64, cl.read_rate) *| @max(dt, 1)));
            cl.unread -= n;
            const after = cl.recv_cap -| (cl.unread + cl.oooBytes());
            if (n > 0 and ((before < cl.eff_mss and after >= cl.eff_mss) or after - before >= 2 * cl.eff_mss)) cl.ack_due = true;
        }
        if (cl.rto_at) |at| {
            if (now >= at) {
                if (cl.snd_una != cl.snd_max) {
                    if (cl.peer_wnd > 0) {
                        const flight = cl.snd_max -% cl.snd_una;
                        cl.ssthresh = @max(flight / 2, 2 * cl.eff_mss);
                        cl.cwnd = cl.eff_mss;
                        cl.snd_nxt = cl.snd_una;
                        cl.dupacks = 0;
                    } else if (cl.byte_probes) {
                        cl.snd_nxt = cl.snd_una;
                    } else {
                        try cl.emit(sim, cl.snd_una -% 1, tcp_mod.ACK, &.{});
                    }
                    cl.rto = @min(cl.rto * 2, 4000);
                    cl.rto_at = now + cl.rto;
                } else {
                    cl.rto_at = null;
                }
            }
        }
        const has_unsent = seqLt(cl.snd_nxt, cl.dataEnd()) or (cl.snd_nxt == cl.dataEnd() and !cl.fin_sent);
        if (cl.peer_wnd == 0 and has_unsent and cl.snd_una == cl.snd_max) {
            if (cl.persist_at) |at| {
                if (now >= at) {
                    if (cl.byte_probes and seqLt(cl.snd_nxt, cl.dataEnd())) {
                        const off: u64 = cl.snd_nxt -% (iss +% 1);
                        const one = [1]u8{pattern(off)};
                        try cl.emit(sim, cl.snd_nxt, tcp_mod.ACK, &one);
                        cl.snd_nxt +%= 1;
                        cl.snd_max = cl.snd_nxt;
                        if (cl.rto_at == null) cl.rto_at = now + cl.rto;
                    } else {
                        try cl.emit(sim, cl.snd_una -% 1, tcp_mod.ACK, &.{});
                    }
                    cl.persist_at = now + cl.rto;
                }
            } else {
                cl.persist_at = now + cl.rto;
            }
        } else {
            cl.persist_at = null;
        }
        try cl.sendData(sim);
        if (cl.delack_at) |at| {
            if (now >= at) cl.ack_due = true;
        }
        if (cl.ack_due) try cl.emit(sim, cl.snd_nxt, tcp_mod.ACK, &.{});
    }

    fn insertOoo(cl: *Client, left: u32, right: u32) void {
        var l = left;
        var r = right;
        var i: usize = 0;
        while (i < cl.ooo_count) {
            const e = cl.ooo[i];
            if (seqLe(l, e.right) and seqGe(r, e.left)) {
                if (seqLt(e.left, l)) l = e.left;
                if (seqGt(e.right, r)) r = e.right;
                var k = i;
                while (k + 1 < cl.ooo_count) : (k += 1) cl.ooo[k] = cl.ooo[k + 1];
                cl.ooo_count -= 1;
                continue;
            }
            i += 1;
        }
        if (cl.ooo_count == cl.ooo.len) return;
        var pos: usize = 0;
        while (pos < cl.ooo_count and seqLt(cl.ooo[pos].left, l)) pos += 1;
        var k: usize = cl.ooo_count;
        while (k > pos) : (k -= 1) cl.ooo[k] = cl.ooo[k - 1];
        cl.ooo[pos] = .{ .left = l, .right = r };
        cl.ooo_count += 1;
    }

    fn advance(cl: *Client, to: u32) void {
        const n = to -% cl.rcv_nxt;
        cl.rcv_nxt = to;
        cl.unread += n;
        cl.delivered += n;
        while (cl.ooo_count > 0 and seqLe(cl.ooo[0].left, cl.rcv_nxt)) {
            const e = cl.ooo[0];
            var k: usize = 0;
            while (k + 1 < cl.ooo_count) : (k += 1) cl.ooo[k] = cl.ooo[k + 1];
            cl.ooo_count -= 1;
            if (seqGt(e.right, cl.rcv_nxt)) {
                const more = e.right -% cl.rcv_nxt;
                cl.rcv_nxt = e.right;
                cl.unread += more;
                cl.delivered += more;
            }
        }
    }

    fn onPacket(cl: *Client, sim: *Sim, data: []u8) !void {
        const p = parse.parse(data) catch return error.EngineEmittedMalformedPacket;
        if (p.l4 != .tcp) return error.EngineEmittedNonTcp;
        if (!checksum.verifyIpv4Header(data[0..20])) return error.EngineBadIpChecksum;
        if (!parse.l4ChecksumValid(data, p)) return error.EngineBadTcpChecksum;
        const th = p.l4.tcp;
        if (th.dst_port != cl.ep.port or th.src_port != cl.server.port) return error.EngineWrongPorts;
        const opts = if (th.header_len > 20) parse.parseTcpOptions(data[p.l4_off + 20 .. p.payload_off]) else parse.TcpOptions{};
        const payload = data[p.payload_off..][0..p.payload_len];
        if (th.flags.rst) {
            if (!(cl.got_fin and cl.finAcked())) cl.resets += 1;
            return;
        }
        if (cl.state == .syn_sent) {
            if (!(th.flags.syn and th.flags.ack)) return;
            if (th.ack != iss +% 1) return error.EngineBadSynAck;
            cl.irs = th.seq;
            cl.rcv_nxt = th.seq +% 1;
            cl.snd_una = iss +% 1;
            cl.sack_ok = cl.offer_sack and opts.sack_permitted;
            cl.ts_ok = cl.offer_ts and opts.has_timestamp;
            cl.ws_ok = cl.offer_ws and opts.has_wscale;
            cl.peer_ws = if (cl.ws_ok) opts.wscale else 0;
            cl.peer_wnd = th.window;
            const peer_mss: u32 = if (opts.mss != 0) opts.mss else 536;
            cl.eff_mss = @max(@min(cl.mss, peer_mss) -| (if (cl.ts_ok) @as(u32, 12) else 0), 64);
            cl.cwnd = 10 * cl.eff_mss;
            if (cl.ts_ok) cl.ts_recent = opts.ts_val;
            cl.state = .established;
            cl.rto = base_rto;
            cl.rto_at = null;
            cl.right_edge = cl.rcv_nxt +% cl.syn_window;
            cl.ack_due = true;
            return;
        }
        if (cl.state != .established) return;
        if (th.flags.syn) {
            cl.ack_due = true;
            return;
        }
        if (th.flags.ack) {
            if (seqGt(th.ack, cl.snd_max)) return error.EngineAckedUnsentData;
            const new_wnd = @as(u32, th.window) << @intCast(cl.peer_ws);
            if (seqGt(th.ack, cl.snd_una)) {
                const acked = th.ack -% cl.snd_una;
                cl.snd_una = th.ack;
                if (seqLt(cl.snd_nxt, cl.snd_una)) cl.snd_nxt = cl.snd_una;
                cl.dupacks = 0;
                if (cl.cwnd < cl.ssthresh) {
                    cl.cwnd +|= @min(acked, cl.eff_mss);
                } else {
                    cl.cwnd +|= @max(cl.eff_mss * cl.eff_mss / @max(cl.cwnd, 1), 1);
                }
                cl.cwnd = @min(cl.cwnd, 8 << 20);
                cl.rto = base_rto;
                cl.rto_at = if (cl.snd_una == cl.snd_max) null else sim.w.clock + cl.rto;
            } else if (th.ack == cl.snd_una and payload.len == 0 and !th.flags.fin and new_wnd == cl.peer_wnd and cl.snd_una != cl.snd_max) {
                cl.dupacks += 1;
                if (cl.dupacks == 3) {
                    const flight = cl.snd_max -% cl.snd_una;
                    cl.ssthresh = @max(flight / 2, 2 * cl.eff_mss);
                    cl.cwnd = cl.ssthresh;
                    cl.snd_nxt = cl.snd_una;
                }
            }
            cl.peer_wnd = new_wnd;
        }
        if (cl.ts_ok and opts.has_timestamp) cl.ts_recent = opts.ts_val;
        if (payload.len > 0) {
            const base_off: u32 = th.seq -% (cl.irs +% 1);
            for (payload, 0..) |b, i| {
                if (b != pattern(@as(u64, base_off) + i)) return error.EchoCorruption;
            }
            const seg_end = th.seq +% @as(u32, @intCast(payload.len));
            if (seqGt(seg_end, cl.right_edge) and seqGt(seg_end, cl.rcv_nxt +% 1)) return error.EngineExceededReceiveWindow;
            if (seqLe(th.seq, cl.rcv_nxt)) {
                if (seqGt(seg_end, cl.rcv_nxt)) cl.advance(seg_end);
            } else {
                cl.insertOoo(th.seq, seg_end);
                cl.ack_due = true;
            }
            cl.unacked_segs += 1;
            if (cl.unacked_segs >= cl.ack_every or cl.ooo_count > 0) {
                cl.ack_due = true;
            } else if (cl.delack_at == null) {
                cl.delack_at = sim.w.clock + 40;
            }
        }
        if (th.flags.fin) {
            const fin_seq = th.seq +% @as(u32, @intCast(payload.len));
            if (!cl.got_fin and fin_seq == cl.rcv_nxt) {
                cl.got_fin = true;
                cl.rcv_nxt +%= 1;
            }
            cl.ack_due = true;
        }
    }
};

const Chooser = union(enum) {
    smith: *std.testing.Smith,
    prng: *std.Random.DefaultPrng,

    fn hashOf(src: std.lang.SourceLocation) u32 {
        return (@as(u32, src.line) *% 0x9e37_79b1) ^ src.column;
    }

    fn range(ch: Chooser, comptime T: type, lo: T, hi: T, src: std.lang.SourceLocation) T {
        return switch (ch) {
            .smith => |s| s.valueRangeAtMostWithHash(T, lo, hi, hashOf(src)),
            .prng => |p| p.random().intRangeAtMost(T, lo, hi),
        };
    }

    fn flag(ch: Chooser, src: std.lang.SourceLocation) bool {
        return switch (ch) {
            .smith => |s| s.valueWithHash(bool, hashOf(src)),
            .prng => |p| p.random().boolean(),
        };
    }

    fn full(ch: Chooser, comptime T: type, src: std.lang.SourceLocation) T {
        return switch (ch) {
            .smith => |s| s.valueWithHash(T, hashOf(src)),
            .prng => |p| p.random().int(T),
        };
    }

    fn stop(ch: Chooser, src: std.lang.SourceLocation) bool {
        return switch (ch) {
            .smith => |s| s.eosWithHash(hashOf(src)),
            .prng => |p| p.random().uintLessThan(u32, 2500) == 0,
        };
    }
};

const Mode = enum { reliable, chaos };

const Sim = struct {
    allocator: std.mem.Allocator,
    cfg: config.Config,
    judge: verdict.Judge = .{},
    caps: device.Capabilities,
    w: *SimWorker,
    rng: std.Random.DefaultPrng,
    to_engine: Link = .{},
    to_client: Link = .{},
    client: *Client,
    server: Server = .{},
    failure: ?anyerror = null,
    scratch: [70000]u8 = undefined,
    engine_drops: u64 = 0,
    mode: Mode = .reliable,
    trace: bool = false,

    fn tracePacket(sim: *const Sim, direction: []const u8, data: []const u8) void {
        if (!sim.trace) return;
        const p = parse.parse(data) catch return;
        if (p.l4 != .tcp) return;
        const t = p.l4.tcp;
        std.debug.print("{d:>7} {s} {s}{s}{s}{s}{s} seq={d} ack={d} win={d} len={d}\n", .{
            sim.w.clock,
            direction,
            if (t.flags.syn) "S" else "",
            if (t.flags.fin) "F" else "",
            if (t.flags.rst) "R" else "",
            if (t.flags.psh) "P" else "",
            if (t.flags.ack) "." else "",
            t.seq,
            t.ack,
            t.window,
            p.payload_len,
        });
    }

    fn create(allocator: std.mem.Allocator, ch: Chooser) !*Sim {
        const sim = try allocator.create(Sim);
        errdefer allocator.destroy(sim);
        sim.* = .{
            .allocator = allocator,
            .cfg = config.Config.fromPreset(.desktop),
            .caps = .{},
            .w = undefined,
            .rng = std.Random.DefaultPrng.init(ch.full(u64, @src())),
            .client = undefined,
        };
        const mtus = [_]u32{ 576, 1280, 1500, 4000 };
        const mtu = mtus[ch.range(u8, 0, mtus.len - 1, @src())];
        sim.caps = .{ .mtu = mtu, .queues = 1 };
        const cfg = &sim.cfg;
        cfg.stack.mode = .userspace;
        cfg.device.mtu = mtu;
        cfg.stack.tcp_rx_window = ch.range(u32, 2048, 96 << 10, @src());
        cfg.stack.tcp_tx_buffer = ch.range(u32, 2048, 96 << 10, @src());
        cfg.stack.tcp_timestamps = ch.flag(@src());
        cfg.stack.tcp_sack = ch.flag(@src());
        cfg.stack.tcp_window_scaling = ch.flag(@src());
        cfg.stack.tcp_congestion = if (ch.flag(@src())) .cubic else .newreno;
        cfg.stack.tcp_linger_ms = 400;
        cfg.stack.tcp_idle_timeout_ms = 30 * 60 * 1000;
        const w = try allocator.create(SimWorker);
        errdefer allocator.destroy(w);
        w.* = .{
            .allocator = allocator,
            .loop = .{ .allocator = allocator },
            .pool = undefined,
            .wheel = timeouts.Wheel.init(1),
            .counters_storage = .{},
            .counters = undefined,
            .cfg = &sim.cfg,
            .tcp = undefined,
            .handler = .{ .allocator = allocator },
            .clock = 1,
            .sim = sim,
        };
        w.counters = &w.counters_storage;
        const buffer_size = sim.caps.bufferSize();
        w.pool = try pool.Pool.init(allocator, .{ .count = 384, .buffer_size = buffer_size });
        errdefer w.pool.deinit();
        w.tcp = try SimWorker.Tcp.init(allocator, &sim.cfg, 16, buffer_size, ch.full(u64, @src()));
        errdefer w.tcp.deinit(allocator);
        w.handler.delay_ms = ch.range(u64, 0, 30, @src());
        sim.w = w;
        const cl = try allocator.create(Client);
        cl.* = .{
            .ep = addr.Endpoint.parse("10.7.0.2:43210") catch unreachable,
            .server = addr.Endpoint.parse("10.9.9.9:7") catch unreachable,
            .mss = @min(mtu - 40, ch.range(u32, 256, 8960, @src())),
            .offer_sack = ch.flag(@src()),
            .offer_ts = ch.flag(@src()),
            .offer_ws = ch.flag(@src()),
            .ws_shift = ch.range(u8, 0, 9, @src()),
            .byte_probes = ch.flag(@src()),
            .total = ch.range(u32, 1, 160 << 10, @src()),
            .recv_cap = ch.range(u32, 1024, 256 << 10, @src()),
            .read_rate = ch.range(u32, 64, 256 << 10, @src()),
            .ack_every = ch.range(u8, 1, 2, @src()),
        };
        sim.client = cl;
        sim.to_engine.loss_pct = ch.range(u8, 0, 12, @src());
        sim.to_client.loss_pct = ch.range(u8, 0, 12, @src());
        sim.to_engine.dup_pct = ch.range(u8, 0, 4, @src());
        sim.to_client.dup_pct = ch.range(u8, 0, 4, @src());
        sim.to_engine.delay_ms = ch.range(u32, 0, 3, @src());
        sim.to_client.delay_ms = ch.range(u32, 0, 3, @src());
        sim.to_engine.jitter_ms = ch.range(u32, 0, 8, @src());
        sim.to_client.jitter_ms = ch.range(u32, 0, 8, @src());
        sim.server.cap = ch.range(u64, 1024, 512 << 10, @src());
        sim.server.rate = ch.range(u64, 16, 512 << 10, @src());
        sim.server.chunk = ch.range(u32, 1, 65536, @src());
        return sim;
    }

    fn destroy(sim: *Sim) void {
        const allocator = sim.allocator;
        sim.to_engine.deinit(allocator);
        sim.to_client.deinit(allocator);
        const w = sim.w;
        for (w.handler.dials.items) |pd| {
            if (pd.dial.fd != sys.invalid_fd) sys.close(pd.dial.fd);
        }
        var it = w.tcp.conns.iterator();
        while (it.next()) |i| {
            const c = w.tcp.conns.value(i);
            if (c.up.fd != sys.invalid_fd) sys.close(c.up.fd);
        }
        w.handler.dials.deinit(allocator);
        w.loop.pending.deinit(allocator);
        w.tcp.deinit(allocator);
        w.pool.deinit();
        allocator.destroy(w);
        allocator.destroy(sim.client);
        allocator.destroy(sim);
    }

    fn captureOutput(sim: *Sim, header: []const u8, vh: gso.VirtioNetHdr, parts: []const device.PayloadRef) void {
        if (sim.failure != null) return;
        if (vh.flags != 0 or vh.gso_type != 0) {
            sim.failure = error.UnexpectedOffloadMetadata;
            return;
        }
        var n = header.len;
        @memcpy(sim.scratch[0..n], header);
        for (parts) |p| {
            @memcpy(sim.scratch[n..][0..p.len], p.buf.ptr[p.off..][0..p.len]);
            n += p.len;
        }
        sim.tracePacket("engine>", sim.scratch[0..n]);
        sim.to_client.send(sim.allocator, sim.rng.random(), sim.w.clock, sim.scratch[0..n]) catch |err| {
            sim.failure = err;
        };
    }

    fn injectEngine(sim: *Sim, data: []const u8) !void {
        const w = sim.w;
        const b = w.pool.get() orelse {
            sim.engine_drops += 1;
            return;
        };
        if (data.len > b.cap - b.headroom()) {
            w.pool.put(b);
            return error.PacketTooLarge;
        }
        @memcpy(b.ptr[b.headroom()..][0..data.len], data);
        b.len = @intCast(data.len);
        const pkt = parse.parse(b.bytes()) catch {
            w.pool.put(b);
            return;
        };
        if (pkt.l4 != .tcp) {
            w.pool.put(b);
            return;
        }
        w.tcp.input(w, b, .{}, pkt);
    }

    fn recvNow(sim: *Sim, fd: sys.fd_t, buf: []u8) i32 {
        if (sim.mode == .chaos) {
            const n = @min(buf.len, sim.rng.random().uintAtMost(usize, 3000));
            if (n == 0) return sys.Errno.again.result();
            @memset(buf[0..n], 0x42);
            return @intCast(n);
        }
        const s = sim.serverFor(fd) catch {
            sim.failure = error.UnknownUpstreamFd;
            return sys.Errno.badf.result();
        };
        return s.onRecv(buf) orelse sys.Errno.again.result();
    }

    fn serverFor(sim: *Sim, fd: sys.fd_t) !*Server {
        if (fd != sim.server.fd or fd == sys.invalid_fd) return error.UnknownUpstreamFd;
        return &sim.server;
    }

    fn pumpDials(sim: *Sim) !void {
        const w = sim.w;
        var i: usize = 0;
        while (i < w.handler.dials.items.len) {
            const pd = w.handler.dials.items[i];
            const d = pd.dial;
            if (d.aborted) {
                _ = w.handler.dials.orderedRemove(i);
                d.phase = .idle;
                w.tcp.onDialDone(w, d, .canceled);
                continue;
            }
            if (w.clock < pd.at) {
                i += 1;
                continue;
            }
            _ = w.handler.dials.orderedRemove(i);
            const rc = std.os.linux.eventfd(0, std.os.linux.EFD.CLOEXEC);
            if (std.os.linux.errno(rc) != .SUCCESS) return error.EventfdFailed;
            const fd: sys.fd_t = @intCast(rc);
            if (sim.server.fd != sys.invalid_fd) return error.SecondUpstreamConnection;
            sim.server = .{ .cap = sim.server.cap, .rate = sim.server.rate, .chunk = sim.server.chunk, .fd = fd };
            d.fd = fd;
            d.phase = .done;
            w.tcp.onDialDone(w, d, .success);
        }
    }

    fn pumpCompletions(sim: *Sim) !void {
        const w = sim.w;
        var budget: u32 = 512;
        var i: usize = 0;
        while (i < w.loop.pending.items.len and budget > 0) {
            const c = w.loop.pending.items[i];
            const outcome: ?i32 = if (c.state == .canceling) sys.Errno.canceled.result() else switch (c.op) {
                .recv => |op| (try sim.serverFor(op.fd)).onRecv(op.buf),
                .poll => |op| (try sim.serverFor(op.fd)).readable(),
                .sendmsg => |op| try (try sim.serverFor(op.fd)).onSend(op.msg.iov[0..@intCast(op.msg.iovlen)]),
                .writev => |op| try (try sim.serverFor(op.fd)).onSend(op.iov),
                else => return error.UnexpectedOperation,
            };
            if (outcome) |r| {
                w.loop.finish(i, r);
                budget -= 1;
                i = 0;
            } else {
                i += 1;
            }
        }
    }

    fn refreshServer(sim: *Sim) void {
        const s = &sim.server;
        if (s.fd == sys.invalid_fd) return;
        var it = sim.w.tcp.conns.iterator();
        while (it.next()) |i| {
            const c = sim.w.tcp.conns.value(i);
            if (c.up.fd == s.fd) {
                if (c.up.shut_wr) s.eof_seen = true;
                return;
            }
        }
    }

    fn checkInvariants(sim: *Sim) !void {
        var it = sim.w.tcp.conns.iterator();
        while (it.next()) |i| {
            const c = sim.w.tcp.conns.value(i);
            var rx: u32 = 0;
            var k: usize = 0;
            while (k < c.rx_count) : (k += 1) rx += c.rx.?.entries[(c.rx_head + k) % tcp_mod.rx_ring_capacity].len;
            if (rx != c.rx_bytes) return error.RxAccountingBroken;
            if (c.rx_count == 0 and c.rx != null and !c.up.tx_c.isActive()) return error.RxRingLeaked;
            if (c.ooo_count == 0 and c.ooo != null) return error.OooRingLeaked;
            var ooo: u32 = 0;
            const ooo_entries = if (c.ooo) |r| r.entries[0..c.ooo_count] else &[_]@TypeOf(c.ooo.?.entries[0]){};
            for (ooo_entries, 0..) |e, j| {
                ooo += e.len;
                if (!seqGt(e.seq, c.rcv_nxt)) return error.OooEntryNotAhead;
                if (j > 0) {
                    const prev = ooo_entries[j - 1];
                    if (seqGt(prev.seq +% prev.len, e.seq)) return error.OooEntriesOverlap;
                }
            }
            if (ooo != c.ooo_bytes) return error.OooAccountingBroken;
            var tx: u64 = 0;
            var b = c.tx.head;
            while (b) |buf| : (b = buf.next) tx += buf.len;
            if (tx < c.tx_head_off or tx - c.tx_head_off != c.tx_bytes) return error.TxAccountingBroken;
            if (c.synchronized() and !(seqLe(c.snd_una, c.snd_nxt) and seqLe(c.snd_nxt, c.snd_max))) return error.SendSequenceDisorder;
        }
        if (sim.w.pool.in_use > sim.w.pool.capacity()) return error.PoolAccountingBroken;
    }

    fn step(sim: *Sim, dt: u64) !void {
        const w = sim.w;
        w.clock += dt;
        const now = w.clock;
        while (sim.to_engine.popDue(now)) |pkt| {
            defer sim.allocator.free(pkt.data);
            try sim.injectEngine(pkt.data);
            if (sim.failure) |e| return e;
        }
        try sim.pumpDials();
        try sim.pumpCompletions();
        sim.refreshServer();
        sim.server.tick(dt);
        try sim.pumpCompletions();
        w.wheel.advance(now, w, SimWorker.onTimer);
        w.tcp.flush(w);
        if (sim.failure) |e| return e;
        while (sim.to_client.popDue(now)) |pkt| {
            defer sim.allocator.free(pkt.data);
            try sim.client.onPacket(sim, pkt.data);
        }
        if (sim.mode == .reliable) try sim.client.tick(sim, dt);
        try sim.checkInvariants();
    }

    fn dumpEngine(sim: *Sim) void {
        std.debug.print("scenario mtu={d} rx_window={d} tx_buffer={d} ts={} sack={} ws={} client mss={d} eff_mss={d} ws_shift={d} probes={} recv_cap={d} server cap={d} rate={d} chunk={d} pool in_use={d} drops={d}\n", .{
            sim.caps.mtu,    sim.cfg.stack.tcp_rx_window, sim.cfg.stack.tcp_tx_buffer, sim.cfg.stack.tcp_timestamps, sim.cfg.stack.tcp_sack, sim.cfg.stack.tcp_window_scaling,
            sim.client.mss,  sim.client.eff_mss,          sim.client.ws_shift,         sim.client.byte_probes,       sim.client.recv_cap,    sim.server.cap,
            sim.server.rate, sim.server.chunk,            sim.w.pool.in_use,           sim.engine_drops,
        });
        var it = sim.w.tcp.conns.iterator();
        while (it.next()) |i| {
            const c = sim.w.tcp.conns.value(i);
            std.debug.print("conn state={t} snd_una={d} snd_nxt={d} snd_max={d} snd_wnd={d} cwnd={d} rto={d} retries={d} rcv_nxt={d} rcv_adv={d} rx_bytes={d} rx_count={d} ooo={d}/{d} tx_bytes={d} rtx_pending={} in_recovery={} sack_count={d} up_connected={} up_tx_active={} up_rx_active={} rto_timer={} persist={} mss={d} ws={d}/{d}\n", .{
                c.state, c.snd_una, c.snd_nxt, c.snd_max, c.snd_wnd, c.cwnd, c.rto, c.retries, c.rcv_nxt, c.rcv_adv, c.rx_bytes, c.rx_count, c.ooo_count, c.ooo_bytes, c.tx_bytes, c.rtx_pending, c.in_recovery, c.sack_count, c.up.connected, c.up.tx_c.isActive(), c.up.rx_c.isActive(), c.rto_timer.active, c.persist_timer.active, c.mss, c.snd_wscale, c.rcv_wscale,
            });
        }
    }

    fn reliableDone(sim: *Sim) bool {
        const cl = sim.client;
        return cl.state == .established and cl.delivered == cl.total and cl.got_fin and cl.finAcked() and sim.w.tcp.conns.len == 0;
    }

    fn runReliable(sim: *Sim, ch: Chooser) !void {
        var turbulent: u64 = 0;
        const turbulent_limit: u64 = ch.range(u64, 0, 20_000, @src());
        while (turbulent < turbulent_limit and !sim.reliableDone()) {
            const dt: u64 = ch.range(u64, 1, 8, @src());
            try sim.step(dt);
            turbulent += dt;
        }
        sim.to_engine.calm();
        sim.to_client.calm();
        sim.client.read_rate = 1 << 30;
        sim.server.rate = 1 << 30;
        sim.server.cap = 1 << 30;
        sim.server.chunk = 65536;
        var calm: u64 = 0;
        while (!sim.reliableDone()) {
            if (calm > 240_000) {
                std.debug.print("tcp sim stalled: client delivered {d}/{d} got_fin={} fin_acked={} snd_una={d} snd_max={d} peer_wnd={d} resets={d} upstream received {d} echoed {d} eof={} closed={} conns={d}\n", .{
                    sim.client.delivered, sim.client.total,  sim.client.got_fin,  sim.client.finAcked(), sim.client.snd_una,  sim.client.snd_max, sim.client.peer_wnd, sim.client.resets,
                    sim.server.received,  sim.server.echoed, sim.server.eof_seen, sim.server.closed,     sim.w.tcp.conns.len,
                });
                sim.dumpEngine();
                return error.ConnectionStalled;
            }
            try sim.step(5);
            calm += 5;
        }
        if (sim.client.resets != 0) return error.UnexpectedReset;
        if (sim.server.received != sim.client.total) return error.UpstreamIncomplete;
        try sim.drainAndCheckLeaks();
    }

    fn runChaos(sim: *Sim, ch: Chooser) !void {
        sim.mode = .chaos;
        sim.to_engine.calm();
        const ports = [_]u16{ 40000, 40001, 40002 };
        var steps: u32 = 0;
        var last_seq: [ports.len]u32 = .{ 5000, 9000, 13000 };
        var last_ack: [ports.len]u32 = @splat(0);
        while (!ch.stop(@src()) and steps < 3000) : (steps += 1) {
            const which = ch.range(u8, 0, ports.len - 1, @src());
            const flag_choices = [_]u8{ tcp_mod.SYN, tcp_mod.ACK, tcp_mod.ACK | tcp_mod.PSH, tcp_mod.FIN | tcp_mod.ACK, tcp_mod.RST, tcp_mod.RST | tcp_mod.ACK, tcp_mod.SYN | tcp_mod.ACK, 0 };
            const flags = flag_choices[ch.range(u8, 0, flag_choices.len - 1, @src())];
            const seq = last_seq[which] +% (ch.range(u32, 0, 4096, @src()) -% 1024);
            const ack = last_ack[which] +% (ch.range(u32, 0, 4096, @src()) -% 2048);
            const len = ch.range(u32, 0, @min(sim.caps.mtu - 40, 1400), @src());
            var payload: [1400]u8 = undefined;
            for (payload[0..len], 0..) |*b, i| b.* = @truncate(i);
            var opts_buf: [16]u8 = undefined;
            var olen: usize = 0;
            if (flags & tcp_mod.SYN != 0) {
                @memcpy(opts_buf[0..10], &[_]u8{ 2, 4, 0x05, 0x78, 4, 2, 3, 3, 7, 1 });
                olen = 10;
            }
            var buf: [2048]u8 = undefined;
            const ep: addr.Endpoint = .{ .addr = sim.client.ep.addr, .port = ports[which] };
            const pkt = helpers.buildTcp4(&buf, ep, sim.client.server, .{ .seq = seq, .ack = ack, .flags = flags, .window = ch.full(u16, @src()), .options = opts_buf[0..olen], .payload = payload[0..len] });
            try sim.injectEngine(pkt);
            if (ch.flag(@src())) last_seq[which] = seq +% len;
            const dt = ch.range(u64, 0, 400, @src());
            try sim.chaosStep(dt, ch);
            while (sim.to_client.popDue(sim.w.clock)) |out| {
                defer sim.allocator.free(out.data);
                const p = parse.parse(out.data) catch return error.EngineEmittedMalformedPacket;
                if (p.l4 != .tcp) return error.EngineEmittedNonTcp;
                if (!parse.l4ChecksumValid(out.data, p)) return error.EngineBadTcpChecksum;
                for (ports, 0..) |port, idx| {
                    if (p.l4.tcp.dst_port == port) {
                        last_ack[idx] = p.l4.tcp.seq +% p.payload_len;
                        if (p.l4.tcp.flags.syn) last_ack[idx] +%= 1;
                    }
                }
            }
        }
        sim.w.tcp.shutdownAll(sim.w);
        sim.w.tcp.flush(sim.w);
        try sim.drainAndCheckLeaks();
    }

    fn chaosStep(sim: *Sim, dt: u64, ch: Chooser) !void {
        const w = sim.w;
        w.clock += dt;
        var i: usize = 0;
        while (i < w.handler.dials.items.len) {
            const d = w.handler.dials.items[i].dial;
            _ = w.handler.dials.orderedRemove(i);
            if (d.aborted or ch.flag(@src())) {
                d.phase = .idle;
                w.tcp.onDialDone(w, d, if (d.aborted) .canceled else .connrefused);
            } else {
                const rc = std.os.linux.eventfd(0, std.os.linux.EFD.CLOEXEC);
                if (std.os.linux.errno(rc) != .SUCCESS) return error.EventfdFailed;
                d.fd = @intCast(rc);
                d.phase = .done;
                w.tcp.onDialDone(w, d, .success);
            }
        }
        var budget: u32 = 64;
        i = 0;
        while (i < w.loop.pending.items.len and budget > 0) : (budget -= 1) {
            const c = w.loop.pending.items[i];
            if (c.state == .canceling) {
                w.loop.finish(i, sys.Errno.canceled.result());
                i = 0;
                continue;
            }
            const choice = ch.range(u8, 0, 5, @src());
            const r: ?i32 = switch (c.op) {
                .poll => switch (choice) {
                    0 => null,
                    1 => sys.Errno.connreset.result(),
                    else => @bitCast(@as(u32, @bitCast(io.Events{ .in = true }))),
                },
                .recv => |op| switch (choice) {
                    0 => null,
                    1 => 0,
                    2 => sys.Errno.connreset.result(),
                    else => blk: {
                        const n = @min(op.buf.len, @as(usize, ch.range(u32, 1, 3000, @src())));
                        @memset(op.buf[0..n], 0x42);
                        break :blk @intCast(n);
                    },
                },
                .sendmsg => |op| switch (choice) {
                    0 => null,
                    1 => sys.Errno.pipe.result(),
                    else => blk: {
                        var total: usize = 0;
                        for (op.msg.iov[0..@intCast(op.msg.iovlen)]) |v| total += v.len;
                        break :blk @intCast(if (total == 0) 0 else ch.range(u32, 0, @intCast(@min(total, std.math.maxInt(u32))), @src()));
                    },
                },
                else => return error.UnexpectedOperation,
            };
            if (r) |res| {
                w.loop.finish(i, res);
                i = 0;
            } else {
                i += 1;
            }
        }
        w.wheel.advance(w.clock, w, SimWorker.onTimer);
        w.tcp.flush(w);
        if (sim.failure) |e| return e;
        try sim.checkInvariants();
    }

    fn drainAndCheckLeaks(sim: *Sim) !void {
        const w = sim.w;
        var rounds: u32 = 0;
        while (rounds < 2000 and (w.tcp.conns.len != 0 or w.loop.pending.items.len != 0 or w.handler.dials.items.len != 0)) : (rounds += 1) {
            w.clock += 50;
            while (w.handler.dials.items.len > 0) {
                const d = w.handler.dials.orderedRemove(0).dial;
                d.phase = .idle;
                w.tcp.onDialDone(w, d, .canceled);
            }
            while (w.loop.pending.items.len > 0) {
                const c = w.loop.pending.items[0];
                if (c.state != .canceling) w.loop.cancel(c);
                w.loop.finish(0, sys.Errno.canceled.result());
            }
            w.wheel.advance(w.clock, w, SimWorker.onTimer);
            w.tcp.flush(w);
            if (rounds == 100) w.tcp.shutdownAll(w);
            while (sim.to_client.popDue(std.math.maxInt(u64))) |pkt| sim.allocator.free(pkt.data);
            while (sim.to_engine.popDue(std.math.maxInt(u64))) |pkt| sim.allocator.free(pkt.data);
        }
        if (w.tcp.conns.len != 0) return error.ConnectionsNotReleased;
        if (w.loop.pending.items.len != 0) return error.CompletionsLeaked;
        if (w.pool.in_use != 0) {
            std.debug.print("tcp sim leaked {d} packet buffers\n", .{w.pool.in_use});
            return error.PacketBuffersLeaked;
        }
        if (w.wheel.count != 0) return error.TimersLeaked;
        sim.server.fd = sys.invalid_fd;
    }
};

fn run(ch: Chooser) !void {
    return runTraced(ch, false);
}

fn runTraced(ch: Chooser, trace: bool) !void {
    const sim = try Sim.create(std.testing.allocator, ch);
    defer sim.destroy();
    sim.trace = trace;
    if (ch.range(u8, 0, 4, @src()) == 0) {
        try sim.runChaos(ch);
    } else {
        try sim.runReliable(ch);
    }
}

fn simulate(_: void, smith: *std.testing.Smith) anyerror!void {
    if (!sys.is_linux) return error.SkipZigTest;
    try run(.{ .smith = smith });
}

test "tcp simulation fuzz" {
    try std.testing.fuzz({}, simulate, .{});
}

test "tcp simulation seeded scenarios" {
    if (!sys.is_linux) return error.SkipZigTest;
    var first: u64 = 0;
    var count: u64 = 48;
    if (std.testing.environ.getPosix("ZEPTUN_SIM_SEEDS")) |text| {
        var parts = std.mem.splitScalar(u8, text, ':');
        first = std.fmt.parseInt(u64, parts.first(), 10) catch 0;
        if (parts.next()) |n| count = std.fmt.parseInt(u64, n, 10) catch count;
    }
    var seed: u64 = first;
    while (seed < first + count) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(0x7a65_7074_756e +% seed);
        run(.{ .prng = &prng }) catch |err| {
            std.debug.print("tcp simulation seed {d} failed: {t}\n", .{ seed, err });
            return err;
        };
    }
}
