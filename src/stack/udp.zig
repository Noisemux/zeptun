const std = @import("std");
const build_options = @import("build_options");
const addr = @import("../addr.zig");
const checksum = @import("../packet/checksum.zig");
const parse = @import("../packet/parse.zig");
const pool = @import("../packet/pool.zig");
const gso = @import("../packet/gso.zig");
const table = @import("../flow/table.zig");
const timeouts = @import("../flow/timeouts.zig");
const ip = @import("ip.zig");
const icmp = @import("icmp.zig");
const dns = @import("dns.zig");
const handler_mod = @import("../handler/handler.zig");
const elastic = @import("../elastic.zig");
const config = @import("../config.zig");

pub fn Udp(comptime W: type) type {
    return struct {
        const Self = @This();
        const HState = handler_mod.UdpState(W);

        const Move = struct {
            s: *Session,
            to: u16,
            since: u64,
        };

        const Transfer = struct {
            key: parse.FlowKey,
            session: Session,
            deadline: u64,
            from: u16,
            accepted: bool,
        };

        pub const Session = struct {
            client: addr.Endpoint = .{},
            dns_orig: ?addr.Endpoint = null,
            closing: bool = false,
            moved: bool = false,
            meter_epoch: u8 = 0,
            move_to: u16 = 0,
            meter: u32 = 0,
            last_active: u64 = 0,
            timer: timeouts.Timer = .{ .kind = @backingInt(timeouts.Kind.udp_idle) },
            ip_id: u16 = 0,
            handler: HState = .{},

            fn fromHandler(h: *HState) *Session {
                return @alignCast(@fieldParentPtr("handler", h));
            }
        };

        sessions: table.FlowTable(Session),
        idle_ms: u32,
        enabled: bool,
        nat: config.NatMode,
        moving: [elastic.move_capacity]Move = undefined,
        moving_len: u8 = 0,
        fwd: [elastic.move_capacity]*Session = undefined,
        fwd_len: u8 = 0,

        pub fn init(allocator: std.mem.Allocator, max_sessions: u32, idle_ms: u32, enabled: bool, nat: config.NatMode) !Self {
            return .{
                .sessions = try table.FlowTable(Session).init(allocator, max_sessions),
                .idle_ms = idle_ms,
                .enabled = enabled,
                .nat = nat,
            };
        }

        pub fn deinit(u: *Self, allocator: std.mem.Allocator) void {
            u.sessions.deinit(allocator);
        }

        pub fn input(u: *Self, w: *W, b: *pool.Buffer, vh: gso.VirtioNetHdr, pkt: parse.Packet) void {
            var handed = false;
            defer if (!handed) w.pool.put(b);
            const data = b.bytes();
            if (!u.enabled) {
                icmp.sendUnreachable(w, data, pkt, true);
                return;
            }
            const uh = pkt.l4.udp;
            const v6 = pkt.ip.isV6();
            const al = pkt.ip.addrLen();
            var redirect: ?addr.Endpoint = null;
            if (uh.dst_port == dns.port and w.cfg.dnsActive() and vh.gsoKind() != gso.VirtioNetHdr.gso_udp_l4) {
                const dst_addr = addr.Address.fromSlice(pkt.ip.dst(data));
                const local = eqlOpt(w.cfg.dnsAddress4(), dst_addr) or eqlOpt(w.cfg.dnsAddress6(), dst_addr);
                if (local or w.cfg.dns.hijack) {
                    w.counters.inc(.dns_hijacked);
                    const upstream = w.cfg.dns.upstream;
                    if (w.handler.fake) |t| {
                        switch (dns.reply(w, t, b, pkt, upstream != null)) {
                            .reply => {
                                w.counters.inc(.dns_fake_answers);
                                return;
                            },
                            .drop => return,
                            .forward => {},
                        }
                    }
                    redirect = upstream orelse return;
                }
            }
            var key: parse.FlowKey = .{ .proto = parse.proto.udp, .v6 = @intFromBool(v6), .src_port = uh.src_port };
            @memcpy(key.src[0..al], pkt.ip.src(data));
            switch (w.cfg.stack.udp_nat) {
                .endpoint_independent => {},
                .address => @memcpy(key.dst[0..al], pkt.ip.dst(data)),
                .address_port => {
                    @memcpy(key.dst[0..al], pkt.ip.dst(data));
                    key.dst_port = uh.dst_port;
                },
            }
            const now = w.now();
            const idx = u.sessions.find(&key) orelse blk: {
                if (w.elasticLive()) {
                    if (w.peerOwner(.udp, &key) orelse w.newFlowTarget(key.hash())) |owner| {
                        handed = true;
                        w.handoff(owner, b, vh);
                        return;
                    }
                }
                if (u.sessions.isFull()) {
                    if (u.sessions.oldest()) |old| {
                        w.counters.inc(.udp_evicted);
                        u.close(w, u.sessions.value(old));
                    }
                    if (u.sessions.isFull()) {
                        w.counters.inc(.udp_dropped);
                        return;
                    }
                }
                var bypass = false;
                if (w.judge().active()) {
                    switch (w.judge().ask(parse.proto.udp, v6, pkt.ip.src(data), uh.src_port, pkt.ip.dst(data), uh.dst_port)) {
                        .proxy => {},
                        .direct => bypass = true,
                        .drop => return,
                        .reject => {
                            icmp.sendUnreachable(w, data, pkt, true);
                            return;
                        },
                    }
                }
                const i = u.sessions.insert(key, .{}) catch return;
                const s = u.sessions.value(i);
                s.* = .{
                    .client = .{ .addr = addr.Address.fromSlice(pkt.ip.src(data)), .port = uh.src_port },
                    .last_active = now,
                };
                w.counters.inc(.udp_opened);
                w.counters.inc(.udp_active);
                if (!w.handler.udpOpen(w, &s.handler, if (v6) .v6 else .v4, pkt.ip.tos, bypass)) {
                    s.closing = true;
                    u.release(w, s);
                    icmp.sendUnreachable(w, data, pkt, true);
                    return;
                }
                if (s.closing) {
                    w.counters.inc(.udp_dropped);
                    return;
                }
                w.wheel.schedule(&s.timer, now + u.idle_ms);
                break :blk i;
            };
            const s = u.sessions.value(idx);
            if (s.moved) {
                handed = true;
                w.handoff(s.move_to, b, vh);
                return;
            }
            u.sessions.touch(idx);
            if (s.closing) {
                w.counters.inc(.udp_dropped);
                return;
            }
            s.last_active = now;
            elastic.meterAdd(&s.meter, &s.meter_epoch, now, pkt.payload_len);
            var dst: addr.Endpoint = .{ .addr = addr.Address.fromSlice(pkt.ip.dst(data)), .port = uh.dst_port };
            if (redirect) |r| {
                s.dns_orig = dst;
                dst = r;
            }
            const seg: u16 = if (vh.gsoKind() == gso.VirtioNetHdr.gso_udp_l4) vh.gso_size else 0;
            w.handler.udpSend(w, &s.handler, dst, b, b.off + pkt.payload_off, pkt.payload_len, seg);
        }

        fn eqlOpt(a: ?addr.Address, b: addr.Address) bool {
            return if (a) |x| x.eql(b) else false;
        }

        fn accepts(u: *Self, s: *Session, from: addr.Endpoint) bool {
            const mode = u.nat;
            if (mode == .endpoint_independent) return true;
            const k = u.sessions.entry(u.sessions.indexOfValue(s)).key;
            const al: usize = if (from.addr.family == .v6) 16 else 4;
            if (!std.mem.eql(u8, k.dst[0..al], from.addr.bytes[0..al])) return false;
            return mode == .address or k.dst_port == from.port;
        }

        pub fn unreachable_(u: *Self, w: *W, hs: *HState, target: addr.Endpoint) void {
            _ = u;
            const s = Session.fromHandler(hs);
            if (s.closing or s.moved or target.addr.family != s.client.addr.family) return;
            icmp.sendPortUnreachable(w, s.client, target);
        }

        pub fn deliver(u: *Self, w: *W, hs: *HState, from: addr.Endpoint, b: *pool.Buffer, seg: u16) void {
            const s = Session.fromHandler(hs);
            var src = from;
            if (s.dns_orig) |orig| {
                if (w.cfg.dns.upstream) |up| {
                    if (from.eql(up)) src = orig;
                }
            }
            if (s.closing or s.moved or src.addr.family != s.client.addr.family or !u.accepts(s, src)) {
                w.pool.put(b);
                return;
            }
            s.last_active = w.now();
            elastic.meterAdd(&s.meter, &s.meter_epoch, s.last_active, b.len);
            const caps = w.caps();
            if (seg != 0 and b.len > seg and !(caps.vnet_hdr and caps.uso)) {
                var pos: u32 = 0;
                while (pos < b.len) {
                    const n = @min(@as(u32, seg), b.len - pos);
                    const nb = w.pool.get() orelse break;
                    @memcpy(nb.ptr[nb.headroom()..][0..n], b.ptr[b.off + pos ..][0..n]);
                    nb.len = n;
                    emit(w, s, src, nb, 0);
                    pos += n;
                }
                w.pool.put(b);
                return;
            }
            emit(w, s, src, b, if (seg != 0 and b.len > seg) seg else 0);
        }

        fn emit(w: *W, s: *Session, src: addr.Endpoint, b: *pool.Buffer, seg: u16) void {
            const v6 = s.client.addr.family == .v6;
            const ip_hlen: u16 = ip.headerLen(v6);
            const hdr_len: u32 = ip_hlen + 8;
            if (b.headroom() < hdr_len + gso.VirtioNetHdr.size or b.len + 8 > 0xffff) {
                w.pool.put(b);
                w.counters.inc(.udp_dropped);
                return;
            }
            const udp_len: u32 = b.len + 8;
            const hdr = b.prepend(hdr_len);
            _ = ip.writeHeader(hdr, v6, src.addr.slice(), s.client.addr.slice(), parse.proto.udp, udp_len, s.ip_id);
            s.ip_id +%= if (seg != 0) @intCast((b.len - hdr_len + seg - 1) / seg) else 1;
            const uh = hdr[ip_hlen..];
            parse.setBe16(uh, 0, src.port);
            parse.setBe16(uh, 2, s.client.port);
            parse.setBe16(uh, 4, @intCast(udp_len));
            uh[6] = 0;
            uh[7] = 0;
            const caps = w.caps();
            const acc = checksum.pseudo(v6, src.addr.slice(), s.client.addr.slice(), parse.proto.udp, udp_len);
            if (caps.vnet_hdr) {
                checksum.writeNative16(uh[6..8], checksum.fold(acc));
                w.transmit(b, gso.VirtioNetHdr.udp(ip_hlen, seg));
            } else {
                checksum.writeNative16(uh[6..8], checksum.finishUdp(checksum.sum(b.bytes()[ip_hlen..], acc)));
                w.transmit(b, .{});
            }
        }

        pub fn onTimer(u: *Self, w: *W, t: *timeouts.Timer) void {
            const s: *Session = @alignCast(@fieldParentPtr("timer", t));
            if (s.closing) return;
            const now = w.now();
            if (now - s.last_active >= u.idle_ms) {
                u.close(w, s);
            } else {
                w.wheel.schedule(&s.timer, s.last_active + u.idle_ms);
            }
        }

        pub fn close(u: *Self, w: *W, s: *Session) void {
            if (s.moved) return u.removeForward(s);
            if (s.closing) return;
            s.closing = true;
            w.wheel.cancel(&s.timer);
            w.handler.udpClose(w, &s.handler);
            u.release(w, s);
        }

        pub fn closeByHandler(u: *Self, w: *W, hs: *HState) void {
            u.close(w, Session.fromHandler(hs));
        }

        pub fn maybeRelease(u: *Self, w: *W, hs: *HState) void {
            u.release(w, Session.fromHandler(hs));
        }

        fn release(u: *Self, w: *W, s: *Session) void {
            if (!s.closing or !s.handler.idle()) return;
            if (s.timer.active) return;
            w.handler.udpFinalize(w, &s.handler);
            const idx = u.sessions.indexOfValue(s);
            if (!u.sessions.entry(idx).live) return;
            u.sessions.remove(idx);
            w.counters.dec(.udp_active);
            w.counters.inc(.udp_closed);
        }

        pub fn shutdownAll(u: *Self, w: *W) void {
            var it = u.sessions.iterator();
            while (it.next()) |i| u.close(w, u.sessions.value(i));
        }

        pub fn localCount(u: *const Self) u32 {
            return u.sessions.len - u.fwd_len;
        }

        fn movable(w: *W, s: *const Session) bool {
            return !s.closing and !s.moved and w.handler.udpMovable(&s.handler);
        }

        pub fn migrateOut(u: *Self, w: *W, s: *Session, to: u16) bool {
            if (!movable(w, s)) return false;
            if (@as(usize, u.moving_len) + u.fwd_len >= elastic.move_capacity) return false;
            if (w.pool.buffer_size < @sizeOf(Transfer) + 16) return false;
            w.handler.udpQuiesce(w, &s.handler);
            u.moving[u.moving_len] = .{ .s = s, .to = to, .since = w.now() };
            u.moving_len += 1;
            return true;
        }

        pub fn progressMigrations(u: *Self, w: *W) void {
            const now = w.now();
            var i: usize = 0;
            while (i < u.moving_len) {
                const m = u.moving[i];
                const s = m.s;
                var done = true;
                if (s.closing or s.moved or !s.handler.migrating) {
                    s.handler.migrating = false;
                } else if (w.handler.udpQuiet(w, &s.handler)) {
                    if (!u.transfer(w, s, m.to)) u.resumeSession(w, s);
                } else if (now -| m.since > 1000) {
                    u.resumeSession(w, s);
                } else {
                    done = false;
                }
                if (done) {
                    u.moving_len -= 1;
                    u.moving[i] = u.moving[u.moving_len];
                } else {
                    i += 1;
                }
            }
        }

        fn resumeSession(u: *Self, w: *W, s: *Session) void {
            _ = u;
            s.handler.migrating = false;
            if (s.closing) return;
            w.handler.udpResume(w, &s.handler);
        }

        fn transfer(u: *Self, w: *W, s: *Session, to: u16) bool {
            const b = w.pool.get() orelse return false;
            const rec = elastic.record(Transfer, b) orelse {
                w.pool.put(b);
                return false;
            };
            w.handler.udpDetach(w, &s.handler);
            rec.key = u.sessions.entry(u.sessions.indexOfValue(s)).key;
            rec.session = s.*;
            rec.deadline = if (s.timer.active) @max(s.timer.deadline, 1) else 0;
            rec.from = w.id;
            rec.accepted = false;
            w.wheel.cancel(&s.timer);
            w.handler.udpDisown(&s.handler);
            s.moved = true;
            s.move_to = to;
            s.last_active = w.now();
            u.fwd[u.fwd_len] = s;
            u.fwd_len += 1;
            w.counters.dec(.udp_active);
            w.counters.inc(.udp_migrated);
            w.sendControl(to, b, .udp_transfer);
            return true;
        }

        pub fn install(u: *Self, w: *W, b: *pool.Buffer) void {
            const rec = elastic.record(Transfer, b).?;
            rec.accepted = u.adopt(w, rec);
            if (!rec.accepted) w.handler.udpDiscard(w, &rec.session.handler);
            w.sendControl(rec.from, b, .udp_ack);
        }

        fn adopt(u: *Self, w: *W, rec: *Transfer) bool {
            if (w.engine.state.load(.acquire) != .running or u.sessions.isFull()) return false;
            const idx = u.sessions.insert(rec.key, .{}) catch return false;
            const s = u.sessions.value(idx);
            s.* = rec.session;
            s.moved = false;
            s.timer = .{ .kind = @backingInt(timeouts.Kind.udp_idle) };
            w.handler.udpAdopt(w, &s.handler);
            const now = w.now();
            w.wheel.schedule(&s.timer, if (rec.deadline != 0) @max(rec.deadline, now + 1) else now + u.idle_ms);
            w.counters.inc(.udp_active);
            return true;
        }

        pub fn dropRecord(u: *Self, w: *W, b: *pool.Buffer) void {
            _ = u;
            const rec = elastic.record(Transfer, b).?;
            w.handler.udpDiscard(w, &rec.session.handler);
            w.pool.put(b);
        }

        pub fn onTransferAck(u: *Self, w: *W, b: *pool.Buffer) void {
            const rec = elastic.record(Transfer, b).?;
            if (u.sessions.find(&rec.key)) |idx| {
                const s = u.sessions.value(idx);
                if (s.moved) u.removeForward(s);
            }
            w.pool.put(b);
        }

        fn removeForward(u: *Self, s: *Session) void {
            var i: usize = 0;
            while (i < u.fwd_len) : (i += 1) {
                if (u.fwd[i] == s) {
                    u.fwd_len -= 1;
                    u.fwd[i] = u.fwd[u.fwd_len];
                    break;
                }
            }
            s.moved = false;
            u.sessions.remove(u.sessions.indexOfValue(s));
        }

        pub fn expireForwards(u: *Self, w: *W, now: u64) void {
            _ = w;
            var i: usize = u.fwd_len;
            while (i > 0) {
                i -= 1;
                const s = u.fwd[i];
                if (now -| s.last_active >= elastic.forward_ttl_ms) u.removeForward(s);
            }
        }

        pub fn donate(u: *Self, w: *W, to: u16, fraction: u32, by_count: bool) void {
            const Cand = struct { s: *Session, weight: u64 };
            var cand: [elastic.move_capacity]Cand = undefined;
            var n: usize = 0;
            var total: u64 = 0;
            const now = w.now();
            var it = u.sessions.iterator();
            while (it.next()) |i| {
                const s = u.sessions.value(i);
                if (!movable(w, s)) continue;
                const weight: u64 = if (by_count) 1 else elastic.meterRecent(s.meter, s.meter_epoch, now);
                if (weight == 0) continue;
                total += weight;
                if (n < cand.len) {
                    cand[n] = .{ .s = s, .weight = weight };
                    n += 1;
                    continue;
                }
                var low: usize = 0;
                for (cand[1..], 1..) |x, j| {
                    if (x.weight < cand[low].weight) low = j;
                }
                if (weight > cand[low].weight) cand[low] = .{ .s = s, .weight = weight };
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
                if (u.migrateOut(w, x.s, to)) goal -|= x.weight;
            }
        }

        pub fn drainOut(u: *Self, w: *W) void {
            var it = u.sessions.iterator();
            while (it.next()) |i| {
                if (@as(usize, u.moving_len) + u.fwd_len >= elastic.move_capacity) return;
                const s = u.sessions.value(i);
                if (!movable(w, s)) continue;
                const target = w.newFlowTarget(u.sessions.entry(i).key.hash()) orelse return;
                _ = u.migrateOut(w, s, target);
            }
        }
    };
}
