const std = @import("std");
const builtin = @import("builtin");
const addr = @import("../addr.zig");
const io = @import("../io/io.zig");
const sys = @import("../io/sys.zig");
const checksum = @import("../packet/checksum.zig");
const parse = @import("../packet/parse.zig");
const pool = @import("../packet/pool.zig");
const table = @import("../flow/table.zig");
const timeouts = @import("../flow/timeouts.zig");
const ip = @import("ip.zig");
const log = @import("../log.zig");

pub const echo_request_v4: u8 = 8;
pub const echo_reply_v4: u8 = 0;
pub const echo_request_v6: u8 = 128;
pub const echo_reply_v6: u8 = 129;

pub const max_sessions: u32 = 256;

var wire_ids: std.atomic.Value(u16) = .init(0x5a00);

pub fn Ping(comptime W: type) type {
    return struct {
        const Self = @This();
        const Loop = W.Loop;

        pub const Session = struct {
            fd: sys.fd_t = sys.invalid_fd,
            v6: bool = false,
            raw: bool = false,
            closing: bool = false,
            client: [16]u8 = @splat(0),
            client_id: u16 = 0,
            wire_id: u16 = 0,
            last_active: u64 = 0,
            timer: timeouts.Timer = .{ .kind = @backingInt(timeouts.Kind.icmp_idle) },
            rx_c: Loop.Completion = .{},
            name: sys.Sockaddr = .{},
        };

        sessions: table.FlowTable(Session),
        idle_ms: u32,
        disabled: [2]bool = .{ false, false },

        pub fn init(allocator: std.mem.Allocator, idle_ms: u32) !Self {
            return .{ .sessions = try table.FlowTable(Session).init(allocator, max_sessions), .idle_ms = idle_ms };
        }

        pub fn deinit(p: *Self, allocator: std.mem.Allocator) void {
            p.sessions.deinit(allocator);
        }

        fn openSocket(p: *Self, w: *W, v6: bool, s: *Session) bool {
            if (p.disabled[@intFromBool(v6)]) return false;
            const family: addr.Family = if (v6) .v6 else .v4;
            var raw = false;
            const fd = sys.socket(family, if (v6) .icmp6 else .icmp4) catch blk: {
                if (!sys.is_linux) break :blk null;
                raw = true;
                break :blk sys.socket(family, if (v6) .icmp6_raw else .icmp4_raw) catch null;
            } orelse {
                p.disabled[@intFromBool(v6)] = true;
                log.warn("icmp: no {s} echo socket available, answering pings locally", .{if (v6) "ipv6" else "ipv4"});
                return false;
            };
            log.debug("icmp: {s} {s} echo socket", .{ if (raw) "raw" else "datagram", if (v6) "ipv6" else "ipv4" });
            w.handler.protect.apply(fd, family) catch {
                sys.close(fd);
                return false;
            };
            w.loop.register(fd) catch {
                sys.close(fd);
                return false;
            };
            s.fd = fd;
            s.raw = raw or sys.is_windows or sys.is_darwin or sys.is_bsd;
            return true;
        }

        pub fn input(p: *Self, w: *W, b: *pool.Buffer, pkt: parse.Packet) bool {
            const data = b.bytes();
            const v6 = pkt.ip.isV6();
            const msg = data[pkt.l4_off..pkt.ip.total_len];
            if (msg.len < 8) return false;
            const al = pkt.ip.addrLen();
            const id = std.mem.readInt(u16, msg[4..6], .big);
            var key: parse.FlowKey = .{ .proto = if (v6) parse.proto.icmpv6 else parse.proto.icmp, .v6 = @intFromBool(v6), .src_port = id };
            @memcpy(key.src[0..al], pkt.ip.src(data));
            const now = w.now();
            const idx = p.sessions.find(&key) orelse blk: {
                if (p.sessions.isFull()) {
                    if (p.sessions.oldest()) |old| p.close(w, p.sessions.value(old));
                    if (p.sessions.isFull()) return false;
                }
                const i = p.sessions.insert(key, .{}) catch return false;
                const s = p.sessions.value(i);
                s.* = .{ .v6 = v6, .client_id = id, .last_active = now };
                @memcpy(s.client[0..al], pkt.ip.src(data));
                if (!p.openSocket(w, v6, s)) {
                    p.sessions.remove(i);
                    return false;
                }
                s.wire_id = if (s.raw) wire_ids.fetchAdd(1, .monotonic) else id;
                p.armRecv(w, s);
                w.wheel.schedule(&s.timer, now + p.idle_ms);
                break :blk i;
            };
            p.sessions.touch(idx);
            const s = p.sessions.value(idx);
            if (s.closing) {
                w.pool.put(b);
                return true;
            }
            s.last_active = now;
            var sa = sys.Sockaddr.fromEndpoint(.{ .addr = addr.Address.fromSlice(pkt.ip.dst(data)), .port = 0 });
            if (s.raw) {
                const old_word = checksum.readNative16(msg[4..6]);
                std.mem.writeInt(u16, msg[4..6], s.wire_id, .big);
                if (!v6) {
                    const hc = checksum.readNative16(msg[2..4]);
                    checksum.writeNative16(msg[2..4], checksum.update16(hc, old_word, checksum.readNative16(msg[4..6])));
                }
            }
            const r = sys.sendto(s.fd, msg, sys.msg_dontwait, &sa);
            if (r < 0) w.counters.inc(.rx_dropped) else w.counters.inc(.icmp_echo);
            w.pool.put(b);
            return true;
        }

        fn armRecv(p: *Self, w: *W, s: *Session) void {
            _ = p;
            if (s.rx_c.isActive() or s.closing) return;
            s.rx_c = .{ .op = .{ .poll = .{ .fd = s.fd, .events = .{ .in = true } } }, .userdata = s, .callback = onReadable };
            w.loop.submit(&s.rx_c);
        }

        fn onReadable(ud: ?*anyopaque, loop: *Loop, c: *Loop.Completion, result: i32) io.Disposition {
            _ = c;
            const s: *Session = @ptrCast(@alignCast(ud.?));
            const w: *W = @alignCast(@fieldParentPtr("loop", loop));
            const p = &w.ping;
            if (s.closing) {
                p.release(w, s);
                return .disarm;
            }
            if (result < 0 and sys.toErrno(result) != .again) {
                p.close(w, s);
                return .disarm;
            }
            var budget: u32 = 16;
            while (budget > 0) : (budget -= 1) {
                const b = w.pool.get() orelse break;
                const room = b.cap - b.headroom();
                const hdr: u32 = 40;
                if (room <= hdr) {
                    w.pool.put(b);
                    break;
                }
                const n = sys.recvfrom(s.fd, b.ptr[b.headroom() + hdr ..][0 .. room - hdr], sys.msg_dontwait, &s.name);
                if (n <= 0) {
                    w.pool.put(b);
                    break;
                }
                p.deliver(w, s, b, @intCast(n));
            }
            p.armRecv(w, s);
            return .disarm;
        }

        fn deliver(p: *Self, w: *W, s: *Session, b: *pool.Buffer, n: u32) void {
            _ = p;
            const start = b.headroom() + 40;
            var msg = b.ptr[start..][0..n];
            if (!s.v6 and msg.len >= 20 and msg[0] & 0xf0 == 0x40) {
                const ihl: usize = @as(usize, msg[0] & 0x0f) * 4;
                if (ihl < 20 or ihl + 8 > msg.len) {
                    w.pool.put(b);
                    return;
                }
                msg = msg[ihl..];
            }
            const reply: u8 = if (s.v6) echo_reply_v6 else echo_reply_v4;
            if (msg.len < 8 or msg[0] != reply or msg[1] != 0) {
                w.pool.put(b);
                return;
            }
            if (s.raw and std.mem.readInt(u16, msg[4..6], .big) != s.wire_id) {
                w.pool.put(b);
                return;
            }
            const remote = s.name.toEndpoint() orelse {
                w.pool.put(b);
                return;
            };
            if ((remote.addr.family == .v6) != s.v6) {
                w.pool.put(b);
                return;
            }
            std.mem.writeInt(u16, msg[4..6], s.client_id, .big);
            msg[2] = 0;
            msg[3] = 0;
            const ip_hlen: u32 = ip.headerLen(s.v6);
            const msg_off: u32 = @intCast(msg.ptr - b.ptr);
            b.off = msg_off - ip_hlen;
            b.len = ip_hlen + @as(u32, @intCast(msg.len));
            const out = b.bytes();
            const al: usize = if (s.v6) 16 else 4;
            _ = ip.writeHeader(out, s.v6, remote.addr.slice(), s.client[0..al], if (s.v6) parse.proto.icmpv6 else parse.proto.icmp, @intCast(msg.len), 0);
            var acc: u64 = 0;
            if (s.v6) acc = checksum.pseudoV6(out[8..24], out[24..40], parse.proto.icmpv6, @intCast(msg.len));
            checksum.writeNative16(msg[2..4], checksum.finish(checksum.sum(msg, acc)));
            s.last_active = w.now();
            w.transmit(b, .{});
        }

        pub fn onTimer(p: *Self, w: *W, t: *timeouts.Timer) void {
            const s: *Session = @alignCast(@fieldParentPtr("timer", t));
            if (s.closing) return;
            const now = w.now();
            if (now - s.last_active >= p.idle_ms) {
                p.close(w, s);
            } else {
                w.wheel.schedule(&s.timer, s.last_active + p.idle_ms);
            }
        }

        pub fn close(p: *Self, w: *W, s: *Session) void {
            if (s.closing) return;
            s.closing = true;
            w.wheel.cancel(&s.timer);
            if (s.rx_c.isActive()) w.loop.cancel(&s.rx_c);
            p.release(w, s);
        }

        fn release(p: *Self, w: *W, s: *Session) void {
            if (!s.closing or s.rx_c.isActive() or s.timer.active) return;
            if (s.fd != sys.invalid_fd) {
                w.loop.unregister(s.fd);
                sys.close(s.fd);
                s.fd = sys.invalid_fd;
            }
            const idx = p.sessions.indexOfValue(s);
            if (!p.sessions.entry(idx).live) return;
            p.sessions.remove(idx);
        }

        pub fn shutdownAll(p: *Self, w: *W) void {
            var it = p.sessions.iterator();
            while (it.next()) |i| p.close(w, p.sessions.value(i));
        }

        pub fn idle(p: *const Self) bool {
            return p.sessions.len == 0;
        }
    };
}

test "icmp echo reply rebuild keeps checksums valid" {
    var buf: [128]u8 = @splat(0);
    const msg = buf[40..56];
    msg[0] = echo_reply_v4;
    std.mem.writeInt(u16, msg[4..6], 77, .big);
    std.mem.writeInt(u16, msg[6..8], 3, .big);
    @memcpy(msg[8..16], "zeptun!!");
    msg[2] = 0;
    msg[3] = 0;
    const out = buf[20..56];
    _ = ip.writeHeader(out, false, &[_]u8{ 1, 1, 1, 1 }, &[_]u8{ 172, 19, 0, 1 }, parse.proto.icmp, 16, 0);
    checksum.writeNative16(msg[2..4], checksum.finish(checksum.sum(msg, 0)));
    const pkt = try parse.parse(out);
    try std.testing.expect(pkt.l4 == .icmp);
    try std.testing.expect(checksum.verifyIpv4Header(out[0..20]));
    try std.testing.expectEqual(@as(u16, 0xffff), checksum.fold(checksum.sum(msg, 0)));
}
