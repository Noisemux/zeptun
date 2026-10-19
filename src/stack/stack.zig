const std = @import("std");
const build_options = @import("build_options");
const config = @import("../config.zig");
const parse = @import("../packet/parse.zig");
const pool = @import("../packet/pool.zig");
const gso = @import("../packet/gso.zig");
const checksum = @import("../packet/checksum.zig");
const timeouts = @import("../flow/timeouts.zig");
pub const ip = @import("ip.zig");
pub const icmp = @import("icmp.zig");
pub const udp = @import("udp.zig");
pub const tcp = @import("tcp.zig");
pub const system = @import("system.zig");
pub const dns = @import("dns.zig");
pub const relay = @import("relay.zig");
pub const ping = @import("ping.zig");
pub const redirect = @import("redirect.zig");

pub fn dispatch(w: anytype, b: *pool.Buffer, vh: gso.VirtioNetHdr) void {
    const W = @TypeOf(w.*);
    if (W.has_passthrough and w.cfg.handler.kind == .passthrough) {
        if (w.passthrough) |*p| p.onPacket(w, b, vh) else w.pool.put(b);
        return;
    }
    const data = b.bytes();
    const pkt = parse.parse(data) catch {
        w.counters.inc(.parse_errors);
        w.pool.put(b);
        return;
    };
    if (pkt.ip.isV6() and !build_options.enable_ipv6) {
        w.pool.put(b);
        return;
    }
    if (pkt.ip.isFragment()) {
        if (!build_options.enable_fragments) {
            w.pool.put(b);
            return;
        }
        const whole = w.reasm.insert(&w.wheel, &w.pool, w.now(), b, pkt, @backingInt(timeouts.Kind.frag_expire)) orelse return;
        w.counters.inc(.fragments_reassembled);
        const full = parse.parse(whole.bytes()) catch {
            w.pool.put(whole);
            return;
        };
        return deliver(w, whole, .{}, full);
    }
    if (w.cfg.stack.verify_checksums and !vh.needsCsum()) {
        if (pkt.l4 != .other and !parse.l4ChecksumValid(data, pkt)) {
            w.counters.inc(.parse_errors);
            w.pool.put(b);
            return;
        }
    }
    deliver(w, b, vh, pkt);
}

fn deliver(w: anytype, b: *pool.Buffer, vh: gso.VirtioNetHdr, pkt: parse.Packet) void {
    const W = @TypeOf(w.*);
    if (build_options.enable_icmp and pkt.ip.ttl <= 1) {
        if (icmp.expired(w, b, pkt)) {
            w.counters.inc(.icmp_time_exceeded);
            w.pool.put(b);
            return;
        }
    }
    switch (pkt.l4) {
        .tcp => {
            if (W.has_system) {
                if (w.system) |*sy| if (sy.handles(pkt.ip.isV6())) {
                    if (sy.input(w, b, vh, pkt)) return;
                    if (w.cfg.stack.mode == .system or !W.has_userspace_tcp) {
                        w.pool.put(b);
                        return;
                    }
                };
            }
            if (W.has_userspace_tcp) {
                w.tcp.input(w, b, vh, pkt);
            } else {
                w.pool.put(b);
            }
        },
        .udp => w.udp.input(w, b, vh, pkt),
        .icmp => {
            if (build_options.enable_icmp) icmp.input(w, b, pkt) else w.pool.put(b);
        },
        .other => w.pool.put(b),
    }
}
