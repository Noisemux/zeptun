const std = @import("std");
const builtin = @import("builtin");
const zeptun = @import("zeptun");
const micro = @import("micro.zig");
const traffic = @import("traffic.zig");
const socks5_server = @import("socks5_server.zig");
const replay = @import("replay.zig");

const addr = zeptun.addr;

const usage =
    \\usage: zeptun-bench <command> [options]
    \\
    \\  micro [--json F] [--markdown F] [--svg F] [--baseline F] [--max-regression PCT] [--filter S] [--min-ms N]
    \\  tcp-server --listen ADDR:PORT
    \\  tcp-client --connect ADDR:PORT [--streams N] [--seconds S] [--reverse] [--mbps N] [--json F]
    \\  udp-server --listen ADDR:PORT [--echo]
    \\  udp-client --connect ADDR:PORT [--seconds S] [--size BYTES] [--pps N] [--echo] [--gso] [--json F]
    \\  rr-client --connect ADDR:PORT [--socks5 ADDR:PORT] [--conns N] [--seconds S] [--size BYTES] [--crr] [--rate TPS] [--json F]
    \\  conns --connect ADDR:PORT [--count N] [--hold-ms N] [--json F]
    \\  udp-flows --connect ADDR:PORT [--count N] [--hold-ms N] [--json F]
    \\  verify --connect ADDR:PORT [--bytes N] [--seed N] [--json F]
    \\  socks5-server --listen ADDR:PORT [--map-host ADDR] [--user U --pass P] [--max-clients N]
    \\  dns-client --server ADDR:PORT --name NAME [--type A|AAAA] [--count N] [--expect ADDR] [--json F]
    \\  monitor --pid PID [--seconds S] [--interval-ms N] [--json F]
    \\  replay --pcap FILE [--loops N] [--json F]
    \\
;

const Args = struct {
    list: []const []const u8,

    fn value(a: Args, name: []const u8) ?[]const u8 {
        var i: usize = 0;
        while (i + 1 < a.list.len) : (i += 1) {
            if (std.mem.eql(u8, a.list[i], name)) return a.list[i + 1];
        }
        return null;
    }

    fn flag(a: Args, name: []const u8) bool {
        for (a.list) |x| {
            if (std.mem.eql(u8, x, name)) return true;
        }
        return false;
    }

    fn int(a: Args, comptime T: type, name: []const u8, default: T) !T {
        const v = a.value(name) orelse return default;
        return std.fmt.parseInt(T, v, 10) catch error.InvalidArgument;
    }

    fn endpoint(a: Args, name: []const u8) !addr.Endpoint {
        const v = a.value(name) orelse return error.MissingArgument;
        return addr.Endpoint.parse(v) catch error.InvalidArgument;
    }
};

fn writeJson(io: std.Io, path: ?[]const u8, comptime fmt: []const u8, args: anytype) !void {
    const p = path orelse return;
    var buf: [4096]u8 = undefined;
    const text = try std.mem.print(&buf, fmt, args);
    if (std.Io.Dir.path.dirname(p)) |dir| std.Io.Dir.cwd().createDirPath(io, dir) catch {};
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = text });
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const all = try init.minimal.args.toSlice(arena);
    if (all.len < 2) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const cmd = all[1];
    const a: Args = .{ .list = all[2..] };
    const io = init.io;
    if (std.mem.eql(u8, cmd, "micro")) {
        return micro.runAll(arena, io, .{
            .json_path = a.value("--json"),
            .markdown_path = a.value("--markdown"),
            .svg_path = a.value("--svg"),
            .baseline_path = a.value("--baseline"),
            .max_regression_pct = if (a.value("--max-regression")) |v| std.fmt.parseFloat(f64, v) catch 15.0 else 15.0,
            .filter = a.value("--filter"),
            .min_ns = @as(u64, try a.int(u32, "--min-ms", 300)) * std.time.ns_per_ms,
        });
    }
    if (std.mem.eql(u8, cmd, "tcp-server")) {
        try traffic.tcpServer(try a.endpoint("--listen"));
        return 0;
    }
    if (std.mem.eql(u8, cmd, "tcp-client")) {
        const r = try traffic.tcpStream(arena, try a.endpoint("--connect"), try a.int(u32, "--streams", 1), try a.int(u32, "--seconds", 10), a.flag("--reverse"), try a.int(u64, "--mbps", 0));
        std.debug.print("tcp {s} streams={d}: {d:.3} Gbit/s ({d} bytes in {d:.2}s)\n", .{ if (r.reverse) "download" else "upload", r.streams, r.gbps, r.bytes, r.seconds });
        try writeJson(io, a.value("--json"), "{{\"kind\":\"tcp\",\"reverse\":{},\"streams\":{d},\"seconds\":{d:.3},\"bytes\":{d},\"gbps\":{d:.4}}}\n", .{ r.reverse, r.streams, r.seconds, r.bytes, r.gbps });
        return if (r.bytes > 0) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "udp-server")) {
        try traffic.udpServer(try a.endpoint("--listen"), a.flag("--echo"));
        return 0;
    }
    if (std.mem.eql(u8, cmd, "udp-client")) {
        const r = try traffic.udpClient(try a.endpoint("--connect"), try a.int(u32, "--seconds", 10), try a.int(u32, "--size", 64), try a.int(u64, "--pps", 0), a.flag("--echo"), a.flag("--gso"));
        std.debug.print("udp size={d}: sent {d} ({d:.0} pps), received {d}, corrupt {d}\n", .{ r.size, r.sent, r.pps, r.received, r.corrupt });
        try writeJson(io, a.value("--json"), "{{\"kind\":\"udp\",\"size\":{d},\"seconds\":{d:.3},\"sent\":{d},\"received\":{d},\"corrupt\":{d},\"pps\":{d:.1}}}\n", .{ r.size, r.seconds, r.sent, r.received, r.corrupt, r.pps });
        return if (r.sent > 0 and r.corrupt == 0 and (!a.flag("--echo") or r.received > 0)) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "rr-client")) {
        const socks: ?addr.Endpoint = if (a.value("--socks5")) |v| addr.Endpoint.parse(v) catch return error.InvalidArgument else null;
        const r = try traffic.rrClient(arena, try a.endpoint("--connect"), socks, try a.int(u32, "--conns", 1), try a.int(u32, "--seconds", 10), try a.int(u16, "--size", 64), a.flag("--crr"), try a.int(u64, "--rate", 0));
        std.debug.print("rr conns={d} size={d}: {d:.0} tps, p50 {d:.0} us, p90 {d:.0} us, p99 {d:.0} us, p99.9 {d:.0} us, max {d:.0} us, mean {d:.1} us, errors {d}\n", .{ r.conns, r.size, r.tps, r.p50_us, r.p90_us, r.p99_us, r.p999_us, r.max_us, r.mean_us, r.errors });
        try writeJson(io, a.value("--json"), "{{\"kind\":\"rr\",\"conns\":{d},\"size\":{d},\"tps\":{d:.1},\"p50_us\":{d:.1},\"p90_us\":{d:.1},\"p99_us\":{d:.1},\"p999_us\":{d:.1},\"max_us\":{d:.1},\"mean_us\":{d:.2},\"errors\":{d}}}\n", .{ r.conns, r.size, r.tps, r.p50_us, r.p90_us, r.p99_us, r.p999_us, r.max_us, r.mean_us, r.errors });
        return 0;
    }
    if (std.mem.eql(u8, cmd, "conns")) {
        const r = try traffic.connScale(arena, try a.endpoint("--connect"), try a.int(u32, "--count", 1000), try a.int(u32, "--hold-ms", 500));
        std.debug.print("conns: {d}/{d} established, {d} failed, {d:.0} conn/s\n", .{ r.established, r.requested, r.failed, r.rate });
        try writeJson(io, a.value("--json"), "{{\"kind\":\"conns\",\"requested\":{d},\"established\":{d},\"failed\":{d},\"rate\":{d:.1}}}\n", .{ r.requested, r.established, r.failed, r.rate });
        return if (r.failed == 0) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "udp-flows")) {
        const r = try traffic.udpFlows(arena, try a.endpoint("--connect"), try a.int(u32, "--count", 1000), try a.int(u32, "--hold-ms", 500));
        std.debug.print("udp flows: {d}/{d} answered, {d:.0} flows/s\n", .{ r.answered, r.requested, r.rate });
        try writeJson(io, a.value("--json"), "{{\"kind\":\"udp_flows\",\"requested\":{d},\"answered\":{d},\"rate\":{d:.1}}}\n", .{ r.requested, r.answered, r.rate });
        return if (r.answered == r.requested) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "verify")) {
        const total = try a.int(u64, "--bytes", 64 << 20);
        const r = try traffic.verifyEcho(try a.endpoint("--connect"), total, try a.int(u64, "--seed", 0x9e3779b97f4a7c15));
        std.debug.print("verify: {s} {d} bytes echoed in {d:.2}s ({d:.3} Gbit/s)\n", .{ if (r.ok) "OK" else "CORRUPT", r.bytes, r.seconds, r.gbps });
        try writeJson(io, a.value("--json"), "{{\"kind\":\"verify\",\"ok\":{},\"bytes\":{d},\"gbps\":{d:.4}}}\n", .{ r.ok, r.bytes, r.gbps });
        return if (r.ok) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "dns-client")) {
        const name = a.value("--name") orelse return error.MissingArgument;
        const aaaa = if (a.value("--type")) |t| std.ascii.eqlIgnoreCase(t, "AAAA") else false;
        const r = try traffic.dnsClient(try a.endpoint("--server"), name, aaaa, try a.int(u32, "--count", 1));
        if (r.answer) |ans| {
            std.debug.print("dns {s}: {f} rcode {d}, {d}/{d} replies, p50 {d:.0} us, p99 {d:.0} us, mean {d:.1} us\n", .{ name, ans, r.rcode, r.replies, r.queries, r.p50_us, r.p99_us, r.mean_us });
        } else {
            std.debug.print("dns {s}: no address rcode {d}, {d}/{d} replies, p50 {d:.0} us, p99 {d:.0} us, mean {d:.1} us\n", .{ name, r.rcode, r.replies, r.queries, r.p50_us, r.p99_us, r.mean_us });
        }
        try writeJson(io, a.value("--json"), "{{\"kind\":\"dns\",\"queries\":{d},\"replies\":{d},\"p50_us\":{d:.1},\"p99_us\":{d:.1},\"mean_us\":{d:.2}}}\n", .{ r.queries, r.replies, r.p50_us, r.p99_us, r.mean_us });
        if (a.value("--expect")) |want| {
            const w = addr.Address.parse(want) catch return error.InvalidArgument;
            return if (r.answer != null and r.answer.?.eql(w)) 0 else 1;
        }
        return if (r.replies == r.queries and r.answer != null) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "socks5-server")) {
        try socks5_server.run(.{
            .listen = try a.endpoint("--listen"),
            .map_host = if (a.value("--map-host")) |m| addr.Address.parse(m) catch return error.InvalidArgument else null,
            .max_clients = try a.int(u32, "--max-clients", 0),
            .username = a.value("--user") orelse "",
            .password = a.value("--pass") orelse "",
        });
        return 0;
    }
    if (std.mem.eql(u8, cmd, "replay")) {
        const path = a.value("--pcap") orelse return error.MissingArgument;
        const data = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(if (@bitSizeOf(usize) >= 64) 4 << 30 else 512 << 20));
        const r = try replay.run(arena, data, try a.int(u32, "--loops", 1));
        const rate = @as(f64, @floatFromInt(r.records)) / @max(r.seconds, 1e-9);
        std.debug.print("replay: {d} records ({d} bytes), tcp {d}, udp {d}, icmp {d}, other {d}, truncated {d}, malformed {d}, bad checksum {d} (repaired {d}), rewrites {d}, coalesced {d}, segments {d}, failures {d}, {d:.0} records/s\n", .{ r.records, r.bytes, r.tcp, r.udp, r.icmp, r.other, r.truncated, r.malformed, r.bad_checksum, r.repaired, r.rewrites, r.coalesced, r.segments, r.failures, rate });
        try writeJson(io, a.value("--json"), "{{\"kind\":\"replay\",\"records\":{d},\"tcp\":{d},\"udp\":{d},\"truncated\":{d},\"malformed\":{d},\"bad_checksum\":{d},\"coalesced\":{d},\"segments\":{d},\"failures\":{d},\"records_per_sec\":{d:.1}}}\n", .{ r.records, r.tcp, r.udp, r.truncated, r.malformed, r.bad_checksum, r.coalesced, r.segments, r.failures, rate });
        return if (r.failures == 0) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "monitor")) {
        const pid = try a.int(i32, "--pid", 0);
        const r = try traffic.monitor(pid, try a.int(u32, "--seconds", 10), try a.int(u32, "--interval-ms", 1000));
        std.debug.print("monitor pid={d}: avg cpu {d:.1}%, max cpu {d:.1}%, max rss {d} KB, peak hwm {d} KB, max pss {d} KB\n", .{ pid, r.avg_cpu_pct, r.max_cpu_pct, r.max_rss_kb, r.peak_hwm_kb, r.max_pss_kb });
        try writeJson(io, a.value("--json"), "{{\"kind\":\"monitor\",\"samples\":{d},\"avg_cpu_pct\":{d:.2},\"max_cpu_pct\":{d:.2},\"max_rss_kb\":{d},\"peak_hwm_kb\":{d},\"max_pss_kb\":{d}}}\n", .{ r.samples, r.avg_cpu_pct, r.max_cpu_pct, r.max_rss_kb, r.peak_hwm_kb, r.max_pss_kb });
        return 0;
    }
    std.debug.print("{s}", .{usage});
    return 2;
}

test {
    _ = traffic;
    _ = replay;
}
