const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config.zig");
const addr = @import("../addr.zig");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");

pub const supported = sys.is_linux and !sys.is_android;

const paths = [_][:0]const u8{ "/usr/bin/resolvectl", "/bin/resolvectl", "/usr/sbin/resolvectl" };
const env = [_:null]?[*:0]const u8{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"};

const stub = "127.0.0.53";
const stub_wait_ms: i32 = 100;

fn ownsResolved() bool {
    if (comptime !supported) return false;
    const ep = addr.Endpoint{ .addr = addr.Address.parse(stub) catch return false, .port = 53 };
    const sa = sys.Sockaddr.fromEndpoint(ep);
    const fd = sys.socket(.v4, .tcp) catch return false;
    defer sys.close(fd);
    const r = sys.connect(fd, &sa);
    if (r == 0) return true;
    if (sys.toErrno(r) != .inprogress) return false;
    var fds = [_]std.os.linux.pollfd{.{ .fd = fd, .events = std.os.linux.POLL.OUT, .revents = 0 }};
    if (sys.linuxResult(std.os.linux.poll(&fds, 1, stub_wait_ms)) <= 0) return false;
    return sys.socketError(fd) == .success;
}

fn tool() ?[:0]const u8 {
    if (comptime !supported) return null;
    if (!sys.fileExists("/run/systemd/resolve/resolv.conf")) return null;
    if (!ownsResolved()) return null;
    for (paths) |p| {
        if (sys.fileExecutable(p)) return p;
    }
    return null;
}

const wait_ms: u64 = 2000;

fn run(exe: [:0]const u8, args: []const [*:0]const u8) bool {
    if (comptime !supported) return false;
    const linux = std.os.linux;
    var argv: [8:null]?[*:0]const u8 = @splat(null);
    if (args.len + 1 >= argv.len) return false;
    argv[0] = exe.ptr;
    for (args, 1..) |a, i| argv[i] = a;
    const pid = sys.linuxResult(linux.fork());
    if (pid < 0) return false;
    if (pid == 0) {
        _ = linux.execve(exe.ptr, &argv, &env);
        linux.exit_group(127);
    }
    const deadline = sys.monotonicMs() + wait_ms;
    var status: u32 = 0;
    while (true) {
        const r = sys.linuxResult(linux.wait4(pid, &status, linux.W.NOHANG, null));
        if (r > 0) break;
        if (r < 0 and sys.toErrno(r) != .intr) return false;
        if (sys.monotonicMs() >= deadline) {
            _ = linux.kill(pid, linux.SIG.KILL);
            _ = sys.linuxResult(linux.wait4(pid, &status, 0, null));
            log.warn("route: resolvectl did not answer within {d} ms", .{wait_ms});
            return false;
        }
        sys.sleepMs(2);
    }
    return status & 0x7f == 0 and (status >> 8) & 0xff == 0;
}

pub fn apply(cfg: *const config.Config, ifname: []const u8) bool {
    if (comptime !supported) return false;
    if (!cfg.dnsActive() or cfg.dns_resolved == .off) return false;
    if (cfg.dns_resolved == .auto and !cfg.route.auto_route) return false;
    const exe = tool() orelse return false;
    var name: [16:0]u8 = @splat(0);
    if (ifname.len >= name.len) return false;
    @memcpy(name[0..ifname.len], ifname);
    var servers: [2][64:0]u8 = @splat(@splat(0));
    var args: [4][*:0]const u8 = undefined;
    var n: usize = 2;
    args[0] = "dns";
    args[1] = &name;
    if (cfg.dnsAddress4()) |a| {
        if (format(&servers[n - 2], a)) |s| {
            args[n] = s;
            n += 1;
        }
    }
    if (cfg.dnsAddress6()) |a| {
        if (format(&servers[n - 2], a)) |s| {
            args[n] = s;
            n += 1;
        }
    }
    if (n == 2) return false;
    if (!run(exe, args[0..n])) {
        log.warn("route: handing DNS to systemd-resolved failed, queries to 127.0.0.53 keep going to its own upstream servers", .{});
        return false;
    }
    _ = run(exe, &.{ "domain", &name, "~." });
    _ = run(exe, &.{ "default-route", &name, "true" });
    log.info("route: systemd-resolved now sends every domain to {s}", .{ifname});
    return true;
}

pub fn revert(ifname: []const u8) void {
    if (comptime !supported) return;
    const exe = tool() orelse return;
    var name: [16:0]u8 = @splat(0);
    if (ifname.len >= name.len) return;
    @memcpy(name[0..ifname.len], ifname);
    _ = run(exe, &.{ "revert", &name });
}

fn format(buf: *[64:0]u8, a: addr.Address) ?[*:0]const u8 {
    var stream = std.Io.Writer.fixed(buf[0..]);
    stream.print("{f}", .{a}) catch return null;
    const len = stream.end;
    if (len >= buf.len) return null;
    buf[len] = 0;
    return buf;
}

test "resolved formats addresses" {
    var buf: [64:0]u8 = @splat(0);
    const a = try addr.Address.parse("172.19.0.2");
    const out = format(&buf, a).?;
    try std.testing.expectEqualStrings("172.19.0.2", std.mem.sliceTo(out, 0));
}

test "resolved runs a tool and reports its exit status" {
    if (comptime !supported) return;
    if (!sys.fileExecutable("/bin/true") or !sys.fileExecutable("/bin/false")) return;
    try std.testing.expect(run("/bin/true", &.{}));
    try std.testing.expect(!run("/bin/false", &.{}));
}
