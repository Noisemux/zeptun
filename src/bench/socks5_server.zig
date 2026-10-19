const std = @import("std");
const zeptun = @import("zeptun");

const sys = zeptun.io.sys;
const addr = zeptun.addr;
const socks5 = zeptun.handler.socks5;
const traffic = @import("traffic.zig");
const linux = std.os.linux;

pub const Options = struct {
    listen: addr.Endpoint,
    map_host: ?addr.Address = null,
    username: []const u8 = "",
    password: []const u8 = "",
    max_clients: u32 = 0,
};

const Server = struct {
    opts: Options,
    live: std.atomic.Value(u32) = .init(0),
    refused: std.atomic.Value(u32) = .init(0),
};

fn readFull(fd: i32, buf: []u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const n = sys.linuxResult(linux.read(fd, buf[off..].ptr, buf.len - off));
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

fn writeFull(fd: i32, buf: []const u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const n = sys.linuxResult(linux.sendto(fd, buf[off..].ptr, buf.len - off, linux.MSG.NOSIGNAL, null, 0));
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

pub fn run(opts: Options) !void {
    const lfd = try traffic.listenTcp(opts.listen, 4096);
    std.debug.print("socks5-server listening on {f}\n", .{opts.listen});
    const server = try std.heap.page_allocator.create(Server);
    server.* = .{ .opts = opts };
    while (true) {
        const fd = sys.linuxResult(linux.accept4(lfd, null, null, linux.SOCK.CLOEXEC));
        if (fd < 0) continue;
        if (opts.max_clients != 0 and server.live.load(.acquire) >= opts.max_clients) {
            const refused = server.refused.fetchAdd(1, .monotonic) + 1;
            if (refused % 16 == 1) std.debug.print("socks5-server: at the client limit, refused {d}\n", .{refused});
            sys.close(fd);
            continue;
        }
        _ = server.live.fetchAdd(1, .monotonic);
        const t = std.Thread.spawn(.{ .stack_size = 512 * 1024 }, session, .{ server, fd }) catch {
            _ = server.live.fetchSub(1, .monotonic);
            sys.close(fd);
            continue;
        };
        t.detach();
    }
}

fn reply(fd: i32, code: u8, bound: addr.Endpoint) void {
    var buf: [32]u8 = undefined;
    buf[0] = 5;
    buf[1] = code;
    buf[2] = 0;
    const n = socks5.encodeAddress(buf[3..], bound);
    _ = writeFull(fd, buf[0 .. 3 + n]);
}

fn session(server: *Server, fd: i32) void {
    var keep = false;
    defer {
        if (!keep) sys.close(fd);
        _ = server.live.fetchSub(1, .monotonic);
    }
    _ = sys.setsockoptInt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, 1);
    var hdr: [2]u8 = undefined;
    if (!readFull(fd, &hdr) or hdr[0] != 5) return;
    var methods: [255]u8 = undefined;
    if (!readFull(fd, methods[0..hdr[1]])) return;
    const want_auth = server.opts.username.len > 0;
    const method: u8 = if (want_auth) 2 else 0;
    if (std.mem.findScalar(u8, methods[0..hdr[1]], method) == null) {
        _ = writeFull(fd, &[_]u8{ 5, 0xff });
        return;
    }
    if (!writeFull(fd, &[_]u8{ 5, method })) return;
    if (want_auth) {
        var ah: [2]u8 = undefined;
        if (!readFull(fd, &ah) or ah[0] != 1) return;
        var user: [255]u8 = undefined;
        if (!readFull(fd, user[0..ah[1]])) return;
        var pl: [1]u8 = undefined;
        if (!readFull(fd, &pl)) return;
        var pass: [255]u8 = undefined;
        if (!readFull(fd, pass[0..pl[0]])) return;
        const ok = std.mem.eql(u8, user[0..ah[1]], server.opts.username) and std.mem.eql(u8, pass[0..pl[0]], server.opts.password);
        if (!writeFull(fd, &[_]u8{ 1, if (ok) 0 else 1 }) or !ok) return;
    }
    var req: [4]u8 = undefined;
    if (!readFull(fd, &req) or req[0] != 5) return;
    var target: addr.Endpoint = .{};
    switch (req[3]) {
        1 => {
            var b: [6]u8 = undefined;
            if (!readFull(fd, &b)) return;
            target = .{ .addr = addr.Address.v4(b[0..4].*), .port = std.mem.readInt(u16, b[4..6], .big) };
        },
        4 => {
            var b: [18]u8 = undefined;
            if (!readFull(fd, &b)) return;
            target = .{ .addr = addr.Address.v6(b[0..16].*), .port = std.mem.readInt(u16, b[16..18], .big) };
        },
        3 => {
            var l: [1]u8 = undefined;
            if (!readFull(fd, &l)) return;
            var b: [257]u8 = undefined;
            if (!readFull(fd, b[0 .. @as(usize, l[0]) + 2])) return;
            target.port = std.mem.readInt(u16, b[l[0]..][0..2], .big);
            if (server.opts.map_host) |m| {
                target.addr = m;
            } else {
                target.addr = addr.Address.parse(b[0..l[0]]) catch {
                    reply(fd, 4, .{});
                    return;
                };
            }
        },
        else => {
            reply(fd, 8, .{});
            return;
        },
    }
    if (server.opts.map_host) |m| {
        if (req[1] == 1) target.addr = m;
    }
    switch (req[1]) {
        1 => {
            const up = traffic.connectTcp(target) catch {
                reply(fd, 5, .{});
                return;
            };
            reply(fd, 0, .{ .addr = addr.Address.v4(@splat(0)), .port = 0 });
            relay(fd, up);
        },
        3 => {
            keep = true;
            udpAssociate(server, fd, target.addr.family);
        },
        5 => forwardUdp(server, fd, target.addr.family),
        else => reply(fd, 7, .{}),
    }
}

fn forwardUdp(server: *Server, ctrl: i32, family: addr.Family) void {
    const af: u32 = if (family == .v6) linux.AF.INET6 else linux.AF.INET;
    const ufd = sys.linuxResult(linux.socket(af, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0));
    if (ufd < 0) return reply(ctrl, 1, .{});
    defer sys.close(ufd);
    reply(ctrl, 0, .{});
    var stream: [70000]u8 = undefined;
    var have: usize = 0;
    var dgram: [65536]u8 = undefined;
    var fds = [2]linux.pollfd{
        .{ .fd = ctrl, .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = ufd, .events = linux.POLL.IN, .revents = 0 },
    };
    while (true) {
        const r = sys.linuxResult(linux.poll(&fds, 2, 60_000));
        if (r <= 0) return;
        if (fds[0].revents != 0) {
            const n = sys.linuxResult(linux.read(ctrl, stream[have..].ptr, stream.len - have));
            if (n <= 0) return;
            have += @intCast(n);
            var off: usize = 0;
            while (true) {
                const f = socks5.parseFrame(stream[off..have]) catch |err| switch (err) {
                    error.NeedMore => break,
                    else => return,
                };
                if (have - off < f.total) break;
                var dst = f.src orelse addr.Endpoint{ .addr = server.opts.map_host orelse return, .port = f.port };
                if (server.opts.map_host) |m| dst.addr = m;
                var dsa = sys.Sockaddr.fromEndpoint(dst);
                _ = sys.sendto(ufd, stream[off + f.header_len .. off + f.total], 0, &dsa);
                off += f.total;
            }
            @memmove(stream[0 .. have - off], stream[off..have]);
            have -= off;
        }
        if (fds[1].revents & linux.POLL.IN != 0) {
            var from: sys.Sockaddr = .{};
            const n = sys.recvfrom(ufd, &dgram, 0, &from);
            if (n <= 0) continue;
            const from_ep = from.toEndpoint() orelse continue;
            var hdr: [socks5.max_frame_header]u8 = undefined;
            const hl = socks5.encodeFrameHeader(&hdr, .{ .ip = from_ep }, @intCast(n));
            if (!writeFull(ctrl, hdr[0..hl]) or !writeFull(ctrl, dgram[0..@intCast(n)])) return;
        }
    }
}

const Pipe = struct {
    src: i32,
    dst: i32,
    fn run(p: Pipe) void {
        var fds: [2]i32 = undefined;
        const use_splice = sys.linuxResult(linux.pipe2(&fds, .{ .CLOEXEC = true })) == 0;
        if (use_splice) {
            _ = linux.fcntl(fds[1], linux.F.SETPIPE_SZ, 1 << 20);
            defer sys.close(fds[0]);
            defer sys.close(fds[1]);
            while (true) {
                const n = sys.linuxResult(linux.syscall6(.splice, @as(usize, @bitCast(@as(isize, p.src))), 0, @as(usize, @bitCast(@as(isize, fds[1]))), 0, 1 << 20, 1));
                if (n <= 0) break;
                var left: usize = @intCast(n);
                while (left > 0) {
                    const m = sys.linuxResult(linux.syscall6(.splice, @as(usize, @bitCast(@as(isize, fds[0]))), 0, @as(usize, @bitCast(@as(isize, p.dst))), 0, left, 1));
                    if (m <= 0) {
                        _ = sys.shutdown(p.src, .read);
                        _ = sys.shutdown(p.dst, .write);
                        return;
                    }
                    left -= @intCast(m);
                }
            }
        } else {
            var buf: [256 * 1024]u8 = undefined;
            while (true) {
                const n = sys.linuxResult(linux.read(p.src, &buf, buf.len));
                if (n <= 0 or !writeFull(p.dst, buf[0..@intCast(n)])) break;
            }
        }
        _ = sys.shutdown(p.dst, .write);
    }
};

fn relay(client: i32, upstream: i32) void {
    const t = std.Thread.spawn(.{ .stack_size = 512 * 1024 }, Pipe.run, .{Pipe{ .src = upstream, .dst = client }}) catch {
        sys.close(upstream);
        return;
    };
    Pipe.run(.{ .src = client, .dst = upstream });
    t.join();
    sys.close(upstream);
}

fn udpAssociate(server: *Server, ctrl: i32, family: addr.Family) void {
    defer sys.close(ctrl);
    const af: u32 = if (family == .v6) linux.AF.INET6 else linux.AF.INET;
    const ufd = sys.linuxResult(linux.socket(af, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0));
    if (ufd < 0) return reply(ctrl, 1, .{});
    defer sys.close(ufd);
    var local: sys.Sockaddr = .{};
    _ = sys.getsockname(ctrl, &local);
    var bind_ep = local.toEndpoint() orelse addr.Endpoint{};
    if (bind_ep.addr.family != family) bind_ep.addr = if (family == .v6) addr.Address.v6(@splat(0)) else addr.Address.v4(@splat(0));
    bind_ep.port = 0;
    var bsa = sys.Sockaddr.fromEndpoint(bind_ep);
    if (sys.bind(ufd, &bsa) < 0) return reply(ctrl, 1, .{});
    _ = sys.getsockname(ufd, &bsa);
    reply(ctrl, 0, bsa.toEndpoint() orelse .{});
    var client_addr: ?sys.Sockaddr = null;
    var buf: [65536]u8 = undefined;
    var fds = [2]linux.pollfd{
        .{ .fd = ctrl, .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = ufd, .events = linux.POLL.IN, .revents = 0 },
    };
    while (true) {
        const r = sys.linuxResult(linux.poll(&fds, 2, 60_000));
        if (r <= 0) return;
        if (fds[0].revents != 0) return;
        if (fds[1].revents & linux.POLL.IN == 0) continue;
        var from: sys.Sockaddr = .{};
        const n = sys.recvfrom(ufd, &buf, 0, &from);
        if (n <= 0) continue;
        const data = buf[0..@intCast(n)];
        const from_ep = from.toEndpoint() orelse continue;
        const is_client = if (client_addr) |ca| (ca.toEndpoint() orelse addr.Endpoint{}).eql(from_ep) else true;
        if (is_client) {
            if (client_addr == null) client_addr = from;
            const p = socks5.parseUdpHeader(data) catch continue;
            var dst = p.src orelse addr.Endpoint{ .addr = server.opts.map_host orelse continue, .port = p.port };
            if (server.opts.map_host) |m| dst.addr = m;
            var dsa = sys.Sockaddr.fromEndpoint(dst);
            _ = sys.sendto(ufd, data[p.header_len..], 0, &dsa);
        } else {
            var out: [65536 + 32]u8 = undefined;
            const hl = socks5.encodeUdpHeader(&out, from_ep);
            @memcpy(out[hl..][0..data.len], data);
            if (client_addr) |*ca| _ = sys.sendto(ufd, out[0 .. hl + data.len], 0, ca);
        }
    }
}
