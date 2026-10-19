const std = @import("std");
const builtin = @import("builtin");
const io = @import("io.zig");
const sys = @import("sys.zig");

const libc = std.c;

const wake_token: usize = std.math.maxInt(usize);
const wake_ident: usize = 0;
const user_event = builtin.target.os.tag != .openbsd;
const msg_dontwait: u32 = libc.MSG.DONTWAIT;
const msg_nosignal: u32 = if (sys.is_darwin) 0 else libc.MSG.NOSIGNAL;
const zero_timeout: libc.timespec = .{ .sec = 0, .nsec = 0 };

fn change(ident: usize, filter: i32, flags: u32, fflags: u32, udata: usize) libc.Kevent {
    var ev = std.mem.zeroes(libc.Kevent);
    ev.ident = ident;
    ev.filter = @intCast(filter);
    ev.flags = @intCast(flags);
    ev.fflags = fflags;
    ev.udata = udata;
    return ev;
}

fn apply(kq: i32, changes: []const libc.Kevent) i32 {
    var out: [1]libc.Kevent = undefined;
    return sys.libcResult(libc.kevent(kq, changes.ptr, @intCast(changes.len), &out, 0, &zero_timeout));
}

fn dataErrno(data: anytype) sys.Errno {
    if (data <= 0 or data > std.math.maxInt(u16)) return .other;
    return sys.mapErrno(@as(libc.E, @fromBackingInt(@intCast(@as(u16, @intCast(data))))));
}

pub const Loop = struct {
    pub const completion_based = false;
    pub const kind: io.BackendKind = .kqueue;

    pub inline fn completionBased(_: *const Loop) bool {
        return completion_based;
    }

    pub const Callback = *const fn (userdata: ?*anyopaque, loop: *Loop, c: *Completion, result: i32) io.Disposition;

    pub const Completion = struct {
        op: io.Operation = .none,
        userdata: ?*anyopaque = null,
        callback: Callback = noopCallback,
        state: io.State = .idle,
        result: i32 = 0,
        connecting: bool = false,
        where: Where = .none,
        next: ?*Completion = null,
        prev: ?*Completion = null,

        pub inline fn isActive(c: *const Completion) bool {
            return c.state != .idle;
        }
    };

    const Where = enum(u8) { none, readers, writers, ready };

    const List = struct {
        head: ?*Completion = null,
        tail: ?*Completion = null,

        fn push(l: *List, c: *Completion) void {
            c.next = null;
            c.prev = l.tail;
            if (l.tail) |t| t.next = c else l.head = c;
            l.tail = c;
        }

        fn remove(l: *List, c: *Completion) void {
            if (c.prev) |p| p.next = c.next else l.head = c.next;
            if (c.next) |n| n.prev = c.prev else l.tail = c.prev;
            c.next = null;
            c.prev = null;
        }

        fn pop(l: *List) ?*Completion {
            const c = l.head orelse return null;
            l.remove(c);
            return c;
        }
    };

    const FdState = struct {
        readers: List = .{},
        writers: List = .{},
        registered: bool = false,
    };

    allocator: std.mem.Allocator,
    kq: i32,
    wake_pipe: [2]sys.fd_t,
    fds: []FdState,
    ready: List = .{},
    active: u32 = 0,
    now_ns: u64,
    events: []libc.Kevent,

    pub fn init(allocator: std.mem.Allocator, options: io.Options) !Loop {
        const kq = libc.kqueue();
        if (kq < 0) return error.SystemResources;
        errdefer _ = libc.close(kq);
        _ = libc.fcntl(kq, libc.F.SETFD, @as(c_int, libc.FD_CLOEXEC));
        var wake_pipe: [2]sys.fd_t = .{ sys.invalid_fd, sys.invalid_fd };
        errdefer {
            sys.close(wake_pipe[0]);
            sys.close(wake_pipe[1]);
        }
        const user_ok = user_event and apply(kq, &.{change(wake_ident, libc.EVFILT.USER, libc.EV.ADD | libc.EV.CLEAR, 0, wake_token)}) >= 0;
        if (!user_ok) {
            wake_pipe = try sys.pipe();
            const ident: usize = @intCast(wake_pipe[0]);
            if (apply(kq, &.{change(ident, libc.EVFILT.READ, libc.EV.ADD | libc.EV.CLEAR, 0, wake_token)}) < 0) return error.SystemResources;
        }
        const fds = try allocator.alloc(FdState, @max(options.max_fds_hint, 64));
        errdefer allocator.free(fds);
        @memset(fds, .{});
        const events = try allocator.alloc(libc.Kevent, @max(options.max_events, 16));
        return .{
            .allocator = allocator,
            .kq = kq,
            .wake_pipe = wake_pipe,
            .fds = fds,
            .now_ns = sys.monotonicNs(),
            .events = events,
        };
    }

    pub fn deinit(loop: *Loop) void {
        _ = libc.close(loop.kq);
        sys.close(loop.wake_pipe[0]);
        sys.close(loop.wake_pipe[1]);
        loop.allocator.free(loop.fds);
        loop.allocator.free(loop.events);
        loop.* = undefined;
    }

    pub fn enable(loop: *Loop) !void {
        _ = loop;
    }

    pub inline fn now(loop: *const Loop) u64 {
        return loop.now_ns / std.time.ns_per_ms;
    }

    pub inline fn nowNs(loop: *const Loop) u64 {
        return loop.now_ns;
    }

    pub fn updateTime(loop: *Loop) void {
        loop.now_ns = sys.monotonicNs();
    }

    pub inline fn pending(loop: *const Loop) u32 {
        return loop.active;
    }

    pub fn wakeup(loop: *Loop) void {
        if (loop.wake_pipe[1] != sys.invalid_fd) {
            const one = [1]u8{1};
            _ = sys.write(loop.wake_pipe[1], &one);
            return;
        }
        if (comptime user_event) {
            _ = apply(loop.kq, &.{change(wake_ident, libc.EVFILT.USER, 0, libc.NOTE.TRIGGER, wake_token)});
        }
    }

    fn drainWake(loop: *Loop) void {
        if (loop.wake_pipe[0] == sys.invalid_fd) return;
        var buf: [64]u8 = undefined;
        while (sys.read(loop.wake_pipe[0], &buf) > 0) {}
    }

    fn state(loop: *Loop, fd: i32) *FdState {
        const idx: usize = @intCast(fd);
        if (idx >= loop.fds.len) {
            var new_len = loop.fds.len * 2;
            while (new_len <= idx) new_len *= 2;
            const grown = loop.allocator.realloc(loop.fds, new_len) catch @panic("kqueue fd table allocation failed");
            @memset(grown[loop.fds.len..], .{});
            loop.fds = grown;
        }
        return &loop.fds[idx];
    }

    pub fn register(loop: *Loop, fd: sys.fd_t) !void {
        if (fd < 0) return error.NotSupported;
        const st = loop.state(fd);
        if (st.registered) return;
        const ident: usize = @intCast(fd);
        const flags = libc.EV.ADD | libc.EV.CLEAR | libc.EV.RECEIPT;
        const changes = [2]libc.Kevent{
            change(ident, libc.EVFILT.READ, flags, 0, ident),
            change(ident, libc.EVFILT.WRITE, flags, 0, ident),
        };
        var receipts: [2]libc.Kevent = undefined;
        const rc = libc.kevent(loop.kq, &changes, changes.len, &receipts, receipts.len, &zero_timeout);
        if (rc < 0) return registerError(sys.mapErrno(libc.errno(rc)));
        for (receipts[0..@intCast(rc)]) |r| {
            if (r.filter != libc.EVFILT.READ or r.flags & libc.EV.ERROR == 0 or r.data == 0) continue;
            return registerError(dataErrno(r.data));
        }
        st.registered = true;
    }

    fn registerError(e: sys.Errno) error{ NotSupported, SystemResources } {
        return switch (e) {
            .perm, .inval, .nodev, .opnotsupp, .nosys, .badf => error.NotSupported,
            else => error.SystemResources,
        };
    }

    pub fn unregister(loop: *Loop, fd: sys.fd_t) void {
        if (fd < 0) return;
        const idx: usize = @intCast(fd);
        if (idx >= loop.fds.len) return;
        const st = &loop.fds[idx];
        loop.failAll(&st.readers);
        loop.failAll(&st.writers);
        if (st.registered) {
            const flags = libc.EV.DELETE | libc.EV.RECEIPT;
            const changes = [2]libc.Kevent{
                change(idx, libc.EVFILT.READ, flags, 0, 0),
                change(idx, libc.EVFILT.WRITE, flags, 0, 0),
            };
            var receipts: [2]libc.Kevent = undefined;
            _ = libc.kevent(loop.kq, &changes, changes.len, &receipts, receipts.len, &zero_timeout);
            st.registered = false;
        }
    }

    fn failAll(loop: *Loop, list: *List) void {
        while (list.pop()) |c| {
            c.result = sys.Errno.canceled.result();
            c.where = .ready;
            loop.ready.push(c);
        }
    }

    pub fn submit(loop: *Loop, c: *Completion) void {
        std.debug.assert(c.state == .idle);
        c.state = .active;
        c.connecting = false;
        loop.active += 1;
        switch (c.op) {
            .none => {
                c.result = 0;
                c.where = .ready;
                loop.ready.push(c);
            },
            .close => |op| {
                loop.unregister(op.fd);
                sys.close(op.fd);
                c.result = 0;
                c.where = .ready;
                loop.ready.push(c);
            },
            else => {
                const r = attempt(c);
                if (r == sys.Errno.again.result()) {
                    loop.wait(c);
                } else {
                    c.result = r;
                    c.where = .ready;
                    loop.ready.push(c);
                }
            },
        }
    }

    fn wait(loop: *Loop, c: *Completion) void {
        const fd = c.op.fd();
        loop.register(fd) catch {
            c.result = sys.Errno.badf.result();
            c.where = .ready;
            loop.ready.push(c);
            return;
        };
        const st = loop.state(fd);
        if (c.op.wantsRead()) {
            c.where = .readers;
            st.readers.push(c);
        } else {
            c.where = .writers;
            st.writers.push(c);
        }
    }

    fn attempt(c: *Completion) i32 {
        return switch (c.op) {
            .none, .close => 0,
            .read => |op| sys.read(op.fd, op.buf),
            .write => |op| sys.write(op.fd, op.buf),
            .writev => |op| sys.writev(op.fd, op.iov),
            .recv => |op| sys.recv(op.fd, op.buf, op.flags | msg_dontwait),
            .send => |op| sys.send(op.fd, op.buf, op.flags | msg_dontwait | msg_nosignal),
            .recvmsg => |op| sys.libcResult(libc.recvmsg(op.fd, op.msg, op.flags | msg_dontwait)),
            .sendmsg => |op| sys.libcResult(libc.sendmsg(op.fd, op.msg, op.flags | msg_dontwait | msg_nosignal)),
            .accept => |op| sys.accept(op.fd, op.peer),
            .connect => |op| blk: {
                if (!c.connecting) {
                    c.connecting = true;
                    const r = sys.connect(op.fd, op.addr);
                    if (sys.toErrno(r) == .inprogress or sys.toErrno(r) == .already) break :blk sys.Errno.again.result();
                    break :blk r;
                }
                const e = sys.socketError(op.fd);
                if (e != .success) break :blk e.result();
                var peer: sys.Sockaddr = .{};
                const pr = sys.getpeername(op.fd, &peer);
                if (sys.toErrno(pr) == .notconn) break :blk sys.Errno.again.result();
                break :blk 0;
            },
            .poll => |op| blk: {
                var mask: i16 = 0;
                if (op.events.in) mask |= libc.POLL.IN;
                if (op.events.out) mask |= libc.POLL.OUT;
                var pfd = [1]libc.pollfd{.{ .fd = op.fd, .events = mask, .revents = 0 }};
                const r = sys.libcResult(libc.poll(&pfd, 1, 0));
                if (r < 0) break :blk r;
                if (r == 0) break :blk sys.Errno.again.result();
                const rev: u32 = @bitCast(@as(i32, pfd[0].revents));
                const ev: io.Events = .{
                    .in = rev & libc.POLL.IN != 0,
                    .out = rev & libc.POLL.OUT != 0,
                    .err = rev & libc.POLL.ERR != 0,
                    .hup = rev & libc.POLL.HUP != 0,
                };
                break :blk @bitCast(@as(u32, @bitCast(ev)));
            },
        };
    }

    pub fn cancel(loop: *Loop, c: *Completion) void {
        if (c.state != .active) return;
        switch (c.where) {
            .readers, .writers => {
                const st = loop.state(c.op.fd());
                if (c.where == .readers) st.readers.remove(c) else st.writers.remove(c);
                c.result = sys.Errno.canceled.result();
                c.where = .ready;
                loop.ready.push(c);
            },
            else => {},
        }
    }

    pub fn cancelFd(loop: *Loop, fd: sys.fd_t) void {
        if (fd < 0) return;
        const idx: usize = @intCast(fd);
        if (idx >= loop.fds.len) return;
        loop.failAll(&loop.fds[idx].readers);
        loop.failAll(&loop.fds[idx].writers);
    }

    fn retry(loop: *Loop, list: *List) void {
        while (list.head) |c| {
            const r = attempt(c);
            if (r == sys.Errno.again.result()) break;
            list.remove(c);
            c.result = r;
            c.where = .ready;
            loop.ready.push(c);
        }
    }

    pub fn run(loop: *Loop, timeout_ns: u64) !void {
        var ts: libc.timespec = zero_timeout;
        const forever = loop.ready.head == null and timeout_ns == std.math.maxInt(u64);
        if (loop.ready.head == null and !forever) {
            ts = .{
                .sec = @intCast(@min(timeout_ns / std.time.ns_per_s, std.math.maxInt(i32))),
                .nsec = @intCast(timeout_ns % std.time.ns_per_s),
            };
        }
        const rc = libc.kevent(loop.kq, loop.events.ptr, 0, loop.events.ptr, @intCast(loop.events.len), if (forever) null else &ts);
        const n: usize = if (rc >= 0) @intCast(rc) else switch (sys.mapErrno(libc.errno(rc))) {
            .intr => 0,
            else => |e| return sys.errnoError(e),
        };
        loop.now_ns = sys.monotonicNs();
        for (loop.events[0..n]) |ev| {
            if (ev.udata == wake_token) {
                loop.drainWake();
                continue;
            }
            const fd: usize = ev.ident;
            if (fd >= loop.fds.len) continue;
            const st = &loop.fds[fd];
            const bad = ev.flags & libc.EV.ERROR != 0;
            if (bad or ev.filter == libc.EVFILT.READ) loop.retry(&st.readers);
            if (bad or ev.filter == libc.EVFILT.WRITE) loop.retry(&st.writers);
        }
        var batch = loop.ready;
        loop.ready = .{};
        while (batch.pop()) |c| {
            c.where = .none;
            c.state = .idle;
            loop.active -= 1;
            if (c.callback(c.userdata, loop, c, c.result) == .rearm and c.state == .idle) loop.submit(c);
        }
    }
};

fn noopCallback(_: ?*anyopaque, _: *Loop, _: *Loop.Completion, _: i32) io.Disposition {
    return .disarm;
}

test "kqueue recv send connect accept" {
    if (!(sys.is_darwin or sys.is_bsd)) return error.SkipZigTest;
    var loop = try Loop.init(std.testing.allocator, .{});
    defer loop.deinit();
    const addr = @import("../addr.zig");
    const lfd = try sys.socket(.v4, .tcp);
    defer sys.close(lfd);
    var sa = sys.Sockaddr.fromEndpoint(try addr.Endpoint.parse("127.0.0.1:0"));
    try std.testing.expect(sys.bind(lfd, &sa) == 0);
    try std.testing.expect(sys.listen(lfd, 8) == 0);
    try std.testing.expect(sys.getsockname(lfd, &sa) == 0);
    const cfd = try sys.socket(.v4, .tcp);
    defer sys.close(cfd);
    const Ctx = struct {
        accepted: i32 = -1,
        connected: ?i32 = null,
        received: usize = 0,
        buf: [32]u8 = undefined,
        fn onAccept(ud: ?*anyopaque, _: *Loop, _: *Loop.Completion, r: i32) io.Disposition {
            const self: *@This() = @ptrCast(@alignCast(ud.?));
            self.accepted = r;
            return .disarm;
        }
        fn onConnect(ud: ?*anyopaque, _: *Loop, _: *Loop.Completion, r: i32) io.Disposition {
            const self: *@This() = @ptrCast(@alignCast(ud.?));
            self.connected = r;
            return .disarm;
        }
        fn onRecv(ud: ?*anyopaque, _: *Loop, _: *Loop.Completion, r: i32) io.Disposition {
            const self: *@This() = @ptrCast(@alignCast(ud.?));
            if (r > 0) self.received += @intCast(r);
            return if (r > 0 and self.received < 11) .rearm else .disarm;
        }
    };
    var ctx: Ctx = .{};
    var ac: Loop.Completion = .{ .op = .{ .accept = .{ .fd = lfd } }, .userdata = &ctx, .callback = Ctx.onAccept };
    var cc: Loop.Completion = .{ .op = .{ .connect = .{ .fd = cfd, .addr = &sa } }, .userdata = &ctx, .callback = Ctx.onConnect };
    loop.submit(&ac);
    loop.submit(&cc);
    var spins: u32 = 0;
    while ((ctx.accepted < 0 or ctx.connected == null) and spins < 100) : (spins += 1) try loop.run(50 * std.time.ns_per_ms);
    try std.testing.expect(ctx.accepted >= 0);
    try std.testing.expectEqual(@as(i32, 0), ctx.connected.?);
    defer sys.close(ctx.accepted);
    var rc: Loop.Completion = .{ .op = .{ .recv = .{ .fd = ctx.accepted, .buf = &ctx.buf } }, .userdata = &ctx, .callback = Ctx.onRecv };
    loop.submit(&rc);
    try loop.run(0);
    try std.testing.expect(sys.send(cfd, "hello ", 0) == 6);
    try std.testing.expect(sys.send(cfd, "world", 0) == 5);
    spins = 0;
    while (ctx.received < 11 and spins < 100) : (spins += 1) try loop.run(50 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 11), ctx.received);
    try std.testing.expectEqual(@as(u32, 0), loop.pending());
}

test "kqueue cancel waiting op and wakeup" {
    if (!(sys.is_darwin or sys.is_bsd)) return error.SkipZigTest;
    var loop = try Loop.init(std.testing.allocator, .{});
    defer loop.deinit();
    var fds: [2]libc.fd_t = undefined;
    try std.testing.expect(libc.socketpair(libc.AF.UNIX, libc.SOCK.STREAM, 0, &fds) == 0);
    defer _ = libc.close(fds[0]);
    defer _ = libc.close(fds[1]);
    try sys.setNonblocking(fds[0]);
    const Ctx = struct {
        result: ?i32 = null,
        buf: [8]u8 = undefined,
        fn onRead(ud: ?*anyopaque, _: *Loop, _: *Loop.Completion, r: i32) io.Disposition {
            const self: *@This() = @ptrCast(@alignCast(ud.?));
            self.result = r;
            return .disarm;
        }
    };
    var ctx: Ctx = .{};
    var c: Loop.Completion = .{ .op = .{ .recv = .{ .fd = fds[0], .buf = &ctx.buf } }, .userdata = &ctx, .callback = Ctx.onRead };
    loop.submit(&c);
    try std.testing.expectEqual(@as(u32, 1), loop.pending());
    loop.cancel(&c);
    try loop.run(0);
    try std.testing.expectEqual(sys.Errno.canceled, sys.toErrno(ctx.result.?));
    loop.wakeup();
    const start = sys.monotonicNs();
    try loop.run(3 * std.time.ns_per_s);
    try std.testing.expect(sys.monotonicNs() - start < std.time.ns_per_s);
}

test "kqueue poll and pipe readiness" {
    if (!(sys.is_darwin or sys.is_bsd)) return error.SkipZigTest;
    var loop = try Loop.init(std.testing.allocator, .{});
    defer loop.deinit();
    const p = try sys.pipe();
    defer sys.close(p[0]);
    defer sys.close(p[1]);
    const Ctx = struct {
        polled: ?i32 = null,
        read: ?i32 = null,
        buf: [8]u8 = undefined,
        fn onPoll(ud: ?*anyopaque, _: *Loop, _: *Loop.Completion, r: i32) io.Disposition {
            const self: *@This() = @ptrCast(@alignCast(ud.?));
            self.polled = r;
            return .disarm;
        }
        fn onRead(ud: ?*anyopaque, _: *Loop, _: *Loop.Completion, r: i32) io.Disposition {
            const self: *@This() = @ptrCast(@alignCast(ud.?));
            self.read = r;
            return .disarm;
        }
    };
    var ctx: Ctx = .{};
    var pc: Loop.Completion = .{ .op = .{ .poll = .{ .fd = p[0], .events = .{ .in = true } } }, .userdata = &ctx, .callback = Ctx.onPoll };
    var rdc: Loop.Completion = .{ .op = .{ .read = .{ .fd = p[0], .buf = &ctx.buf } }, .userdata = &ctx, .callback = Ctx.onRead };
    loop.submit(&pc);
    loop.submit(&rdc);
    try loop.run(0);
    try std.testing.expect(ctx.polled == null and ctx.read == null);
    try std.testing.expectEqual(@as(i32, 3), sys.write(p[1], "abc"));
    var spins: u32 = 0;
    while ((ctx.polled == null or ctx.read == null) and spins < 100) : (spins += 1) try loop.run(50 * std.time.ns_per_ms);
    const ev: io.Events = @bitCast(@as(u32, @bitCast(ctx.polled.?)));
    try std.testing.expect(ev.in);
    try std.testing.expectEqual(@as(i32, 3), ctx.read.?);
    try std.testing.expectEqual(@as(u32, 0), loop.pending());
}
