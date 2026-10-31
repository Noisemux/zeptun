const std = @import("std");
const linux = std.os.linux;
const io = @import("io.zig");
const sys = @import("sys.zig");

pub fn probe() bool {
    var params = std.mem.zeroes(linux.io_uring_params);
    const rc = linux.io_uring_setup(2, &params);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

const tag_cancel: u64 = 1;
const tag_timeout: u64 = 2;
const tag_mask: u64 = 7;

const setup_attempts = [_]u32{
    linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN | linux.IORING_SETUP_SUBMIT_ALL,
    linux.IORING_SETUP_COOP_TASKRUN | linux.IORING_SETUP_SUBMIT_ALL,
    0,
};

pub const BufferRing = struct {
    ring: *align(std.heap.page_size_min) linux.io_uring_buf_ring,
    entries: u16,
    group: u16,
    pending: u16 = 0,

    pub fn add(br: *BufferRing, buf: []u8, bid: u16) void {
        linux.IoUring.buf_ring_add(br.ring, buf, bid, br.entries - 1, br.pending);
        br.pending += 1;
    }

    pub fn commit(br: *BufferRing) void {
        if (br.pending == 0) return;
        linux.IoUring.buf_ring_advance(br.ring, br.pending);
        br.pending = 0;
    }
};

pub fn Impl(comptime Outer: type) type {
    return struct {
        const Loop = @This();
        const Completion = Outer.Completion;

        inline fn outer(loop: *Loop) *Outer {
            return @alignCast(@fieldParentPtr("uring", loop));
        }

        const List = struct {
            head: ?*Completion = null,
            tail: ?*Completion = null,

            fn push(l: *List, c: *Completion) void {
                c.next = null;
                if (l.tail) |t| t.next = c else l.head = c;
                l.tail = c;
            }

            fn pop(l: *List) ?*Completion {
                const c = l.head orelse return null;
                l.head = c.next;
                if (l.head == null) l.tail = null;
                c.next = null;
                return c;
            }

            fn remove(l: *List, target: *Completion) bool {
                var prev: ?*Completion = null;
                var cur = l.head;
                while (cur) |c| : (cur = c.next) {
                    if (c == target) {
                        if (prev) |p| p.next = c.next else l.head = c.next;
                        if (l.tail == c) l.tail = prev;
                        c.next = null;
                        return true;
                    }
                    prev = c;
                }
                return false;
            }
        };

        const Local = struct {
            c: *Completion,
            result: i32,
        };

        ring: linux.IoUring,
        backlog: List = .{},
        local: List = .{},
        active: u32 = 0,
        now_ns: u64 = 0,
        wake_fd: i32,
        wake_c: Completion = .{},
        wake_value: u64 = 0,
        wake_armed: bool = false,
        fixed: [32]i32 = @splat(-1),
        fixed_count: u32 = 0,
        ext_arg: bool,
        timeout_armed: bool = false,
        timeout_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
        cqes: [1024]linux.io_uring_cqe = undefined,
        setup_flags: u32 = 0,

        pub fn init(allocator: std.mem.Allocator, options: io.Options) !Loop {
            _ = allocator;
            const entries = std.math.ceilPowerOfTwo(u16, @max(options.entries, 8)) catch 4096;
            var ring: linux.IoUring = undefined;
            var chosen: u32 = 0;
            var last_err: anyerror = error.SystemOutdated;
            const ok = for (setup_attempts) |base| {
                var flags = base | linux.IORING_SETUP_CQSIZE;
                if (options.defer_enable) flags |= linux.IORING_SETUP_R_DISABLED;
                if (options.sqpoll) {
                    flags = (flags & ~@as(u32, linux.IORING_SETUP_DEFER_TASKRUN | linux.IORING_SETUP_COOP_TASKRUN)) | linux.IORING_SETUP_SQPOLL;
                    if (options.sqpoll_cpu != null) flags |= linux.IORING_SETUP_SQ_AFF;
                }
                var params = std.mem.zeroInit(linux.io_uring_params, .{
                    .flags = flags,
                    .sq_thread_idle = options.sqpoll_idle_ms,
                    .sq_thread_cpu = options.sqpoll_cpu orelse 0,
                    .cq_entries = @as(u32, entries) * 4,
                });
                if (linux.IoUring.init_params(entries, &params)) |r| {
                    ring = r;
                    chosen = flags;
                    break true;
                } else |err| {
                    last_err = err;
                    if (err != error.ArgumentsInvalid) return err;
                }
            } else false;
            if (!ok) return last_err;
            errdefer ring.deinit();
            const efd_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
            if (linux.errno(efd_rc) != .SUCCESS) return error.SystemResources;
            return .{
                .ring = ring,
                .wake_fd = @intCast(efd_rc),
                .ext_arg = ring.features & linux.IORING_FEAT_EXT_ARG != 0,
                .setup_flags = chosen,
                .now_ns = sys.monotonicNs(),
            };
        }

        pub fn deinit(loop: *Loop) void {
            loop.ring.deinit();
            _ = linux.close(loop.wake_fd);
            loop.* = undefined;
        }

        pub fn enable(loop: *Loop) !void {
            if (loop.setup_flags & linux.IORING_SETUP_R_DISABLED == 0) return;
            const rc = linux.io_uring_register(loop.ring.fd, .REGISTER_ENABLE_RINGS, null, 0);
            if (linux.errno(rc) != .SUCCESS) return error.SystemResources;
            loop.setup_flags &= ~@as(u32, linux.IORING_SETUP_R_DISABLED);
        }

        pub inline fn now(loop: *const Loop) u64 {
            return loop.now_ns / std.time.ns_per_ms;
        }

        pub inline fn nowNs(loop: *const Loop) u64 {
            return loop.now_ns;
        }

        pub fn setupBufferRing(loop: *Loop, entries: u16, group: u16) !BufferRing {
            const br = try linux.IoUring.setup_buf_ring(loop.ring.fd, entries, group, .{ .inc = false });
            linux.IoUring.buf_ring_init(br);
            return .{ .ring = br, .entries = entries, .group = group };
        }

        pub fn freeBufferRing(loop: *Loop, br: *BufferRing) void {
            linux.IoUring.free_buf_ring(loop.ring.fd, br.ring, br.entries, br.group);
        }

        pub fn updateTime(loop: *Loop) void {
            loop.now_ns = sys.monotonicNs();
        }

        pub fn register(loop: *Loop, fd: sys.fd_t) !void {
            _ = loop;
            _ = fd;
        }

        pub fn unregister(loop: *Loop, fd: sys.fd_t) void {
            _ = loop;
            _ = fd;
        }

        pub fn registerFixed(loop: *Loop, fds: []const sys.fd_t) !void {
            if (fds.len > loop.fixed.len) return error.LimitExceeded;
            try loop.ring.register_files(fds);
            for (fds, 0..) |fd, i| loop.fixed[i] = fd;
            loop.fixed_count = @intCast(fds.len);
        }

        inline fn fixedIndex(loop: *const Loop, fd: sys.fd_t) ?u32 {
            var i: u32 = 0;
            while (i < loop.fixed_count) : (i += 1) {
                if (loop.fixed[i] == fd) return i;
            }
            return null;
        }

        pub fn wakeup(loop: *Loop) void {
            const one: u64 = 1;
            _ = linux.write(loop.wake_fd, std.mem.asBytes(&one), 8);
        }

        fn armWake(loop: *Loop) void {
            if (loop.wake_armed) return;
            loop.wake_c = .{
                .op = .{ .read = .{ .fd = loop.wake_fd, .buf = std.mem.asBytes(&loop.wake_value) } },
                .callback = wakeCallback,
            };
            loop.wake_armed = true;
            loop.submitInternal(&loop.wake_c);
        }

        fn wakeCallback(_: ?*anyopaque, o: *Outer, c: *Completion, result: i32) io.Disposition {
            _ = c;
            const loop = &o.uring;
            if (sys.toErrno(result) == .canceled) {
                loop.wake_armed = false;
                return .disarm;
            }
            return .rearm;
        }

        pub fn submit(loop: *Loop, c: *Completion) void {
            std.debug.assert(c.state == .idle);
            if (!loop.wake_armed) loop.armWake();
            loop.submitInternal(c);
        }

        fn submitInternal(loop: *Loop, c: *Completion) void {
            c.state = .queued;
            loop.active += 1;
            const sqe = loop.getSqe() orelse {
                loop.backlog.push(c);
                return;
            };
            loop.prep(sqe, c);
        }

        fn getSqe(loop: *Loop) ?*linux.io_uring_sqe {
            return loop.ring.get_sqe() catch blk: {
                _ = loop.ring.submit() catch return null;
                break :blk loop.ring.get_sqe() catch null;
            };
        }

        fn prep(loop: *Loop, sqe: *linux.io_uring_sqe, c: *Completion) void {
            c.state = .active;
            const no_offset: u64 = @bitCast(@as(i64, -1));
            switch (c.op) {
                .none => sqe.prep_nop(),
                .read => |op| if (op.group != io.no_group) {
                    sqe.prep_rw(if (op.multishot) .READ_MULTISHOT else .READ, op.fd, 0, if (op.multishot) 0 else op.buf.len, 0);
                    sqe.flags |= linux.IOSQE_BUFFER_SELECT;
                    sqe.buf_index = op.group;
                } else {
                    sqe.prep_rw(.READ, op.fd, @intFromPtr(op.buf.ptr), op.buf.len, no_offset);
                },
                .write => |op| sqe.prep_rw(.WRITE, op.fd, @intFromPtr(op.buf.ptr), op.buf.len, no_offset),
                .writev => |op| sqe.prep_rw(.WRITEV, op.fd, @intFromPtr(op.iov.ptr), op.iov.len, no_offset),
                .recv => |op| {
                    if (op.group != io.no_group) {
                        sqe.prep_rw(.RECV, op.fd, 0, op.buf.len, 0);
                        sqe.flags |= linux.IOSQE_BUFFER_SELECT;
                        sqe.buf_index = op.group;
                    } else {
                        sqe.prep_rw(.RECV, op.fd, @intFromPtr(op.buf.ptr), op.buf.len, 0);
                    }
                    sqe.rw_flags = op.flags;
                },
                .send => |op| {
                    sqe.prep_rw(.SEND, op.fd, @intFromPtr(op.buf.ptr), op.buf.len, 0);
                    sqe.rw_flags = op.flags | linux.MSG.NOSIGNAL;
                },
                .recvmsg => |op| {
                    sqe.prep_rw(.RECVMSG, op.fd, @intFromPtr(op.msg), 1, 0);
                    sqe.rw_flags = op.flags;
                },
                .sendmsg => |op| {
                    sqe.prep_rw(.SENDMSG, op.fd, @intFromPtr(op.msg), 1, 0);
                    sqe.rw_flags = op.flags | linux.MSG.NOSIGNAL;
                },
                .accept => |op| {
                    c.addrlen = 128;
                    const peer_ptr: u64 = if (op.peer) |p| @intFromPtr(p.mutPtr()) else 0;
                    const len_ptr: u64 = if (op.peer != null) @intFromPtr(&c.addrlen) else 0;
                    sqe.prep_rw(.ACCEPT, op.fd, peer_ptr, 0, len_ptr);
                    sqe.rw_flags = linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
                },
                .connect => |op| sqe.prep_rw(.CONNECT, op.fd, @intFromPtr(op.addr.ptr()), 0, op.addr.len),
                .poll => |op| {
                    sqe.prep_rw(.POLL_ADD, op.fd, 0, 0, 0);
                    var mask: u32 = 0;
                    if (op.events.in) mask |= linux.POLL.IN | 0x2000;
                    if (op.events.out) mask |= linux.POLL.OUT;
                    sqe.rw_flags = mask;
                },
                .close => |op| sqe.prep_rw(.CLOSE, op.fd, 0, 0, 0),
            }
            if (c.op != .close and c.op != .none) {
                if (loop.fixedIndex(sqe.fd)) |idx| {
                    sqe.fd = @intCast(idx);
                    sqe.flags |= linux.IOSQE_FIXED_FILE;
                }
            }
            sqe.user_data = @intFromPtr(c);
        }

        pub fn cancel(loop: *Loop, c: *Completion) void {
            switch (c.state) {
                .idle, .canceling => {},
                .queued => {
                    if (loop.backlog.remove(c)) {
                        c.state = .canceling;
                        loop.local.push(c);
                    }
                },
                .active => {
                    const sqe = loop.getSqe() orelse return;
                    sqe.prep_rw(.ASYNC_CANCEL, -1, @intFromPtr(c), 0, 0);
                    sqe.user_data = @intFromPtr(c) | tag_cancel;
                    c.state = .canceling;
                },
            }
        }

        pub fn cancelFd(loop: *Loop, fd: sys.fd_t) void {
            const sqe = loop.getSqe() orelse return;
            sqe.prep_rw(.ASYNC_CANCEL, fd, 0, 0, 0);
            sqe.rw_flags = linux.IORING_ASYNC_CANCEL_FD | linux.IORING_ASYNC_CANCEL_ALL;
            sqe.user_data = tag_cancel;
        }

        pub inline fn pending(loop: *const Loop) u32 {
            return loop.active;
        }

        fn flushBacklog(loop: *Loop) void {
            while (loop.backlog.head) |c| {
                const sqe = loop.ring.get_sqe() catch break;
                _ = loop.backlog.pop();
                loop.prep(sqe, c);
            }
        }

        fn dispatchLocal(loop: *Loop) void {
            var list = loop.local;
            loop.local = .{};
            while (list.pop()) |c| {
                c.state = .idle;
                loop.active -= 1;
                if (c.callback(c.userdata, loop.outer(), c, sys.Errno.canceled.result()) == .rearm) loop.submit(c);
            }
        }

        pub fn run(loop: *Loop, timeout_ns: u64) !void {
            if (!loop.wake_armed) loop.armWake();
            loop.flushBacklog();
            if (loop.local.head != null) loop.dispatchLocal();
            const to_submit = loop.ring.flush_sq();
            const ready = loop.ring.cq_ready();
            var flags: u32 = linux.IORING_ENTER_GETEVENTS;
            var min_complete: u32 = 0;
            const sqpoll = loop.setup_flags & linux.IORING_SETUP_SQPOLL != 0;
            if (ready == 0 and timeout_ns != 0 and loop.local.head == null) {
                min_complete = 1;
            }
            if (sqpoll) _ = loop.ring.sq_ring_needs_enter(&flags);
            var rc: usize = 0;
            if (min_complete == 1 and loop.ext_arg and timeout_ns != std.math.maxInt(u64)) {
                var ts: linux.kernel_timespec = .{ .sec = @intCast(timeout_ns / std.time.ns_per_s), .nsec = @intCast(timeout_ns % std.time.ns_per_s) };
                var arg: linux.io_uring_getevents_arg = .{ .sigmask = 0, .sigmask_sz = linux.NSIG / 8, .pad = 0, .ts = @intFromPtr(&ts) };
                rc = linux.syscall6(.io_uring_enter, @as(usize, @bitCast(@as(isize, loop.ring.fd))), to_submit, 1, flags | linux.IORING_ENTER_EXT_ARG, @intFromPtr(&arg), @sizeOf(linux.io_uring_getevents_arg));
            } else if (min_complete == 1 and timeout_ns != std.math.maxInt(u64)) {
                if (!loop.timeout_armed) {
                    if (loop.ring.get_sqe()) |sqe| {
                        loop.timeout_ts = .{ .sec = @intCast(timeout_ns / std.time.ns_per_s), .nsec = @intCast(timeout_ns % std.time.ns_per_s) };
                        sqe.prep_rw(.TIMEOUT, -1, @intFromPtr(&loop.timeout_ts), 1, 0);
                        sqe.user_data = tag_timeout;
                        loop.timeout_armed = true;
                    } else |_| {}
                }
                rc = linux.io_uring_enter(loop.ring.fd, loop.ring.flush_sq(), 1, flags, null);
            } else if (to_submit > 0 or min_complete > 0 or !sqpoll or loop.ring.cq_ring_needs_flush()) {
                rc = linux.io_uring_enter(loop.ring.fd, to_submit, min_complete, flags, null);
            }
            switch (linux.errno(rc)) {
                .SUCCESS, .INTR, .TIME, .BUSY, .AGAIN => {},
                .BADF, .BADFD, .NXIO => return error.RingClosed,
                else => |e| return sys.errnoError(sys.mapErrno(e)),
            }
            loop.now_ns = sys.monotonicNs();
            loop.reap();
        }

        fn reap(loop: *Loop) void {
            var rounds: u32 = 0;
            while (rounds < 4) : (rounds += 1) {
                const cq = &loop.ring.cq;
                const tail = @atomicLoad(u32, cq.tail, .acquire);
                const head = cq.head.*;
                const available = tail -% head;
                if (available == 0) break;
                const n: u32 = @min(available, loop.cqes.len);
                var i: u32 = 0;
                while (i < n) : (i += 1) {
                    loop.cqes[i] = cq.cqes[(head +% i) & cq.mask];
                }
                @atomicStore(u32, cq.head, head +% n, .release);
                for (loop.cqes[0..n]) |cqe| loop.complete(cqe);
                if (n < loop.cqes.len) break;
            }
        }

        fn complete(loop: *Loop, cqe: linux.io_uring_cqe) void {
            const ud = cqe.user_data;
            if (ud & tag_mask != 0 or ud == 0) {
                if (ud == tag_timeout) loop.timeout_armed = false;
                return;
            }
            const c: *Completion = @ptrFromInt(@as(usize, @intCast(ud)));
            var res: i32 = if (cqe.res < 0) sys.mapErrno(@as(linux.E, @fromBackingInt(@intCast(-cqe.res)))).result() else cqe.res;
            switch (c.op) {
                .poll => if (cqe.res >= 0) {
                    const m: u32 = @intCast(cqe.res);
                    const ev: io.Events = .{
                        .in = m & (linux.POLL.IN | 0x2000) != 0,
                        .out = m & linux.POLL.OUT != 0,
                        .err = m & linux.POLL.ERR != 0,
                        .hup = m & linux.POLL.HUP != 0,
                    };
                    res = @bitCast(@as(u32, @bitCast(ev)));
                },
                .accept => |op| if (cqe.res >= 0) {
                    if (op.peer) |p| p.len = c.addrlen;
                },
                else => {},
            }
            c.cqe_flags = cqe.flags;
            if (cqe.flags & linux.IORING_CQE_F_MORE != 0) {
                _ = c.callback(c.userdata, loop.outer(), c, res);
                return;
            }
            c.state = .idle;
            loop.active -= 1;
            if (c.callback(c.userdata, loop.outer(), c, res) == .rearm and c.state == .idle) {
                loop.submitInternal(c);
            }
        }
    };
}
