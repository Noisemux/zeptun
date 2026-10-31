const std = @import("std");
const builtin = @import("builtin");
const zeptun = @import("zeptun");
const args = @import("args.zig");

const Engine = zeptun.Engine;
const sys = zeptun.io.sys;
const file = zeptun.io.file;

pub const panic = if (builtin.mode == .debug or builtin.mode == .safe) std.debug.FullPanic(std.debug.defaultPanic) else std.debug.FullPanic(rawPanic);

pub const std_options: std.Options = .{
    .signal_stack_size = if (builtin.mode == .debug or builtin.mode == .safe) 1 << 18 else null,
};

fn rawPanic(msg: []const u8, ra: ?usize) noreturn {
    @branchHint(.cold);
    _ = ra;
    file.writeStd(.err, "zeptun: panic: ");
    file.writeStd(.err, msg);
    file.writeStd(.err, "\n");
    @trap();
}

var global_engine: std.atomic.Value(?*Engine) = .init(null);
var stop_requested: std.atomic.Value(bool) = .init(false);
var defer_stop: std.atomic.Value(bool) = .init(false);
var environ: std.process.Environ = undefined;

fn requestStop() void {
    stop_requested.store(true, .release);
    if (defer_stop.load(.acquire)) return;
    if (global_engine.load(.acquire)) |e| e.stop();
}

fn onSignal(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    requestStop();
}

const LogFile = struct {
    var handle: ?file.Handle = null;

    fn sink(_: ?*anyopaque, level: zeptun.log.Level, message: []const u8) void {
        const h = handle orelse return;
        var buf: [2048]u8 = undefined;
        const body = message[0..@min(message.len, buf.len - 32)];
        const line = std.mem.print(&buf, "zeptun [{t}] {s}\n", .{ level, body }) catch return;
        file.writeAll(h, line) catch {};
    }
};

const ExitStatus = union(enum) { exited: u32, abnormal };

fn spawnWait(arena: std.mem.Allocator, script: []const u8, ifname: []const u8) !ExitStatus {
    if (builtin.target.os.tag == .windows) {
        const w = sys.windows;
        const line = try arena.print("cmd.exe /c \"{s}\" {s}", .{ script, ifname });
        const line_w = try std.unicode.wtf8ToWtf16LeAllocZ(arena, line);
        var si: w.STARTUPINFOW = .{};
        var pi: w.PROCESS_INFORMATION = .{};
        if (w.kernel32.CreateProcessW(null, line_w, null, null, 0, w.CREATE_NO_WINDOW, null, null, &si, &pi) == 0) return error.SpawnFailed;
        defer _ = w.kernel32.CloseHandle(pi.hThread.?);
        defer _ = w.kernel32.CloseHandle(pi.hProcess.?);
        _ = w.kernel32.WaitForSingleObject(pi.hProcess.?, w.INFINITE);
        var code: u32 = 0;
        if (w.kernel32.GetExitCodeProcess(pi.hProcess.?, &code) == 0) return .abnormal;
        return .{ .exited = code };
    }
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", try arena.dupeSentinel(u8, script, 0), try arena.dupeSentinel(u8, ifname, 0) };
    const envp: [*:null]const ?[*:0]const u8 = environ.block.slice.ptr;
    var status: i32 = 0;
    if (builtin.target.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = sys.linuxResult(linux.fork());
        if (rc < 0) return error.SpawnFailed;
        if (rc == 0) {
            _ = linux.execve("/bin/sh", &argv, envp);
            linux.exit_group(127);
        }
        while (true) {
            const r = sys.linuxResult(linux.wait4(rc, &status, 0, null));
            if (r >= 0) break;
            if (sys.toErrno(r) != .intr) return error.SpawnFailed;
        }
    } else {
        const pid = std.c.fork();
        if (pid < 0) return error.SpawnFailed;
        if (pid == 0) {
            _ = std.c.execve("/bin/sh", &argv, envp);
            std.c._exit(127);
        }
        var st: c_int = 0;
        while (std.c.waitpid(pid, &st, 0) < 0) {
            if (std.c._errno().* != @backingInt(std.c.E.INTR)) return error.SpawnFailed;
        }
        status = @bitCast(st);
    }
    if (status & 0x7f != 0) return .abnormal;
    return .{ .exited = @intCast((status >> 8) & 0xff) };
}

fn runScript(arena: std.mem.Allocator, script: []const u8, ifname: []const u8) void {
    const term = spawnWait(arena, script, ifname) catch |err| {
        zeptun.log.err("script {s} failed to start: {t}", .{ script, err });
        return;
    };
    switch (term) {
        .exited => |code| if (code != 0) zeptun.log.warn("script {s} exited with {d}", .{ script, code }),
        .abnormal => zeptun.log.warn("script {s} terminated abnormally", .{script}),
    }
}

fn ignoreSignal(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
}

fn stderrSink(_: ?*anyopaque, level: zeptun.log.Level, message: []const u8) void {
    file.print(.err, "zeptun [{t}] {s}\n", .{ level, message });
}

fn installSignals() void {
    if (builtin.target.os.tag == .windows) {
        const Console = struct {
            fn onControl(ctrl_type: u32) callconv(.winapi) sys.windows.BOOL {
                requestStop();
                if (ctrl_type >= 2) {
                    var waited: u32 = 0;
                    while (waited < 45) : (waited += 1) sys.sleepMs(100);
                }
                return 1;
            }
        };
        _ = sys.windows.kernel32.SetConsoleCtrlHandler(Console.onControl, 1);
        return;
    }
    var act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
    act.handler = .{ .handler = ignoreSignal };
    std.posix.sigaction(.PIPE, &act, null);
}

var safe_allocator = std.heap.SafeAllocator.init(std.heap.page_allocator, .{});

fn engineAllocator() std.mem.Allocator {
    return if (builtin.mode == .debug) safe_allocator.allocator() else std.heap.page_allocator;
}

pub fn main(init: std.process.Init.Minimal) u8 {
    environ = init.environ;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const all = init.args.toSlice(arena) catch {
        file.writeStd(.err, "zeptun: out of memory\n");
        return 2;
    };
    const argv: []const []const u8 = if (all.len > 0) all[1..] else &.{};
    const parsed = args.parse(arena, argv) catch |err| {
        file.print(.err, "zeptun: {t}\n\n", .{err});
        file.writeStd(.err, args.usage);
        return 2;
    };
    switch (parsed.command) {
        .help => {
            file.writeStd(.out, args.usage);
            return 0;
        },
        .version => {
            file.print(.out, "zeptun {s} zig {s} {t}-{t}\n", .{ zeptun.version, builtin.zig_version_string, builtin.target.cpu.arch, builtin.target.os.tag });
            return 0;
        },
        .probe => return probe(&parsed),
        .run => {},
    }
    zeptun.log.setSink(stderrSink, null);
    if (parsed.st.log_file) |path| {
        const h = file.open(path, .append) catch |err| {
            file.print(.err, "zeptun: cannot open log file {s}: {t}\n", .{ path, err });
            return 2;
        };
        LogFile.handle = h;
        zeptun.log.setSink(LogFile.sink, null);
    }
    defer if (LogFile.handle) |h| {
        zeptun.log.setSink(null, null);
        LogFile.handle = null;
        file.close(h);
    };
    zeptun.log.setLevel(parsed.st.cfg.log_level);
    std.process.raiseFileDescriptorLimit();
    const e = Engine.create(engineAllocator(), parsed.st.cfg) catch |err| {
        file.print(.err, "zeptun: invalid configuration: {t}\n", .{err});
        return 2;
    };
    defer e.destroy();
    global_engine.store(e, .release);
    defer global_engine.store(null, .release);
    if (parsed.st.pid_file) |path| {
        var buf: [32]u8 = undefined;
        const pid: i64 = if (builtin.target.os.tag == .linux) std.os.linux.getpid() else if (builtin.target.os.tag == .windows) sys.windows.kernel32.GetCurrentProcessId() else std.c.getpid();
        const text = std.mem.print(&buf, "{d}\n", .{pid}) catch unreachable;
        file.writeFile(path, text) catch |err| {
            file.print(.err, "zeptun: cannot write pid file {s}: {t}\n", .{ path, err });
            return 2;
        };
    }
    defer if (parsed.st.pid_file) |path| file.remove(path);
    const hooks = parsed.st.post_up != null or parsed.st.pre_down != null;
    defer_stop.store(parsed.st.pre_down != null, .release);
    installSignals();
    if (parsed.st.stats_interval_s == 0 and !hooks) {
        e.run() catch |err| {
            file.print(.err, "zeptun: {t}\n", .{err});
            return 1;
        };
        return 0;
    }
    e.start() catch |err| {
        file.print(.err, "zeptun: {t}\n", .{err});
        return 1;
    };
    if (parsed.st.post_up) |script| {
        if (e.isRunning() and !stop_requested.load(.acquire)) runScript(arena, script, e.interfaceName());
    }
    const interval_ticks: u32 = if (parsed.st.stats_interval_s == 0) std.math.maxInt(u32) else parsed.st.stats_interval_s * 10;
    var prev: zeptun.stats.Snapshot = .{};
    var prev_ms = sys.monotonicMs();
    while (e.isRunning() and !stop_requested.load(.acquire)) {
        var slept: u32 = 0;
        while (slept < interval_ticks and e.isRunning() and !stop_requested.load(.acquire)) : (slept += 1) sys.sleepMs(100);
        if (parsed.st.stats_interval_s == 0 or stop_requested.load(.acquire)) continue;
        var cur: zeptun.stats.Snapshot = .{};
        e.snapshot(&cur);
        var mem: zeptun.stats.Memory = .{};
        e.memory(&mem);
        const now = sys.monotonicMs();
        const dt: f64 = @as(f64, @floatFromInt(@max(now - prev_ms, 1))) / 1000.0;
        const rx_mbps = @as(f64, @floatFromInt(cur.rx_bytes -% prev.rx_bytes)) * 8.0 / 1e6 / dt;
        const tx_mbps = @as(f64, @floatFromInt(cur.tx_bytes -% prev.tx_bytes)) * 8.0 / 1e6 / dt;
        file.print(.err, "zeptun stats: tun rx {d:.1} Mbit/s tx {d:.1} Mbit/s | pkts rx {d} tx {d} | up rx {d} tx {d} | tcp active {d} opened {d} rtx {d} rto {d} | udp active {d} | nat {d} | drops rx {d} tx {d} | pool exhausted {d} | gso rx {d} tx {d} | workers {d} handoffs {d} migrated tcp {d} udp {d} | mem {d}/{d} bufs {d} KB resident {d} KB released {d} waiting\n", .{
            rx_mbps,
            tx_mbps,
            cur.rx_packets,
            cur.tx_packets,
            cur.upstream_rx_bytes,
            cur.upstream_tx_bytes,
            cur.tcp_active,
            cur.tcp_opened,
            cur.tcp_retransmits,
            cur.timeouts,
            cur.udp_active,
            cur.nat_active,
            cur.rx_dropped,
            cur.tx_dropped,
            cur.pool_exhausted,
            cur.gso_rx_packets,
            cur.gso_tx_packets,
            cur.workers,
            cur.handoffs,
            cur.tcp_migrated,
            cur.udp_migrated,
            mem.in_use,
            mem.buffers,
            mem.resident_bytes / 1024,
            mem.released_bytes / 1024,
            mem.starved_flows,
        });
        prev = cur;
        prev_ms = now;
    }
    if (parsed.st.pre_down) |script| {
        if (e.isRunning()) runScript(arena, script, e.interfaceName());
    }
    defer_stop.store(false, .release);
    e.stop();
    e.wait();
    return 0;
}

fn probe(parsed: *const args.Parsed) u8 {
    file.print(.out, "zeptun {s}\n", .{zeptun.version});
    file.print(.out, "cpus: {d}\n", .{sys.cpuCount()});
    file.print(.out, "io_uring: {s}\n", .{if (zeptun.io.IoUring != void and zeptun.io.available(.io_uring)) "available" else "unavailable"});
    file.print(.out, "epoll: {s}\n", .{if (zeptun.io.Epoll != void) "available" else "unavailable"});
    if (builtin.target.os.tag != .linux) return 0;
    var t = zeptun.device.linux.Tun.open(.{
        .name = parsed.st.cfg.device.name.slice(),
        .queues = 2,
        .mtu = parsed.st.cfg.device.mtu,
    }) catch |err| {
        file.print(.out, "tun: cannot open ({t}); CAP_NET_ADMIN is required\n", .{err});
        return 1;
    };
    defer t.close();
    file.print(.out, "tun: {s} queues={d} vnet_hdr={} csum={} tso={} uso={} offload_flags=0x{x} features=0x{x}\n", .{
        t.nameSlice(),
        t.queue_count,
        t.caps.vnet_hdr,
        t.caps.csum_offload,
        t.caps.tso,
        t.caps.uso,
        t.offload_flags,
        t.features,
    });
    return 0;
}
