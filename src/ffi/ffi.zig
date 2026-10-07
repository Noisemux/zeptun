const std = @import("std");
const builtin = @import("builtin");
const zeptun = @import("zeptun");

const Engine = zeptun.Engine;
const config = zeptun.config;
const errors = zeptun.errors;
const external = zeptun.device.external;
const stats = zeptun.stats;
const log = zeptun.log;
const addr = zeptun.addr;

pub const std_options: std.Options = .{
    .signal_stack_size = if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) 1 << 18 else null,
};

pub const panic = if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) std.debug.FullPanic(std.debug.defaultPanic) else std.debug.FullPanic(rawPanic);

fn rawPanic(msg: []const u8, ra: ?usize) noreturn {
    @branchHint(.cold);
    _ = ra;
    zeptun.io.file.writeStd(.err, "zeptun: panic: ");
    zeptun.io.file.writeStd(.err, msg);
    zeptun.io.file.writeStd(.err, "\n");
    @trap();
}

pub const version_major = 1;
pub const version_minor = 1;
pub const version_patch = 1;

pub const Packet = external.Packet;
pub const PacketsFn = external.OutputFn;
pub const ProtectFn = *const fn (ctx: ?*anyopaque, fd: c_int) callconv(.c) bool;
pub const LogFn = *const fn (ctx: ?*anyopaque, level: c_int, message: [*]const u8, len: usize) callconv(.c) void;

pub const Config = extern struct {
    struct_size: u32,
    preset: u32,
    device_kind: u32,
    tun_fd: i32,
    tun_name: [16]u8,
    mtu: u32,
    queues: u16,
    offload: u8,
    configure: u8,
    address4: [64]u8,
    address6: [64]u8,
    stack_mode: u32,
    handler_kind: u32,
    socks5_server: [64]u8,
    socks5_username: [256]u8,
    socks5_password: [256]u8,
    socks5_udp: u8,
    socks5_pipeline: u8,
    auto_route: u8,
    passthrough_gso: u8,
    fwmark: u32,
    route_table: u32,
    rule_priority: u32,
    io_backend: u32,
    max_tcp_sessions: u32,
    max_udp_sessions: u32,
    tcp_rx_window: u32,
    tcp_tx_buffer: u32,
    udp_idle_timeout_ms: u32,
    tcp_idle_timeout_ms: u32,
    pad0: u32,
    memory_budget_bytes: u64,
    log_level: u32,
    workers: u32,
    reserved: [8]u32,
};

comptime {
    std.debug.assert(@sizeOf(Config) == 848);
    std.debug.assert(@offsetOf(Config, "memory_budget_bytes") == 800);
    std.debug.assert(@sizeOf(stats.Snapshot) == 8 + 8 * stats.count);
    std.debug.assert(@offsetOf(stats.Snapshot, "rx_packets") == 8);
    std.debug.assert(@offsetOf(stats.Snapshot, "udp_migrated") == 8 + 8 * (stats.count - 1));
}

const Handle = struct {
    engine: *Engine,
    allocator: std.mem.Allocator,
    arena: ?*std.heap.ArenaAllocator = null,
    started: std.atomic.Value(bool) = .init(false),
};

fn allocator() std.mem.Allocator {
    if (builtin.link_libc) return std.heap.c_allocator;
    if (builtin.single_threaded) return std.heap.page_allocator;
    return std.heap.smp_allocator;
}

inline fn code(c: errors.Code) c_int {
    return @intFromEnum(c);
}

fn cstr(buf: []const u8) []const u8 {
    return std.mem.sliceTo(buf, 0);
}

fn handleOf(tun: ?*anyopaque) ?*Handle {
    return @ptrCast(@alignCast(tun orelse return null));
}

fn toConfig(c: *const Config) !config.Config {
    const preset: config.Preset = std.enums.fromInt(config.Preset, c.preset) orelse return error.InvalidArgument;
    var cfg = config.Config.fromPreset(preset);
    cfg.device.kind = std.enums.fromInt(config.DeviceKind, c.device_kind) orelse return error.InvalidArgument;
    cfg.device.fd = c.tun_fd;
    const name = cstr(&c.tun_name);
    if (name.len > 0) cfg.device.name = .init(name);
    if (c.mtu != 0) cfg.device.mtu = c.mtu;
    if (c.queues != 0) {
        cfg.device.queues = c.queues;
        cfg.io.workers = c.queues;
    }
    if (c.workers != 0) cfg.io.workers = @intCast(@min(c.workers, 256));
    cfg.device.offload = c.offload != 0;
    cfg.device.configure = c.configure != 0;
    const a4 = cstr(&c.address4);
    cfg.device.address4 = if (a4.len > 0) try addr.Prefix.parse(a4) else null;
    const a6 = cstr(&c.address6);
    cfg.device.address6 = if (a6.len > 0) try addr.Prefix.parse(a6) else null;
    cfg.stack.mode = std.enums.fromInt(config.StackMode, c.stack_mode) orelse return error.InvalidArgument;
    cfg.handler.kind = std.enums.fromInt(config.HandlerKind, c.handler_kind) orelse return error.InvalidArgument;
    const srv = cstr(&c.socks5_server);
    if (srv.len > 0) cfg.handler.socks5.server = try addr.Endpoint.parse(srv);
    cfg.handler.socks5.username = .init(cstr(&c.socks5_username));
    cfg.handler.socks5.password = .init(cstr(&c.socks5_password));
    cfg.handler.socks5.udp = if (c.socks5_udp != 0) .enabled else .disabled;
    cfg.handler.socks5.pipeline = std.enums.fromInt(config.PipelineMode, c.socks5_pipeline) orelse .auto;
    cfg.handler.passthrough_gso = c.passthrough_gso != 0;
    cfg.handler.direct.fwmark = c.fwmark;
    cfg.route.auto_route = c.auto_route != 0;
    if (c.route_table != 0) cfg.route.table = c.route_table;
    if (c.rule_priority != 0) cfg.route.rule_priority = c.rule_priority;
    cfg.io.backend = std.enums.fromInt(config.IoBackend, c.io_backend) orelse return error.InvalidArgument;
    if (c.max_tcp_sessions != 0) cfg.stack.max_tcp_sessions = c.max_tcp_sessions;
    if (c.max_udp_sessions != 0) cfg.stack.max_udp_sessions = c.max_udp_sessions;
    if (c.tcp_rx_window != 0) cfg.stack.tcp_rx_window = c.tcp_rx_window;
    if (c.tcp_tx_buffer != 0) cfg.stack.tcp_tx_buffer = c.tcp_tx_buffer;
    if (c.udp_idle_timeout_ms != 0) cfg.stack.udp_idle_timeout_ms = c.udp_idle_timeout_ms;
    if (c.tcp_idle_timeout_ms != 0) cfg.stack.tcp_idle_timeout_ms = c.tcp_idle_timeout_ms;
    if (c.memory_budget_bytes != 0) cfg.memory.budget_bytes = c.memory_budget_bytes;
    cfg.log_level = std.enums.fromInt(log.Level, @as(u8, @intCast(@min(c.log_level, 4)))) orelse .info;
    if (cfg.device.kind != .tun) cfg.stack.mode = .userspace;
    return cfg;
}

export fn zeptun_version() callconv(.c) u32 {
    return (version_major << 16) | (version_minor << 8) | version_patch;
}

export fn zeptun_version_string() callconv(.c) [*:0]const u8 {
    return "zeptun " ++ zeptun.version;
}

export fn zeptun_strerror(c: c_int) callconv(.c) [*:0]const u8 {
    return errors.Code.fromInt(c).message().ptr;
}

export fn zeptun_config_init(out: ?*Config, preset: u32) callconv(.c) c_int {
    const c = out orelse return code(.invalid_argument);
    const p = std.enums.fromInt(config.Preset, preset) orelse return code(.invalid_argument);
    const src = config.Config.fromPreset(p);
    c.* = std.mem.zeroes(Config);
    c.struct_size = @sizeOf(Config);
    c.preset = preset;
    c.device_kind = @intFromEnum(src.device.kind);
    c.tun_fd = -1;
    const name = src.device.name.slice();
    @memcpy(c.tun_name[0..name.len], name);
    c.mtu = src.device.mtu;
    c.queues = src.device.queues;
    c.offload = @intFromBool(src.device.offload);
    c.configure = @intFromBool(src.device.configure);
    if (src.device.address4) |a| _ = std.fmt.bufPrint(c.address4[0..63], "{f}", .{a}) catch {};
    if (src.device.address6) |a| _ = std.fmt.bufPrint(c.address6[0..63], "{f}", .{a}) catch {};
    c.stack_mode = @intFromEnum(src.stack.mode);
    c.handler_kind = @intFromEnum(src.handler.kind);
    c.socks5_udp = 1;
    c.route_table = src.route.table;
    c.rule_priority = src.route.rule_priority;
    c.io_backend = @intFromEnum(src.io.backend);
    c.max_tcp_sessions = src.stack.max_tcp_sessions;
    c.max_udp_sessions = src.stack.max_udp_sessions;
    c.tcp_rx_window = src.stack.tcp_rx_window;
    c.tcp_tx_buffer = src.stack.tcp_tx_buffer;
    c.udp_idle_timeout_ms = src.stack.udp_idle_timeout_ms;
    c.tcp_idle_timeout_ms = src.stack.tcp_idle_timeout_ms;
    c.memory_budget_bytes = src.memory.budget_bytes;
    c.log_level = @intFromEnum(src.log_level);
    c.workers = src.io.workers;
    return code(.ok);
}

export fn zeptun_create(cfg: ?*const Config, out: ?*?*anyopaque) callconv(.c) c_int {
    const c = cfg orelse return code(.invalid_argument);
    const dst = out orelse return code(.invalid_argument);
    dst.* = null;
    if (c.struct_size < @sizeOf(Config)) return code(.invalid_argument);
    const zc = toConfig(c) catch |err| return code(errors.fromError(err));
    const a = allocator();
    const h = a.create(Handle) catch return code(.out_of_memory);
    const e = Engine.create(a, zc) catch |err| {
        a.destroy(h);
        return code(errors.fromError(err));
    };
    h.* = .{ .engine = e, .allocator = a };
    dst.* = h;
    return code(.ok);
}

export fn zeptun_create_from_toml(toml: ?[*]const u8, len: usize, out: ?*?*anyopaque) callconv(.c) c_int {
    return createFromDocument(toml, len, out, .toml);
}

export fn zeptun_create_from_json(json: ?[*]const u8, len: usize, out: ?*?*anyopaque) callconv(.c) c_int {
    return createFromDocument(json, len, out, .json);
}

const DocumentKind = enum { json, toml, any };

fn createFromDocument(src: ?[*]const u8, len: usize, out: ?*?*anyopaque, kind: DocumentKind) c_int {
    const text = src orelse return code(.invalid_argument);
    const dst = out orelse return code(.invalid_argument);
    dst.* = null;
    const a = allocator();
    const arena = a.create(std.heap.ArenaAllocator) catch return code(.out_of_memory);
    arena.* = .init(a);
    var ok = false;
    defer if (!ok) {
        arena.deinit();
        a.destroy(arena);
    };
    var st: zeptun.config_json.State = .{};
    const copy = arena.allocator().dupe(u8, text[0..len]) catch return code(.out_of_memory);
    const applied = switch (kind) {
        .json => st.applyJson(arena.allocator(), copy),
        .toml => st.applyToml(arena.allocator(), copy),
        .any => st.applyDocument(arena.allocator(), copy),
    };
    applied catch |err| return code(switch (err) {
        error.OutOfMemory => .out_of_memory,
        error.ConfigError => .config_error,
    });
    const h = a.create(Handle) catch return code(.out_of_memory);
    const e = Engine.create(a, st.cfg) catch |err| {
        a.destroy(h);
        return code(errors.fromError(err));
    };
    h.* = .{ .engine = e, .allocator = a, .arena = arena };
    ok = true;
    dst.* = h;
    return code(.ok);
}

export fn zeptun_set_read_callback(tun: ?*anyopaque, cb: ?PacketsFn, ctx: ?*anyopaque) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const shared = h.engine.external orelse return code(.not_supported);
    if (h.started.load(.acquire)) return code(.already_running);
    shared.setOutput(cb, ctx);
    return code(.ok);
}

export fn zeptun_set_passthrough_callback(tun: ?*anyopaque, cb: ?PacketsFn, ctx: ?*anyopaque) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const shared = h.engine.passthrough_shared orelse return code(.not_supported);
    if (h.started.load(.acquire)) return code(.already_running);
    shared.setOutput(cb, ctx);
    return code(.ok);
}

export fn zeptun_set_adapter_guid(tun: ?*anyopaque, guid: ?[*:0]const u8) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const text = guid orelse return code(.invalid_argument);
    if (h.started.load(.acquire)) return code(.already_running);
    h.engine.setAdapterGuid(std.mem.span(text)) catch return code(.invalid_argument);
    return code(.ok);
}

export fn zeptun_set_device_fd(tun: ?*anyopaque, fd: c_int) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    if (h.started.load(.acquire)) return code(.already_running);
    h.engine.setDeviceFd(@intCast(fd));
    return code(.ok);
}

export fn zeptun_set_flow_callback(tun: ?*anyopaque, cb: ?zeptun.flow.verdict.Fn, ctx: ?*anyopaque) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    if (h.started.load(.acquire)) return code(.already_running);
    h.engine.setJudge(cb, ctx);
    return code(.ok);
}

export fn zeptun_set_protect_callback(tun: ?*anyopaque, cb: ?ProtectFn, ctx: ?*anyopaque) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    if (h.started.load(.acquire)) return code(.already_running);
    h.engine.setProtect(cb, ctx);
    return code(.ok);
}

var log_cb: ?LogFn = null;
var log_ctx: ?*anyopaque = null;

fn logBridge(_: ?*anyopaque, level: log.Level, message: []const u8) void {
    if (log_cb) |f| f(log_ctx, @intFromEnum(level), message.ptr, message.len);
}

export fn zeptun_set_log_callback(cb: ?LogFn, ctx: ?*anyopaque, level: c_int) callconv(.c) c_int {
    log_ctx = ctx;
    log_cb = cb;
    log.setSink(if (cb != null) logBridge else null, null);
    log.setLevel(std.enums.fromInt(log.Level, @as(u8, @intCast(std.math.clamp(level, 0, 4)))) orelse .info);
    return code(.ok);
}

export fn zeptun_start(tun: ?*anyopaque) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    if (h.started.swap(true, .acquire)) return code(.already_running);
    h.engine.start() catch |err| {
        h.started.store(false, .release);
        return code(errors.fromError(err));
    };
    return code(.ok);
}

export fn zeptun_run(tun: ?*anyopaque) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    if (h.started.swap(true, .acquire)) return code(.already_running);
    h.engine.run() catch |err| return code(errors.fromError(err));
    return code(.ok);
}

export fn zeptun_stop(tun: ?*anyopaque) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    if (!h.started.load(.acquire)) return code(.not_running);
    h.engine.stop();
    return code(.ok);
}

export fn zeptun_destroy(tun: ?*anyopaque) callconv(.c) void {
    const h = handleOf(tun) orelse return;
    const a = h.allocator;
    h.engine.destroy();
    if (h.arena) |arena| {
        arena.deinit();
        a.destroy(arena);
    }
    a.destroy(h);
}

export fn zeptun_write_packet(tun: ?*anyopaque, data: ?[*]const u8, len: usize) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const d = data orelse return code(.invalid_argument);
    const shared = h.engine.external orelse return code(.not_supported);
    shared.inject(d[0..len]) catch |err| return code(switch (err) {
        error.TooLarge => .invalid_argument,
        error.Full => .would_block,
        error.Closed => .closed,
    });
    shared.notify();
    return code(.ok);
}

export fn zeptun_write_packets(tun: ?*anyopaque, packets: ?[*]const Packet, count: usize) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const p = packets orelse return code(.invalid_argument);
    const shared = h.engine.external orelse return code(.not_supported);
    const n = shared.injectBatch(p[0..count]);
    return @intCast(@min(n, std.math.maxInt(c_int)));
}

export fn zeptun_inject_packets(tun: ?*anyopaque, packets: ?[*]const Packet, count: usize) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const p = packets orelse return code(.invalid_argument);
    const shared = h.engine.passthrough_shared orelse return code(.not_supported);
    const n = shared.injectBatch(p[0..count]);
    return @intCast(@min(n, std.math.maxInt(c_int)));
}

export fn zeptun_network_changed(tun: ?*anyopaque, interface_index: u32) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    h.engine.networkChanged(interface_index);
    return code(.ok);
}

export fn zeptun_stats(tun: ?*anyopaque, out: ?*stats.Snapshot) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const o = out orelse return code(.invalid_argument);
    h.engine.snapshot(o);
    return code(.ok);
}

export fn zeptun_memory(tun: ?*anyopaque, out: ?*stats.Memory) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const o = out orelse return code(.invalid_argument);
    h.engine.memory(o);
    return code(.ok);
}

export fn zeptun_interface_name(tun: ?*anyopaque, buf: ?[*]u8, len: usize) callconv(.c) c_int {
    const h = handleOf(tun) orelse return code(.invalid_argument);
    const b = buf orelse return code(.invalid_argument);
    const name = h.engine.interfaceName();
    if (len <= name.len) return code(.limit_exceeded);
    @memcpy(b[0..name.len], name);
    b[name.len] = 0;
    return @intCast(name.len);
}

test "ffi config roundtrip" {
    var c: Config = undefined;
    try std.testing.expectEqual(@as(c_int, 0), zeptun_config_init(&c, 1));
    const z = try toConfig(&c);
    try std.testing.expectEqual(config.StackMode.userspace, z.stack.mode);
    try std.testing.expectEqual(@as(u32, 1200), z.stack.max_tcp_sessions);
    try std.testing.expectEqualStrings("172.19.0.1/30", cstr(&c.address4));
    try std.testing.expect(zeptun_version() == 0x010101);
    try std.testing.expectEqualStrings("timeout", std.mem.span(zeptun_strerror(-15)));
}

test "a device fd set after a toml config switches the device kind" {
    const toml = "[handler.socks5]\nserver = \"127.0.0.1:1080\"\n";
    var handle: ?*anyopaque = null;
    try std.testing.expectEqual(@as(c_int, 0), zeptun_create_from_toml(toml.ptr, toml.len, &handle));
    defer zeptun_destroy(handle);
    const h = handleOf(handle).?;
    try std.testing.expectEqual(config.DeviceKind.tun, h.engine.device_kind);
    try std.testing.expectEqual(@as(c_int, 0), zeptun_set_device_fd(handle, 7));
    try std.testing.expectEqual(config.DeviceKind.fd, h.engine.device_kind);
    try std.testing.expectEqual(config.DeviceKind.fd, h.engine.cfg.device.kind);
    try std.testing.expectEqual(@as(i32, 7), h.engine.cfg.device.fd);
}
