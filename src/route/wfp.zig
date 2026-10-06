const std = @import("std");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");

pub const supported = sys.is_windows;

pub const GUID = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

const DisplayData = extern struct {
    name: ?[*:0]const u16 = null,
    description: ?[*:0]const u16 = null,
};

const ByteBlob = extern struct {
    size: u32 = 0,
    data: ?[*]u8 = null,
};

const Session = extern struct {
    session_key: GUID = std.mem.zeroes(GUID),
    display_data: DisplayData = .{},
    flags: u32 = 0,
    txn_wait_timeout_ms: u32 = 0,
    process_id: u32 = 0,
    sid: ?*anyopaque = null,
    username: ?[*:0]u16 = null,
    kernel_mode: i32 = 0,
};

const SubLayer = extern struct {
    sub_layer_key: GUID,
    display_data: DisplayData = .{},
    flags: u32 = 0,
    provider_key: ?*GUID = null,
    provider_data: ByteBlob = .{},
    weight: u16 = 0,
};

const Value = extern struct {
    kind: u32 = 0,
    data: extern union {
        uint8: u8,
        uint16: u16,
        uint32: u32,
        uint64: ?*u64,
        blob: ?*ByteBlob,
    } = .{ .uint64 = null },
};

const Condition = extern struct {
    field_key: GUID,
    match_type: u32 = match_equal,
    value: Value,
};

const Action = extern struct {
    kind: u32,
    filter_type: GUID = std.mem.zeroes(GUID),
};

const Filter = extern struct {
    filter_key: GUID = std.mem.zeroes(GUID),
    display_data: DisplayData = .{},
    flags: u32 = 0,
    provider_key: ?*GUID = null,
    provider_data: ByteBlob = .{},
    layer_key: GUID,
    sub_layer_key: GUID,
    weight: Value,
    num_conditions: u32 = 0,
    conditions: ?[*]const Condition = null,
    action: Action,
    provider_context: extern union { raw: u64, key: GUID } = .{ .raw = 0 },
    reserved: ?*GUID = null,
    filter_id: u64 = 0,
    effective_weight: Value = .{},
};

comptime {
    if (@sizeOf(usize) == 8) {
        std.debug.assert(@sizeOf(Filter) == 200);
        std.debug.assert(@offsetOf(Filter, "weight") == 96);
        std.debug.assert(@offsetOf(Filter, "action") == 128);
        std.debug.assert(@offsetOf(Filter, "effective_weight") == 184);
        std.debug.assert(@sizeOf(Condition) == 40);
        std.debug.assert(@sizeOf(Session) == 72);
    }
}

const authn_default: u32 = 0xffff_ffff;
const session_flag_dynamic: u32 = 1;
const match_equal: u32 = 0;
const value_uint8: u32 = 1;
const value_uint16: u32 = 2;
const value_uint32: u32 = 3;
const value_byte_blob: u32 = 12;
const action_block: u32 = 0x1001;
const action_permit: u32 = 0x1002;
const filter_flag_clear_action_right: u32 = 0x8;

const layer_connect_v4: GUID = .{ .data1 = 0xc38d57d1, .data2 = 0x05a7, .data3 = 0x4c33, .data4 = .{ 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };
const layer_connect_v6: GUID = .{ .data1 = 0x4a72393b, .data2 = 0x319f, .data3 = 0x44bc, .data4 = .{ 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4 } };
const condition_app_id: GUID = .{ .data1 = 0xd78e1e87, .data2 = 0x8644, .data3 = 0x4ea5, .data4 = .{ 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 } };
const condition_local_interface_index: GUID = .{ .data1 = 0x667fd755, .data2 = 0xd695, .data3 = 0x434a, .data4 = .{ 0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc } };
const condition_remote_port: GUID = .{ .data1 = 0xc35a604d, .data2 = 0xd22b, .data3 = 0x4e1a, .data4 = .{ 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b } };

const api = if (supported) struct {
    extern "fwpuclnt" fn FwpmEngineOpen0(server: ?[*:0]const u16, authn: u32, identity: ?*anyopaque, session: ?*const Session, engine: *?*anyopaque) callconv(.winapi) u32;
    extern "fwpuclnt" fn FwpmEngineClose0(engine: ?*anyopaque) callconv(.winapi) u32;
    extern "fwpuclnt" fn FwpmSubLayerAdd0(engine: ?*anyopaque, sub_layer: *const SubLayer, sd: ?*anyopaque) callconv(.winapi) u32;
    extern "fwpuclnt" fn FwpmFilterAdd0(engine: ?*anyopaque, filter: *const Filter, sd: ?*anyopaque, id: ?*u64) callconv(.winapi) u32;
    extern "fwpuclnt" fn FwpmGetAppIdFromFileName0(file: [*:0]const u16, app_id: *?*ByteBlob) callconv(.winapi) u32;
    extern "fwpuclnt" fn FwpmFreeMemory0(p: *?*anyopaque) callconv(.winapi) void;
    extern "kernel32" fn GetModuleFileNameW(module: ?*anyopaque, buf: [*]u16, size: u32) callconv(.winapi) u32;
    extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
} else struct {};

pub const Options = struct {
    tun_index: u32,
    ipv4: bool,
    ipv6: bool,
    block_dns: bool,
    allow_apps: []const []const u8 = &.{},
};

pub const Handle = struct {
    engine: ?*anyopaque = null,
};

const name_text = std.unicode.utf8ToUtf16LeStringLiteral("zeptun");

fn randomGuid() GUID {
    var bytes: [16]u8 = undefined;
    const pid: u64 = if (supported) api.GetCurrentProcessId() else 0;
    var prng = std.Random.DefaultPrng.init(sys.monotonicNs() ^ (pid << 32) ^ @intFromPtr(&bytes));
    prng.random().bytes(&bytes);
    return std.mem.bytesToValue(GUID, &bytes);
}

fn add(engine: ?*anyopaque, sub_layer: GUID, layer: GUID, weight: u8, action: u32, flags: u32, conditions: []const Condition) !void {
    const filter: Filter = .{
        .display_data = .{ .name = name_text },
        .flags = flags,
        .layer_key = layer,
        .sub_layer_key = sub_layer,
        .weight = .{ .kind = value_uint8, .data = .{ .uint8 = weight } },
        .num_conditions = @intCast(conditions.len),
        .conditions = if (conditions.len > 0) conditions.ptr else null,
        .action = .{ .kind = action },
    };
    const rc = api.FwpmFilterAdd0(engine, &filter, null, null);
    if (rc != 0) {
        log.err("wfp: adding filter failed (error 0x{x})", .{rc});
        return error.RouteError;
    }
}

fn permitApp(engine: ?*anyopaque, sub_layer: GUID, path: []const u8) !void {
    var wide: [32768]u16 = undefined;
    const n = std.unicode.utf8ToUtf16Le(wide[0 .. wide.len - 1], path) catch return error.InvalidArgument;
    wide[n] = 0;
    var app_id: ?*ByteBlob = null;
    const rc = api.FwpmGetAppIdFromFileName0(@ptrCast(&wide), &app_id);
    if (rc != 0 or app_id == null) {
        log.warn("wfp: resolving the application id of {s} failed (error 0x{x})", .{ path, rc });
        return error.RouteError;
    }
    defer {
        var p: ?*anyopaque = @ptrCast(app_id);
        api.FwpmFreeMemory0(&p);
    }
    const permit = [_]Condition{.{ .field_key = condition_app_id, .value = .{ .kind = value_byte_blob, .data = .{ .blob = app_id } } }};
    try add(engine, sub_layer, layer_connect_v4, 13, action_permit, filter_flag_clear_action_right, &permit);
    try add(engine, sub_layer, layer_connect_v6, 13, action_permit, filter_flag_clear_action_right, &permit);
}

pub fn install(options: Options) !Handle {
    if (!supported) return error.NotSupported;
    var handle: Handle = .{};
    const session: Session = .{ .display_data = .{ .name = name_text }, .flags = session_flag_dynamic };
    var rc = api.FwpmEngineOpen0(null, authn_default, null, &session, &handle.engine);
    if (rc != 0) {
        log.err("wfp: opening the filtering engine failed (error 0x{x})", .{rc});
        return error.RouteError;
    }
    errdefer close(&handle);
    const sub_layer_key = randomGuid();
    const sub_layer: SubLayer = .{ .sub_layer_key = sub_layer_key, .display_data = .{ .name = name_text }, .weight = 0xffff };
    rc = api.FwpmSubLayerAdd0(handle.engine, &sub_layer, null);
    if (rc != 0) {
        log.err("wfp: adding the sublayer failed (error 0x{x})", .{rc});
        return error.RouteError;
    }
    var path: [32768]u16 = undefined;
    const len = api.GetModuleFileNameW(null, &path, path.len - 1);
    if (len == 0) return error.RouteError;
    path[len] = 0;
    var app_id: ?*ByteBlob = null;
    rc = api.FwpmGetAppIdFromFileName0(@ptrCast(&path), &app_id);
    if (rc != 0 or app_id == null) {
        log.err("wfp: resolving the application id failed (error 0x{x})", .{rc});
        return error.RouteError;
    }
    defer {
        var p: ?*anyopaque = @ptrCast(app_id);
        api.FwpmFreeMemory0(&p);
    }
    const permit_app = [_]Condition{.{ .field_key = condition_app_id, .value = .{ .kind = value_byte_blob, .data = .{ .blob = app_id } } }};
    try add(handle.engine, sub_layer_key, layer_connect_v4, 13, action_permit, filter_flag_clear_action_right, &permit_app);
    try add(handle.engine, sub_layer_key, layer_connect_v6, 13, action_permit, filter_flag_clear_action_right, &permit_app);
    for (options.allow_apps) |app| permitApp(handle.engine, sub_layer_key, app) catch |err| {
        log.warn("wfp: {s} keeps the strict filters: {s}", .{ app, @errorName(err) });
    };
    if (!options.ipv6) try add(handle.engine, sub_layer_key, layer_connect_v6, 12, action_block, 0, &.{});
    const on_tun = [_]Condition{.{ .field_key = condition_local_interface_index, .value = .{ .kind = value_uint32, .data = .{ .uint32 = options.tun_index } } }};
    if (options.ipv4) try add(handle.engine, sub_layer_key, layer_connect_v4, 11, action_permit, 0, &on_tun);
    if (options.ipv6) try add(handle.engine, sub_layer_key, layer_connect_v6, 11, action_permit, 0, &on_tun);
    if (options.block_dns) {
        const dns = [_]Condition{.{ .field_key = condition_remote_port, .value = .{ .kind = value_uint16, .data = .{ .uint16 = 53 } } }};
        try add(handle.engine, sub_layer_key, layer_connect_v4, 10, action_block, 0, &dns);
        try add(handle.engine, sub_layer_key, layer_connect_v6, 10, action_block, 0, &dns);
    }
    log.info("wfp: strict route filters installed", .{});
    return handle;
}

pub fn close(handle: *Handle) void {
    if (!supported) return;
    if (handle.engine) |e| _ = api.FwpmEngineClose0(e);
    handle.engine = null;
}
