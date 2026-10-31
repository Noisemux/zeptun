const std = @import("std");

pub const Code = enum(c_int) {
    ok = 0,
    invalid_argument = -1,
    out_of_memory = -2,
    permission_denied = -3,
    not_supported = -4,
    device_error = -5,
    io_error = -6,
    already_running = -7,
    not_running = -8,
    would_block = -9,
    not_found = -10,
    limit_exceeded = -11,
    address_in_use = -12,
    system_outdated = -13,
    closed = -14,
    timeout = -15,
    config_error = -16,
    route_error = -17,
    busy = -18,
    unknown = -99,

    pub fn message(code: Code) [:0]const u8 {
        return switch (code) {
            .ok => "ok",
            .invalid_argument => "invalid argument",
            .out_of_memory => "out of memory",
            .permission_denied => "permission denied",
            .not_supported => "not supported",
            .device_error => "device error",
            .io_error => "i/o error",
            .already_running => "already running",
            .not_running => "not running",
            .would_block => "would block",
            .not_found => "not found",
            .limit_exceeded => "limit exceeded",
            .address_in_use => "address in use",
            .system_outdated => "system outdated",
            .closed => "closed",
            .timeout => "timeout",
            .config_error => "configuration error",
            .route_error => "route configuration error",
            .busy => "busy",
            .unknown => "unknown error",
        };
    }

    pub fn fromInt(v: c_int) Code {
        return std.enums.fromInt(Code, v) orelse .unknown;
    }
};

pub fn fromError(err: anyerror) Code {
    return switch (err) {
        error.OutOfMemory => .out_of_memory,
        error.InvalidArgument, error.InvalidAddress, error.InvalidPrefix, error.InvalidPort, error.InvalidCharacter, error.Overflow => .invalid_argument,
        error.PermissionDenied, error.AccessDenied => .permission_denied,
        error.NotSupported, error.Unsupported, error.OperationNotSupported => .not_supported,
        error.DeviceError, error.DeviceNotFound, error.NoDevice, error.DeviceBusy => .device_error,
        error.AlreadyRunning => .already_running,
        error.NotRunning => .not_running,
        error.WouldBlock => .would_block,
        error.NotFound, error.FileNotFound => .not_found,
        error.LimitExceeded, error.Exhausted, error.Full, error.NoPorts, error.SystemResources, error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => .limit_exceeded,
        error.AddressInUse => .address_in_use,
        error.SystemOutdated => .system_outdated,
        error.Closed, error.BrokenPipe, error.ConnectionResetByPeer => .closed,
        error.Timeout, error.TimedOut => .timeout,
        error.ConfigError => .config_error,
        error.RouteError, error.NetlinkError => .route_error,
        error.Busy => .busy,
        error.Unexpected, error.InputOutput => .io_error,
        else => .unknown,
    };
}

test "codes are stable" {
    try std.testing.expectEqual(@as(c_int, 0), @backingInt(Code.ok));
    try std.testing.expectEqual(@as(c_int, -99), @backingInt(Code.unknown));
    try std.testing.expectEqual(Code.permission_denied, fromError(error.PermissionDenied));
    try std.testing.expectEqual(Code.unknown, Code.fromInt(-1234));
    try std.testing.expectEqualStrings("timeout", Code.timeout.message());
}
