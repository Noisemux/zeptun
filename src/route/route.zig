const std = @import("std");
const build_options = @import("build_options");
const config = @import("../config.zig");
const addr = @import("../addr.zig");
const sys = @import("../io/sys.zig");
const log = @import("../log.zig");

pub const linux = @import("linux.zig");
pub const nftables = @import("nftables.zig");
pub const monitor = @import("monitor.zig");
pub const android = @import("android.zig");
pub const windows = @import("windows.zig");
pub const macos = @import("macos.zig");
pub const resolved = @import("resolved.zig");
pub const netns = @import("netns.zig");

pub const State = struct {
    includes: config.PrefixList = .{},
    redirect: bool = false,
    resolved: bool = false,
    ifname: [16]u8 = @splat(0),
    linux_applied: if (sys.is_linux) ?linux.Applied else void = if (sys.is_linux) null else {},
    platform: if (sys.is_windows) windows.Applied else if (macos.supported) macos.Applied else void = if (sys.is_windows) .{} else if (macos.supported) .{} else {},
    active: bool = false,
};

const max_link_addresses = 2 + config.max_prefixes;

fn collectAddresses(cfg: *const config.Config, out: *[max_link_addresses]addr.Prefix) []const addr.Prefix {
    var n: usize = 0;
    if (cfg.device.address4) |p| {
        out[n] = p;
        n += 1;
    }
    if (cfg.device.address6) |p| {
        if (build_options.enable_ipv6) {
            out[n] = p;
            n += 1;
        }
    }
    for (cfg.device.extra_addresses.slice()) |p| {
        if (p.addr.family == .v6 and !build_options.enable_ipv6) continue;
        if (n == out.len) break;
        out[n] = p;
        n += 1;
    }
    return out[0..n];
}

pub fn applyLink(cfg: *const config.Config, ifname: []const u8, ifindex: u32, txqlen: ?u32, state: *State) !void {
    if (!build_options.enable_route or !cfg.device.configure) return;
    var buf: [max_link_addresses]addr.Prefix = undefined;
    const addrs = collectAddresses(cfg, &buf);
    if (sys.is_linux and (!sys.is_android or cfg.device.kind == .tun)) {
        state.linux_applied = linux.configureLink(.{
            .name = ifname,
            .mtu = cfg.device.mtu,
            .txqlen = txqlen,
            .addresses = addrs,
        }) catch |err| {
            log.err("route: configuring link {s} failed: {t}", .{ ifname, err });
            return error.RouteError;
        };
        state.active = true;
        return;
    }
    if (sys.is_windows) {
        state.platform = try windows.configure(cfg, ifindex, addrs);
        state.active = true;
        return;
    }
    if (macos.supported) {
        state.platform = try macos.configure(cfg, ifname, addrs);
        state.active = true;
    }
}

pub fn applyRoutes(cfg: *const config.Config, ifname: []const u8, state: *State) !void {
    if (!build_options.enable_route or !cfg.device.configure or !cfg.route.auto_route) return;
    if (sys.is_linux and (!sys.is_android or cfg.device.kind == .tun)) {
        const applied = if (state.linux_applied) |*a| a else return error.RouteError;
        var include_uids = cfg.route.include_uids;
        var exclude_uids = cfg.route.exclude_uids;
        android.resolve(cfg, &include_uids, &exclude_uids);
        var uid_buf: [2 * config.max_uid_ranges + 2]config.UidRange = undefined;
        const uids = config.excludedUids(include_uids.slice(), exclude_uids.slice(), &uid_buf);
        var uid_pairs: [2 * config.max_uid_ranges + 2][2]u32 = undefined;
        for (uids, 0..) |r, i| uid_pairs[i] = .{ r.start, r.end };
        var inc_if: [config.max_interfaces][]const u8 = undefined;
        for (0..cfg.route.include_interfaces.len) |i| inc_if[i] = cfg.route.include_interfaces.get(i);
        var exc_if: [config.max_interfaces][]const u8 = undefined;
        for (0..cfg.route.exclude_interfaces.len) |i| exc_if[i] = cfg.route.exclude_interfaces.get(i);
        state.includes = cfg.route.include;
        if (cfg.dns.fake_ip and (cfg.route.include.len > 0 or cfg.route.include_extra.len > 0)) {
            if (cfg.dns.fake_range4) |p| state.includes.append(p) catch {};
            if (cfg.dns.fake_range6) |p| state.includes.append(p) catch {};
        }
        linux.configureAutoRoute(applied, .{
            .table = cfg.route.table,
            .rule_priority = cfg.route.rule_priority,
            .fwmark = cfg.route.fwmark,
            .fwmask = cfg.route.fwmark_mask,
            .ipv4 = cfg.device.address4 != null,
            .ipv6 = cfg.device.address6 != null and build_options.enable_ipv6,
            .include = state.includes.slice(),
            .exclude = cfg.route.exclude.slice(),
            .include_extra = cfg.route.include_extra,
            .exclude_extra = cfg.route.exclude_extra,
            .strict = cfg.route.strict,
            .dns_to_tunnel = cfg.dns.hijack or cfg.dns.fake_ip,
            .excluded_uids = uid_pairs[0..uids.len],
            .include_interfaces = inc_if[0..cfg.route.include_interfaces.len],
            .exclude_interfaces = exc_if[0..cfg.route.exclude_interfaces.len],
        }) catch |err| {
            log.err("route: installing policy routes for {s} failed: {t}", .{ ifname, err });
            return error.RouteError;
        };
        if (resolved.supported and ifname.len < state.ifname.len) {
            @memcpy(state.ifname[0..ifname.len], ifname);
            state.resolved = resolved.apply(cfg, ifname);
            if (!state.resolved and cfg.dnsActive()) {
                log.warn("route: systemd-resolved handover failed; DNS queries will leave this host over its real resolver and fake-ip will not be used", .{});
            }
        }
        return;
    }
    if (sys.is_windows) return windows.applyRoutes(cfg, &state.platform);
    if (macos.supported) return macos.applyRoutes(cfg, ifname, &state.platform);
}

pub fn refreshRoutes(cfg: *const config.Config, ifname: []const u8, state: *State) !void {
    if (!build_options.enable_route or !cfg.device.configure or !cfg.route.auto_route or !state.active) return;
    if (sys.is_windows) return windows.refreshRoutes(cfg, &state.platform);
    if (macos.supported) return macos.refreshRoutes(cfg, ifname, &state.platform);
}

pub fn applyRedirect(cfg: *const config.Config, ifname: []const u8, port: u16, state: *State) !void {
    if (!sys.is_linux or sys.is_android) return error.NotSupported;
    _ = cfg;
    try nftables.install(.{ .ifname = ifname, .port = port });
    state.redirect = true;
    log.info("auto-redirect: tcp routed to {s} is redirected to port {d}", .{ ifname, port });
}

pub fn teardown(state: *State) void {
    if (state.resolved) {
        state.resolved = false;
        resolved.revert(std.mem.sliceTo(&state.ifname, 0));
    }
    if (state.redirect) {
        state.redirect = false;
        nftables.remove("zeptun");
    }
    if (!state.active) return;
    state.active = false;
    if (sys.is_linux) {
        if (state.linux_applied) |a| linux.teardown(a);
        return;
    }
    if (sys.is_windows) return windows.teardown(&state.platform);
    if (macos.supported) return macos.teardown(&state.platform);
}
