const std = @import("std");
const config = @import("config.zig");
const addr = @import("addr.zig");
const log = @import("log.zig");
const file = @import("io/file.zig");

pub const Error = error{ ConfigError, OutOfMemory };

pub const Document = struct {
    preset: ?config.Preset = null,
    tun: ?struct {
        name: ?[]const u8 = null,
        fd: ?i32 = null,
        mtu: ?u32 = null,
        queues: ?u16 = null,
        offload: ?bool = null,
        multi_queue: ?bool = null,
        persist: ?bool = null,
        napi: ?bool = null,
        jumbo: ?bool = null,
        txqueuelen: ?u32 = null,
        configure: ?bool = null,
        netns: ?[]const u8 = null,
        guid: ?[]const u8 = null,
        address: ?[]const []const u8 = null,
    } = null,
    stack: ?struct {
        mode: ?config.StackMode = null,
        tcp_rx_window: ?u32 = null,
        tcp_rx_budget: ?u32 = null,
        tcp_tx_budget: ?u32 = null,
        tcp_tx_buffer: ?u32 = null,
        tcp_mss_clamp: ?u16 = null,
        tcp_initial_cwnd: ?u16 = null,
        congestion: ?config.Congestion = null,
        sack: ?bool = null,
        timestamps: ?bool = null,
        window_scaling: ?bool = null,
        tcp_connect_timeout_ms: ?u32 = null,
        tcp_idle_timeout_ms: ?u32 = null,
        tcp_delayed_ack_ms: ?u16 = null,
        tcp_early_accept: ?bool = null,
        udp_idle_timeout_ms: ?u32 = null,
        udp: ?bool = null,
        udp_nat: ?config.NatMode = null,
        icmp: ?config.IcmpMode = null,
        max_tcp_sessions: ?u32 = null,
        max_udp_sessions: ?u32 = null,
        listen_port_base: ?u16 = null,
        nat_port_base: ?u16 = null,
        nat_port_limit: ?u16 = null,
    } = null,
    handler: ?struct {
        kind: ?config.HandlerKind = null,
        socks5: ?struct {
            server: ?[]const u8 = null,
            username: ?[]const u8 = null,
            password: ?[]const u8 = null,
            udp: ?bool = null,
            udp_mode: ?config.Socks5UdpMode = null,
            udp_address: ?[]const u8 = null,
            pipeline: ?bool = null,
            optimistic_data: ?bool = null,
            pool_size: ?u16 = null,
            pool_idle_ms: ?u32 = null,
        } = null,
        tcp_fastopen: ?bool = null,
        preserve_dscp: ?bool = null,
        direct: ?struct {
            fwmark: ?u32 = null,
            bind_interface: ?[]const u8 = null,
        } = null,
    } = null,
    route: ?struct {
        auto_route: ?bool = null,
        table: ?u32 = null,
        rule_priority: ?u32 = null,
        fwmark: ?u32 = null,
        include: ?[]const []const u8 = null,
        exclude: ?[]const []const u8 = null,
        include_file: ?[]const u8 = null,
        exclude_file: ?[]const u8 = null,
        strict: ?bool = null,
        allow_app: ?[]const []const u8 = null,
        auto_redirect: ?bool = null,
        redirect_port: ?u16 = null,
        include_uid: ?[]const []const u8 = null,
        exclude_uid: ?[]const []const u8 = null,
        include_interface: ?[]const []const u8 = null,
        exclude_interface: ?[]const []const u8 = null,
        include_package: ?[]const []const u8 = null,
        exclude_package: ?[]const []const u8 = null,
        android_user: ?[]const u32 = null,
        dns_servers: ?[]const []const u8 = null,
    } = null,
    io: ?struct {
        backend: ?config.IoBackend = null,
        ring_entries: ?u16 = null,
        sqpoll: ?bool = null,
        workers: ?u16 = null,
        pin_cpus: ?bool = null,
        rx_parallel: ?u16 = null,
        tx_slots: ?u16 = null,
        busy_poll_us: ?u32 = null,
        multishot_rx: ?bool = null,
        monitor_network: ?bool = null,
        elastic: ?config.ElasticMode = null,
    } = null,
    memory: ?struct {
        budget_bytes: ?u64 = null,
        buffers_per_worker: ?u32 = null,
    } = null,
    dns: ?struct {
        fake_ip: ?bool = null,
        fake_ranges: ?[]const []const u8 = null,
        cache_size: ?u32 = null,
        ttl: ?u32 = null,
        address: ?[]const []const u8 = null,
        hijack: ?bool = null,
        upstream: ?[]const u8 = null,
        systemd_resolved: ?bool = null,
    } = null,
    log_level: ?log.Level = null,
    stats_interval_s: ?u32 = null,
    log_file: ?[]const u8 = null,
    pid_file: ?[]const u8 = null,
    post_up_script: ?[]const u8 = null,
    pre_down_script: ?[]const u8 = null,
};

pub const State = struct {
    cfg: config.Config = .{},
    addresses_overridden: bool = false,
    fake_ranges_overridden: bool = false,
    include_more: std.ArrayList(addr.Prefix) = .empty,
    exclude_more: std.ArrayList(addr.Prefix) = .empty,
    stats_interval_s: u32 = 0,
    log_file: ?[]const u8 = null,
    pid_file: ?[]const u8 = null,
    post_up: ?[]const u8 = null,
    pre_down: ?[]const u8 = null,

    pub fn resetTo(s: *State, preset: config.Preset) void {
        s.cfg = config.Config.fromPreset(preset);
        s.addresses_overridden = false;
        s.fake_ranges_overridden = false;
        s.include_more = .empty;
        s.exclude_more = .empty;
    }

    pub fn addPrefix(s: *State, arena: std.mem.Allocator, include: bool, prefix: addr.Prefix) error{OutOfMemory}!void {
        const list = if (include) &s.cfg.route.include else &s.cfg.route.exclude;
        if (list.append(prefix)) |_| return else |_| {}
        const more = if (include) &s.include_more else &s.exclude_more;
        try more.append(arena, prefix);
        if (include) s.cfg.route.include_extra = more.items else s.cfg.route.exclude_extra = more.items;
    }

    pub fn addAddress(s: *State, text: []const u8) error{InvalidArgument}!void {
        const prefix = addr.Prefix.parse(text) catch return error.InvalidArgument;
        if (!s.addresses_overridden) {
            s.cfg.device.address4 = null;
            s.cfg.device.address6 = null;
            s.cfg.device.extra_addresses = .{};
            s.addresses_overridden = true;
        }
        const slot = if (prefix.addr.family == .v4) &s.cfg.device.address4 else &s.cfg.device.address6;
        if (slot.* == null) {
            slot.* = prefix;
            return;
        }
        s.cfg.device.extra_addresses.append(prefix) catch return error.InvalidArgument;
    }

    pub fn setFakeRange(s: *State, text: []const u8) error{InvalidArgument}!void {
        const prefix = addr.Prefix.parse(text) catch return error.InvalidArgument;
        if (!s.fake_ranges_overridden) {
            s.cfg.dns.fake_range4 = null;
            s.cfg.dns.fake_range6 = null;
            s.fake_ranges_overridden = true;
        }
        if (prefix.addr.family == .v4) s.cfg.dns.fake_range4 = prefix else s.cfg.dns.fake_range6 = prefix;
    }

    pub fn setDnsAddress(s: *State, text: []const u8) error{InvalidArgument}!void {
        const a = addr.Address.parse(text) catch return error.InvalidArgument;
        if (a.family == .v4) s.cfg.dns.address4 = a else s.cfg.dns.address6 = a;
    }

    pub fn addPrefixLines(s: *State, arena: std.mem.Allocator, include: bool, bytes: []const u8) Error!void {
        var lines = std.mem.tokenizeAny(u8, bytes, "\r\n");
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t");
            if (line.len == 0 or line[0] == '#') continue;
            const prefix = addr.Prefix.parse(line) catch return error.ConfigError;
            try s.addPrefix(arena, include, prefix);
        }
    }

    pub fn loadPrefixFile(s: *State, arena: std.mem.Allocator, include: bool, path: []const u8) Error!void {
        const bytes = file.readAlloc(arena, path, 64 << 20) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.ConfigError;
        try s.addPrefixLines(arena, include, bytes);
    }

    pub fn applyJson(s: *State, arena: std.mem.Allocator, bytes: []const u8) Error!void {
        var parser: Parser = .{ .src = bytes, .arena = arena };
        const doc = try parser.document(Document);
        try s.apply(arena, doc);
    }

    pub fn applyToml(s: *State, arena: std.mem.Allocator, bytes: []const u8) Error!void {
        const toml = @import("config_toml.zig");
        try s.apply(arena, try toml.parse(arena, bytes));
    }

    pub fn applyDocument(s: *State, arena: std.mem.Allocator, bytes: []const u8) Error!void {
        var i: usize = 0;
        while (i < bytes.len and (bytes[i] == ' ' or bytes[i] == '\t' or bytes[i] == '\n' or bytes[i] == '\r')) i += 1;
        if (i < bytes.len and bytes[i] == '{') return s.applyJson(arena, bytes);
        return s.applyToml(arena, bytes);
    }

    fn apply(s: *State, arena: std.mem.Allocator, doc: Document) Error!void {
        if (doc.preset) |pr| s.resetTo(pr);
        const c = &s.cfg;
        if (doc.tun) |t| {
            if (t.name) |n| {
                if (n.len >= 16) return error.ConfigError;
                c.device.name = .init(n);
            }
            if (t.fd) |fd| {
                if (fd >= 0) {
                    c.device.fd = fd;
                    c.device.kind = .fd;
                }
            }
            set(&c.device.mtu, t.mtu);
            if (t.queues) |q| {
                c.device.queues = q;
                c.io.workers = q;
            }
            set(&c.device.offload, t.offload);
            set(&c.device.multi_queue, t.multi_queue);
            set(&c.device.persist, t.persist);
            set(&c.device.napi, t.napi);
            set(&c.device.jumbo, t.jumbo);
            set(&c.device.txqueuelen, t.txqueuelen);
            set(&c.device.configure, t.configure);
            if (t.netns) |n| c.device.netns = .init(n);
            if (t.guid) |g| {
                c.device.guid = if (g.len == 0) null else (config.Guid.parse(g) catch return error.ConfigError);
            }
            if (t.address) |list| for (list) |text| s.addAddress(text) catch return error.ConfigError;
        }
        if (doc.stack) |st| {
            set(&c.stack.mode, st.mode);
            set(&c.stack.tcp_rx_window, st.tcp_rx_window);
            set(&c.stack.tcp_rx_budget, st.tcp_rx_budget);
            set(&c.stack.tcp_tx_budget, st.tcp_tx_budget);
            set(&c.stack.tcp_tx_buffer, st.tcp_tx_buffer);
            set(&c.stack.tcp_mss_clamp, st.tcp_mss_clamp);
            set(&c.stack.tcp_initial_cwnd, st.tcp_initial_cwnd);
            set(&c.stack.tcp_congestion, st.congestion);
            set(&c.stack.tcp_sack, st.sack);
            set(&c.stack.tcp_timestamps, st.timestamps);
            set(&c.stack.tcp_window_scaling, st.window_scaling);
            set(&c.stack.tcp_connect_timeout_ms, st.tcp_connect_timeout_ms);
            set(&c.stack.tcp_idle_timeout_ms, st.tcp_idle_timeout_ms);
            set(&c.stack.tcp_delayed_ack_ms, st.tcp_delayed_ack_ms);
            if (st.tcp_early_accept) |v| c.stack.tcp_early_accept = if (v) .on else .off;
            set(&c.stack.udp_idle_timeout_ms, st.udp_idle_timeout_ms);
            if (st.udp) |u| c.stack.udp = if (u) .enabled else .disabled;
            set(&c.stack.udp_nat, st.udp_nat);
            set(&c.stack.icmp, st.icmp);
            set(&c.stack.max_tcp_sessions, st.max_tcp_sessions);
            set(&c.stack.max_udp_sessions, st.max_udp_sessions);
            set(&c.stack.listen_port_base, st.listen_port_base);
            set(&c.stack.nat_port_base, st.nat_port_base);
            set(&c.stack.nat_port_limit, st.nat_port_limit);
        }
        if (doc.handler) |hd| {
            set(&c.handler.kind, hd.kind);
            if (hd.socks5) |s5| {
                if (s5.server) |srv| c.handler.socks5.server = addr.Endpoint.parse(srv) catch return error.ConfigError;
                if (s5.username) |u| c.handler.socks5.username = .init(u);
                if (s5.password) |pw| c.handler.socks5.password = .init(pw);
                if (s5.udp) |u| c.handler.socks5.udp = if (u) .enabled else .disabled;
                if (s5.pipeline) |v| c.handler.socks5.pipeline = if (v) .on else .off;
                set(&c.handler.socks5.optimistic_data, s5.optimistic_data);
                set(&c.handler.socks5.udp_mode, s5.udp_mode);
                if (s5.udp_address) |ua| c.handler.socks5.udp_address = addr.Address.parse(ua) catch return error.ConfigError;
                set(&c.handler.socks5.pool_size, s5.pool_size);
                set(&c.handler.socks5.pool_idle_ms, s5.pool_idle_ms);
            }
            set(&c.handler.tcp_fastopen, hd.tcp_fastopen);
            set(&c.handler.preserve_dscp, hd.preserve_dscp);
            if (hd.direct) |d| {
                set(&c.handler.direct.fwmark, d.fwmark);
                if (d.bind_interface) |bi| c.handler.direct.bind_interface = .init(bi);
            }
        }
        if (doc.route) |r| {
            set(&c.route.auto_route, r.auto_route);
            set(&c.route.table, r.table);
            set(&c.route.rule_priority, r.rule_priority);
            set(&c.route.fwmark, r.fwmark);
            if (r.include) |list| for (list) |text| {
                try s.addPrefix(arena, true, addr.Prefix.parse(text) catch return error.ConfigError);
            };
            if (r.exclude) |list| for (list) |text| {
                try s.addPrefix(arena, false, addr.Prefix.parse(text) catch return error.ConfigError);
            };
            if (r.include_file) |f| try s.loadPrefixFile(arena, true, f);
            if (r.exclude_file) |f| try s.loadPrefixFile(arena, false, f);
            set(&c.route.strict, r.strict);
            if (r.allow_app) |list| c.route.allow_apps = list;
            set(&c.route.auto_redirect, r.auto_redirect);
            set(&c.route.redirect_port, r.redirect_port);
            if (r.include_uid) |list| for (list) |text| {
                c.route.include_uids.append(config.UidRange.parse(text) catch return error.ConfigError) catch return error.ConfigError;
            };
            if (r.exclude_uid) |list| for (list) |text| {
                c.route.exclude_uids.append(config.UidRange.parse(text) catch return error.ConfigError) catch return error.ConfigError;
            };
            if (r.include_interface) |list| for (list) |text| c.route.include_interfaces.append(text) catch return error.ConfigError;
            if (r.exclude_interface) |list| for (list) |text| c.route.exclude_interfaces.append(text) catch return error.ConfigError;
            if (r.include_package) |list| for (list) |text| c.route.include_packages.append(text) catch return error.ConfigError;
            if (r.exclude_package) |list| for (list) |text| c.route.exclude_packages.append(text) catch return error.ConfigError;
            if (r.android_user) |list| for (list) |u| c.route.android_users.append(.{ .start = u, .end = u }) catch return error.ConfigError;
            if (r.dns_servers) |list| for (list) |text| {
                const a = addr.Address.parse(text) catch return error.ConfigError;
                c.route.dns.append(.{ .addr = a, .bits = if (a.family == .v4) 32 else 128 }) catch return error.ConfigError;
            };
        }
        if (doc.io) |o| {
            set(&c.io.backend, o.backend);
            set(&c.io.ring_entries, o.ring_entries);
            set(&c.io.sqpoll, o.sqpoll);
            set(&c.io.workers, o.workers);
            set(&c.io.pin_cpus, o.pin_cpus);
            set(&c.io.rx_parallel, o.rx_parallel);
            set(&c.io.tx_slots, o.tx_slots);
            set(&c.io.busy_poll_us, o.busy_poll_us);
            set(&c.io.multishot_rx, o.multishot_rx);
            if (o.monitor_network) |v| c.io.monitor_network = if (v) .on else .off;
            set(&c.io.elastic, o.elastic);
        }
        if (doc.memory) |m| {
            set(&c.memory.budget_bytes, m.budget_bytes);
            set(&c.memory.buffers_per_worker, m.buffers_per_worker);
        }
        if (doc.dns) |d| {
            set(&c.dns.fake_ip, d.fake_ip);
            if (d.fake_ranges) |list| for (list) |text| s.setFakeRange(text) catch return error.ConfigError;
            set(&c.dns.cache_size, d.cache_size);
            set(&c.dns.ttl, d.ttl);
            if (d.address) |list| for (list) |text| s.setDnsAddress(text) catch return error.ConfigError;
            set(&c.dns.hijack, d.hijack);
            if (d.upstream) |u| c.dns.upstream = addr.Endpoint.parse(u) catch return error.ConfigError;
            if (d.systemd_resolved) |v| c.dns_resolved = if (v) .on else .off;
        }
        set(&c.log_level, doc.log_level);
        set(&s.stats_interval_s, doc.stats_interval_s);
        if (doc.log_file) |v| s.log_file = v;
        if (doc.pid_file) |v| s.pid_file = v;
        if (doc.post_up_script) |v| s.post_up = v;
        if (doc.pre_down_script) |v| s.pre_down = v;
        if (c.device.kind != .tun) c.stack.mode = .userspace;
    }
};

fn set(dst: anytype, src: anytype) void {
    if (src) |v| dst.* = v;
}

const Parser = struct {
    src: []const u8,
    pos: usize = 0,
    arena: std.mem.Allocator,
    depth: u8 = 0,

    const max_depth = 16;

    fn document(p: *Parser, comptime T: type) Error!T {
        const v = try p.value(T);
        p.skipSpace();
        if (p.pos != p.src.len) return error.ConfigError;
        return v;
    }

    fn skipSpace(p: *Parser) void {
        while (p.pos < p.src.len) : (p.pos += 1) {
            switch (p.src[p.pos]) {
                ' ', '\t', '\n', '\r' => {},
                else => return,
            }
        }
    }

    fn eat(p: *Parser, ch: u8) bool {
        p.skipSpace();
        if (p.pos < p.src.len and p.src[p.pos] == ch) {
            p.pos += 1;
            return true;
        }
        return false;
    }

    fn expect(p: *Parser, ch: u8) Error!void {
        if (!p.eat(ch)) return error.ConfigError;
    }

    fn word(p: *Parser, text: []const u8) bool {
        p.skipSpace();
        if (!std.mem.startsWith(u8, p.src[p.pos..], text)) return false;
        p.pos += text.len;
        return true;
    }

    fn string(p: *Parser) Error![]const u8 {
        try p.expect('"');
        const start = p.pos;
        var escaped = false;
        while (p.pos < p.src.len) : (p.pos += 1) {
            const ch = p.src[p.pos];
            if (ch == '"') break;
            if (ch < 0x20) return error.ConfigError;
            if (ch == '\\') {
                escaped = true;
                p.pos += 1;
            }
        }
        if (p.pos >= p.src.len) return error.ConfigError;
        const raw = p.src[start..p.pos];
        p.pos += 1;
        return if (escaped) unescape(p.arena, raw) else raw;
    }

    fn unescape(arena: std.mem.Allocator, raw: []const u8) Error![]const u8 {
        const out = try arena.alloc(u8, raw.len);
        var o: usize = 0;
        var i: usize = 0;
        while (i < raw.len) {
            if (raw[i] != '\\') {
                out[o] = raw[i];
                o += 1;
                i += 1;
                continue;
            }
            if (i + 1 >= raw.len) return error.ConfigError;
            const e = raw[i + 1];
            i += 2;
            const simple: ?u8 = switch (e) {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => 8,
                'f' => 12,
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'u' => null,
                else => return error.ConfigError,
            };
            if (simple) |ch| {
                out[o] = ch;
                o += 1;
                continue;
            }
            var cp: u21 = try hex4(raw, i);
            i += 4;
            if (cp >= 0xd800 and cp < 0xdc00) {
                if (i + 6 > raw.len or raw[i] != '\\' or raw[i + 1] != 'u') return error.ConfigError;
                const low = try hex4(raw, i + 2);
                if (low < 0xdc00 or low >= 0xe000) return error.ConfigError;
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                i += 6;
            } else if (cp >= 0xdc00 and cp < 0xe000) {
                return error.ConfigError;
            }
            var enc: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &enc) catch return error.ConfigError;
            if (o + n > out.len) return error.ConfigError;
            @memcpy(out[o..][0..n], enc[0..n]);
            o += n;
        }
        return out[0..o];
    }

    fn hex4(raw: []const u8, at: usize) Error!u21 {
        if (at + 4 > raw.len) return error.ConfigError;
        return std.fmt.parseInt(u16, raw[at..][0..4], 16) catch error.ConfigError;
    }

    fn integer(p: *Parser, comptime T: type) Error!T {
        p.skipSpace();
        const start = p.pos;
        if (p.pos < p.src.len and p.src[p.pos] == '-') p.pos += 1;
        while (p.pos < p.src.len and std.ascii.isDigit(p.src[p.pos])) p.pos += 1;
        return std.fmt.parseInt(T, p.src[start..p.pos], 10) catch error.ConfigError;
    }

    fn value(p: *Parser, comptime T: type) Error!T {
        switch (@typeInfo(T)) {
            .optional => |o| {
                if (p.word("null")) return null;
                return try p.value(o.child);
            },
            .bool => {
                if (p.word("true")) return true;
                if (p.word("false")) return false;
                return error.ConfigError;
            },
            .int => return p.integer(T),
            .@"enum" => return std.meta.stringToEnum(T, try p.string()) orelse error.ConfigError,
            .pointer => |ptr| {
                if (ptr.child == u8) return p.string();
                try p.expect('[');
                var list: std.ArrayList(ptr.child) = .empty;
                if (p.eat(']')) return list.items;
                while (true) {
                    try list.append(p.arena, try p.value(ptr.child));
                    if (p.eat(',')) continue;
                    try p.expect(']');
                    return list.items;
                }
            },
            .@"struct" => |st| {
                if (p.depth == max_depth) return error.ConfigError;
                p.depth += 1;
                defer p.depth -= 1;
                var out: T = .{};
                try p.expect('{');
                if (p.eat('}')) return out;
                while (true) {
                    const key = try p.string();
                    try p.expect(':');
                    const known = inline for (st.fields) |f| {
                        if (std.mem.eql(u8, key, f.name)) {
                            @field(out, f.name) = try p.value(f.type);
                            break true;
                        }
                    } else false;
                    if (!known) return error.ConfigError;
                    if (p.eat(',')) continue;
                    try p.expect('}');
                    return out;
                }
            },
            else => @compileError("unsupported config field type " ++ @typeName(T)),
        }
    }
};

test "json document applies over presets" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var s: State = .{};
    try s.applyJson(arena,
        \\{"preset":"mobile","handler":{"kind":"socks5","socks5":{"server":"10.0.0.1:1080","udp_mode":"tcp","pool_size":2}},
        \\ "dns":{"fake_ip":true,"fake_ranges":["10.128.0.0/10"]},"route":{"strict":true,"exclude_uid":["1000-1999"],"exclude":["192.168.0.0/16"]}}
    );
    try std.testing.expectEqual(config.Preset.mobile, s.cfg.preset);
    try std.testing.expectEqual(config.Socks5UdpMode.tcp, s.cfg.handler.socks5.udp_mode);
    try std.testing.expectEqual(@as(u16, 2), s.cfg.handler.socks5.pool_size);
    try std.testing.expect(s.cfg.dns.fake_range6 == null);
    try std.testing.expectEqual(@as(u8, 10), s.cfg.dns.fake_range4.?.bits);
    try std.testing.expect(s.cfg.route.strict);
    try std.testing.expectEqual(@as(u32, 1999), s.cfg.route.exclude_uids.slice()[0].end);
    try s.cfg.validate();
    var lines: std.ArrayList(u8) = .empty;
    for (0..40) |i| try lines.print(arena, "10.{d}.0.0/16\n", .{i});
    try s.addPrefixLines(arena, true, lines.items);
    try std.testing.expectEqual(@as(usize, 32), s.cfg.route.include.len);
    try std.testing.expectEqual(@as(usize, 8), s.cfg.route.include_extra.len);
    try std.testing.expectError(error.ConfigError, s.applyJson(arena, "{\"bogus\":1}"));
}

test "json document carries namespace, nat and address lists" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var s: State = .{};
    try s.applyJson(arena_state.allocator(),
        \\{"tun":{"netns":"office","guid":"24198F4C-7895-434C-AD35-9E29A92DDC51","address":["10.5.0.1/24","10.6.0.1/24","fd11::1/64"]},
        \\ "stack":{"udp_nat":"address_port"},"dns":{"systemd_resolved":false}}
    );
    try std.testing.expectEqualStrings("office", s.cfg.device.netns.slice());
    try std.testing.expectEqual(@as(u16, 0x7895), s.cfg.device.guid.?.d2);
    try std.testing.expectEqual(config.NatMode.address_port, s.cfg.stack.udp_nat);
    try std.testing.expectEqual(config.AutoMode.off, s.cfg.dns_resolved);
    try std.testing.expectEqual(@as(u8, 24), s.cfg.device.address4.?.bits);
    try std.testing.expectEqual(@as(u8, 64), s.cfg.device.address6.?.bits);
    try std.testing.expectEqual(@as(usize, 1), s.cfg.device.extra_addresses.slice().len);
}

test "json parser strings, escapes and errors" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Doc = struct {
        name: ?[]const u8 = null,
        list: ?[]const []const u8 = null,
        nums: ?[]const u32 = null,
        flag: ?bool = null,
        level: ?log.Level = null,
        inner: ?struct { n: ?i32 = null } = null,
    };
    var p: Parser = .{ .src = " { \"name\" : \"a\\\"b\\\\c\\u00e9\\ud83d\\ude00\", \"list\":[\"x\", \"y\"], \"nums\":[1,2,3], \"flag\":false, \"level\":\"debug\", \"inner\":{\"n\":-5} } ", .arena = arena };
    const d = try p.document(Doc);
    try std.testing.expectEqualStrings("a\"b\\c\u{e9}\u{1f600}", d.name.?);
    try std.testing.expectEqual(@as(usize, 2), d.list.?.len);
    try std.testing.expectEqualStrings("y", d.list.?[1]);
    try std.testing.expectEqual(@as(u32, 3), d.nums.?[2]);
    try std.testing.expect(!d.flag.?);
    try std.testing.expectEqual(log.Level.debug, d.level.?);
    try std.testing.expectEqual(@as(i32, -5), d.inner.?.n.?);
    const bad = [_][]const u8{ "{", "{\"name\":}", "{\"name\":\"x\"} x", "{\"flag\":1}", "{\"nums\":[1,]}", "{\"name\":\"\\q\"}", "{\"level\":\"loud\"}", "{\"name\":null,}", "[]" };
    for (bad) |text| {
        var bp: Parser = .{ .src = text, .arena = arena };
        try std.testing.expectError(error.ConfigError, bp.document(Doc));
    }
    var empty: Parser = .{ .src = "{}", .arena = arena };
    const e = try empty.document(Doc);
    try std.testing.expect(e.name == null);
}
