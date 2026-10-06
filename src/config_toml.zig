const std = @import("std");
const json = @import("config_json.zig");

pub const Error = json.Error;
pub const Document = json.Document;

const max_path = 8;

pub fn parse(arena: std.mem.Allocator, text: []const u8) Error!Document {
    var doc: Document = .{};
    var p: Parser = .{ .src = text, .arena = arena };
    try p.run(&doc);
    return doc;
}

const Parser = struct {
    src: []const u8,
    pos: usize = 0,
    arena: std.mem.Allocator,
    table: [max_path][]const u8 = undefined,
    table_len: usize = 0,

    fn run(p: *Parser, doc: *Document) Error!void {
        while (true) {
            p.skipBlank();
            if (p.pos >= p.src.len) return;
            if (p.src[p.pos] == '[') {
                try p.header();
                continue;
            }
            try p.entry(doc);
        }
    }

    fn skipBlank(p: *Parser) void {
        while (p.pos < p.src.len) {
            switch (p.src[p.pos]) {
                ' ', '\t', '\r', '\n' => p.pos += 1,
                '#' => while (p.pos < p.src.len and p.src[p.pos] != '\n') : (p.pos += 1) {},
                else => return,
            }
        }
    }

    fn skipInline(p: *Parser) void {
        while (p.pos < p.src.len) {
            switch (p.src[p.pos]) {
                ' ', '\t' => p.pos += 1,
                '#' => while (p.pos < p.src.len and p.src[p.pos] != '\n') : (p.pos += 1) {},
                else => return,
            }
        }
    }

    fn header(p: *Parser) Error!void {
        p.pos += 1;
        if (p.pos < p.src.len and p.src[p.pos] == '[') return error.ConfigError;
        p.table_len = try p.path(&p.table, ']');
        if (p.table_len == 0) return error.ConfigError;
        try p.endOfLine();
    }

    fn entry(p: *Parser, doc: *Document) Error!void {
        var keys: [max_path][]const u8 = undefined;
        const n = try p.path(&keys, '=');
        if (n == 0 or p.table_len + n > max_path) return error.ConfigError;
        var full: [max_path][]const u8 = undefined;
        @memcpy(full[0..p.table_len], p.table[0..p.table_len]);
        @memcpy(full[p.table_len..][0..n], keys[0..n]);
        try assign(Document, doc, full[0 .. p.table_len + n], p);
        try p.endOfLine();
    }

    fn path(p: *Parser, out: *[max_path][]const u8, close: u8) Error!usize {
        var n: usize = 0;
        while (true) {
            p.skipInline();
            if (n == max_path) return error.ConfigError;
            out[n] = try p.key();
            n += 1;
            p.skipInline();
            if (p.pos >= p.src.len) return error.ConfigError;
            const ch = p.src[p.pos];
            p.pos += 1;
            if (ch == close) return n;
            if (ch != '.') return error.ConfigError;
        }
    }

    fn key(p: *Parser) Error![]const u8 {
        if (p.pos < p.src.len and (p.src[p.pos] == '"' or p.src[p.pos] == '\'')) return p.string();
        const start = p.pos;
        while (p.pos < p.src.len) : (p.pos += 1) {
            const ch = p.src[p.pos];
            if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') break;
        }
        if (p.pos == start) return error.ConfigError;
        return p.src[start..p.pos];
    }

    fn endOfLine(p: *Parser) Error!void {
        p.skipInline();
        if (p.pos >= p.src.len) return;
        const ch = p.src[p.pos];
        if (ch == '\n' or ch == '\r') return;
        return error.ConfigError;
    }

    fn string(p: *Parser) Error![]const u8 {
        const quote = p.src[p.pos];
        p.pos += 1;
        const start = p.pos;
        var escaped = false;
        while (p.pos < p.src.len) : (p.pos += 1) {
            const ch = p.src[p.pos];
            if (ch == quote) break;
            if (ch == '\n') return error.ConfigError;
            if (quote == '"' and ch == '\\') {
                escaped = true;
                p.pos += 1;
            }
        }
        if (p.pos >= p.src.len) return error.ConfigError;
        const raw = p.src[start..p.pos];
        p.pos += 1;
        return if (escaped) p.unescape(raw) else raw;
    }

    fn unescape(p: *Parser, raw: []const u8) Error![]const u8 {
        const out = try p.arena.alloc(u8, raw.len);
        var o: usize = 0;
        var i: usize = 0;
        while (i < raw.len) : (i += 1) {
            if (raw[i] != '\\') {
                out[o] = raw[i];
                o += 1;
                continue;
            }
            i += 1;
            if (i >= raw.len) return error.ConfigError;
            out[o] = switch (raw[i]) {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '"' => '"',
                '\\' => '\\',
                else => return error.ConfigError,
            };
            o += 1;
        }
        return out[0..o];
    }

    fn word(p: *Parser) []const u8 {
        const start = p.pos;
        while (p.pos < p.src.len) : (p.pos += 1) {
            const ch = p.src[p.pos];
            if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-' and ch != '+' and ch != '.') break;
        }
        return p.src[start..p.pos];
    }

    fn scalar(p: *Parser, comptime T: type) Error!T {
        p.skipInline();
        if (p.pos >= p.src.len) return error.ConfigError;
        switch (@typeInfo(T)) {
            .bool => {
                const w = p.word();
                if (std.mem.eql(u8, w, "true")) return true;
                if (std.mem.eql(u8, w, "false")) return false;
                return error.ConfigError;
            },
            .int => {
                const w = p.word();
                if (w.len == 0) return error.ConfigError;
                var buf: [32]u8 = undefined;
                var n: usize = 0;
                for (w) |ch| {
                    if (ch == '_') continue;
                    if (n == buf.len) return error.ConfigError;
                    buf[n] = ch;
                    n += 1;
                }
                return std.fmt.parseInt(T, buf[0..n], 0) catch error.ConfigError;
            },
            .@"enum" => {
                const text = if (p.src[p.pos] == '"' or p.src[p.pos] == '\'') try p.string() else p.word();
                return std.meta.stringToEnum(T, text) orelse error.ConfigError;
            },
            .pointer => |ptr| {
                if (ptr.child == u8) {
                    if (p.src[p.pos] != '"' and p.src[p.pos] != '\'') return error.ConfigError;
                    return p.string();
                }
                if (p.src[p.pos] != '[') return error.ConfigError;
                p.pos += 1;
                var list: std.ArrayList(ptr.child) = .empty;
                while (true) {
                    p.skipBlank();
                    if (p.pos >= p.src.len) return error.ConfigError;
                    if (p.src[p.pos] == ']') {
                        p.pos += 1;
                        return list.items;
                    }
                    try list.append(p.arena, try p.scalar(ptr.child));
                    p.skipBlank();
                    if (p.pos < p.src.len and p.src[p.pos] == ',') p.pos += 1;
                }
            },
            else => @compileError("unsupported config field type " ++ @typeName(T)),
        }
    }
};

fn assign(comptime T: type, out: *T, keys: []const []const u8, p: *Parser) Error!void {
    switch (@typeInfo(T)) {
        .optional => |o| {
            if (@typeInfo(o.child) == .@"struct") {
                if (out.* == null) out.* = .{};
                return assign(o.child, &out.*.?, keys, p);
            }
            out.* = try p.scalar(o.child);
            if (keys.len != 0) return error.ConfigError;
            return;
        },
        .@"struct" => |st| {
            if (keys.len == 0) return error.ConfigError;
            inline for (st.fields) |f| {
                if (std.mem.eql(u8, keys[0], f.name)) return assign(f.type, &@field(out.*, f.name), keys[1..], p);
            }
            return error.ConfigError;
        },
        else => {
            if (keys.len != 0) return error.ConfigError;
            out.* = try p.scalar(T);
        },
    }
}

test "toml document reaches every section" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const text =
        \\preset = "server"
        \\log_level = "info"
        \\stats_interval_s = 5
        \\
        \\[tun]
        \\name = "zeptun0"
        \\mtu = 8_500
        \\netns = "office"
        \\address = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
        \\
        \\[stack]
        \\mode = "userspace"
        \\udp_nat = "address_port"
        \\tcp_rx_window = 524288
        \\
        \\[handler]
        \\kind = "socks5"
        \\
        \\[handler.socks5]
        \\server = "127.0.0.1:1080"
        \\pool_size = 4
        \\
        \\[route]
        \\auto_route = true
        \\strict = true
        \\allow_app = ['C:\Program Files\ZedSecure\xray.exe', "D:\\O'Brien\\zeptun.exe"]
        \\exclude = [
        \\  "192.168.0.0/16",
        \\]
        \\
        \\[dns]
        \\fake_ip = true
        \\systemd_resolved = false
    ;
    const doc = try parse(arena_state.allocator(), text);
    try std.testing.expectEqual(@as(?@TypeOf(doc.preset.?), .server), doc.preset);
    try std.testing.expectEqualStrings("zeptun0", doc.tun.?.name.?);
    try std.testing.expectEqual(@as(u32, 8500), doc.tun.?.mtu.?);
    try std.testing.expectEqualStrings("office", doc.tun.?.netns.?);
    try std.testing.expectEqual(@as(usize, 2), doc.tun.?.address.?.len);
    try std.testing.expectEqualStrings("fdfe:dcba:9876::1/126", doc.tun.?.address.?[1]);
    try std.testing.expectEqual(@as(u32, 524288), doc.stack.?.tcp_rx_window.?);
    try std.testing.expectEqualStrings("127.0.0.1:1080", doc.handler.?.socks5.?.server.?);
    try std.testing.expect(doc.route.?.auto_route.?);
    try std.testing.expectEqualStrings("192.168.0.0/16", doc.route.?.exclude.?[0]);
    try std.testing.expect(doc.route.?.strict.?);
    try std.testing.expectEqualStrings("C:\\Program Files\\ZedSecure\\xray.exe", doc.route.?.allow_app.?[0]);
    try std.testing.expectEqualStrings("D:\\O'Brien\\zeptun.exe", doc.route.?.allow_app.?[1]);
    try std.testing.expect(doc.dns.?.fake_ip.?);
    try std.testing.expect(!doc.dns.?.systemd_resolved.?);
    try std.testing.expectEqual(@as(u32, 5), doc.stats_interval_s.?);
}

test "toml rejects unknown keys and broken lines" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectError(error.ConfigError, parse(arena, "[tun]\nbogus = 1"));
    try std.testing.expectError(error.ConfigError, parse(arena, "[nope]\nname = \"x\""));
    try std.testing.expectError(error.ConfigError, parse(arena, "[tun]\nmtu = 1500 trailing"));
    try std.testing.expectError(error.ConfigError, parse(arena, "[tun]\nname = unquoted"));
    try std.testing.expectError(error.ConfigError, parse(arena, "[stack]\nmode = \"nope\""));
}

test "toml comments and dotted keys" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const text =
        \\# leading comment
        \\tun.name = "zep9"
        \\handler.socks5.server = "10.0.0.1:1080"
        \\[io]
        \\workers = 2 # trailing comment
    ;
    const doc = try parse(arena_state.allocator(), text);
    try std.testing.expectEqualStrings("zep9", doc.tun.?.name.?);
    try std.testing.expectEqualStrings("10.0.0.1:1080", doc.handler.?.socks5.?.server.?);
    try std.testing.expectEqual(@as(u16, 2), doc.io.?.workers.?);
}
