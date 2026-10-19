const std = @import("std");
const builtin = @import("builtin");
const sys = @import("../io/sys.zig");

const linux = std.os.linux;

pub const Error = error{ NetlinkError, PermissionDenied, NotSupported, Exists, NotFound, InvalidArgument, SystemResources };

const nfnl_subsys_nftables: u16 = 10;
const nfnl_msg_batch_begin: u16 = 16;
const nfnl_msg_batch_end: u16 = 17;
const nft_msg_newtable: u16 = 0;
const nft_msg_deltable: u16 = 2;
const nft_msg_newchain: u16 = 3;
const nft_msg_newrule: u16 = 6;

const nfta_table_name: u16 = 1;
const nfta_table_flags: u16 = 2;
const nfta_chain_table: u16 = 1;
const nfta_chain_name: u16 = 3;
const nfta_chain_hook: u16 = 4;
const nfta_chain_policy: u16 = 5;
const nfta_chain_type: u16 = 7;
const nfta_hook_hooknum: u16 = 1;
const nfta_hook_priority: u16 = 2;
const nfta_rule_table: u16 = 1;
const nfta_rule_chain: u16 = 2;
const nfta_rule_expressions: u16 = 4;
const nfta_list_elem: u16 = 1;
const nfta_expr_name: u16 = 1;
const nfta_expr_data: u16 = 2;
const nfta_data_value: u16 = 1;

const nfproto_inet: u8 = 1;
const hook_prerouting: u32 = 0;
const hook_input: u32 = 1;
const hook_output: u32 = 3;
const nf_accept: u32 = 1;
const reg1: u32 = 1;

const meta_l4proto: u32 = 16;
const meta_oifname: u32 = 7;
const cmp_eq: u32 = 0;
const fib_result_oifname: u32 = 2;
const fib_f_daddr: u32 = 2;
const fib_f_iif: u32 = 8;
const payload_transport: u32 = 2;
const ct_status: u32 = 2;
const ips_dst_nat: u32 = 32;
const reject_tcp_rst: u32 = 1;

const nlm_f_request: u16 = 0x1;
const nlm_f_ack: u16 = 0x4;
const nlm_f_create: u16 = 0x400;
const nlm_f_append: u16 = 0x800;
const nla_f_nested: u16 = 0x8000;
const nlmsg_error: u16 = 2;

const NlMsgHdr = extern struct {
    len: u32,
    kind: u16,
    flags: u16,
    seq: u32,
    pid: u32,
};

const Batch = struct {
    buf: [16384]u8 align(4) = undefined,
    len: usize = 0,
    msg_start: usize = 0,
    nests: [8]usize = undefined,
    depth: usize = 0,
    seq: u32,
    first_seq: u32,
    acked: u32 = 0,

    fn put(b: *Batch, bytes: []const u8) void {
        @memcpy(b.buf[b.len..][0..bytes.len], bytes);
        b.len += bytes.len;
    }

    fn pad(b: *Batch) void {
        const aligned = std.mem.alignForward(usize, b.len, 4);
        @memset(b.buf[b.len..aligned], 0);
        b.len = aligned;
    }

    fn begin(b: *Batch, kind: u16, flags: u16, family: u8, ack: bool) void {
        b.msg_start = b.len;
        const h: NlMsgHdr = .{ .len = 0, .kind = kind, .flags = flags | nlm_f_request | (if (ack) nlm_f_ack else 0), .seq = b.seq, .pid = 0 };
        if (ack) b.acked += 1;
        b.seq += 1;
        b.put(std.mem.asBytes(&h));
        const res_id = std.mem.nativeToBig(u16, if (kind == nfnl_msg_batch_begin or kind == nfnl_msg_batch_end) nfnl_subsys_nftables else 0);
        b.put(&.{ family, 0 });
        b.put(std.mem.asBytes(&res_id));
    }

    fn end(b: *Batch) void {
        std.mem.writeInt(u32, b.buf[b.msg_start..][0..4], @intCast(b.len - b.msg_start), builtin.target.cpu.arch.endian());
    }

    fn attr(b: *Batch, kind: u16, bytes: []const u8) void {
        const total: u16 = @intCast(4 + bytes.len);
        b.put(std.mem.asBytes(&total));
        b.put(std.mem.asBytes(&kind));
        b.put(bytes);
        b.pad();
    }

    fn str(b: *Batch, kind: u16, s: []const u8) void {
        var tmp: [64]u8 = undefined;
        @memcpy(tmp[0..s.len], s);
        tmp[s.len] = 0;
        b.attr(kind, tmp[0 .. s.len + 1]);
    }

    fn be32(b: *Batch, kind: u16, v: u32) void {
        const x = std.mem.nativeToBig(u32, v);
        b.attr(kind, std.mem.asBytes(&x));
    }

    fn open(b: *Batch, kind: u16) void {
        b.nests[b.depth] = b.len;
        b.depth += 1;
        const zero: u16 = 0;
        const k = kind | nla_f_nested;
        b.put(std.mem.asBytes(&zero));
        b.put(std.mem.asBytes(&k));
    }

    fn close(b: *Batch) void {
        b.depth -= 1;
        const start = b.nests[b.depth];
        std.mem.writeInt(u16, b.buf[start..][0..2], @intCast(b.len - start), builtin.target.cpu.arch.endian());
    }

    fn data(b: *Batch, kind: u16, value: []const u8) void {
        b.open(kind);
        b.attr(nfta_data_value, value);
        b.close();
    }

    fn expr(b: *Batch, name: []const u8) void {
        b.open(nfta_list_elem);
        b.str(nfta_expr_name, name);
        b.open(nfta_expr_data);
    }

    fn exprEnd(b: *Batch) void {
        b.close();
        b.close();
    }

    fn meta(b: *Batch, key: u32) void {
        b.expr("meta");
        b.be32(1, reg1);
        b.be32(2, key);
        b.exprEnd();
    }

    fn cmp(b: *Batch, value: []const u8) void {
        b.expr("cmp");
        b.be32(1, reg1);
        b.be32(2, cmp_eq);
        b.data(3, value);
        b.exprEnd();
    }

    fn ruleBegin(b: *Batch, table: []const u8, chain_name: []const u8) void {
        b.begin((nfnl_subsys_nftables << 8) | nft_msg_newrule, nlm_f_create | nlm_f_append, nfproto_inet, true);
        b.str(nfta_rule_table, table);
        b.str(nfta_rule_chain, chain_name);
        b.open(nfta_rule_expressions);
    }

    fn ruleEnd(b: *Batch) void {
        b.close();
        b.end();
    }

    fn baseChain(b: *Batch, table: []const u8, name: []const u8, kind: []const u8, hook: u32, priority: i32) void {
        b.begin((nfnl_subsys_nftables << 8) | nft_msg_newchain, nlm_f_create, nfproto_inet, true);
        b.str(nfta_chain_table, table);
        b.str(nfta_chain_name, name);
        b.open(nfta_chain_hook);
        b.be32(nfta_hook_hooknum, hook);
        b.be32(nfta_hook_priority, @bitCast(priority));
        b.close();
        b.be32(nfta_chain_policy, nf_accept);
        b.str(nfta_chain_type, kind);
        b.end();
    }
};

pub const Redirect = struct {
    table: []const u8 = "zeptun",
    ifname: []const u8,
    port: u16,
};

fn ifnameBytes(name: []const u8) [16]u8 {
    var out: [16]u8 = @splat(0);
    @memcpy(out[0..@min(name.len, 15)], name[0..@min(name.len, 15)]);
    return out;
}

fn openSocket() Error!i32 {
    const r = sys.linuxResult(linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 12));
    if (r < 0) return switch (sys.toErrno(r)) {
        .acces, .perm => error.PermissionDenied,
        .afnosupport => error.NotSupported,
        else => error.NetlinkError,
    };
    var sa: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    if (sys.linuxResult(linux.bind(r, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl))) < 0) {
        _ = linux.close(r);
        return error.NetlinkError;
    }
    const tv = linux.timeval{ .sec = 3, .usec = 0 };
    _ = linux.setsockopt(r, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    return r;
}

fn newBatch() Batch {
    const seed: u32 = @truncate(sys.monotonicNs());
    return .{ .seq = seed, .first_seq = seed };
}

fn commit(fd: i32, b: *Batch) Error!void {
    var dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    if (sys.linuxResult(linux.sendto(fd, &b.buf, b.len, 0, @ptrCast(&dst), @sizeOf(linux.sockaddr.nl))) < 0) return error.NetlinkError;
    var remaining = b.acked;
    var rbuf: [8192]u8 align(4) = undefined;
    while (remaining > 0) {
        const got = sys.linuxResult(linux.recvfrom(fd, &rbuf, rbuf.len, 0, null, null));
        if (got < 0) {
            if (sys.toErrno(got) == .intr) continue;
            return error.NetlinkError;
        }
        var off: usize = 0;
        const total: usize = @intCast(got);
        while (off + @sizeOf(NlMsgHdr) <= total) {
            const h = std.mem.bytesToValue(NlMsgHdr, rbuf[off..][0..@sizeOf(NlMsgHdr)]);
            if (h.len < @sizeOf(NlMsgHdr) or off + h.len > total) return error.NetlinkError;
            if (h.kind == nlmsg_error) {
                const code = std.mem.readInt(i32, rbuf[off + @sizeOf(NlMsgHdr) ..][0..4], builtin.target.cpu.arch.endian());
                if (code != 0) {
                    const e: linux.E = @fromBackingInt(@intCast(-code));
                    return switch (e) {
                        .PERM, .ACCES => error.PermissionDenied,
                        .EXIST => error.Exists,
                        .NOENT => error.NotFound,
                        .INVAL => error.InvalidArgument,
                        .OPNOTSUPP, .AFNOSUPPORT, .PROTONOSUPPORT => error.NotSupported,
                        .NOMEM, .NOBUFS => error.SystemResources,
                        else => error.NetlinkError,
                    };
                }
                remaining -|= 1;
            }
            off += std.mem.alignForward(usize, h.len, 4);
        }
    }
}

pub fn remove(table: []const u8) void {
    if (!sys.is_linux) return;
    const fd = openSocket() catch return;
    defer _ = linux.close(fd);
    var b = newBatch();
    b.begin(nfnl_msg_batch_begin, 0, 0, false);
    b.end();
    b.begin((nfnl_subsys_nftables << 8) | nft_msg_deltable, 0, nfproto_inet, true);
    b.str(nfta_table_name, table);
    b.end();
    b.begin(nfnl_msg_batch_end, 0, 0, false);
    b.end();
    commit(fd, &b) catch {};
}

pub fn install(r: Redirect) Error!void {
    if (!sys.is_linux) return error.NotSupported;
    remove(r.table);
    const fd = try openSocket();
    defer _ = linux.close(fd);
    var b = newBatch();
    encode(&b, r);
    try commit(fd, &b);
}

fn encode(b: *Batch, r: Redirect) void {
    const port_be = std.mem.nativeToBig(u16, r.port);
    const ifname = ifnameBytes(r.ifname);
    b.begin(nfnl_msg_batch_begin, 0, 0, false);
    b.end();
    b.begin((nfnl_subsys_nftables << 8) | nft_msg_newtable, nlm_f_create, nfproto_inet, true);
    b.str(nfta_table_name, r.table);
    b.be32(nfta_table_flags, 0);
    b.end();
    b.baseChain(r.table, "output", "nat", hook_output, -100);
    b.baseChain(r.table, "prerouting", "nat", hook_prerouting, -100);
    b.baseChain(r.table, "input", "filter", hook_input, 0);

    b.ruleBegin(r.table, "output");
    b.meta(meta_l4proto);
    b.cmp(&.{6});
    b.meta(meta_oifname);
    b.cmp(&ifname);
    redirectTo(b, &port_be);
    b.ruleEnd();

    b.ruleBegin(r.table, "prerouting");
    b.meta(meta_l4proto);
    b.cmp(&.{6});
    b.expr("fib");
    b.be32(1, reg1);
    b.be32(2, fib_result_oifname);
    b.be32(3, fib_f_daddr | fib_f_iif);
    b.exprEnd();
    b.cmp(&ifname);
    redirectTo(b, &port_be);
    b.ruleEnd();

    b.ruleBegin(r.table, "input");
    b.meta(meta_l4proto);
    b.cmp(&.{6});
    b.expr("payload");
    b.be32(1, reg1);
    b.be32(2, payload_transport);
    b.be32(3, 2);
    b.be32(4, 2);
    b.exprEnd();
    b.cmp(std.mem.asBytes(&port_be));
    b.expr("ct");
    b.be32(1, reg1);
    b.be32(2, ct_status);
    b.exprEnd();
    const mask: u32 = ips_dst_nat;
    const zero: u32 = 0;
    b.expr("bitwise");
    b.be32(1, reg1);
    b.be32(2, reg1);
    b.be32(3, 4);
    b.data(4, std.mem.asBytes(&mask));
    b.data(5, std.mem.asBytes(&zero));
    b.exprEnd();
    b.cmp(std.mem.asBytes(&zero));
    b.expr("reject");
    b.be32(1, reject_tcp_rst);
    b.exprEnd();
    b.ruleEnd();

    b.begin(nfnl_msg_batch_end, 0, 0, false);
    b.end();
}

fn redirectTo(b: *Batch, port_be: *const u16) void {
    b.expr("immediate");
    b.be32(1, reg1);
    b.data(2, std.mem.asBytes(port_be));
    b.exprEnd();
    b.expr("redir");
    b.be32(1, reg1);
    b.exprEnd();
}

test "nftables batch encodes aligned messages" {
    var b = newBatch();
    encode(&b, .{ .ifname = "zeptun0", .port = 4321 });
    try std.testing.expect(b.len % 4 == 0);
    try std.testing.expectEqual(@as(u32, 7), b.acked);
    var off: usize = 0;
    var messages: usize = 0;
    while (off < b.len) {
        const h = std.mem.bytesToValue(NlMsgHdr, b.buf[off..][0..@sizeOf(NlMsgHdr)]);
        try std.testing.expect(h.len >= @sizeOf(NlMsgHdr) + 4);
        off += std.mem.alignForward(usize, h.len, 4);
        messages += 1;
    }
    try std.testing.expectEqual(b.len, off);
    try std.testing.expectEqual(@as(usize, 9), messages);
}
