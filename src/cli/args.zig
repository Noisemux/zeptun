const std = @import("std");
const zeptun = @import("zeptun");
const config = zeptun.config;
const addr = zeptun.addr;
const log = zeptun.log;
const config_json = zeptun.config_json;

pub const Command = enum { run, version, probe, help };

pub const Parsed = struct {
    command: Command = .run,
    config_path: ?[]const u8 = null,
    st: config_json.State = .{},
};

pub const Error = error{ InvalidArgument, MissingValue, UnknownOption, ConfigError, OutOfMemory };

pub const usage =
    \\usage: zeptun [run|probe|version|help] [options]
    \\
    \\device:
    \\  --tun NAME                 TUN interface name (default zeptun0)
    \\  --tun-fd FD                use an existing TUN file descriptor
    \\  --netns NAME               create the interface inside this network namespace
    \\  --tun-guid GUID            fixed adapter GUID for the Wintun device (Windows)
    \\  --udp-nat MODE             endpoint-independent (default), address or address-port
    \\  --mtu N                    interface MTU (default 1500)
    \\  --queues N                 most queues and workers, 0 = automatic (one per CPU while elastic, else CPUs / 4)
    \\  --elastic MODE             auto | on | off | rotate: start with one queue, attach more only when they add throughput
    \\  --address CIDR             interface address, repeatable (IPv4 and IPv6)
    \\  --no-address               do not assign default addresses
    \\  --no-offload               disable IFF_VNET_HDR and TSO/USO offloads
    \\  --no-multi-queue           single queue device
    \\  --persist                  keep the device after exit
    \\  --tun-napi                 deliver injected packets through NAPI with GRO (IFF_NAPI)
    \\  --no-jumbo                 without offloads, keep TCP segments to the client within the MTU
    \\  --txqueuelen N             device queue length (default: 1000-4096 packets without offloads)
    \\  --no-configure             do not configure link, addresses or routes
    \\stack:
    \\  --stack MODE               userspace (default) | hybrid | system
    \\  --preset NAME              desktop | mobile | server
    \\  --max-tcp N                TCP session cap
    \\  --max-udp N                UDP session cap
    \\  --tcp-rx-window BYTES      largest per connection receive window
    \\  --tcp-rx-budget BYTES      per worker memory windows may grow into beyond their 128K start
    \\  --tcp-tx-budget BYTES      per worker memory downlink queues may grow into beyond their floor
    \\  --tcp-tx-buffer BYTES      per connection send buffer
    \\  --tcp-idle-timeout MS
    \\  --tcp-delayed-ack MS       piggyback ACKs for small segments up to MS, 0 = ACK immediately
    \\  --tcp-early-accept         complete the client handshake before the upstream connects (default with socks5)
    \\  --no-tcp-early-accept      wait for the upstream before completing the client handshake
    \\  --udp-timeout MS
    \\  --congestion ALG           cubic | newreno
    \\  --no-udp                   reject UDP flows
    \\  --icmp MODE                auto (forward with direct, local with socks5) | forward | local | drop
    \\handler:
    \\  --handler KIND             direct | socks5
    \\  --socks5 HOST:PORT         SOCKS5 server, implies --handler socks5
    \\  --socks5-user USER
    \\  --socks5-pass PASS
    \\  --socks5-no-udp            disable UDP ASSOCIATE
    \\  --socks5-udp-mode MODE     udp (UDP ASSOCIATE, default) | tcp (datagrams framed over the control connection)
    \\  --socks5-udp-address ADDR  use this address instead of the relay address the server reports
    \\  --socks5-pipeline          send greeting, auth and request in one write (default without auth)
    \\  --socks5-no-pipeline       wait for each SOCKS5 reply before the next message
    \\  --socks5-no-optimistic     do not send buffered client data together with the CONNECT request
    \\  --socks5-pool N            pre-connected, pre-authenticated proxy connections per worker (default 4, 0 = off)
    \\  --socks5-pool-idle MS      recycle idle pooled connections after MS (default 3000)
    \\  --tcp-fastopen             use TCP Fast Open for upstream connections
    \\  --no-dscp                  do not copy the client DSCP marking to upstream sockets
    \\  --fwmark N                 SO_MARK for upstream sockets
    \\  --bind-interface NAME      bind upstream sockets to an interface
    \\dns:
    \\  --fake-ip                  answer A/AAAA queries with fake addresses and send domains to the SOCKS5 proxy
    \\  --fake-ip-range CIDR       fake address pool, repeatable for IPv4 and IPv6 (default 198.18.0.0/15, fc00::/18)
    \\  --fake-ip-cache N          remembered domains (default 16384)
    \\  --fake-ip-ttl SECONDS      TTL of fake answers (default 1)
    \\  --dns-address ADDR         in-tunnel DNS server address (default second address of the TUN prefix)
    \\  --dns-hijack               capture DNS sent to any address
    \\  --systemd-resolved MODE    auto | on | off: point systemd-resolved at the in-tunnel resolver while the tunnel is up
    \\  --dns-upstream HOST:PORT   resolver for hijacked or non-address queries
    \\routing:
    \\  --auto-route               install policy routing through the tunnel
    \\  --route CIDR               route only this prefix through the tunnel, repeatable, implies --auto-route
    \\  --exclude CIDR             keep this prefix off the tunnel, repeatable
    \\  --route-file FILE          read tunnel prefixes from FILE, one per line
    \\  --exclude-file FILE        read excluded prefixes from FILE, one per line
    \\  --strict-route             block address families the tunnel does not carry instead of leaking them
    \\  --auto-redirect            send TCP headed for the tunnel to a kernel socket with nftables instead (Linux)
    \\  --redirect-port N          port of the redirect listener (default: chosen by the kernel)
    \\  --include-uid UID[-UID]    only route these users through the tunnel, repeatable (Linux)
    \\  --exclude-uid UID[-UID]    keep these users off the tunnel, repeatable (Linux)
    \\  --include-package NAME     only route this Android app through the tunnel, repeatable (Android root)
    \\  --exclude-package NAME     keep this Android app off the tunnel, repeatable (Android root)
    \\  --android-user N           only route these Android users, repeatable (Android root)
    \\  --include-interface NAME   only route traffic arriving on NAME, repeatable (Linux)
    \\  --exclude-interface NAME   keep traffic arriving on NAME off the tunnel, repeatable (Linux)
    \\  --table N                  routing table (default 2022)
    \\  --rule-priority N          first of ten rule priorities (default 9000)
    \\io:
    \\  --io BACKEND               auto | io_uring | epoll
    \\  --sqpoll                   enable io_uring SQPOLL
    \\  --ring-entries N
    \\  --rx-parallel N            concurrent device reads per queue
    \\  --tx-slots N               in-flight device writes per queue
    \\  --busy-poll MICROS         keep polling this long after activity before sleeping
    \\  --no-multishot             read the TUN with parallel reads instead of io_uring multishot
    \\  --no-network-monitor       do not watch for default route changes
    \\  --pin                      pin each worker to one CPU
    \\  --no-pin                   do not pin workers to CPUs (default)
    \\  --memory-budget BYTES      bound buffer pools and sessions
    \\  --buffers N                packet buffers per worker
    \\misc:
    \\  -c, --config FILE          JSON configuration file
    \\  --log-level LEVEL          err | warn | info | debug
    \\  --log-file FILE            append logs to FILE instead of stderr
    \\  --pid-file FILE            write the process id to FILE while running
    \\  --post-up SCRIPT           run /bin/sh SCRIPT IFNAME after the tunnel is up
    \\  --pre-down SCRIPT          run /bin/sh SCRIPT IFNAME before the tunnel is torn down
    \\  --stats SECONDS            print counters periodically
    \\  -h, --help
    \\
;

fn parseEnum(comptime E: type, text: []const u8) Error!E {
    return std.meta.stringToEnum(E, text) orelse error.InvalidArgument;
}

fn parseInt(comptime T: type, text: []const u8) Error!T {
    return std.fmt.parseInt(T, text, 0) catch error.InvalidArgument;
}

fn parseSize(text: []const u8) Error!u64 {
    if (text.len == 0) return error.InvalidArgument;
    const last = std.ascii.toLower(text[text.len - 1]);
    const mult: u64 = switch (last) {
        'k' => 1 << 10,
        'm' => 1 << 20,
        'g' => 1 << 30,
        else => 1,
    };
    const digits = if (mult == 1) text else text[0 .. text.len - 1];
    return (std.fmt.parseInt(u64, digits, 10) catch return error.InvalidArgument) * mult;
}

fn splitAssignments(arena: std.mem.Allocator, argv: []const []const u8) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (argv) |a| {
        if (std.mem.startsWith(u8, a, "--")) {
            if (std.mem.findScalar(u8, a, '=')) |eq| {
                try out.append(arena, a[0..eq]);
                try out.append(arena, a[eq + 1 ..]);
                continue;
            }
        }
        try out.append(arena, a);
    }
    return out.items;
}

pub fn parse(arena: std.mem.Allocator, raw_argv: []const []const u8) Error!Parsed {
    const argv = try splitAssignments(arena, raw_argv);
    var p: Parsed = .{};
    var i: usize = 0;
    if (i < argv.len) {
        if (std.meta.stringToEnum(Command, argv[i])) |cmd| {
            p.command = cmd;
            i += 1;
        }
    }
    var j = i;
    while (j < argv.len) : (j += 1) {
        const a = argv[j];
        if (std.mem.eql(u8, a, "--preset")) {
            if (j + 1 >= argv.len) return error.MissingValue;
            p.st.cfg = config.Config.fromPreset(try parseEnum(config.Preset, argv[j + 1]));
        }
    }
    j = i;
    while (j < argv.len) : (j += 1) {
        const a = argv[j];
        if (std.mem.eql(u8, a, "-c") or std.mem.eql(u8, a, "--config")) {
            if (j + 1 >= argv.len) return error.MissingValue;
            p.config_path = argv[j + 1];
            try loadFile(arena, &p, argv[j + 1]);
        }
    }
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        const Flag = struct {
            fn value(list: []const []const u8, idx: *usize) Error![]const u8 {
                if (idx.* + 1 >= list.len) return error.MissingValue;
                idx.* += 1;
                return list[idx.*];
            }
        };
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            p.command = .help;
        } else if (std.mem.eql(u8, a, "-c") or std.mem.eql(u8, a, "--config") or std.mem.eql(u8, a, "--preset")) {
            i += 1;
        } else if (std.mem.eql(u8, a, "--tun")) {
            const v = try Flag.value(argv, &i);
            if (v.len >= 16) return error.InvalidArgument;
            p.st.cfg.device.name = .init(v);
            p.st.cfg.device.kind = .tun;
        } else if (std.mem.eql(u8, a, "--udp-nat")) {
            const v = try Flag.value(argv, &i);
            p.st.cfg.stack.udp_nat = if (std.mem.eql(u8, v, "endpoint-independent"))
                .endpoint_independent
            else if (std.mem.eql(u8, v, "address"))
                .address
            else if (std.mem.eql(u8, v, "address-port"))
                .address_port
            else
                return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--tun-guid")) {
            const v = try Flag.value(argv, &i);
            p.st.cfg.device.guid = config.Guid.parse(v) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--netns")) {
            const v = try Flag.value(argv, &i);
            p.st.cfg.device.netns = .init(v);
        } else if (std.mem.eql(u8, a, "--tun-fd")) {
            p.st.cfg.device.fd = try parseInt(i32, try Flag.value(argv, &i));
            p.st.cfg.device.kind = .fd;
            p.st.cfg.stack.mode = .userspace;
        } else if (std.mem.eql(u8, a, "--mtu")) {
            p.st.cfg.device.mtu = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--queues")) {
            const q = try parseInt(u16, try Flag.value(argv, &i));
            p.st.cfg.device.queues = q;
            p.st.cfg.io.workers = q;
        } else if (std.mem.eql(u8, a, "--elastic")) {
            p.st.cfg.io.elastic = try parseEnum(config.ElasticMode, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--address")) {
            try p.st.addAddress(try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--no-address")) {
            p.st.cfg.device.address4 = null;
            p.st.cfg.device.address6 = null;
            p.st.addresses_overridden = true;
        } else if (std.mem.eql(u8, a, "--no-offload")) {
            p.st.cfg.device.offload = false;
        } else if (std.mem.eql(u8, a, "--no-multi-queue")) {
            p.st.cfg.device.multi_queue = false;
        } else if (std.mem.eql(u8, a, "--tun-napi")) {
            p.st.cfg.device.napi = true;
        } else if (std.mem.eql(u8, a, "--no-jumbo")) {
            p.st.cfg.device.jumbo = false;
        } else if (std.mem.eql(u8, a, "--txqueuelen")) {
            p.st.cfg.device.txqueuelen = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--persist")) {
            p.st.cfg.device.persist = true;
        } else if (std.mem.eql(u8, a, "--no-configure")) {
            p.st.cfg.device.configure = false;
        } else if (std.mem.eql(u8, a, "--stack")) {
            p.st.cfg.stack.mode = try parseEnum(config.StackMode, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--max-tcp")) {
            p.st.cfg.stack.max_tcp_sessions = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--max-udp")) {
            p.st.cfg.stack.max_udp_sessions = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--tcp-rx-window")) {
            p.st.cfg.stack.tcp_rx_window = @intCast(@min(try parseSize(try Flag.value(argv, &i)), 1 << 30));
        } else if (std.mem.eql(u8, a, "--tcp-rx-budget")) {
            p.st.cfg.stack.tcp_rx_budget = @intCast(@min(try parseSize(try Flag.value(argv, &i)), 1 << 30));
        } else if (std.mem.eql(u8, a, "--tcp-tx-buffer")) {
            p.st.cfg.stack.tcp_tx_buffer = @intCast(@min(try parseSize(try Flag.value(argv, &i)), 1 << 30));
        } else if (std.mem.eql(u8, a, "--tcp-tx-budget")) {
            p.st.cfg.stack.tcp_tx_budget = @intCast(@min(try parseSize(try Flag.value(argv, &i)), 1 << 30));
        } else if (std.mem.eql(u8, a, "--tcp-idle-timeout")) {
            p.st.cfg.stack.tcp_idle_timeout_ms = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--udp-timeout")) {
            p.st.cfg.stack.udp_idle_timeout_ms = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--congestion")) {
            p.st.cfg.stack.tcp_congestion = try parseEnum(config.Congestion, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--no-udp")) {
            p.st.cfg.stack.udp = .disabled;
        } else if (std.mem.eql(u8, a, "--icmp")) {
            p.st.cfg.stack.icmp = try parseEnum(config.IcmpMode, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--handler")) {
            p.st.cfg.handler.kind = try parseEnum(config.HandlerKind, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--socks5")) {
            p.st.cfg.handler.socks5.server = addr.Endpoint.parse(try Flag.value(argv, &i)) catch return error.InvalidArgument;
            p.st.cfg.handler.kind = .socks5;
        } else if (std.mem.eql(u8, a, "--socks5-user")) {
            p.st.cfg.handler.socks5.username = .init(try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--socks5-pass")) {
            p.st.cfg.handler.socks5.password = .init(try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--socks5-no-udp")) {
            p.st.cfg.handler.socks5.udp = .disabled;
        } else if (std.mem.eql(u8, a, "--socks5-udp-mode")) {
            p.st.cfg.handler.socks5.udp_mode = try parseEnum(config.Socks5UdpMode, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--socks5-udp-address")) {
            p.st.cfg.handler.socks5.udp_address = addr.Address.parse(try Flag.value(argv, &i)) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--socks5-pipeline")) {
            p.st.cfg.handler.socks5.pipeline = .on;
        } else if (std.mem.eql(u8, a, "--socks5-no-pipeline")) {
            p.st.cfg.handler.socks5.pipeline = .off;
        } else if (std.mem.eql(u8, a, "--fwmark")) {
            p.st.cfg.handler.direct.fwmark = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--bind-interface")) {
            p.st.cfg.handler.direct.bind_interface = .init(try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--auto-route")) {
            p.st.cfg.route.auto_route = true;
        } else if (std.mem.eql(u8, a, "--route")) {
            try p.st.addPrefix(arena, true, addr.Prefix.parse(try Flag.value(argv, &i)) catch return error.InvalidArgument);
            p.st.cfg.route.auto_route = true;
        } else if (std.mem.eql(u8, a, "--exclude")) {
            try p.st.addPrefix(arena, false, addr.Prefix.parse(try Flag.value(argv, &i)) catch return error.InvalidArgument);
        } else if (std.mem.eql(u8, a, "--route-file")) {
            try p.st.loadPrefixFile(arena, true, try Flag.value(argv, &i));
            p.st.cfg.route.auto_route = true;
        } else if (std.mem.eql(u8, a, "--exclude-file")) {
            try p.st.loadPrefixFile(arena, false, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--strict-route")) {
            p.st.cfg.route.strict = true;
        } else if (std.mem.eql(u8, a, "--auto-redirect")) {
            p.st.cfg.route.auto_redirect = true;
            p.st.cfg.route.auto_route = true;
        } else if (std.mem.eql(u8, a, "--redirect-port")) {
            p.st.cfg.route.redirect_port = try parseInt(u16, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--include-uid")) {
            p.st.cfg.route.include_uids.append(config.UidRange.parse(try Flag.value(argv, &i)) catch return error.InvalidArgument) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--exclude-uid")) {
            p.st.cfg.route.exclude_uids.append(config.UidRange.parse(try Flag.value(argv, &i)) catch return error.InvalidArgument) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--include-package")) {
            p.st.cfg.route.include_packages.append(try Flag.value(argv, &i)) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--exclude-package")) {
            p.st.cfg.route.exclude_packages.append(try Flag.value(argv, &i)) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--android-user")) {
            const u = try parseInt(u32, try Flag.value(argv, &i));
            p.st.cfg.route.android_users.append(.{ .start = u, .end = u }) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--include-interface")) {
            p.st.cfg.route.include_interfaces.append(try Flag.value(argv, &i)) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--exclude-interface")) {
            p.st.cfg.route.exclude_interfaces.append(try Flag.value(argv, &i)) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--table")) {
            p.st.cfg.route.table = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--rule-priority")) {
            p.st.cfg.route.rule_priority = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--io")) {
            p.st.cfg.io.backend = try parseEnum(config.IoBackend, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--sqpoll")) {
            p.st.cfg.io.sqpoll = true;
        } else if (std.mem.eql(u8, a, "--ring-entries")) {
            p.st.cfg.io.ring_entries = try parseInt(u16, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--rx-parallel")) {
            p.st.cfg.io.rx_parallel = try parseInt(u16, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--tx-slots")) {
            p.st.cfg.io.tx_slots = try parseInt(u16, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--no-multishot")) {
            p.st.cfg.io.multishot_rx = false;
        } else if (std.mem.eql(u8, a, "--no-network-monitor")) {
            p.st.cfg.io.monitor_network = .off;
        } else if (std.mem.eql(u8, a, "--busy-poll")) {
            p.st.cfg.io.busy_poll_us = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--no-pin")) {
            p.st.cfg.io.pin_cpus = false;
        } else if (std.mem.eql(u8, a, "--pin")) {
            p.st.cfg.io.pin_cpus = true;
        } else if (std.mem.eql(u8, a, "--tcp-early-accept")) {
            p.st.cfg.stack.tcp_early_accept = .on;
        } else if (std.mem.eql(u8, a, "--no-tcp-early-accept")) {
            p.st.cfg.stack.tcp_early_accept = .off;
        } else if (std.mem.eql(u8, a, "--socks5-no-optimistic")) {
            p.st.cfg.handler.socks5.optimistic_data = false;
        } else if (std.mem.eql(u8, a, "--socks5-pool")) {
            p.st.cfg.handler.socks5.pool_size = try parseInt(u16, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--socks5-pool-idle")) {
            p.st.cfg.handler.socks5.pool_idle_ms = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--tcp-fastopen")) {
            p.st.cfg.handler.tcp_fastopen = true;
        } else if (std.mem.eql(u8, a, "--no-dscp")) {
            p.st.cfg.handler.preserve_dscp = false;
        } else if (std.mem.eql(u8, a, "--fake-ip")) {
            p.st.cfg.dns.fake_ip = true;
        } else if (std.mem.eql(u8, a, "--fake-ip-range")) {
            try p.st.setFakeRange(try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--fake-ip-cache")) {
            p.st.cfg.dns.cache_size = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--fake-ip-ttl")) {
            p.st.cfg.dns.ttl = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--dns-address")) {
            try p.st.setDnsAddress(try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--dns-hijack")) {
            p.st.cfg.dns.hijack = true;
        } else if (std.mem.eql(u8, a, "--systemd-resolved")) {
            p.st.cfg.dns_resolved = try parseEnum(config.AutoMode, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--dns-upstream")) {
            p.st.cfg.dns.upstream = addr.Endpoint.parse(try Flag.value(argv, &i)) catch return error.InvalidArgument;
        } else if (std.mem.eql(u8, a, "--tcp-delayed-ack")) {
            p.st.cfg.stack.tcp_delayed_ack_ms = try parseInt(u16, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--memory-budget")) {
            p.st.cfg.memory.budget_bytes = try parseSize(try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--buffers")) {
            p.st.cfg.memory.buffers_per_worker = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--log-level")) {
            p.st.cfg.log_level = try parseEnum(log.Level, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--stats")) {
            p.st.stats_interval_s = try parseInt(u32, try Flag.value(argv, &i));
        } else if (std.mem.eql(u8, a, "--log-file")) {
            p.st.log_file = try Flag.value(argv, &i);
        } else if (std.mem.eql(u8, a, "--pid-file")) {
            p.st.pid_file = try Flag.value(argv, &i);
        } else if (std.mem.eql(u8, a, "--post-up")) {
            p.st.post_up = try Flag.value(argv, &i);
        } else if (std.mem.eql(u8, a, "--pre-down")) {
            p.st.pre_down = try Flag.value(argv, &i);
        } else {
            return error.UnknownOption;
        }
    }
    if (p.st.cfg.device.kind != .tun) p.st.cfg.stack.mode = .userspace;
    return p;
}

fn loadFile(arena: std.mem.Allocator, p: *Parsed, path: []const u8) Error!void {
    const bytes = zeptun.io.file.readAlloc(arena, path, 1 << 20) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.ConfigError;
    try p.st.applyDocument(arena, bytes);
}

test "parse command line" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const argv = [_][]const u8{ "run", "--tun", "tun9", "--mtu", "8500", "--socks5", "127.0.0.1:1080", "--address", "10.8.0.1/24", "--stack", "userspace", "--tcp-rx-window", "4m", "--stats", "5" };
    const p = try parse(arena_state.allocator(), &argv);
    try std.testing.expectEqual(Command.run, p.command);
    try std.testing.expectEqualStrings("tun9", p.st.cfg.device.name.slice());
    try std.testing.expectEqual(@as(u32, 8500), p.st.cfg.device.mtu);
    try std.testing.expectEqual(config.HandlerKind.socks5, p.st.cfg.handler.kind);
    try std.testing.expectEqual(@as(u16, 1080), p.st.cfg.handler.socks5.server.port);
    try std.testing.expect(p.st.cfg.device.address6 == null);
    try std.testing.expectEqual(@as(u8, 24), p.st.cfg.device.address4.?.bits);
    try std.testing.expectEqual(@as(u32, 4 << 20), p.st.cfg.stack.tcp_rx_window);
    try std.testing.expectEqual(@as(u32, 5), p.st.stats_interval_s);
    try std.testing.expectError(error.UnknownOption, parse(arena_state.allocator(), &[_][]const u8{"--bogus"}));
}

test "parse namespace and nat options" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const argv = [_][]const u8{ "run", "--netns", "office", "--udp-nat", "address-port", "--systemd-resolved", "off", "--tun-guid", "{24198F4C-7895-434C-AD35-9E29A92DDC51}" };
    const p = try parse(arena_state.allocator(), &argv);
    try std.testing.expectEqualStrings("office", p.st.cfg.device.netns.slice());
    try std.testing.expectEqual(@as(u32, 0x24198F4C), p.st.cfg.device.guid.?.d1);
    try std.testing.expectEqual(config.NatMode.address_port, p.st.cfg.stack.udp_nat);
    try std.testing.expectEqual(config.AutoMode.off, p.st.cfg.dns_resolved);
    try std.testing.expectError(error.InvalidArgument, parse(arena_state.allocator(), &[_][]const u8{ "run", "--udp-nat", "cone" }));
}
