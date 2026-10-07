const std = @import("std");

const Features = struct {
    socks5: bool,
    direct: bool,
    passthrough: bool,
    userspace_tcp: bool,
    system_stack: bool,
    io_uring: bool,
    epoll: bool,
    icmp: bool,
    ipv6: bool,
    fragments: bool,
    gso: bool,
    route: bool,
    tracing: bool,
    max_log_level: u8,
    mobile: bool,
};

const Overrides = struct {
    mobile: ?bool,
    socks5: ?bool,
    direct: ?bool,
    passthrough: ?bool,
    userspace_tcp: ?bool,
    system_stack: ?bool,
    io_uring: ?bool,
    epoll: ?bool,
    icmp: ?bool,
    ipv6: ?bool,
    fragments: ?bool,
    gso: ?bool,
    route: ?bool,
    tracing: ?bool,
    max_log_level: ?u8,

    fn read(b: *std.Build) Overrides {
        return .{
            .mobile = b.option(bool, "mobile", "Mobile preset: userspace stack only, no io_uring, no route module"),
            .socks5 = b.option(bool, "enable-socks5", "Compile the SOCKS5 handler"),
            .direct = b.option(bool, "enable-direct", "Compile the direct handler"),
            .passthrough = b.option(bool, "enable-passthrough", "Compile the passthrough handler"),
            .userspace_tcp = b.option(bool, "enable-userspace-tcp", "Compile the userspace TCP terminator"),
            .system_stack = b.option(bool, "enable-system-stack", "Compile the system-stack TCP fast path"),
            .io_uring = b.option(bool, "enable-io-uring", "Compile the io_uring backend"),
            .epoll = b.option(bool, "enable-epoll", "Compile the epoll backend"),
            .icmp = b.option(bool, "enable-icmp", "Compile ICMP handling"),
            .ipv6 = b.option(bool, "enable-ipv6", "Compile IPv6 support"),
            .fragments = b.option(bool, "enable-fragments", "Compile IP fragment reassembly"),
            .gso = b.option(bool, "enable-gso", "Compile GSO/GRO offload paths"),
            .route = b.option(bool, "enable-route", "Compile route and address configuration"),
            .tracing = b.option(bool, "enable-tracing", "Compile trace level logging"),
            .max_log_level = b.option(u8, "max-log-level", "Highest compiled log level, 0=err .. 4=trace"),
        };
    }
};

fn resolveFeatures(o: Overrides, target: std.Target) Features {
    const os = target.os.tag;
    const android = target.abi.isAndroid();
    const mobile = o.mobile orelse (os == .ios or android);
    const linux_desktop = os == .linux and !mobile;
    return .{
        .socks5 = o.socks5 orelse true,
        .direct = o.direct orelse true,
        .passthrough = o.passthrough orelse true,
        .userspace_tcp = o.userspace_tcp orelse true,
        .system_stack = o.system_stack orelse linux_desktop,
        .io_uring = o.io_uring orelse linux_desktop,
        .epoll = o.epoll orelse (os == .linux),
        .icmp = o.icmp orelse true,
        .ipv6 = o.ipv6 orelse true,
        .fragments = o.fragments orelse true,
        .gso = o.gso orelse (os == .linux),
        .route = o.route orelse (os != .ios and os != .tvos and os != .watchos and os != .visionos),
        .tracing = o.tracing orelse false,
        .max_log_level = o.max_log_level orelse 3,
        .mobile = mobile,
    };
}

fn featureOptions(b: *std.Build, f: Features) *std.Build.Step.Options {
    const opts = b.addOptions();
    opts.addOption(bool, "enable_socks5", f.socks5);
    opts.addOption(bool, "enable_direct", f.direct);
    opts.addOption(bool, "enable_passthrough", f.passthrough);
    opts.addOption(bool, "enable_userspace_tcp", f.userspace_tcp);
    opts.addOption(bool, "enable_system_stack", f.system_stack);
    opts.addOption(bool, "enable_io_uring", f.io_uring);
    opts.addOption(bool, "enable_epoll", f.epoll);
    opts.addOption(bool, "enable_icmp", f.icmp);
    opts.addOption(bool, "enable_ipv6", f.ipv6);
    opts.addOption(bool, "enable_fragments", f.fragments);
    opts.addOption(bool, "enable_gso", f.gso);
    opts.addOption(bool, "enable_route", f.route);
    opts.addOption(bool, "enable_tracing", f.tracing);
    opts.addOption(u8, "max_log_level", f.max_log_level);
    opts.addOption(bool, "mobile", f.mobile);
    opts.addOption([]const u8, "version", "1.1.3");
    return opts;
}

fn needsLibc(t: std.Target) bool {
    return switch (t.os.tag) {
        .macos, .ios, .tvos, .visionos, .freebsd, .openbsd, .netbsd, .dragonfly => true,
        else => false,
    };
}

fn canLinkExecutables(t: std.Target) bool {
    return switch (t.os.tag) {
        .ios, .tvos, .visionos, .watchos => false,
        else => true,
    };
}

fn supportsShared(t: std.Target) bool {
    return switch (t.os.tag) {
        .ios, .tvos, .visionos, .watchos => false,
        else => true,
    };
}

const Artifacts = struct {
    engine: *std.Build.Module,
    ffi: *std.Build.Module,
    static_lib: *std.Build.Step.Compile,
    shared_lib: ?*std.Build.Step.Compile,
};

fn ffiLinksLibc(t: std.Target, android_libc: ?[]const u8) bool {
    if (needsLibc(t)) return true;
    return switch (t.os.tag) {
        .linux => if (t.abi.isAndroid()) android_libc != null else true,
        else => false,
    };
}

var android_libc_file: ?[]const u8 = null;

fn makeArtifacts(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, o: Overrides, strip: ?bool) Artifacts {
    const features = resolveFeatures(o, target.result);
    const lib_libc = ffiLinksLibc(target.result, android_libc_file);
    const engine = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = needsLibc(target.result),
        .pic = true,
        .strip = strip,
    });
    engine.addOptions("build_options", featureOptions(b, features));
    const ffi = b.createModule(.{
        .root_source_file = b.path("src/ffi/ffi.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = lib_libc,
        .pic = true,
        .strip = strip,
    });
    ffi.addImport("zeptun", engine);
    const static_lib = b.addLibrary(.{ .name = if (target.result.abi == .msvc) "zeptun_static" else "zeptun", .root_module = ffi, .linkage = .static });
    if (target.result.abi.isAndroid() and lib_libc) static_lib.setLibCFile(.{ .cwd_relative = android_libc_file.? });
    var shared_lib: ?*std.Build.Step.Compile = null;
    if (supportsShared(target.result)) {
        const shared_mod = b.createModule(.{
            .root_source_file = b.path("src/ffi/ffi.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = lib_libc,
            .pic = true,
            .strip = strip,
        });
        shared_mod.addImport("zeptun", engine);
        const lib = b.addLibrary(.{
            .name = "zeptun",
            .root_module = shared_mod,
            .linkage = .dynamic,
            .version = if (target.result.abi.isAndroid()) null else .{ .major = 1, .minor = 1, .patch = 3 },
        });
        if (target.result.os.tag == .linux) {
            lib.link_z_max_page_size = 16384;
            lib.link_z_common_page_size = 16384;
        }
        if (target.result.abi.isAndroid() and lib_libc) lib.setLibCFile(.{ .cwd_relative = android_libc_file.? });
        shared_lib = lib;
    }
    return .{ .engine = engine, .ffi = ffi, .static_lib = static_lib, .shared_lib = shared_lib };
}

const cross_targets = [_][]const u8{
    "x86_64-linux-gnu",
    "x86_64-linux-musl",
    "aarch64-linux-gnu",
    "aarch64-linux-musl",
    "aarch64-linux-android",
    "arm-linux-androideabi",
    "x86_64-linux-android",
    "x86_64-windows-gnu",
    "aarch64-windows-gnu",
    "x86_64-windows-msvc",
    "aarch64-windows-msvc",
    "x86_64-macos",
    "aarch64-macos",
    "aarch64-ios",
    "aarch64-ios-simulator",
    "x86_64-freebsd",
};

const android_abis = [_]struct { triple: []const u8, abi: []const u8 }{
    .{ .triple = "aarch64-linux-android", .abi = "arm64-v8a" },
    .{ .triple = "arm-linux-androideabi", .abi = "armeabi-v7a" },
    .{ .triple = "x86_64-linux-android", .abi = "x86_64" },
    .{ .triple = "x86-linux-android", .abi = "x86" },
};

const ios_slices = [_]struct { triple: []const u8, name: []const u8 }{
    .{ .triple = "aarch64-ios", .name = "ios-arm64" },
    .{ .triple = "aarch64-ios-simulator", .name = "ios-arm64-simulator" },
    .{ .triple = "x86_64-ios-simulator", .name = "ios-x86_64-simulator" },
};

fn resolveTriple(b: *std.Build, triple: []const u8) std.Build.ResolvedTarget {
    const query = std.Target.Query.parse(.{ .arch_os_abi = triple }) catch @panic("invalid cross target triple");
    return b.resolveTargetQuery(query);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const overrides = Overrides.read(b);
    const strip = b.option(bool, "strip", "Strip debug information");
    android_libc_file = b.option([]const u8, "android-libc", "zig libc file describing an Android NDK sysroot, enables pthread workers inside the Android library");

    const main = makeArtifacts(b, target, optimize, overrides, strip);
    b.modules.put(b.graph.arena, "zeptun", main.engine) catch @panic("OOM");
    b.installArtifact(main.static_lib);
    if (main.shared_lib) |lib| b.installArtifact(lib);
    b.installFile("include/zeptun.h", "include/zeptun.h");

    const can_link = canLinkExecutables(target.result);
    if (can_link) {
        const cli_mod = b.createModule(.{
            .root_source_file = b.path("src/cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needsLibc(target.result),
            .strip = strip,
        });
        cli_mod.addImport("zeptun", main.engine);
        const cli = b.addExecutable(.{ .name = "zeptun", .root_module = cli_mod });
        b.installArtifact(cli);
        const run_cli = b.addRunArtifact(cli);
        run_cli.step.dependOn(b.getInstallStep());
        if (b.args) |a| run_cli.addArgs(a);
        b.step("run", "Run the zeptun CLI").dependOn(&run_cli.step);

        const test_filters = b.option([]const []const u8, "test-filter", "Filter unit tests") orelse &.{};
        const engine_tests = b.addTest(.{ .root_module = main.engine, .filters = test_filters });
        const ffi_tests = b.addTest(.{ .root_module = main.ffi, .filters = test_filters });
        const cli_tests = b.addTest(.{ .root_module = cli_mod, .filters = test_filters });
        const test_step = b.step("test", "Run unit tests");
        const test_compile_step = b.step("test-compile", "Compile unit tests without running them, for cross targets");
        for ([_]*std.Build.Step.Compile{ engine_tests, ffi_tests, cli_tests }) |t| {
            test_step.dependOn(&b.addRunArtifact(t).step);
            test_compile_step.dependOn(&t.step);
        }

        if (target.result.os.tag == .linux) {
            const bench_mod = b.createModule(.{
                .root_source_file = b.path("src/bench/main.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = needsLibc(target.result),
                .strip = strip,
            });
            bench_mod.addImport("zeptun", main.engine);
            const bench = b.addExecutable(.{ .name = "zeptun-bench", .root_module = bench_mod });
            b.installArtifact(bench);
            const run_bench = b.addRunArtifact(bench);
            run_bench.addArgs(&.{ "micro", "--json", "zig-out/bench/micro.json", "--markdown", "zig-out/bench/micro.md", "--svg", "zig-out/bench/micro.svg" });
            if (b.args) |a| run_bench.addArgs(a);
            b.step("bench", "Run hot-path microbenchmarks").dependOn(&run_bench.step);
            const bench_tests = b.addTest(.{ .root_module = bench_mod, .filters = test_filters });
            test_step.dependOn(&b.addRunArtifact(bench_tests).step);

            const netns = b.addSystemCommand(&.{ "unshare", "--user", "--map-root-user", "--net", "--", "sh", "-c", "ip link set lo up && exec \"$0\"" });
            netns.addArtifactArg(engine_tests);
            b.step("test-netns", "Run unit tests inside an unprivileged user and network namespace").dependOn(&netns.step);

            const smoke_mod = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true });
            smoke_mod.addCSourceFile(.{ .file = b.path("tests/ffi_smoke.c"), .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" } });
            smoke_mod.addIncludePath(b.path("include"));
            smoke_mod.linkLibrary(main.static_lib);
            const smoke = b.addExecutable(.{ .name = "ffi-smoke", .root_module = smoke_mod });
            const run_smoke = b.addRunArtifact(smoke);
            run_smoke.expectExitCode(0);
            b.step("test-ffi", "Build and run the C ABI smoke test against libzeptun.a").dependOn(&run_smoke.step);

            const integration = b.addSystemCommand(&.{ "sh", "scripts/netns_integration.sh" });
            integration.addArtifactArg(cli);
            integration.addArtifactArg(bench);
            b.step("test-integration", "Run end-to-end tests through a real TUN device in network namespaces").dependOn(&integration.step);
        }
    }

    const cross_step = b.step("cross", "Build libzeptun for the full cross-compilation matrix");
    for (cross_targets) |triple| {
        const rt = resolveTriple(b, triple);
        const art = makeArtifacts(b, rt, optimize, overrides, strip);
        const dest: std.Build.InstallDir = .{ .custom = b.fmt("cross/{s}", .{triple}) };
        cross_step.dependOn(&b.addInstallArtifact(art.static_lib, .{ .dest_dir = .{ .override = dest } }).step);
        if (art.shared_lib) |lib| {
            cross_step.dependOn(&b.addInstallArtifact(lib, .{ .dest_dir = .{ .override = dest } }).step);
        }
    }

    const android_step = b.step("android", "Build 16 KB page aligned libzeptun.so for every Android ABI");
    for (android_abis) |entry| {
        const rt = resolveTriple(b, entry.triple);
        var o = overrides;
        o.mobile = true;
        const art = makeArtifacts(b, rt, if (optimize == .Debug) .ReleaseSmall else optimize, o, true);
        if (art.shared_lib) |lib| {
            const dest: std.Build.InstallDir = .{ .custom = b.fmt("android/jniLibs/{s}", .{entry.abi}) };
            android_step.dependOn(&b.addInstallArtifact(lib, .{ .dest_dir = .{ .override = dest } }).step);
        }
        const prebuilt: std.Build.InstallDir = .{ .custom = b.fmt("android/prebuilt/{s}", .{entry.abi}) };
        android_step.dependOn(&b.addInstallArtifact(art.static_lib, .{ .dest_dir = .{ .override = prebuilt } }).step);
    }

    const ios_step = b.step("ios", "Build ReleaseSmall static libraries for the iOS XCFramework slices");
    for (ios_slices) |slice| {
        const rt = resolveTriple(b, slice.triple);
        var o = overrides;
        o.mobile = true;
        const art = makeArtifacts(b, rt, if (optimize == .Debug) .ReleaseSmall else optimize, o, true);
        const dest: std.Build.InstallDir = .{ .custom = b.fmt("ios/{s}", .{slice.name}) };
        ios_step.dependOn(&b.addInstallArtifact(art.static_lib, .{ .dest_dir = .{ .override = dest } }).step);
    }
    ios_step.dependOn(&b.addInstallFile(b.path("include/zeptun.h"), "ios/include/zeptun.h").step);
    ios_step.dependOn(&b.addInstallFile(b.path("include/module.modulemap"), "ios/include/module.modulemap").step);
}
