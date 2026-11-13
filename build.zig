//! zigware build graph.
//!
//! Layout mirrors commonwarexyz/monorepo: every commonware crate is one package at
//! `src/<name>/root.zig`, built as its own Zig module that may import only the packages
//! listed as its dependencies below (the same dependency graph as the Rust crates).
//! `src/zigware.zig` re-exports every package as the `zigware` module.
//! Examples live at `examples/<name>/main.zig`.
//!
//! Steps:
//!   zig build                 install every example binary into zig-out/bin
//!   zig build test            run every package's unit tests (-Dtest-filter=... to narrow)
//!   zig build test-<package>  run one package's unit tests, e.g. zig build test-codec
//!   zig build run-<example>   run an example: zig build run-log -- --help
//!   zig build check           compile everything without running

const std = @import("std");

const Package = struct {
    name: []const u8,
    /// Packages this one may `@import`, by name. Mirrors the crate's Cargo.toml
    /// `[dependencies]` (proc-macro crates are comptime code in Zig and have no package).
    deps: []const []const u8,
};

/// Every package, in dependency order. Add a dependency edge here when a package needs
/// another; the graph must stay acyclic and match commonware's.
const packages = [_]Package{
    .{ .name = "formatting", .deps = &.{} },
    .{ .name = "allocator", .deps = &.{} },
    .{ .name = "bench", .deps = &.{} },
    .{ .name = "conformance", .deps = &.{"formatting"} },
    .{ .name = "invariants", .deps = &.{"formatting"} },
    .{ .name = "simd", .deps = &.{"invariants"} },
    .{ .name = "codec", .deps = &.{ "conformance", "formatting" } },
    .{ .name = "utils", .deps = &.{ "codec", "formatting", "conformance", "invariants" } },
    .{ .name = "parallel", .deps = &.{"utils"} },
    .{ .name = "math", .deps = &.{ "codec", "invariants", "parallel", "utils", "simd" } },
    .{ .name = "cryptography", .deps = &.{
        "codec", "formatting", "math", "parallel", "utils", "invariants", "simd", "conformance",
    } },
    .{ .name = "runtime", .deps = &.{
        "codec", "cryptography", "formatting", "parallel", "utils", "conformance",
    } },
    .{ .name = "actor", .deps = &.{ "runtime", "utils" } },
    .{ .name = "storage", .deps = &.{
        "codec",       "cryptography", "formatting", "parallel", "runtime", "utils", "math",
        "conformance", "invariants",
    } },
    .{ .name = "stream", .deps = &.{
        "codec", "cryptography", "formatting", "math", "runtime", "utils",
    } },
    .{ .name = "coding", .deps = &.{
        "codec",       "cryptography", "parallel", "storage", "utils", "runtime", "invariants",
        "conformance",
    } },
    .{ .name = "clearing", .deps = &.{
        "codec", "cryptography", "formatting", "parallel", "storage", "utils", "runtime",
    } },
    .{ .name = "p2p", .deps = &.{
        "actor",       "codec", "cryptography", "math", "parallel", "runtime", "stream", "utils",
        "conformance",
    } },
    .{ .name = "broadcast", .deps = &.{
        "actor", "codec", "cryptography", "p2p", "parallel", "runtime", "utils",
    } },
    .{ .name = "collector", .deps = &.{
        "actor", "codec", "cryptography", "p2p", "runtime", "utils",
    } },
    .{ .name = "resolver", .deps = &.{
        "actor", "codec", "cryptography", "p2p", "runtime", "stream", "utils", "conformance",
    } },
    .{ .name = "consensus", .deps = &.{
        "actor", "broadcast",   "codec",      "coding",   "cryptography", "formatting",
        "math",  "parallel",    "p2p",        "resolver", "runtime",      "storage",
        "utils", "conformance", "invariants",
    } },
    .{ .name = "glue", .deps = &.{
        "actor",  "broadcast", "codec",    "coding",   "consensus", "cryptography",
        "math",   "p2p",       "parallel", "resolver", "runtime",   "storage",
        "stream", "utils",
    } },
    .{ .name = "deployer", .deps = &.{ "cryptography", "utils" } },
};

/// Example binaries at `examples/<name>/main.zig`; each may import any package.
/// Add an example here once its main.zig exists.
const examples = [_][]const u8{};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filter = b.option([]const u8, "test-filter", "Only run tests matching");
    const filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};

    const options = b.addOptions();
    options.addOption([]const u8, "version", "0.0.0");
    const git_rev = b.option([]const u8, "git-rev", "Git revision baked into binaries");
    options.addOption([]const u8, "git_rev", git_rev orelse "unknown");
    const slow_tests = b.option(bool, "slow-tests", "Also run large tests") orelse false;
    options.addOption(bool, "slow_tests", slow_tests);
    const fuzz_soak = b.option(u32, "fuzz-soak", "Multiply seeded fuzz iterations") orelse 1;
    options.addOption(u32, "fuzz_soak", fuzz_soak);
    const fuzz_seed = b.option(u64, "fuzz-seed", "Mixed into every seeded fuzz seed") orelse 0;
    options.addOption(u64, "fuzz_seed", fuzz_seed);
    const minifuzz_branch = b.option([]const u8, "minifuzz-branch", "Replay a minifuzz failure");
    options.addOption([]const u8, "minifuzz_branch", minifuzz_branch orelse "");
    const options_module = options.createModule();

    // One module per package, then the dependency edges.
    var modules: [packages.len]*std.Build.Module = undefined;
    for (packages, 0..) |package, index| {
        modules[index] = b.addModule(package.name, .{
            .root_source_file = b.path(b.fmt("src/{s}/root.zig", .{package.name})),
            .target = target,
            .optimize = optimize,
        });
        modules[index].addImport("build_options", options_module);
    }
    for (packages, 0..) |package, index| {
        for (package.deps) |dep| modules[index].addImport(dep, modules[package_index(dep)]);
    }

    // `zigware`: every package under one name, for examples and downstream users.
    const zigware = b.addModule("zigware", .{
        .root_source_file = b.path("src/zigware.zig"),
        .target = target,
        .optimize = optimize,
    });
    for (packages, 0..) |package, index| zigware.addImport(package.name, modules[index]);

    const test_step = b.step("test", "Run every package's unit tests");
    const check_step = b.step("check", "Compile everything without running");
    for (packages, 0..) |package, index| {
        const tests = b.addTest(.{
            .name = b.fmt("test-{s}", .{package.name}),
            .root_module = modules[index],
            .filters = filters,
        });
        const run = b.addRunArtifact(tests);
        test_step.dependOn(&run.step);
        check_step.dependOn(&tests.step);
        const step_name = b.fmt("test-{s}", .{package.name});
        b.step(step_name, b.fmt("Run {s} unit tests", .{package.name})).dependOn(&run.step);
    }

    add_examples(b, zigware, target, optimize, test_step, check_step, filters);
}

fn package_index(name: []const u8) usize {
    for (packages, 0..) |package, index| {
        if (std.mem.eql(u8, package.name, name)) return index;
    }
    std.debug.panic("build.zig: unknown package dependency '{s}'", .{name});
}

/// Each example gets an install, a `run-<name>` step, and its own test binary.
fn add_examples(
    b: *std.Build,
    zigware: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    check_step: *std.Build.Step,
    filters: []const []const u8,
) void {
    for (examples) |name| {
        const root = b.createModule(.{
            .root_source_file = b.path(b.fmt("examples/{s}/main.zig", .{name})),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zigware", .module = zigware }},
        });
        const exe = b.addExecutable(.{ .name = name, .root_module = root });
        b.installArtifact(exe);
        check_step.dependOn(&exe.step);

        const run = b.addRunArtifact(exe);
        run.addPassthruArgs();
        b.step(b.fmt("run-{s}", .{name}), b.fmt("Run the {s} example", .{name}))
            .dependOn(&run.step);

        const tests = b.addTest(.{
            .name = b.fmt("test-example-{s}", .{name}),
            .root_module = root,
            .filters = filters,
        });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }
}
