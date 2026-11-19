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
//!   zig build test-example-<example>  run one example's tests, e.g. test-example-bridge
//!   zig build check           compile everything without running
//!   zig build bench           measure every package's benchmarks (src/<package>/benches.zig);
//!                             -Dbench-filter=... narrows, COMMONWARE_BENCH_FULL=1 for full inputs

const std = @import("std");

const Package = struct {
    name: []const u8,
    /// Packages this one may `@import`, by name. Mirrors the crate's Cargo.toml
    /// `[dependencies]` (proc-macro crates are comptime code in Zig and have no package).
    deps: []const []const u8,
    /// Directory under `src/` when it differs from `name` (a crate nested in another's).
    dir: ?[]const u8 = null,

    fn path(package: Package) []const u8 {
        return package.dir orelse package.name;
    }
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
    .{ .name = "curve25519", .dir = "cryptography/curve25519", .deps = &.{
        "codec",      "cryptography", "formatting", "math", "parallel", "utils", "conformance",
        "invariants",
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
        "codec",   "cryptography", "formatting", "parallel", "storage", "utils",
        "runtime", "conformance",  "invariants",
    } },
    .{ .name = "p2p", .deps = &.{
        "actor",   "codec",  "cryptography", "math",        "parallel",
        "runtime", "stream", "utils",        "conformance", "invariants",
    } },
    .{ .name = "broadcast", .deps = &.{
        "actor", "codec", "cryptography", "p2p", "parallel", "runtime", "utils", "invariants",
    } },
    .{ .name = "collector", .deps = &.{
        "actor", "codec", "cryptography", "p2p", "runtime", "utils", "invariants",
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
        "actor",  "broadcast", "codec",       "coding",     "consensus", "cryptography",
        "math",   "p2p",       "parallel",    "resolver",   "runtime",   "storage",
        "stream", "utils",     "conformance", "invariants",
    } },
    .{ .name = "deployer", .deps = &.{ "cryptography", "utils" } },
};

/// Example binaries at `examples/<name>/main.zig`; each may import any package and `ui`
/// (`examples/ui/root.zig`, the terminal UI the examples share). An example with several
/// binaries lists each as `<name>/<binary>`, built from `examples/<name>/<binary>.zig` as
/// `<name>-<binary>`.
/// Add an example here once its main.zig exists.
const examples = [_][]const u8{
    "estimator",     "flood",       "chat",           "log",
    "bridge/dealer", "flood/setup", "bridge/indexer", "bridge/validator",
    "dkg",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filter = b.option([]const []const u8, "test-filter", "Only run tests matching any");
    const filters: []const []const u8 = test_filter orelse &.{};

    const options = b.addOptions();
    options.addOption([]const u8, "version", "0.0.0");
    const git_rev = b.option([]const u8, "git-rev", "Git revision baked into binaries");
    options.addOption([]const u8, "git_rev", git_rev orelse "unknown");
    const slow_tests = b.option(bool, "slow-tests", "Also run large tests") orelse false;
    options.addOption(bool, "slow_tests", slow_tests);
    add_test_options(b, options);
    const fuzz_soak = b.option(u32, "fuzz-soak", "Multiply seeded fuzz iterations") orelse 1;
    options.addOption(u32, "fuzz_soak", fuzz_soak);
    const fuzz_soak_budget_s = b.option(
        u32,
        "fuzz-soak-budget-s",
        "Seconds a soaked minifuzz target may run past its unsoaked cases (0: no limit)",
    ) orelse 0;
    options.addOption(u32, "fuzz_soak_budget_s", fuzz_soak_budget_s);
    const fuzz_seed = b.option(u64, "fuzz-seed", "Mixed into every seeded fuzz seed") orelse 0;
    options.addOption(u64, "fuzz_seed", fuzz_seed);
    const minifuzz_branch = b.option([]const u8, "minifuzz-branch", "Replay a minifuzz failure");
    options.addOption([]const u8, "minifuzz_branch", minifuzz_branch orelse "");
    const options_module = options.createModule();

    // One module per package, then the dependency edges.
    var modules: [packages.len]*std.Build.Module = undefined;
    for (packages, 0..) |package, index| {
        modules[index] = b.addModule(package.name, .{
            .root_source_file = b.path(b.fmt("src/{s}/root.zig", .{package.path()})),
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

    add_examples(b, zigware, options_module, target, optimize, test_step, check_step, filters);
    add_benches(b, &modules, options_module, target, optimize, test_step, check_step);
    add_test_rest(b, test_step);

    add_deployer(b, modules[package_index("deployer")], target, optimize, check_step);
}

/// The test-run options: heavy-test sharding and the cancel audit.
fn add_test_options(b: *std.Build, options: *std.Build.Step.Options) void {
    add_heavy_shard_options(b, options);
    add_cancel_audit_option(b, options);
}

/// `-Dcancel-audit` (on by default): the deterministic runtime panics when a task swallows its
/// cancel (catches `error.Canceled` without propagating it or calling `io.recancel()`) and then
/// reaches another cancelation point. `-Dcancel-audit=false` turns it off.
fn add_cancel_audit_option(b: *std.Build, options: *std.Build.Step.Options) void {
    const cancel_audit = b.option(
        bool,
        "cancel-audit",
        "Panic when a deterministic task swallows its cancel (no recancel) and waits again " ++
            "(default: true)",
    ) orelse true;
    options.addOption(bool, "cancel_audit", cancel_audit);
}

/// `-Dheavy-shards=n -Dheavy-shard=i`: with `-Dslow-tests`, run only every n-th heavy test
/// (cryptography's `skip_heavy`), starting at the i-th, so nightly splits them across jobs.
fn add_heavy_shard_options(b: *std.Build, options: *std.Build.Step.Options) void {
    const heavy_shards = b.option(u32, "heavy-shards", "Split heavy slow tests this way") orelse 1;
    const heavy_shard = b.option(u32, "heavy-shard", "Which heavy-test split to run") orelse 0;
    if (heavy_shards == 0 or heavy_shard >= heavy_shards) @panic("need -Dheavy-shard < shards");
    options.addOption(u32, "heavy_shards", heavy_shards);
    options.addOption(u32, "heavy_shard", heavy_shard);
}

/// `test-rest`: every test `test` runs except consensus's and glue's, which CI's other
/// ReleaseSafe jobs run (`zig build test-consensus`, `test-glue`). `test-others` also leaves out
/// cryptography, which nightly runs in jobs of its own.
fn add_test_rest(b: *std.Build, test_step: *std.Build.Step) void {
    const rest = "Run every unit test except consensus and glue";
    add_test_except(b, test_step, "test-rest", rest, &.{ "consensus", "glue" });
    const others = "Run every unit test except consensus, glue, and cryptography";
    add_test_except(b, test_step, "test-others", others, &.{ "consensus", "glue", "cryptography" });
}

/// A step that runs every package test `test` runs except those of `excluded`.
fn add_test_except(
    b: *std.Build,
    test_step: *std.Build.Step,
    name: []const u8,
    description: []const u8,
    comptime excluded: []const []const u8,
) void {
    var excluded_runs: [excluded.len]*std.Build.Step = undefined;
    for (excluded, &excluded_runs) |package, *run| {
        const package_step = b.top_level_steps.get(b.fmt("test-{s}", .{package})).?;
        std.debug.assert(package_step.step.dependencies.items.len == 1);
        run.* = package_step.step.dependencies.items[0];
    }
    const step = b.step(name, description);
    for (test_step.dependencies.items) |dependency| {
        const skip = std.mem.indexOfScalar(*std.Build.Step, &excluded_runs, dependency) != null;
        if (!skip) step.dependOn(dependency);
    }
    const total = test_step.dependencies.items.len;
    std.debug.assert(step.dependencies.items.len + excluded_runs.len == total);
}

/// `deployer`: commonware's deployer CLI (`zig build run-deployer -- aws list`).
fn add_deployer(
    b: *std.Build,
    deployer: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    check_step: *std.Build.Step,
) void {
    const root = b.createModule(.{
        .root_source_file = b.path("src/deployer/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "deployer", .module = deployer }},
    });
    const exe = b.addExecutable(.{ .name = "deployer", .root_module = root });
    b.installArtifact(exe);
    check_step.dependOn(&exe.step);
    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run-deployer", "Run the deployer CLI").dependOn(&run.step);
}

fn package_index(name: []const u8) usize {
    for (packages, 0..) |package, index| {
        if (std.mem.eql(u8, package.name, name)) return index;
    }
    std.debug.panic("build.zig: unknown package dependency '{s}'", .{name});
}

/// Every package with a `src/<package>/benches.zig` gets a `bench-<package>` harness
/// (`src/bench/main.zig`): `zig build bench` measures it (in ReleaseFast unless -Doptimize says
/// otherwise), and `zig build test` runs each benchmark once on the smoke inputs.
fn add_benches(
    b: *std.Build,
    modules: []const *std.Build.Module,
    options_module: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    check_step: *std.Build.Step,
) void {
    const bench_step = b.step("bench", "Measure every package's benchmarks");
    const bench_filter = b.option([]const u8, "bench-filter", "Only run benchmarks matching");
    const bench_install = b.step(
        "bench-install",
        "Install the measured bench harnesses to zig-out/bench (etc/scripts/bench-compare.sh)",
    );
    const bench_optimize: std.builtin.OptimizeMode = if (optimize == .debug)
        .fast
    else
        optimize;
    // Package code compiles in its module's mode, so measured runs get their own graph.
    var measured_modules: [packages.len]*std.Build.Module = undefined;
    for (packages, 0..) |package, index| {
        measured_modules[index] = b.createModule(.{
            .root_source_file = b.path(b.fmt("src/{s}/root.zig", .{package.path()})),
            .target = target,
            .optimize = bench_optimize,
        });
        measured_modules[index].addImport("build_options", options_module);
    }
    for (packages, 0..) |package, index| {
        for (package.deps) |dep| {
            measured_modules[index].addImport(dep, measured_modules[package_index(dep)]);
        }
    }
    for (packages, 0..) |package, index| {
        const path = b.fmt("src/{s}/benches.zig", .{package.path()});
        b.dependOnDirectoryContents(b.path(b.fmt("src/{s}", .{package.path()})));
        b.root.access(b.graph.io, path, .{}) catch continue;
        for ([_]std.builtin.OptimizeMode{ optimize, bench_optimize }, 0..) |mode, measured| {
            const graph = if (measured == 0) modules else &measured_modules;
            const exe = bench_harness(b, graph, options_module, package, index, path, target, mode);
            const run = b.addRunArtifact(exe);
            if (measured == 0) {
                run.addArg("--test");
                run.expectExitCode(0); // Checked runs keep the smoke log out of test output.
                check_step.dependOn(&exe.step);
                test_step.dependOn(&run.step);
            } else {
                run.addArg("--bench");
                run.has_side_effects = true;
                const installed = b.addInstallArtifact(exe, .{
                    .dest_dir = .{ .override = .{ .custom = "bench" } },
                });
                bench_install.dependOn(&installed.step);
                if (bench_filter) |filter| run.addArgs(&.{ "--", filter });
                bench_step.dependOn(&run.step);
            }
        }
    }
    add_qmdb_harnesses(b, &measured_modules, modules, target, optimize, test_step, check_step);
}

/// commonware's opt-in QMDB harnesses (`storage/src/qmdb/benches/{cold_read,constantinople,
/// scale}.rs`): `zig build qmdb-<name> -- <args>` runs one in ReleaseFast unless -Doptimize
/// says otherwise; `zig build test` runs each harness's tiny smoke test.
fn add_qmdb_harnesses(
    b: *std.Build,
    measured_modules: []const *std.Build.Module,
    modules: []const *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    check_step: *std.Build.Step,
) void {
    const harness_optimize: std.builtin.OptimizeMode = if (optimize == .debug) .fast else optimize;
    const imports = [_][]const u8{
        "bench", "codec", "cryptography", "parallel", "runtime", "storage", "utils",
    };
    for ([_][]const u8{ "cold_read", "constantinople", "scale" }) |name| {
        const source = b.path(b.fmt("src/storage/qmdb/benches/{s}.zig", .{name}));
        const step_name = b.fmt("qmdb-{s}", .{name});
        std.mem.replaceScalar(u8, @constCast(step_name), '_', '-');
        for ([_]bool{ true, false }) |measured| {
            const graph = if (measured) measured_modules else modules;
            const root = b.createModule(.{
                .root_source_file = source,
                .target = target,
                .optimize = if (measured) harness_optimize else optimize,
            });
            for (imports) |dep| root.addImport(dep, graph[package_index(dep)]);
            if (measured) {
                const exe = b.addExecutable(.{ .name = step_name, .root_module = root });
                check_step.dependOn(&exe.step);
                const run = b.addRunArtifact(exe);
                run.addPassthruArgs();
                run.has_side_effects = true;
                const description = b.fmt("Run the {s} QMDB harness", .{name});
                b.step(step_name, description).dependOn(&run.step);
            } else {
                const tests = b.addTest(.{
                    .name = b.fmt("test-{s}", .{step_name}),
                    .root_module = root,
                });
                test_step.dependOn(&b.addRunArtifact(tests).step);
            }
        }
    }
}

fn bench_harness(
    b: *std.Build,
    modules: []const *std.Build.Module,
    options_module: *std.Build.Module,
    package: Package,
    index: usize,
    path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const bench = modules[package_index("bench")];
    const benches = b.createModule(.{
        .root_source_file = b.path(path),
        .target = target,
        .optimize = optimize,
    });
    benches.addImport(package.name, modules[index]);
    benches.addImport("bench", bench);
    benches.addImport("build_options", options_module);
    for (package.deps) |dep| benches.addImport(dep, modules[package_index(dep)]);
    const root = b.createModule(.{
        .root_source_file = b.path("src/bench/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bench", .module = bench },
            .{ .name = "benches", .module = benches },
        },
    });
    return b.addExecutable(.{ .name = b.fmt("bench-{s}", .{package.name}), .root_module = root });
}

/// Each example gets an install, a `run-<name>` step, and its own test binary.
fn add_examples(
    b: *std.Build,
    zigware: *std.Build.Module,
    options_module: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    check_step: *std.Build.Step,
    filters: []const []const u8,
) void {
    const ui = b.createModule(.{
        .root_source_file = b.path("examples/ui/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zigware", .module = zigware }},
    });
    for (examples) |entry| {
        const is_binary = std.mem.indexOfScalar(u8, entry, '/') != null;
        const source = if (is_binary)
            b.fmt("examples/{s}.zig", .{entry})
        else
            b.fmt("examples/{s}/main.zig", .{entry});
        const name = std.mem.replaceOwned(u8, b.allocator, entry, "/", "-") catch @panic("OOM");
        const root = b.createModule(.{
            .root_source_file = b.path(source),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zigware", .module = zigware },
                .{ .name = "build_options", .module = options_module },
                .{ .name = "ui", .module = ui },
            },
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
        const run_tests = b.addRunArtifact(tests);
        test_step.dependOn(&run_tests.step);
        example_test_step(b, entry).dependOn(&run_tests.step);
    }
}

/// `test-example-<dir>`: the tests of every binary under `examples/<dir>`.
fn example_test_step(b: *std.Build, entry: []const u8) *std.Build.Step {
    const dir = entry[0 .. std.mem.indexOfScalar(u8, entry, '/') orelse entry.len];
    const step_name = b.fmt("test-example-{s}", .{dir});
    if (b.top_level_steps.get(step_name)) |existing| return &existing.step;
    return b.step(step_name, b.fmt("Run the {s} example's tests", .{dir}));
}
