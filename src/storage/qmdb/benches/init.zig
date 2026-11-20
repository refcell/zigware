//! `qmdb::init` (commonware's `qmdb/benches/init.rs`): the time to reopen a populated database,
//! with and without the init-time `location -> key` cache. Each variant is populated once
//! (seeded, churned, pruned, and synced), untimed, and every cache size reopens the same data.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

const StoreDb = common.StoreDb;
const Session = common.Session;
const Disk = common.Disk;

const num_elements: u64 = 100_000;
const num_operations: u64 = 1_000_000;
const commit_frequency: u32 = 10_000;

/// Init cache sizes compared: disabled (the baseline), and one covering the working set.
const cache_sizes = [_]?usize{ null, 1 << 18 };

const Case = struct { elements: u64, operations: u64 };

pub fn run(runner: *bench.Runner) !void {
    // Smoke inputs shrink the case: `zig build test` runs these in debug builds.
    const standard = [_]Case{.{ .elements = num_elements, .operations = num_operations }};
    const full = standard ++ [_]Case{
        .{ .elements = num_elements * 3, .operations = num_operations * 3 },
    };
    const smoke = [_]Case{.{ .elements = 100, .operations = 1_000 }};
    const cases = runner.inputs.pick([]const Case, &smoke, &standard, &full);
    for (cases) |case| {
        inline for (common.fixed_variants ++ common.vec_variants) |V| {
            try run_variant(V, runner, case);
        }
        try run_variant(common.Variant("store::variable", StoreDb), runner, case);
    }
}

fn benchmark_of(name: []const u8, cache: ?usize, case: Case) bench.Benchmark {
    return bench.Benchmark.init("qmdb::init")
        .with_param("variant", name)
        .with_param("cache", cache orelse 0)
        .with_param("elements", case.elements);
}

/// Populates the variant lazily, on the first selected cache size, and destroys it after.
fn run_variant(comptime V: type, runner: *bench.Runner, case: Case) !void {
    var selected = false;
    for (cache_sizes) |cache| {
        if (runner.matches(benchmark_of(V.name, cache, case).name())) selected = true;
    }
    if (!selected) return;
    var disk: Disk = .init(runner);
    try disk.open(runner.allocator);
    defer disk.close();
    // A listing only prints the names: seeding the variant would take minutes per variant.
    if (!runner.list) try populate(V.Db, runner.allocator, &disk, case);
    for (cache_sizes) |cache| {
        var workload: InitWorkload(V.Db) = .{
            .gpa = runner.allocator,
            .disk = &disk,
            .options = .{ .init_cache = cache },
        };
        try runner.run(benchmark_of(V.name, cache, case), &workload);
    }
    if (runner.list) return;
    var session: Session(V.Db) = undefined;
    try session.open(runner.allocator, &disk, .{});
    try session.close();
}

/// Commonware's `populate_and_sync` (or the store's equivalent): seed, churn, prune, sync.
fn populate(comptime D: type, gpa: Allocator, disk: *Disk, case: Case) !void {
    var session: Session(D) = undefined;
    try session.open(gpa, disk, .{});
    defer session.shut();
    const db = &session.db;
    if (D == StoreDb) {
        try common.gen_store_random_kv(gpa, db, case.elements, case.operations, commit_frequency);
        try db.prune(db.inactivity_floor());
    } else {
        try common.gen_random_kv(D, gpa, db, case.elements, case.operations, commit_frequency);
        try db.prune(db.sync_boundary());
    }
    try db.sync();
    assert(db.bounds().end > case.elements);
}

/// Each iteration opens the populated database and closes it, keeping its storage.
fn InitWorkload(comptime D: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        disk: *Disk,
        options: common.Options,

        pub fn iter(self: *Self) !u64 {
            var session: Session(D) = undefined;
            try session.open(self.gpa, self.disk, self.options);
            defer session.shut();
            const end = session.db.bounds().end;
            assert(end != 0);
            return end;
        }
    };
}
