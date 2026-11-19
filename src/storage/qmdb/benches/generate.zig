//! `qmdb::generate` (commonware's `qmdb/benches/generate.rs`): seed a database, churn it with
//! random updates and deletes (committing periodically), then prune and sync it. Opening and
//! destroying the database are untimed.

const std = @import("std");
const assert = std.debug.assert;
const bench = @import("bench");
const common = @import("common.zig");

const Bytes = common.Bytes;
const StoreDb = common.StoreDb;
const TestRng = common.TestRng;
const Variant = common.Variant;
const Fresh = common.Fresh;
const make_value = common.make_value;
const flush = common.flush;

pub fn run(runner: *bench.Runner) !void {
    try bench_generate(runner);
}

const generate_elements: u64 = 1_000;
const generate_operations: u64 = 10_000;
const commits_per_iteration: u64 = 100;
const keyless_operations: u64 = 10_000;
const keyless_commit_frequency: u32 = 25;

/// Seeds and churns a fresh database per iteration, then prunes it to its sync boundary (the
/// store: its inactivity floor) and syncs it.
fn GenerateWorkload(comptime D: type) type {
    return struct {
        const Self = @This();

        fresh: Fresh(D),
        elements: u64,
        operations: u64,

        pub fn setup(self: *Self) !void {
            try self.fresh.setup();
        }

        pub fn before_iter(self: *Self) !void {
            _ = try self.fresh.next();
        }

        pub fn iter(self: *Self) !u64 {
            const gpa = self.fresh.gpa;
            const db = self.fresh.db();
            const elements = self.elements;
            const operations = self.operations;
            const commit_frequency: u32 = @intCast(operations / commits_per_iteration);
            if (D == StoreDb) {
                try common.gen_store_random_kv(gpa, db, elements, operations, commit_frequency);
                try db.prune(db.inactivity_floor());
            } else {
                try common.gen_random_kv(D, gpa, db, elements, operations, commit_frequency);
                try db.prune(db.sync_boundary());
            }
            try db.sync();
            assert(db.bounds().end > elements);
            return db.bounds().end;
        }

        pub fn teardown(self: *Self) !void {
            try self.fresh.teardown();
        }
    };
}

fn bench_generate(runner: *bench.Runner) !void {
    // Smoke inputs shrink the case: `zig build test` runs these in debug builds.
    const elements = runner.inputs.pick(u64, 100, generate_elements, generate_elements);
    const operations = runner.inputs.pick(u64, 1_000, generate_operations, generate_operations);
    inline for (common.fixed_variants ++ common.vec_variants) |V| {
        try run_generate(V, runner, elements, operations);
    }
    // The full run also measures the store at the init bench's population size.
    try run_generate(Variant("store::variable", StoreDb), runner, elements, operations);
    if (runner.inputs == .full) {
        const variant = Variant("store::variable", StoreDb);
        try run_generate(variant, runner, elements * 100, operations * 100);
    }
    const keyless_ops = runner.inputs.pick(u64, 1_000, keyless_operations, keyless_operations);
    for ([_]u64{ keyless_ops, keyless_ops * 2 }) |ops| {
        inline for (common.keyless_variants) |V| try run_keyless_generate(V, runner, ops);
    }
}

fn run_generate(comptime V: type, runner: *bench.Runner, elements: u64, operations: u64) !void {
    const benchmark = bench.Benchmark.init("qmdb::generate")
        .with_param("variant", V.name)
        .with_param("elements", elements)
        .with_param("operations", operations);
    if (!runner.matches(benchmark.name())) return;
    var workload: GenerateWorkload(V.Db) = .{
        .fresh = .{ .gpa = runner.allocator, .disk = .init(runner) },
        .elements = elements,
        .operations = operations,
    };
    try runner.run(benchmark, &workload);
}

/// Appends `operations` variable values to a fresh keyless database per iteration, applying
/// a batch whenever the rng draws a multiple of `keyless_commit_frequency`, then syncs.
fn KeylessGenerateWorkload(comptime D: type) type {
    return struct {
        const Self = @This();

        fresh: Fresh(D),
        operations: u64,

        pub fn setup(self: *Self) !void {
            try self.fresh.setup();
        }

        pub fn before_iter(self: *Self) !void {
            _ = try self.fresh.next();
        }

        pub fn iter(self: *Self) !u64 {
            const gpa = self.fresh.gpa;
            const db = self.fresh.db();
            var rng: TestRng = .init(42);
            var batch: ?D.UnmerkleizedBatch = try db.new_batch();
            errdefer if (batch) |*pending| pending.deinit();
            for (0..self.operations) |_| {
                const value = try make_value(Bytes, gpa, &rng);
                batch.?.append(value) catch |err| {
                    gpa.free(value);
                    return err;
                };
                if (rng.next_u32() % keyless_commit_frequency == 0) {
                    try flush(D, db, &batch, false, true);
                }
            }
            try flush(D, db, &batch, false, false);
            try db.sync();
            assert(db.bounds().end > self.operations);
            return db.bounds().end;
        }

        pub fn teardown(self: *Self) !void {
            try self.fresh.teardown();
        }
    };
}

fn run_keyless_generate(comptime V: type, runner: *bench.Runner, operations: u64) !void {
    const benchmark = bench.Benchmark.init("qmdb::generate")
        .with_param("variant", V.name)
        .with_param("operations", operations);
    if (!runner.matches(benchmark.name())) return;
    var workload: KeylessGenerateWorkload(V.Db) = .{
        .fresh = .{ .gpa = runner.allocator, .disk = .init(runner) },
        .operations = operations,
    };
    try runner.run(benchmark, &workload);
}
