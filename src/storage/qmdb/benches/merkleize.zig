//! `qmdb::merkleize` (commonware's `qmdb/benches/merkleize.rs`): the time to build a
//! speculative batch of random updates (10% of the keys, sampled with replacement), merkleize
//! it, and read its root. Seeding, syncing, and churn are untimed.
//!
//! - `qmdb::merkleize/v=.. k=.. ch=.. s=..  cc=..`: on a freshly seeded database, the batch
//!   built on the database or (`ch`) on a merkleized parent prepared before each iteration,
//!   after an optional seed sync (`s`) and page-cache clear (`cc`). Reports `blob_reads`.
//! - `qmdb::merkleize/variant=.. keys=.. churn=50 cache_pages=32`: after 50 overwrite batches,
//!   with a small page cache, so the floor walk's reads of inactive operations show.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const runtime = @import("runtime");
const common = @import("common.zig");

const metrics = runtime.telemetry.metrics;
const metered = runtime.storage.metered;
const Digest = common.Digest;
const TestRng = common.TestRng;
const Session = common.Session;
const Disk = common.Disk;
const Variant = common.Variant;
const AnyDb = common.AnyDb;
const mmr = common.mmr;
const mmb = common.mmb;
const FixedDigest = common.FixedDigest;
const VariableDigest = common.VariableDigest;

/// Huge blobs, so iteration times do not include blob boundary crossings.
const merkleize_items_per_blob: u64 = 10_000_000;
/// Large enough that most reads hit the cache.
const large_page_cache_pages: u32 = 16_384;
/// Small enough that most reads miss the cache.
const small_page_cache_pages: u32 = 32;
/// Overwrite batches applied before timing the churned benchmark.
const churn_batches: u64 = 50;

/// Commonware's merkleize `VARIANTS`, without the `current` entries.
const variants = .{
    Variant("any::unordered::fixed::mmr", AnyDb(mmr, .unordered, FixedDigest)),
    Variant("any::unordered::variable::mmr", AnyDb(mmr, .unordered, VariableDigest)),
    Variant("any::unordered::fixed::mmb", AnyDb(mmb, .unordered, FixedDigest)),
    Variant("any::unordered::variable::mmb", AnyDb(mmb, .unordered, VariableDigest)),
    Variant("any::ordered::fixed::mmr", AnyDb(mmr, .ordered, FixedDigest)),
    Variant("any::ordered::variable::mmr", AnyDb(mmr, .ordered, VariableDigest)),
    Variant("any::ordered::fixed::mmb", AnyDb(mmb, .ordered, FixedDigest)),
    Variant("any::ordered::variable::mmb", AnyDb(mmb, .ordered, VariableDigest)),
};

const Options = struct {
    num_keys: u64,
    chained: bool,
    seed_sync: bool,
    clear_cache: bool,
};

pub fn run(runner: *bench.Runner) !void {
    try bench_merkleize(runner);
    try bench_merkleize_churned(runner);
}

/// Commonware's `main_num_keys`; smoke inputs shrink the case for debug builds.
fn main_num_keys(inputs: bench.Inputs, seed_sync: bool) []const u64 {
    return switch (inputs) {
        .smoke => &.{200},
        .standard => &.{10_000},
        .full => if (seed_sync) &.{ 10_000, 100_000 } else &.{ 10_000, 100_000, 1_000_000 },
    };
}

fn bench_merkleize(runner: *bench.Runner) !void {
    for ([_]bool{ false, true }) |chained| {
        for ([_]bool{ false, true }) |seed_sync| {
            const clear_options: []const bool = if (!chained and seed_sync)
                &.{ false, true }
            else
                &.{false};
            for (clear_options) |clear_cache| {
                for (main_num_keys(runner.inputs, seed_sync)) |num_keys| {
                    const options: Options = .{
                        .num_keys = num_keys,
                        .chained = chained,
                        .seed_sync = seed_sync,
                        .clear_cache = clear_cache,
                    };
                    inline for (variants) |V| try run_merkleize(V, runner, options);
                }
            }
        }
    }
}

fn run_merkleize(comptime V: type, runner: *bench.Runner, options: Options) !void {
    const benchmark = bench.Benchmark.init("qmdb::merkleize")
        .with_param("v", V.name)
        .with_param("k", options.num_keys)
        .with_param("ch", options.chained)
        .with_param("s", options.seed_sync)
        .with_param("cc", options.clear_cache);
    if (!runner.matches(benchmark.name())) return;
    var workload: MerkleizeWorkload(V.Db) = .{
        .meter = .init(runner, large_page_cache_pages),
        .options = options,
    };
    try runner.run(benchmark, &workload);
}

/// A database on disk behind a storage meter that counts blob reads (commonware's
/// `runtime_storage_reads_total`).
fn Metered(comptime D: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        disk: Disk,
        page_cache_pages: u32,
        registry: metrics.Registry = undefined,
        meter: metered.Storage = undefined,
        session: Session(D) = undefined,

        fn init(runner: *const bench.Runner, page_cache_pages: u32) Self {
            assert(page_cache_pages > 0);
            return .{
                .gpa = runner.allocator,
                .disk = .init(runner),
                .page_cache_pages = page_cache_pages,
            };
        }

        fn open(self: *Self) !*D {
            try self.disk.open(self.gpa);
            errdefer self.disk.close();
            self.registry = .init(self.gpa);
            errdefer self.registry.deinit();
            const scope = metrics.Scope.init(&self.registry).child("bench");
            self.meter = try .init(self.gpa, self.disk.storage(), &scope);
            errdefer self.meter.deinit();
            self.disk.override = self.meter.storage();
            try self.session.open(self.gpa, &self.disk, .{
                .items_per_blob = merkleize_items_per_blob,
                .page_cache_pages = self.page_cache_pages,
            });
            assert(self.session.db.bounds().end > 0);
            return &self.session.db;
        }

        fn reads(self: *const Self) u64 {
            return self.meter.metrics.storage_reads.metric().get();
        }

        fn close(self: *Self) !void {
            defer {
                self.disk.override = null;
                self.meter.deinit();
                self.registry.deinit();
                self.disk.close();
            }
            try self.session.close();
        }
    };
}

/// Commonware's `MerkleizeWorkload`.
fn MerkleizeWorkload(comptime D: type) type {
    return struct {
        const Self = @This();

        meter: Metered(D),
        options: Options,
        rng: TestRng = .init(99),
        parent: ?*D.MerkleizedBatch = null,
        start_reads: u64 = 0,

        pub fn setup(self: *Self) !void {
            const db = try self.meter.open();
            errdefer self.meter.close() catch {};
            try common.seed_db(D, db, self.options.num_keys);
            if (self.options.seed_sync) try db.sync();
            if (self.options.clear_cache) self.meter.session.cache.clear();
            self.start_reads = self.meter.reads();
            assert(db.bounds().end > self.options.num_keys);
        }

        pub fn before_iter(self: *Self) !void {
            if (!self.options.chained) return;
            self.release_parent();
            const db = &self.meter.session.db;
            var batch = try db.new_batch();
            errdefer batch.deinit();
            try self.write_updates(&batch);
            self.parent = try batch.merkleize(db);
            assert(self.parent != null);
        }

        pub fn iter(self: *Self) !Digest {
            const db = &self.meter.session.db;
            var batch = if (self.options.chained) self.parent.?.new_batch() else try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                try self.write_updates(&batch);
                break :merkleized try batch.merkleize(db);
            };
            defer merkleized.release();
            return merkleized.root();
        }

        pub fn teardown(self: *Self) !void {
            self.release_parent();
            try self.meter.close();
        }

        pub fn metrics(self: *const Self, buffer: []bench.Metric) []const bench.Metric {
            assert(buffer.len >= 1);
            const reads = self.meter.reads() -| self.start_reads;
            buffer[0] = .init("blob_reads", reads);
            return buffer[0..1];
        }

        fn write_updates(self: *Self, batch: *D.UnmerkleizedBatch) !void {
            const keys = self.options.num_keys;
            try common.write_random_updates(D, batch, keys / 10, keys, &self.rng);
        }

        fn release_parent(self: *Self) void {
            if (self.parent) |parent| parent.release();
            self.parent = null;
        }
    };
}

fn bench_merkleize_churned(runner: *bench.Runner) !void {
    const keys: []const u64 = switch (runner.inputs) {
        .smoke => &.{200},
        .standard => &.{10_000},
        .full => &.{ 10_000, 100_000 },
    };
    for (keys) |num_keys| {
        inline for (variants) |V| try run_churned(V, runner, num_keys);
    }
}

fn run_churned(comptime V: type, runner: *bench.Runner, num_keys: u64) !void {
    const benchmark = bench.Benchmark.init("qmdb::merkleize")
        .with_param("variant", V.name)
        .with_param("keys", num_keys)
        .with_param("churn", churn_batches)
        .with_param("cache_pages", small_page_cache_pages);
    if (!runner.matches(benchmark.name())) return;
    var workload: ChurnedWorkload(V.Db) = .{
        .meter = .init(runner, small_page_cache_pages),
        .num_keys = num_keys,
    };
    try runner.run(benchmark, &workload);
}

/// Commonware's `run_churned_bench`: seed, apply `churn_batches` overwrite batches, commit,
/// and sync, untimed; each iteration merkleizes a batch of overwrites and reads its root.
fn ChurnedWorkload(comptime D: type) type {
    return struct {
        const Self = @This();

        meter: Metered(D),
        num_keys: u64,
        rng: TestRng = .init(99),

        pub fn setup(self: *Self) !void {
            const db = try self.meter.open();
            errdefer self.meter.close() catch {};
            const keys = self.num_keys;
            try common.seed_db(D, db, keys);
            for (0..churn_batches) |_| {
                var batch = try db.new_batch();
                const merkleized = merkleized: {
                    errdefer batch.deinit();
                    try common.write_random_updates(D, &batch, keys / 10, keys, &self.rng);
                    break :merkleized try batch.merkleize(db);
                };
                defer merkleized.release();
                try db.apply_batch(merkleized);
            }
            try db.commit();
            try db.sync();
            assert(db.bounds().end > keys);
        }

        pub fn iter(self: *Self) !Digest {
            const db = &self.meter.session.db;
            const keys = self.num_keys;
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                try common.write_random_updates(D, &batch, keys / 10, keys, &self.rng);
                break :merkleized try batch.merkleize(db);
            };
            defer merkleized.release();
            return merkleized.root();
        }

        pub fn teardown(self: *Self) !void {
            try self.meter.close();
        }
    };
}
