//! `qmdb::chained_growth` (commonware's `qmdb/benches/chained_growth.rs`): chained-growth
//! merkleization of `current` databases. Before each iteration (untimed), a fresh database is
//! seeded with `num_keys` keys and synced, then a chain of `prebuilt_chain` batches is grown,
//! each parent applied while its child is alive, and the result committed and synced. The
//! iteration grows `batches` more batches of one random update each (so each overlay covers a
//! tiny fraction of the chunks), applying each parent, and applies the last child.
//!
//! Difference from commonware: the databases use common's `bench-fixed` partitions, not
//! `bench-chained-growth`; each iteration has a fresh disk either way.

const std = @import("std");
const assert = std.debug.assert;
const bench = @import("bench");
const common = @import("common.zig");

const Digest = common.Digest;
const TestRng = common.TestRng;
const Fresh = common.Fresh;
const Variant = common.Variant;
const CurrentChunksDb = common.CurrentChunksDb;
const FixedDigest = common.FixedDigest;
const mmb = common.mmb;

const chained_items_per_blob: u64 = 10_000_000;
const large_page_cache_pages: u32 = 16_384;
/// Random updates per batch.
const updates_per_batch: u64 = 1;
/// Commonware's `GROW_COUNTS`.
const grow_counts = [_]u64{100};

const variants = .{
    Variant(
        "current::unordered::fixed::mmb chunk=32",
        CurrentChunksDb(mmb, .unordered, FixedDigest, 32),
    ),
    Variant(
        "current::ordered::fixed::mmb chunk=32",
        CurrentChunksDb(mmb, .ordered, FixedDigest, 32),
    ),
    Variant(
        "current::unordered::fixed::mmb chunk=256",
        CurrentChunksDb(mmb, .unordered, FixedDigest, 256),
    ),
    Variant(
        "current::ordered::fixed::mmb chunk=256",
        CurrentChunksDb(mmb, .ordered, FixedDigest, 256),
    ),
};

const Case = struct {
    num_keys: u64,
    prebuilt_chain: u64,
    batches: u64,
};

pub fn run(runner: *bench.Runner) !void {
    // Smoke inputs shrink the case: `zig build test` runs these in debug builds.
    const num_keys = runner.inputs.pick(u64, 200, 1_000_000, 1_000_000);
    const prebuilt_chain = runner.inputs.pick(u64, 20, 10_000, 10_000);
    for (grow_counts) |count| {
        const batches = runner.inputs.pick(u64, 5, count, count);
        const case: Case = .{
            .num_keys = num_keys,
            .prebuilt_chain = prebuilt_chain,
            .batches = batches,
        };
        inline for (variants) |V| try run_variant(V, runner, case, count);
    }
}

fn run_variant(comptime V: type, runner: *bench.Runner, case: Case, count: u64) !void {
    const benchmark = bench.Benchmark.init("qmdb::chained_growth")
        .with_param("variant", V.name)
        .with_param("batches", count);
    if (!runner.matches(benchmark.name())) return;
    var workload: ChainedWorkload(V.Db) = .{
        .fresh = .{
            .gpa = runner.allocator,
            .disk = .init(runner),
            .options = .{
                .items_per_blob = chained_items_per_blob,
                .page_cache_pages = large_page_cache_pages,
            },
        },
        .case = case,
    };
    try runner.run(benchmark, &workload);
}

fn ChainedWorkload(comptime D: type) type {
    return struct {
        const Self = @This();

        fresh: Fresh(D),
        case: Case,
        rng: TestRng = .init(99),
        /// The merkleized tip of the chain, not yet applied.
        parent: ?*D.MerkleizedBatch = null,

        pub fn setup(self: *Self) !void {
            assert(self.case.num_keys > 0);
            try self.fresh.setup();
        }

        /// A fresh seeded database with a prebuilt chain, committed and synced.
        pub fn before_iter(self: *Self) !void {
            self.release_parent();
            const db = try self.fresh.next();
            try common.seed_db(D, db, self.case.num_keys);
            try db.sync();
            self.rng = .init(99);
            var batch = try db.new_batch();
            self.parent = try self.merkleize_updates(db, &batch);
            for (0..self.case.prebuilt_chain) |_| try self.grow(db);
            // Flush buffered data so the timed region does not inherit setup fsync cost.
            try db.commit();
            try db.sync();
            assert(self.parent != null);
        }

        pub fn iter(self: *Self) !u64 {
            const db = self.fresh.db();
            for (0..self.case.batches) |_| try self.grow(db);
            const last = self.parent.?;
            self.parent = null;
            defer last.release();
            try db.apply_batch(last);
            return db.bounds().end;
        }

        pub fn teardown(self: *Self) !void {
            self.release_parent();
            try self.fresh.teardown();
        }

        /// Forks a child of one random update off the parent, merkleizes it (reading its
        /// root), applies the parent, and makes the child the new parent.
        fn grow(self: *Self, db: *D) !void {
            const parent = self.parent.?;
            var batch = parent.new_batch();
            const child = try self.merkleize_updates(db, &batch);
            errdefer child.release();
            std.mem.doNotOptimizeAway(child.root());
            self.parent = null;
            defer parent.release();
            try db.apply_batch(parent);
            self.parent = child;
        }

        /// Writes the random updates into `batch` and merkleizes it (consuming it).
        fn merkleize_updates(self: *Self, db: *D, batch: *D.UnmerkleizedBatch) !*D.MerkleizedBatch {
            errdefer batch.deinit();
            const keys = self.case.num_keys;
            try common.write_random_updates(D, batch, updates_per_batch, keys, &self.rng);
            return batch.merkleize(db);
        }

        fn release_parent(self: *Self) void {
            if (self.parent) |parent| parent.release();
            self.parent = null;
        }
    };
}
