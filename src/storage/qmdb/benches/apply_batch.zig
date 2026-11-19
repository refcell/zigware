//! `qmdb::apply_batch` (commonware's `qmdb/benches/apply_batch.rs`): the time to apply an
//! already-merkleized batch to a seeded database, directly or through ancestors that are
//! uncommitted, committed, or dropped. Seeding, merkleizing, and destroying are untimed.

const std = @import("std");
const assert = std.debug.assert;
const bench = @import("bench");
const storage = @import("storage");
const common = @import("common.zig");

const qmdb = storage.qmdb;
const Digest = common.Digest;
const TestRng = common.TestRng;
const Fresh = common.Fresh;
const FixedDigest = common.FixedDigest;
const key_at = common.key_at;
const make_value = common.make_value;

const num_keys: u64 = 65_536;
const updates_standard: u64 = 16_384;
const apply_items_per_blob: u64 = 10_000_000;

/// The unordered fixed database of commonware's `apply_batch` (`AnyUFixDb<Mmb>`).
const AnyDb = common.AnyDb(common.mmb, .unordered, FixedDigest);

/// The ordered fixed database with a 256-partition snapshot index (`AnyOFixP256Db<Mmb>`).
const OrderedP256Db = db: {
    const any = qmdb.any;
    const F = common.mmb;
    const Op = any.operation.Ordered(F, Digest, FixedDigest);
    const U = any.operation.update.Ordered(Digest, FixedDigest);
    const I = storage.index.partitioned.ordered.Index(common.Translator, u64, 1);
    const C = storage.journal.contiguous.fixed.Journal(Op);
    break :db any.Db(F, U, C, I, common.Sha256, common.chunk_bytes);
};

/// The immutable fixed database (`ImmFixDb<Mmb>`).
const ImmutableDb = db: {
    const immutable = qmdb.immutable;
    const F = common.mmb;
    const Op = immutable.Operation(F, Digest, FixedDigest);
    const C = storage.journal.contiguous.fixed.Journal(Op);
    break :db immutable.Db(F, Digest, FixedDigest, C, common.Sha256, common.Translator);
};

/// How the applied batch relates to the committed database.
const Case = enum {
    /// A batch built on the database.
    direct,
    /// A child applied while its parent is uncommitted.
    uncomm_ancestor,
    /// A child applied after its parent.
    comm_ancestor,
    /// The third of a chain applied after the first.
    comm_uncomm_chain,
    /// The third of a chain applied after its ancestors are released.
    multi_uncomm,

    /// Batches in the chain.
    fn depth(case: Case) usize {
        return switch (case) {
            .direct => 1,
            .uncomm_ancestor, .comm_ancestor => 2,
            .comm_uncomm_chain, .multi_uncomm => 3,
        };
    }
};

pub fn run(runner: *bench.Runner) !void {
    // Smoke inputs shrink the case: `zig build test` runs these in debug builds.
    const keys = runner.inputs.pick(u64, 256, num_keys, num_keys);
    const updates = runner.inputs.pick(u64, 64, updates_standard, updates_standard);
    const any = "any::unordered::fixed::mmb";
    try run_case(AnyDb, .direct, any, runner, keys, updates);
    const p256 = "any::ordered::p256::fixed::mmb";
    try run_case(OrderedP256Db, .direct, p256, runner, keys, updates);
    try run_case(AnyDb, .uncomm_ancestor, any, runner, keys, updates);
    try run_case(AnyDb, .comm_ancestor, any, runner, keys, updates);
    try run_case(AnyDb, .comm_uncomm_chain, any, runner, keys, updates);
    try run_case(AnyDb, .multi_uncomm, any, runner, keys, updates);
    const immutable = "immutable::fixed::mmb";
    try run_case(ImmutableDb, .direct, immutable, runner, keys, updates);
    try run_case(ImmutableDb, .uncomm_ancestor, immutable, runner, keys, updates);
}

fn run_case(
    comptime D: type,
    comptime case: Case,
    variant: []const u8,
    runner: *bench.Runner,
    keys: u64,
    updates: u64,
) !void {
    const benchmark = bench.Benchmark.init("qmdb::apply_batch")
        .with_param("case", @tagName(case))
        .with_param("variant", variant)
        .with_param("chunk", common.chunk_bytes)
        .with_param("updates", updates);
    if (!runner.matches(benchmark.name())) return;
    var workload: ApplyWorkload(D, case) = .{
        .fresh = .{
            .gpa = runner.allocator,
            .disk = .init(runner),
            .options = .{ .items_per_blob = apply_items_per_blob },
        },
        .keys = keys,
        .updates = updates,
    };
    try runner.run(benchmark, &workload);
}

/// Before each iteration: a fresh database seeded with `keys` keys, and a chain of
/// `case.depth()` merkleized batches of `updates` writes each. The iteration applies the last.
fn ApplyWorkload(comptime D: type, comptime case: Case) type {
    const immutable = comptime @hasDecl(D, "Set");
    return struct {
        const Self = @This();

        fresh: Fresh(D),
        keys: u64,
        updates: u64,
        chain: [3]?*D.MerkleizedBatch = @splat(null),
        rng: TestRng = .init(7),
        /// The next fresh key of an immutable database, which is insert-only.
        counter: u64 = 0,

        pub fn setup(self: *Self) !void {
            try self.fresh.setup();
        }

        pub fn before_iter(self: *Self) !void {
            self.release();
            const db = try self.fresh.next();
            self.rng = .init(7);
            self.counter = 0;
            if (immutable) try self.seed_immutable(db) else try common.seed_db(D, db, self.keys);
            for (0..case.depth()) |level| {
                var batch = if (level == 0)
                    try db.new_batch()
                else
                    self.chain[level - 1].?.new_batch();
                errdefer batch.deinit();
                try self.write_updates(&batch);
                self.chain[level] = try batch.merkleize(db);
            }
            switch (case) {
                .direct, .uncomm_ancestor => {},
                .comm_ancestor, .comm_uncomm_chain => try db.apply_batch(self.chain[0].?),
                .multi_uncomm => for (self.chain[0..2]) |*batch| {
                    batch.*.?.release();
                    batch.* = null;
                },
            }
            assert(self.chain[case.depth() - 1] != null);
        }

        pub fn iter(self: *Self) !u64 {
            const db = self.fresh.db();
            const before = db.bounds().end;
            try db.apply_batch(self.chain[case.depth() - 1].?);
            assert(db.bounds().end > before);
            return db.bounds().end;
        }

        pub fn teardown(self: *Self) !void {
            self.release();
            try self.fresh.teardown();
        }

        fn release(self: *Self) void {
            for (&self.chain) |*batch| {
                if (batch.*) |merkleized| merkleized.release();
                batch.* = null;
            }
            assert(self.chain[0] == null);
        }

        /// Commonware's `write_updates`, or fresh keys for an immutable database.
        fn write_updates(self: *Self, batch: *D.UnmerkleizedBatch) !void {
            const gpa = self.fresh.gpa;
            for (0..self.updates) |_| {
                if (immutable) {
                    const key = key_at(self.counter);
                    self.counter += 1;
                    try batch.set(key, try make_value(Digest, gpa, &self.rng));
                } else {
                    const key = key_at(self.rng.next_u64() % self.keys);
                    try batch.write(key, try make_value(Digest, gpa, &self.rng));
                }
            }
        }

        /// Commonware's `seed_imm_db`: `keys` fresh keys in one committed batch.
        fn seed_immutable(self: *Self, db: *D) !void {
            const gpa = self.fresh.gpa;
            var batch = try db.new_batch();
            {
                errdefer batch.deinit();
                for (0..self.keys) |_| {
                    const key = key_at(self.counter);
                    self.counter += 1;
                    try batch.set(key, try make_value(Digest, gpa, &self.rng));
                }
            }
            try apply_commit(D, db, &batch);
            assert(self.counter == self.keys);
        }
    };
}

/// Merkleizes `batch` (consumed on success), applies it, and commits.
fn apply_commit(comptime D: type, db: *D, batch: *D.UnmerkleizedBatch) !void {
    const before = db.bounds().end;
    const merkleized = merkleized: {
        errdefer batch.deinit();
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    try db.commit();
    assert(db.bounds().end > before);
}
