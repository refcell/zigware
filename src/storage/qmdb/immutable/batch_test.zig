//! Batch scenarios of the immutable database (commonware's `qmdb/immutable/mod.rs`
//! `run_batch_{stacked_apply,speculative_root,many_sequential,large}`,
//! `run_proof_refused_after_sibling_apply`, and `run_operations_match_applied_log`). Every
//! scenario runs under both families.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Digest = support.Digest;
const Sha256 = support.Sha256;
const fill = support.fill;
const to_digest = support.to_digest;

fn expect_value(actual: ?Digest, expected: Digest) !void {
    try testing.expect(actual != null and actual.?.eql(expected));
}

/// Merkleizes a batch on `parent` (or on `db` if null) setting `to_digest(i)` to
/// `fill(i)` for `i` in `[first, end)`, with `metadata`.
fn merkleize_range(
    db: anytype,
    parent: ?*@typeInfo(@TypeOf(db)).pointer.child.MerkleizedBatch,
    first: u64,
    end: u64,
    metadata: ?Digest,
) !*@typeInfo(@TypeOf(db)).pointer.child.MerkleizedBatch {
    assert(first <= end);
    var batch = if (parent) |p| p.new_batch() else try db.new_batch();
    errdefer batch.deinit();
    for (first..end) |i| try batch.set(to_digest(i), fill(@truncate(i)));
    if (metadata) |m| batch.with_metadata(m);
    return batch.merkleize(db);
}

test "immutable stacked batches apply through the child" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const parent = try merkleize_range(&db, null, 0, 5, null);
        defer parent.release();
        const child = try merkleize_range(&db, parent, 5, 10, null);
        defer child.release();
        const expected_root = child.root();
        try db.apply_batch(child);
        try testing.expect(db.root().eql(expected_root));
        for (0..10) |i| try expect_value(try db.get(&to_digest(i)), fill(@intCast(i)));
        try db.destroy();
    }
}

test "immutable speculative roots match the applied roots" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        for ([_]?Digest{ null, fill(55) }) |metadata| {
            const first = db.bounds().end;
            const merkleized = try merkleize_range(&db, null, first, first + 10, metadata);
            defer merkleized.release();
            const speculative = merkleized.root();
            try db.apply_batch(merkleized);
            try testing.expect(db.root().eql(speculative));
        }
        try db.destroy();
    }
}

test "immutable many sequential batches stay readable" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const batches: u64 = 20;
        const keys_per_batch: u64 = 5;
        for (0..batches) |b| {
            const first = b * 100;
            const merkleized = try merkleize_range(&db, null, first, first + keys_per_batch, null);
            defer merkleized.release();
            try db.apply_batch(merkleized);
        }
        for (0..batches) |b| {
            for (b * 100..b * 100 + keys_per_batch) |i| {
                try expect_value(try db.get(&to_digest(i)), fill(@truncate(i)));
            }
        }
        try testing.expectEqual(1 + batches * (keys_per_batch + 1), db.bounds().end);
        try db.destroy();
    }
}

test "immutable large batch reads and proves its full range" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const n: u64 = 500;
        const merkleized = try merkleize_range(&db, null, 0, n, null);
        defer merkleized.release();
        try db.apply_batch(merkleized);
        for (0..n) |i| try expect_value(try db.get(&to_digest(i)), fill(@truncate(i)));
        const root = db.root();
        var proved = try db.proof(0, 1000);
        defer proved.deinit(gpa);
        const Op = support.Fixed(F).Operation;
        const proof = &proved.proof;
        try testing.expect(try verify.verify(F, Sha256, Op, gpa, proof, 0, proved.items, &root));
        try testing.expectEqual(1 + n + 1, db.bounds().end);
        try db.destroy();
    }
}

test "immutable batch proofs are refused after a sibling applies" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const Db = support.Fixed(F);
        var pins: [merkle.max_pinned_nodes]Db.Digest = undefined;
        const batch = try merkleize_range(&db, null, 1, 2, null);
        defer batch.release();
        const sibling = try merkleize_range(&db, null, 1, 2, fill(7));
        defer sibling.release();
        var proof = try batch.proof(&db);
        proof.deinit(gpa);
        _ = try batch.pinned_nodes(&db, &pins);
        // The sibling moves the database to a state outside the batch's chain.
        try db.apply_batch(sibling);
        try testing.expectError(error.StaleRead, batch.proof(&db));
        try testing.expectError(error.StaleRead, batch.pinned_nodes(&db, &pins));
        try db.destroy();
    }
}

/// A batch's operations, proof, and pins, captured before it applies, checked against the
/// range it applied at and what the log recovers for that range.
fn Captured(comptime Db: type) type {
    return struct {
        const Self = @This();

        start: u64,
        ops: []const Db.Operation,
        root: Db.Digest,
        proof: Db.Proof,
        pins_buffer: [merkle.max_pinned_nodes]Db.Digest = undefined,
        pins_len: usize = 0,

        fn capture(self: *Self, batch: *Db.MerkleizedBatch, db: *Db) !void {
            self.start, self.ops = batch.operations();
            self.root = batch.root();
            self.proof = try batch.proof(db);
            errdefer self.proof.deinit(gpa);
            self.pins_len = (try batch.pinned_nodes(db, &self.pins_buffer)).len;
            assert(self.ops.len > 0);
        }

        fn check_applied(self: *const Self, applied_start: u64, applied_end: u64) !void {
            try testing.expectEqual(applied_start, self.start);
            try testing.expectEqual(applied_end, self.start + self.ops.len);
        }

        /// The batch's proof and pinned nodes against `db` are still the captured ones.
        fn check_unchanged(self: *const Self, batch: *Db.MerkleizedBatch, db: *Db) !void {
            var proof = try batch.proof(db);
            defer proof.deinit(gpa);
            try testing.expect(proof.eql(&self.proof));
            var pins: [merkle.max_pinned_nodes]Db.Digest = undefined;
            const got = try batch.pinned_nodes(db, &pins);
            try testing.expectEqual(self.pins_len, got.len);
            for (got, self.pins_buffer[0..self.pins_len]) |a, b| try testing.expect(a.eql(b));
        }

        fn check_log(self: *const Self, db: *Db) !void {
            const F = Db.Family;
            const end = self.start + self.ops.len;
            var logged = try db.historical_proof(end, self.start, self.ops.len);
            defer logged.deinit(gpa);
            try testing.expectEqual(self.ops.len, logged.items.len);
            for (logged.items, self.ops) |a, b| try testing.expect(a.eql(b));
            try testing.expect(logged.proof.eql(&self.proof));
            const Op = Db.Operation;
            const pins = self.pins_buffer[0..self.pins_len];
            const with_pins = verify.verify_with_pinned_nodes;
            const proof = &self.proof;
            const root = &self.root;
            const start = self.start;
            const ops = self.ops;
            try testing.expect(try verify.verify(F, Sha256, Op, gpa, proof, start, ops, root));
            try testing.expect(try with_pins(F, Sha256, Op, gpa, proof, start, ops, pins, root));
        }

        fn deinit(self: *Self) void {
            self.proof.deinit(gpa);
        }
    };
}

/// Commit flushes the Merkle nodes and prunes memory to the peaks: a batch whose base sits
/// mid-mountain refuses its proof and pins with `ElementPruned`, and a batch built on the
/// flushed state reads every node below it from the pinned peaks.
fn check_after_flush(comptime Db: type, db: *Db) !void {
    var pins: [merkle.max_pinned_nodes]Db.Digest = undefined;
    const late = try merkleize_range(db, null, 5, 6, null);
    defer late.release();
    try db.apply_batch(late);
    try db.commit();
    try testing.expectError(error.ElementPruned, late.proof(db));
    try testing.expectError(error.ElementPruned, late.pinned_nodes(db, &pins));
    const flushed = try merkleize_range(db, null, 6, 7, null);
    defer flushed.release();
    var captured: Captured(Db) = undefined;
    try captured.capture(flushed, db);
    defer captured.deinit();
    const start = db.bounds().end;
    try db.apply_batch(flushed);
    try captured.check_applied(start, db.bounds().end);
    try captured.check_log(db);
}

test "immutable batch operations match the applied log" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const Db = support.Fixed(F);
        var captured: [4]Captured(Db) = undefined;
        var captured_len: usize = 0;
        defer for (captured[0..captured_len]) |*c| c.deinit();
        // A db-based batch, then a parent and its child built on it, then a write-free batch.
        const seed = try merkleize_range(&db, null, 1, 3, null);
        defer seed.release();
        try captured[0].capture(seed, &db);
        captured_len = 1;
        var start = db.bounds().end;
        try db.apply_batch(seed);
        try captured[0].check_applied(start, db.bounds().end);
        const parent = try merkleize_range(&db, null, 3, 4, null);
        defer parent.release();
        const child = try merkleize_range(&db, parent, 4, 5, null);
        defer child.release();
        // A chained batch's operations are its own suffix only.
        for ([_]*Db.MerkleizedBatch{ parent, child }) |batch| {
            try captured[captured_len].capture(batch, &db);
            captured_len += 1;
        }
        for ([_]*Db.MerkleizedBatch{ parent, child }, 1..) |batch, at| {
            start = db.bounds().end;
            try db.apply_batch(batch);
            try captured[at].check_applied(start, db.bounds().end);
            // With the database at the parent's tip, the child's proof and pins are unchanged.
            if (at == 1) try captured[2].check_unchanged(child, &db);
        }
        const empty = try merkleize_range(&db, null, 0, 0, null);
        defer empty.release();
        try captured[captured_len].capture(empty, &db);
        captured_len += 1;
        start = db.bounds().end;
        try db.apply_batch(empty);
        try captured[3].check_applied(start, db.bounds().end);
        // An operation's chunk of the log is also its proof's: each delta matches the log.
        for (captured[0..captured_len]) |*c| try c.check_log(&db);
        try check_after_flush(Db, &db);
        try db.destroy();
    }
}
