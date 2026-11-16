//! Tests of the authenticated journal, ported from commonware's `journal/authenticated.rs`.
//! Every test runs under both Merkle families.
//!
//! Commonware's test operation is qmdb's `any::operation::Unordered`; these tests only compare
//! roots between journals, so a fixed stand-in (`Op`: a tag, a key, and a value) checks the
//! same behavior. `drop` is `deinit` (unsynced state is discarded on close) and
//! `start_and_recover` is `Storage.crash`. Tests that drive delayed or failing syncs, record
//! read options, or run parallel strategies have no counterpart: syncs complete synchronously
//! and merkleization is sequential here.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const merkle = @import("../merkle/mod.zig");
const fixed = @import("contiguous/fixed.zig");
const variable = @import("contiguous/variable.zig");
const authenticated_journal = @import("authenticated_journal.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Hasher = merkle.hasher.Standard(Sha256);
const CacheRef = runtime.buffer.paged.CacheRef;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };

/// The test operation: tag 0 is an update of key to value, tag 1 a commit.
const Op = struct { u8, [32]u8, [32]u8 };
const commit_op: Op = .{ 1, @splat(0), @splat(0) };

/// Commonware's `create_operation(index)`: an update of `fill(index)` to `fill(index + 1)`.
fn create_operation(index: u8) Op {
    return .{ 0, @splat(index), @splat(index +% 1) };
}

fn is_commit(op: Op) bool {
    return op[0] == 1;
}

fn always(_: Op) bool {
    return true;
}

fn TestJournal(comptime F: type) type {
    return authenticated_journal.Journal(F, fixed.Journal(Op), Sha256);
}

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    journal_cache: CacheRef,
    merkle_cache: CacheRef,
    merkle_items_per_blob: u64 = 11,

    fn init() !Harness {
        var journal_cache = try CacheRef.init(gpa, 101, 11);
        errdefer journal_cache.deinit();
        return .{
            .storage = .init(gpa),
            .journal_cache = journal_cache,
            .merkle_cache = try CacheRef.init(gpa, 101, 11),
        };
    }

    fn deinit(self: *Harness) void {
        self.merkle_cache.deinit();
        self.journal_cache.deinit();
        self.storage.deinit();
    }

    fn merkle_cfg(self: *Harness, comptime suffix: []const u8) merkle.full.Config {
        return .{
            .journal_partition = "mmr-journal-" ++ suffix,
            .metadata_partition = "mmr-metadata-" ++ suffix,
            .items_per_blob = self.merkle_items_per_blob,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.merkle_cache,
        };
    }

    fn journal_cfg(self: *Harness, comptime suffix: []const u8) fixed.Config {
        return .{
            .partition = "journal-" ++ suffix,
            .items_per_blob = 7,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.journal_cache,
        };
    }

    /// Commonware's `create_empty_journal`: opens at the last commit.
    fn open(self: *Harness, comptime F: type, comptime suffix: []const u8) !TestJournal(F) {
        return self.open_with(F, suffix, is_commit);
    }

    fn open_with(
        self: *Harness,
        comptime F: type,
        comptime suffix: []const u8,
        comptime predicate: fn (Op) bool,
    ) !TestJournal(F) {
        const storage = self.storage.interface();
        const merkle_config = self.merkle_cfg(suffix);
        const journal_config = self.journal_cfg(suffix);
        const bagging: merkle.Bagging = .forward_fold;
        return TestJournal(F).init(gpa, storage, merkle_config, journal_config, predicate, bagging);
    }

    fn open_at_most(
        self: *Harness,
        comptime F: type,
        comptime suffix: []const u8,
        max_size: u64,
        comptime predicate: fn (Op) bool,
    ) !TestJournal(F) {
        return TestJournal(F).init_at_most(
            gpa,
            self.storage.interface(),
            self.merkle_cfg(suffix),
            self.journal_cfg(suffix),
            max_size,
            predicate,
            .forward_fold,
        );
    }

    /// Commonware's `create_journal_with_ops`: `count` operations, synced.
    fn open_with_ops(
        self: *Harness,
        comptime F: type,
        comptime suffix: []const u8,
        count: usize,
    ) !TestJournal(F) {
        var journal = try self.open(F, suffix);
        errdefer journal.deinit();
        for (0..count) |i| {
            try testing.expectEqual(i, try journal.append(create_operation(@intCast(i))));
        }
        try journal.sync();
        return journal;
    }

    /// Commonware's `create_components`: a Merkle structure and an operation journal opened
    /// independently.
    fn components(self: *Harness, comptime F: type, comptime suffix: []const u8) !struct {
        TestJournal(F).Merkle,
        fixed.Journal(Op),
    } {
        const storage = self.storage.interface();
        var structure =
            try TestJournal(F).Merkle.init(gpa, storage, &hasher, self.merkle_cfg(suffix));
        errdefer structure.deinit();
        const journal = try fixed.Journal(Op).init(gpa, storage, self.journal_cfg(suffix));
        return .{ structure, journal };
    }
};

const hasher = Hasher.init(.forward_fold);

fn verify_proof(proof: anytype, start: u64, ops: []const Op, root: *const Digest) !bool {
    var encoded: [128][codec.fixed_size(Op).?]u8 = undefined;
    var slices: [128][]const u8 = undefined;
    std.debug.assert(ops.len <= encoded.len);
    for (ops, 0..) |op, index| {
        encoded[index] = codec.encode_fixed(Op, op);
        slices[index] = &encoded[index];
    }
    return proof.verify_range_inclusion(&hasher, start, slices[0..ops.len], root);
}

fn expect_op(expected: Op, actual: Op) !void {
    try testing.expect(std.meta.eql(expected, actual));
}

fn run(comptime test_fn: anytype) !void {
    inline for (families) |F| try test_fn(F);
}

fn new_creates_empty_journal(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "new-empty");
    defer journal.deinit();
    try testing.expectEqual(0, journal.get_bounds().start);
    try testing.expectEqual(0, journal.get_bounds().end);
}

test "new creates an empty journal" {
    try run(new_creates_empty_journal);
}

fn align_with_empty_components(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure, var journal = try harness.components(F, "align-empty");
    defer structure.deinit();
    defer journal.deinit();
    const batch_size = authenticated_journal.apply_batch_size;
    try TestJournal(F).align_merkle(gpa, &structure, &journal, &hasher, batch_size);
    try testing.expectEqual(0, structure.leaves());
    try testing.expectEqual(0, journal.size());
}

test "align with an empty Merkle structure and journal" {
    try run(align_with_empty_components);
}

fn from_components_rejects_merkle_ahead(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure, var journal = try harness.components(F, "mmr-ahead");
    // Keep the Merkle structure one operation ahead of the journal.
    var batch = try structure.new_batch();
    for (0..20) |i| {
        const op = create_operation(@intCast(i));
        try batch.add(gpa, &hasher, &codec.encode_fixed(Op, op));
        if (i < 19) _ = try journal.append(op);
    }
    const merkleized = try batch.merkleize(&structure, &hasher);
    try structure.apply_batch(merkleized);
    merkleized.release(gpa);
    try journal.sync();
    const result = TestJournal(F).from_components(gpa, structure, journal, hasher, 1 << 16);
    try testing.expectError(error.Corruption, result);
}

test "from_components rejects a Merkle structure ahead of the journal" {
    try run(from_components_rejects_merkle_ahead);
}

fn align_when_journal_ahead(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure, var journal = try harness.components(F, "journal-ahead");
    defer structure.deinit();
    defer journal.deinit();
    for (0..20) |i| _ = try journal.append(create_operation(@intCast(i)));
    _ = try journal.append(commit_op);
    try journal.sync();
    // The journal has 21 operations and the structure none; a small batch size replays them
    // over several batches.
    try TestJournal(F).align_merkle(gpa, &structure, &journal, &hasher, 8);
    try testing.expectEqual(21, structure.leaves());
    try testing.expectEqual(21, journal.size());
    // The replayed structure matches one built by appending.
    var reference = try harness.open(F, "journal-ahead-reference");
    defer reference.deinit();
    for (0..20) |i| _ = try reference.append(create_operation(@intCast(i)));
    _ = try reference.append(commit_op);
    try testing.expect((try structure.root(&hasher, 0)).eql(try reference.root(0)));
}

test "align replays journal operations the Merkle structure lacks" {
    try run(align_when_journal_ahead);
}

fn align_with_mismatched_committed_ops(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "mismatched");
    for (0..20) |i| try testing.expectEqual(i, try journal.append(create_operation(@intCast(i))));
    try testing.expectEqual(20, journal.size());
    // A persisted suffix without a commit is discarded on restart.
    try journal.sync();
    journal.deinit();
    journal = try harness.open(F, "mismatched");
    defer journal.deinit();
    try testing.expectEqual(0, journal.size());
}

test "uncommitted operations are discarded on reopen" {
    try run(align_with_mismatched_committed_ops);
}

fn initialization_selection_backing(comptime F: type) !void {
    _ = F;
    // Select the latest complete commit at or below each cap, before and after pruning.
    const authenticated = @import("authenticated.zig");
    for ([_]u64{ 0, 7 }) |start| {
        for ([_]u64{ 0, 1, 2, 3, 4, 7, 8, 11, 12, 14, 15, 100 }) |cap| {
            var harness = try Harness.init();
            defer harness.deinit();
            const storage = harness.storage.interface();
            const cfg = harness.journal_cfg("select");
            var journal = try fixed.Journal(Op).init(gpa, storage, cfg);
            for (0..15) |i| {
                const commit = i == 1 or i == 3 or i == 10 or i == 13;
                _ = try journal.append(if (commit) commit_op else create_operation(@intCast(i)));
            }
            try journal.sync();
            if (start > 0) _ = try journal.prune(start);
            journal.deinit();
            // The expected exclusive end among the retained commit candidates.
            var expected: ?u64 = null;
            for ([_]u64{ 2, 4, 11, 14 }) |end| {
                if (end <= cap and end > start) expected = end;
            }
            if (cap < start) {
                const recovered = fixed.Journal(Op).recover(gpa, storage, cfg, cap);
                try testing.expectError(error.ItemPruned, recovered);
                continue;
            }
            var pending = try fixed.Journal(Op).recover(gpa, storage, cfg, cap);
            const Matcher = struct {
                fn matches(_: void, op: Op) bool {
                    return is_commit(op);
                }
            };
            const selected = authenticated.last_matching(&pending, cap, {}, Matcher.matches);
            if (expected == null and start > 0) {
                pending.deinit();
                try testing.expectError(error.ItemPruned, selected);
                continue;
            }
            const size = selected catch |err| {
                pending.deinit();
                return err;
            };
            try testing.expectEqual(expected orelse 0, size);
            // Publication makes the selected end authoritative on reopen.
            var published = try pending.finish(size);
            published.deinit();
            var reopened = try fixed.Journal(Op).init(gpa, storage, cfg);
            defer reopened.deinit();
            try testing.expectEqual(size, reopened.size());
        }
    }
}

fn initialization_selection_caps(comptime F: type) !void {
    // Bound both authenticated components to every prefix around the durable tip.
    for ([_]u64{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 100 }) |cap| {
        var harness = try Harness.init();
        defer harness.deinit();
        var journal = try harness.open_with(F, "authenticated-cap", always);
        var roots: [9]Digest = undefined;
        roots[0] = try journal.root(0);
        for (0..8) |i| {
            _ = try journal.append(create_operation(@intCast(i)));
            roots[i + 1] = try journal.root(0);
        }
        try journal.sync();
        journal.deinit();
        journal = try harness.open_at_most(F, "authenticated-cap", cap, always);
        const size = @min(cap, 8);
        try testing.expectEqual(size, journal.size());
        try testing.expect((try journal.root(0)).eql(roots[size]));
        journal.deinit();
        journal = try harness.open_with(F, "authenticated-cap", always);
        defer journal.deinit();
        try testing.expectEqual(size, journal.size());
        try testing.expect((try journal.root(0)).eql(roots[size]));
    }
}

test "initialization selects the last commit at or below each cap" {
    try run(initialization_selection_backing);
    try run(initialization_selection_caps);
}

fn apply_op_and_read_operations(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "apply_op");
    defer journal.deinit();
    try testing.expectEqual(0, journal.size());
    for (0..50) |i| {
        try testing.expectEqual(i, try journal.append(create_operation(@intCast(i))));
        try testing.expectEqual(i + 1, journal.size());
    }
    try journal.sync();
    for (0..50) |i| try expect_op(create_operation(@intCast(i)), try journal.read(i));
    // Reads at the first, middle, and last positions, and through `read_many`.
    try expect_op(create_operation(0), try journal.read(0));
    try expect_op(create_operation(25), try journal.read(25));
    try expect_op(create_operation(49), try journal.read(49));
    var out: [3]Op = undefined;
    try journal.read_many(&.{ 0, 25, 49 }, &out);
    try expect_op(create_operation(25), out[1]);
}

test "append returns locations and operations read back" {
    try run(apply_op_and_read_operations);
}

fn read_errors(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "read_pruned", 100);
    defer journal.deinit();
    try testing.expectError(error.ItemOutOfRange, journal.read(100));
    _ = try journal.append(commit_op);
    try journal.sync();
    const boundary = try journal.prune(50);
    try testing.expect(boundary > 0);
    try testing.expectError(error.ItemPruned, journal.read(0));
    try testing.expectError(error.ItemOutOfRange, journal.read(200));
}

test "reads of pruned or out-of-range operations fail" {
    try run(read_errors);
}

fn sync_persists(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "close_pending");
    for (0..20) |i| try testing.expectEqual(i, try journal.append(create_operation(@intCast(i))));
    try testing.expectEqual(20, try journal.append(commit_op));
    try journal.sync();
    journal.deinit();
    harness.storage.crash();
    journal = try harness.open(F, "close_pending");
    defer journal.deinit();
    try testing.expectEqual(21, journal.size());
    for (0..20) |i| try expect_op(create_operation(@intCast(i)), try journal.read(i));
}

test "sync persists operations" {
    try run(sync_persists);
}

fn start_sync_durability(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "start_sync");
    for (0..5) |i| _ = try journal.append(create_operation(@intCast(i)));
    _ = try journal.append(commit_op);
    try journal.start_sync();
    const root = try journal.root(0);
    journal.deinit();
    harness.storage.crash();
    journal = try harness.open(F, "start_sync");
    defer journal.deinit();
    try testing.expectEqual(6, journal.size());
    try testing.expect((try journal.root(0)).eql(root));
    for (0..5) |i| try expect_op(create_operation(@intCast(i)), try journal.read(i));
}

test "start_sync gives commit durability" {
    try run(start_sync_durability);
}

fn commit_recovers_by_replay(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "commit_replay");
    for (0..30) |i| _ = try journal.append(create_operation(@intCast(i)));
    _ = try journal.append(commit_op);
    // Commit syncs the operations but only flushes the Merkle structure, so after a crash
    // recovery replays the operations the structure lost.
    try journal.commit();
    const root = try journal.root(0);
    journal.deinit();
    harness.storage.crash();
    journal = try harness.open(F, "commit_replay");
    defer journal.deinit();
    try testing.expectEqual(31, journal.size());
    try testing.expect((try journal.root(0)).eql(root));
}

test "commit is recovered by replaying operations" {
    try run(commit_recovers_by_replay);
}

fn prune_empty_journal(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "prune_empty");
    defer journal.deinit();
    try testing.expectEqual(0, try journal.prune(0));
}

test "prune of an empty journal" {
    try run(prune_empty_journal);
}

fn prune_to_location(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "prune_to", 100);
    defer journal.deinit();
    _ = try journal.append(commit_op);
    try journal.sync();
    const count_before = journal.size();
    const boundary = try journal.prune(50);
    // The boundary is the journal's retained start, at or below the request (blob aligned).
    try testing.expect(boundary <= 50);
    try testing.expectEqual(journal.get_bounds().start, boundary);
    try testing.expect(journal.get_bounds().start < journal.get_bounds().end);
    // Pruning keeps the operation count, and the Merkle structure follows the journal.
    try testing.expectEqual(count_before, journal.size());
    try testing.expectEqual(boundary, journal.merkle.bounds().start);
}

test "prune returns the journal's actual boundary" {
    try run(prune_to_location);
}

fn prune_reporting_updates_merkle_boundary(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "trait_prune", 100);
    defer journal.deinit();
    _ = try journal.append(commit_op);
    try journal.sync();
    const first = try journal.prune_reporting(50);
    try testing.expect(first.pruned);
    const item_boundary = journal.get_bounds().start;
    const merkle_boundary = journal.merkle.bounds().start;
    try testing.expectEqual(item_boundary, merkle_boundary);
    try testing.expect(merkle_boundary > 0);
    const second = try journal.prune_reporting(50);
    try testing.expect(!second.pruned);
    try testing.expectEqual(item_boundary, journal.get_bounds().start);
    try testing.expectEqual(merkle_boundary, journal.merkle.bounds().start);
}

test "prune updates the Merkle boundary and reports whether it pruned" {
    try run(prune_reporting_updates_merkle_boundary);
}

fn bounds_empty_and_pruned(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "oldest");
    try testing.expectEqual(journal.get_bounds().start, journal.get_bounds().end);
    try journal.destroy();
    journal = try harness.open_with_ops(F, "oldest", 100);
    try testing.expectEqual(0, journal.get_bounds().start);
    try testing.expectEqual(100, journal.get_bounds().end);
    try journal.destroy();
    // Without a commit the operations reopen empty, so commit before pruning.
    journal = try harness.open_with_ops(F, "oldest", 100);
    _ = try journal.append(commit_op);
    try journal.sync();
    const boundary = try journal.prune(50);
    try testing.expectEqual(boundary, journal.get_bounds().start);
    try testing.expect(boundary <= 50);
    try testing.expect(journal.get_bounds().start < journal.get_bounds().end);
    try journal.destroy();
}

test "bounds of empty, unpruned, and pruned journals" {
    try run(bounds_empty_and_pruned);
}

fn merkle_prunes_to_journal_boundary(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "mmr_boundary", 50);
    defer journal.deinit();
    _ = try journal.append(commit_op);
    try journal.sync();
    const boundary = try journal.prune(25);
    try testing.expectEqual(journal.get_bounds().start, boundary);
    try testing.expect(boundary <= 25);
    try testing.expectEqual(51, journal.size());
    try testing.expectEqual(boundary, journal.merkle.bounds().start);
}

test "the Merkle structure prunes to the journal's boundary" {
    try run(merkle_prunes_to_journal_boundary);
}

fn proofs(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "proof_multi", 50);
    defer journal.deinit();
    const root = try journal.root(0);
    // All operations.
    var proved = try journal.proof(0, 50, 0);
    try testing.expectEqual(50, proved.items.len);
    for (proved.items, 0..) |op, i| try expect_op(create_operation(@intCast(i)), op);
    try testing.expect(try verify_proof(&proved.proof, 0, proved.items, &root));
    proved.deinit(gpa);
    // Limited by `max_ops`.
    proved = try journal.historical_proof(journal.size(), 0, 20, 0);
    try testing.expectEqual(20, proved.items.len);
    try testing.expect(try verify_proof(&proved.proof, 0, proved.items, &root));
    proved.deinit(gpa);
    // At the end of the journal.
    proved = try journal.historical_proof(journal.size(), 40, 20, 0);
    try testing.expectEqual(10, proved.items.len);
    for (proved.items, 40..) |op, i| try expect_op(create_operation(@intCast(i)), op);
    try testing.expect(try verify_proof(&proved.proof, 40, proved.items, &root));
    proved.deinit(gpa);
    // A size beyond the journal, and a start at the size.
    try testing.expectError(error.RangeOutOfBounds, journal.historical_proof(51, 0, 1, 0));
    try testing.expectError(error.RangeOutOfBounds, journal.historical_proof(50, 50, 1, 0));
}

test "proofs over ranges, limits, and the journal end" {
    try run(proofs);
}

fn historical_proof_truly_historical(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "proof_historical", 50);
    defer journal.deinit();
    const historical_root = try journal.root(0);
    const historical_size = journal.size();
    for (50..100) |i| _ = try journal.append(create_operation(@intCast(i)));
    try journal.sync();
    var proved = try journal.historical_proof(historical_size, 0, 50, 0);
    defer proved.deinit(gpa);
    try testing.expectEqual(50, proved.items.len);
    for (proved.items, 0..) |op, i| try expect_op(create_operation(@intCast(i)), op);
    try testing.expect(try verify_proof(&proved.proof, 0, proved.items, &historical_root));
    try testing.expect(!try verify_proof(&proved.proof, 0, proved.items, &try journal.root(0)));
}

test "historical proofs verify against the historical root" {
    try run(historical_proof_truly_historical);
}

fn historical_proof_pruned_location(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "proof_pruned", 50);
    defer journal.deinit();
    _ = try journal.append(commit_op);
    try journal.sync();
    const boundary = try journal.prune(25);
    try testing.expect(boundary > 0);
    const result = journal.historical_proof(journal.size(), 0, 1, 0);
    try testing.expect(std.meta.isError(result));
}

test "historical proofs of pruned locations fail" {
    try run(historical_proof_pruned_location);
}

fn replay_operations(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var empty = try harness.open(F, "replay-empty");
    var replay = try empty.replay(.{ .start = 0, .end = 0 }, 10 * @sizeOf(Op));
    try testing.expect((try replay.next()) == null);
    replay.deinit();
    empty.deinit();
    var journal = try harness.open_with_ops(F, "replay", 50);
    defer journal.deinit();
    for ([_]u64{ 0, 25 }) |start| {
        replay = try journal.replay(.{ .start = start, .end = 50 }, 100 * @sizeOf(Op));
        defer replay.deinit();
        var expected = start;
        while (try replay.next()) |batch| {
            try testing.expectEqual(expected, batch.start);
            for (batch.items, expected..) |op, i| try expect_op(create_operation(@intCast(i)), op);
            expected += batch.items.len;
        }
        try testing.expectEqual(50, expected);
    }
}

test "replay from the start and the middle" {
    try run(replay_operations);
}

/// A batch on `parent` (or the journal when null) with `ops` added and merkleized.
fn batch_of(
    comptime F: type,
    journal: *TestJournal(F),
    parent: ?*TestJournal(F).MerkleizedBatch,
    ops: []const Op,
) !*TestJournal(F).MerkleizedBatch {
    var batch = if (parent) |p| p.new_batch() else try journal.new_batch();
    errdefer batch.deinit(gpa);
    for (ops) |op| try batch.add(gpa, op);
    return batch.merkleize(gpa, journal);
}

fn batch_root(
    comptime F: type,
    journal: *TestJournal(F),
    batch: *TestJournal(F).MerkleizedBatch,
) !Digest {
    return batch.root(&journal.hasher, 0);
}

fn speculative_batch(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "speculative_batch", 10);
    defer journal.deinit();
    const original_root = try journal.root(0);
    // Fork two batches with different items: their roots differ from each other and the
    // journal's, which they leave unchanged.
    const m1 = try batch_of(F, &journal, null, &.{create_operation(100)});
    defer m1.release(gpa);
    const m2 = try batch_of(F, &journal, null, &.{create_operation(200)});
    defer m2.release(gpa);
    try testing.expect(!(try batch_root(F, &journal, m1)).eql(try batch_root(F, &journal, m2)));
    try testing.expect(!(try batch_root(F, &journal, m1)).eql(original_root));
    try testing.expect((try journal.root(0)).eql(original_root));
    const expected_root = try batch_root(F, &journal, m1);
    try journal.apply_batch(m1);
    try testing.expect((try journal.root(0)).eql(expected_root));
    try testing.expectEqual(11, journal.size());
}

test "speculative batches fork independent roots" {
    try run(speculative_batch);
}

fn speculative_batch_stacking(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "batch_stacking", 10);
    defer journal.deinit();
    const a = try batch_of(F, &journal, null, &.{create_operation(100)});
    const b = try batch_of(F, &journal, a, &.{create_operation(200)});
    defer b.release(gpa);
    const expected_root = try batch_root(F, &journal, b);
    try journal.apply_batch(b);
    a.release(gpa);
    try testing.expect((try journal.root(0)).eql(expected_root));
    try testing.expectEqual(12, journal.size());
    try expect_op(create_operation(100), try journal.read(10));
    try expect_op(create_operation(200), try journal.read(11));
}

test "stacked batches apply their ancestors' items" {
    try run(speculative_batch_stacking);
}

fn speculative_batch_sequential(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "batch_sequential", 10);
    defer journal.deinit();
    const a = try batch_of(F, &journal, null, &.{create_operation(100)});
    try journal.apply_batch(a);
    a.release(gpa);
    try testing.expectEqual(11, journal.size());
    const b = try batch_of(F, &journal, null, &.{create_operation(200)});
    defer b.release(gpa);
    const expected_root = try batch_root(F, &journal, b);
    try journal.apply_batch(b);
    try testing.expect((try journal.root(0)).eql(expected_root));
    try testing.expectEqual(12, journal.size());
    try expect_op(create_operation(100), try journal.read(10));
    try expect_op(create_operation(200), try journal.read(11));
}

test "sequential batches apply on the committed state" {
    try run(speculative_batch_sequential);
}

fn stale_batch_sibling(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "stale-sibling");
    const a = try batch_of(F, &journal, null, &.{create_operation(1)});
    defer a.release(gpa);
    const b = try batch_of(F, &journal, null, &.{create_operation(2)});
    defer b.release(gpa);
    // Apply A and commit, so the reopened state includes it.
    try journal.apply_batch(a);
    _ = try journal.append(commit_op);
    try journal.sync();
    const root_a = try journal.root(0);
    const size_a = journal.size();
    try testing.expectError(error.StaleBatch, journal.apply_batch(b));
    // The eager reject wrote nothing: reopening recovers exactly A's state.
    journal.deinit();
    journal = try harness.open(F, "stale-sibling");
    try testing.expect((try journal.root(0)).eql(root_a));
    try testing.expectEqual(size_a, journal.size());
    try expect_op(create_operation(1), try journal.read(0));
    try journal.destroy();
}

test "a sibling of an applied batch is stale" {
    try run(stale_batch_sibling);
}

fn stale_batch_chained(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "stale-chained", 5);
    defer journal.deinit();
    const parent = try batch_of(F, &journal, null, &.{create_operation(10)});
    const child_a = try batch_of(F, &journal, parent, &.{create_operation(20)});
    defer child_a.release(gpa);
    const child_b = try batch_of(F, &journal, parent, &.{create_operation(30)});
    defer child_b.release(gpa);
    try journal.apply_batch(child_a);
    const result = journal.apply_batch(child_b);
    parent.release(gpa);
    try testing.expectError(error.StaleBatch, result);
}

test "a sibling child is stale after its cousin is applied" {
    try run(stale_batch_chained);
}

fn stale_batch_order(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    // Parent then child applies in order.
    var journal = try harness.open(F, "stale-parent-first");
    var parent = try batch_of(F, &journal, null, &.{create_operation(1)});
    var child = try batch_of(F, &journal, parent, &.{create_operation(2)});
    const expected_root = try batch_root(F, &journal, child);
    try journal.apply_batch(parent);
    try journal.apply_batch(child);
    try testing.expect((try journal.root(0)).eql(expected_root));
    try testing.expectEqual(2, journal.size());
    child.release(gpa);
    parent.release(gpa);
    journal.deinit();
    // Applying the child first (the whole chain) makes the parent stale.
    journal = try harness.open(F, "stale-child-first");
    defer journal.deinit();
    parent = try batch_of(F, &journal, null, &.{create_operation(1)});
    defer parent.release(gpa);
    child = try batch_of(F, &journal, parent, &.{create_operation(2)});
    defer child.release(gpa);
    try journal.apply_batch(child);
    try testing.expectError(error.StaleBatch, journal.apply_batch(parent));
}

test "a parent then its child apply, but not the reverse" {
    try run(stale_batch_order);
}

fn stale_batch_interior_fork(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "stale-interior");
    for (0..4) |i| _ = try journal.append(create_operation(@intCast(i)));
    // Retain the chain A -> B, then apply a sibling of A with the same length.
    const a = try batch_of(F, &journal, null, &.{ create_operation(10), commit_op });
    defer a.release(gpa);
    const b = try batch_of(F, &journal, a, &.{create_operation(20)});
    defer b.release(gpa);
    const sibling = try batch_of(F, &journal, null, &.{ create_operation(30), commit_op });
    defer sibling.release(gpa);
    try journal.apply_batch(sibling);
    try journal.sync();
    const root = try journal.root(0);
    const size = journal.size();
    // The journal's size lies inside B's chain, but the sibling produced it: B is stale and
    // must fail before writing anything.
    try testing.expectError(error.StaleBatch, journal.apply_batch(b));
    try testing.expectEqual(size, journal.journal.size());
    journal.deinit();
    journal = try harness.open(F, "stale-interior");
    try testing.expect((try journal.root(0)).eql(root));
    try testing.expectEqual(size, journal.size());
    try expect_op(create_operation(30), try journal.read(4));
    try journal.destroy();
}

test "a retained child of a fork is stale after the fork's sibling is applied" {
    try run(stale_batch_interior_fork);
}

fn apply_batch_empty_child_after_parent(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "empty-child", 4);
    const parent = try batch_of(F, &journal, null, &.{create_operation(10)});
    defer parent.release(gpa);
    const child = try batch_of(F, &journal, parent, &.{});
    defer child.release(gpa);
    try journal.apply_batch(parent);
    const root = try journal.root(0);
    const size = journal.size();
    // The journal is already at the empty child's tip, so applying it changes nothing.
    try journal.apply_batch(child);
    try testing.expect((try journal.root(0)).eql(root));
    try testing.expectEqual(size, journal.size());
    try journal.destroy();
}

test "an empty child applies after its parent" {
    try run(apply_batch_empty_child_after_parent);
}

fn apply_batch_rejects_dropped_journal_ancestor(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "dropped-items", 4);
    const seed = try batch_of(F, &journal, null, &.{ create_operation(5), commit_op });
    try journal.apply_batch(seed);
    seed.release(gpa);
    try journal.sync();
    const root = try journal.root(0);
    const size = journal.size();
    // In the chain A -> B -> C, A's Merkle batch outlives its journal batch, so C retains A's
    // Merkle changes but not A's items.
    const a = try batch_of(F, &journal, null, &.{create_operation(10)});
    const b = try batch_of(F, &journal, a, &.{create_operation(20)});
    const a_merkle = a.inner.retain();
    a.release(gpa);
    const c = try batch_of(F, &journal, b, &.{ create_operation(30), commit_op });
    try testing.expectError(error.AncestorDropped, journal.apply_batch(c));
    c.release(gpa);
    b.release(gpa);
    a_merkle.release(gpa);
    // Reopening recovers the state from before the rejected batch.
    journal.deinit();
    journal = try harness.open(F, "dropped-items");
    try testing.expect((try journal.root(0)).eql(root));
    try testing.expectEqual(size, journal.size());
    try journal.destroy();
}

test "a batch whose ancestor's items were dropped is rejected" {
    try run(apply_batch_rejects_dropped_journal_ancestor);
}

fn apply_batch_skips_committed_ancestor_items(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "rp-skip", 3);
    defer journal.deinit();
    const parent_ops = [_]Op{ create_operation(10), create_operation(11) };
    const parent = try batch_of(F, &journal, null, &parent_ops);
    defer parent.release(gpa);
    const child_ops = [_]Op{ create_operation(20), create_operation(21), create_operation(22) };
    const child = try batch_of(F, &journal, parent, &child_ops);
    defer child.release(gpa);
    try journal.apply_batch(parent);
    // The parent's items are committed already, so the child appends only its own.
    try journal.apply_batch(child);
    var proved = try journal.proof(3, 5, 0);
    defer proved.deinit(gpa);
    try testing.expectEqual(5, proved.items.len);
    try expect_op(create_operation(11), proved.items[1]);
    try expect_op(create_operation(22), proved.items[4]);
}

test "a child skips its committed parent's items" {
    try run(apply_batch_skips_committed_ancestor_items);
}

fn apply_batch_cross_batch(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "rp-cross", 2);
    defer journal.deinit();
    const grandparent_ops = [_]Op{ create_operation(3), create_operation(4), create_operation(5) };
    const grandparent = try batch_of(F, &journal, null, &grandparent_ops);
    defer grandparent.release(gpa);
    const parent_ops = [_]Op{ create_operation(6), create_operation(7) };
    const parent = try batch_of(F, &journal, grandparent, &parent_ops);
    defer parent.release(gpa);
    const child = try batch_of(F, &journal, parent, &.{create_operation(8)});
    defer child.release(gpa);
    try journal.apply_batch(grandparent);
    try journal.apply_batch(parent);
    try journal.apply_batch(child);
    try testing.expectEqual(8, journal.size());
    var proved = try journal.proof(2, 6, 0);
    defer proved.deinit(gpa);
    for (proved.items, 3..) |op, i| try expect_op(create_operation(@intCast(i)), op);
}

test "apply_batch across a three-level chain" {
    try run(apply_batch_cross_batch);
}

fn merkleize_with_items(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "mw-matches", 5);
    defer journal.deinit();
    const ops = [_]Op{ create_operation(10), create_operation(11), create_operation(12) };
    // `add` then merkleize, and `merkleize` with the items, give the same root.
    const expected = try batch_of(F, &journal, null, &ops);
    defer expected.release(gpa);
    var batch = try journal.new_batch();
    const actual = try journal.merkleize(&batch, &ops, 0);
    defer actual.batch.release(gpa);
    try testing.expect(actual.root.eql(try batch_root(F, &journal, expected)));
    // Its items are readable after apply.
    try journal.apply_batch(actual.batch);
    try testing.expect((try journal.root(0)).eql(actual.root));
    try testing.expectEqual(8, journal.size());
    try expect_op(ops[0], try journal.read(5));
    try expect_op(ops[2], try journal.read(7));
}

test "merkleize with items matches add and applies" {
    try run(merkleize_with_items);
}

fn apply_batch_skips_only_committed_ancestor_items(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "skip-partial");
    defer journal.deinit();
    // Build A -> B -> C, apply A, then C directly: B's items must still be appended.
    const a = try batch_of(F, &journal, null, &.{create_operation(1)});
    defer a.release(gpa);
    const b = try batch_of(F, &journal, a, &.{create_operation(2)});
    defer b.release(gpa);
    const c = try batch_of(F, &journal, b, &.{create_operation(3)});
    defer c.release(gpa);
    try journal.apply_batch(a);
    try journal.apply_batch(c);
    try testing.expectEqual(3, journal.size());
    var reference = try harness.open(F, "skip-partial-ref");
    defer reference.deinit();
    for (1..4) |i| _ = try reference.append(create_operation(@intCast(i)));
    try testing.expect((try journal.root(0)).eql(try reference.root(0)));
}

test "a grandchild skips only its committed ancestor's items" {
    try run(apply_batch_skips_only_committed_ancestor_items);
}

fn apply_batch_detects_dropped_uncommitted_ancestor(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "dropped-uncommitted");
    defer journal.deinit();
    const a = try batch_of(F, &journal, null, &.{create_operation(1)});
    const b = try batch_of(F, &journal, a, &.{create_operation(2)});
    a.release(gpa);
    const c = try batch_of(F, &journal, b, &.{create_operation(3)});
    defer c.release(gpa);
    b.release(gpa);
    try testing.expectEqual(1, c.ancestor_items.len);
    try testing.expectError(error.AncestorDropped, journal.apply_batch(c));
    try testing.expectEqual(0, journal.size());
}

test "a dropped uncommitted ancestor is detected before appending" {
    try run(apply_batch_detects_dropped_uncommitted_ancestor);
}

fn apply_batch_after_committed_ancestor_dropped(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "dropped-committed");
    defer journal.deinit();
    var a_ops: [8]Op = undefined;
    for (&a_ops, 0..) |*op, i| op.* = create_operation(@intCast(i));
    const a = try batch_of(F, &journal, null, &a_ops);
    const b = try batch_of(F, &journal, a, &.{create_operation(8)});
    try journal.apply_batch(a);
    a.release(gpa);
    const c = try batch_of(F, &journal, b, &.{create_operation(9)});
    defer c.release(gpa);
    // Only B remains in the retained ancestor suffix.
    try testing.expectEqual(1, c.ancestor_items.len);
    try testing.expectEqual(0, try journal.merkle.mem.validate_batch(c.inner));
    b.release(gpa);
    try journal.apply_batch(c);
    try testing.expectEqual(10, journal.size());
    var reference = try harness.open(F, "dropped-committed-ref");
    defer reference.deinit();
    for (0..10) |i| _ = try reference.append(create_operation(@intCast(i)));
    try testing.expect((try journal.root(0)).eql(try reference.root(0)));
}

test "a dropped committed prefix does not shift uncommitted ancestor items" {
    try run(apply_batch_after_committed_ancestor_dropped);
}

fn merkleize_after_committed_prefix_dropped(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open(F, "committed-prefix");
    defer journal.deinit();
    var prefix_ops: [8]Op = undefined;
    for (&prefix_ops, 0..) |*op, i| op.* = create_operation(@intCast(i));
    var batch = try journal.new_batch();
    const prefix = try journal.merkleize(&batch, &prefix_ops, 0);
    batch = prefix.batch.new_batch();
    const pending_ops = [_]Op{ create_operation(8), create_operation(9) };
    const pending = try journal.merkleize(&batch, &pending_ops, 0);
    // Commit and release the prefix; the child is then the pending suffix's only owner.
    try journal.apply_batch(prefix.batch);
    prefix.batch.release(gpa);
    batch = pending.batch.new_batch();
    pending.batch.release(gpa);
    const child = try journal.merkleize(&batch, &.{create_operation(10)}, 0);
    defer child.batch.release(gpa);
    try journal.apply_batch(child.batch);
    try testing.expect((try journal.root(0)).eql(child.root));
    try testing.expectEqual(11, journal.size());
}

test "merkleize retains a speculative suffix after its committed prefix is released" {
    try run(merkleize_after_committed_prefix_dropped);
}

fn speculative_proof_and_pins(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var journal = try harness.open_with_ops(F, "speculative-proof", 9);
    defer journal.deinit();
    const ops = [_]Op{ create_operation(20), create_operation(21), create_operation(22) };
    const parent = try batch_of(F, &journal, null, &.{create_operation(10)});
    defer parent.release(gpa);
    const batch = try batch_of(F, &journal, parent, &ops);
    defer batch.release(gpa);
    // The proof covers exactly the batch's items against its speculative root.
    const root = try batch_root(F, &journal, batch);
    var proof = try journal.speculative_proof(batch, 0);
    defer proof.deinit(gpa);
    try testing.expect(try verify_proof(&proof, 10, &ops, &root));
    try testing.expect(!try verify_proof(&proof, 9, &ops, &root));
    // The pins at the batch's first item match those of the applied structure.
    var pins: [merkle.max_pinned_nodes]Digest = undefined;
    const speculative = try journal.speculative_pinned_nodes(batch, &pins);
    try journal.apply_batch(batch);
    var applied: [merkle.max_pinned_nodes]Digest = undefined;
    const expected = try journal.merkle.pinned_nodes_at(10, &applied);
    try testing.expectEqual(expected.len, speculative.len);
    for (expected, speculative) |want, got| try testing.expect(want.eql(got));
}

test "speculative proofs and pinned nodes match the applied state" {
    try run(speculative_proof_and_pins);
}

fn fully_pruned_reopens(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    // Fill exactly one operation blob, then prune the complete durable prefix.
    var journal = try harness.open_with(F, "fully-pruned-reopen", always);
    for (0..7) |i| try testing.expectEqual(i, try journal.append(create_operation(@intCast(i))));
    try journal.sync();
    const root = try journal.root(0);
    try testing.expectEqual(7, try journal.prune(7));
    try testing.expectEqual(7, journal.get_bounds().start);
    try testing.expectEqual(7, journal.get_bounds().end);
    try testing.expect((try journal.root(0)).eql(root));
    journal.deinit();
    // Reopen at the retained boundary and append at that position.
    journal = try harness.open_with(F, "fully-pruned-reopen", always);
    try testing.expectEqual(7, journal.get_bounds().start);
    try testing.expectEqual(7, journal.get_bounds().end);
    try testing.expect((try journal.root(0)).eql(root));
    try testing.expectEqual(7, try journal.append(create_operation(7)));
    try testing.expectEqual(8, journal.get_bounds().end);
    try journal.destroy();
}

test "a fully pruned journal keeps its append position and root across reopen" {
    try run(fully_pruned_reopens);
}

fn init_at_most_without_match(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var fresh = try harness.open(F, "no-match-fresh");
    const fresh_root = try fresh.root(0);
    try fresh.destroy();
    for ([_]u64{ 1, 0 }) |max_size| {
        // Commit twice to a log starting at zero, then prune the Merkle structure above the
        // log's start (as a state sync starting inside the first section does).
        var journal = try harness.open(F, "no-match");
        for (0..10) |i| {
            const commit = i == 1 or i == 9;
            _ = try journal.append(if (commit) commit_op else create_operation(@intCast(i)));
        }
        try journal.sync();
        try journal.merkle.prune(8);
        try journal.sync();
        const bounds = journal.get_bounds();
        const merkle_bounds = journal.merkle.bounds();
        const root = try journal.root(0);
        journal.deinit();
        // The first commit ends at two, below the structure's pruning boundary: the open fails
        // and changes nothing.
        const below_boundary = harness.open_at_most(F, "no-match", 3, is_commit);
        try testing.expectError(error.ElementPruned, below_boundary);
        journal = try harness.open(F, "no-match");
        try testing.expectEqual(bounds, journal.get_bounds());
        try testing.expectEqual(merkle_bounds, journal.merkle.bounds());
        try testing.expect((try journal.root(0)).eql(root));
        try testing.expect((try journal.merkle.get_node(0)) == null);
        journal.deinit();
        // No commit ends at or below the cap, so both components are emptied.
        journal = try harness.open_at_most(F, "no-match", max_size, is_commit);
        try testing.expectEqual(0, journal.get_bounds().end);
        try testing.expect((try journal.root(0)).eql(fresh_root));
        journal.deinit();
        journal = try harness.open(F, "no-match");
        try testing.expectEqual(0, journal.get_bounds().end);
        try testing.expect((try journal.root(0)).eql(fresh_root));
        try journal.destroy();
    }
}

test "init_at_most without a match empties the journal beside a pruned Merkle structure" {
    try run(init_at_most_without_match);
}

fn variable_backing(comptime F: type) !void {
    // The journal works over the variable backing, whose items own memory.
    const Bytes = []const u8;
    const VJournal = authenticated_journal.Journal(F, variable.Journal(Bytes), Sha256);
    const Matcher = struct {
        fn is_commit_bytes(item: Bytes) bool {
            return item.len == 0;
        }
    };
    var harness = try Harness.init();
    defer harness.deinit();
    const journal_cfg: variable.Config(Bytes) = .{
        .partition = "variable",
        .items_per_section = 7,
        .codec_config = .{ .range = .full(), .item = {} },
        .cache_ref = &harness.journal_cache,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
    const storage = harness.storage.interface();
    const merkle_cfg = harness.merkle_cfg("variable");
    const predicate = Matcher.is_commit_bytes;
    var journal =
        try VJournal.init(gpa, storage, merkle_cfg, journal_cfg, predicate, .forward_fold);
    for (0..12) |i| {
        const byte: u8 = @intCast(i);
        _ = try journal.append(&.{ byte, byte, byte });
    }
    // A batch takes ownership of its items.
    var batch = try journal.new_batch();
    try batch.add(gpa, try gpa.dupe(u8, "batched"));
    try batch.add(gpa, try gpa.dupe(u8, ""));
    const merkleized = try batch.merkleize(gpa, &journal);
    try journal.apply_batch(merkleized);
    merkleized.release(gpa);
    try journal.sync();
    const root = try journal.root(0);
    journal.deinit();
    // Recovery reads owned items while selecting the last commit.
    journal =
        try VJournal.init(gpa, storage, merkle_cfg, journal_cfg, predicate, .forward_fold);
    defer journal.deinit();
    try testing.expectEqual(14, journal.size());
    try testing.expect((try journal.root(0)).eql(root));
    var proved = try journal.proof(11, 3, 0);
    defer proved.deinit(gpa);
    try testing.expectEqualStrings("batched", proved.items[1]);
}

test "the journal runs over the variable backing" {
    try run(variable_backing);
}

/// Where an interrupted destroy stopped, in the order destroy reaches each outcome.
const Interrupted = enum(u8) {
    /// Before the operation journal's clear was staged: reopens at its last commit.
    unchanged,
    /// While removing the operation journal: reopens empty.
    in_journal,
    /// After removing the operation journal, while removing the Merkle structure: reopens
    /// empty.
    in_merkle,
    completed,
};

fn partition_exists(harness: *Harness, partition: []const u8) !bool {
    var names = harness.storage.interface().scan(gpa, partition) catch |err| switch (err) {
        error.PartitionMissing => return false,
        else => return err,
    };
    names.deinit(gpa);
    return true;
}

/// Commits twice around a prune, so the Merkle metadata holds a boundary and pins that the
/// retained operations cannot rebuild.
fn commit_twice_around_prune(comptime J: type, journal: *J, ops: *const [102]Op) !void {
    for (ops[0..51]) |op| _ = try journal.append(op);
    try journal.sync();
    _ = try journal.prune(40);
    for (ops[51..]) |op| _ = try journal.append(op);
    try journal.sync();
}

/// Commits 41 new operations and returns the root.
fn commit_after_empty(comptime J: type, journal: *J) !Digest {
    for (150..190) |i| _ = try journal.append(create_operation(@intCast(i)));
    _ = try journal.append(commit_op);
    try journal.sync();
    return journal.root(0);
}

/// An operation journal that keeps few blobs once pruned.
fn destroy_journal_cfg(
    comptime C: type,
    comptime over_variable: bool,
    harness: *Harness,
) C.BackingConfig {
    if (over_variable) return .{
        .partition = "journal-interrupted-destroy",
        .items_per_section = 32,
        .codec_config = codec.unit_cfg(codec.Cfg(Op)),
        .cache_ref = &harness.journal_cache,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
    return .{
        .partition = "journal-interrupted-destroy",
        .items_per_blob = 32,
        .write_buffer = 1024,
        .replay_buffer = 1024,
        .cache_ref = &harness.journal_cache,
    };
}

/// One destroy of a twice-committed, pruned journal, stopped after `allowed` mutations.
fn interrupted_destroy_once(
    comptime F: type,
    comptime over_variable: bool,
    partitions: []const []const u8,
    allowed: u64,
) !Interrupted {
    const C = if (over_variable) variable.Journal(Op) else fixed.Journal(Op);
    const J = authenticated_journal.Journal(F, C, Sha256);
    var harness = try Harness.init();
    defer harness.deinit();
    // The Merkle node journal keeps few blobs once pruned, so destroy has few places to stop.
    harness.merkle_items_per_blob = 64;
    const empty = harness.storage.backend.audit();
    const storage = harness.storage.interface();
    const merkle_cfg = harness.merkle_cfg("interrupted-destroy");
    const journal_cfg = destroy_journal_cfg(C, over_variable, &harness);
    var ops: [102]Op = undefined;
    for (&ops, 0..) |*op, i| {
        op.* = if (i == 50 or i == 101) commit_op else create_operation(@intCast(i));
    }
    var journal = try J.init(gpa, storage, merkle_cfg, journal_cfg, is_commit, .forward_fold);
    const fresh_root = try journal.root(0);
    try commit_twice_around_prune(J, &journal, &ops);
    const bounds = journal.get_bounds();
    const root = try journal.root(0);
    try testing.expect(bounds.start > 0 and bounds.end == 102);
    // Destroy fails exactly when one of its mutations was refused.
    harness.storage.allow_mutations(allowed);
    const destroyed = if (journal.destroy()) true else |_| false;
    try testing.expectEqual(!destroyed, harness.storage.mutation_refused);
    harness.storage.mutations_allowed = null;
    harness.storage.mutation_refused = false;
    if (destroyed) {
        try testing.expectEqual(empty, harness.storage.backend.audit());
        return .completed;
    }
    // Removing its last partition ends the operation journal's removal.
    var journal_removed = true;
    for (partitions) |partition| {
        if (try partition_exists(&harness, partition)) journal_removed = false;
    }
    // The reopened journal is exactly the last commit or empty.
    journal = try J.init(gpa, storage, merkle_cfg, journal_cfg, is_commit, .forward_fold);
    const outcome: Interrupted = if (std.meta.eql(journal.get_bounds(), bounds)) outcome: {
        try testing.expect(!journal_removed);
        try testing.expect((try journal.root(0)).eql(root));
        for (bounds.start..bounds.end) |position| {
            try expect_op(ops[position], try journal.read(position));
        }
        break :outcome .unchanged;
    } else outcome: {
        try testing.expectEqual(0, journal.get_bounds().end);
        try testing.expect((try journal.root(0)).eql(fresh_root));
        // An emptied journal keeps nothing of its past: new commits reopen under their root.
        const reused = try commit_after_empty(J, &journal);
        journal.deinit();
        journal = try J.init(gpa, storage, merkle_cfg, journal_cfg, is_commit, .forward_fold);
        try testing.expectEqual(0, journal.get_bounds().start);
        try testing.expectEqual(41, journal.get_bounds().end);
        try testing.expect((try journal.root(0)).eql(reused));
        break :outcome if (journal_removed) .in_merkle else .in_journal;
    };
    // A retried destroy completes and leaves no blob behind.
    try journal.destroy();
    try testing.expectEqual(empty, harness.storage.backend.audit());
    return outcome;
}

/// Stops the destroy before its first mutation, then its second, and so on until one
/// completes, requiring every outcome in order (issue 5668).
fn interrupted_destroy_reopens(
    comptime F: type,
    comptime over_variable: bool,
    partitions: []const []const u8,
) !void {
    var outcomes: [256]Interrupted = undefined;
    var count: usize = 0;
    while (true) {
        try testing.expect(count < outcomes.len);
        outcomes[count] = try interrupted_destroy_once(F, over_variable, partitions, count);
        count += 1;
        if (outcomes[count - 1] == .completed) break;
    }
    // Nothing changes before the first mutation, and a later stop never reaches an earlier
    // outcome.
    try testing.expectEqual(Interrupted.unchanged, outcomes[0]);
    for (outcomes[1..count], outcomes[0 .. count - 1]) |later, earlier| {
        try testing.expect(@backingInt(later) >= @backingInt(earlier));
    }
    for ([_]Interrupted{ .unchanged, .in_journal, .in_merkle, .completed }) |outcome| {
        try testing.expect(std.mem.indexOfScalar(Interrupted, outcomes[0..count], outcome) != null);
    }
    // Destroy stages the journal's clear and removes each of its partitions, then the Merkle
    // metadata, node blobs, and checkpoint, so it can stop at least once before each.
    try testing.expect(count - 1 >= partitions.len + 4);
}

test "an interrupted destroy over a fixed journal reopens at its last commit or empty" {
    const partitions = [_][]const u8{
        "journal-interrupted-destroy-blobs",
        "journal-interrupted-destroy-metadata",
    };
    inline for (families) |F| try interrupted_destroy_reopens(F, false, &partitions);
}

test "an interrupted destroy over a variable journal reopens at its last commit or empty" {
    const partitions = [_][]const u8{
        "journal-interrupted-destroy_data",
        "journal-interrupted-destroy_offsets-blobs",
        "journal-interrupted-destroy_offsets-metadata",
    };
    inline for (families) |F| try interrupted_destroy_reopens(F, true, &partitions);
}
