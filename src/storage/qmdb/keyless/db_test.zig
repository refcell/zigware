//! Tests of the keyless database, ported from commonware's `qmdb/keyless/{mod,fixed}.rs`.
//! Every scenario runs under both families. Commonware's `drop(db)` is `deinit` here: it
//! closes without syncing, so only what `commit` or `sync` made durable survives the reopen.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const value = @import("../value.zig");
const verify = @import("../verify.zig");
const keyless = @import("mod.zig");
const qmdb = @import("../mod.zig");

const Sha256 = cryptography.Sha256;
const U64 = utils.sequence.U64;
const metrics = runtime.telemetry.metrics;
const qmdb_support = @import("../test_support.zig");
const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };

const Encoding = value.Fixed(U64);

fn TestDb(comptime F: type) type {
    const Journal = fixed.Journal(keyless.Operation(F, Encoding));
    return keyless.Db(F, Encoding, Journal, Sha256);
}

/// Whether `proof` authenticates `ops` at `start` under `root`.
fn verified(comptime F: type, proof: anytype, start: u64, ops: anytype, root: anytype) !bool {
    return verify.verify(F, Sha256, TestDb(F).Operation, gpa, proof, start, ops, root);
}

/// Commonware's `TestValue::make` for `U64`.
fn make(i: u64) U64 {
    return U64.init(i * 10 + 1);
}

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init() !Harness {
        return .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness, comptime F: type) TestDb(F).Cfg {
        return .{
            .merkle = .{
                .journal_partition = "fixed-journal-partition",
                .metadata_partition = "fixed-metadata-partition",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.cache_ref,
            },
            .log = .{
                .partition = "fixed-log-journal-partition",
                .items_per_blob = 7,
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
        };
    }

    fn open(self: *Harness, comptime F: type) !TestDb(F) {
        return self.open_at_most(F, null);
    }

    fn open_at_most(self: *Harness, comptime F: type, max_size: ?u64) !TestDb(F) {
        // Each open registers the metric set afresh, as commonware's fresh child contexts do.
        self.registry.deinit();
        self.registry = metrics.Registry.init(gpa);
        const scope = metrics.Scope.init(&self.registry).child("db");
        return TestDb(F).init(gpa, self.storage.interface(), scope, self.cfg(F), max_size);
    }
};

/// Appends `values` in one batch with `floor` (or the inherited floor), and applies it.
fn append_batch(comptime F: type, db: *TestDb(F), values: []const U64, floor: ?u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (values) |item| try batch.append(item);
        if (floor) |loc| batch.with_inactivity_floor(loc);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn append_range(comptime F: type, db: *TestDb(F), from: u64, to: u64) !void {
    var values: std.ArrayList(U64) = .empty;
    defer values.deinit(gpa);
    for (from..to) |i| try values.append(gpa, make(i));
    try append_batch(F, db, values.items, null);
}

test "keyless empty" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        try testing.expectEqual(merkle.Range{ .start = 0, .end = 1 }, db.bounds());
        try testing.expectEqual(@as(?U64, null), try db.get_metadata());
        const root = db.root();
        try testing.expect(root.eql(keyless.initial_root(F, Encoding, Sha256)));
        // An unapplied batch leaves no trace.
        var batch = try db.new_batch();
        try batch.append(make(1));
        batch.deinit();
        db.deinit();
        db = try harness.open(F);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(@as(u64, 1), db.bounds().end);
        // Committing an empty batch makes the db durably non-empty.
        var empty = try db.new_batch();
        empty.with_metadata(make(99));
        const merkleized = try empty.merkleize(&db);
        try db.apply_batch(merkleized);
        merkleized.release();
        try db.commit();
        try testing.expectEqual(@as(u64, 2), db.bounds().end);
        try testing.expectEqual(@as(?U64, make(99)), try db.get_metadata());
        try testing.expectEqual(@as(?U64, make(99)), try db.get(1));
        const committed = db.root();
        db.deinit();
        db = try harness.open(F);
        try testing.expectEqual(@as(u64, 2), db.bounds().end);
        try testing.expectEqual(@as(?U64, make(99)), try db.get_metadata());
        try testing.expect(db.root().eql(committed));
        try db.destroy();
    }
}

test "keyless build basic and recovery" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        var batch = try db.new_batch();
        try testing.expectEqual(@as(u64, 1), batch.size());
        try batch.append(make(1));
        try testing.expectEqual(@as(u64, 2), batch.size());
        try batch.append(make(2));
        const merkleized = try batch.merkleize(&db);
        try db.apply_batch(merkleized);
        merkleized.release();
        try testing.expectEqual(@as(u64, 4), db.bounds().end);
        try testing.expectEqual(@as(?U64, null), try db.get(3));
        const root = db.root();
        try db.sync();
        db.deinit();
        db = try harness.open(F);
        try testing.expectEqual(@as(u64, 4), db.bounds().end);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(@as(?U64, make(1)), try db.get(1));
        try testing.expectEqual(@as(?U64, make(2)), try db.get(2));
        // Appends never merkleized or applied leave no trace.
        var dropped = try db.new_batch();
        for (100..200) |i| try dropped.append(make(i));
        dropped.deinit();
        db.deinit();
        db = try harness.open(F);
        try testing.expect(db.root().eql(root));
        try append_range(F, &db, 300, 400);
        try db.commit();
        const committed = db.root();
        db.deinit();
        db = try harness.open(F);
        try testing.expectEqual(@as(u64, 4 + 101), db.bounds().end);
        try testing.expect(db.root().eql(committed));
        try db.destroy();
    }
}

test "keyless commit after sync recovery" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        try append_batch(F, &db, &.{make(10)}, null);
        try db.commit();
        try db.sync();
        const second = db.bounds().end;
        try append_batch(F, &db, &.{make(20)}, null);
        try db.commit();
        const bounds = db.bounds();
        const root = db.root();
        db.deinit();
        // A crash keeps the committed (durable) journal; the Merkle structure replays it.
        harness.storage.crash();
        db = try harness.open(F);
        try testing.expectEqual(bounds, db.bounds());
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(@as(?U64, make(10)), try db.get(1));
        try testing.expectEqual(@as(?U64, make(20)), try db.get(second));
        try db.destroy();
    }
}

test "keyless proof" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_range(F, &db, 0, 50);
        const root = db.root();
        var all = try db.proof(0, 100);
        defer all.deinit(gpa);
        try testing.expectEqual(@as(usize, 52), all.items.len);
        try testing.expect(try verified(F, &all.proof, 0, all.items, &root));
        var part = try db.proof(10, 5);
        defer part.deinit(gpa);
        try testing.expectEqual(@as(usize, 5), part.items.len);
        try testing.expect(try verified(F, &part.proof, 10, part.items, &root));
        // A proof does not verify at the wrong location.
        try testing.expect(!try verified(F, &part.proof, 11, part.items, &root));
    }
}

test "keyless metadata" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        var batch = try db.new_batch();
        try batch.append(make(1));
        batch.with_metadata(make(99));
        const merkleized = try batch.merkleize(&db);
        try db.apply_batch(merkleized);
        merkleized.release();
        try testing.expectEqual(@as(?U64, make(99)), try db.get_metadata());
        try append_batch(F, &db, &.{}, null);
        try testing.expectEqual(@as(?U64, null), try db.get_metadata());
    }
}

test "keyless pruning" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(1));
        try append_batch(F, &db, &.{ make(1), make(2) }, 3);
        try testing.expectEqual(@as(u64, 3), db.bounds().end - 1);
        try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
        try append_batch(F, &db, &.{make(3)}, 5);
        const root = db.root();
        try db.prune(3);
        try testing.expect(db.root().eql(root));
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(6));
    }
}

test "keyless get many" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_batch(F, &db, &.{ make(1), make(2) }, null);
        try db.commit();
        var out: [2]?U64 = undefined;
        try db.get_many(&.{ 1, 2 }, &out);
        try testing.expectEqual([2]?U64{ make(1), make(2) }, out);
        try db.get_many(&.{}, out[0..0]);
        try testing.expectError(error.LocationOutOfOrder, db.get_many(&.{ 2, 1 }, &out));
        try testing.expectError(error.LocationOutOfOrder, db.get_many(&.{ 1, 1 }, &out));
        const end = db.bounds().end;
        try testing.expectError(error.LocationOutOfBounds, db.get_many(&.{ 1, end }, &out));
        // Through an unmerkleized batch.
        var batch = try db.new_batch();
        defer batch.deinit();
        const loc3 = batch.size();
        try batch.append(make(3));
        try batch.get_many(&.{ 1, loc3 }, &db, &out);
        try testing.expectEqual([2]?U64{ make(1), make(3) }, out);
        const unordered = batch.get_many(&.{ loc3, 1 }, &db, &out);
        try testing.expectError(error.LocationOutOfOrder, unordered);
        const batch_end = batch.size();
        const past = batch.get_many(&.{ 1, batch_end }, &db, &out);
        try testing.expectError(error.LocationOutOfBounds, past);
        // Through a merkleized parent and its child.
        var parent_batch = try db.new_batch();
        const parent_loc = parent_batch.size();
        try parent_batch.append(make(3));
        const parent = try parent_batch.merkleize(&db);
        defer parent.release();
        try parent.get_many(&.{ 1, parent_loc }, &db, &out);
        try testing.expectEqual([2]?U64{ make(1), make(3) }, out);
        const tip = parent.bounds.tip.size;
        const past_tip = parent.get_many(&.{ 1, tip }, &db, &out);
        try testing.expectError(error.LocationOutOfBounds, past_tip);
        var child = parent.new_batch();
        defer child.deinit();
        try child.append(make(4));
        try child.get_many(&.{ 1, 2 }, &db, &out);
        try testing.expectEqual([2]?U64{ make(1), make(2) }, out);
    }
}

test "keyless chained batches apply in sequence" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        var parent_batch = try db.new_batch();
        try parent_batch.append(make(1));
        const parent = try parent_batch.merkleize(&db);
        defer parent.release();
        var child_batch = parent.new_batch();
        try child_batch.append(make(2));
        const child = try child_batch.merkleize(&db);
        defer child.release();
        // The child's reads see the parent's operations.
        try testing.expectEqual(@as(?U64, make(1)), try child.get(1, &db));
        try testing.expectEqual(@as(?U64, make(2)), try child.get(3, &db));
        try db.apply_batch(parent);
        try testing.expect(db.root().eql(parent.root()));
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try testing.expectEqual(@as(u64, 5), db.bounds().end);
        try testing.expectEqual(@as(?U64, make(2)), try db.get(3));
    }
}

test "keyless child applies with its unapplied parent" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        var parent_batch = try db.new_batch();
        try parent_batch.append(make(1));
        const parent = try parent_batch.merkleize(&db);
        var child_batch = parent.new_batch();
        try child_batch.append(make(2));
        const child = try child_batch.merkleize(&db);
        defer child.release();
        // Dropping the parent keeps its operations alive in the child.
        parent.release();
        try testing.expectEqual(@as(?U64, make(1)), try child.get(1, &db));
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try testing.expectEqual(@as(?U64, make(1)), try db.get(1));
        try testing.expectEqual(@as(?U64, make(2)), try db.get(3));
    }
}

test "keyless stale batch" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        var a_batch = try db.new_batch();
        try a_batch.append(make(1));
        const a = try a_batch.merkleize(&db);
        defer a.release();
        var b_batch = try db.new_batch();
        try b_batch.append(make(2));
        const b = try b_batch.merkleize(&db);
        defer b.release();
        try db.apply_batch(a);
        // The sibling was built on the state `a` replaced.
        try testing.expectError(error.StaleBatch, db.apply_batch(b));
        try testing.expectError(error.StaleRead, b.get(1, &db));
        // Applying the same batch twice is stale too.
        try testing.expectError(error.StaleBatch, db.apply_batch(a));
    }
}

test "keyless floor regression and beyond-commit floors are rejected" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_batch(F, &db, &.{ make(1), make(2) }, 2);
        var regressed = try db.new_batch();
        defer regressed.deinit();
        regressed.with_inactivity_floor(1);
        try testing.expectError(error.FloorRegressed, regressed.merkleize(&db));
        var beyond = try db.new_batch();
        defer beyond.deinit();
        try beyond.append(make(3));
        // The commit lands at 5, so 6 is past it while 5 is accepted.
        beyond.with_inactivity_floor(6);
        try testing.expectError(error.FloorBeyondCommit, beyond.merkleize(&db));
        try append_batch(F, &db, &.{make(3)}, 5);
        try testing.expectEqual(@as(u64, 5), db.inactivity_floor());
    }
}

test "keyless reads below the floor are refused" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_batch(F, &db, &.{ make(1), make(2) }, 2);
        var batch = try db.new_batch();
        defer batch.deinit();
        try testing.expectError(error.BelowInactivityFloor, batch.get(1, &db));
        try testing.expectEqual(@as(?U64, make(2)), try batch.get(2, &db));
        // The database itself still serves retained locations below the floor.
        try testing.expectEqual(@as(?U64, make(1)), try db.get(1));
    }
}

test "keyless bounded initialization recovers an earlier commit" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        try append_batch(F, &db, &.{ make(1), make(2) }, null);
        const first_root = db.root();
        const first_end = db.bounds().end;
        try append_batch(F, &db, &.{ make(3), make(4) }, null);
        try db.sync();
        db.deinit();
        try testing.expectError(error.InvalidInitializationBound, harness.open_at_most(F, 0));
        // A bound inside the second batch selects the first batch's commit.
        db = try harness.open_at_most(F, first_end + 1);
        try testing.expectEqual(first_end, db.bounds().end);
        try testing.expect(db.root().eql(first_root));
        try db.destroy();
    }
}

test "keyless speculative proof matches the applied log" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        const Db = TestDb(F);
        var batch = try db.new_batch();
        try batch.append(make(1));
        try batch.append(make(2));
        const seed = try batch.merkleize(&db);
        defer seed.release();
        const start, const ops = seed.operations();
        try testing.expectEqual(@as(usize, 3), ops.len);
        var proof = try seed.proof(&db);
        defer proof.deinit(gpa);
        var pins_buffer: [merkle.max_pinned_nodes]Db.Digest = undefined;
        const pins = try seed.pinned_nodes(&db, &pins_buffer);
        const root = seed.root();
        try testing.expect(try verified(F, &proof, start, ops, &root));
        const with_pins = verify.verify_with_pinned_nodes;
        const Op = Db.Operation;
        try testing.expect(try with_pins(F, Sha256, Op, gpa, &proof, start, ops, pins, &root));
        try db.apply_batch(seed);
        var logged = try db.historical_proof(start + ops.len, start, ops.len);
        defer logged.deinit(gpa);
        try testing.expect(logged.proof.eql(&proof));
        for (logged.items, ops) |a, b| try testing.expect(a.eql(b));
    }
}

test "keyless chained floor regression and beyond-commit floors are rejected" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        var parent_batch = try db.new_batch();
        try parent_batch.append(make(1));
        try parent_batch.append(make(2));
        parent_batch.with_inactivity_floor(2);
        const parent = try parent_batch.merkleize(&db);
        defer parent.release();
        // A child inherits its parent's floor, not the database's.
        var regressed = parent.new_batch();
        defer regressed.deinit();
        try testing.expectEqual(@as(u64, 2), regressed.inactivity_floor);
        regressed.with_inactivity_floor(1);
        try testing.expectError(error.FloorRegressed, regressed.merkleize(&db));
        // The child's commit lands at 4.
        var beyond = parent.new_batch();
        defer beyond.deinit();
        beyond.with_inactivity_floor(5);
        try testing.expectError(error.FloorBeyondCommit, beyond.merkleize(&db));
        var valid = parent.new_batch();
        valid.with_inactivity_floor(4);
        const child = try valid.merkleize(&db);
        defer child.release();
        try db.apply_batch(child);
        try testing.expectEqual(@as(u64, 4), db.inactivity_floor());
        try testing.expect(db.root().eql(child.root()));
    }
}

test "keyless init_from_log builds over an opened log and refuses an empty one" {
    inline for (families) |F| {
        const Db = TestDb(F);
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.cfg(F);
        const storage = harness.storage.interface();
        const scope = metrics.Scope.init(&harness.registry).child("db");
        const empty = try qmdb.init_journal(Db.Journal, gpa, storage, cfg.merkle, cfg.log, .{});
        const refused = Db.init_from_log(gpa, scope, empty);
        try testing.expectError(error.HistoricalFloorPruned, refused);
        var db = try harness.open(F);
        errdefer db.deinit();
        try append_batch(F, &db, &.{ make(1), make(2) }, 2);
        try db.sync();
        const root = db.root();
        db.deinit();
        const log = try qmdb.init_journal(Db.Journal, gpa, storage, cfg.merkle, cfg.log, .{});
        harness.registry.deinit();
        harness.registry = metrics.Registry.init(gpa);
        const reopened = metrics.Scope.init(&harness.registry).child("db");
        db = try Db.init_from_log(gpa, reopened, log);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        try testing.expectEqual(@as(?U64, make(2)), try db.get(2));
        try db.destroy();
    }
}

/// Commonware's unclean `drop(db)` and reopen: the storage loses what was not synced.
fn crash_reopen(comptime F: type, harness: *Harness, db: *TestDb(F)) !void {
    harness.storage.crash();
    db.deinit();
    db.* = try harness.open(F);
}

/// Appends `count` values from `make(first)` to a batch and drops it unapplied (a failed
/// commit).
fn abandon_appends(comptime F: type, db: *TestDb(F), first: u64, count: u64) !void {
    var batch = try db.new_batch();
    defer batch.deinit();
    for (first..first + count) |i| try batch.append(make(i));
    assert(batch.size() == db.bounds().end + count);
}

test "keyless empty database recovers from failed commits" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        const root = db.root();
        const elements: u64 = 200;
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(@as(u64, 1), db.bounds().end);
        try testing.expect(db.root().eql(root));
        for ([_]u64{ 0, 500, 1000 }, [_]u64{ 1, 1, 3 }) |first, batches| {
            try abandon_appends(F, &db, first, elements * batches);
            try crash_reopen(F, &harness, &db);
            try testing.expectEqual(@as(u64, 1), db.bounds().end);
            try testing.expect(db.root().eql(root));
        }
        try append_range(F, &db, 2000, 2000 + elements);
        try db.commit();
        try crash_reopen(F, &harness, &db);
        try testing.expect(db.bounds().end > 1);
        try testing.expect(!db.root().eql(root));
        try db.destroy();
    }
}

test "keyless replay drops trailing unapplied appends" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        try append_range(F, &db, 0, 10);
        try db.commit();
        const committed_root = db.root();
        const committed_size = db.bounds().end;
        try abandon_appends(F, &db, 99, 1);
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(committed_size, db.bounds().end);
        try testing.expect(db.root().eql(committed_root));
        // Appends resume at the recovered end.
        var batch = try db.new_batch();
        try testing.expectEqual(committed_size, batch.size());
        batch.deinit();
        try append_batch(F, &db, &.{make(77)}, null);
        try db.commit();
        try testing.expectEqual(make(77), (try db.get(committed_size)).?);
        const new_root = db.root();
        const new_size = db.bounds().end;
        try abandon_appends(F, &db, 200, 5);
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(new_size, db.bounds().end);
        try testing.expect(db.root().eql(new_root));
        try db.destroy();
    }
}

test "keyless non-empty database recovers from failed commits, also after pruning" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        const elements: u64 = 200;
        // The floor advances to the new commit, so history may later be pruned up to it.
        var values: [elements]U64 = undefined;
        for (&values, 0..) |*item, i| item.* = make(i);
        try append_batch(F, &db, &values, db.bounds().end + elements);
        try db.commit();
        const root = db.root();
        const op_count = db.bounds().end;
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(op_count, db.bounds().end);
        try testing.expect(db.root().eql(root));
        try abandon_appends(F, &db, 1000, elements);
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(op_count, db.bounds().end);
        try testing.expect(db.root().eql(root));
        try db.prune(db.bounds().end - 1);
        try testing.expectEqual(op_count, db.bounds().end);
        try testing.expect(db.root().eql(root));
        try db.sync();
        try abandon_appends(F, &db, 2000, elements);
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(op_count, db.bounds().end);
        try testing.expect(db.root().eql(root));
        try append_range(F, &db, 3000, 3000 + elements);
        try db.commit();
        try crash_reopen(F, &harness, &db);
        try testing.expect(db.bounds().end > op_count);
        try testing.expect(!db.root().eql(root));
        try db.destroy();
    }
}

/// Commonware's `commit_appends`: appends `count` values from `make(first)` with the floor
/// at the new commit, applies them, and commits.
fn commit_appends(comptime F: type, db: *TestDb(F), first: u64, count: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (first..first + count) |i| try batch.append(make(i));
        batch.with_inactivity_floor(db.bounds().end + count);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    try db.commit();
}

test "keyless proofs over many ranges verify only where they belong" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        const elements: u64 = 100;
        try append_range(F, &db, 0, elements);
        const past_end = db.historical_proof(db.bounds().end + 1, 5, 10);
        try testing.expectError(error.RangeOutOfBounds, past_end);
        const root = db.root();
        const wrong_root = Sha256.hash(&.{&@as([32]u8, @splat(0xFF))});
        const Range = struct { u64, u64 };
        const ranges = [_]Range{
            .{ 0, 10 }, .{ 10, 5 },           .{ 50, 20 },      .{ 90, 15 },
            .{ 0, 1 },  .{ elements - 1, 1 }, .{ elements, 1 },
        };
        for (ranges) |range| {
            const start, const max_ops = range;
            var proved = try db.proof(start, max_ops);
            defer proved.deinit(gpa);
            const proof = &proved.proof;
            try testing.expect(try verified(F, proof, start, proved.items, &root));
            const expected = @min(max_ops, db.bounds().end - start);
            try testing.expectEqual(expected, proved.items.len);
            try testing.expect(!try verified(F, proof, start, proved.items, &wrong_root));
            if (start > 0) {
                try testing.expect(!try verified(F, proof, start - 1, proved.items, &root));
            }
        }
    }
}

test "keyless proofs verify after pruning and reopening" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        const elements: u64 = 100;
        var values: [elements]U64 = undefined;
        for (0..2) |round| {
            for (&values, 0..) |*item, i| item.* = make(round * elements + i);
            try append_batch(F, &db, &values, db.bounds().end + elements);
        }
        const root = db.root();
        try db.prune(30);
        const oldest_retained = db.bounds().start;
        try testing.expect(db.root().eql(root));
        try db.sync();
        db.deinit();
        db = try harness.open(F);
        try testing.expect(db.root().eql(root));
        const Range = struct { u64, u64 };
        const ranges = [_]Range{
            .{ oldest_retained, 10 }, .{ 50, 20 }, .{ 150, 10 }, .{ 190, 15 },
        };
        for (ranges) |range| {
            const start, const max_ops = range;
            if (start < oldest_retained) continue;
            var proved = try db.proof(start, max_ops);
            defer proved.deinit(gpa);
            try testing.expect(try verified(F, &proved.proof, start, proved.items, &root));
        }
        for ([_]u64{ 150, db.bounds().end - 5 }) |prune_to| {
            try db.prune(prune_to);
            const oldest = db.bounds().start;
            var proved = try db.proof(oldest, 20);
            defer proved.deinit(gpa);
            try testing.expect(try verified(F, &proved.proof, oldest, proved.items, &root));
        }
        try db.destroy();
    }
}

test "keyless reads past the end are empty or out of bounds" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        // Location 0 is the initial commit, which holds no value.
        try testing.expectEqual(@as(?U64, null), try db.get(0));
        try append_batch(F, &db, &.{ make(1), make(2) }, null);
        try testing.expectEqual(make(1), (try db.get(1)).?);
        try testing.expectEqual(@as(?U64, null), try db.get(3));
        try testing.expectError(error.LocationOutOfBounds, db.get(4));
    }
}

test "keyless reads below the pruning boundary fail" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        var round: u64 = 0;
        while (db.bounds().start == 0) {
            round += 1;
            try testing.expect(round <= 64);
            try commit_appends(F, &db, round * 100, 16);
            try db.prune(db.bounds().end - 1);
        }
        const start = db.bounds().start;
        var out: [2]?U64 = undefined;
        try testing.expectError(error.ItemPruned, db.get(start - 1));
        try testing.expectError(error.ItemPruned, db.get_many(&.{ start - 1, start }, &out));
        _ = try db.get(start);
        try db.get_many(&.{start}, out[0..1]);
    }
}

test "keyless bounded initialization at a pruned target fails" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        const first_start = db.bounds().end;
        try commit_appends(F, &db, 0, 16);
        var round: u64 = 0;
        while (db.bounds().start <= first_start) {
            round += 1;
            try testing.expect(round <= 64);
            try commit_appends(F, &db, round * 100, 16);
            try db.prune(db.bounds().end - 1);
        }
        const oldest_retained = db.bounds().start;
        db.deinit();
        try testing.expectError(error.ItemPruned, harness.open_at_most(F, oldest_retained));
        db = try harness.open(F);
        db.deinit();
        try testing.expectError(error.ItemPruned, harness.open_at_most(F, first_start));
        db = try harness.open(F);
        try db.destroy();
    }
}

/// Commits two batches of two appends with floors 3 and 6, and returns the size after the first.
fn commit_two_floors(comptime F: type, db: *TestDb(F)) !u64 {
    try append_batch(F, db, &.{ make(1), make(2) }, 3);
    try db.commit();
    const bound = db.bounds().end;
    try append_batch(F, db, &.{ make(3), make(4) }, 6);
    try db.commit();
    try testing.expectEqual(@as(u64, 6), db.inactivity_floor());
    return bound;
}

test "keyless bounded initialization restores the earlier floor and gates pruning" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        const bound = try commit_two_floors(F, &db);
        db.deinit();
        db = try harness.open_at_most(F, bound);
        try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
        try db.prune(3);
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(4));
        try db.destroy();
    }
}

test "keyless bounded initialization after a reopen is durable" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        const bound = try commit_two_floors(F, &db);
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(@as(u64, 6), db.inactivity_floor());
        db.deinit();
        db = try harness.open_at_most(F, bound);
        try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
        try testing.expectEqual(@as(u64, 3), db.bounds().end - 1);
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
        try db.destroy();
    }
}

/// Merkleizes a batch appending `values` on `parent` (or on `db` if null), with `floor`.
fn merkleize_values(
    comptime D: type,
    db: *D,
    parent: ?*D.MerkleizedBatch,
    values: []const U64,
    floor: ?u64,
) !*D.MerkleizedBatch {
    var batch = if (parent) |p| p.new_batch() else try db.new_batch();
    errdefer batch.deinit();
    for (values) |item| try batch.append(item);
    if (floor) |loc| batch.with_inactivity_floor(loc);
    return batch.merkleize(db);
}

/// A child of `parent` appending `make(200..280)`.
fn build_child(comptime F: type, parent: *TestDb(F).MerkleizedBatch) !TestDb(F).UnmerkleizedBatch {
    var child = parent.new_batch();
    errdefer child.deinit();
    for (200..280) |i| try child.append(make(i));
    assert(child.size() == parent.bounds.tip.size + 80);
    return child;
}

test "keyless a child merkleized across a prune keeps its root" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        try append_range(F, &db, 0, 80);
        try db.commit();
        const floor = db.bounds().end + 1;
        const parent = try merkleize_values(TestDb(F), &db, null, &.{make(100)}, floor);
        defer parent.release();
        var child = try build_child(F, parent);
        defer child.deinit();
        var twin = try build_child(F, parent);
        const expected = expected: {
            errdefer twin.deinit();
            break :expected try twin.merkleize(&db);
        };
        defer expected.release();
        try db.apply_batch(parent);
        try db.commit();
        try db.prune(db.inactivity_floor());
        try testing.expect(db.bounds().start > 0);
        const merkleized = try child.merkleize(&db);
        child = try db.new_batch(); // `merkleize` consumed it; the deferred deinit frees this.
        defer merkleized.release();
        try testing.expect(merkleized.root().eql(expected.root()));
        try db.destroy();
    }
}

test "keyless batches of a losing fork are stale" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_batch(F, &db, &.{make(0)}, null);
        try db.commit();
        const winner = try merkleize_values(TestDb(F), &db, null, &.{make(1)}, null);
        defer winner.release();
        const loser = try merkleize_values(TestDb(F), &db, null, &.{make(2)}, null);
        defer loser.release();
        try testing.expectEqual(winner.bounds.tip.size, loser.bounds.tip.size);
        try testing.expect(!winner.root().eql(loser.root()));
        var child = loser.new_batch();
        defer child.deinit();
        try child.append(make(3));
        var direct = try db.new_batch();
        defer direct.deinit();
        try direct.append(make(4));
        try db.apply_batch(winner);
        var out: [2]?U64 = undefined;
        try testing.expectError(error.StaleRead, direct.get(0, &db));
        try testing.expectError(error.StaleRead, direct.get_many(&.{0}, &db, out[0..1]));
        try testing.expectError(error.StaleRead, child.get(0, &db));
        try testing.expectError(error.StaleRead, child.get_many(&.{0}, &db, out[0..1]));
        try testing.expectError(error.StaleRead, loser.get(0, &db));
        try testing.expectError(error.StaleRead, child.get_many(&.{}, &db, out[0..0]));
        try testing.expectError(error.StaleRead, loser.get_many(&.{}, &db, out[0..0]));
        try testing.expectError(error.StaleRead, child.get(child.size(), &db));
        try testing.expectError(error.StaleRead, loser.get(loser.bounds.tip.size, &db));
        try testing.expectError(error.StaleRead, child.get_many(&.{ 1, 0 }, &db, &out));
        try testing.expectError(error.StaleBatch, child.merkleize(&db));
        try testing.expectError(error.StaleBatch, db.validate_batch(loser));
    }
}

test "keyless applying a descendant makes its parent's reads stale" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        const parent = try merkleize_values(TestDb(F), &db, null, &.{make(1)}, null);
        defer parent.release();
        try testing.expectEqual(make(1), (try parent.get(1, &db)).?);
        const child = try merkleize_values(TestDb(F), &db, parent, &.{make(2)}, null);
        defer child.release();
        try db.apply_batch(child);
        try testing.expectEqual(make(1), (try child.get(1, &db)).?);
        var out: [1]?U64 = undefined;
        try testing.expectError(error.StaleRead, parent.get(1, &db));
        try testing.expectError(error.StaleRead, parent.get_many(&.{1}, &db, &out));
    }
}

test "keyless batches refuse to merkleize against another database" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var other = try Harness.init();
        defer other.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        var foreign = try other.open(F);
        defer foreign.deinit();
        try append_batch(F, &db, &.{make(11)}, null);
        try append_batch(F, &foreign, &.{make(99)}, null);
        try testing.expectEqual(db.bounds().end, foreign.bounds().end);
        try testing.expect(!db.root().eql(foreign.root()));
        var batch = try db.new_batch();
        defer batch.deinit();
        try batch.append(make(22));
        try testing.expectError(error.StaleBatch, batch.merkleize(&foreign));
        const parent = try merkleize_values(TestDb(F), &db, null, &.{make(33)}, null);
        defer parent.release();
        var child = parent.new_batch();
        defer child.deinit();
        try child.append(make(44));
        try testing.expectError(error.StaleBatch, child.merkleize(&foreign));
    }
}

test "keyless batches whose sibling applied refuse to merkleize" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        var direct = try db.new_batch();
        defer direct.deinit();
        try direct.append(make(11));
        const sibling = try merkleize_values(TestDb(F), &db, null, &.{make(22)}, null);
        defer sibling.release();
        try db.apply_batch(sibling);
        try testing.expectError(error.StaleBatch, direct.merkleize(&db));
        const parent = try merkleize_values(TestDb(F), &db, null, &.{make(33)}, null);
        defer parent.release();
        var child = parent.new_batch();
        defer child.deinit();
        try child.append(make(44));
        const other = try merkleize_values(TestDb(F), &db, null, &.{make(55)}, null);
        defer other.release();
        try db.apply_batch(other);
        try testing.expectError(error.StaleBatch, child.merkleize(&db));
    }
}

test "keyless a child's root is the same whatever its ancestors' states" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        const grandparent = try merkleize_values(TestDb(F), &db, null, &.{make(1)}, null);
        var grandparent_held = true;
        defer if (grandparent_held) grandparent.release();
        const parent = try merkleize_values(TestDb(F), &db, grandparent, &.{make(2)}, null);
        defer parent.release();
        const pending = try merkleize_values(TestDb(F), &db, parent, &.{make(3)}, null);
        defer pending.release();
        // The grandparent applied, then released.
        try db.apply_batch(grandparent);
        const applied = try merkleize_values(TestDb(F), &db, parent, &.{make(3)}, null);
        defer applied.release();
        try testing.expect(pending.root().eql(applied.root()));
        grandparent.release();
        grandparent_held = false;
        const retired = try merkleize_values(TestDb(F), &db, parent, &.{make(3)}, null);
        defer retired.release();
        try testing.expect(retired.bounds.db.eql(db.commitment()));
        try testing.expect(pending.root().eql(retired.root()));
        // A child built before its parent applied, merkleized after.
        var child_batch = parent.new_batch();
        try child_batch.append(make(3));
        try db.apply_batch(parent);
        const child = child: {
            errdefer child_batch.deinit();
            break :child try child_batch.merkleize(&db);
        };
        defer child.release();
        try testing.expect(pending.root().eql(child.root()));
        try db.apply_batch(child);
        var proved = try db.proof(0, 100);
        defer proved.deinit(gpa);
        const root = db.root();
        try testing.expect(try verified(F, &proved.proof, 0, proved.items, &root));
        try db.destroy();
    }
}

test "keyless chain reads survive dropped ancestors" {
    inline for (families) |F| {
        const D = TestDb(F);
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_batch(F, &db, &.{make(0)}, null);
        const base_a = db.bounds().end;
        const a = try merkleize_values(D, &db, null, &.{ make(1), make(2) }, null);
        var a_held = true;
        defer if (a_held) a.release();
        const base_b = a.bounds.tip.size;
        const b = try merkleize_values(D, &db, a, &.{ make(3), make(4) }, null);
        var b_held = true;
        defer if (b_held) b.release();
        const base_c = b.bounds.tip.size;
        const c = try merkleize_values(D, &db, b, &.{make(5)}, null);
        defer c.release();
        var child = c.new_batch();
        defer child.deinit();
        a.release();
        a_held = false;
        b.release();
        b_held = false;
        // Values of all three levels resolve from the items the chain retains.
        const locations = [_]u64{ base_a, base_a + 1, base_b, base_b + 1, base_c };
        var out: [5]?U64 = undefined;
        for (locations, 1..) |location, i| {
            try testing.expectEqual(make(i), (try c.get(location, &db)).?);
            try testing.expectEqual(make(i), (try child.get(location, &db)).?);
        }
        try c.get_many(&locations, &db, &out);
        for (out, 1..) |got, i| try testing.expectEqual(make(i), got.?);
        try child.get_many(&locations, &db, &out);
        for (out, 1..) |got, i| try testing.expectEqual(make(i), got.?);
        // The child's dropped ancestors are unapplied, so it cannot merkleize.
        try testing.expectError(error.StaleBatch, child.merkleize(&db));
        try db.apply_batch(c);
        for (locations, 1..) |location, i| {
            try testing.expectEqual(make(i), (try db.get(location)).?);
        }
    }
}

test "keyless batch reads end at the batch's size" {
    inline for (families) |F| {
        const D = TestDb(F);
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        const base = db.bounds().end;
        try append_batch(F, &db, &.{ make(10), make(11), make(12) }, null);
        var batch = try db.new_batch();
        defer batch.deinit();
        for (0..3) |i| try testing.expectEqual(make(10 + i), (try batch.get(base + i, &db)).?);
        const new_location = batch.size();
        try batch.append(make(99));
        try testing.expectEqual(make(99), (try batch.get(new_location, &db)).?);
        const end = new_location + 1;
        var out: [2]?U64 = undefined;
        try testing.expectError(error.LocationOutOfBounds, batch.get(end, &db));
        const past = batch.get_many(&.{ base, end }, &db, &out);
        try testing.expectError(error.LocationOutOfBounds, past);
        // A stacked child reads its parent's appends, and its own end bounds it.
        const parent = try merkleize_values(D, &db, null, &.{make(1)}, null);
        defer parent.release();
        var child = parent.new_batch();
        defer child.deinit();
        try testing.expectEqual(make(1), (try child.get(db.bounds().end, &db)).?);
        const child_location = child.size();
        try child.append(make(2));
        try testing.expectEqual(make(2), (try child.get(child_location, &db)).?);
        try testing.expectError(error.LocationOutOfBounds, child.get(9999, &db));
    }
}

test "keyless merkleized chain reads end at each batch's tip" {
    inline for (families) |F| {
        const D = TestDb(F);
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_batch(F, &db, &.{make(10)}, null);
        const loc1 = db.bounds().end;
        const parent = try merkleize_values(D, &db, null, &.{make(1)}, null);
        defer parent.release();
        const loc2 = parent.bounds.tip.size;
        const child = try merkleize_values(D, &db, parent, &.{make(2)}, null);
        defer child.release();
        try testing.expectEqual(make(10), (try child.get(1, &db)).?);
        try testing.expectEqual(make(1), (try child.get(loc1, &db)).?);
        try testing.expectEqual(make(2), (try child.get(loc2, &db)).?);
        const child_end = child.bounds.tip.size;
        try testing.expectError(error.LocationOutOfBounds, child.get(child_end, &db));
        // An ancestor's view ends at its own tip.
        try testing.expectError(error.LocationOutOfBounds, parent.get(loc2, &db));
        // Applying the descendant moves the database off the ancestor's states.
        try db.apply_batch(child);
        try testing.expectEqual(make(2), (try db.get(loc2)).?);
        try testing.expectError(error.StaleRead, parent.get(loc1, &db));
    }
}

test "keyless empty and large batches apply their speculative roots" {
    inline for (families) |F| {
        const D = TestDb(F);
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_batch(F, &db, &.{make(1)}, null);
        // A batch with no appends still adds its commit.
        const root_before = db.root();
        const size_before = db.bounds().end;
        const empty = try merkleize_values(D, &db, null, &.{}, null);
        defer empty.release();
        try db.apply_batch(empty);
        try testing.expect(!db.root().eql(root_before));
        try testing.expect(db.root().eql(empty.root()));
        try testing.expectEqual(size_before + 1, db.bounds().end);
        const n: u64 = 500;
        const first = db.bounds().end;
        try append_range(F, &db, 0, n);
        for (0..n) |i| try testing.expectEqual(make(i), (try db.get(first + i)).?);
        const root = db.root();
        var proved = try db.proof(0, 1000);
        defer proved.deinit(gpa);
        try testing.expect(try verified(F, &proved.proof, 0, proved.items, &root));
        try testing.expectEqual(first + n + 1, db.bounds().end);
    }
}

test "keyless descendants of a stale fork are stale, and a child may not precede its parent" {
    inline for (families) |F| {
        const D = TestDb(F);
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        const common = try merkleize_values(D, &db, null, &.{make(10)}, null);
        defer common.release();
        const sibling_a = try merkleize_values(D, &db, common, &.{make(11)}, null);
        defer sibling_a.release();
        const sibling_b = try merkleize_values(D, &db, common, &.{make(12)}, null);
        defer sibling_b.release();
        try db.apply_batch(sibling_a);
        try testing.expectError(error.StaleBatch, db.validate_batch(sibling_b));
        const parent_a = try merkleize_values(D, &db, null, &.{make(1)}, null);
        defer parent_a.release();
        const parent_b = try merkleize_values(D, &db, null, &.{make(2)}, null);
        defer parent_b.release();
        const child_b = try merkleize_values(D, &db, parent_b, &.{make(3)}, null);
        defer child_b.release();
        try db.apply_batch(parent_a);
        try testing.expectError(error.StaleBatch, db.validate_batch(child_b));
        // A child applied before its parent leaves the parent stale.
        const parent = try merkleize_values(D, &db, null, &.{make(4)}, null);
        defer parent.release();
        const child = try merkleize_values(D, &db, parent, &.{make(5)}, null);
        defer child.release();
        try db.apply_batch(child);
        try testing.expectError(error.StaleBatch, db.apply_batch(parent));
    }
}

test "keyless a pending child's root matches the child rebuilt after its parent commits" {
    inline for (families) |F| {
        const D = TestDb(F);
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        const parent = try merkleize_values(D, &db, null, &.{make(1)}, null);
        defer parent.release();
        const pending = try merkleize_values(D, &db, parent, &.{make(2)}, null);
        defer pending.release();
        try db.apply_batch(parent);
        try db.commit();
        const committed = try merkleize_values(D, &db, null, &.{make(2)}, null);
        defer committed.release();
        try testing.expect(pending.root().eql(committed.root()));
    }
}

test "keyless floors track across commits and reopens" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
        try append_batch(F, &db, &.{ make(1), make(2) }, 2);
        try db.commit();
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        try crash_reopen(F, &harness, &db);
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        // A floor may stay put, then advance.
        try append_batch(F, &db, &.{make(3)}, 2);
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        try append_batch(F, &db, &.{make(4)}, 5);
        try testing.expectEqual(@as(u64, 5), db.inactivity_floor());
        try db.destroy();
    }
}

test "keyless the floor is part of the root, and may reach the commit" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var other = try Harness.init();
        defer other.deinit();
        var db_a = try harness.open(F);
        defer db_a.deinit();
        var db_b = try other.open(F);
        defer db_b.deinit();
        try append_batch(F, &db_a, &.{ make(1), make(2) }, null);
        // Location 3 is the commit's own: the largest floor the commit accepts.
        try append_batch(F, &db_b, &.{ make(1), make(2) }, 3);
        try testing.expectEqual(@as(u64, 3), db_b.inactivity_floor());
        try testing.expect(!db_a.root().eql(db_b.root()));
    }
}

test "keyless a single live commit survives pruning and reopening" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        const metadata = make(42);
        const commit_location: u64 = 4;
        var batch = try db.new_batch();
        for (1..4) |i| try batch.append(make(i));
        batch.with_metadata(metadata);
        batch.with_inactivity_floor(commit_location);
        const merkleized = merkleized: {
            errdefer batch.deinit();
            break :merkleized try batch.merkleize(&db);
        };
        defer merkleized.release();
        try db.apply_batch(merkleized);
        try db.commit();
        try testing.expectEqual(commit_location, db.inactivity_floor());
        const root = db.root();
        // Pruning is blob-aligned, so the start may stay below the floor.
        try db.prune(commit_location);
        try testing.expect(db.bounds().start <= commit_location);
        try testing.expectEqual(commit_location + 1, db.bounds().end);
        try testing.expectEqual(metadata, (try db.get(commit_location)).?);
        try testing.expectEqual(metadata, (try db.get_metadata()).?);
        try testing.expect(db.root().eql(root));
        try db.sync();
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(commit_location + 1));
        db.deinit();
        db = try harness.open(F);
        try testing.expectEqual(commit_location + 1, db.bounds().end);
        try testing.expectEqual(commit_location, db.inactivity_floor());
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(metadata, (try db.get_metadata()).?);
        try append_batch(F, &db, &.{ make(5), make(6) }, 7);
        try db.commit();
        try testing.expectEqual(@as(u64, 7), db.bounds().end - 1);
        try testing.expectEqual(@as(u64, 7), db.inactivity_floor());
        try testing.expectEqual(make(5), (try db.get(5)).?);
        try testing.expectEqual(make(6), (try db.get(6)).?);
        try testing.expectEqual(metadata, (try db.get(commit_location)).?);
        try db.destroy();
    }
}

test "keyless a chain with rising floors applies through its tip" {
    inline for (families) |F| {
        const D = TestDb(F);
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        const parent = try merkleize_values(D, &db, null, &.{make(1)}, 2);
        defer parent.release();
        const child = try merkleize_values(D, &db, parent, &.{make(2)}, 3);
        defer child.release();
        const grandchild = try merkleize_values(D, &db, child, &.{make(3)}, 5);
        defer grandchild.release();
        try db.apply_batch(grandchild);
        try testing.expectEqual(@as(u64, 6), db.bounds().end - 1);
        try testing.expectEqual(@as(u64, 5), db.inactivity_floor());
    }
}

// Commonware's keyless/fixed.rs test_keyless_fixed_metrics: the gauges, call counters, and
// duration histograms after one of each operation, timed on the config's `io`.
test "keyless metrics count and time each operation" {
    const F = merkle.mmr.Family;
    var harness = try Harness.init();
    defer harness.deinit();
    var cfg = harness.cfg(F);
    cfg.io = testing.io;
    const scope = metrics.Scope.init(&harness.registry).child("db");
    var db = try TestDb(F).init(gpa, harness.storage.interface(), scope, cfg, null);
    defer db.deinit();
    const location = db.bounds().end;
    try append_batch(F, &db, &.{U64.init(7)}, null);
    try testing.expect((try db.get(location)).?.eql(U64.init(7)));
    var many: [1]?U64 = undefined;
    try db.get_many(&.{location}, &many);
    try testing.expect(many[0].?.eql(U64.init(7)));
    try db.commit();
    try db.sync();
    try (try db.start_sync()).wait_release();
    try db.prune(0);
    try qmdb_support.expect_metric_values(gpa, &harness.registry, &.{
        .{ "db_size", "3" },                       .{ "db_pruning_boundary", "0" },
        .{ "db_retained", "3" },                   .{ "db_inactivity_floor", "0" },
        .{ "db_last_commit", "2" },                .{ "db_get_calls_total", "1" },
        .{ "db_get_many_calls_total", "1" },       .{ "db_lookups_requested_total", "2" },
        .{ "db_apply_batch_calls_total", "1" },    .{ "db_operations_applied_total", "2" },
        .{ "db_commit_calls_total", "1" },         .{ "db_sync_calls_total", "1" },
        .{ "db_start_sync_calls_total", "1" },     .{ "db_prune_calls_total", "1" },
        .{ "db_get_duration_count", "1" },         .{ "db_get_many_duration_count", "1" },
        .{ "db_apply_batch_duration_count", "1" }, .{ "db_commit_duration_count", "1" },
        .{ "db_sync_duration_count", "1" },        .{ "db_prune_duration_count", "1" },
    });
}
