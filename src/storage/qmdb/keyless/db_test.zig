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
