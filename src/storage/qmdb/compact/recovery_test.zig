//! Crash-point and tampered-witness tests of the compact db, ported from commonware's
//! `qmdb/compact/db.rs`: `test_compact_import_crash_points` (on torn writes and failed syncs
//! from the faulty storage) and the `test_compact_reopen_rejects_*` and
//! `test_compact_bounded_initialization_rejects_corrupt_target_entry` tests. commonware tells
//! the corruption kinds apart by message; Zig errors carry none, so each is `DataCorrupted`.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const Faults = @import("../../archive/faults.zig").Faults;
const op_mod = @import("operation.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Storage = runtime.storage.Storage;
const CacheRef = runtime.buffer.paged.CacheRef;
const Probability = utils.Probability;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;
const all_dbs = .{
    support.KeylessFixed(Mmr),
    support.KeylessFixed(Mmb),
    support.ImmutableFixed(Mmr),
    support.ImmutableFixed(Mmb),
};

fn config(comptime Db: type, cache_ref: *CacheRef, partition: []const u8) Db.Cfg {
    return .{
        .witness = .{
            .partition = partition,
            .items_per_section = 4,
            .codec_config = {},
            .cache_ref = cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        },
        .codec_config = support.codec_config(Db),
    };
}

/// Applies `seed`'s mutation with `metadata` and `floor`, without making it durable.
fn apply_seed(comptime Db: type, db: *Db, seed: u64, metadata: u64, floor: ?u64) !Db.Commitment {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        try support.mutate(Db, &batch, seed);
        batch.with_metadata(support.metadata_value(Db, metadata));
        if (floor) |location| batch.with_inactivity_floor(location);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    return merkleized.commitment();
}

/// Durably commits `seed`'s mutation, with `seed`'s value as metadata, on top of the state in
/// `cfg`'s partition, returning the new target.
fn commit_seed(comptime Db: type, storage: Storage, cfg: Db.Cfg, seed: u64) !Db.CompactTarget {
    var db = try Db.init(gpa, storage, cfg, null);
    defer db.deinit();
    _ = try apply_seed(Db, &db, seed, seed, null);
    try db.sync();
    return db.target();
}

/// The state a sync client fetches for `target`: its commit and pinned nodes (owned).
fn Import(comptime Db: type) type {
    return struct { target: Db.CompactTarget, pinned: []Db.Digest, commit: Db.Operation };
}

fn fetch(comptime Db: type, storage: Storage, cfg: Db.Cfg, target: Db.CompactTarget) !Import(Db) {
    var db = try Db.init(gpa, storage, cfg, null);
    defer db.deinit();
    const request: Db.Request = .{ .boundary = .{ .size = target.size, .start = target.size - 1 } };
    var response = try db.serve(request);
    response.boundary.proof.deinit(gpa);
    const boundary = response.boundary;
    return .{ .target = target, .pinned = boundary.pinned_nodes, .commit = boundary.op };
}

/// Imports `import` into `cfg`'s partition; the db takes the commit.
fn import_db(comptime Db: type, storage: Storage, cfg: Db.Cfg, import: Import(Db)) !Db {
    const last = import.target.size - 1;
    const db = try Db.init_from_sync(gpa, storage, cfg, last, import.pinned, import.commit);
    try testing.expect(db.target().eql(import.target));
    return db;
}

const Crash = union(enum) {
    /// The import is built but nothing is written.
    before_replacement,
    /// The reset is durable, but the imported and applied witnesses are not.
    after_reset,
    /// The witnesses are written but their sync fails; the device keeps each unsynced write's
    /// prefix with the given percent retention.
    during_append: u64,
    /// The durability operation completed.
    after_durability,
};

const Reopened = enum { seeded, imported, applied, no_tip };

/// Crashes while replacing a seeded partition with an import, reopens, then re-syncs an
/// interrupted import. Every crash point reopens as a retained state or an interrupted import,
/// never as a fresh db.
fn crash_import(comptime Db: type, crash: Crash, seed: u64) !Reopened {
    var faults: Faults = undefined;
    faults.init(gpa, seed);
    defer faults.deinit();
    const storage = faults.interface();
    var cache_before = try CacheRef.init(gpa, 77, 9);
    defer cache_before.deinit();
    const src = config(Db, &cache_before, "compact-import-crash-src");
    const dst = config(Db, &cache_before, "compact-import-crash-dst");
    const target = try commit_seed(Db, storage, src, 2);
    const import = try fetch(Db, storage, src, target);
    defer gpa.free(import.pinned);
    const seeded = try commit_seed(Db, storage, dst, 1);
    var applied: ?Db.Commitment = null;
    {
        var db = try import_db(Db, storage, dst, import);
        defer db.deinit();
        switch (crash) {
            .before_replacement => {},
            .after_reset => _ = try apply_seed(Db, &db, 3, 3, null),
            .during_append => |percent| {
                // Retain unsynced writes from the start: the journal may write full pages
                // before it is asked to sync them.
                const write_rate: runtime.storage.faulty.WriteConfig = .{
                    .failure_rate = Probability.zero,
                    .retention_rate = Probability.init(percent, 100).?,
                    .mode = .prefix,
                };
                faults.layer.config = .{ .write_rate = write_rate };
                applied = try apply_seed(Db, &db, 3, 3, null);
                faults.layer.config = .{ .write_rate = write_rate, .sync_rate = .one };
                if (db.commit()) |_| return error.TestUnexpectedResult else |_| {}
            },
            .after_durability => try db.commit(),
        }
    }
    faults.disarm();
    try faults.crash();
    var cache_after = try CacheRef.init(gpa, 77, 9);
    defer cache_after.deinit();
    const reopen_cfg = config(Db, &cache_after, "compact-import-crash-dst");
    var db = Db.init(gpa, storage, reopen_cfg, null) catch |err| switch (err) {
        error.DataCorrupted => {
            try resync(Db, storage, &cache_after, target);
            return .no_tip;
        },
        else => return err,
    };
    defer db.deinit();
    const reopened = db.commitment();
    if (reopened.size == seeded.size and reopened.root.eql(seeded.root)) return .seeded;
    if (reopened.size == target.size and reopened.root.eql(target.root)) return .imported;
    if (applied) |tip| if (reopened.eql(tip)) return .applied;
    return error.TestUnexpectedResult;
}

/// A re-sync of an interrupted import replaces the partition, and the import reopens.
fn resync(comptime Db: type, storage: Storage, cache: *CacheRef, target: Db.CompactTarget) !void {
    const src = config(Db, cache, "compact-import-crash-src");
    const dst = config(Db, cache, "compact-import-crash-dst");
    const import = try fetch(Db, storage, src, target);
    defer gpa.free(import.pinned);
    {
        var db = try import_db(Db, storage, dst, import);
        defer db.deinit();
        try db.commit();
    }
    var db = try Db.init(gpa, storage, dst, null);
    defer db.deinit();
    try testing.expect(db.target().eql(target));
}

test "compact import crash points reopen a retained state or an interrupted import" {
    inline for (all_dbs) |Db| {
        try testing.expectEqual(Reopened.seeded, try crash_import(Db, .before_replacement, 0));
        try testing.expectEqual(Reopened.no_tip, try crash_import(Db, .after_reset, 0));
        try testing.expectEqual(Reopened.no_tip, try crash_import(Db, .{ .during_append = 0 }, 0));
        const full: Crash = .{ .during_append = 100 };
        try testing.expectEqual(Reopened.applied, try crash_import(Db, full, 0));
        for (0..8) |seed| {
            const reopened = try crash_import(Db, .{ .during_append = 50 }, seed);
            try testing.expect(reopened != .seeded);
        }
        try testing.expectEqual(Reopened.imported, try crash_import(Db, .after_durability, 0));
    }
}

/// Rewrites the witness journal from `position`: `edit` changes the entry there, and the
/// entries above it are kept.
fn rewrite_entry(
    comptime Db: type,
    storage: Storage,
    cfg: Db.Cfg,
    position: u64,
    edit: anytype,
) !void {
    var recovery = try Db.Journal.recover(gpa, storage, cfg.witness, null);
    const end = recovery.get_bounds().end;
    var entries: std.ArrayList(Db.Stored) = .empty;
    defer {
        for (entries.items) |*entry| entry.deinit(gpa);
        entries.deinit(gpa);
    }
    {
        errdefer recovery.deinit();
        try testing.expect(position < end);
        for (position..end) |at| {
            const entry = try recovery.read(at);
            errdefer {
                var owned = entry;
                owned.deinit(gpa);
            }
            try entries.append(gpa, entry);
        }
        try edit(&entries.items[0]);
    }
    var journal = try recovery.finish(position);
    defer journal.deinit();
    for (entries.items) |entry| _ = try journal.append(entry);
    try journal.sync();
}

fn Edits(comptime Db: type) type {
    return struct {
        fn fill(byte: u8) Db.Digest {
            return .{ .bytes = @splat(byte) };
        }

        /// An extra pinned node cannot rebuild the Merkle.
        fn extra_pin(entry: *Db.Stored) !void {
            const count = entry.pinned_nodes.len;
            const pins = try gpa.alloc(Db.Digest, count + 1);
            @memcpy(pins[0..count], entry.pinned_nodes);
            pins[count] = fill(0xff);
            gpa.free(entry.pinned_nodes);
            entry.pinned_nodes = pins;
        }

        /// A flipped pinned node rebuilds, with another root.
        fn flip_pin(entry: *Db.Stored) !void {
            try testing.expect(entry.pinned_nodes.len > 0);
            @constCast(entry.pinned_nodes)[0] = fill(0xff);
        }

        /// A commit whose floor lies beyond its own location.
        fn floor_beyond_tip(entry: *Db.Stored) !void {
            const metadata = support.metadata_value(Db, 11);
            try replace_commit(entry, op_mod.commit(Db.Operation, metadata, 10));
        }

        /// A mutation where the commit belongs.
        fn non_commit(entry: *Db.Stored) !void {
            try replace_commit(entry, support.mutation_op(Db, 7));
        }

        fn replace_commit(entry: *Db.Stored, op: Db.Operation) !void {
            const bytes = try codec.encode(Db.Operation, gpa, op);
            gpa.free(entry.commit);
            entry.commit = bytes;
        }
    };
}

/// Commits `seed`'s mutation with metadata 11 and floor 1, durably.
fn commit_floored(comptime Db: type, harness: *support.Harness, seed: u64) !Db.CompactTarget {
    var db = try harness.open(Db, null);
    defer db.deinit();
    _ = try apply_seed(Db, &db, seed, 11, 1);
    try db.sync();
    return db.target();
}

// Commonware's `test_compact_reopen_rejects_tampered_witness`,
// `test_compact_reopen_rejects_commit_floor_beyond_tip`, and
// `test_compact_reopen_rejects_non_commit_tip`.
test "compact reopen rejects a tampered tip witness" {
    inline for (all_dbs) |Db| {
        const E = Edits(Db);
        inline for (.{ E.extra_pin, E.floor_beyond_tip, E.non_commit }) |edit| {
            var harness = try support.Harness.init(gpa);
            defer harness.deinit();
            _ = try commit_floored(Db, &harness, 7);
            // The journal holds the genesis witness, then the tip.
            const storage = harness.storage.interface();
            try rewrite_entry(Db, storage, harness.cfg(Db), 1, edit);
            try testing.expectError(error.DataCorrupted, harness.open(Db, null));
        }
    }
}

// Commonware's `test_compact_reopen_rejects_tampered_pinned_nodes`: with no stored proof to
// cross-check, a flipped pinned node reopens with another root.
test "compact reopen of a flipped pinned node yields another root" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        const tampered = try commit_floored(Db, &harness, 7);
        const storage = harness.storage.interface();
        try rewrite_entry(Db, storage, harness.cfg(Db), 1, Edits(Db).flip_pin);
        var db = try harness.open(Db, null);
        defer db.deinit();
        try testing.expectEqual(tampered.size, db.size());
        try testing.expect(!db.target().eql(tampered));
    }
}

fn expect_tip(comptime Db: type, harness: *support.Harness, tip: Db.CompactTarget) !void {
    var db = try harness.open(Db, null);
    defer db.deinit();
    try testing.expect(db.target().eql(tip));
}

// Commonware's `test_compact_bounded_initialization_rejects_corrupt_target_entry`.
test "compact bounded initialization rejects a corrupt target and keeps newer history" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        const bound = (try commit_floored(Db, &harness, 1)).size;
        const tip = try commit_floored(Db, &harness, 2);
        // The journal holds the genesis witness, the bounded target, and the tip.
        const storage = harness.storage.interface();
        try rewrite_entry(Db, storage, harness.cfg(Db), 1, Edits(Db).extra_pin);
        // The tip entry is intact, so an unbounded reopen succeeds.
        try expect_tip(Db, &harness, tip);
        // The corrupt target fails the bounded open before anything is discarded.
        try testing.expectError(error.DataCorrupted, harness.open(Db, bound));
        try expect_tip(Db, &harness, tip);
    }
}
