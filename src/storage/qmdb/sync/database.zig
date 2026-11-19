//! The database a sync builds (commonware's `qmdb/sync/database.rs`).
//!
//! commonware's `Database` trait becomes a comptime interface checked by `assert_database`.
//! A database type `DB` declares:
//! - `Family`, `Op`, `Digest`, `Hasher`, `Journal` (a sync journal, see `journal.zig`), and
//!   `Config` with `journal_config(cfg)` (commonware's `Config::journal_config`);
//! - `from_sync_result(gpa, storage, scope, cfg, journal, pinned_nodes, range, batch)`, which
//!   takes ownership of the journal and the pinned nodes, also on error;
//! - `persist_sync_result(*DB)`, called only once the root of `target` matches the target;
//! - `discard_local_state(gpa, storage, cfg)`, called when the opened sync journal holds no
//!   operation of the target's range;
//! - `local_pinned_nodes(gpa, storage, cfg, target, *journal) ?[]Digest` (owned), probed when
//!   the journal already reaches the target;
//! - `target(*const DB) Target`, the sync target that reaches the applied state; its root is
//!   the ops root, which `current` computes differently from its canonical root;
//! - `prune_to_target(*DB, Target)`, pruning history a reached target no longer needs;
//! - optionally `validate_target(Target) EngineError!void`, rejecting a target the database
//!   cannot sync to; the engine checks the initial target and every adopted update.
//!
//! The shared bodies for databases backed by a persisted `merkle.full.Merkle` are here:
//! `discard_local_state` and `local_pinned_nodes`, plus `journal_covers_range`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const target_mod = @import("target.zig");
const Scope = runtime.telemetry.metrics.Scope;

const Storage = runtime.storage.Storage;

/// Fails compilation unless `DB` provides the sync database interface.
pub fn assert_database(comptime DB: type) void {
    comptime {
        for (.{ "Family", "Op", "Digest", "Hasher", "Journal", "Config" }) |name| {
            if (!@hasDecl(DB, name)) @compileError(@typeName(DB) ++ " lacks " ++ name);
        }
        for (.{
            "from_sync_result",
            "persist_sync_result",
            "discard_local_state",
            "local_pinned_nodes",
            "target",
            "prune_to_target",
            "journal_config",
        }) |name| {
            if (!@hasDecl(DB, name)) @compileError(@typeName(DB) ++ " lacks " ++ name);
        }
        merkle.check_family(DB.Family);
    }
}

/// Whether a completed sync journal's `bounds` cover `range`: retained data reaches back to
/// `range.start` and ends exactly at `range.end`.
pub fn journal_covers_range(bounds: merkle.Range, range: merkle.Range) bool {
    assert(range.start < range.end);
    assert(bounds.start <= bounds.end);
    return bounds.start <= range.start and bounds.end == range.end;
}

/// Durably empties the persisted Merkle structure `cfg` names, including its pruning boundary
/// and pins (commonware's `Retain::Nothing`).
pub fn discard_local_state(
    comptime F: type,
    comptime H: type,
    gpa: Allocator,
    storage: Storage,
    cfg: merkle.full.Config,
) !void {
    const Merkle = merkle.full.Merkle(F, H.Digest);
    const hasher = qmdb.hasher(H);
    var recovery = try Merkle.Recovery.prepare(gpa, storage, &hasher, cfg, .nothing);
    var structure = try recovery.finish(); // Consumes `recovery`, also on error.
    defer structure.deinit();
    assert(structure.leaves() == 0);
    try structure.sync();
}

/// The pins at `target.start` from the persisted Merkle structure `cfg` names, when its
/// bounds cover the target and its root (with `inactivity_floor`) matches `target.root`.
/// Null when the persisted state cannot authenticate the target, including when an
/// interrupted reset left required nodes unavailable. The caller owns the result.
pub fn local_pinned_nodes(
    comptime F: type,
    comptime H: type,
    gpa: Allocator,
    storage: Storage,
    cfg: merkle.full.Config,
    wanted: target_mod.Target(F, H.Digest),
    inactivity_floor: u64,
) !?[]H.Digest {
    assert(wanted.start < wanted.end);
    const Merkle = merkle.full.Merkle(F, H.Digest);
    const hasher = qmdb.hasher(H);
    var structure = Merkle.init(gpa, storage, &hasher, cfg) catch |err| switch (err) {
        // An interrupted reset can leave durable boundary metadata ahead of the journal.
        error.MissingNode => return null,
        else => return err,
    };
    defer structure.deinit();
    const bounds = structure.bounds();
    if (bounds.start > wanted.start or bounds.end != wanted.end) return null;
    const inactive_peaks = merkle.inactive_peaks(F, wanted.end, inactivity_floor);
    const root = try structure.root(&hasher, inactive_peaks);
    if (!root.eql(wanted.root)) return null;
    var buffer: [merkle.max_pinned_nodes]H.Digest = undefined;
    const pins = try structure.pinned_nodes_at(wanted.start, &buffer);
    return try gpa.dupe(H.Digest, pins);
}

/// A variant database's authenticated journal type (`Log` in any, `Journal` elsewhere).
fn LogOf(comptime DbType: type) type {
    return if (@hasDecl(DbType, "Log")) DbType.Log else DbType.Journal;
}

const discard_merkle = discard_local_state;
const merkle_pinned_nodes = local_pinned_nodes;

/// The sync database adapter of a variant over a persisted Merkle structure and a backing
/// contiguous journal `C` (commonware's `sync::Database` impls of any, immutable, and
/// keyless, which differ only in how the database is built over the filled log). `build`
/// takes ownership of the journal, also on error (the variant's `init_from_log`). `V`
/// declares `Db`, `Backing` (the contiguous journal `C`), `Hasher`, and
/// `build(gpa, scope, cfg, log) !Db`.
pub fn Persisted(comptime F: type, comptime V: type) type {
    const DbType = V.Db;
    const C = V.Backing;
    const H = V.Hasher;
    const build = V.build;
    const Log = LogOf(DbType);
    return struct {
        const Self = @This();
        pub const Db = DbType;
        pub const Family = F;
        pub const Op = Db.Operation;
        pub const Digest = H.Digest;
        pub const Hasher = H;
        pub const Journal = C;
        pub const Config = Db.Cfg;
        pub const Target = target_mod.Target(F, Digest);

        db: Db,

        pub fn deinit(self: *Self) void {
            self.db.deinit();
            self.* = undefined;
        }

        pub fn journal_config(cfg: Config) C.BackingConfig {
            return cfg.log;
        }

        /// Builds the database over the filled sync journal `log`: the Merkle structure is
        /// opened for `range` with `pinned_nodes`, missing leaves are replayed from the log,
        /// and the result is synced. Takes ownership of `log` and `pinned_nodes`.
        pub fn from_sync_result(
            gpa: Allocator,
            storage: Storage,
            scope: Scope,
            cfg: Config,
            log: C,
            pinned_nodes: ?[]Digest,
            range: merkle.Range,
            apply_batch_size: u64,
        ) !Self {
            assert(range.start < range.end);
            var owned_log = log;
            const structure = structure: {
                defer if (pinned_nodes) |pins| gpa.free(pins);
                errdefer owned_log.deinit();
                break :structure try Log.Merkle.init_sync(gpa, storage, .{
                    .config = cfg.merkle,
                    .range = range,
                    .pinned_nodes = pinned_nodes,
                });
            };
            const hasher = qmdb.hasher(H);
            const journal =
                try Log.from_components(gpa, structure, owned_log, hasher, apply_batch_size);
            var self: Self = .{ .db = try build(gpa, scope, cfg, journal) };
            errdefer self.deinit();
            try self.db.sync();
            return self;
        }

        pub fn persist_sync_result(_: *Self) !void {}

        pub fn discard_local_state(gpa: Allocator, storage: Storage, cfg: Config) !void {
            try discard_merkle(F, H, gpa, storage, cfg.merkle);
        }

        pub fn local_pinned_nodes(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            wanted: Target,
            log: *C,
        ) !?[]Digest {
            const span = log.get_bounds();
            const bounds: merkle.Range = .{ .start = span.start, .end = span.end };
            const range: merkle.Range = .{ .start = wanted.start, .end = wanted.end };
            if (wanted.start == 0 or !journal_covers_range(bounds, range)) {
                return null;
            }
            // The inactivity floor is the last commit's, not the wanted's start.
            var reader: LogReader = .{ .log = log };
            const floor = try qmdb.find_inactivity_floor_at(gpa, &reader, wanted.end);
            return merkle_pinned_nodes(F, H, gpa, storage, cfg.merkle, wanted, floor);
        }

        /// The target reaching the applied state: its root over `[sync_boundary, end)`.
        pub fn target(self: *const Self) Target {
            return .init(self.db.root(), self.db.sync_boundary(), self.db.bounds().end);
        }

        /// Prunes the history below the start of a reached `target`.
        pub fn prune_to_target(self: *Self, reached: Target) !void {
            assert(reached.start < reached.end);
            try self.db.prune(reached.start);
        }

        const LogReader = struct {
            log: *C,

            pub fn bounds(reader: *const LogReader) merkle.Range {
                const span = reader.log.get_bounds();
                return .{ .start = span.start, .end = span.end };
            }

            pub fn read(reader: *LogReader, _: Allocator, location: u64) !Op {
                return reader.log.read(location);
            }
        };
    };
}

const testing = std.testing;

// commonware's `test_journal_covers_range`.
test "sync journal covers range" {
    const range: merkle.Range = .{ .start = 10, .end = 20 };
    try testing.expect(journal_covers_range(.{ .start = 10, .end = 20 }, range));
    try testing.expect(journal_covers_range(.{ .start = 5, .end = 20 }, range));
    try testing.expect(!journal_covers_range(.{ .start = 11, .end = 20 }, range));
    try testing.expect(!journal_covers_range(.{ .start = 10, .end = 19 }, range));
    try testing.expect(!journal_covers_range(.{ .start = 10, .end = 21 }, range));
    try testing.expect(!journal_covers_range(.{ .start = 0, .end = 0 }, range));
}

const support = @import("../../merkle/persisted/full_test.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const Sha256 = @import("cryptography").Sha256;
const Mmr = merkle.mmr.Family;
const TestMerkle = merkle.full.Merkle(Mmr, Sha256.Digest);

/// A synced tree of 50 leaves in `harness`, pruned to `prune_to` when nonzero.
fn seed(harness: *support.Harness, prune_to: u64) !void {
    const hasher = qmdb.hasher(Sha256);
    const storage = harness.storage.interface();
    var structure = try TestMerkle.init(test_gpa, storage, &hasher, harness.cfg());
    defer structure.deinit();
    var batch = try structure.new_batch();
    for (0..50) |i| {
        const leaf = support.test_digest(i);
        batch.add(test_gpa, &hasher, &leaf.bytes) catch |err| {
            batch.deinit(test_gpa);
            return err;
        };
    }
    const merkleized = try batch.merkleize(&structure, &hasher);
    defer merkleized.release(test_gpa);
    try structure.apply_batch(merkleized);
    try structure.sync();
    if (prune_to > 0) {
        try structure.prune(prune_to);
        try structure.sync();
    }
}

const test_gpa = testing.allocator;

fn expect_unavailable(
    storage: Storage,
    cfg: merkle.full.Config,
    target: target_mod.Target(Mmr, Sha256.Digest),
    floor: u64,
) !void {
    const pins = try local_pinned_nodes(Mmr, Sha256, test_gpa, storage, cfg, target, floor);
    try testing.expect(pins == null);
}

// commonware's `local_pinned_nodes_treats_reset_journal_as_unavailable`.
test "sync local pinned nodes treat a reset journal as unavailable" {
    var harness = try support.Harness.init();
    defer harness.deinit();
    try seed(&harness, 30);
    // A node journal reset below the persisted pin boundary cannot supply local pins.
    const restart: u64 = 7;
    const position = try merkle.position_from_location(Mmr, restart);
    const cfg = harness.cfg();
    var journal = try fixed.Journal(Sha256.Digest).init_at_size(
        test_gpa,
        harness.storage.interface(),
        cfg.journal(),
        position,
    );
    journal.deinit();
    const target = target_mod.Target(Mmr, Sha256.Digest).init(.fill(0), restart, 20);
    const storage = harness.storage.interface();
    const pins = try local_pinned_nodes(Mmr, Sha256, test_gpa, storage, cfg, target, restart);
    try testing.expect(pins == null);
}

test "sync local pinned nodes authenticate a matching root" {
    var harness = try support.Harness.init();
    defer harness.deinit();
    try seed(&harness, 0);
    const storage = harness.storage.interface();
    const cfg = harness.cfg();
    const hasher = qmdb.hasher(Sha256);
    const floor: u64 = 12;
    var expected: [merkle.max_pinned_nodes]Sha256.Digest = undefined;
    const root, const want = blk: {
        var structure = try TestMerkle.init(test_gpa, storage, &hasher, cfg);
        defer structure.deinit();
        const peaks = merkle.inactive_peaks(Mmr, 50, floor);
        const root = try structure.root(&hasher, peaks);
        break :blk .{ root, (try structure.pinned_nodes_at(20, &expected)).len };
    };
    const Target = target_mod.Target(Mmr, Sha256.Digest);
    const matching: Target = .init(root, 20, 50);
    const found = try local_pinned_nodes(Mmr, Sha256, test_gpa, storage, cfg, matching, floor);
    const pins = found.?;
    defer test_gpa.free(pins);
    try testing.expectEqualSlices(Sha256.Digest, expected[0..want], pins);
    // Another root, a floor giving another root, or a range ending elsewhere is unavailable.
    const other: Target = .init(.fill(9), 20, 50);
    try expect_unavailable(storage, cfg, other, floor);
    const short: Target = .init(root, 20, 49);
    try expect_unavailable(storage, cfg, short, floor);
    // Discarding local state empties the structure.
    try discard_local_state(Mmr, Sha256, test_gpa, storage, cfg);
    var reopened = try TestMerkle.init(test_gpa, storage, &hasher, cfg);
    defer reopened.deinit();
    try testing.expectEqual(@as(u64, 0), reopened.leaves());
}
