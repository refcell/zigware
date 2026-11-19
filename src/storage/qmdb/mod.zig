//! A collection of authenticated databases inspired by QMDB (Quick Merkle Database).
//!
//! Port of commonware's `storage/src/qmdb`: the shared modules and the keyless, immutable,
//! any, store, current, sync, and compact databases. A database's state is derived from an
//! append-only log of operations; its Merkle root commits to that log, and proofs show that
//! operations (and, for keyed variants, key values) are in it. See commonware's module
//! documentation for the batch lifecycle, batch validity, durability, and initialization
//! bounds; the Zig types keep the same semantics.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const merkle = @import("../merkle/mod.zig");
const journal = @import("../journal/mod.zig");
const runtime_storage = @import("runtime").storage;

pub const value = @import("value.zig");
pub const operation = @import("operation.zig");
pub const floor = @import("floor.zig");
pub const chain = @import("chain.zig");
pub const verify = @import("verify.zig");
pub const cache = @import("cache.zig");
pub const snapshot = @import("snapshot.zig");
pub const bitmap = @import("bitmap.zig");
pub const metrics = @import("metrics.zig");
pub const keyless = @import("keyless/mod.zig");
pub const immutable = @import("immutable/mod.zig");
pub const any = @import("any/mod.zig");
pub const store = @import("store/mod.zig");
pub const sync = @import("sync/mod.zig");
pub const current = @import("current/mod.zig");
pub const compact = @import("compact/mod.zig");

/// Errors from an authenticated database (commonware's `qmdb::Error`). Payloads (locations,
/// sizes, the failed check's name) are not carried: Zig errors have none.
pub const Error = error{
    /// A QMDB initialization bound cannot exclude its initial commit.
    InvalidInitializationBound,
    /// Database state failed a consistency check.
    DataCorrupted,
    /// The operation at the location, or the bitmap chunk covering it, has been pruned.
    OperationPruned,
    /// The requested key was not found in the snapshot.
    KeyNotFound,
    /// The key exists in the db, so its exclusion cannot be proven.
    KeyExists,
    /// A log that must end with a commit does not, or a compact sync result is not exactly
    /// one commit at the expected location.
    UnexpectedData,
    /// A requested location is at or past the size of the database or batch being read.
    LocationOutOfBounds,
    /// A batched read's locations were out of order.
    LocationOutOfOrder,
    /// A prune location exceeds the furthest location pruning may reach.
    PruneBeyondMinRequired,
    /// The batch cannot be merkleized or applied against the database's state.
    StaleBatch,
    /// A read through a batch found the database at no state of the batch's chain.
    StaleRead,
    /// A batch read asked for a location below the batch's inactivity floor.
    BelowInactivityFloor,
    /// The batch's inactivity floor is lower than the floor it builds on.
    FloorRegressed,
    /// A commit's inactivity floor exceeds the commit operation's own location.
    FloorBeyondCommit,
    /// The commit at the given operation count cannot be reconstructed from retained history.
    HistoricalFloorPruned,
} || merkle.Error || journal.Error || runtime_storage.Error;

/// Merkle peak bagging policy used by QMDB operation roots.
pub const root_bagging: merkle.Bagging = .backward_fold;

/// The Merkle hasher QMDB operation roots and proofs use (commonware's `qmdb::hasher`).
pub fn hasher(comptime H: type) merkle.hasher.Standard(H) {
    return merkle.hasher.Standard(H).init(root_bagging);
}

/// The root of an operation log holding only the encoded operation `encoded`; variants derive
/// their initial root from the bootstrap commit with it.
pub fn single_operation_root(comptime F: type, comptime H: type, encoded: []const u8) H.Digest {
    const standard = hasher(H);
    const leaf = standard.leaf_digest(F.location_to_position(0), encoded);
    const root = merkle.hasher.root(F, &standard, 1, 0, &.{leaf}) catch
        unreachable; // Proof: a single-leaf root has one peak and no inactive peaks.
    return root;
}

/// Rejects a bound that cannot retain the bootstrap commit.
pub fn validate_initialization_bound(bound: ?u64) Error!void {
    if (bound) |size| if (size == 0) return error.InvalidInitializationBound;
}

/// Validates a selected commit against its retained history and returns its floor (null for a
/// fresh, empty journal). `commit_floor` is the selected last operation's inactivity floor, or
/// null when that operation is not a commit.
pub fn validate_initialization_commit(
    start: u64,
    size: u64,
    fresh: bool,
    commit_floor: ??u64,
    replay_from_floor: bool,
) Error!?u64 {
    if (size == 0) return if (fresh) null else error.DataCorrupted;
    const selected = commit_floor orelse return error.DataCorrupted;
    const inactivity_floor = selected orelse return error.DataCorrupted;
    if (inactivity_floor >= size) return error.DataCorrupted;
    if (replay_from_floor and inactivity_floor < start) return error.HistoricalFloorPruned;
    assert(inactivity_floor < size);
    return inactivity_floor;
}

/// Options of `init_journal`.
pub const InitOptions = struct {
    /// Retain at most this many operations (the last commit within them).
    max_size: ?u64 = null,
    /// Whether the variant rebuilds a snapshot from the floor, which must then be retained.
    replay_from_floor: bool = false,
    /// Operations a pruned activity bitmap no longer covers; the selected commit and its floor
    /// must not lie below them (`current`'s pruned bits).
    pruned_bits: u64 = 0,
    /// The fewest operations the selected commit may retain (`current`'s pair-absorption
    /// threshold).
    minimum_size: u64 = 0,
};

/// `log` timed on the database's clock `io` unless it names its own (one clock times the
/// database and its journal). Journal configs without an `io` field pass through unchanged.
pub fn log_with_io(log: anytype, io: ?std.Io) @TypeOf(log) {
    var result = log;
    if (comptime @hasField(@TypeOf(log), "io")) {
        if (result.io == null) result.io = io;
        assert(result.io != null or io == null);
    }
    return result;
}

/// Opens the authenticated journal `J` of a QMDB variant, selecting the last commit (within
/// `options.max_size`) and validating it before any history is discarded (commonware's
/// `init_journal`).
pub fn init_journal(
    comptime J: type,
    gpa: std.mem.Allocator,
    storage: runtime_storage.Storage,
    merkle_cfg: merkle.full.Config,
    journal_cfg: anytype,
    options: InitOptions,
) !J {
    try validate_initialization_bound(options.max_size);
    const Floored = struct {
        fn floored(op: J.Item) bool {
            return op.inactivity_floor() != null;
        }
    };
    var pending = try J.prepare(
        gpa,
        storage,
        merkle_cfg,
        journal_cfg,
        options.max_size,
        Floored.floored,
        root_bagging,
    );
    validate_pending(J, gpa, &pending, options) catch |err| {
        pending.deinit();
        return err;
    };
    return pending.finish(); // Consumes `pending`, also on error.
}

fn validate_pending(
    comptime J: type,
    gpa: std.mem.Allocator,
    pending: anytype,
    options: InitOptions,
) !void {
    const bounds = pending.bounds();
    assert(bounds.start <= bounds.end);
    // Checked before publishing, so a refused bound discards no history.
    if (bounds.end < options.pruned_bits) return error.HistoricalFloorPruned;
    var commit: ?J.Item = if (bounds.end == 0) null else try pending.read(bounds.end - 1);
    defer if (commit) |*op| op.deinit(gpa);
    const commit_floor: ??u64 = if (commit) |op| op.inactivity_floor() else null;
    const fresh = pending.is_fresh();
    const replay = options.replay_from_floor;
    const selected_floor = try validate_initialization_commit(
        bounds.start,
        bounds.end,
        fresh,
        commit_floor,
        replay,
    );
    if (selected_floor) |selected| {
        if (selected < options.pruned_bits) return error.HistoricalFloorPruned;
    }
    if (bounds.end < options.minimum_size) return error.HistoricalFloorPruned;
}

/// The inactivity floor declared by the commit at `op_count - 1`, or null if that operation is
/// not a commit (commonware's `commit_floor_at`). `reader` provides `bounds()` (a
/// `journal.contiguous.Bounds`) and `read(gpa, location)` returning an owned operation with
/// `inactivity_floor()` and `deinit(gpa)`. Fails with `HistoricalFloorPruned` when `op_count`
/// is zero, `ItemPruned` when `op_count - 1` precedes the retained start, and `DataCorrupted`
/// when the commit declares a floor past its own location.
pub fn commit_floor_at(gpa: std.mem.Allocator, reader: anytype, op_count: u64) !?u64 {
    if (op_count == 0) return error.HistoricalFloorPruned;
    const last = op_count - 1;
    const bounds = reader.bounds();
    if (last < bounds.start) return error.ItemPruned;
    assert(last < bounds.end);
    var op = try reader.read(gpa, last);
    defer op.deinit(gpa);
    const inactivity_floor = op.inactivity_floor() orelse return null;
    if (inactivity_floor > last) return error.DataCorrupted;
    return inactivity_floor;
}

/// The inactivity floor declared by the commit at `op_count - 1` (commonware's
/// `find_inactivity_floor_at`): `commit_floor_at` for callers that require a commit there, so
/// a retained non-commit is `HistoricalFloorPruned`.
pub fn find_inactivity_floor_at(
    gpa: std.mem.Allocator,
    reader: anytype,
    op_count: u64,
) !u64 {
    const inactivity_floor = try commit_floor_at(gpa, reader, op_count);
    return inactivity_floor orelse error.HistoricalFloorPruned;
}

/// The inactive peak count of the log at historical size `op_count`.
pub fn inactive_peaks_at(
    comptime F: type,
    gpa: std.mem.Allocator,
    reader: anytype,
    op_count: u64,
) !usize {
    if (op_count == 0) return 0;
    const inactivity_floor = try find_inactivity_floor_at(gpa, reader, op_count);
    return merkle.inactive_peaks(F, op_count, inactivity_floor);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("mod_test.zig");
    _ = @import("fuzz_floor.zig");
    _ = @import("operation_fuzz_test.zig");
}
