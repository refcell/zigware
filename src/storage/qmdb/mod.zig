//! A collection of authenticated databases inspired by QMDB (Quick Merkle Database).
//!
//! Port of commonware's `storage/src/qmdb` (shared modules, keyless, immutable, and any; the
//! current, sync, and compact variants come later). A database's state is derived from an
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
pub const keyless = @import("keyless/mod.zig");
pub const immutable = @import("immutable/mod.zig");
pub const any = @import("any/mod.zig");

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
    /// A compact sync result is not exactly one commit at the expected location.
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

/// The inactivity floor declared at the commit immediately preceding `op_count`
/// (commonware's `find_inactivity_floor_at`). `reader` provides `bounds()` (a
/// `journal.contiguous.Bounds`) and `read(gpa, location)` returning an owned operation with
/// `inactivity_floor()` and `deinit(gpa)`.
pub fn find_inactivity_floor_at(
    gpa: std.mem.Allocator,
    reader: anytype,
    op_count: u64,
) !u64 {
    if (op_count == 0) return error.HistoricalFloorPruned;
    const last = op_count - 1;
    const bounds = reader.bounds();
    if (last < bounds.start) return error.ItemPruned;
    var op = try reader.read(gpa, last);
    defer op.deinit(gpa);
    const inactivity_floor = op.inactivity_floor() orelse return error.HistoricalFloorPruned;
    if (inactivity_floor > last) return error.DataCorrupted;
    return inactivity_floor;
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
    _ = @import("operation_fuzz_test.zig");
}
