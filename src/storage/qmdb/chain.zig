//! Shared validation for QMDB batch chains (qmdb/chain.rs).
//!
//! A batch chain is a linked sequence of in-memory batches built on a database state. A state
//! is a database `Commitment` (size and root). The states of a batch's chain are its recorded
//! database boundary, each ancestor's tip, and the batch's own tip; while the database is at
//! one of them, reads through the batch are exact. At any other state the batch is stale:
//! reads return `StaleRead`, and merkleize and apply return `StaleBatch`.
//!
//! commonware returns a `Compatible<'a, T>` borrow witness from its checks; Zig has no borrow
//! checker, so the checks here return `void` and callers read the database directly after
//! they pass.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../merkle/mod.zig");
const operation = @import("operation.zig");
const value = @import("value.zig");

pub const Error = error{ StaleBatch, StaleRead, FloorRegressed, FloorBeyondCommit };

/// Identifies a QMDB state by its operation `size` and authenticated `root`.
pub fn Commitment(comptime F: type, comptime D: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();

        /// Number of operations in the state.
        size: u64,
        /// Root committing to those operations.
        root: D,

        pub fn eql(a: Self, b: Self) bool {
            return a.size == b.size and a.root.eql(b.root);
        }

        /// Checks that `current` still equals this commitment, for reads through a batch built
        /// directly on the database at this commitment.
        pub fn compatible(self: Self, current: Self) Error!void {
            if (!self.eql(current)) return error.StaleRead;
        }

        pub fn encode_size(self: Self) usize {
            return operation.location_size(self.size) + codec.encode_size(D, self.root);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            operation.write_location(self.size, writer);
            codec.write(D, self.root, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const size = try operation.read_location(F, reader);
            const root = try codec.read(D, gpa, reader);
            return .{ .size = size, .root = root };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const size = operation.arbitrary_location(F, u);
            const root = try value.arbitrary(D, gpa, u);
            return .{ .size = size, .root = root };
        }
    };
}

/// Position and inactivity-floor state for a merkleized QMDB batch.
pub fn Bounds(comptime F: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const State = Commitment(F, D);

        /// The commitment immediately before this batch's own operations.
        base: State,
        /// The commitment at the recorded database boundary, between applied database
        /// operations and operations kept in this batch chain.
        db: State,
        /// This batch's tip: the state after all its operations.
        tip: State,
        /// Tip commitments this batch retained from its ancestors at merkleize, newest first.
        /// Owned (free with `deinit`).
        ancestors: []const State,
        /// Inactivity floor declared by this batch's commit.
        inactivity_floor: u64,

        /// Initial bounds for a batch built directly on the database at `state`.
        pub fn from_db(state: State, inactivity_floor: u64) Self {
            return .{
                .base = state,
                .db = state,
                .tip = state,
                .ancestors = &.{},
                .inactivity_floor = inactivity_floor,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.ancestors);
            self.* = undefined;
        }

        /// Checks that `current` is a state of this batch's chain: its tip, the recorded
        /// database boundary, or an ancestor's tip.
        pub fn compatible(self: *const Self, current: State) Error!void {
            if (current.eql(self.tip) or current.eql(self.db)) return;
            for (self.ancestors) |ancestor| if (current.eql(ancestor)) return;
            return error.StaleRead;
        }

        /// Validates that this batch can be applied to the database at `current`.
        pub fn validate_apply_to(self: *const Self, current: State) Error!void {
            return validate_batch_applicable(F, D, current, self.db, self.ancestors);
        }
    };
}

/// Advances the inherited recorded boundary to the base of the oldest reachable ancestor.
pub fn effective_boundary(
    comptime F: type,
    comptime D: type,
    inherited: Commitment(F, D),
    oldest_live_base: ?Commitment(F, D),
) Commitment(F, D) {
    if (oldest_live_base) |base| if (base.size > inherited.size) return base;
    return inherited;
}

/// Validates that a batch can be applied to the database at `current`: the database is at
/// the batch's recorded boundary or at one of its ancestors' tips.
pub fn validate_batch_applicable(
    comptime F: type,
    comptime D: type,
    current: Commitment(F, D),
    batch_db: Commitment(F, D),
    ancestors: []const Commitment(F, D),
) Error!void {
    if (current.eql(batch_db)) return;
    for (ancestors) |state| if (current.eql(state)) return;
    return error.StaleBatch;
}

/// Validates a batch's floor against the floor it builds on (`start`) and its own commit
/// location.
pub fn validate_merkleize_floor(start: u64, floor: u64, commit_location: u64) Error!void {
    if (floor < start) return error.FloorRegressed;
    if (floor > commit_location) return error.FloorBeyondCommit;
    assert(start <= floor and floor <= commit_location);
}

test {
    _ = @import("chain_test.zig");
}
