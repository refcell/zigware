//! The operation types a compact db is built over (commonware's `qmdb/compact/operation.rs`
//! and the `compact::Operation` impls in `keyless/compact.rs` and `immutable/compact.rs`).
//!
//! commonware seals a trait implemented by the keyless and immutable operations. Here the
//! interface is comptime: an operation `O` is keyless when it has an `append` variant (its
//! mutations are appended values, in order) and immutable when it has a `set` variant (its
//! mutations are sets, one per key in key order, the last set of a key winning). Both have a
//! `commit` variant holding `operation.Commit(O.Value)`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const value_mod = @import("../value.zig");

/// Whether `O` is an immutable (keyed) operation.
pub fn is_keyed(comptime O: type) bool {
    const keyed = @hasField(O, "set");
    comptime assert(keyed != @hasField(O, "append"));
    comptime assert(@hasField(O, "commit"));
    return keyed;
}

/// What one batch mutation records: a value (keyless) or a key and value (immutable).
pub fn Mutation(comptime O: type) type {
    return if (is_keyed(O)) O.Set else O.Value;
}

/// The name commonware records on spans.
pub fn name(comptime O: type) []const u8 {
    return if (is_keyed(O)) "immutable" else "keyless";
}

/// The operation of one mutation (`Sealed::mutation`).
pub fn from_mutation(comptime O: type, mutation: Mutation(O)) O {
    return if (comptime is_keyed(O)) .{ .set = mutation } else .{ .append = mutation };
}

/// A commit operation (`Operation::commit`). Takes `metadata`.
pub fn commit(comptime O: type, commit_metadata: ?O.Value, floor: u64) O {
    return .{ .commit = .{ .metadata = commit_metadata, .floor = floor } };
}

/// The metadata of a commit, or null for a commit without it or any other operation.
pub fn metadata(comptime O: type, op: *const O) ?O.Value {
    return switch (op.*) {
        .commit => |c| c.metadata,
        else => null,
    };
}

/// A copy of the commit `op`, owned by the caller.
pub fn clone_commit(comptime O: type, gpa: Allocator, op: O) Allocator.Error!O {
    assert(op == .commit);
    const owned = try value_mod.clone(?O.Value, gpa, op.commit.metadata);
    return commit(O, owned, op.commit.floor);
}
