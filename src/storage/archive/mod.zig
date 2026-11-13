//! A write-once key-value store for ordered data.
//!
//! Port of commonware's `storage/src/archive`. An archive stores items written once and
//! addressed by both an `index` and a `key`. Commonware's `Archive` and `MultiArchive` traits
//! become a comptime interface over the prunable (index + oversized journal) and immutable
//! (freezer + ordinal + metadata) implementations. The on-disk records of both are ported here
//! with their conformance hashes; the archives themselves land with the oversized journal.

const std = @import("std");

pub const prunable = @import("prunable/mod.zig");
pub const immutable = @import("immutable/mod.zig");

/// Subject of a `get` or `has` operation.
pub fn Identifier(comptime K: type) type {
    return union(enum) {
        index: u64,
        key: *const K,
    };
}

/// Archive-specific errors (commonware's `archive::Error`). Journal, ordinal, metadata, and
/// freezer failures keep their own error names in an implementation's error set.
pub const Error = error{
    /// A stored record failed its checksum or did not decode.
    RecordCorrupted,
};

test {
    std.testing.refAllDecls(@This());
}
