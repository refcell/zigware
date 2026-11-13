//! An immutable key-value store for ordered data with a minimal memory footprint.
//!
//! Port of commonware's `storage/src/freezer`. The on-disk records (`records.zig`) are ported
//! with their conformance hashes; the `Freezer` itself (the hash table over the oversized
//! segmented journal) lands once that journal does.

const std = @import("std");

const records = @import("records.zig");
pub const Cursor = records.Cursor;
pub const Checkpoint = records.Checkpoint;
pub const Entry = records.Entry;
pub const Record = records.Record;

test {
    std.testing.refAllDecls(@This());
    _ = records;
    _ = @import("conformance_test.zig");
}
