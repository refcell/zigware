//! A partitioned unordered index (port of commonware's
//! `storage/src/index/partitioned/unordered.rs`): commonware keeps one unordered index per
//! partition, which behaves exactly like one unordered index over `(partition, sub-key)`.

const partitioned = @import("mod.zig");
const unordered = @import("../unordered.zig");

/// An unordered index whose first `P` key bytes select a partition and translator `T` maps the
/// rest. Initialize with `init(gpa, Translator(T, P).init(t))`.
pub fn Index(comptime T: type, comptime V: type, comptime P: usize) type {
    return unordered.Index(partitioned.Translator(T, P), V);
}
