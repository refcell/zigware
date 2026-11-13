//! Indices: memory-efficient maps from keys to values that store a translated (usually
//! shortened) key, so keys that translate alike collide and share a list of values.
//!
//! Port of commonware's `storage/src/index`. Commonware's `Unordered`, `Ordered`, and `Cursor`
//! traits become one comptime-generic type, `storage.Index(T, V, Heads)`: `unordered.Index` keeps
//! its heads in a hash map and `ordered.Index` in a search tree, which adds
//! `first/last/prev/next_translated_key`. Closures become a context value plus a comptime
//! function. Commonware's `keys`/`items`/`pruned` metrics are the counters of the same names.
//! `partitioned` adds the indices whose first `P` key bytes select a partition.

pub const storage = @import("storage.zig");
pub const unordered = @import("unordered.zig");
pub const ordered = @import("ordered.zig");
pub const partitioned = @import("partitioned/mod.zig");
pub const immutable = @import("immutable.zig");
pub const Values = storage.Values;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("tests.zig");
}
