//! A prunable cache for ordered data with index-based lookups.
//!
//! Port of commonware's `storage/src/cache`. Data is stored in a variable segmented journal
//! (an append-only log) and the location of written data is tracked in memory by index, so a
//! lookup of cached data is a single read.
//!
//! Unlike an archive, the cache does not support key-based lookups (only index-based access),
//! which makes it a fit for caching sequential data whose index the caller knows.
//!
//! # Pruning
//!
//! `prune(min)` removes every section below the one holding `min`. After pruning, `get` on a
//! pruned index returns null, `prune` below the floor is a no-op, and `put` below the floor is
//! satisfied without storing. The pruning granularity is `items_per_blob`.
//!
//! # Compression
//!
//! Keep the choice between no compression and some compression fixed while stored items are
//! retained. Only the level may change between initializations.
//!
//! # Querying for gaps
//!
//! The cache tracks the ranges of stored indices, so `next_gap` and `missing_items` find the
//! unknown indices a caller should fetch (the common pattern when syncing blocks).
//!
//! # Format
//!
//! Each journal item is a `Record`: the index as a varint followed by the encoded value,
//! byte-identical to commonware's.

const std = @import("std");
const codec = @import("codec");
const runtime = @import("runtime");

const storage = @import("storage.zig");
pub const Cache = storage.Cache;
pub const Record = storage.Record;

/// Configuration for a `Cache(V)`.
pub fn Config(comptime V: type) type {
    return struct {
        /// The partition used for the cache's journal.
        partition: []const u8,
        /// The zstd compression level of the journal, or null for none.
        compression: ?u8 = null,
        /// The codec configuration used to decode values.
        codec_config: codec.Cfg(V),
        /// The number of items per section (the granularity of pruning).
        items_per_blob: u64,
        /// Bytes buffered in a section before being written to its blob.
        write_buffer: usize,
        /// The buffer size used when replaying a blob.
        replay_buffer: usize,
        /// The page cache shared by the journal's sections.
        cache_ref: *runtime.buffer.paged.CacheRef,
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
    _ = @import("conformance_test.zig");
}
