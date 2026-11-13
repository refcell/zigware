//! An immutable key-value store optimized for minimal memory usage and write amplification.
//!
//! Port of commonware's `storage/src/freezer`. A freezer is a key-value store for permanent
//! data written once and never modified. It keeps every structure on disk and never rewrites
//! (compacts) inserted data.
//!
//! # Format
//!
//! - A table blob maps `crc32c(key) & (table_size - 1)` to the head of a collision chain. Each
//!   table entry is two `Entry` slots (`epoch || section || position || added || crc`); a
//!   write goes to the slot of the current epoch, or else to the older or empty one.
//! - Key `Record`s (`key || next_section || next_position || value_offset || value_size`) live
//!   in the fixed index of an oversized segmented journal; values live in its glob. Each record
//!   links to the previous head of its chain.
//!
//! # Checkpoints and recovery
//!
//! `sync` returns a `Checkpoint` (`epoch || section || oversized_size || table_size`). `init`
//! with that checkpoint restores exactly the synced state: the journal is truncated to the
//! checkpoint, the table is shrunk to its size, and table slots that are invalid or newer than
//! its epoch are cleared. A null or empty checkpoint deletes everything and starts empty.
//!
//! # Resizing
//!
//! Once half of the table's entries have had `table_resize_frequency` items added since the
//! last resize, `sync` doubles the table and splits `table_resize_chunk_size` entries per sync.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const runtime = @import("runtime");

const records = @import("records.zig");
const storage = @import("storage.zig");
pub const Cursor = records.Cursor;
pub const Checkpoint = records.Checkpoint;
pub const Entry = records.Entry;
pub const Record = records.Record;
pub const Freezer = storage.Freezer;
pub const table_blob_name = storage.table_blob_name;

/// Configuration for a `Freezer(K, V)`.
pub fn Config(comptime V: type) type {
    return struct {
        /// Partition of the key index journal.
        key_partition: []const u8,
        /// Write buffer size of the key index journal.
        key_write_buffer: usize,
        /// Page cache of the key index journal.
        key_cache_ref: *runtime.buffer.paged.CacheRef,
        /// Partition of the value journal.
        value_partition: []const u8,
        /// Optional zstd compression level for values. Keep the choice between none and some
        /// fixed while values are retained.
        value_compression: ?u8 = null,
        /// Write buffer size of the value journal.
        value_write_buffer: usize,
        /// Target size of each value section before a new one starts.
        value_target_size: u64,
        /// Partition of the table blob.
        table_partition: []const u8,
        /// Initial number of table entries (a power of two).
        table_initial_size: u32,
        /// Items added to half the entries since the last resize before the next resize.
        table_resize_frequency: u8,
        /// Entries split per sync during a resize.
        table_resize_chunk_size: u32,
        /// Read buffer size for table scans (recovery) and the journal's replay.
        table_replay_buffer: usize,
        /// Codec configuration of values.
        codec_config: codec.Cfg(V),

        pub fn validate(config: @This()) void {
            assert(config.table_initial_size > 0);
            assert(std.math.isPowerOfTwo(config.table_initial_size));
            assert(config.table_resize_chunk_size > 0);
            assert(config.key_write_buffer > 0 and config.value_write_buffer > 0);
            assert(config.table_replay_buffer > 0);
        }
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = records;
    _ = @import("conformance_test.zig");
    _ = @import("tests.zig");
}
