//! The prunable archive (commonware's `archive/prunable`): an index over an oversized
//! segmented journal, pruned by section.
//!
//! # Format
//!
//! Each key index record is `index || key || value_offset || value_size` (big-endian), with the
//! value stored in the section's value journal.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const oversized = @import("../../journal/segmented/oversized.zig");
const freezer_records = @import("../../freezer/records.zig");
const storage = @import("storage.zig");

pub const Archive = storage.Archive;
pub const Positions = @import("sections.zig").Positions;

/// Configuration for a prunable `Archive(T, K, V)`. The partition name slices must outlive
/// the archive.
pub fn Config(comptime T: type, comptime V: type) type {
    return struct {
        /// Transforms keys into their in-memory representation. The archive assumes
        /// translated keys spread uniformly; otherwise lookups degrade toward O(n).
        translator: T,
        /// Partition of the per-section validation markers. Recovery adopts entries below a
        /// section's marker without re-validating their values.
        metadata_partition: []const u8,
        /// Partition of the key journal (index + key records).
        key_partition: []const u8,
        /// Page cache of the key journal.
        key_cache_ref: *runtime.buffer.paged.CacheRef,
        /// Partition of the value journal.
        value_partition: []const u8,
        /// Optional zstd compression level for values. Keep the choice between none and some
        /// fixed while values are retained.
        compression: ?u8 = null,
        /// Codec configuration of values.
        codec_config: codec.Cfg(V),
        /// Items per section (the granularity of pruning), fixed for the life of the data:
        /// `init` fails with `RecordCorrupted` when a stored record's section no longer
        /// matches its index.
        items_per_section: u64,
        /// Bytes buffered for the key journal before a blob write.
        key_write_buffer: usize,
        /// Bytes buffered for the value journal before a blob write.
        value_write_buffer: usize,
        /// Buffer size for replaying the key journal.
        replay_buffer: usize,

        pub fn validate(config: @This()) void {
            assert(config.items_per_section > 0);
            assert(config.key_write_buffer > 0 and config.value_write_buffer > 0);
            assert(config.replay_buffer > 0);
        }
    };
}

/// A key index record of the prunable archive.
pub fn Record(comptime K: type) type {
    const key_size = codec.fixed_size(K) orelse @compileError("archive keys are fixed-size");
    comptime assert(!codec.owns_memory(K));
    return struct {
        const Self = @This();
        pub const fixed_size: usize = 8 + key_size + 8 + 4;

        index: u64,
        key: K,
        /// Byte offset in the value journal (same section).
        value_offset: u64,
        /// Size of the value in the value journal.
        value_size: u32,

        /// The value's `(offset, size)` in the value journal (commonware's `OversizedRecord`).
        pub fn value_location(record: Self) oversized.Location {
            return .{ .offset = record.value_offset, .size = record.value_size };
        }

        pub fn with_location(record: Self, value_offset: u64, value_size: u32) Self {
            var result = record;
            result.value_offset = value_offset;
            result.value_size = value_size;
            return result;
        }

        pub fn write(record: Self, writer: *codec.Writer) void {
            writer.write_int(u64, record.index);
            codec.write(K, record.key, writer);
            writer.write_int(u64, record.value_offset);
            writer.write_int(u32, record.value_size);
        }

        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{
                .index = try reader.read_int(u64),
                .key = try codec.read_fixed(K, reader),
                .value_offset = try reader.read_int(u64),
                .value_size = try reader.read_int(u32),
            };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return .{
                .index = u.int(u64),
                .key = try freezer_records.arbitrary_key(K, gpa, u),
                .value_offset = u.int(u64),
                .value_size = u.int(u32),
            };
        }
    };
}

test {
    std.testing.refAllDecls(@This());
    comptime assert(codec.fixed_size(Record([8]u8)).? == 28);
    _ = @import("conformance_test.zig");
    _ = @import("sections.zig");
    _ = @import("tests.zig");
    _ = @import("fuzz_test.zig");
}
