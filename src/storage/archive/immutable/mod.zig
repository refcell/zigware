//! The immutable archive (commonware's `archive/immutable`): a freezer for keys and values, an
//! ordinal from index to freezer cursor, and metadata holding both stores' checkpoints.
//!
//! # Format
//!
//! Each metadata value is a `Record`: tag `0` and a freezer `Checkpoint`, or tag `1` and the
//! ordinal's committed bitmap of one section (`Option<BitMap>`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const runtime = @import("runtime");
const freezer = @import("../../freezer/mod.zig");
const storage = @import("storage.zig");

pub const Archive = storage.Archive;

/// Configuration for an immutable `Archive(K, V)`.
pub fn Config(comptime V: type) type {
    return struct {
        /// Partition of the commit record (freezer checkpoint and ordinal section bitmaps).
        metadata_partition: []const u8,
        /// Partition of the freezer table.
        freezer_table_partition: []const u8,
        /// Initial number of freezer table entries (a power of two).
        freezer_table_initial_size: u32,
        /// Items added to half the table entries since the last resize before the next.
        freezer_table_resize_frequency: u8,
        /// Table entries split per sync during a resize.
        freezer_table_resize_chunk_size: u32,
        /// Partition of the freezer key journal.
        freezer_key_partition: []const u8,
        /// Page cache of the freezer key journal.
        freezer_key_cache_ref: *runtime.buffer.paged.CacheRef,
        /// Partition of the freezer value journal.
        freezer_value_partition: []const u8,
        /// Target size of each freezer value section.
        freezer_value_target_size: u64,
        /// Optional zstd compression level for values. Keep the choice between none and some
        /// fixed for the life of the archive.
        freezer_value_compression: ?u8 = null,
        /// Partition of the ordinal (index to freezer cursor).
        ordinal_partition: []const u8,
        /// Items per ordinal section, fixed for the life of the data.
        items_per_section: u64,
        /// Write buffer of the freezer key journal.
        freezer_key_write_buffer: usize,
        /// Write buffer of the freezer value journal.
        freezer_value_write_buffer: usize,
        /// Write buffer of each ordinal blob.
        ordinal_write_buffer: usize,
        /// Read buffer for replaying the freezer table and the ordinal.
        replay_buffer: usize,
        /// Codec configuration of values.
        codec_config: codec.Cfg(V),

        pub fn validate(config: @This()) void {
            assert(config.items_per_section > 0);
            assert(config.replay_buffer > 0 and config.ordinal_write_buffer > 0);
            assert(std.math.isPowerOfTwo(config.freezer_table_initial_size));
        }
    };
}

/// The ordinal's committed-record bitmap (commonware's default `BitMap`).
pub const BitMap = utils.bitmap.DefaultBitMap;

/// Metadata key prefix of the freezer checkpoint.
pub const freezer_prefix: u8 = 0;
/// Metadata key prefix of the ordinal sections' bitmaps.
pub const ordinal_prefix: u8 = 1;

/// A metadata value of the immutable archive.
pub const Record = union(enum) {
    freezer: freezer.Checkpoint,
    ordinal: ?BitMap,

    pub fn write(record: Record, writer: *codec.Writer) void {
        switch (record) {
            .freezer => |checkpoint| {
                writer.write_byte(0);
                codec.write(freezer.Checkpoint, checkpoint, writer);
            },
            .ordinal => |bits| {
                writer.write_byte(1);
                codec.write(?BitMap, bits, writer);
            },
        }
    }

    pub fn encode_size(record: Record) usize {
        return 1 + switch (record) {
            .freezer => freezer.Checkpoint.fixed_size,
            .ordinal => |bits| codec.encode_size(?BitMap, bits),
        };
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Record {
        const tag = try reader.read_byte();
        return switch (tag) {
            0 => .{ .freezer = try codec.read_fixed(freezer.Checkpoint, reader) },
            1 => .{ .ordinal = try codec.read_cfg(?BitMap, gpa, reader, .full()) },
            else => reader.fail(error.InvalidEnum, tag),
        };
    }

    pub fn deinit(record: *Record, gpa: Allocator) void {
        switch (record.*) {
            .freezer => {},
            .ordinal => |bits| codec.free(?BitMap, gpa, bits),
        }
        record.* = undefined;
    }

    /// `#[derive(Arbitrary)]`: a variant index, then the variant's field.
    pub fn arbitrary(
        gpa: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Record {
        // arbitrary 1.4's derive: `(u64::from(u32) * variants) >> 32`.
        const variant = (@as(u64, u.int(u32)) * 2) >> 32;
        return switch (variant) {
            0 => .{ .freezer = try freezer.Checkpoint.arbitrary(gpa, u) },
            1 => .{ .ordinal = try codec.arbitrary.value(?BitMap, gpa, u) },
            else => unreachable,
        };
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("conformance_test.zig");
    _ = @import("tests.zig");
    _ = @import("fuzz_test.zig");
}

test "immutable archive record round trip" {
    const gpa = std.testing.allocator;
    var bits = try BitMap.zeroes(gpa, 10);
    defer bits.deinit(gpa);
    bits.set(3, true);
    const records = [_]Record{
        .{ .freezer = .{ .epoch = 1, .section = 2, .oversized_size = 3, .table_size = 4 } },
        .{ .ordinal = bits },
        .{ .ordinal = null },
    };
    for (records) |record| {
        const bytes = try codec.encode(Record, gpa, record);
        defer gpa.free(bytes);
        try std.testing.expectEqual(record.encode_size(), bytes.len);
        var decoded = try codec.decode(Record, gpa, bytes);
        defer decoded.deinit(gpa);
        const again = try codec.encode(Record, gpa, decoded);
        defer gpa.free(again);
        try std.testing.expectEqualSlices(u8, bytes, again);
    }
    try std.testing.expectError(error.InvalidEnum, codec.decode(Record, gpa, &.{2}));
}
