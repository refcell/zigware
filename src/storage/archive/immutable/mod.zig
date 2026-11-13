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
const freezer = @import("../../freezer/mod.zig");

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
