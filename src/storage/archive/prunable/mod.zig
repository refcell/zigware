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
const oversized = @import("../../journal/segmented/oversized.zig");
const freezer_records = @import("../../freezer/records.zig");

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
}
