//! The freezer's on-disk records (commonware's `freezer/storage.rs` codec types), byte-identical
//! to commonware's.
//!
//! - `Cursor`: the location of a value, `section || offset || size` (20 bytes, big-endian).
//! - `Checkpoint`: the committed progress, `epoch || section || oversized_size || table_size`.
//! - `Entry`: one slot of a table entry, `epoch || section || position || added || crc`, where
//!   the CRC32C covers the other fields' big-endian bytes. Each table entry holds two slots.
//! - `Record(K)`: a key index record, `key || next_section || next_position || value_offset ||
//!   value_size`, with `(u64 max, u64 max)` as the "no next" sentinel.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const oversized = @import("../journal/segmented/oversized.zig");
const cryptography = @import("cryptography");

/// Location of an item in the freezer, for reading its value without walking its chain.
pub const Cursor = struct {
    bytes: [fixed_size]u8,

    pub const fixed_size: usize = 8 + 8 + 4;

    pub fn init(section_value: u64, offset_value: u64, size_value: u32) Cursor {
        var cursor: Cursor = undefined;
        std.mem.writeInt(u64, cursor.bytes[0..8], section_value, .big);
        std.mem.writeInt(u64, cursor.bytes[8..16], offset_value, .big);
        std.mem.writeInt(u32, cursor.bytes[16..20], size_value, .big);
        assert(cursor.section() == section_value and cursor.size() == size_value);
        return cursor;
    }

    pub fn section(cursor: Cursor) u64 {
        return std.mem.readInt(u64, cursor.bytes[0..8], .big);
    }

    pub fn offset(cursor: Cursor) u64 {
        return std.mem.readInt(u64, cursor.bytes[8..16], .big);
    }

    pub fn size(cursor: Cursor) u32 {
        return std.mem.readInt(u32, cursor.bytes[16..20], .big);
    }

    pub fn write(cursor: Cursor, writer: *codec.Writer) void {
        writer.write_bytes(&cursor.bytes);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Cursor {
        return .{ .bytes = (try reader.take_array(fixed_size)).* };
    }

    pub fn order(a: Cursor, b: Cursor) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }

    /// `#[derive(Arbitrary)]` over the byte array.
    pub fn arbitrary(_: Allocator, u: *codec.arbitrary.Unstructured) codec.arbitrary.Error!Cursor {
        var cursor: Cursor = undefined;
        u.fill(&cursor.bytes);
        return cursor;
    }
};

/// Marker of freezer progress, used to restore a consistent state after shutdown.
pub const Checkpoint = struct {
    /// The epoch of the last committed operation.
    epoch: u64 = 0,
    /// The section of the last committed operation.
    section: u64 = 0,
    /// The size of the oversized index journal in the last committed section.
    oversized_size: u64 = 0,
    /// The size of the table.
    table_size: u32 = 0,

    pub const fixed_size: usize = 8 + 8 + 8 + 4;

    pub fn init(table_size: u32) Checkpoint {
        return .{ .table_size = table_size };
    }

    /// Whether this checkpoint represents a fresh freezer.
    pub fn is_empty(checkpoint: Checkpoint) bool {
        return checkpoint.epoch == 0 and checkpoint.section == 0 and
            checkpoint.oversized_size == 0 and checkpoint.table_size == 0;
    }

    pub fn write(checkpoint: Checkpoint, writer: *codec.Writer) void {
        writer.write_int(u64, checkpoint.epoch);
        writer.write_int(u64, checkpoint.section);
        writer.write_int(u64, checkpoint.oversized_size);
        writer.write_int(u32, checkpoint.table_size);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Checkpoint {
        return .{
            .epoch = try reader.read_int(u64),
            .section = try reader.read_int(u64),
            .oversized_size = try reader.read_int(u64),
            .table_size = try reader.read_int(u32),
        };
    }

    /// `#[derive(Arbitrary)]`: the fields in order.
    pub fn arbitrary(
        _: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Checkpoint {
        return .{
            .epoch = u.int(u64),
            .section = u.int(u64),
            .oversized_size = u.int(u64),
            .table_size = u.int(u32),
        };
    }
};

/// One slot of a table entry.
pub const Entry = struct {
    /// Epoch in which this slot was written.
    epoch: u64 = 0,
    /// Section in which this slot was written.
    section: u64 = 0,
    /// Position in the key index of that section.
    position: u64 = 0,
    /// Items added to this entry since the last resize.
    added: u8 = 0,
    /// CRC32C of `epoch || section || position || added`.
    crc: u32 = 0,

    pub const fixed_size: usize = 8 + 8 + 8 + 1 + 4;
    /// A table entry holds two slots.
    pub const full_size: usize = 2 * fixed_size;
    pub const empty: Entry = .{};

    pub fn compute_crc(epoch: u64, section: u64, position: u64, added: u8) u32 {
        var bytes: [25]u8 = undefined;
        std.mem.writeInt(u64, bytes[0..8], epoch, .big);
        std.mem.writeInt(u64, bytes[8..16], section, .big);
        std.mem.writeInt(u64, bytes[16..24], position, .big);
        bytes[24] = added;
        return cryptography.Crc32.checksum(&bytes);
    }

    pub fn init(epoch: u64, section: u64, position: u64, added: u8) Entry {
        const entry: Entry = .{
            .epoch = epoch,
            .section = section,
            .position = position,
            .added = added,
            .crc = compute_crc(epoch, section, position, added),
        };
        if (std.debug.runtime_safety) assert(entry.is_valid()); // Recomputes the CRC.
        return entry;
    }

    /// Whether every field is zero (a slot never written).
    pub fn is_empty(entry: Entry) bool {
        return entry.epoch == 0 and entry.section == 0 and entry.position == 0 and
            entry.added == 0 and entry.crc == 0;
    }

    /// Whether the checksum matches. An empty slot is not valid.
    pub fn is_valid(entry: Entry) bool {
        return compute_crc(entry.epoch, entry.section, entry.position, entry.added) == entry.crc;
    }

    pub fn write(entry: Entry, writer: *codec.Writer) void {
        writer.write_int(u64, entry.epoch);
        writer.write_int(u64, entry.section);
        writer.write_int(u64, entry.position);
        writer.write_int(u8, entry.added);
        writer.write_int(u32, entry.crc);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Entry {
        return .{
            .epoch = try reader.read_int(u64),
            .section = try reader.read_int(u64),
            .position = try reader.read_int(u64),
            .added = try reader.read_int(u8),
            .crc = try reader.read_int(u32),
        };
    }

    /// `#[derive(Arbitrary)]`: the fields in order (the CRC is arbitrary too).
    pub fn arbitrary(_: Allocator, u: *codec.arbitrary.Unstructured) codec.arbitrary.Error!Entry {
        return .{
            .epoch = u.int(u64),
            .section = u.int(u64),
            .position = u.int(u64),
            .added = u.int(u8),
            .crc = u.int(u32),
        };
    }
};

/// Sentinel `next` marking the end of a collision chain.
pub const no_next_section: u64 = std.math.maxInt(u64);
pub const no_next_position: u64 = std.math.maxInt(u64);

/// A key index record: the key, the next record of its collision chain, and where its value is.
pub fn Record(comptime K: type) type {
    const key_size = codec.fixed_size(K) orelse @compileError("freezer keys are fixed-size");
    comptime assert(!codec.owns_memory(K));
    return struct {
        const Self = @This();
        pub const fixed_size: usize = key_size + 8 + 8 + 8 + 4;

        key: K,
        next_section: u64,
        next_position: u64,
        value_offset: u64,
        value_size: u32,

        pub fn init(key: K, next_link: ?[2]u64, value_offset: u64, value_size: u32) Self {
            const link = next_link orelse .{ no_next_section, no_next_position };
            const record: Self = .{
                .key = key,
                .next_section = link[0],
                .next_position = link[1],
                .value_offset = value_offset,
                .value_size = value_size,
            };
            assert((record.next() == null) == (next_link == null));
            return record;
        }

        /// The next record of the collision chain as `(section, position)`, if any.
        pub fn next(record: Self) ?[2]u64 {
            if (record.next_section == no_next_section and
                record.next_position == no_next_position) return null;
            return .{ record.next_section, record.next_position };
        }

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
            codec.write(K, record.key, writer);
            writer.write_int(u64, record.next_section);
            writer.write_int(u64, record.next_position);
            writer.write_int(u64, record.value_offset);
            writer.write_int(u32, record.value_size);
        }

        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{
                .key = try codec.read_fixed(K, reader),
                .next_section = try reader.read_int(u64),
                .next_position = try reader.read_int(u64),
                .value_offset = try reader.read_int(u64),
                .value_size = try reader.read_int(u32),
            };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return .{
                .key = try arbitrary_key(K, gpa, u),
                .next_section = u.int(u64),
                .next_position = u.int(u64),
                .value_offset = u.int(u64),
                .value_size = u.int(u32),
            };
        }
    };
}

/// A key the way its Rust `Arbitrary` impl draws it: the type's own `arbitrary`, or byte by
/// byte for byte-array newtypes (`FixedBytes`, `U64`), whose derived impl reads one `u8` each.
pub fn arbitrary_key(
    comptime K: type,
    gpa: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!K {
    if (@typeInfo(K) == .@"struct" and !@hasDecl(K, "arbitrary") and @hasField(K, "bytes")) {
        var key: K = undefined;
        u.fill(&key.bytes);
        return key;
    }
    return codec.arbitrary.value(K, gpa, u);
}

const testing = std.testing;

test "freezer record layouts" {
    comptime assert(codec.fixed_size(Cursor).? == 20);
    comptime assert(codec.fixed_size(Checkpoint).? == 28);
    comptime assert(codec.fixed_size(Entry).? == 29);
    comptime assert(codec.fixed_size(Record([8]u8)).? == 36);
    const cursor = Cursor.init(1, 2, 3);
    try testing.expectEqual(@as(u64, 1), cursor.section());
    try testing.expectEqual(@as(u64, 2), cursor.offset());
    try testing.expectEqual(@as(u32, 3), cursor.size());
    try testing.expect(Entry.empty.is_empty());
    try testing.expect(!Entry.empty.is_valid());
    var entry = Entry.init(1, 2, 3, 4);
    try testing.expect(entry.is_valid());
    entry.added = 5;
    try testing.expect(!entry.is_valid());
    try testing.expect(Checkpoint.is_empty(.{}));
    try testing.expect(!Checkpoint.init(4).is_empty());
    const R = Record([8]u8);
    try testing.expectEqual(@as(?[2]u64, null), R.init(@splat(1), null, 0, 0).next());
    const linked = R.init(@splat(1), .{ 3, 4 }, 0, 0).next().?;
    try testing.expectEqual([2]u64{ 3, 4 }, linked);
}
