//! Shared codecs for QMDB operations (qmdb/operation.rs).
//!
//! commonware's `Floored`, `Operation`, and `Committable` traits become declarations on each
//! operation type: `inactivity_floor() ?u64`, `key() ?*const Key`, `is_update()`,
//! `is_delete()`, and `is_commit()`. Locations are plain `u64`s; a location encodes as a
//! `UInt<u64>` varint and decoding refuses one above the family's `max_leaves`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../merkle/mod.zig");

// One wire-tag table serves every database, so no tag stands for two kinds of operation; an
// encoded operation opens with its tag (commonware's `qmdb::operation` contexts).

/// Wire tag for a commit operation; every database tags its commits alike.
pub const commit_context: u8 = 0;
/// Wire tag for an update operation of an any or current database.
pub const update_context: u8 = 1;
/// Wire tag for a delete operation of an any or current database.
pub const delete_context: u8 = 2;
/// Wire tag for a set operation of an immutable database.
pub const set_context: u8 = 3;
/// Wire tag for an append operation of a keyless database.
pub const append_context: u8 = 4;

/// Writes `location` as a varint (commonware's `Location::write`).
pub fn write_location(location: u64, writer: *codec.Writer) void {
    codec.varint.write(u64, location, writer);
}

/// Encoded size of `location`.
pub fn location_size(location: u64) usize {
    return codec.varint.size(u64, location);
}

/// Reads a location and refuses one above `F.max_leaves` (commonware's `Location::read`).
pub fn read_location(comptime F: type, reader: *codec.Reader) codec.Error!u64 {
    merkle.check_family(F);
    const location = try codec.varint.read(u64, reader);
    if (!merkle.location_is_valid(F, location)) {
        return reader.invalid("Location", "value exceeds MAX_LEAVES");
    }
    return location;
}

/// `Location::arbitrary`: a location in `0..=F.max_leaves`.
pub fn arbitrary_location(comptime F: type, u: *codec.arbitrary.Unstructured) u64 {
    const location = u.int_in_range(u64, 0, F.max_leaves);
    assert(merkle.location_is_valid(F, location));
    return location;
}

/// A commit operation's payload: optional metadata and the inactivity floor it declares.
pub fn Commit(comptime V: type) type {
    return struct {
        metadata: ?V,
        floor: u64,
    };
}

/// Unpadded size of a fixed-encoded commit operation, context byte included.
pub fn commit_fixed_operation_size(comptime V: type) usize {
    const value_size = codec.fixed_size(V).?;
    return 1 + 1 + value_size + 8;
}

/// Writes a commit's metadata and floor in the fixed encoding: a present flag, the value or
/// zeros, then the floor as a big-endian u64.
pub fn write_commit_fixed(comptime V: type, commit: Commit(V), writer: *codec.Writer) void {
    const value_size = codec.fixed_size(V).?;
    const start = writer.end;
    if (commit.metadata) |metadata| {
        codec.write(bool, true, writer);
        codec.write(V, metadata, writer);
    } else {
        writer.write_byte_n(0, 1 + value_size);
    }
    writer.write_int(u64, commit.floor);
    assert(writer.end - start == commit_fixed_operation_size(V) - 1);
}

/// Reads a commit's metadata and floor from the fixed encoding.
pub fn read_commit_fixed(
    comptime F: type,
    comptime V: type,
    gpa: Allocator,
    reader: *codec.Reader,
) codec.Error!Commit(V) {
    const value_size = codec.fixed_size(V).?;
    const metadata: ?V = if (try codec.read(bool, gpa, reader))
        try codec.read(V, gpa, reader)
    else none: {
        try codec.util.ensure_zeros(reader, value_size);
        break :none null;
    };
    const floor = try reader.read_int(u64);
    if (!merkle.location_is_valid(F, floor)) {
        return reader.invalid("storage::qmdb::operation::commit", "commit floor location overflow");
    }
    return .{ .metadata = metadata, .floor = floor };
}

/// Encoded size of a variable-encoded commit payload.
pub fn commit_variable_payload_size(comptime V: type, commit: Commit(V)) usize {
    return codec.encode_size(?V, commit.metadata) + location_size(commit.floor);
}

/// Writes a commit's metadata and floor in the variable encoding.
pub fn write_commit_variable(comptime V: type, commit: Commit(V), writer: *codec.Writer) void {
    codec.write(?V, commit.metadata, writer);
    write_location(commit.floor, writer);
}

/// Reads a commit's metadata and floor from the variable encoding.
pub fn read_commit_variable(
    comptime F: type,
    comptime V: type,
    gpa: Allocator,
    reader: *codec.Reader,
    cfg: codec.Cfg(V),
) codec.Error!Commit(V) {
    const metadata = try codec.read_cfg(?V, gpa, reader, cfg);
    errdefer codec.free(?V, gpa, metadata);
    const floor = try read_location(F, reader);
    return .{ .metadata = metadata, .floor = floor };
}

/// Formats a commit as commonware's `Display` does: `[commit <hex> floor:<n>]`.
pub fn format_commit(
    comptime V: type,
    commit: Commit(V),
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    if (commit.metadata) |metadata| {
        try writer.writeAll("[commit ");
        try format_encoded(V, metadata, writer);
        try writer.print(" floor:{d}]", .{commit.floor});
    } else {
        try writer.print("[commit floor:{d}]", .{commit.floor});
    }
}

/// Longest encoding `format_encoded` prints in full.
pub const format_encoded_max = 4096;

/// Writes the lowercase hex of `value`'s encoding (commonware's `hex(&value.encode())`).
/// Formatting does not allocate, so an encoding longer than `format_encoded_max` prints as
/// `<N bytes>` instead.
pub fn format_encoded(
    comptime V: type,
    value: V,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    var buffer: [format_encoded_max]u8 = undefined;
    const size = codec.encode_size(V, value);
    if (size > buffer.len) return writer.print("<{d} bytes>", .{size});
    const encoded = codec.encode_to(V, value, &buffer);
    assert(encoded.len == size);
    try writer.print("{x}", .{encoded});
}

const testing = std.testing;

test "fixed commit layout" {
    const F = merkle.mmr.Family;
    var buffer: [18]u8 = undefined;
    var writer = codec.Writer.init(buffer[1..]);
    write_commit_fixed(u64, .{ .metadata = 7, .floor = 9 }, &writer);
    try testing.expectEqual(@as(usize, 17), writer.end);
    var reader = codec.Reader.init(writer.written());
    const commit = try read_commit_fixed(F, u64, testing.allocator, &reader);
    try testing.expectEqual(@as(?u64, 7), commit.metadata);
    try testing.expectEqual(@as(u64, 9), commit.floor);
}

/// Decodes `value`'s varint encoding as a location of family `F`.
fn decode_location(comptime F: type, value: u64) !u64 {
    var buffer: [10]u8 = undefined;
    var writer = codec.Writer.init(&buffer);
    write_location(value, &writer);
    var reader = codec.Reader.init(writer.written());
    const location = read_location(F, &reader) catch |err| {
        try testing.expectEqualStrings("Location", reader.diagnostic.context);
        return err;
    };
    try testing.expectEqual(@as(usize, 0), reader.remaining());
    return location;
}

// merkle/mmr/mod.rs `test_location_read_cfg_valid_values`.
test "location read accepts every value up to max_leaves" {
    const F = merkle.mmr.Family;
    for ([_]u64{ 0, 12345, F.max_leaves - 1, F.max_leaves }) |value| {
        try testing.expectEqual(value, try decode_location(F, value));
    }
}

// merkle/mmr/mod.rs `test_location_read_cfg_invalid_values`.
test "location read refuses values beyond max_leaves" {
    const F = merkle.mmr.Family;
    for ([_]u64{ F.max_leaves + 1, std.math.maxInt(u64) }) |value| {
        try testing.expectError(error.Invalid, decode_location(F, value));
    }
}
