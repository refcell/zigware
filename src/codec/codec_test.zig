//! Tests for the core encode/decode operations (codec/src/codec.rs tests).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec.zig");
const buf = @import("buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("error.zig").Error;
const Bytes = @import("types/bytes.zig").Bytes;

const gpa = testing.allocator;

test "insufficient buffer" {
    var reader = Reader.init(&.{ 0x01, 0x02 });
    try testing.expectError(error.EndOfBuffer, codec.read(u32, gpa, &reader));
}

test "extra data" {
    var reader = Reader.init(&.{ 0x01, 0x02 });
    try testing.expectError(error.ExtraData, codec.decode_reader(u8, gpa, &reader, {}));
    try testing.expectEqual(@as(u64, 1), reader.diagnostic.value);
}

test "encode fixed" {
    const encoded = codec.encode_fixed(u32, 42);
    try testing.expectEqual(@as(usize, 4), encoded.len);
    try testing.expectEqual(@as(u32, 42), try codec.decode(u32, gpa, &encoded));
}

test "pointer codec (Arc)" {
    const inner: []const u8 = &.{ 1, 2, 3 };
    const encoded = try codec.encode(*const []const u8, gpa, &inner);
    defer gpa.free(encoded);
    const plain = try codec.encode([]const u8, gpa, inner);
    defer gpa.free(plain);
    try testing.expectEqualSlices(u8, plain, encoded);
    try testing.expectEqual(
        codec.encode_size([]const u8, inner),
        codec.encode_size(*const []const u8, &inner),
    );

    const T = *const []const u8;
    const decoded = try codec.decode_cfg(T, gpa, encoded, .{ .range = .to_inclusive(3) });
    defer codec.free(T, gpa, decoded);
    try testing.expectEqualSlices(u8, inner, decoded.*);

    var reader = Reader.init(encoded);
    const short_cfg: codec.Cfg(T) = .{ .range = .to_inclusive(2) };
    try testing.expectError(error.InvalidLength, codec.read_cfg(T, gpa, &reader, short_cfg));
    try testing.expectEqual(@as(u64, 3), reader.diagnostic.value);
    try testing.expectError(
        error.EndOfBuffer,
        codec.decode_cfg(T, gpa, encoded[0 .. encoded.len - 1], .{ .range = .to_inclusive(3) }),
    );
}

/// A custom fixed-size type, as in commonware's `FixedBytes`.
const FixedBytes = struct {
    raw: [2]u8,
    pub const fixed_size = 2;

    pub fn write(self: FixedBytes, writer: *Writer) void {
        codec.write([2]u8, self.raw, writer);
    }

    pub fn read(gpa_: Allocator, reader: *Reader, _: void) Error!FixedBytes {
        return .{ .raw = try codec.read([2]u8, gpa_, reader) };
    }
};

test "custom fixed-size type" {
    const value = FixedBytes{ .raw = .{ 1, 2 } };
    try testing.expectEqual([2]u8{ 1, 2 }, codec.encode_fixed(FixedBytes, value));
    try testing.expectEqual(value, try codec.decode_fixed(FixedBytes, &.{ 1, 2 }));
    try testing.expectEqual(value, try codec.decode(FixedBytes, gpa, &.{ 1, 2 }));
    try testing.expectError(error.EndOfBuffer, codec.decode(FixedBytes, gpa, &.{1}));
    try testing.expectError(error.ExtraData, codec.decode(FixedBytes, gpa, &.{ 1, 2, 3 }));
    var reader = Reader.init(&.{ 1, 2 });
    try testing.expectEqual(value, try codec.read_fixed(FixedBytes, &reader));
}

/// A custom variable-size type with a config and owned memory, as in commonware's `Item`.
const Item = struct {
    id: u64,
    name: ?u32,
    metadata: []const u8,

    pub const Cfg = struct { max_metadata_len: usize };

    pub fn write(self: Item, writer: *Writer) void {
        codec.write(u64, self.id, writer);
        codec.write(?u32, self.name, writer);
        codec.write([]const u8, self.metadata, writer);
    }

    pub fn encode_size(self: Item) usize {
        return codec.encode_size(u64, self.id) + codec.encode_size(?u32, self.name) +
            codec.encode_size([]const u8, self.metadata);
    }

    pub fn read(allocator: Allocator, reader: *Reader, cfg: Cfg) Error!Item {
        const id = try codec.read(u64, allocator, reader);
        const name = try codec.read(?u32, allocator, reader);
        const range = codec.Cfg([]const u8){ .range = .to_inclusive(cfg.max_metadata_len) };
        const metadata = try codec.read_cfg([]const u8, allocator, reader, range);
        return .{ .id = id, .name = name, .metadata = metadata };
    }

    pub fn deinit(self: *Item, allocator: Allocator) void {
        allocator.free(self.metadata);
    }
};

test "custom variable-size type with config" {
    const item = Item{ .id = 101, .name = null, .metadata = &.{ 1, 2, 3 } };
    const encoded = try codec.encode(Item, gpa, item);
    defer gpa.free(encoded);
    try testing.expectEqual(@as(usize, 8 + 1 + 1 + 3), encoded.len);
    const decoded = try codec.decode_cfg(Item, gpa, encoded, .{ .max_metadata_len = 1024 });
    defer codec.free(Item, gpa, decoded);
    try testing.expectEqual(item.id, decoded.id);
    try testing.expectEqual(item.name, decoded.name);
    try testing.expectEqualSlices(u8, item.metadata, decoded.metadata);
    const short_cfg = Item.Cfg{ .max_metadata_len = 2 };
    try testing.expectError(error.InvalidLength, codec.decode_cfg(Item, gpa, encoded, short_cfg));

    // A slice of owning custom items frees every item.
    const items = [_]Item{ item, item };
    const many = try codec.encode([]const Item, gpa, &items);
    defer gpa.free(many);
    const cfg: codec.Cfg([]const Item) = .{ .range = .full(), .item = .{ .max_metadata_len = 8 } };
    const decoded_items = try codec.decode_cfg([]const Item, gpa, many, cfg);
    defer codec.free([]const Item, gpa, decoded_items);
    try testing.expectEqual(@as(usize, 2), decoded_items.len);
}

const Color = enum(u8) { red = 0, green = 1, blue = 7 };

test "tag enums" {
    try testing.expectEqual(@as(?usize, 1), codec.fixed_size(Color));
    try testing.expectEqual([1]u8{7}, codec.encode_fixed(Color, .blue));
    try testing.expectEqual(Color.green, try codec.decode(Color, gpa, &.{1}));
    var reader = Reader.init(&.{2});
    try testing.expectError(error.InvalidEnum, codec.read(Color, gpa, &reader));
    try testing.expectEqual(@as(u64, 2), reader.diagnostic.value);
}

test "free reports no leaks for nested owned values" {
    const T = struct { ?*const []const u16, [2][]const u8 };
    const inner: []const u16 = &.{ 1, 2 };
    const value: T = .{ &inner, .{ &.{9}, &.{} } };
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    const cfg: codec.Cfg(T) = .{ .{ .range = .full() }, .{ .range = .full() } };
    const decoded = try codec.decode_cfg(T, gpa, encoded, cfg);
    defer codec.free(T, gpa, decoded);
    try testing.expectEqualSlices(u16, inner, decoded[0].?.*);
    try testing.expectEqualSlices(u8, &.{9}, decoded[1][0]);
}

/// `#[fixed_array(bytes([u8; N]))]`: a generic fixed-size type (commonware's `GenericFixed`).
fn GenericFixed(comptime size: usize) type {
    return struct {
        raw: [size]u8,

        const Self = @This();
        pub const fixed_size = size;

        pub fn write(self: Self, writer: *Writer) void {
            writer.write_bytes(&self.raw);
        }

        pub fn read(_: Allocator, reader: *Reader, _: void) Error!Self {
            return .{ .raw = (try reader.take_array(size)).* };
        }
    };
}

test "generic fixed array conversions" {
    const Generic = GenericFixed(3);
    const generic: Generic = .{ .raw = .{ 1, 2, 3 } };
    try testing.expectEqual([3]u8{ 1, 2, 3 }, codec.encode_fixed(Generic, generic));
    try testing.expectEqual(generic, try codec.decode_fixed(Generic, &.{ 1, 2, 3 }));
    try testing.expectEqual(generic, try codec.decode(Generic, gpa, &.{ 1, 2, 3 }));
    var reader = Reader.init(&.{ 1, 2, 3, 4 });
    try testing.expectError(error.ExtraData, codec.decode_reader(Generic, gpa, &reader, {}));
    try testing.expectEqual(@as(u64, 1), reader.diagnostic.value);
}

// buf.rs `Viewing` tests: a Reader is a borrowed cursor, `Bytes` reads share its storage.

test "viewing scalar reads" {
    const encoded = "\x00\x00\x00\x07ab";
    var input = Reader.init(encoded);
    try testing.expectEqual(@as(u32, 7), try codec.read(u32, gpa, &input));
    var other = input;
    try testing.expectEqual("ab".*, try codec.read([2]u8, gpa, &input));
    try testing.expectEqual(@as(usize, 2), other.remaining());
    try testing.expectEqual("ab".*, try codec.read([2]u8, gpa, &other));
    try testing.expectEqual(@as(usize, 0), input.remaining());
    try testing.expectEqual(@as(usize, 0), input.rest().len);
}

test "viewing retained fields and split frames" {
    const encoded = "\x05hello\x05world";
    var input = Reader.init(encoded);
    // A frame longer than its field leaves trailing data.
    var overlong = input;
    const overlong_frame = try overlong.take(7);
    try testing.expectError(error.ExtraData, codec.decode_cfg(Bytes, gpa, overlong_frame, .full()));
    const first = try codec.decode_cfg(Bytes, gpa, try input.take(6), .full());
    try testing.expectEqual(@as([*]const u8, encoded[1..].ptr), first.data.ptr);
    try testing.expectEqual(@as(usize, 6), input.remaining());
    const second = try codec.read_cfg(Bytes, gpa, &input, .full());
    try testing.expectEqual(@as([*]const u8, encoded[7..].ptr), second.data.ptr);
    try testing.expectEqualStrings("hello", first.data);
    try testing.expectEqualStrings("world", second.data);
    try testing.expectEqual(@as(usize, 0), (try input.take(0)).len);
}

test "viewing empty ranges and invalid input" {
    for ([_][]const u8{ "", "hello" }) |encoded| {
        var input = Reader.init(encoded);
        try input.skip(0);
        try testing.expectEqual(@as(usize, 0), (try input.take(0)).len);
        try testing.expectEqual(encoded.len, input.remaining());
        try input.skip(encoded.len);
        try input.skip(0);
        try testing.expectEqual(@as(usize, 0), (try input.take(0)).len);
        try testing.expectEqual(@as(usize, 0), input.remaining());
        // Past the end is an error, not a panic.
        try testing.expectError(error.EndOfBuffer, input.skip(1));
    }
    for ([_][]const u8{ "", "\x05hi", "\x01ab", "\x80" }) |bytes| {
        try testing.expect(std.meta.isError(codec.decode_cfg(Bytes, gpa, bytes, .full())));
    }
    const empty = try codec.decode_cfg(Bytes, gpa, "\x00", .full());
    try testing.expectEqual(@as(usize, 0), empty.data.len);
}
