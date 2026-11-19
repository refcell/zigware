//! Data frames exchanged between authenticated peers (commonware
//! `p2p/src/authenticated/data.rs`): a channel varint followed by a length-prefixed message.
//! On the wire a data frame is prefixed by `data_prefix`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const p2p = @import("../root.zig");

const Channel = p2p.Channel;
const UInt = codec.varint.UInt(u64);
const Unstructured = codec.arbitrary.Unstructured;

/// Prefix byte identifying a data frame on the wire.
pub const data_prefix: u8 = 0;

/// The maximum overhead in bytes when encoding a message into a data frame: the frame
/// discriminant (1), the channel varint (10), and the message length varint (5).
pub const max_payload_overhead: u32 = 1 + 10 + 5;

comptime {
    assert(max_payload_overhead == 1 + codec.varint.max_u64_varint_size +
        codec.varint.max_u32_varint_size);
}

/// The largest application payload a stream with `stream_max_size` carries.
pub fn max_size(comptime stream_max_size: u32) u32 {
    if (stream_max_size < max_payload_overhead) {
        @compileError("stream message limit too small for p2p framing");
    }
    return stream_max_size - max_payload_overhead;
}

/// An arbitrary message sent between peers on `channel`. Decoded messages borrow from the
/// decoded buffer.
pub const Data = struct {
    /// Routes the message to its channel handler.
    channel: Channel,
    message: []const u8,

    pub const Cfg = codec.RangeCfg(usize);

    pub fn encode_size(data: Data) usize {
        return (UInt{ .value = data.channel }).encode_size() +
            codec.encode_size(usize, data.message.len) + data.message.len;
    }

    pub fn write(data: Data, writer: *codec.Writer) void {
        (UInt{ .value = data.channel }).write(writer);
        codec.write(usize, data.message.len, writer);
        writer.write_bytes(data.message);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, range: Cfg) codec.Error!Data {
        const channel = try codec.varint.read(u64, reader);
        const len = try codec.read_usize(reader, range);
        const message = try reader.take(len);
        assert(message.len == len);
        return .{ .channel = channel, .message = message };
    }

    pub fn order(a: Data, b: Data) std.math.Order {
        const by_channel = std.math.order(a.channel, b.channel);
        if (by_channel != .eq) return by_channel;
        return std.mem.order(u8, a.message, b.message);
    }

    /// commonware's `Arbitrary for Data`: a channel, then up to 1024 message bytes.
    pub fn arbitrary(gpa: Allocator, u: *Unstructured) codec.arbitrary.Error!Data {
        const channel = u.int(u64);
        const size: usize = @intCast(u.int_in_range(u64, 0, 1024));
        const message = try gpa.alloc(u8, size);
        errdefer gpa.free(message);
        try u.bytes(message);
        return .{ .channel = channel, .message = message };
    }
};

/// The header of a data frame carrying `message_len` bytes on `channel`:
/// `data_prefix || channel || message_len`. Sending the header and then the message as two
/// parts gives commonware's `EncodedData` payload without copying the message.
pub const Header = struct {
    bytes: [max_payload_overhead]u8,
    len: u8,

    pub fn init(channel: Channel, message_len: usize) Header {
        var header: Header = .{ .bytes = undefined, .len = 0 };
        var writer: codec.Writer = .init(&header.bytes);
        writer.write_byte(data_prefix);
        (UInt{ .value = channel }).write(&writer);
        codec.write(usize, message_len, &writer);
        header.len = @intCast(writer.written().len);
        assert(header.len >= 3 and header.len <= max_payload_overhead);
        return header;
    }

    pub fn slice(header: *const Header) []const u8 {
        return header.bytes[0..header.len];
    }
};

const testing = std.testing;

test {
    _ = @import("data_alloc_test.zig");
}

test "max size leaves room for framing" {
    try testing.expectEqual(@as(u32, 1024 - 16), max_size(1024));
}

test "data codec roundtrip and length range" {
    const gpa = testing.allocator;
    const original: Data = .{ .channel = 12345, .message = "Hello, world!" };
    const encoded = try codec.encode(Data, gpa, original);
    defer gpa.free(encoded);
    const decoded = try codec.decode_cfg(Data, gpa, encoded, .inclusive(13, 13));
    try testing.expect(original.order(decoded) == .eq);
    const too_long = codec.decode_cfg(Data, gpa, encoded, .range(0, 13));
    try testing.expectError(error.InvalidLength, too_long);
    const too_short_range = codec.decode_cfg(Data, gpa, encoded, .from(14));
    try testing.expectError(error.InvalidLength, too_short_range);
}

test "data decode rejects a truncated message" {
    const invalid = [_]u8{ 3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const result = codec.decode_cfg(Data, testing.allocator, &invalid, .full());
    try testing.expect(std.meta.isError(result));
}

test "header and message encode like Data with the prefix" {
    const gpa = testing.allocator;
    const message = "hello world!";
    const encoded = try codec.encode(Data, gpa, .{ .channel = 12345, .message = message });
    defer gpa.free(encoded);
    const header: Header = .init(12345, message.len);
    const framed = try std.mem.concat(gpa, u8, &.{ header.slice(), message });
    defer gpa.free(framed);
    try testing.expectEqual(data_prefix, framed[0]);
    try testing.expectEqualSlices(u8, encoded, framed[1..]);
}

fn DataConformance() type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const gen = codec.arbitrary.default_generator(Data);
            const value = try codec.arbitrary.generate(Data, gen, arena.allocator(), seed);
            return codec.encode(Data, gpa, value);
        }
    };
}

test "conformance: Data encoding matches commonware" {
    const conformance = @import("conformance");
    const name = "commonware_p2p::authenticated::data::tests::conformance::CodecConformance<Data>";
    const file = @embedFile("../conformance.toml");
    try conformance.verify(DataConformance(), testing.allocator, name, 65536, file);
}
