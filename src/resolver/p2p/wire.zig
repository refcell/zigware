//! Messages between resolver peers (commonware `resolver/src/p2p/wire.rs`).
//!
//! A `Message` is an 8-byte big-endian request id followed by a tagged `Payload`: tag 0 and a
//! key (request), tag 1 and a length-prefixed value (response), or tag 2 alone (error).
//! Encodings are byte-identical to commonware's (checked by its conformance hashes).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");

const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;

const tag_request: u8 = 0;
const tag_response: u8 = 1;
const tag_error: u8 = 2;

/// Bytes a request adds to the key it carries: an 8-byte request id and a 1-byte tag. An error
/// carries no key and is exactly this size.
pub const request_overhead: usize = 8 + 1;

/// Largest number of bytes a response adds to its value: the request id, the tag, and a
/// value-length varint of at most 5 bytes.
pub const response_overhead_max: usize = request_overhead + codec.varint.max_u32_varint_size;

/// An upper bound on the encoded size of any message for keys of type `Key` and values of at
/// most `value_size` bytes. `value_size` must fit the u32 length prefix.
pub fn max_message_size(comptime Key: type, value_size: usize) usize {
    assert(value_size <= std.math.maxInt(u32)); // value must fit the u32 length prefix
    const key_size = comptime codec.max_encode_size(Key).?;
    // An error is a request without a key, so a request is always at least as wide.
    const request = key_size + request_overhead;
    const response = value_size + response_overhead_max;
    const result = @max(request, response);
    assert(result >= request_overhead);
    return result;
}

/// A message sent between peers. Responses carry the id of the request they answer.
pub fn Message(comptime Key: type) type {
    return struct {
        const Self = @This();

        /// Unique identifier for the message.
        id: u64,
        /// The data being sent.
        payload: Payload(Key),

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_int(u64, self.id);
            self.payload.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return 8 + self.payload.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const id = try reader.read_int(u64);
            const payload = try Payload(Key).read(gpa, reader, {});
            return .{ .id = id, .payload = payload };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.id == b.id and a.payload.eql(b.payload);
        }

        /// commonware's `Arbitrary for Message`.
        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const id = u.int(u64);
            const payload = try Payload(Key).arbitrary(gpa, u);
            return .{ .id = id, .payload = payload };
        }
    };
}

/// The contents of a message sent between peers.
pub fn Payload(comptime Key: type) type {
    comptime assert(codec.Cfg(Key) == void);
    return union(enum) {
        const Self = @This();

        /// A request for the value of a key.
        request: Key,
        /// A response to a request. Decoding borrows the value from the input.
        response: codec.Bytes,
        /// A response that indicates an unspecified error, so the requester can retry sooner
        /// than a timeout.
        @"error",

        pub fn write(self: Self, writer: *codec.Writer) void {
            switch (self) {
                .request => |key| {
                    writer.write_byte(tag_request);
                    codec.write(Key, key, writer);
                },
                .response => |data| {
                    writer.write_byte(tag_response);
                    data.write(writer);
                },
                .@"error" => writer.write_byte(tag_error),
            }
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                .request => |key| codec.encode_size(Key, key),
                .response => |data| data.encode_size(),
                .@"error" => 0,
            };
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const tag = try reader.read_byte();
            switch (tag) {
                tag_request => return .{ .request = try codec.read(Key, gpa, reader) },
                // The p2p connection already bounds a message, and a view never allocates,
                // so the value length needs no limit: an oversized length fails the read.
                tag_response => return .{
                    .response = try codec.Bytes.read(gpa, reader, .full()),
                },
                tag_error => return .@"error",
                else => return reader.invalid("Payload", "Invalid payload type"),
            }
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .request => |key| codec.order(Key, key, b.request) == .eq,
                .response => |data| std.mem.eql(u8, data.data, b.response.data),
                .@"error" => true,
            };
        }

        /// commonware's `Arbitrary for Payload`.
        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            switch (u.int_in_range(u32, 0, 2)) {
                0 => return .{ .request = try codec.arbitrary.value(Key, gpa, u) },
                1 => {
                    const size = u.int_in_range(u64, 0, 1024);
                    const data = try gpa.alloc(u8, @intCast(size));
                    try u.bytes(data);
                    return .{ .response = .init(data) };
                },
                2 => return .@"error",
                else => unreachable, // Proof: int_in_range returns a value in 0..=2.
            }
        }
    };
}

const testing = std.testing;
const MockKey = @import("mocks/key.zig").Key;

fn expect_roundtrip(message: Message(MockKey)) !void {
    const gpa = testing.allocator;
    const encoded = try codec.encode(Message(MockKey), gpa, message);
    defer gpa.free(encoded);
    const decoded = try codec.decode(Message(MockKey), gpa, encoded);
    try testing.expect(message.eql(decoded));
}

test "codec request" {
    try expect_roundtrip(.{ .id = 1234, .payload = .{ .request = .{ .value = 123 } } });
}

test "codec response" {
    try expect_roundtrip(.{ .id = 4321, .payload = .{ .response = .init("Hello, world!") } });
}

test "codec error" {
    try expect_roundtrip(.{ .id = 255, .payload = .@"error" });
}

test "wire bytes" {
    const gpa = testing.allocator;
    const M = Message(u8);
    const request = try codec.encode(M, gpa, .{ .id = 1, .payload = .{ .request = 7 } });
    defer gpa.free(request);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 1, 0, 7 }, request);
    const response_message: M = .{ .id = 2, .payload = .{ .response = .init("ab") } };
    const response = try codec.encode(M, gpa, response_message);
    defer gpa.free(response);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 'a', 'b' }, response);
    try testing.expectError(error.Invalid, codec.decode(M, gpa, &.{ 0, 0, 0, 0, 0, 0, 0, 2, 3 }));
    try testing.expectError(error.EndOfBuffer, codec.decode(M, gpa, &.{ 0, 0, 0, 0, 0, 0, 0, 2 }));
    // A declared value length beyond the input fails without allocating.
    const oversized = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 2, 1, 0xff, 0xff, 0xff, 0xff, 0x0f };
    try testing.expectError(error.EndOfBuffer, codec.decode(M, gpa, &oversized));
}

fn message_size(payload: Payload(u8)) !usize {
    const gpa = testing.allocator;
    const message: Message(u8) = .{ .id = std.math.maxInt(u64), .payload = payload };
    const encoded = try codec.encode(Message(u8), gpa, message);
    defer gpa.free(encoded);
    return encoded.len;
}

test "message overhead" {
    const gpa = testing.allocator;
    // A request adds exactly its overhead to the key, and an error is exactly that overhead.
    try testing.expectEqual(1 + request_overhead, try message_size(.{ .request = 255 }));
    try testing.expectEqual(request_overhead, try message_size(.@"error"));
    // Responses on both sides of each varint length boundary stay within the overhead.
    for ([_]usize{ 0, 127, 128, 16_383, 16_384 }) |len| {
        const value = try gpa.alloc(u8, len);
        defer gpa.free(value);
        @memset(value, 0);
        const size = try message_size(.{ .response = .init(value) });
        try testing.expect(size - len <= response_overhead_max);
    }
    // A u32::MAX-byte value adds exactly the overhead: measure an empty response's envelope
    // and add the largest length prefix, so the test never allocates that value.
    const envelope = try message_size(.{ .response = .init(&.{}) }) - 1;
    const prefix = codec.encode_size(usize, std.math.maxInt(u32));
    try testing.expectEqual(response_overhead_max, envelope + prefix);
}

test "max message size" {
    try testing.expectEqual(response_overhead_max, max_message_size(u8, 0));
    try testing.expectEqual(100 + response_overhead_max, max_message_size(u8, 100));
    try testing.expectEqual(64 + request_overhead, max_message_size([64]u8, 0));
    const largest: usize = std.math.maxInt(u32);
    try testing.expectEqual(largest + response_overhead_max, max_message_size(u8, largest));
}

fn CodecConformance(comptime T: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const gen = codec.arbitrary.default_generator(T);
            const value = try codec.arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

test "conformance: Message and Payload encodings match commonware" {
    const conformance = @import("conformance");
    const file = @embedFile("conformance.toml");
    const prefix = "commonware_resolver::p2p::wire::tests::conformance::";
    const gpa = std.heap.smp_allocator;
    const n_cases = conformance.default_cases;
    const message_name = prefix ++ "CodecConformance<Message<u8>>";
    try conformance.verify(CodecConformance(Message(u8)), gpa, message_name, n_cases, file);
    const payload_name = prefix ++ "CodecConformance<Payload<u8>>";
    try conformance.verify(CodecConformance(Payload(u8)), gpa, payload_name, n_cases, file);
}

/// Any successful decode re-encodes to exactly the input (commonware's codec fuzzing).
fn decode_canonical(_: void, smith: *std.testing.Smith) anyerror!void {
    var data: [256]u8 = undefined;
    const input = data[0..smith.slice(&data)];
    const M = Message([4]u8);
    const message = codec.decode(M, testing.allocator, input) catch return;
    var buffer: [data.len]u8 = undefined;
    const encoded = codec.encode_to(M, message, &buffer);
    try testing.expectEqualSlices(u8, input, encoded);
    try testing.expectEqual(input.len, message.encode_size());
}

test "fuzz: wire decode is canonical" {
    const p2p = @import("p2p");
    try p2p.fuzz.run({}, decode_canonical, 0x7265736f6c766572, 2000);
}
