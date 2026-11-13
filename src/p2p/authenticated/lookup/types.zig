//! Messages exchanged between lookup peers (commonware
//! `p2p/src/authenticated/lookup/types.rs`): a one-byte discriminant, then the data frame.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const data_mod = @import("../data.zig");

const Data = data_mod.Data;
const Unstructured = codec.arbitrary.Unstructured;

/// Prefix that identifies a `Data` message.
pub const data_prefix: u8 = data_mod.data_prefix;
/// Prefix that identifies a `Ping` message.
pub const ping_prefix: u8 = 1;

comptime {
    assert(data_prefix == 0);
    assert(ping_prefix != data_prefix);
}

/// The messages that can be sent between peers.
pub const Message = union(enum) {
    data: Data,
    ping,

    /// The largest data message a peer accepts.
    pub const Cfg = usize;

    pub fn encode_size(message: Message) usize {
        return 1 + switch (message) {
            .data => |data| data.encode_size(),
            .ping => 0,
        };
    }

    pub fn write(message: Message, writer: *codec.Writer) void {
        switch (message) {
            .data => |data| {
                writer.write_byte(data_prefix);
                data.write(writer);
            },
            .ping => writer.write_byte(ping_prefix),
        }
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, max_data_length: Cfg) codec.Error!Message {
        const prefix = try reader.read_byte();
        return switch (prefix) {
            data_prefix => .{ .data = try Data.read(gpa, reader, .to_inclusive(max_data_length)) },
            ping_prefix => .ping,
            else => reader.fail(error.InvalidEnum, prefix),
        };
    }

    /// `#[derive(Arbitrary)]`: the variant from a `u32`, then its fields.
    pub fn arbitrary(gpa: Allocator, u: *Unstructured) codec.arbitrary.Error!Message {
        const variant = (@as(u64, u.int(u32)) * 2) >> 32;
        assert(variant < 2);
        if (variant == 0) return .{ .data = try Data.arbitrary(gpa, u) };
        return .ping;
    }
};

const testing = std.testing;

test "max payload overhead bounds a data message" {
    const message: Message = .{ .data = .{ .channel = std.math.maxInt(u64), .message = &.{} } };
    // An empty message has a one-byte length; the overhead reserves five.
    try testing.expectEqual(@as(usize, 1 + 10 + 1), message.encode_size());
    const big_len: usize = 1 << 29;
    const length_size = codec.encode_size(usize, big_len);
    try testing.expectEqual(@as(usize, data_mod.max_payload_overhead), 1 + 10 + length_size);
    try testing.expect((Message{ .ping = {} }).encode_size() <= data_mod.max_payload_overhead);
}

test "decode data within and beyond the limit" {
    const gpa = testing.allocator;
    const within: Message = .{ .data = .{ .channel = 7, .message = "ping" } };
    const encoded = try codec.encode(Message, gpa, within);
    defer gpa.free(encoded);
    const decoded = try codec.decode_cfg(Message, gpa, encoded, 4);
    try testing.expectEqual(@as(u64, 7), decoded.data.channel);
    try testing.expectEqualStrings("ping", decoded.data.message);

    const beyond: Message = .{ .data = .{ .channel = 9, .message = "hello" } };
    const too_long = try codec.encode(Message, gpa, beyond);
    defer gpa.free(too_long);
    try testing.expectError(error.InvalidLength, codec.decode_cfg(Message, gpa, too_long, 4));
    try testing.expectError(error.InvalidEnum, codec.decode_cfg(Message, gpa, &.{2}, 4));
    const ping = try codec.decode_cfg(Message, gpa, &.{ping_prefix}, 4);
    try testing.expect(ping == .ping);
}

fn MessageConformance() type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const gen = codec.arbitrary.default_generator(Message);
            const value = try codec.arbitrary.generate(Message, gen, arena.allocator(), seed);
            return codec.encode(Message, gpa, value);
        }
    };
}

test "conformance: lookup Message encoding matches commonware" {
    const conformance = @import("conformance");
    const name = "commonware_p2p::authenticated::lookup::types::tests::conformance::" ++
        "CodecConformance<Message>";
    const file = @embedFile("../../conformance.toml");
    try conformance.verify(MessageConformance(), testing.allocator, name, 65536, file);
}
