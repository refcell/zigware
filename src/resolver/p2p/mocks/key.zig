//! A one-byte key for tests (commonware `resolver/src/p2p/mocks/key.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");

/// A key that can be used for testing; encodes as its byte.
pub const Key = struct {
    value: u8,

    pub const fixed_size: usize = 1;

    pub fn init(value: u8) Key {
        return .{ .value = value };
    }

    pub fn write(self: Key, writer: *codec.Writer) void {
        writer.write_byte(self.value);
    }

    pub fn encode_size(_: Key) usize {
        return fixed_size;
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Key {
        return .{ .value = try reader.read_byte() };
    }

    pub fn order(a: Key, b: Key) std.math.Order {
        return std.math.order(a.value, b.value);
    }

    pub fn eql(a: Key, b: Key) bool {
        return a.value == b.value;
    }

    pub fn format(self: Key, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("Key({d})", .{self.value});
    }
};

comptime {
    utils.Span(Key);
    assert(codec.fixed_size(Key).? == 1);
}
