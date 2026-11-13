//! Tests for `Digestible`, `Committable`, and `Digested` (commonware `lib.rs`).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const parallel = @import("parallel");
const digestible = @import("digestible.zig");
const Sha256 = @import("sha256.zig").Sha256;

/// A digestible block whose commitment is its digest.
const Block = struct {
    height: u64,
    across_calls: *u32,

    pub const Digest = Sha256.Digest;
    pub const Commitment = Sha256.Digest;

    pub fn digest(self: *const Block) Digest {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, self.height, .big);
        return Sha256.hash(&.{&bytes});
    }

    pub fn digest_across(self: *const Block, strategy: anytype) Digest {
        _ = strategy;
        self.across_calls.* += 1;
        return self.digest();
    }

    pub fn commitment(self: *const Block) Commitment {
        return self.digest();
    }

    pub fn write(self: Block, writer: *codec.Writer) void {
        codec.write(u64, self.height, writer);
    }

    pub const fixed_size: usize = 8;

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!Block {
        _ = try reader.read_int(u64);
        return error.Invalid; // Tests only encode blocks.
    }
};

/// A digestible value without `digest_across`.
const Plain = struct {
    byte: u8,

    pub const Digest = Sha256.Digest;

    pub fn digest(self: *const Plain) Digest {
        return Sha256.hash(&.{&.{self.byte}});
    }
};

comptime {
    digestible.assert_digestible(Block);
    digestible.assert_committable(Block);
    digestible.assert_digestible(Plain);
}

test "digested computes through the strategy and pairs precomputed digests" {
    var calls: u32 = 0;
    const block: Block = .{ .height = 7, .across_calls = &calls };
    const computed = digestible.Digested(Block).compute(&block, parallel.sequential);
    try testing.expectEqual(1, calls);
    try testing.expect(computed.digest().eql(block.digest()));
    try testing.expect(computed.digest().eql(block.commitment()));
    try testing.expectEqual(&block, computed.inner());

    const precomputed = digestible.Digested(Block).precomputed(&block, block.digest());
    try testing.expectEqual(1, calls);
    try testing.expect(precomputed.eql(computed));
    const other: Block = .{ .height = 8, .across_calls = &calls };
    const different = digestible.Digested(Block).precomputed(&other, other.digest());
    try testing.expect(!different.eql(computed));

    // A digestible without `digest_across` falls back to `digest`.
    const plain: Plain = .{ .byte = 1 };
    const digested = digestible.Digested(Plain).compute(&plain, parallel.sequential);
    try testing.expect(digested.digest().eql(plain.digest()));
}

test "digested encodes as its value" {
    var calls: u32 = 0;
    const block: Block = .{ .height = 0x0102030405060708, .across_calls = &calls };
    const digested = digestible.Digested(Block).compute(&block, parallel.sequential);
    var buffer: [16]u8 = undefined;
    try testing.expectEqual(8, digested.encode_size());
    var writer = codec.Writer.init(buffer[0..digested.encode_size()]);
    digested.write(&writer);
    const expected = try codec.encode(Block, testing.allocator, block);
    defer testing.allocator.free(expected);
    try testing.expectEqualSlices(u8, expected, writer.written());
}
