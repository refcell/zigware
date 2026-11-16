//! Test blocks for the coding tests: a copy of commonware's `marshal::mocks::block`
//! `EmptyBlock<Sha256>` and `encode_block`, until consensus-marshal's `mocks.block` lands
//! (docs/lanes/broadcast-collector.md).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const coding = @import("coding");
const cryptography = @import("cryptography");
const parallel = @import("parallel");

const types = @import("types.zig");
const Height = @import("../../types.zig").Height;

const Sha256 = cryptography.Sha256;

/// A block with no explicit consensus context; its parent digest is its context.
pub const EmptyBlock = struct {
    parent_value: Sha256.Digest,
    height_value: Height,
    timestamp: u64,

    pub const Digest = Sha256.Digest;
    pub const Context = Sha256.Digest;

    pub fn init(parent_digest: Sha256.Digest, height_value: u64, timestamp: u64) EmptyBlock {
        return .{
            .parent_value = parent_digest,
            .height_value = .new(height_value),
            .timestamp = timestamp,
        };
    }

    /// SHA-256 of the parent, then the big-endian height and timestamp.
    pub fn digest(block: *const EmptyBlock) Sha256.Digest {
        var height_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &height_bytes, block.height_value.get(), .big);
        var timestamp_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &timestamp_bytes, block.timestamp, .big);
        return Sha256.hash(&.{ &block.parent_value.bytes, &height_bytes, &timestamp_bytes });
    }

    pub fn parent(block: *const EmptyBlock) Sha256.Digest {
        return block.parent_value;
    }

    pub fn height(block: *const EmptyBlock) Height {
        return block.height_value;
    }

    pub fn context(block: *const EmptyBlock) Context {
        return block.parent_value;
    }

    pub fn eql(a: *const EmptyBlock, b: *const EmptyBlock) bool {
        const same_height = a.height_value.get() == b.height_value.get();
        return a.parent_value.eql(b.parent_value) and same_height and a.timestamp == b.timestamp;
    }

    pub fn write(block: EmptyBlock, writer: *codec.Writer) void {
        block.parent_value.write(writer);
        block.height_value.write(writer);
        codec.write(codec.UInt(u64), .{ .value = block.timestamp }, writer);
    }

    pub fn encode_size(block: EmptyBlock) usize {
        return Sha256.Digest.fixed_size + codec.encode_size(Height, block.height_value) +
            codec.encode_size(codec.UInt(u64), .{ .value = block.timestamp });
    }

    /// commonware `BoundedBlock::max_encode_size`: the digest and two `u64` varints.
    pub fn max_encode_size(_: void) usize {
        return Sha256.Digest.fixed_size + Height.max_encode_size + codec.varint.max_size(u64);
    }

    pub fn read(allocator: Allocator, reader: *codec.Reader, _: void) codec.Error!EmptyBlock {
        const parent_value = try codec.read(Sha256.Digest, allocator, reader);
        const height_value = try codec.read(Height, allocator, reader);
        const timestamp = try codec.read(codec.UInt(u64), allocator, reader);
        return .{
            .parent_value = parent_value,
            .height_value = height_value,
            .timestamp = timestamp.value,
        };
    }
};

pub const RS = coding.ReedSolomon(Sha256);
pub const Coded = types.CodedBlock(EmptyBlock, RS, Sha256);

/// commonware `encode_block`: codes `block` with `config` sequentially.
pub fn encode_block(gpa: Allocator, block: EmptyBlock, config: coding.Config) !Coded {
    const coded = try Coded.encode(gpa, try .compute(gpa, block), config, parallel.sequential);
    assert(coded.digest().eql(block.digest()));
    return coded;
}
