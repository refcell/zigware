//! Test blocks for the coding tests: marshal's `mocks.block.EmptyBlock(Sha256)` and
//! commonware's `mocks::block::encode_block`, which codes a block into a `CodedBlock`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const coding = @import("coding");
const cryptography = @import("cryptography");
const parallel = @import("parallel");

const types = @import("types.zig");
const mocks_block = @import("../mocks/block.zig");

const Sha256 = cryptography.Sha256;

pub const EmptyBlock = mocks_block.EmptyBlock(Sha256);
pub const RS = coding.ReedSolomon(Sha256);
pub const Coded = types.CodedBlock(EmptyBlock, RS, Sha256);

/// commonware `encode_block`: codes `block` with `config` sequentially.
pub fn encode_block(gpa: Allocator, block: EmptyBlock, config: coding.Config) !Coded {
    const coded = try Coded.encode(gpa, try .compute(gpa, block), config, parallel.sequential);
    assert(coded.digest().eql(block.digest()));
    return coded;
}
