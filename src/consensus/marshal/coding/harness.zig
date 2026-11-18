//! The coding variant's test harness (the coding parts of commonware
//! `marshal/mocks/harness.rs`: `CodingB`, `CodingCtx`, `genesis_commitment`,
//! `make_coding_block`, and `CodingHarness`), on top of marshal's shared harness
//! (`mocks/harness.zig`).
//!
//! Coding blocks are erasure coded for the committee: a test block at `height` embeds a
//! context over the parent's coding commitment, and genesis uses a trusted commitment under
//! `genesis_coding_config`, which is never coded.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const broadcast = @import("broadcast");
const coding = @import("coding");
const parallel = @import("parallel");

const types = @import("types.zig");
const commitment_module = @import("../../commitment.zig");
const variant = @import("variant.zig");
const shared = @import("../mocks/harness.zig");
const mocks_block = @import("../mocks/block.zig");
const consensus_types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");

const Height = consensus_types.Height;
const Round = consensus_types.Round;
const View = consensus_types.View;
pub const Sha256 = shared.Sha256;
const D = shared.D;
const K = shared.K;

pub const RS = coding.ReedSolomon(Sha256);
/// The coding commitment of a `CodingB` (commonware's `TestCommitment`).
/// Spelled over the digests, since `CodingB`'s context refers to it.
pub const TestCommitment = commitment_module.Commitment(D, RS.Commitment, D);
/// A context over coding commitments.
pub const CodingCtx = simplex_types.Context(TestCommitment, K);
/// The application block of the coding tests.
pub const CodingB = mocks_block.Block(Sha256, CodingCtx);
pub const CodingVariant = variant.Coding(CodingB, RS, Sha256, K);
comptime {
    assert(TestCommitment == types.CommitmentOf(CodingB, RS, Sha256));
}
pub const CodedTestBlock = CodingVariant.Block;
/// The shards engine's commitment records (commonware `RECORDS`).
pub const records: usize = 16;

/// The coding config of genesis commitments: genesis is trusted, so it is never coded.
pub const genesis_coding_config: coding.Config = .{ .minimum_shards = 1, .extra_shards = 1 };

/// The genesis parent commitment: empty digests under the genesis config.
pub fn genesis_commitment() TestCommitment {
    return .init(.empty, .empty, .empty, genesis_coding_config);
}

/// A block over `context` at `height` with parent digest `parent` (commonware
/// `make_coding_block`).
pub fn make_coding_block(
    gpa: Allocator,
    context: CodingCtx,
    parent: D,
    at: Height,
    timestamp: u64,
) !CodingB {
    return CodingB.init(gpa, context, parent, at, timestamp);
}

/// The height-zero application block that seeds a fresh actor.
pub fn make_coding_genesis_block(gpa: Allocator) !CodingB {
    const context: CodingCtx = .{
        .round = .new(.zero(), .zero()),
        .leader = shared.default_leader(),
        .parent = .{ .zero(), genesis_commitment() },
    };
    return make_coding_block(gpa, context, shared.genesis_parent(), .zero(), 0);
}

/// The coding variant's harness (commonware `CodingHarness`).
pub const CodingHarness = struct {
    pub const ApplicationBlock = CodingB;
    pub const Variant = CodingVariant;
    pub const TestBlock = CodedTestBlock;
    pub const Commitment = TestCommitment;
    pub const Buffer = variant.Buffer(CodingB, RS, Sha256, K);

    pub fn genesis_parent_commitment(_: u32) Commitment {
        return genesis_commitment();
    }

    /// The block at `height` over `parent` and its commitment, coded for `participants`
    /// (owned by the caller).
    pub fn make_test_block(
        gpa: Allocator,
        parent: D,
        parent_commitment: Commitment,
        at: Height,
        timestamp: u64,
        participants: u32,
    ) !TestBlock {
        assert(participants >= 4 and participants <= std.math.maxInt(u16));
        const parent_view: View = if (at.previous()) |previous| .new(previous.get()) else .zero();
        const context: CodingCtx = .{
            .round = .new(.zero(), .new(at.get())),
            .leader = shared.default_leader(),
            .parent = .{ parent_view, parent_commitment },
        };
        const raw = try make_coding_block(gpa, context, parent, at, timestamp);
        const config = types.coding_config_for_participants(@intCast(participants));
        const digested = try broadcast.Digested(CodingB).compute(gpa, raw);
        return TestBlock.encode(gpa, digested, config, parallel.sequential);
    }

    /// The height-zero block under its trusted genesis commitment, whose root is the block
    /// digest (it is never coded).
    pub fn genesis_block(gpa: Allocator, _: u32) !TestBlock {
        const inner = try make_coding_genesis_block(gpa);
        const digest_value = inner.digest();
        const context_digest = try types.hash_context(Sha256, gpa, inner.context());
        const value: Commitment =
            .init(digest_value, digest_value, context_digest, genesis_coding_config);
        const digested = try broadcast.Digested(CodingB).compute(gpa, inner);
        assert(digested.digest().eql(digest_value));
        return TestBlock.precomputed(digested, value);
    }

    pub fn commitment(block: *const TestBlock) Commitment {
        return block.commitment();
    }

    pub fn digest(block: *const TestBlock) D {
        return block.digest();
    }

    pub fn height(block: *const TestBlock) Height {
        return block.height();
    }
};

test {
    _ = @import("harness_test.zig");
}
