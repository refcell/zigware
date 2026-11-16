//! Tests of coded validation, ported from commonware `marshal/coding/validation.rs`.

const std = @import("std");
const testing = std.testing;
const coding = @import("coding");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");

const types = @import("types.zig");
const validation = @import("validation.zig");
const consensus_types = @import("../../types.zig");

const Sha256 = cryptography.Sha256;
const HashDigest = Sha256.Digest;
const CodingConfig = coding.Config;
const Height = consensus_types.Height;
const Round = consensus_types.Round;
const FixedEpocher = consensus_types.FixedEpocher;
const gpa = testing.allocator;

const TestCommitment = types.CommitmentOf(TestBlock, coding.ReedSolomon(Sha256), Sha256);

/// A block carrying its digest, round context, and commitment.
const TestBlock = struct {
    digest_value: Sha256.Digest,
    parent_value: Sha256.Digest,
    height_value: Height,
    context_value: Round,
    commitment_value: TestCommitment,

    pub const Digest = Sha256.Digest;
    pub const Context = Round;

    pub fn digest(block: *const TestBlock) Sha256.Digest {
        return block.digest_value;
    }

    pub fn parent(block: *const TestBlock) Sha256.Digest {
        return block.parent_value;
    }

    pub fn height(block: *const TestBlock) Height {
        return block.height_value;
    }

    pub fn context(block: *const TestBlock) Round {
        return block.context_value;
    }

    pub fn commitment(block: *const TestBlock) TestCommitment {
        return block.commitment_value;
    }
};

const Fixture = struct {
    epocher: FixedEpocher,
    block: TestBlock,
    parent: TestBlock,
    context: Round,
    commitment: TestCommitment,
    parent_commitment: TestCommitment,
    config: CodingConfig,
};

fn round(view: u64) Round {
    return .new(.new(0), .new(view));
}

fn commitment_for(
    digest: HashDigest,
    context: Round,
    config: CodingConfig,
    root_label: []const u8,
) !TestCommitment {
    const context_digest = try types.hash_context(Sha256, gpa, context);
    return .init(digest, Sha256.hash(&.{root_label}), context_digest, config);
}

fn baseline_fixture() !Fixture {
    const config = types.coding_config_for_participants(4);
    const parent_context = round(6);
    const context = round(7);
    const parent_digest = Sha256.hash(&.{"parent"});
    const digest = Sha256.hash(&.{"block"});
    const parent_commitment =
        try commitment_for(parent_digest, parent_context, config, "parent_root");
    const commitment = try commitment_for(digest, context, config, "block_root");
    return .{
        .epocher = .new(utils.NonZero(u64).init(10).?),
        .parent = .{
            .digest_value = parent_digest,
            .parent_value = Sha256.hash(&.{"grandparent"}),
            .height_value = .new(6),
            .context_value = parent_context,
            .commitment_value = parent_commitment,
        },
        .block = .{
            .digest_value = digest,
            .parent_value = parent_digest,
            .height_value = .new(7),
            .context_value = context,
            .commitment_value = commitment,
        },
        .context = context,
        .commitment = commitment,
        .parent_commitment = parent_commitment,
        .config = config,
    };
}

fn validate_block(fixture: Fixture) !void {
    return validation.validate_block(
        Sha256,
        gpa,
        fixture.epocher,
        &fixture.block,
        &fixture.parent,
        fixture.context,
        fixture.commitment,
        fixture.parent_commitment,
    );
}

fn validate_proposal(commitment: TestCommitment, config: CodingConfig, context: ?Round) !void {
    return validation.validate_proposal(Sha256, gpa, commitment, config, context);
}

fn validate_reconstruction(
    block: *const TestBlock,
    config: CodingConfig,
    commitment: TestCommitment,
) !void {
    return validation.validate_reconstruction(
        Sha256,
        gpa,
        block,
        config,
        commitment,
        parallel.sequential,
    );
}

test "validate block ok" {
    try validate_block(try baseline_fixture());
}

test "validate proposal ok" {
    const fixture = try baseline_fixture();
    try validate_proposal(fixture.commitment, fixture.config, fixture.context);
}

test "validate reconstruction ok" {
    const fixture = try baseline_fixture();
    try validate_reconstruction(&fixture.block, fixture.config, fixture.commitment);
}

test "validate block commitment error" {
    var fixture = try baseline_fixture();
    fixture.commitment = try commitment_for(
        Sha256.hash(&.{"other_block"}),
        fixture.context,
        fixture.config,
        "other_root",
    );
    try testing.expectError(error.Commitment, validate_block(fixture));
}

test "validate block parent commitment error" {
    var fixture = try baseline_fixture();
    fixture.parent_commitment = try commitment_for(
        Sha256.hash(&.{"other_parent"}),
        fixture.parent.context_value,
        fixture.config,
        "other_parent_root",
    );
    try testing.expectError(error.ParentCommitment, validate_block(fixture));
}

test "validate block epoch error" {
    var fixture = try baseline_fixture();
    // Height 7 lies in epoch 0 of a 10-height epocher; the context claims epoch 1.
    fixture.context = .new(.new(1), .new(7));
    try testing.expectError(error.Epoch, validate_block(fixture));
}

test "validate block parent digest error" {
    var fixture = try baseline_fixture();
    fixture.block.parent_value = Sha256.hash(&.{"wrong_parent"});
    try testing.expectError(error.ParentDigest, validate_block(fixture));
}

test "validate block height error" {
    var fixture = try baseline_fixture();
    fixture.block.height_value = .new(9);
    try testing.expectError(error.Height, validate_block(fixture));
}

test "validate block context digest error" {
    var fixture = try baseline_fixture();
    const wrong_context = round(9);
    fixture.commitment = try commitment_for(
        fixture.block.digest_value,
        wrong_context,
        fixture.config,
        "block_root",
    );
    fixture.block.commitment_value = fixture.commitment;
    try testing.expectError(error.ContextDigest, validate_block(fixture));
}

test "validate block context error" {
    var fixture = try baseline_fixture();
    // Same epoch, so only the context comparison differs.
    fixture.context = round(8);
    try testing.expectError(error.Context, validate_block(fixture));
}

test "validate proposal coding config error" {
    const fixture = try baseline_fixture();
    const wrong = types.coding_config_for_participants(7);
    try testing.expectError(
        error.CodingConfig,
        validate_proposal(fixture.commitment, wrong, fixture.context),
    );
}

test "validate proposal context digest error" {
    const fixture = try baseline_fixture();
    try testing.expectError(
        error.ContextDigest,
        validate_proposal(fixture.commitment, fixture.config, round(8)),
    );
}

test "validate proposal reproposal exception not valid in later context" {
    const fixture = try baseline_fixture();
    // Re-proposals skip the context-digest check because the commitment keeps the original
    // proposal context.
    try validate_proposal(fixture.commitment, fixture.config, null);
    // The same commitment is not accepted as a normal proposal in a later context, so the
    // re-proposal exception cannot alias a distinct context-dependent outcome.
    try testing.expectError(
        error.ContextDigest,
        validate_proposal(fixture.commitment, fixture.config, round(8)),
    );
}

test "validate proposal none context still enforces coding config" {
    const fixture = try baseline_fixture();
    const wrong = types.coding_config_for_participants(7);
    try testing.expectError(error.CodingConfig, validate_proposal(fixture.commitment, wrong, null));
}

test "validate reconstruction block digest error" {
    const fixture = try baseline_fixture();
    const wrong = try commitment_for(
        Sha256.hash(&.{"wrong_block_digest"}),
        fixture.context,
        fixture.config,
        "block_root",
    );
    try testing.expectError(
        error.BlockDigest,
        validate_reconstruction(&fixture.block, fixture.config, wrong),
    );
}

test "validate reconstruction coding config error" {
    const fixture = try baseline_fixture();
    const wrong_config = types.coding_config_for_participants(7);
    const wrong = try commitment_for(
        fixture.block.digest_value,
        fixture.context,
        wrong_config,
        "block_root",
    );
    try testing.expectError(
        error.CodingConfig,
        validate_reconstruction(&fixture.block, fixture.config, wrong),
    );
}

test "validate reconstruction context digest error" {
    const fixture = try baseline_fixture();
    const wrong = try commitment_for(
        fixture.block.digest_value,
        round(8),
        fixture.config,
        "block_root",
    );
    try testing.expectError(
        error.ContextDigest,
        validate_reconstruction(&fixture.block, fixture.config, wrong),
    );
}
