//! Validation of coded proposals, blocks, and reconstructions (commonware
//! `marshal/coding/validation.rs`).
//!
//! `has_contiguous_height` (marshal `ancestry`) and `is_block_in_expected_epoch` (marshal
//! `application::validation`) are one-line helpers of consensus-marshal's lane, copied here
//! until those modules land (docs/lanes/broadcast-collector.md).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const coding = @import("coding");
const cryptography = @import("cryptography");

const types = @import("types.zig");
const consensus_types = @import("../../types.zig");

const CodingConfig = coding.Config;
const Height = consensus_types.Height;
const Epoch = consensus_types.Epoch;

/// Why a proposal's commitment is invalid.
pub const ProposalError = error{ CodingConfig, ContextDigest };

/// Why a block does not match its commitments and context.
pub const BlockError = error{
    Commitment,
    ParentCommitment,
    Epoch,
    ParentDigest,
    Height,
    ContextDigest,
    Context,
};

/// Why a reconstructed block does not match its commitment. commonware's `ContextDigest`
/// carries the expected and actual digests; Zig errors carry no payload.
pub const ReconstructionError = error{ BlockDigest, CodingConfig, ContextDigest };

/// Checks a proposal's commitment against the expected coding config and, unless it is a
/// re-proposal (`context` null, whose commitment keeps the original proposal's context),
/// against the digest of its context.
pub fn validate_proposal(
    comptime H: type,
    gpa: Allocator,
    payload: anytype,
    expected_config: CodingConfig,
    context: anytype,
) (ProposalError || Allocator.Error)!void {
    comptime assert(@typeInfo(@TypeOf(context)) == .optional);
    if (!payload.config().eql(expected_config)) return error.CodingConfig;
    const value = context orelse return;
    const digest = try types.hash_context(H, gpa, value);
    if (!payload.context().eql(digest)) return error.ContextDigest;
}

/// Checks a block against its commitment, its parent, and the context it was proposed in:
/// commitments, epoch, parent digest, contiguous height, then the context and its digest.
pub fn validate_block(
    comptime H: type,
    gpa: Allocator,
    epocher: anytype,
    block: anytype,
    parent: @TypeOf(block),
    context: anytype,
    commitment: anytype,
    parent_commitment: @TypeOf(commitment),
) (BlockError || Allocator.Error)!void {
    if (!block.commitment().eql(commitment)) return error.Commitment;
    if (!parent.commitment().eql(parent_commitment)) return error.ParentCommitment;
    const epoch = context_epoch(context);
    if (!is_block_in_expected_epoch(epocher, block.height(), epoch)) return error.Epoch;
    if (!block.parent().eql(parent.digest())) return error.ParentDigest;
    if (!has_contiguous_height(parent.height(), block.height())) return error.Height;
    const block_context = block.context();
    const digest = try types.hash_context(H, gpa, block_context);
    if (!commitment.context().eql(digest)) return error.ContextDigest;
    if (!context_eql(block_context, context)) return error.Context;
}

/// Checks a reconstructed block and the coding config decoded with it against `commitment`.
pub fn validate_reconstruction(
    comptime H: type,
    gpa: Allocator,
    block: anytype,
    config: CodingConfig,
    commitment: anytype,
    strategy: anytype,
) (ReconstructionError || Allocator.Error)!void {
    const B = @typeInfo(@TypeOf(block)).pointer.child;
    const digest = cryptography.digestible.digest_across(B, block, strategy);
    if (!digest.eql(commitment.block())) return error.BlockDigest;
    if (!config.eql(commitment.config())) return error.CodingConfig;
    const context_digest = try types.hash_context(H, gpa, block.context());
    if (!commitment.context().eql(context_digest)) return error.ContextDigest;
}

/// Whether `child_height` directly follows `parent_height` (marshal `ancestry`).
pub fn has_contiguous_height(parent_height: Height, child_height: Height) bool {
    const previous = child_height.previous() orelse return false;
    return previous.get() == parent_height.get();
}

/// Whether `block_height` falls in `expected_epoch` (marshal `application::validation`).
pub fn is_block_in_expected_epoch(epocher: anytype, block_height: Height, expected: Epoch) bool {
    const bounds = epocher.containing(block_height) orelse return false;
    return bounds.epoch.get() == expected.get();
}

/// A context's epoch (commonware `Epochable`): a method, or a field such as `Round`'s.
fn context_epoch(context: anytype) Epoch {
    const T = @TypeOf(context);
    if (comptime @hasDecl(T, "epoch")) return context.epoch();
    return context.epoch;
}

fn context_eql(a: anytype, b: @TypeOf(a)) bool {
    const T = @TypeOf(a);
    if (comptime @hasDecl(T, "eql")) return a.eql(b);
    return std.meta.eql(a, b);
}
