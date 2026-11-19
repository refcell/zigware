//! Shared marshal fixtures for stateful actor tests (commonware
//! `glue/src/stateful/tests/fixtures.rs`): a real marshal actor over immutable or prunable
//! finalized archives on the deterministic runtime's storage, started with a reporter that
//! acknowledges every block or holds its receipts, and a backfill resolver that ignores every
//! fetch. Aborting a fixture releases its storage, so a later fixture with the same prefix
//! restarts on the same partitions. Only tests import it.
//!
//! zigware differences: blocks are marshal's mock block (`mocks.harness.B`), signed by the
//! mock harness's validators; commonware's glue `TestBlock` and one-validator scheme carry
//! no behavior these tests check.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const resolver_api = @import("resolver");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");

const marshal = consensus.marshal;
const harness = marshal.mocks.harness;
const handler = marshal.resolver.handler;
pub const H = harness.StandardHarness;
pub const V = H.Variant;
/// The marshal block (digested) the mailbox serves.
pub const Block = H.TestBlock;
pub const B = harness.B;
pub const D = harness.D;
pub const K = harness.K;
pub const S = harness.S;
pub const Finalization = harness.Finalization;
pub const Validators = harness.Fixture;
pub const Reporter = marshal.mocks.Application(B);
pub const Ctx = runtime.deterministic.Context;
pub const Height = consensus.Height;
pub const Round = consensus.Round;
pub const Floor = marshal.core.Floor;
pub const Processed = marshal.core.Processed;
pub const Cutoff = marshal.core.Cutoff;

/// marshal's mock types: the fixture every caller used before `FixtureFor`.
pub const Defaults = struct {
    pub const B = harness.B;
    pub const D = harness.D;
    pub const K = harness.K;
    pub const S = harness.S;
    pub const Finalization = harness.Finalization;
    pub const Validators = harness.Fixture;
    pub const Provider = harness.Provider;
    pub const Application = marshal.mocks.Application(harness.B);

    pub fn genesis(gpa: Allocator) !H.TestBlock {
        return H.genesis_block(gpa, harness.num_validators);
    }
};

pub const FixtureFor = @import("marshal_fixture_for.zig").FixtureFor;
const default = FixtureFor(Defaults);
pub const IgnoreResolver = default.IgnoreResolver;
pub const PrunableStores = default.PrunableStores;
pub const ImmutableStores = default.ImmutableStores;
pub const Params = default.Params;
pub const Options = default.Options;
pub const Fixture = default.Fixture;

/// The test chain: blocks `0..count`, each the child of the one before, block 0 being the
/// genesis every fixture starts from. The caller frees it with `free_chain`.
pub fn chain(gpa: Allocator, count: usize) ![]Block {
    assert(count > 0);
    const blocks = try gpa.alloc(Block, count);
    var made: usize = 0;
    errdefer {
        for (blocks[0..made]) |*block| block.deinit();
        gpa.free(blocks);
    }
    blocks[0] = try H.genesis_block(gpa, harness.num_validators);
    made = 1;
    for (1..count) |index| {
        const parent = blocks[index - 1].digest();
        blocks[index] = try H.make_test_block(gpa, parent, parent, .new(index), index, 0);
        made += 1;
    }
    assert(made == count);
    return blocks;
}

pub fn free_chain(gpa: Allocator, blocks: []Block) void {
    for (blocks) |*block| block.deinit();
    gpa.free(blocks);
}

pub fn round(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// A finalization for `view` over `payload`, signed by every validator (commonware
/// `finalization`).
pub fn finalization(
    gpa: Allocator,
    validators: *const Validators,
    view: u64,
    payload: D,
) !Finalization {
    const parent: consensus.View = .new(view -| 1);
    const proposal = harness.Proposal.init(round(view), parent, payload);
    return harness.make_finalization(gpa, validators, proposal, harness.num_validators);
}

/// The signing validators (commonware `scheme_mocks::fixture`).
pub fn make_validators(gpa: Allocator) !Validators {
    var rng = utils.rng.test_rng();
    return harness.fixture(gpa, &rng);
}

/// Polls `condition(args)` every simulated millisecond, failing after `limit_ms`.
pub fn wait_until(ctx: Ctx, limit_ms: u64, condition: anytype, args: anytype) !void {
    for (0..limit_ms) |_| {
        if (try @call(.auto, condition, args)) return;
        try ctx.sleep(.fromMilliseconds(1));
    }
    return error.TestConditionTimeout;
}
