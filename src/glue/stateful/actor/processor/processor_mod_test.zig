//! commonware `glue/src/stateful/actor/processor/mod.rs` tests not covered by the sibling
//! processor test files: `rebuild_pending`'s rejections and closed-provider handling.
//! commonware's `ScriptedParentProvider` is the harness provider with the scripted parent
//! stored under the child's parent digest (or removed, for a subscription that ends).

const std = @import("std");
const testing = std.testing;
const harness_mod = @import("testing.zig");

const Harness = harness_mod.Harness;
const TestBlock = harness_mod.TestBlock;
const digested = harness_mod.digested;
const u64_digest = harness_mod.u64_digest;
const Height = @TypeOf(TestBlock.genesis().height());
const TestApp = harness_mod.TestApp;
const Probe = harness_mod.Probe;
const gpa = testing.allocator;

/// Block 1 finalized on genesis, then blocks 2 and 3 staged on it.
fn finalized_chain(harness: *Harness) ![3]TestBlock {
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    const block3 = try harness.stage_pending_child(&block2, 3);
    return .{ block1, block2, block3 };
}

/// Rebuilds `target` with the harness provider and returns the result.
fn rebuild(harness: *Harness, target: TestBlock) !void {
    var provider = harness.provider();
    return harness.execution.rebuild_pending(harness.app, &provider, try digested(target));
}

// commonware `execution_rebuild_pending_rejects_stale_ancestor_quickly`: a block below the
// anchor's height is rejected before its parent is fetched.
test "stateful processor: rebuild_pending rejects a stale ancestor without fetching" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var chain: [5]TestBlock = undefined;
    var parent = TestBlock.genesis();
    for (&chain, 1..) |*block, view| {
        block.* = try harness.stage_pending_child(&parent, view);
        try harness.finalize(block);
        parent = block.*;
    }
    harness.execution.state.clear();
    const fetches = harness.provider_state.fetches;
    try testing.expectError(error.Invalid, rebuild(&harness, chain[1]));
    try testing.expectEqual(fetches, harness.provider_state.fetches);
}

// commonware `execution_rebuild_pending_rejects_sync_target_mismatch_before_caching`: a
// replayed batch whose sync target differs from the block's is rejected and not cached.
test "stateful processor: rebuild_pending rejects a sync target mismatch" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    harness.execution.state.clear();
    var target = chain[1].target;
    target.start = 1;
    target.end = 2;
    const mismatched = TestBlock.init(chain[0].digest(), chain[1].height(), chain[1].round, target);
    try harness.provider_state.insert(mismatched);
    try testing.expectError(error.Invalid, rebuild(&harness, mismatched));
    try testing.expect(!harness.execution.pending_contains(mismatched.digest()));
}

// commonware `execution_rebuild_pending_rejects_height_gap_to_processed_anchor`: a block at
// height 3 whose parent is the anchor at height 1 is rejected and not cached.
test "stateful processor: rebuild_pending rejects a height gap to the anchor" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    const gap = TestBlock.init(chain[0].digest(), .new(3), harness_mod.round(3), chain[0].target);
    try testing.expectError(error.Invalid, rebuild(&harness, gap));
    try testing.expect(!harness.execution.pending_contains(gap.digest()));
}

// commonware `execution_rebuild_pending_rejects_wrong_parent_digest`: a fetched parent
// whose digest is not the one the child names is rejected after one fetch.
test "stateful processor: rebuild_pending rejects a wrong parent digest" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    const wrong_parent = chain[1].with_root(u64_digest(999));
    try testing.expect(!wrong_parent.digest().eql(chain[2].parent()));
    harness.execution.state.clear();
    try harness.provider_state.blocks.put(gpa, chain[2].parent(), wrong_parent);
    const fetches = harness.provider_state.fetches;
    try testing.expectError(error.Invalid, rebuild(&harness, chain[2]));
    try testing.expectEqual(fetches + 1, harness.provider_state.fetches);
    try testing.expect(!harness.execution.pending_contains(chain[2].digest()));
}

// commonware `execution_rebuild_pending_rejects_parent_at_max_height`: an unverified
// ancestor claiming height `u64::MAX` (which has no successor) is rejected after one fetch.
test "stateful processor: rebuild_pending rejects a parent at the maximum height" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    const max: Height = .new(std.math.maxInt(u64));
    const parent = TestBlock.init(chain[1].parent(), max, chain[1].round, chain[1].target);
    const third = chain[2];
    const child = TestBlock.init(parent.digest(), third.height(), third.round, third.target);
    harness.execution.state.clear();
    try harness.provider_state.insert(parent);
    const fetches = harness.provider_state.fetches;
    try testing.expectError(error.Invalid, rebuild(&harness, child));
    try testing.expectEqual(fetches + 1, harness.provider_state.fetches);
    try testing.expect(!harness.execution.pending_contains(child.digest()));
}

// commonware `execution_rebuild_pending_returns_incomplete_when_parent_subscription_ends`
// and `execution_rebuild_pending_does_not_retry_closed_provider_forever`: a parent
// subscription that closes without a block leaves the rebuild incomplete after one fetch,
// without retrying. Adapted: commonware scripts a later answer after the closed one; here
// the provider no longer holds the parent, so a retry would fetch again.
test "stateful processor: rebuild_pending is incomplete once a parent fetch closes" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    harness.execution.state.clear();
    try testing.expect(harness.provider_state.blocks.remove(chain[0].digest()));
    const fetches = harness.provider_state.fetches;
    try testing.expectError(error.Incomplete, rebuild(&harness, chain[1]));
    try testing.expectEqual(fetches + 1, harness.provider_state.fetches);
    try testing.expect(!harness.execution.pending_contains(chain[1].digest()));
}

const runtime = @import("runtime");
const db = @import("../../db/mod.zig");
const Any = harness_mod.Any;

fn counter(harness: *Harness) !?u64 {
    const readers = harness.databases.readers();
    const value = try harness_mod.read_applied(readers, harness_mod.counter_key());
    return if (value) |digest| harness_mod.digest_u64(digest) else null;
}

// commonware `execution_finalize_identical_duplicate_returns_false` and
// `execution_duplicate_finalization_skips_hooks`: a duplicate finalization of the applied
// block is reported as such, and applies nothing and runs no hook. Adapted: zigware's
// duplicate check is `redelivered`, which the processing loop consults before `finalize`
// (commonware's `finalize` returns false), so the hooks are never reached.
test "stateful processor: an identical duplicate finalization is a redelivery" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var observations: std.ArrayList(TestApp.Observation) = .empty;
    defer observations.deinit(gpa);
    harness.processor.app.observations = &observations;
    const genesis = TestBlock.genesis();
    const block = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block);
    try testing.expectEqual(1, observations.items.len);
    observations.clearRetainingCapacity();
    var again = try digested(block);
    defer again.deinit();
    try testing.expect(harness.processor.redelivered(&again));
    try testing.expectEqual(0, observations.items.len);
    try testing.expectEqual(1, try counter(&harness));
}

// commonware `execution_finalization_persists_state_to_db`: a finalized block's state
// survives reopening the database.
test "stateful processor: finalization persists state across a reopen" {
    var harness: Harness = undefined;
    try harness.init();
    const genesis = TestBlock.genesis();
    const block = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block);
    try testing.expectEqual(1, try counter(&harness));
    // Close the database (and the processor over it), then reopen it on the same storage.
    harness.processor.deinit();
    harness.databases.deinit();
    defer {
        harness.provider_state.deinit();
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }
    const env: db.Env = .{
        .gpa = gpa,
        .io = testing.io,
        .storage = harness.storage.interface(),
        .scope = runtime.telemetry.metrics.Scope.init(&harness.registry).child("reopen"),
    };
    var reopened = try Any.Shared.open(env, harness.config(), null);
    defer reopened.deinit();
    const key = harness_mod.height_key(block.height());
    const view = (try harness_mod.read_applied(reopened.readers(), key)).?;
    try testing.expectEqual(1, harness_mod.digest_u64(view));
}

// commonware `execution_finalized_handoff_preserves_cached_and_reconstructed_captures`: a
// cached block finalizes from its batch without processing; an uncached one is
// reconstructed through `process`. Each capture sees the pre-apply state, and each
// finalized hook receives that capture after the apply.
test "stateful processor: finalized hooks see cached and reconstructed captures" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var observations: std.ArrayList(TestApp.Observation) = .empty;
    defer observations.deinit(gpa);
    const app = &harness.processor.app;
    app.observations = &observations;
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 7);
    const block2 = try harness.stage_pending_child(&block1, 11);

    var cached: Probe = .{ .target = block1.digest() };
    defer cached.deinit();
    app.probe = &cached;
    try harness.finalize(&block1);
    try testing.expectEqual(0, cached.calls); // Finalized from its cached batch.
    harness.execution.state.clear();
    var reconstructed: Probe = .{ .target = block2.digest() };
    defer reconstructed.deinit();
    app.probe = &reconstructed;
    try harness.finalize(&block2);
    try testing.expectEqual(1, reconstructed.calls);

    const expected = [_]TestApp.Observation{
        .{
            .captured = .{ .prior_counter = null, .batch_counter = 1, .batch_view = 7 },
            .post_counter = 1,
            .post_view = 7,
        },
        .{
            .captured = .{ .prior_counter = 1, .batch_counter = 2, .batch_view = 11 },
            .post_counter = 2,
            .post_view = 11,
        },
    };
    try testing.expectEqualSlices(TestApp.Observation, &expected, observations.items);
}
