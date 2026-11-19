//! commonware `glue/src/stateful/actor/core/processing.rs` tests, second half (from
//! `finalization_joins_incompatible_verification`); the first half is processing_test.zig.
//! Barriers complete synchronously here, so tests built on a pending barrier or gated
//! ancestry acquisition say in their comment how they were adapted.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const utils = @import("utils");
const runtime = @import("runtime");
const core = @import("testing.zig");
const test_io = @import("../../test_io.zig");

const harness = core.harness;
const TestBlock = harness.TestBlock;
const Fixture = core.Fixture;
const gpa = testing.allocator;

fn deinit_fixture(fixture: *Fixture) void {
    fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
}

// commonware `finalization_joins_incompatible_verification`: a verification on a fork the
// finalization abandons keeps running while finalization waits for it, then resolves
// false. Adapted: commonware also parks an ancestry acquisition to learn when
// finalization paused; here the pending acknowledgement shows the wait.
test "stateful processing: finalization joins an incompatible verification" {
    try test_io.run_on_deterministic(late_joins_incompatible);
}

fn late_joins_incompatible() anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const winner, var winner_batch = try fixture.harness.build_child(&genesis, 1);
    winner_batch.deinit();
    // The fork's parent is staged (cached and fetchable) so its child can be built on it.
    const losing_parent = try fixture.harness.stage_pending_child(&genesis, 2);
    const losing_child, var child_batch = try fixture.harness.build_child(&losing_parent, 3);
    child_batch.deinit();

    var fork = try fixture.verify(&.{ losing_parent, genesis });
    defer fork.deinit();
    try testing.expect(try fork.recv());

    var probe: harness.Probe = .{ .target = losing_child.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;
    var child = try fixture.verify(&.{ losing_child, losing_parent });
    defer child.deinit();
    try started.recv();

    var waiter = try fixture.finalize(winner);
    defer waiter.deinit();
    // Give finalization time to act: it must still be waiting on the gated child.
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, waiter.poll());
    try release.send({});
    try waiter.wait();
    try testing.expect(!try child.recv());
}

// commonware `finalization_rejects_deep_incompatible_verification`: a gated verification two
// blocks deep on a fork the finalization prunes keeps running while finalization waits,
// then resolves false. Adapted like the shallow case: the pending acknowledgement shows the
// wait instead of a parked ancestry acquisition.
test "stateful processing: finalization rejects a deep incompatible verification" {
    try test_io.run_on_deterministic(late_rejects_deep_incompatible);
}

fn late_rejects_deep_incompatible() anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const winner, var winner_batch = try fixture.harness.build_child(&genesis, 1);
    winner_batch.deinit();
    const losing_parent = try fixture.harness.stage_pending_child(&genesis, 2);
    const losing_child = try fixture.harness.stage_pending_child(&losing_parent, 3);
    const grandchild, var grandchild_batch = try fixture.harness.build_child(&losing_child, 4);
    grandchild_batch.deinit();

    var parent = try fixture.verify(&.{ losing_parent, genesis });
    defer parent.deinit();
    try testing.expect(try parent.recv());
    var child = try fixture.verify(&.{ losing_child, losing_parent });
    defer child.deinit();
    try testing.expect(try child.recv());

    var probe: harness.Probe = .{ .target = grandchild.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;
    var deep = try fixture.verify(&.{ grandchild, losing_child });
    defer deep.deinit();
    try started.recv();

    var waiter = try fixture.finalize(winner);
    defer waiter.deinit();
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, waiter.poll());
    try release.send({});
    try waiter.wait();
    try testing.expect(!try deep.recv());
}

// commonware `anchor_redelivery_keeps_retained_verification_progressing`: redelivering the
// finalized anchor is acknowledged without rerunning its hooks, and does not resolve a
// gated verification of its child. Adapted: the harness anchors at genesis, so block 1 is
// finalized first and becomes the anchor that is redelivered.
test "stateful processing: anchor redelivery keeps a retained verification running" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const finalized = try fixture.harness.stage_pending_child(&genesis, 1);
    var first = try fixture.finalize(finalized);
    defer first.deinit();
    try first.wait();
    const child, var batch = try fixture.harness.build_child(&finalized, 2);
    batch.deinit();

    var probe: harness.Probe = .{ .target = child.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;
    var hooks: harness.Probe = .{ .target = finalized.digest() };
    defer hooks.deinit();
    const app = &fixture.processing.processor.app;
    app.probe = &hooks;
    app.capture_probe = &hooks;
    app.finalized_probe = &hooks;

    var verdict = try fixture.verify(&.{ child, finalized });
    defer verdict.deinit();
    try started.recv();
    var again = try fixture.finalize(finalized);
    defer again.deinit();
    try again.wait();
    try testing.expect(!verdict.is_ready());
    try release.send({});
    try testing.expect(try verdict.recv());
    try testing.expectEqual(0, hooks.calls);
}

// commonware `fresh_boot_genesis_skips_hooks`: on a fresh boot the genesis anchor's
// finalization is acknowledged without processing, capture, or finalized hooks.
test "stateful processing: a fresh boot's genesis finalization skips the hooks" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    var hooks: harness.Probe = .{ .target = genesis.digest() };
    defer hooks.deinit();
    const app = &fixture.processing.processor.app;
    app.probe = &hooks;
    app.capture_probe = &hooks;
    app.finalized_probe = &hooks;
    var waiter = try fixture.finalize(genesis);
    defer waiter.deinit();
    try waiter.wait();
    try testing.expectEqual(0, hooks.calls);
    try testing.expectEqual(null, try fixture.counter());
}

fn run_processing(processing: *core.Processing) anyerror!void {
    return processing.run();
}

// commonware `deferred_verification_resumes_after_sync`: a verification deferred before
// the processing loop starts (as the syncing actor defers one until its databases are
// ready) runs once the loop starts, and answers.
test "stateful processing: a deferred verification resumes once processing starts" {
    var fixture: Fixture = undefined;
    try fixture.harness.init();
    fixture.prunes = .empty;
    fixture.future = null;
    const pair = try actor.mailbox.new(core.Message, gpa, test_io.io, 8);
    fixture.receiver = pair.receiver;
    fixture.mailbox = core.Mailbox.init(gpa, test_io.io, pair.sender);
    const marshal: core.TestMarshal = .{ .prunes = &fixture.prunes };
    const provider = fixture.harness.provider();
    const processor = &fixture.harness.processor;
    fixture.processing = .init(gpa, test_io.io, &fixture.receiver, provider, marshal, processor);
    defer deinit_fixture(&fixture);

    const genesis = TestBlock.genesis();
    const block, var batch = try fixture.harness.build_child(&genesis, 1);
    batch.deinit();
    const verdict_pair = try utils.channel.oneshot.channel(bool, gpa, test_io.io);
    var verdict = verdict_pair.receiver;
    defer verdict.deinit();
    fixture.processing.defer_verification(.{
        .ancestry = try fixture.harness.ancestry(&.{ block, genesis }),
        .verification = verdict_pair.sender,
    });
    try testing.expect(!verdict.is_ready());

    fixture.future = try test_io.io.concurrent(run_processing, .{&fixture.processing});
    try testing.expect(try verdict.recv());
}

/// A parent of genesis at view 1 and two children of it at views 2 and 3, built in a
/// scratch harness so the fixture's cache does not hold the parent's state.
fn uncached_family() !struct { TestBlock, TestBlock, TestBlock } {
    var scratch: harness.Harness = undefined;
    try scratch.init();
    defer scratch.deinit();
    const genesis = TestBlock.genesis();
    const parent = try scratch.stage_pending_child(&genesis, 1);
    const first, var first_batch = try scratch.build_child(&parent, 2);
    first_batch.deinit();
    const second, var second_batch = try scratch.build_child(&parent, 3);
    second_batch.deinit();
    return .{ parent, first, second };
}

// commonware `finalization_reuses_shared_parent_recovery`: two children's verifications
// share one execution of their uncached parent; the parent's finalization waits for that
// execution and reuses it, and both children then verify. The parent is processed once.
test "stateful processing: finalization reuses a shared parent recovery" {
    try test_io.run_on_deterministic(late_reuses_parent_recovery);
}

fn late_reuses_parent_recovery() anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const parent, const first_child, const second_child = try uncached_family();

    var probe: harness.Probe = .{ .target = parent.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;
    fixture.processing.processor.app.probe = &probe;

    var first = try fixture.verify(&.{ first_child, parent });
    defer first.deinit();
    var second = try fixture.verify(&.{ second_child, parent });
    defer second.deinit();
    try started.recv();
    var waiter = try fixture.finalize(parent);
    defer waiter.deinit();
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, waiter.poll());
    try release.send({});
    try waiter.wait();
    try testing.expect(try first.recv());
    try testing.expect(try second.recv());
    try testing.expectEqual(1, probe.calls);
}

const Managed = enum { verify, propose };

/// A descendant request in flight: a verification's verdict, or a proposal running on its
/// own task (the mailbox's propose blocks until it answers).
const Descendant = union(Managed) {
    verify: utils.channel.oneshot.Receiver(bool),
    propose: std.Io.Future(anyerror!bool),

    fn send(fixture: *Fixture, request: Managed, blocks: []const TestBlock) !Descendant {
        std.debug.assert(blocks.len >= 2);
        return switch (request) {
            .verify => .{ .verify = try fixture.verify(blocks) },
            .propose => .{ .propose = try test_io.io.concurrent(propose_on, .{ fixture, blocks }) },
        };
    }

    fn propose_on(fixture: *Fixture, blocks: []const TestBlock) anyerror!bool {
        const context: TestBlock.Context = .{ .round = harness.round(0xff) };
        const ancestry = try fixture.harness.ancestry(blocks);
        var built = try fixture.mailbox.?.propose({}, context, ancestry, {}) orelse return false;
        defer built.deinit();
        return built.inner().parent().eql(blocks[0].digest());
    }

    fn pending(descendant: *Descendant) bool {
        return switch (descendant.*) {
            .verify => |*verdict| !verdict.is_ready(),
            .propose => true, // Checked by the caller's later await.
        };
    }

    fn wait(descendant: *Descendant) !bool {
        return switch (descendant.*) {
            .verify => |*verdict| verdict.recv(),
            .propose => |*future| future.await(test_io.io),
        };
    }

    fn deinit(descendant: *Descendant) void {
        switch (descendant.*) {
            .verify => |*verdict| verdict.deinit(),
            .propose => |*future| _ = future.cancel(test_io.io) catch {},
        }
    }
};

/// Genesis, then blocks at views 1, 2, and 3, each on the last, built in a scratch harness
/// so the fixture holds none of their state.
fn uncached_chain() !struct { TestBlock, TestBlock, TestBlock } {
    var scratch: harness.Harness = undefined;
    try scratch.init();
    defer scratch.deinit();
    const genesis = TestBlock.genesis();
    const first = try scratch.stage_pending_child(&genesis, 1);
    const second = try scratch.stage_pending_child(&first, 2);
    const child, var batch = try scratch.build_child(&second, 3);
    batch.deinit();
    return .{ first, second, child };
}

fn consecutive_finalizations(request: Managed) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const first, const second, const child = try uncached_chain();
    // The replay path comes from the provider (commonware's marshal holds these blocks).
    try fixture.harness.provider_state.insert(first);
    try fixture.harness.provider_state.insert(second);
    // Null target: gates apply to processed blocks in call order (first, second, child).
    var probe: harness.Probe = .{ .target = null };
    defer probe.deinit();
    const replay = try probe.add_gate();
    var replay_started = replay.started;
    defer replay_started.deinit();
    var replay_release = replay.release;
    fixture.processing.verifications.verifier.app.probe = &probe;
    fixture.processing.processor.app.probe = &probe;

    var descendant = try Descendant.send(&fixture, request, &.{ child, second, first, genesis });
    defer descendant.deinit();
    try replay_started.recv();
    // An independent verification of the first block joins its replay. Wait for the join:
    // an acquisition still running when finalization pauses admission restarts once `first`
    // is applied, and then waits for its canonical digest instead of joining.
    var verify_first = try fixture.verify(&.{ first, genesis });
    defer verify_first.deinit();
    try fixture.await_joiners(first.digest(), 2);
    try testing.expect(!verify_first.is_ready());
    try finalize_across(&fixture, &probe, &descendant, &replay_release, &verify_first, .{
        first,
        second,
    });
    // Each block ran once: the finalizations reused the request's executions.
    try testing.expectEqual(3, probe.calls);
}

/// Finalizes `blocks[0]` while its replay is held, then `blocks[1]` while the descendant's
/// own processing is held, and checks the descendant completes valid. `verify_first` (a
/// verification of `blocks[0]` joined to its replay) is answered valid before the second
/// finalization, as in commonware: once the anchor passes `blocks[0]`, a resumed acquisition
/// needs its canonical digest, which this provider does not record, and would wait.
fn finalize_across(
    fixture: *Fixture,
    probe: *harness.Probe,
    descendant: *Descendant,
    replay_release: *utils.channel.oneshot.Sender(void),
    verify_first: *utils.channel.oneshot.Receiver(bool),
    blocks: [2]TestBlock,
) !void {
    const second_gate = try probe.add_gate();
    var second_started = second_gate.started;
    defer second_started.deinit();
    var second_release = second_gate.release;
    const own = try probe.add_gate();
    var own_started = own.started;
    defer own_started.deinit();
    var own_release = own.release;

    var first_waiter = try fixture.finalize(blocks[0]);
    defer first_waiter.deinit();
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, first_waiter.poll());
    try replay_release.send({});
    try first_waiter.wait();
    try testing.expect(try verify_first.recv());
    try second_started.recv();
    try second_release.send({});
    try own_started.recv();
    try testing.expect(descendant.pending());
    // The second finalization keeps the descendant's processing running.
    var second_waiter = try fixture.finalize(blocks[1]);
    defer second_waiter.deinit();
    try second_waiter.wait();
    try own_release.send({});
    try testing.expect(try descendant.wait());
}

// commonware `consecutive_finalizations_preserve_descendant_replay` (verify case): a
// descendant's verification advances across consecutive finalizations of its ancestors
// without re-running their completed executions. Adapted: the ancestry is passed whole
// (commonware fetches the first block from marshal), and per-block call counts are a total.
test "stateful processing: consecutive finalizations preserve a descendant verification" {
    try consecutive_finalizations(.verify);
}

// commonware `consecutive_finalizations_preserve_descendant_replay` (propose case): the same
// with a build on the descendant.
test "stateful processing: consecutive finalizations preserve a descendant proposal" {
    try test_io.run_on_deterministic(late_consecutive_finalizations);
}

fn late_consecutive_finalizations() anyerror!void {
    try consecutive_finalizations(.propose);
}

/// Blocks at views 1 to 4, each on the last. The fixture caches the first two (finalizable
/// without a replay); the third and fourth come from a scratch harness, so the fixture holds
/// none of their state.
fn prunable_chain(fixture: *Fixture) ![4]TestBlock {
    var scratch: harness.Harness = undefined;
    try scratch.init();
    defer scratch.deinit();
    const genesis = TestBlock.genesis();
    var chain: [4]TestBlock = undefined;
    chain[0] = try fixture.harness.stage_pending_child(&genesis, 1);
    chain[1] = try fixture.harness.stage_pending_child(&chain[0], 2);
    const first = try scratch.stage_pending_child(&genesis, 1);
    try testing.expect(chain[0].digest().eql(first.digest()));
    const second = try scratch.stage_pending_child(&chain[0], 2);
    try testing.expect(chain[1].digest().eql(second.digest()));
    chain[2] = try scratch.stage_pending_child(&chain[1], 3);
    chain[3], var batch = try scratch.build_child(&chain[2], 4);
    batch.deinit();
    try fixture.harness.provider_state.insert(chain[2]);
    return chain;
}

/// Prunes after every finalized height and retains nothing beyond the pending window.
fn eager_pruning() !harness.Processor.Pruning {
    const config: @import("../processor/pruning.zig").PruneConfig = .{
        .maintenance_interval = 1,
        .retained_marshal_blocks = 0,
        .retained_qmdb_blocks = 0,
    };
    return harness.Processor.Pruning.init(gpa, config, 1, 0);
}

fn pruning_joins_execution(request: Managed) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    // Set before any message, so the loop reads it after the mailbox hand-off.
    fixture.harness.processor.pruning = try eager_pruning();
    const chain = try prunable_chain(&fixture);
    // Null target: the first gate holds the parent's replay, the second the request's next
    // step (the child's processing, or the build on the parent).
    var probe: harness.Probe = .{ .target = null };
    defer probe.deinit();
    const replay = try probe.add_gate();
    var replay_started = replay.started;
    defer replay_started.deinit();
    var replay_release = replay.release;
    const step = try probe.add_gate();
    var step_started = step.started;
    defer step_started.deinit();
    var step_release = step.release;
    for ([_]*harness.TestApp{
        &fixture.processing.verifications.verifier.app,
        &fixture.processing.processor.app,
    }) |app| {
        app.probe = &probe;
        app.propose_probe = &probe;
    }

    const blocks: []const TestBlock = switch (request) {
        .verify => &.{ chain[3], chain[2] },
        .propose => &.{ chain[2], chain[1] },
    };
    var pending = try Descendant.send(&fixture, request, blocks);
    defer pending.deinit();
    try replay_started.recv();
    var first_waiter = try fixture.finalize(chain[0]);
    defer first_waiter.deinit();
    try first_waiter.wait();
    var second_waiter = try fixture.finalize(chain[1]);
    defer second_waiter.deinit();
    // The prune waits for the parent's replay to finish.
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(0, fixture.prunes.items.len);
    try replay_release.send({});
    // The request's next step starts only once the prune completed.
    try step_started.recv();
    try testing.expectEqualSlices(u64, &.{1}, fixture.prunes.items);
    try step_release.send({});
    try testing.expect(try pending.wait());
    try second_waiter.wait();
    try testing.expectEqual(2, probe.calls);
}

// commonware `pruning_joins_execution_before_database_prune` (verify case): pruning waits
// for a verification's replay of the parent before pruning, and the verification then
// continues without replaying the parent again. Adapted: barriers and prunes complete
// synchronously here, so the prune is seen through marshal's recorded prunes, and the
// target barrier's pending flush is not modeled.
test "stateful processing: pruning joins a verification's replay before pruning" {
    try pruning_joins_execution(.verify);
}

// commonware `pruning_joins_execution_before_database_prune` (propose case): the same with
// a build on the replayed parent.
test "stateful processing: pruning joins a proposal's replay before pruning" {
    try pruning_joins_execution(.propose);
}

// commonware `prune_preserves_completed_verdict_before_later_finalization`: a verification
// on a fork held while blocks 1 and 2 finalize holds the prune back; once released, the
// prune runs, a later finalization of the competing block does not invalidate the
// completed verdict, and a build on that block proceeds. Adapted: barriers and prunes
// complete synchronously, so the prune is seen through marshal's recorded prunes; and the
// test app builds a block where commonware's gated app declines.
test "stateful processing: a prune preserves a completed verdict before a later finalization" {
    try test_io.run_on_deterministic(late_prune_preserves_verdict);
}

fn late_prune_preserves_verdict() anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    fixture.harness.processor.pruning = try eager_pruning();
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    const losing, var losing_batch = try fixture.harness.build_child(&block2, 3);
    losing_batch.deinit();
    const winner, var winner_batch = try fixture.harness.build_child(&block2, 4);
    winner_batch.deinit();

    var verify_probe: harness.Probe = .{ .target = losing.digest() };
    defer verify_probe.deinit();
    const verify_gate = try verify_probe.add_gate();
    var verify_started = verify_gate.started;
    defer verify_started.deinit();
    var verify_release = verify_gate.release;
    fixture.processing.verifications.verifier.app.probe = &verify_probe;
    var build_probe: harness.Probe = .{ .target = winner.digest() };
    defer build_probe.deinit();
    const build_gate = try build_probe.add_gate();
    var build_started = build_gate.started;
    defer build_started.deinit();
    var build_release = build_gate.release;
    fixture.processing.processor.app.propose_probe = &build_probe;

    // The verification starts first: with no held target flush, the prune would otherwise
    // run before it arrives.
    var verdict = try fixture.verify(&.{ losing, block2 });
    defer verdict.deinit();
    try verify_started.recv();
    var first_waiter = try fixture.finalize(block1);
    defer first_waiter.deinit();
    var second_waiter = try fixture.finalize(block2);
    defer second_waiter.deinit();
    try first_waiter.wait();
    // The prune waits for the verification's running processing.
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(0, fixture.prunes.items.len);
    try verify_release.send({});

    var winner_waiter = try fixture.finalize(winner);
    defer winner_waiter.deinit();
    var proposal = try Descendant.send(&fixture, .propose, &.{ winner, block2 });
    defer proposal.deinit();
    try build_started.recv();
    try testing.expect(try verdict.recv()); // The later finalization kept the verdict.
    try testing.expectEqual(1, verify_probe.calls);
    try testing.expectEqual(1, fixture.prunes.items[0]);
    try build_release.send({});
    try testing.expect(try proposal.wait());
    try second_waiter.wait();
    try winner_waiter.wait();
}

// commonware `prune_starts_after_target_barrier`: with blocks 1 and 2 finalized, a
// verification held in the application does not wait for the pending prune, and the prune
// to block 1 runs once it finishes. Adapted: barriers are durable when they start, so
// commonware's held target flush (and the acknowledgements it holds back) is not modeled;
// what remains is that the prune neither blocks nor overtakes the active verification.
test "stateful processing: a pending prune does not block an active verification" {
    try test_io.run_on_deterministic(late_pending_prune_unblocked);
}

fn late_pending_prune_unblocked() anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    fixture.harness.processor.pruning = try eager_pruning();
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    const block3, var batch = try fixture.harness.build_child(&block2, 3);
    batch.deinit();
    var probe: harness.Probe = .{ .target = block3.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;

    // Queued before pruning starts, as in commonware.
    var verdict = try fixture.verify(&.{ block3, block2 });
    defer verdict.deinit();
    try started.recv();
    var first_waiter = try fixture.finalize(block1);
    defer first_waiter.deinit();
    var second_waiter = try fixture.finalize(block2);
    defer second_waiter.deinit();
    try first_waiter.wait();
    try second_waiter.wait();
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(0, fixture.prunes.items.len);
    try release.send({});
    try testing.expect(try verdict.recv());
    // The prune runs once the verification's processing finished, ahead of the next
    // finalization's acknowledgement.
    var third_waiter = try fixture.finalize(block3);
    defer third_waiter.deinit();
    try third_waiter.wait();
    try testing.expectEqual(1, fixture.prunes.items[0]);
}

// commonware `prune_starts_after_target_barrier`'s first half, on a held sync: the prune
// waits for block 1's barrier and drives the active verification to its verdict meanwhile,
// then prunes once the sync is released. Adapted: commonware holds a mock database's flush;
// here block 1's real syncs park in `DelayedSync`, and the prune is due at block 1 (no
// pending acknowledgements), since applying block 2 would wait on block 1's held sync.
test "stateful processing: a prune waiting on a held sync drives an active verification" {
    try test_io.run_on_deterministic(late_prune_drives_verification);
}

fn late_prune_drives_verification() anyerror!void {
    var pending: DelayedSync = .init(gpa, test_io.io);
    defer pending.deinit();
    var fixture: Fixture = undefined;
    var delayed: DelayedSynced = undefined;
    try init_delayed(&fixture, &delayed, &pending);
    defer deinit_fixture(&fixture);
    defer pending.unblock();
    fixture.harness.processor.pruning = try harness.Processor.Pruning.init(gpa, .{
        .maintenance_interval = 1,
        .retained_marshal_blocks = 0,
        .retained_qmdb_blocks = 0,
    }, 0, 0);
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    const block3, var batch = try fixture.harness.build_child(&block2, 3);
    batch.deinit();
    var probe: harness.Probe = .{ .target = block3.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;

    var verdict = try fixture.verify(&.{ block3, block2 });
    defer verdict.deinit();
    try started.recv();
    var waiter = try fixture.finalize(block1);
    defer waiter.deinit();
    try wait_until_parked(&pending);
    // The barrier's syncs park one after another, so count releases rather than parked syncs.
    const completed = pending.completions();
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expect(waiter.poll() == null);

    // The verdict arrives while block 1's sync is still held, and nothing is pruned yet.
    try release.send({});
    try testing.expect(try recv_within(&verdict, 10_000));
    try testing.expectEqual(completed, pending.completions());
    try testing.expect(pending.parked() > 0);
    try testing.expectEqual(0, fixture.prunes.items.len);
    try testing.expect(waiter.poll() == null);

    pending.release_all();
    try waiter.wait();
    try wait_until_pruned(&fixture);
    try testing.expectEqual(1, fixture.prunes.items[0]);
}

const DelayedSync = runtime.storage.mocks.DelayedSync;
const DelayedSynced = runtime.storage.mocks.DelayedSynced;

/// Opens `fixture` over `delayed`, a `DelayedSynced` of its storage, releasing the open's
/// syncs. None of the three may move afterwards.
fn init_delayed(fixture: *Fixture, delayed: *DelayedSynced, pending: *DelayedSync) !void {
    fixture.harness.init_storage();
    delayed.* = .init(gpa, fixture.harness.storage.interface(), pending);
    var releaser: Releaser = .{ .pending = pending };
    var releasing = try test_io.io.concurrent(Releaser.run, .{&releaser});
    defer {
        releaser.stop.store(true, .release);
        releasing.await(test_io.io);
    }
    try fixture.init_with(delayed.storage());
}

/// Releases every parked sync until `stop` is set, so a database opens over a DelayedSync.
const Releaser = struct {
    pending: *DelayedSync,
    stop: std.atomic.Value(bool) = .init(false),

    fn run(self: *Releaser) void {
        // Each pass releases what parked since the last one; the open is bounded.
        while (!self.stop.load(.acquire)) {
            if (self.pending.parked() > 0) self.pending.release_all();
            test_io.io.sleep(.fromMilliseconds(1), .awake) catch return;
        }
        std.debug.assert(self.stop.load(.acquire));
    }
};

/// Receives `receiver`'s value, failing after about `timeout_ms` rather than hanging.
fn recv_within(receiver: anytype, timeout_ms: u64) !bool {
    // Each pass polls once and sleeps a millisecond.
    for (0..timeout_ms) |_| {
        if (receiver.try_recv()) |value| return value else |err| switch (err) {
            error.Empty => try test_io.io.sleep(.fromMilliseconds(1), .awake),
            error.Closed => return err,
        }
    }
    return error.Timeout;
}

fn wait_until_parked(pending: *DelayedSync) !void {
    // Each pass sleeps a millisecond; the barrier's syncs start with the finalization.
    for (0..2_000) |_| {
        if (pending.parked() > 0) return;
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

fn wait_until_pruned(fixture: *const Fixture) !void {
    // Each pass sleeps a millisecond; the prune follows the released sync.
    for (0..2_000) |_| {
        if (fixture.prunes.items.len > 0) return;
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

// commonware `finalized_handoff_survives_pending_barrier`: block 1's acknowledgement waits
// while its finalized hook is held; after release, block 2 applies and both are
// acknowledged, each captured once. Adapted: barriers are durable when they start, so
// commonware's held flush (block 2 applying behind block 1's pending barrier) is not
// modeled; the held hook stands in for the pending handoff.
test "stateful processing: a finalized handoff survives a held finalized hook" {
    try test_io.run_on_deterministic(late_handoff_survives_held_hook);
}

fn late_handoff_survives_held_hook() anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2, var batch = try fixture.harness.build_child(&block1, 2);
    batch.deinit();
    var hook: harness.Probe = .{ .target = block1.digest() };
    defer hook.deinit();
    const gate = try hook.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    var captures: harness.Probe = .{ .target = null };
    defer captures.deinit();
    const app = &fixture.processing.processor.app;
    app.finalized_probe = &hook;
    app.capture_probe = &captures;

    var first_waiter = try fixture.finalize(block1);
    defer first_waiter.deinit();
    try started.recv();
    try testing.expectEqual(1, captures.calls);
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, first_waiter.poll());
    try release.send({});
    var second_waiter = try fixture.finalize(block2);
    defer second_waiter.deinit();
    try first_waiter.wait();
    try second_waiter.wait();
    try testing.expectEqual(2, captures.calls);
    try testing.expectEqual(2, try fixture.counter());
}

// commonware `duplicate_reports_wait_for_durability` (success case): a redelivered report
// of an applied height is acknowledged once a barrier covers it, without applying the
// block again. Adapted: the covering barrier is durable when it starts, so the duplicate
// is acknowledged at once. The failure case (a failed covering flush stops processing and
// cancels the duplicate) is not portable: the covering flush has already succeeded.
test "stateful processing: a duplicate report waits for durability without reapplying" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const block1, var batch = try fixture.harness.build_child(&genesis, 1);
    batch.deinit();
    var captures: harness.Probe = .{ .target = null };
    defer captures.deinit();
    fixture.processing.processor.app.capture_probe = &captures;
    var first_waiter = try fixture.finalize(block1);
    defer first_waiter.deinit();
    try first_waiter.wait();
    var duplicate = try fixture.finalize(block1);
    defer duplicate.deinit();
    try duplicate.wait();
    try testing.expectEqual(1, captures.calls);
    try testing.expectEqual(1, try fixture.counter());
}

/// commonware `live_floor_fences_suffix_ack`'s body for a floor at `floor_height`, with
/// genesis reported (and skipped as the anchor) first when `genesis_processed`.
fn live_floor_redelivery(floor_height: u64, genesis_processed: bool) !void {
    std.debug.assert(floor_height >= 1 and floor_height <= 2);
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    var chain: [5]TestBlock = undefined;
    chain[0] = TestBlock.genesis();
    const tip_index: usize = @intCast(floor_height + 2);
    for (1..tip_index + 1) |index| {
        chain[index] = try fixture.harness.stage_pending_child(&chain[index - 1], index);
    }
    const tip = chain[tip_index];
    const child, var batch = try fixture.harness.build_child(&tip, floor_height + 3);
    batch.deinit();
    var captures: harness.Probe = .{ .target = null };
    defer captures.deinit();
    fixture.processing.processor.app.capture_probe = &captures;
    var probe: harness.Probe = .{ .target = child.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;

    const first: usize = if (genesis_processed) 0 else 1;
    for (chain[first .. tip_index + 1]) |block| try finalize_and_wait(&fixture, block);
    try testing.expectEqual(tip_index, captures.calls);
    // A child of the applied tip stays valid while the floor's suffix is redelivered.
    var verdict = try fixture.verify(&.{ child, tip });
    defer verdict.deinit();
    try started.recv();
    // Installing the floor redelivers F through F+2 with fresh receipts: each is
    // acknowledged and nothing is applied again.
    for (chain[@intCast(floor_height) .. tip_index + 1]) |block| {
        try finalize_and_wait(&fixture, block);
    }
    try testing.expectEqual(tip_index, captures.calls);
    try testing.expect(!verdict.is_ready()); // The verification is not restarted.
    try release.send({});
    try testing.expect(try verdict.recv());
    try testing.expectEqual(1, probe.calls);
    try testing.expectEqual(tip_index, try fixture.counter());
}

fn finalize_and_wait(fixture: *Fixture, block: TestBlock) !void {
    var waiter = try fixture.finalize(block);
    defer waiter.deinit();
    try waiter.wait();
}

// commonware `live_floor_fences_suffix_ack` (unprocessed genesis, floor 1): a live floor
// redelivers the applied suffix; the fresh receipts are acknowledged without reapplying,
// and a verification of the tip's child continues undisturbed. Adapted: commonware drives a
// real marshal whose fanout observer holds every receipt; here the floor's redelivery is
// the same blocks reported again, and barriers are durable when they start, so the fenced
// acknowledgements of F+1 and F+2 are not modeled.
test "stateful processing: a live floor redelivery from an unprocessed genesis" {
    try live_floor_redelivery(1, false);
}

// commonware `live_floor_fences_suffix_ack` (same start: genesis processed, floor 1).
test "stateful processing: a live floor redelivery from a processed genesis" {
    try live_floor_redelivery(1, true);
}

// commonware `live_floor_fences_suffix_ack` (forward start: genesis processed, floor 2).
test "stateful processing: a live floor redelivery from a forward floor" {
    try live_floor_redelivery(2, true);
}

// commonware `successor_barrier_drives_verification_holding_database_read`: a verification
// held mid-processing does not stall the successor barrier for block 2: block 2 is
// acknowledged while the verification is held, which then passes. Adapted: zigware's
// database read lock is released before the batch is returned (`Shared.new_batches`), so a
// held verification holds no read and the barrier never waits for one.
test "stateful processing: a successor barrier proceeds past a held verification" {
    try test_io.run_on_deterministic(late_successor_barrier_proceeds);
}

fn late_successor_barrier_proceeds() anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    const block3, var batch = try fixture.harness.build_child(&block2, 3);
    batch.deinit();
    var probe: harness.Probe = .{ .target = block3.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;

    try finalize_and_wait(&fixture, block1);
    var verdict = try fixture.verify(&.{ block3, block2 });
    defer verdict.deinit();
    try started.recv();
    try finalize_and_wait(&fixture, block2);
    try testing.expect(!verdict.is_ready());
    try release.send({});
    try testing.expect(try verdict.recv());
}

/// Stops the processing loop by cancelling its task (commonware's runtime `stop`), and
/// returns how it ended.
fn shutdown(fixture: *Fixture) anyerror!void {
    var future = fixture.future.?;
    fixture.future = null;
    return future.cancel(test_io.io);
}

fn prune_join(stop: bool) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    var live = true;
    defer if (live) deinit_fixture(&fixture);
    fixture.harness.processor.pruning = try eager_pruning();
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    const candidate, var batch = try fixture.harness.build_child(&block2, 3);
    batch.deinit();
    var probe: harness.Probe = .{ .target = candidate.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    var released = false;
    defer if (!released) release.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    try finalize_and_wait(&fixture, block1);
    // The candidate executes under the gate when block 2's finalization schedules the prune
    // (sent first: with no held flush, the prune would otherwise run before it arrives).
    var verdict = try fixture.verify(&.{ candidate, block2 });
    defer verdict.deinit();
    try started.recv();
    try finalize_and_wait(&fixture, block2);
    // The prune waits for the running execution.
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(0, fixture.prunes.items.len);
    try testing.expect(!verdict.is_ready());
    if (stop) {
        // Shutdown stops processing without waiting for the execution; releasing the loop
        // (zigware drops its executions there) drops it.
        try testing.expectError(error.Canceled, shutdown(&fixture));
        try testing.expectEqual(0, fixture.prunes.items.len);
        live = false;
        deinit_fixture(&fixture);
        try release.closed();
    } else {
        released = true;
        try release.send({});
        try testing.expect(try verdict.recv());
        try testing.expectEqualSlices(u64, &.{1}, fixture.prunes.items);
    }
}

// commonware `prune_join_preserves_execution_until_shutdown` (shutdown case): a prune waits
// for a running candidate execution; shutdown stops processing without waiting and drops
// the execution. Adapted: shutdown is cancelling the loop's task, the verification is sent
// before block 2's finalization (barriers complete at once), and the loop's own task count
// is not inspected.
test "stateful processing: shutdown preempts a prune joining an execution" {
    try prune_join(true);
}

// commonware `prune_join_preserves_execution_until_shutdown` (ordinary maintenance case):
// the prune keeps waiting until the execution is released, lets it finish, then prunes.
test "stateful processing: a prune join lets the execution finish" {
    try test_io.run_on_deterministic(late_prune_join_finishes);
}

fn late_prune_join_finishes() anyerror!void {
    try prune_join(false);
}

fn finalization_join(stop: bool) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    var live = true;
    defer if (live) deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const winner, var winner_batch = try fixture.harness.build_child(&genesis, 1);
    winner_batch.deinit();
    const candidate, var candidate_batch = try fixture.harness.build_child(&genesis, 2);
    candidate_batch.deinit();
    // Cache the winner through its own verification.
    var winner_verdict = try fixture.verify(&.{ winner, genesis });
    defer winner_verdict.deinit();
    try testing.expect(try winner_verdict.recv());

    var probe: harness.Probe = .{ .target = candidate.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    var released = false;
    defer if (!released) release.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;
    var captures: harness.Probe = .{ .target = null };
    defer captures.deinit();
    fixture.processing.processor.app.capture_probe = &captures;
    var verdict = try fixture.verify(&.{ candidate, genesis });
    defer verdict.deinit();
    try started.recv();

    // The winner finalizes while its sibling executes: finalization waits before applying.
    var receipt = try fixture.finalize(winner);
    defer receipt.deinit();
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, receipt.poll());
    try testing.expectEqual(0, captures.calls);
    if (stop) {
        try testing.expectError(error.Canceled, shutdown(&fixture));
        live = false;
        deinit_fixture(&fixture);
        // Shutdown cancels the winner's receipt and drops the candidate's execution.
        try testing.expectError(error.AcknowledgementCanceled, receipt.wait());
        try release.closed();
        try testing.expectEqual(0, captures.calls);
    } else {
        released = true;
        try release.send({});
        try testing.expect(!try verdict.recv()); // The losing sibling is rejected.
        try receipt.wait();
        try testing.expectEqual(1, captures.calls);
        try testing.expectEqual(1, try fixture.counter());
    }
}

// commonware `finalization_join_preserves_execution_until_shutdown` (shutdown case): a
// finalization waits for a running sibling execution; shutdown stops processing without
// waiting, drops the execution, and cancels the finalized block's acknowledgement. Adapted:
// shutdown is cancelling the loop's task, and the loop's executions are dropped when it is
// released, so the checks follow its release.
test "stateful processing: shutdown preempts a finalization joining an execution" {
    try finalization_join(true);
}

// commonware `finalization_join_preserves_execution_until_shutdown` (ordinary case): the
// finalization waits until the execution is released, rejects the sibling, and applies the
// winner.
test "stateful processing: a finalization join rejects the sibling and applies" {
    try finalization_join(false);
}

/// Stops the loop by closing its mailbox, and returns how it ended; the fixture stays
/// alive for checks.
fn stop_loop(fixture: *Fixture) anyerror!void {
    fixture.mailbox.?.deinit();
    fixture.mailbox = null;
    var future = fixture.future.?;
    fixture.future = null;
    return future.await(test_io.io);
}

fn expect_canceled(waiter: anytype) !void {
    try testing.expectError(error.AcknowledgementCanceled, waiter.wait());
}

// commonware `aborted_target_flush_prevents_prune`: when the barrier covering the prune
// target fails, processing stops before pruning, and the unflushed acknowledgements are
// cancelled. Adapted: the barrier fails through the storage's mutation faults (commonware
// drops the held flush), so processing ends with that error, and block 2's report is
// discarded unhandled rather than applied behind the pending barrier.
test "stateful processing: an aborted target barrier prevents the prune" {
    var fixture: Fixture = undefined;
    try fixture.init();
    var live = true;
    defer if (live) deinit_fixture(&fixture);
    fixture.harness.processor.pruning = try eager_pruning();
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    // Set before the reports: every later mutation, and so the barrier, fails.
    fixture.harness.storage.allow_mutations(0);
    var first_waiter = try fixture.finalize(block1);
    defer first_waiter.deinit();
    var second_waiter = try fixture.finalize(block2);
    defer second_waiter.deinit();
    if (stop_loop(&fixture)) |_| return error.TestUnexpectedResult else |_| {}
    try testing.expectEqual(0, fixture.prunes.items.len);
    // Releasing the stopped loop drops the acknowledgements it still holds.
    live = false;
    deinit_fixture(&fixture);
    try expect_canceled(&first_waiter);
    try expect_canceled(&second_waiter);
}

// commonware `idle_acks_follow_flush_outcome`: a completed barrier releases block 1's
// acknowledgement, and when block 2's barrier does not complete, processing stops and
// cancels block 2's acknowledgement. Adapted: block 2's barrier fails through the
// storage's mutation faults (commonware drops the held flush, resolving it as shutdown).
// This also covers `ready_aborted_flush_stops_processing`, which differs only in block 2
// coalescing behind block 1's pending barrier, and barriers here are never pending.
test "stateful processing: acknowledgements follow the barrier's outcome" {
    var fixture: Fixture = undefined;
    try fixture.init();
    var live = true;
    defer if (live) deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    try finalize_and_wait(&fixture, block1);
    fixture.harness.storage.allow_mutations(0); // The loop is idle: block 1 is acknowledged.
    var second_waiter = try fixture.finalize(block2);
    defer second_waiter.deinit();
    if (stop_loop(&fixture)) |_| return error.TestUnexpectedResult else |_| {}
    live = false;
    deinit_fixture(&fixture);
    try expect_canceled(&second_waiter);
}

// commonware `mailbox_eof_finishes_scheduled_prune`: a prune scheduled before ingress
// closes still runs, and processing then stops. Adapted: barriers are durable when they
// start, so both blocks are acknowledged (commonware cancels block 2's, whose barrier never
// starts once the prune ends processing).
test "stateful processing: mailbox close finishes a scheduled prune" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    fixture.harness.processor.pruning = try eager_pruning();
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    var first_waiter = try fixture.finalize(block1);
    defer first_waiter.deinit();
    var second_waiter = try fixture.finalize(block2);
    defer second_waiter.deinit();
    // Queue both reports and close ingress before the loop handles them.
    try stop_loop(&fixture);
    try testing.expectEqualSlices(u64, &.{1}, fixture.prunes.items);
    try first_waiter.wait();
    try second_waiter.wait();
}

/// The shared side of a `GatedAncestry`: whether its blocks are available, how many
/// acquisitions cloned it, and whether a cloned acquisition was dropped (maintenance drops
/// an acquisition when it pauses it).
const AncestryGate = struct {
    mutex: std.Io.Mutex = .init,
    open: bool = false,
    clones: u32 = 0,
    parked: bool = false,

    fn read(gate: *AncestryGate, comptime field: []const u8) @FieldType(AncestryGate, field) {
        gate.mutex.lockUncancelable(test_io.io);
        defer gate.mutex.unlock(test_io.io);
        return @field(gate, field);
    }

    fn release(gate: *AncestryGate) void {
        gate.mutex.lockUncancelable(test_io.io);
        defer gate.mutex.unlock(test_io.io);
        gate.open = true;
    }

    /// Waits until an acquisition was dropped (bounded: a hang guard).
    fn await_parked(gate: *AncestryGate) !void {
        for (0..10_000) |_| {
            if (gate.read("parked")) return;
            try test_io.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestTimedOut;
    }
};

/// commonware's `GatedAncestry` and `PendingAncestry`: an ancestry whose first `always`
/// blocks are available at once and whose rest wait for its gate to open; with no gated
/// blocks it never ends. Each clone is one acquisition.
const GatedAncestry = struct {
    pub const Block = TestBlock;

    gate: *AncestryGate,
    blocks: [3]?harness.Digested = .{ null, null, null },
    index: usize = 0,
    always: usize = 0,
    acquisition: bool = false,

    fn init(
        gate: *AncestryGate,
        blocks: []const TestBlock,
        always: usize,
    ) !harness.Execution.Ancestry {
        std.debug.assert(blocks.len <= 3 and always <= blocks.len);
        var ancestry: GatedAncestry = .{ .gate = gate, .always = always };
        for (blocks, 0..) |block, index| ancestry.blocks[index] = try harness.digested(block);
        return harness.Execution.Ancestry.init(gpa, ancestry);
    }

    fn available(self: *const GatedAncestry) bool {
        return self.index < self.always or self.gate.read("open");
    }

    pub fn peek(self: *const GatedAncestry) ?*const harness.Digested {
        if (self.index >= self.blocks.len or !self.available()) return null;
        return if (self.blocks[self.index]) |*block| block else null;
    }

    pub fn next(self: *GatedAncestry) !?harness.Digested {
        // Waits for the gate (cancelable): a gate that never opens never ends the stream.
        while (!self.available()) try test_io.io.sleep(.fromMilliseconds(1), .awake);
        if (self.index >= self.blocks.len) return null;
        const block = self.blocks[self.index] orelse return null;
        self.blocks[self.index] = null;
        self.index += 1;
        return block;
    }

    pub fn clone(self: *const GatedAncestry) !GatedAncestry {
        self.gate.mutex.lockUncancelable(test_io.io);
        self.gate.clones += 1;
        self.gate.mutex.unlock(test_io.io);
        var copy = self.*;
        copy.acquisition = true;
        for (&copy.blocks) |*slot| {
            if (slot.*) |block| slot.* = block.clone();
        }
        return copy;
    }

    pub fn deinit(self: *GatedAncestry) void {
        for (&self.blocks) |*slot| if (slot.*) |*block| block.deinit();
        if (self.acquisition) {
            self.gate.mutex.lockUncancelable(test_io.io);
            self.gate.parked = true;
            self.gate.mutex.unlock(test_io.io);
        }
    }
};

/// Sends a verification over `ancestry` (taken) and returns its verdict's receiver.
fn verify_with(
    fixture: *Fixture,
    ancestry: harness.Execution.Ancestry,
) !utils.channel.oneshot.Receiver(bool) {
    const pair = try utils.channel.oneshot.channel(bool, gpa, test_io.io);
    try fixture.send(.{ .verify = .{ .ancestry = ancestry, .verification = pair.sender } });
    return pair.receiver;
}

fn unavailable_ancestry(block_available: bool) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const parent = try fixture.harness.stage_pending_child(&genesis, 1);
    const child, var batch = try fixture.harness.build_child(&parent, 2);
    batch.deinit();
    // The ancestry never yields the block, or yields it but never its parent.
    var gate: AncestryGate = .{};
    const blocks: []const TestBlock = if (block_available) &.{child} else &.{};
    var verdict = try verify_with(&fixture, try GatedAncestry.init(&gate, blocks, blocks.len));
    defer verdict.deinit();
    try fixture.barrier();
    const acquisitions = gate.read("clones");
    try testing.expect(acquisitions > 0);
    // Finalization pauses the acquisition, completes, and then restarts it.
    try finalize_and_wait(&fixture, parent);
    try fixture.barrier();
    try testing.expect(gate.read("clones") > acquisitions);
    try testing.expect(!verdict.is_ready());
}

// commonware `unavailable_ancestry_does_not_block_finalization` (block case): a verification
// whose block never arrives keeps acquiring across a finalization without delaying it.
test "stateful processing: an unavailable block does not block finalization" {
    try unavailable_ancestry(false);
}

// commonware `unavailable_ancestry_does_not_block_finalization` (parent case): the same when
// the block arrives but its parent never does.
test "stateful processing: an unavailable parent does not block finalization" {
    try unavailable_ancestry(true);
}

// commonware `tip_redelivery_keeps_acquiring_verification`: a redelivered applied tip
// (genesis) leaves a verification still acquiring its block running, without restarting it.
test "stateful processing: a tip redelivery keeps an acquiring verification" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    var gate: AncestryGate = .{};
    var verdict = try verify_with(&fixture, try GatedAncestry.init(&gate, &.{}, 0));
    defer verdict.deinit();
    try fixture.barrier();
    const attempts = gate.read("clones");
    try finalize_and_wait(&fixture, TestBlock.genesis());
    try fixture.barrier();
    try testing.expectEqual(attempts, gate.read("clones"));
    try testing.expect(!verdict.is_ready());
}

/// A probe's gate with its two ends, the release still owned until sent.
/// Receives from `receiver` once it is ready (bounded, so a missing answer fails).
fn await_ready(comptime T: type, receiver: *utils.channel.oneshot.Receiver(T)) !T {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        if (receiver.is_ready()) return receiver.recv();
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

const HeldGate = struct {
    started: utils.channel.oneshot.Receiver(void),
    release: utils.channel.oneshot.Sender(void),
    released: bool = false,

    fn add(probe: *harness.Probe) !HeldGate {
        const handles = try probe.add_gate();
        return .{ .started = handles.started, .release = handles.release };
    }

    fn open(gate: *HeldGate) !void {
        std.debug.assert(!gate.released);
        gate.released = true;
        try gate.release.send({});
    }

    fn deinit(gate: *HeldGate) void {
        gate.started.deinit();
        if (!gate.released) gate.release.deinit();
    }
};

// commonware `admitted_verification_keeps_processing_alive`: a verification admitted to a
// block's processing before an earlier caller cancels keeps that shared processing alive,
// and the block is processed once. Adapted: commonware orders the admission before the
// cancellation through the scheduler; here the test waits until the second request joined
// the processing before cancelling the first.
test "stateful processing: an admitted verification keeps processing alive" {
    try test_io.run_on_deterministic(late_admitted_verification_alive);
}

fn late_admitted_verification_alive() anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const block, var batch = try fixture.harness.build_child(&genesis, 1);
    batch.deinit();
    var probe: harness.Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var process = try HeldGate.add(&probe);
    defer process.deinit();
    var repeat = try HeldGate.add(&probe);
    defer repeat.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    var first = try fixture.verify(&.{ block, genesis });
    try process.started.recv();
    var gate: AncestryGate = .{};
    const ancestry = try GatedAncestry.init(&gate, &.{ block, genesis }, 0);
    var second = try verify_with(&fixture, ancestry);
    defer second.deinit();
    try fixture.barrier();
    try testing.expect(gate.read("clones") > 0); // The second acquisition is waiting.
    gate.release();
    try fixture.await_joiners(block.digest(), 2);
    first.deinit(); // The first caller leaves.
    try fixture.barrier();
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expect(!process.release.is_closed()); // The processing is still alive.
    try testing.expect(!repeat.started.is_ready());
    try testing.expectEqual(1, probe.calls);
    try process.open();
    try testing.expect(try second.recv());
    try testing.expectEqual(1, probe.calls);
}

fn losing_and_winner(fixture: *Fixture) !struct { TestBlock, TestBlock } {
    const genesis = TestBlock.genesis();
    const losing, var losing_batch = try fixture.harness.build_child(&genesis, 1);
    losing_batch.deinit();
    const winner, var winner_batch = try fixture.harness.build_child(&genesis, 2);
    winner_batch.deinit();
    return .{ losing, winner };
}

// commonware `cancellation_during_finalization_join_releases_maintenance`: a finalization
// waiting for a competing execution proceeds when that request's caller cancels: the
// winner is reconstructed and acknowledged, and the cancelled request gets no reply.
test "stateful processing: a cancellation during a finalization join releases it" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const losing, const winner = try losing_and_winner(&fixture);
    // Null target: the gate holds the losing execution; the winner's reconstruction passes.
    var probe: harness.Probe = .{ .target = null };
    defer probe.deinit();
    var held = try HeldGate.add(&probe);
    defer held.deinit();
    var hooks: harness.Probe = .{ .target = null };
    defer hooks.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;
    fixture.processing.processor.app.probe = &probe;
    fixture.processing.processor.app.finalized_probe = &hooks;

    var request = try fixture.verify(&.{ losing, genesis });
    try held.started.recv();
    // A second verification never acquires its block, and is parked by the finalization.
    var gate: AncestryGate = .{};
    var acquiring = try verify_with(&fixture, try GatedAncestry.init(&gate, &.{}, 0));
    defer acquiring.deinit();
    var receipt = try fixture.finalize(winner);
    defer receipt.deinit();
    try gate.await_parked();
    try testing.expectEqual(null, receipt.poll());
    try testing.expectEqual(0, hooks.calls);
    // Cancelling the losing request ends the wait with its gate still held.
    request.deinit();
    try held.release.closed();
    try receipt.wait();
    try testing.expectEqual(2, probe.calls);
    try testing.expectEqual(1, hooks.calls);
}

// commonware `paused_acquisition_restarts_after_finalization`: a verification whose block
// arrives while its finalization is paused answers from the restarted acquisition once the
// finalization completes, without processing the block as a candidate.
test "stateful processing: a paused acquisition restarts after finalization" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const losing, const winner = try losing_and_winner(&fixture);
    var probe: harness.Probe = .{ .target = null };
    defer probe.deinit();
    var held = try HeldGate.add(&probe);
    defer held.deinit();
    var hooks: harness.Probe = .{ .target = null };
    defer hooks.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;
    fixture.processing.processor.app.probe = &probe;
    fixture.processing.processor.app.finalized_probe = &hooks;

    var losing_request = try fixture.verify(&.{ losing, genesis });
    defer losing_request.deinit();
    try held.started.recv();
    var gate: AncestryGate = .{};
    const ancestry = try GatedAncestry.init(&gate, &.{ winner, genesis }, 0);
    var verification = try verify_with(&fixture, ancestry);
    defer verification.deinit();
    // Finalizing the winner pauses the acquisition; the block arrives during the pause.
    var receipt = try fixture.finalize(winner);
    defer receipt.deinit();
    try gate.await_parked();
    gate.release();
    try testing.expectEqual(null, receipt.poll());
    try held.open();
    try testing.expect(!try losing_request.recv());
    try receipt.wait();
    try testing.expect(try verification.recv());
    try testing.expectEqual(2, probe.calls);
    try testing.expectEqual(1, hooks.calls);
}

// commonware `finalization_rejects_next_step_with_stale_round`: a handoff's recovery step
// retained across a finalization selects a successor whose round is at or before the
// finalized round; the finalization's boundary rejects it unprocessed, the handoff declines,
// and the retained block is processed once. Adapted: the finalized and retained blocks are
// served by the provider.
test "stateful processing: a finalization rejects a next step with a stale round" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const finalized, var batch = try fixture.harness.build_child(&genesis, 1);
    batch.deinit();
    var cached = try fixture.verify(&.{ finalized, genesis });
    defer cached.deinit();
    try testing.expect(try cached.recv()); // Cached through its verification.
    // The retained block comes from a scratch harness; marshal (the provider) serves both
    // blocks to the recovery walk.
    var scratch: harness.Harness = undefined;
    try scratch.init();
    defer scratch.deinit();
    const scratch_finalized = try scratch.stage_pending_child(&genesis, 1);
    try testing.expect(finalized.digest().eql(scratch_finalized.digest()));
    const retained = try scratch.stage_pending_child(&finalized, 2);
    try fixture.harness.provider_state.insert(finalized);
    try fixture.harness.provider_state.insert(retained);
    const stale_round = harness.round(1); // At the finalized round.
    const stale_height = retained.height().next();
    const stale = TestBlock.init(retained.digest(), stale_height, stale_round, retained.target);

    // Null target on the speculative path only: the probe counts every block the recovery
    // processes, and its gate holds the first, the retained block.
    var probe: harness.Probe = .{ .target = null };
    defer probe.deinit();
    var held = try HeldGate.add(&probe);
    defer held.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;
    var hook_probe: harness.Probe = .{ .target = finalized.digest() };
    defer hook_probe.deinit();
    var hook = try HeldGate.add(&hook_probe);
    defer hook.deinit();
    fixture.processing.processor.app.finalized_probe = &hook_probe;

    const pair = try utils.channel.oneshot.channel(core.Mailbox.Built, gpa, test_io.io);
    var prepared = pair.receiver;
    defer prepared.deinit();
    try fixture.send(.{ .propose = .{
        .context = .{ .round = harness.round(0xff) },
        .ancestry = try fixture.harness.ancestry(&.{ stale, retained }),
        .upstream = {},
        .proposal = .{ .prepare = pair.sender },
    } });
    try held.started.recv();
    // Finalization retains that processing; its hook stays open while the step finishes.
    var receipt = try fixture.finalize(finalized);
    defer receipt.deinit();
    try hook.started.recv();
    try held.open();
    // The retained step selects the stale block while the hook is held, and declines.
    const built = try await_ready(core.Mailbox.Built, &prepared);
    defer built.discard();
    try testing.expect(built.handoff.is_wait());
    try testing.expectEqual(null, receipt.poll());
    try hook.open();
    try receipt.wait();
    // The retained block once; the stale block never (commonware's
    // `process_calls.at(stale) == 0`).
    try testing.expectEqual(1, probe.calls);
}
