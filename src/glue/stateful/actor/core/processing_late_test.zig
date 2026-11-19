//! commonware `glue/src/stateful/actor/core/processing.rs` tests, second half (from
//! `finalization_joins_incompatible_verification`); the first half is processing_test.zig.
//! Barriers complete synchronously here, so tests built on a pending barrier or gated
//! ancestry acquisition say in their comment how they were adapted.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const utils = @import("utils");
const core = @import("testing.zig");

const harness = core.harness;
const TestBlock = harness.TestBlock;
const Fixture = core.Fixture;
const gpa = testing.allocator;
const io = testing.io;

fn deinit_fixture(fixture: *Fixture) void {
    fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
}

// commonware `finalization_joins_incompatible_verification`: a verification on a fork the
// finalization abandons keeps running while finalization waits for it, then resolves
// false. Adapted: commonware also parks an ancestry acquisition to learn when
// finalization paused; here the pending acknowledgement shows the wait.
test "stateful processing: finalization joins an incompatible verification" {
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
    try testing.io.sleep(.fromMilliseconds(20), .awake);
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
    try testing.io.sleep(.fromMilliseconds(20), .awake);
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
    const pair = try actor.mailbox.new(core.Message, gpa, io, 8);
    fixture.receiver = pair.receiver;
    fixture.mailbox = core.Mailbox.init(gpa, io, pair.sender);
    const marshal: core.TestMarshal = .{ .prunes = &fixture.prunes };
    const provider = fixture.harness.provider();
    const processor = &fixture.harness.processor;
    fixture.processing = .init(gpa, io, &fixture.receiver, provider, marshal, processor);
    defer deinit_fixture(&fixture);

    const genesis = TestBlock.genesis();
    const block, var batch = try fixture.harness.build_child(&genesis, 1);
    batch.deinit();
    const verdict_pair = try utils.channel.oneshot.channel(bool, gpa, io);
    var verdict = verdict_pair.receiver;
    defer verdict.deinit();
    fixture.processing.defer_verification(.{
        .ancestry = try fixture.harness.ancestry(&.{ block, genesis }),
        .verification = verdict_pair.sender,
    });
    try testing.expect(!verdict.is_ready());

    fixture.future = try io.concurrent(run_processing, .{&fixture.processing});
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
    try testing.io.sleep(.fromMilliseconds(20), .awake);
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
            .propose => .{ .propose = try io.concurrent(propose_on, .{ fixture, blocks }) },
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
            .propose => |*future| future.await(io),
        };
    }

    fn deinit(descendant: *Descendant) void {
        switch (descendant.*) {
            .verify => |*verdict| verdict.deinit(),
            .propose => |*future| _ = future.cancel(io) catch {},
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
    // An independent verification of the first block joins its replay.
    var verify_first = try fixture.verify(&.{ first, genesis });
    defer verify_first.deinit();
    try testing.expect(!verify_first.is_ready());
    try finalize_across(&fixture, &probe, &descendant, &replay_release, .{ first, second });
    try testing.expect(try verify_first.recv());
    // Each block ran once: the finalizations reused the request's executions.
    try testing.expectEqual(3, probe.calls);
}

/// Finalizes `blocks[0]` while its replay is held, then `blocks[1]` while the descendant's
/// own processing is held, and checks the descendant completes valid.
fn finalize_across(
    fixture: *Fixture,
    probe: *harness.Probe,
    descendant: *Descendant,
    replay_release: *utils.channel.oneshot.Sender(void),
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
    try testing.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, first_waiter.poll());
    try replay_release.send({});
    try first_waiter.wait();
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
    try testing.io.sleep(.fromMilliseconds(20), .awake);
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
    try testing.io.sleep(.fromMilliseconds(20), .awake);
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
    try testing.io.sleep(.fromMilliseconds(20), .awake);
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
