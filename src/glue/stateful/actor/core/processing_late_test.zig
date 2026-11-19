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
