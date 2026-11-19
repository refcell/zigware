//! commonware `glue/src/stateful/actor/core/processing.rs` tests: proposals build on recovered
//! state, verdicts, a waiting verification that never votes, finalization acknowledged once
//! durable, redelivery, independence of verifications and builds, and mailbox shutdown. The
//! fixture is in `testing.zig`.

const std = @import("std");
const testing = std.testing;
const fixture_mod = @import("testing.zig");

const harness_mod = fixture_mod.harness;
const Fixture = fixture_mod.Fixture;
const TestBlock = harness_mod.TestBlock;

test "stateful processing: a proposal builds on its parent and verifies" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
    const genesis = TestBlock.genesis();
    const built = (try fixture.propose(genesis, 1)).?;
    defer built.discard();
    const block = built.inner().*;
    try testing.expectEqual(@as(u64, 1), block.height().get());
    try testing.expect(block.parent().eql(genesis.digest()));

    // The built state is cached, so the proposer's own verification accepts it at once.
    var verdict = try fixture.verify(&.{ block, genesis });
    defer verdict.deinit();
    try testing.expect(try verdict.recv());
    const invalid = block.with_root(harness_mod.u64_digest(999));
    var rejected = try fixture.verify(&.{ invalid, genesis });
    defer rejected.deinit();
    try testing.expect(!try rejected.recv());
}

test "stateful processing: a waiting verification gives no vote" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
    // The parent can be neither fetched nor found in finalized history: commonware stays
    // pending, so the verdict is dropped unsent rather than answered false.
    const genesis = TestBlock.genesis();
    const unknown = harness_mod.u64_digest(77);
    const orphan = TestBlock.init(unknown, .new(2), harness_mod.round(2), genesis.target);
    var verdict = try fixture.verify(&.{orphan});
    defer verdict.deinit();
    try testing.expectError(error.Closed, verdict.recv());

    // The loop keeps serving after abstaining.
    const child, var batch = try fixture.harness.build_child(&genesis, 3);
    batch.deinit();
    var later = try fixture.verify(&.{ child.with_root(unknown), genesis });
    defer later.deinit();
    try testing.expect(!try later.recv());
}

test "stateful processing: a finalization is acknowledged once durable" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
    const genesis = TestBlock.genesis();
    const built = (try fixture.propose(genesis, 1)).?;
    const block = built.inner().*;
    built.discard();

    var waiter = try fixture.finalize(block);
    defer waiter.deinit();
    try waiter.wait();
    try testing.expectEqual(@as(?u64, 1), try fixture.counter());
    try testing.expectEqual(@as(u64, 1), fixture.harness.processor.branch_anchor().height.get());

    // A redelivered finalization is already durable: acknowledged without reapplying.
    var again = try fixture.finalize(block);
    defer again.deinit();
    try again.wait();
    try testing.expectEqual(@as(?u64, 1), try fixture.counter());

    // The next block builds on the finalized state.
    const next = (try fixture.propose(block, 2)).?;
    defer next.discard();
    try testing.expect(next.inner().parent().eql(block.digest()));
}

test "stateful processing: a blocked verification does not block a build" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
    const genesis = TestBlock.genesis();
    // A child of genesis whose state is not cached: its verification replays it, gated.
    const child, var batch = try fixture.harness.build_child(&genesis, 5);
    batch.deinit();
    var probe: harness_mod.Probe = .{ .target = child.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    // The handler's verifier holds its own copy of the application.
    fixture.processing.verifications.verifier.app.probe = &probe;

    var verdict = try fixture.verify(&.{ child, genesis });
    defer verdict.deinit();
    try started.recv();
    // The verification is blocked inside the application; a proposal still builds.
    const built = (try fixture.propose(genesis, 6)).?;
    built.discard();
    try release.send({});
    try testing.expect(try verdict.recv());
}

test "stateful processing: subscribe_databases answers the live set" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
    const databases = try fixture.mailbox.?.subscribe_databases();
    try testing.expectEqual(fixture.harness.databases.cell, databases.cell);
}
