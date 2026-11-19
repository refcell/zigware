//! commonware `glue/src/stateful/actor/core/processing.rs` tests: proposals build on recovered
//! state, verdicts, a waiting verification that never votes, finalization acknowledged once
//! durable, redelivery, independence of verifications and builds, and mailbox shutdown.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const actor = @import("actor");
const consensus = @import("consensus");
const utils = @import("utils");
const harness_mod = @import("../processor/testing.zig");
const processing_mod = @import("processing.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const Exact = utils.acknowledgement.Exact;
const Harness = harness_mod.Harness;
const TestBlock = harness_mod.TestBlock;

/// Records marshal prunes.
const TestMarshal = struct {
    prunes: *std.ArrayList(u64),

    pub fn prune(self: TestMarshal, height: consensus.Height) !void {
        try self.prunes.append(gpa, height.get());
    }
};

const TestP = struct {
    pub const App = harness_mod.TestApp;
    pub const Databases = harness_mod.TestP.Databases;
    pub const Provider = harness_mod.TestProvider;
    pub const Marshal = TestMarshal;
};

const Processing = processing_mod.Processing(TestP);
const Mailbox = Processing.Mailbox;
const Message = Processing.Message;

/// A processing loop running over a processor harness, fed through a mailbox.
const Fixture = struct {
    harness: Harness,
    prunes: std.ArrayList(u64) = .empty,
    receiver: Processing.Receiver,
    mailbox: ?Mailbox,
    processing: Processing,
    future: ?Io.Future(anyerror!void) = null,

    /// `fixture` must not move afterwards.
    fn init(fixture: *Fixture) !void {
        try fixture.harness.init();
        errdefer fixture.harness.deinit();
        fixture.prunes = .empty;
        const pair = try actor.mailbox.new(Message, gpa, io, 8);
        fixture.receiver = pair.receiver;
        fixture.mailbox = Mailbox.init(gpa, io, pair.sender);
        const marshal: TestMarshal = .{ .prunes = &fixture.prunes };
        const processor = &fixture.harness.processor;
        const provider = fixture.harness.provider();
        fixture.processing = .init(gpa, io, &fixture.receiver, provider, marshal, processor);
        fixture.future = try io.concurrent(run, .{&fixture.processing});
    }

    fn run(processing: *Processing) anyerror!void {
        return processing.run();
    }

    /// Closes the mailbox, which stops the loop, and releases everything.
    fn deinit(fixture: *Fixture) !void {
        if (fixture.mailbox) |*mailbox| mailbox.deinit();
        fixture.mailbox = null;
        const outcome = if (fixture.future) |*future| future.await(io) else {};
        fixture.processing.deinit();
        fixture.receiver.deinit();
        fixture.prunes.deinit(gpa);
        fixture.harness.deinit();
        try outcome;
    }

    fn send(fixture: *Fixture, message: Message) !void {
        const mailbox = &fixture.mailbox.?;
        const feedback = try mailbox.sender.enqueue(message);
        try testing.expect(feedback != .closed);
    }

    /// Sends a verification of `blocks` (newest first) and returns its verdict's receiver.
    fn verify(fixture: *Fixture, blocks: []const TestBlock) !oneshot.Receiver(bool) {
        const pair = try oneshot.channel(bool, gpa, io);
        try fixture.send(.{ .verify = .{
            .ancestry = try fixture.harness.ancestry(blocks),
            .verification = pair.sender,
        } });
        return pair.receiver;
    }

    /// Proposes on `parent` at `view` and returns the built block.
    fn propose(fixture: *Fixture, parent: TestBlock, view: u64) !?Mailbox.Digested {
        const mailbox = &fixture.mailbox.?;
        const context: TestBlock.Context = .{ .round = harness_mod.round(view) };
        const ancestry = try fixture.harness.ancestry(&.{parent});
        return mailbox.propose({}, context, ancestry, {});
    }

    /// Reports `block` finalized and returns its acknowledgement's waiter.
    fn finalize(fixture: *Fixture, block: TestBlock) !Exact.Waiter {
        const handle = try Exact.handle(gpa, io);
        const update: Mailbox.Update = .{ .block = .{
            .block = try harness_mod.digested(block),
            .ack = handle.acknowledgement,
        } };
        try testing.expect(fixture.mailbox.?.report(update) != .closed);
        return handle.waiter;
    }

    fn counter(fixture: *Fixture) !?u64 {
        const readers = fixture.harness.databases.readers();
        const value = try harness_mod.read_applied(readers, harness_mod.counter_key());
        return if (value) |digest| harness_mod.digest_u64(digest) else null;
    }
};

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
