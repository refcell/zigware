//! The core processing loop's test fixture, shared by the processing tests (commonware
//! `processing.rs`'s test module): a `Processing` over the processor harness, fed through the
//! actor's mailbox, with a marshal that records prunes. Only tests import it.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const actor = @import("actor");
const consensus = @import("consensus");
const utils = @import("utils");
pub const harness = @import("../processor/testing.zig");
const processing_mod = @import("processing.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const Exact = utils.acknowledgement.Exact;
const Harness = harness.Harness;
const TestBlock = harness.TestBlock;

/// Records marshal prunes.
pub const TestMarshal = struct {
    prunes: *std.ArrayList(u64),

    pub fn prune(self: TestMarshal, height: consensus.Height) !void {
        try self.prunes.append(gpa, height.get());
    }
};

pub const TestP = struct {
    pub const App = harness.TestApp;
    pub const Databases = harness.TestP.Databases;
    pub const Provider = harness.TestProvider;
    pub const Marshal = TestMarshal;
};

pub const Processing = processing_mod.Processing(TestP);
pub const Mailbox = Processing.Mailbox;
pub const Message = Processing.Message;

/// A processing loop running over a processor harness, fed through a mailbox.
pub const Fixture = struct {
    harness: Harness,
    prunes: std.ArrayList(u64) = .empty,
    receiver: Processing.Receiver,
    mailbox: ?Mailbox,
    processing: Processing,
    future: ?Io.Future(anyerror!void) = null,

    /// `fixture` must not move afterwards.
    pub fn init(fixture: *Fixture) !void {
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
    pub fn deinit(fixture: *Fixture) !void {
        if (fixture.mailbox) |*mailbox| mailbox.deinit();
        fixture.mailbox = null;
        const outcome = if (fixture.future) |*future| future.await(io) else {};
        fixture.processing.deinit();
        fixture.receiver.deinit();
        fixture.prunes.deinit(gpa);
        fixture.harness.deinit();
        try outcome;
    }

    pub fn send(fixture: *Fixture, message: Message) !void {
        const mailbox = &fixture.mailbox.?;
        const feedback = try mailbox.sender.enqueue(message);
        try testing.expect(feedback != .closed);
    }

    /// Sends a verification of `blocks` (newest first) and returns its verdict's receiver.
    pub fn verify(fixture: *Fixture, blocks: []const TestBlock) !oneshot.Receiver(bool) {
        const pair = try oneshot.channel(bool, gpa, io);
        try fixture.send(.{ .verify = .{
            .ancestry = try fixture.harness.ancestry(blocks),
            .verification = pair.sender,
        } });
        return pair.receiver;
    }

    /// Proposes on `parent` at `view` and returns the built block.
    pub fn propose(fixture: *Fixture, parent: TestBlock, view: u64) !?Mailbox.Digested {
        const mailbox = &fixture.mailbox.?;
        const context: TestBlock.Context = .{ .round = harness.round(view) };
        const ancestry = try fixture.harness.ancestry(&.{parent});
        return mailbox.propose({}, context, ancestry, {});
    }

    /// Sends a proposal on `blocks` (the parent first) at `view` without waiting, and returns
    /// the built block's receiver (closed without a value when the proposal declines).
    pub fn propose_async(
        fixture: *Fixture,
        blocks: []const TestBlock,
        view: u64,
    ) !oneshot.Receiver(Mailbox.Digested) {
        const pair = try oneshot.channel(Mailbox.Digested, gpa, io);
        try fixture.send(.{ .propose = .{
            .context = .{ .round = harness.round(view) },
            .ancestry = try fixture.harness.ancestry(blocks),
            .upstream = {},
            .proposal = .{ .propose = pair.sender },
        } });
        return pair.receiver;
    }

    /// Returns once the loop has handled every earlier message (a database subscription is
    /// answered in mailbox order).
    pub fn barrier(fixture: *Fixture) !void {
        _ = try fixture.mailbox.?.subscribe_databases();
    }

    /// Waits until `count` requests hold the flight processing `digest` (bounded).
    pub fn await_joiners(fixture: *Fixture, digest: TestBlock.Digest, count: u32) !void {
        const execution = fixture.harness.execution;
        // Each pass sleeps 1 ms; the bound is a hang guard.
        for (0..10_000) |_| {
            execution.mutex.lockUncancelable(io);
            const flight = execution.flights.get(digest);
            const joiners = if (flight) |value| value.joiners else 0;
            execution.mutex.unlock(io);
            if (joiners >= count) return;
            try io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestTimedOut;
    }

    /// Reports `block` finalized and returns its acknowledgement's waiter.
    pub fn finalize(fixture: *Fixture, block: TestBlock) !Exact.Waiter {
        const handle = try Exact.handle(gpa, io);
        const update: Mailbox.Update = .{ .block = .{
            .block = try harness.digested(block),
            .ack = handle.acknowledgement,
        } };
        try testing.expect(fixture.mailbox.?.report(update) != .closed);
        return handle.waiter;
    }

    pub fn counter(fixture: *Fixture) !?u64 {
        const readers = fixture.harness.databases.readers();
        const value = try harness.read_applied(readers, harness.counter_key());
        return if (value) |digest| harness.digest_u64(digest) else null;
    }
};
