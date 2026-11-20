//! commonware `glue/src/stateful/actor/syncer/mailbox.rs` tests.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const actor = @import("actor");
const runtime = @import("runtime");
const consensus = @import("consensus");
const mailbox_mod = @import("mailbox.zig");
const db_sync = @import("../../db/sync.zig");

const gpa = testing.allocator;
const Digest = [32]u8;
const Anchor = db_sync.Anchor(Digest);
const Artifact = mailbox_mod.Artifact(u64, Digest);
const Mailbox = mailbox_mod.Mailbox(Artifact, Digest, u64);
const Message = Mailbox.Msg;

/// commonware's mock `anchor(height, view)`.
fn anchor(height: u64, view: u64) Anchor {
    return .{
        .height = .new(height),
        .round = .new(.zero(), .new(view)),
        .digest = @splat(@truncate(height)),
    };
}

/// Runs `body` on a deterministic runtime that fails after 5 simulated seconds, so a
/// retarget that never returns fails instead of hanging.
fn run(comptime body: fn (Io) anyerror!void) !void {
    const timeout_ns = 5 * std.time.ns_per_s;
    try runtime.deterministic.soak(gpa, .{ .timeout_ns = timeout_ns }, {}, struct {
        fn run_round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try try runner.start(body, .{runner.io()});
        }
    }.run_round);
}

const Harness = struct {
    io: Io,
    receiver: actor.mailbox.Receiver(Message),
    mailbox: Mailbox,
    retarget: Io.Future(Mailbox.Error!?Artifact),

    fn init(harness: *Harness, io: Io) !void {
        const pair = try actor.mailbox.new(Message, gpa, io, 1);
        harness.io = io;
        harness.receiver = pair.receiver;
        harness.mailbox = .init(gpa, io, pair.sender);
        const args = .{ harness.mailbox, anchor(7, 9), @as(u64, 7) };
        harness.retarget = try io.concurrent(Mailbox.retarget, args);
    }

    fn deinit(harness: *Harness) void {
        harness.mailbox.deinit();
        harness.receiver.deinit();
    }

    fn next(harness: *Harness) !@FieldType(Message, "retarget") {
        const message = (try harness.receiver.recv()).?;
        try testing.expectEqual(@as(u64, 7), message.retarget.update.targets);
        return message.retarget;
    }
};

fn retarget_retries_when_the_observation_is_dropped(io: Io) !void {
    var harness: Harness = undefined;
    try harness.init(io);
    defer harness.deinit();
    var first = try harness.next();
    try first.response.send(null);
    first.update.discard();

    // A dropped observation sends the update again.
    var second = try harness.next();
    const expected: Artifact = .{ .databases = 3, .anchor = anchor(8, 10) };
    try second.response.send(expected);
    second.update.discard();
    const result = (try harness.retarget.await(io)).?;
    try testing.expect(result.anchor.eql(expected.anchor));
}

test "stateful syncer mailbox: retarget retries when the observation is dropped" {
    try run(retarget_retries_when_the_observation_is_dropped);
}

fn retarget_returns_null_only_after_the_observation_is_recorded(io: Io) !void {
    var harness: Harness = undefined;
    try harness.init(io);
    defer harness.deinit();
    var message = try harness.next();
    try message.response.send(null);
    // Answered but unrecorded: the caller still waits.
    try io.sleep(.fromMilliseconds(5), .awake);
    try testing.expectError(error.Empty, harness.receiver.try_recv());
    const Recorder = struct {
        pub fn record(_: @This(), _: Anchor, _: u64) void {}
    };
    message.update.record(Recorder{});
    try testing.expectEqual(@as(?Artifact, null), try harness.retarget.await(io));
}

test "stateful syncer mailbox: retarget returns null only after the observation is recorded" {
    try run(retarget_returns_null_only_after_the_observation_is_recorded);
}

fn a_stopped_syncer_fails_the_retarget(io: Io) !void {
    var harness: Harness = undefined;
    try harness.init(io);
    defer harness.deinit();
    const message = try harness.next();
    Message.discard(.{ .retarget = message });
    try testing.expectError(error.SyncerStopped, harness.retarget.await(io));
}

test "stateful syncer mailbox: a stopped syncer fails the retarget" {
    try run(a_stopped_syncer_fails_the_retarget);
}
