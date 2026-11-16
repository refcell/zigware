//! commonware `glue/src/stateful/db/mod.rs` tests of tip updates, `dispatch_queued_tips`, and
//! the generation coordinator, plus a regroup and the channel edge cases.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus");
const utils = @import("utils");
const sync = @import("sync.zig");

const gpa = testing.allocator;
const io = testing.io;
const ring = utils.channel.ring;
const Digest = [32]u8;
const Anchor = sync.Anchor(Digest);
const Update = sync.TipUpdate(Digest, u64);

/// commonware's mock `anchor(height, height as u8)`.
fn anchor(height: u64) Anchor {
    return .{
        .height = .new(height),
        .round = .new(.zero(), .new(height)),
        .digest = @splat(@truncate(height)),
    };
}

test "stateful sync: a tip update's observation follows recording" {
    var observed = try Update.with_observation(gpa, io, anchor(1), 7);
    defer observed.observed.deinit();
    const Recorder = struct {
        observer: *utils.channel.oneshot.Receiver(void),
        recorded: ?struct { Anchor, u64 } = null,

        pub fn record(recorder: *@This(), new_anchor: Anchor, targets: u64) void {
            // The observer resolves only after recording.
            std.debug.assert(recorder.observer.try_recv() == error.Empty);
            recorder.recorded = .{ new_anchor, targets };
        }
    };
    var recorder: Recorder = .{ .observer = &observed.observed };
    observed.update.record(&recorder);
    try testing.expect(recorder.recorded.?[0].eql(anchor(1)));
    try testing.expectEqual(7, recorder.recorded.?[1]);
    try observed.observed.recv();
}

const Channels = struct {
    tips: ring.Pair(Update),
    targets: ring.Pair(u64),

    fn init(tip_capacity: usize) !Channels {
        const tips = try ring.channel(Update, gpa, io, tip_capacity);
        return .{ .tips = tips, .targets = try ring.channel(u64, gpa, io, 1) };
    }

    fn deinit(channels: *Channels) void {
        channels.tips.sender.deinit();
        channels.targets.sender.deinit();
        channels.targets.receiver.deinit();
    }
};

fn dispatch(
    tip_updates: *?ring.Receiver(Update),
    target_tx: ring.Sender(u64),
    current_anchor: *Anchor,
    current_target: *u64,
) bool {
    const dispatch_tips = sync.dispatch_queued_tips;
    return dispatch_tips(Digest, u64, tip_updates, target_tx, current_anchor, current_target);
}

test "stateful sync: dispatch_queued_tips keeps the highest recorded target" {
    var channels = try Channels.init(4);
    defer channels.deinit();
    var newer = try Update.with_observation(gpa, io, anchor(2), 2);
    defer newer.observed.deinit();
    var older = try Update.with_observation(gpa, io, anchor(1), 1);
    defer older.observed.deinit();
    try channels.tips.sender.send(newer.update);
    try channels.tips.sender.send(older.update);

    var tip_updates: ?ring.Receiver(Update) = channels.tips.receiver;
    defer if (tip_updates) |*receiver| receiver.deinit();
    var current_anchor = anchor(0);
    var current_target: u64 = 0;
    const sender = channels.targets.sender;
    try testing.expect(dispatch(&tip_updates, sender, &current_anchor, &current_target));

    // Both updates are observed, even the older one the sync did not adopt.
    try newer.observed.recv();
    try older.observed.recv();
    try testing.expect(current_anchor.eql(anchor(2)));
    try testing.expectEqual(2, current_target);
    try testing.expectEqual(2, (try channels.targets.receiver.recv()).?);
    try testing.expectError(error.Empty, channels.targets.receiver.try_recv());
}

test "stateful sync: dispatch_queued_tips advances the anchor without a duplicate target" {
    var channels = try Channels.init(1);
    defer channels.deinit();
    var update = try Update.with_observation(gpa, io, anchor(3), 7);
    defer update.observed.deinit();
    try channels.tips.sender.send(update.update);

    var tip_updates: ?ring.Receiver(Update) = channels.tips.receiver;
    defer if (tip_updates) |*receiver| receiver.deinit();
    var current_anchor = anchor(2);
    var current_target: u64 = 7;
    const sender = channels.targets.sender;
    try testing.expect(dispatch(&tip_updates, sender, &current_anchor, &current_target));

    try update.observed.recv();
    try testing.expect(current_anchor.eql(anchor(3)));
    try testing.expectEqual(7, current_target);
    try testing.expectError(error.Empty, channels.targets.receiver.try_recv());
}

test "stateful sync: dispatch_queued_tips ignores backward tips and closes a dropped channel" {
    var channels = try Channels.init(2);
    var backward = try Update.with_observation(gpa, io, anchor(2), 9);
    defer backward.observed.deinit();
    try channels.tips.sender.send(backward.update);
    channels.tips.sender.deinit();
    defer channels.targets.sender.deinit();
    defer channels.targets.receiver.deinit();

    var tip_updates: ?ring.Receiver(Update) = channels.tips.receiver;
    defer if (tip_updates) |*receiver| receiver.deinit();
    var current_anchor = anchor(2);
    var current_target: u64 = 7;
    const sender = channels.targets.sender;
    try testing.expect(dispatch(&tip_updates, sender, &current_anchor, &current_target));

    // A tip at the current height is observed but not adopted; the drained, senderless
    // channel is closed.
    try backward.observed.recv();
    try testing.expectEqual(null, tip_updates);
    try testing.expect(current_anchor.eql(anchor(2)));
    try testing.expectEqual(7, current_target);
    try testing.expectError(error.Empty, channels.targets.receiver.try_recv());
}

test "stateful sync: an evicted tip update fails its observer" {
    var channels = try Channels.init(1);
    defer channels.deinit();
    var evicted = try Update.with_observation(gpa, io, anchor(1), 1);
    defer evicted.observed.deinit();
    var kept = try Update.with_observation(gpa, io, anchor(2), 2);
    defer kept.observed.deinit();
    try channels.tips.sender.send(evicted.update);
    try channels.tips.sender.send(kept.update);
    try testing.expectError(error.Closed, evicted.observed.recv());
    channels.tips.receiver.deinit(); // Drops `kept` unhandled.
    try testing.expectError(error.Closed, kept.observed.recv());
}

const Pair = struct { left: u64, right: u64 };
const Coordinator = sync.CoordinatorState(Digest, Pair);

fn expect_dispatch(action: sync.CoordinatorAction(Digest, Pair), generation: u64, n: u64) !void {
    try testing.expectEqual(generation, action.dispatch.generation);
    try testing.expectEqual(Pair{ .left = n, .right = n }, action.dispatch.targets);
}

test "stateful sync: the coordinator rejects a stale reached event from an older generation" {
    var state: Coordinator = .init(2, anchor(0), .{ .left = 0, .right = 0 });
    state.record_tip_update(anchor(1), .{ .left = 1, .right = 1 });
    try expect_dispatch(state.next_action(), 1, 1);

    // This event belongs to generation 0 but arrives after database 1 moved to generation 1.
    state.record_reached(1, 0);
    // Only database 0 reached generation 1.
    state.record_reached(0, 1);
    try testing.expectEqual(.wait, std.meta.activeTag(state.next_action()));
}

test "stateful sync: the coordinator dispatches a pending tip before converging" {
    var state: Coordinator = .init(2, anchor(0), .{ .left = 0, .right = 0 });
    state.record_tip_update(anchor(1), .{ .left = 1, .right = 1 });
    try expect_dispatch(state.next_action(), 1, 1);
    state.record_reached(0, 1);
    state.record_reached(1, 1);
    state.record_tip_update(anchor(2), .{ .left = 2, .right = 2 });
    try expect_dispatch(state.next_action(), 2, 2);
    try testing.expect(state.should_dispatch(0) and state.should_dispatch(1));
}

test "stateful sync: the coordinator regroups databases that reached different generations" {
    var state: Coordinator = .init(2, anchor(0), .{ .left = 0, .right = 0 });
    state.record_tip_update(anchor(1), .{ .left = 1, .right = 1 });
    try expect_dispatch(state.next_action(), 1, 1);
    state.record_reached(0, 1);

    // A tip while database 1 still seeks goes to database 1 only.
    state.record_tip_update(anchor(2), .{ .left = 2, .right = 2 });
    try expect_dispatch(state.next_action(), 2, 2);
    try testing.expect(!state.should_dispatch(0));
    try testing.expect(state.should_dispatch(1));
    // A lower or equal tip is ignored.
    state.record_tip_update(anchor(2), .{ .left = 9, .right = 9 });
    state.record_reached(1, 2);

    // Both reached, at generations 1 and 2: database 0 regroups on generation 2.
    try expect_dispatch(state.next_action(), 2, 2);
    try testing.expect(state.should_dispatch(0));
    try testing.expect(!state.should_dispatch(1));
    try testing.expectEqual(.wait, std.meta.activeTag(state.next_action()));
    state.record_reached(0, 2);

    const converged = state.next_action().converged;
    try testing.expect(converged.anchor.eql(anchor(2)));
    try testing.expectEqual(Pair{ .left = 2, .right = 2 }, converged.targets);
}

test "stateful sync: the coordinator converges at once without tips" {
    var state: Coordinator = .init(3, anchor(5), .{ .left = 5, .right = 6 });
    try testing.expectEqual(.wait, std.meta.activeTag(state.next_action()));
    for (0..3) |index| state.record_reached(index, 0);
    // A reached database keeps its state through an unchanged-target dispatch.
    state.mark_reached_same_target(0, 0);
    const converged = state.next_action().converged;
    try testing.expect(converged.anchor.eql(anchor(5)));
    try testing.expectEqual(Pair{ .left = 5, .right = 6 }, converged.targets);
}
