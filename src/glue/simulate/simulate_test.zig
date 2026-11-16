//! Tests of `tracker.zig` and `action.zig` (commonware `simulate/{tracker,action}.rs` tests).

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const simulate = @import("mod.zig");

const PublicKey = cryptography.ed25519.PublicKey;
const PrivateKey = cryptography.ed25519.PrivateKey;
const Tracker = simulate.ProgressTracker(PublicKey);
const Round = consensus.Round;
const Epoch = consensus.Epoch;
const View = consensus.View;
const Height = consensus.Height;
const Duration = utils.time.Duration;
const gpa = testing.allocator;

fn key(seed: u64) PublicKey {
    return PrivateKey.from_seed(seed).public_key();
}

fn round(epoch: u64, view: u64) Round {
    return Round.new(Epoch.new(epoch), View.new(view));
}

fn observe_view(tracker: *Tracker, seed: u64, epoch: u64, view: u64) !void {
    const digest = std.mem.toBytes(std.mem.nativeToLittle(u64, view));
    try tracker.observe(.{
        .pk = key(seed),
        .round = round(epoch, view),
        .height = Height.new(view),
        .block_digest = &digest,
    });
}

test "tracker: conflicting same round from same validator is rejected" {
    // Establish the digest for a round before the validator reports a conflict.
    var tracker = Tracker.init(gpa);
    defer tracker.deinit();
    const pk = key(7);
    try tracker.observe(.{
        .pk = pk,
        .round = round(0, 3),
        .height = Height.new(3),
        .block_digest = &.{ 1, 2, 3 },
    });

    // A different height makes the rejection depend on round agreement alone.
    const conflict: Tracker.Update = .{
        .pk = pk,
        .round = round(0, 3),
        .height = Height.new(4),
        .block_digest = &.{ 9, 9, 9 },
    };
    try testing.expectError(error.ForkAtRound, tracker.observe(conflict));
    try testing.expectEqual(@as(usize, 2), tracker.unique_digests_at(3));
}

test "tracker: stale replay is checked without regressing progress" {
    // Advance one validator beyond the round that will be replayed.
    var tracker = Tracker.init(gpa);
    defer tracker.deinit();
    try tracker.observe(.{
        .pk = key(1),
        .round = round(0, 5),
        .height = Height.new(5),
        .block_digest = &.{ 5, 5, 5 },
    });

    // A replay adds agreement evidence without lowering the validator's progress.
    try tracker.observe(.{
        .pk = key(1),
        .round = round(0, 3),
        .height = Height.new(3),
        .block_digest = &.{ 1, 1, 1 },
    });
    try testing.expectEqual(@as(u64, 5), tracker.min_view());

    // Another validator must agree with the replay even though its round is stale.
    const conflict: Tracker.Update = .{
        .pk = key(2),
        .round = round(0, 3),
        .height = Height.new(3),
        .block_digest = &.{ 2, 2, 2 },
    };
    try testing.expectError(error.ForkAtHeight, tracker.observe(conflict));
}

test "tracker: same view in different epochs is not a fork" {
    var tracker = Tracker.init(gpa);
    defer tracker.deinit();
    try tracker.observe(.{
        .pk = key(1),
        .round = round(0, 3),
        .height = Height.new(3),
        .block_digest = &.{ 1, 1, 1 },
    });
    // View numbers may repeat across epochs; another height keeps both checks independent.
    try tracker.observe(.{
        .pk = key(2),
        .round = round(1, 3),
        .height = Height.new(8),
        .block_digest = &.{ 2, 2, 2 },
    });
    try testing.expectEqual(@as(usize, 2), tracker.tracked_count());
    try testing.expectEqual(round(1, 3), tracker.max_round().?);
}

test "tracker: later epoch low view does not satisfy required view" {
    var tracker = Tracker.init(gpa);
    defer tracker.deinit();
    try observe_view(&tracker, 1, 1, 1);
    try observe_view(&tracker, 2, 1, 2);
    try testing.expect(!tracker.all_reached(1, 10));
    try testing.expect(!tracker.all_reached(2, 10));
}

test "tracker: exact required view satisfies progress threshold" {
    var tracker = Tracker.init(gpa);
    defer tracker.deinit();
    try observe_view(&tracker, 1, 0, 10);
    try observe_view(&tracker, 2, 1, 10);
    try testing.expect(tracker.all_reached(1, 10));
    try testing.expect(tracker.all_reached(2, 10));
    try testing.expect(!tracker.all_reached(1, 11));
}

test "tracker: empty tracker" {
    var tracker = Tracker.init(gpa);
    defer tracker.deinit();
    try testing.expectEqual(@as(u64, 0), tracker.min_view());
    try testing.expectEqual(@as(?Round, null), tracker.max_round());
    try testing.expectEqual(@as(usize, 0), tracker.unique_digests_at(1));
    try testing.expect(tracker.all_reached(0, 1));
}

test "schedule: rejects out of order events" {
    const Schedule = simulate.Schedule(PublicKey);
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    const pk = key(0);
    try schedule.add(gpa, Duration.from_secs(5), .{ .crash = pk });
    const result = schedule.add(gpa, Duration.from_secs(2), .{ .restart = pk });
    try testing.expectError(error.OutOfOrder, result);
    // Equal times are allowed.
    try schedule.add(gpa, Duration.from_secs(5), .{ .restart = pk });
    try testing.expectEqual(@as(usize, 2), schedule.events.items.len);
}
