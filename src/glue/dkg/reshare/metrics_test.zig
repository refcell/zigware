const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const cryptography = @import("cryptography");
const metrics = @import("runtime").telemetry.metrics;
const Metrics = @import("metrics.zig").Metrics;

const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Set = utils.ordered.Set(PublicKey);
const gpa = testing.allocator;

const Sample = struct { peer: PublicKey, epoch: u64 };

/// Asserts the samples of `name` are exactly `expected`, keyed by `peer="<key>"`.
fn expect_exported(registry: *metrics.Registry, name: []const u8, expected: []const Sample) !void {
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    var count: usize = 0;
    var samples = metrics.metric_samples(text, name);
    while (samples.next()) |sample| : (count += 1) {
        const found = for (expected) |entry| {
            var buffer: [128]u8 = undefined;
            const label = try std.fmt.bufPrint(&buffer, "peer=\"{f}\"", .{entry.peer});
            if (std.mem.eql(u8, sample.labels, label)) break entry;
        } else return error.UnexpectedSample;
        try testing.expectEqual(found.epoch, try std.fmt.parseInt(u64, sample.value, 10));
    }
    try testing.expectEqual(expected.len, count);
}

fn set(peers: []const PublicKey) !Set {
    return Set.init(gpa, peers);
}

// commonware `reconcile_prunes_peers_that_left_their_role`: `latest_share` and `latest_ack`
// cover only the installed epoch's dealers and players.
test "metrics: reconcile prunes peers that left their role" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("reshare");
    var reshare = try Metrics(PublicKey).init(gpa, &scope);
    defer reshare.deinit();
    var peers: [3]PublicKey = undefined;
    for (&peers, 0..) |*peer, seed| peer.* = PrivateKey.from_seed(seed).public_key();

    // Observed dealers and players are exported with their latest epochs.
    var all = try set(&peers);
    defer all.deinit(gpa);
    reshare.reconcile(all, all);
    reshare.record_share(peers[0], 1);
    reshare.record_share(peers[1], 1);
    reshare.record_ack(peers[0], 1);
    reshare.record_ack(peers[2], 1);
    try expect_exported(&registry, "reshare_latest_share", &.{
        .{ .peer = peers[0], .epoch = 1 },
        .{ .peer = peers[1], .epoch = 1 },
    });
    try expect_exported(&registry, "reshare_latest_ack", &.{
        .{ .peer = peers[0], .epoch = 1 },
        .{ .peer = peers[2], .epoch = 1 },
    });

    // Leaving a role removes that role's gauge, a peer that keeps its role keeps its epoch,
    // and a dealer appears only once it deals.
    var dealers = try set(&.{ peers[1], peers[2] });
    defer dealers.deinit(gpa);
    var players = try set(&.{peers[0]});
    defer players.deinit(gpa);
    reshare.reconcile(dealers, players);
    try expect_exported(&registry, "reshare_latest_share", &.{.{ .peer = peers[1], .epoch = 1 }});
    try expect_exported(&registry, "reshare_latest_ack", &.{.{ .peer = peers[0], .epoch = 1 }});
    reshare.record_share(peers[1], 2);
    reshare.record_share(peers[2], 2);
    try expect_exported(&registry, "reshare_latest_share", &.{
        .{ .peer = peers[1], .epoch = 2 },
        .{ .peer = peers[2], .epoch = 2 },
    });
}

test "metrics: epoch, phase, and success counters" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("reshare");
    var reshare = try Metrics(PublicKey).init(gpa, &scope);
    defer reshare.deinit();
    reshare.set_epoch(4);
    reshare.set_phase(.inclusion);
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    try testing.expect(metrics.has_metric_value(text, "reshare_current_epoch", 4));
    try testing.expect(metrics.has_metric_value(text, "reshare_current_round", 4));
    try testing.expect(metrics.has_metric_value(text, "reshare_phase", 3));
}
