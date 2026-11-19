//! commonware `simulated/mod.rs` `register_peer_set`: a manager reports no set before one is
//! tracked, then the tracked set at its index as primary peers with no secondaries.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const p2p = @import("../root.zig");
const t = @import("network_test.zig");

const Key = t.Key;
const Net = t.Net;
const key = t.key;

fn register_peer_set(io: Io) !void {
    const network = try Net.init(testing.allocator, io, t.config(2, 3));
    defer network.deinit();
    const manager = network.oracle().manager();
    try testing.expectEqual(null, try manager.peer_set(testing.allocator, 0));

    var primary = [_]Key{ key(1), key(2) };
    const peers: t.Tracked = .{ .primary = t.set(&primary), .secondary = t.set(&.{}) };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(0xFF, peers));

    const owned = (try manager.peer_set(testing.allocator, 0xFF)).?;
    defer owned.free(testing.allocator);
    var expected = [_]Key{ key(1), key(2) };
    t.Tracked.PeerSet.sort(&expected);
    try testing.expectEqualSlices(Key, &expected, owned.primary);
    try testing.expectEqual(0, owned.secondary.len);
    try testing.expectEqual(null, try manager.peer_set(testing.allocator, 0));
}

test "register_peer_set: a tracked set is reported at its index as primary peers" {
    _ = try t.run_deterministic(0, register_peer_set);
}
