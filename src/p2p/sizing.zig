//! Message and peer-set sizing helpers (commonware `p2p/src/sizing.rs`).

const std = @import("std");
const assert = std.debug.assert;

/// The smallest `max_message_size` that admits every payload in `payloads`, or zero if there
/// are none. Every peer on a network must use the same limit. Panics if the largest payload
/// exceeds `u32` max.
pub fn max_message_size(payloads: []const usize) u32 {
    var largest: usize = 0;
    for (payloads) |payload| largest = @max(largest, payload);
    assert(payloads.len > 0 or largest == 0);
    return std.math.cast(u32, largest) orelse @panic("payload must fit in u32");
}

/// The smallest `max_peers_per_set` that admits every peer set drawn from `participants` when
/// the network runs as `local`. A `local` outside `participants` takes one extra slot;
/// duplicate participants count as separate slots. `P` has `order(a, b)`.
pub fn peer_set_limit(comptime P: type, participants: []const P, local: P) usize {
    var contains_local = false;
    for (participants) |participant| {
        if (P.order(participant, local) == .eq) contains_local = true;
    }
    const count = participants.len + @intFromBool(!contains_local);
    assert(count >= 1);
    return count;
}

/// A conservative retained-peer bound for mailbox sizing: each tracked set may contribute
/// `max_peers_per_set` identities, plus `persistent_peers` outside that window.
pub fn max_retained_peers(
    max_peers_per_set: usize,
    tracked_peer_sets: usize,
    persistent_peers: usize,
) usize {
    assert(max_peers_per_set > 0);
    assert(tracked_peer_sets > 0);
    const product = std.math.mul(usize, max_peers_per_set, tracked_peer_sets) catch
        @panic("maximum retained peer count overflow");
    return std.math.add(usize, product, persistent_peers) catch
        @panic("maximum retained peer count overflow");
}

/// Counts identities across `primary` and `secondary`, each sorted and deduplicated by
/// `P.order`. Identities in both roles count once; `extension` counts once when absent from
/// both.
pub fn peer_set_size(
    comptime P: type,
    primary: []const P,
    secondary: []const P,
    extension: ?P,
) usize {
    var p: usize = 0;
    var s: usize = 0;
    var count: usize = 0;
    var contains_extension = extension == null;
    while (p < primary.len or s < secondary.len) : (count += 1) {
        const peer = if (p == primary.len)
            secondary[s]
        else if (s == secondary.len)
            primary[p]
        else switch (P.order(primary[p], secondary[s])) {
            .lt => primary[p],
            .gt => secondary[s],
            .eq => primary[p],
        };
        if (p < primary.len and P.order(primary[p], peer) == .eq) p += 1;
        if (s < secondary.len and P.order(secondary[s], peer) == .eq) s += 1;
        if (extension) |e| {
            if (P.order(e, peer) == .eq) contains_extension = true;
        }
    }
    assert(count <= primary.len + secondary.len);
    return count + @intFromBool(!contains_extension);
}

const testing = std.testing;

const Int = struct {
    value: u32,
    fn order(a: Int, b: Int) std.math.Order {
        return std.math.order(a.value, b.value);
    }
};

fn ints(comptime values: []const u32) [values.len]Int {
    var result: [values.len]Int = undefined;
    for (values, &result) |value, *item| item.* = .{ .value = value };
    return result;
}

test "max_message_size (test_max_message_size)" {
    try testing.expectEqual(@as(u32, 0), max_message_size(&.{}));
    try testing.expectEqual(@as(u32, 7), max_message_size(&.{ 3, 7, 5 }));
    try testing.expectEqual(@as(u32, 5), max_message_size(&.{ 3, 5 }));
    const largest: usize = std.math.maxInt(u32);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), max_message_size(&.{ 0, largest }));
}

test "max_retained_peers (test_max_retained_peers)" {
    try testing.expectEqual(@as(usize, 14), max_retained_peers(3, 4, 2));
}

test "peer_set_limit counts the local identity once" {
    const participants = ints(&.{ 1, 2 });
    try testing.expectEqual(@as(usize, 2), peer_set_limit(Int, &participants, .{ .value = 1 }));
    try testing.expectEqual(@as(usize, 3), peer_set_limit(Int, &participants, .{ .value = 3 }));
}

test "peer_set_size deduplicates roles and includes the extension" {
    const primary = ints(&.{ 1, 3 });
    const secondary = ints(&.{ 2, 3 });
    try testing.expectEqual(@as(usize, 3), peer_set_size(Int, &primary, &secondary, null));
    const two: Int = .{ .value = 2 };
    try testing.expectEqual(@as(usize, 3), peer_set_size(Int, &primary, &secondary, two));
    const four: Int = .{ .value = 4 };
    try testing.expectEqual(@as(usize, 4), peer_set_size(Int, &primary, &secondary, four));
    try testing.expectEqual(@as(usize, 1), peer_set_size(Int, &.{}, &.{}, four));
    try testing.expectEqual(@as(usize, 0), peer_set_size(Int, &.{}, &.{}, null));
}
