//! Tests of the processor's speculative state: caching rules, descendants, the finalization
//! boundary snapshot, and branch retention (commonware's `cache_pending`, `retain_branch`, and
//! `execution_finalization_prunes_losing_fork*` behavior, without databases).

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus");
const pending_mod = @import("pending.zig");

const gpa = testing.allocator;

/// A batch that counts live copies.
const Batch = struct {
    live: *i64,
    id: u64,

    fn init(live: *i64, id: u64) Batch {
        live.* += 1;
        return .{ .live = live, .id = id };
    }

    pub fn clone(self: *const Batch) Batch {
        return init(self.live, self.id);
    }

    pub fn deinit(self: *Batch) void {
        self.live.* -= 1;
        self.* = undefined;
    }
};

const Pending = pending_mod.Pending(u64, Batch);

fn round(view: u64) consensus.Round {
    return .new(.zero(), .new(view));
}

fn anchor(digest: u64, view: u64) Pending.Anchor {
    return .{ .height = .new(view), .round = round(view), .digest = digest };
}

fn cache(state: *Pending, live: *i64, digest: u64, parent: u64, view: u64) !bool {
    const entry: Pending.Entry = .{
        .round = round(view),
        .parent = parent,
        .merkleized = .init(live, digest),
    };
    return state.cache(digest, entry);
}

test "stateful pending: caches only blocks linked to the branch at later rounds" {
    var live: i64 = 0;
    {
        var state = Pending.init(gpa, anchor(1, 1));
        defer state.deinit();
        try testing.expect(try cache(&state, &live, 2, 1, 2));
        try testing.expect(try cache(&state, &live, 3, 2, 3));
        // Not above the anchor's round, or on an unknown parent: refused and released.
        try testing.expect(!try cache(&state, &live, 4, 1, 1));
        try testing.expect(!try cache(&state, &live, 5, 9, 5));
        // An existing entry keeps its state; the duplicate's batch is released.
        try testing.expect(try cache(&state, &live, 2, 1, 2));
        try testing.expectEqual(2, state.speculative_len());
        try testing.expectEqual(2, live);
        try testing.expectEqual(2, state.get(2).?.merkleized.id);
    }
    try testing.expectEqual(0, live);
}

test "stateful pending: the boundary holds the block and its later descendants" {
    var live: i64 = 0;
    var state = Pending.init(gpa, anchor(1, 1));
    defer state.deinit();
    // 1 -> 2 -> 3 -> 5 and 1 -> 4 (a fork); 6 sits on 2 at the same round as 3.
    _ = try cache(&state, &live, 2, 1, 2);
    _ = try cache(&state, &live, 3, 2, 3);
    _ = try cache(&state, &live, 4, 1, 4);
    _ = try cache(&state, &live, 5, 3, 6);
    _ = try cache(&state, &live, 6, 2, 3);
    // 7 is a child of 3 at the boundary's own round.
    _ = try cache(&state, &live, 7, 3, 3);

    var boundary = try state.boundary(3, round(3));
    defer boundary.deinit(gpa);
    try testing.expectEqual(2, boundary.compatible.count());
    try testing.expect(boundary.compatible.contains(3) and boundary.compatible.contains(5));
    // Siblings at the boundary's round are not descendants.
    try testing.expect(!boundary.compatible.contains(6));
    try testing.expect(!boundary.compatible.contains(4));
    // Children at the boundary's round are not descendants either.
    try testing.expect(!boundary.compatible.contains(7));
}

test "stateful pending: retain_branch prunes losing forks and their descendants" {
    var live: i64 = 0;
    {
        var state = Pending.init(gpa, anchor(1, 1));
        defer state.deinit();
        _ = try cache(&state, &live, 2, 1, 2);
        _ = try cache(&state, &live, 3, 2, 3);
        _ = try cache(&state, &live, 4, 1, 3); // A fork of 2.
        _ = try cache(&state, &live, 7, 4, 5); // Its descendant.

        // Finalizing 2 keeps 2 and 3 and prunes the fork 4 with its descendant 7.
        var batch = Batch.init(&live, 99);
        defer batch.deinit();
        try testing.expectEqual(2, try state.retain_branch(anchor(2, 2), 1, &batch));
        try testing.expect(state.contains(2) and state.contains(3));
        try testing.expect(!state.contains(4) and !state.contains(7));
        // 2 was cached, so its own state stays; the anchor is not counted as speculative.
        try testing.expectEqual(2, state.get(2).?.merkleized.id);
        try testing.expectEqual(1, state.speculative_len());
        try testing.expectEqual(2, state.branch.digest);

        // The next finalization drops the previous anchor's entry, which no longer descends.
        try testing.expectEqual(1, try state.retain_branch(anchor(3, 3), 2, &batch));
        try testing.expect(!state.contains(2));
        try testing.expectEqual(3, state.get(3).?.merkleized.id);
        // Finalizing an uncached block caches a copy of its batch.
        try testing.expectEqual(1, try state.retain_branch(anchor(8, 4), 3, &batch));
        try testing.expectEqual(99, state.get(8).?.merkleized.id);
        try testing.expectEqual(0, state.speculative_len());
        // New blocks must now build on 8.
        try testing.expect(!try cache(&state, &live, 9, 3, 5));
        try testing.expect(try cache(&state, &live, 9, 8, 5));
    }
    try testing.expectEqual(0, live);
}
