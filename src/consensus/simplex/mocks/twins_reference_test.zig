//! commonware `simplex/mocks/twins.rs`'s independent reference enumerator for small cases
//! (`reference_next_round_transitions`, `reference_scenario_count`, `reference_scenarios`),
//! and the two tests that check the compressed generator against it:
//! `compressed_counts_match_reference_enumeration` and
//! `compressed_unranking_matches_reference_space`.
//!
//! commonware expands each round by recursion over the cells. Here each cell's choices are
//! listed first and an odometer walks their cross product, and rounds expand a multiset of
//! residual cell partitions (for counts) or a set of whole scenarios (for the space), so
//! nothing recurses.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");
const generator_mod = @import("twins_generator.zig");

const gpa = testing.allocator;
const RoundScenario = generator_mod.RoundScenario;
const Generator = generator_mod.Generator;

/// The reference runs on at most this many participants (so at most this many cells).
const cells_max = 8;
/// The most rounds a reference scenario holds.
const rounds_max = 3;

/// A partition of the participants into consecutive cells, by size.
const Cells = struct {
    len: u32 = 0,
    sizes: [cells_max]u32 = @splat(0),

    fn one(n: u32) Cells {
        var cells: Cells = .{};
        cells.push(n);
        return cells;
    }

    fn push(cells: *Cells, size: u32) void {
        assert(size > 0);
        assert(cells.len < cells_max);
        cells.sizes[cells.len] = size;
        cells.len += 1;
    }

    fn slice(cells: *const Cells) []const u32 {
        return cells.sizes[0..cells.len];
    }

    fn total(cells: *const Cells) u32 {
        var sum: u32 = 0;
        for (cells.slice()) |size| sum += size;
        return sum;
    }
};

/// `len` participants from `start` (commonware's test `range_mask`).
fn range_mask(start: u32, len: u32) u64 {
    if (len == 0) return 0;
    assert(start + len <= 64);
    if (len == 64) return std.math.maxInt(u64);
    return ((@as(u64, 1) << @intCast(len)) - 1) << @intCast(start);
}

/// One cell's share of a transition: the parts it splits into, in order, the participants
/// it adds to each half, and the leader it holds, if any.
const Choice = struct {
    parts: Cells = .{},
    primary: u64 = 0,
    secondary: u64 = 0,
    leader: ?u32 = null,
};

/// The choices of the cell of `size` at `start` when both halves see the same participants
/// (commonware `no_secondary`): participants outside, the rest in both, then the leader.
fn shared_choices(start: u32, size: u32, is_leader: bool, out: *std.ArrayList(Choice)) !void {
    const available = if (is_leader) size - 1 else size;
    var outside: u32 = 0;
    while (outside <= available) : (outside += 1) {
        const both = available - outside;
        var choice: Choice = .{ .primary = range_mask(start + outside, both) };
        if (outside > 0) choice.parts.push(outside);
        if (both > 0) choice.parts.push(both);
        if (is_leader) {
            const leader = start + outside + both;
            choice.primary |= @as(u64, 1) << @intCast(leader);
            choice.parts.push(1);
            choice.leader = leader;
        }
        choice.secondary = choice.primary;
        try out.append(gpa, choice);
    }
    assert(out.items.len == available + 1);
}

/// Where the leader sits in a split round: primary only, secondary only, or both.
const leader_placements = [_][2]bool{ .{ true, false }, .{ false, true }, .{ true, true } };

/// commonware `with_secondary`'s choices for one cell: outside, both, secondary-only, and
/// primary-only parts in that order, and for the leader's cell each leader placement.
fn split_choices(start: u32, size: u32, is_leader: bool, out: *std.ArrayList(Choice)) !void {
    const available = if (is_leader) size - 1 else size;
    var outside: u32 = 0;
    while (outside <= available) : (outside += 1) {
        var both: u32 = 0;
        while (both <= available - outside) : (both += 1) {
            const remaining = available - outside - both;
            var secondary: u32 = 0;
            while (secondary <= remaining) : (secondary += 1) {
                const primary = remaining - secondary;
                var choice: Choice = .{};
                for ([_]u32{ outside, both, secondary, primary }) |part| {
                    if (part > 0) choice.parts.push(part);
                }
                const shared = range_mask(start + outside, both);
                choice.secondary = shared | range_mask(start + outside + both, secondary);
                const primary_start = start + outside + both + secondary;
                choice.primary = shared | range_mask(primary_start, primary);
                if (!is_leader) {
                    try out.append(gpa, choice);
                    continue;
                }
                const leader = primary_start + primary;
                choice.parts.push(1);
                choice.leader = leader;
                const leader_bit = @as(u64, 1) << @intCast(leader);
                for (leader_placements) |placement| {
                    var placed = choice;
                    if (placement[0]) placed.primary |= leader_bit;
                    if (placement[1]) placed.secondary |= leader_bit;
                    try out.append(gpa, placed);
                }
            }
        }
    }
}

const Transition = struct { round: RoundScenario, next: Cells };

/// Every next-round transition from `cells`, with its residual cells (commonware
/// `reference_next_round_transitions`).
fn reference_transitions(cells: *const Cells, out: *std.ArrayList(Transition)) !void {
    assert(cells.len > 0);
    var leader_cell: u32 = 0;
    while (leader_cell < cells.len) : (leader_cell += 1) {
        try mode_transitions(cells, leader_cell, false, out);
        try mode_transitions(cells, leader_cell, true, out);
    }
}

/// The transitions with the leader in `leader_cell`, with halves that see the same
/// participants or (`split`) different ones.
fn mode_transitions(
    cells: *const Cells,
    leader_cell: u32,
    split: bool,
    out: *std.ArrayList(Transition),
) !void {
    var lists: [cells_max]std.ArrayList(Choice) = @splat(.empty);
    defer for (&lists) |*list| list.deinit(gpa);
    var start: u32 = 0;
    for (cells.slice(), 0..) |size, index| {
        const is_leader = index == leader_cell;
        if (split) {
            try split_choices(start, size, is_leader, &lists[index]);
        } else {
            try shared_choices(start, size, is_leader, &lists[index]);
        }
        start += size;
    }
    assert(start == cells.total());
    // An odometer over the cells' choices walks their cross product.
    var digits: [cells_max]u32 = @splat(0);
    while (true) {
        try emit(cells, lists[0..cells.len], digits[0..cells.len], split, out);
        if (!advance(digits[0..cells.len], lists[0..cells.len])) break;
    }
}

/// Steps the odometer; false once it wraps.
fn advance(digits: []u32, lists: []const std.ArrayList(Choice)) bool {
    assert(digits.len == lists.len);
    for (lists, digits) |list, *digit| {
        digit.* += 1;
        if (digit.* < list.items.len) return true;
        digit.* = 0;
    }
    return false;
}

fn emit(
    cells: *const Cells,
    lists: []const std.ArrayList(Choice),
    digits: []const u32,
    split: bool,
    out: *std.ArrayList(Transition),
) !void {
    var round = empty_round;
    var next: Cells = .{};
    var leader: ?u32 = null;
    for (lists, digits) |list, digit| {
        const choice = list.items[digit];
        for (choice.parts.slice()) |part| next.push(part);
        round.primary_mask |= choice.primary;
        round.secondary_mask |= choice.secondary;
        if (choice.leader) |value| leader = value;
    }
    // commonware drops a split round whose halves see the same participants.
    if (split and round.primary_mask == round.secondary_mask) return;
    round.leader = leader.?; // Proof: exactly one cell holds the leader.
    assert(next.total() == cells.total());
    try out.append(gpa, .{ .round = round, .next = next });
}

/// The number of `rounds`-round scenarios from one cell of `n` (commonware
/// `reference_scenario_count`), or null when it overflows `u128`.
fn reference_count(n: u32, rounds: u32) !?u128 {
    const Frontier = std.AutoHashMapUnmanaged(Cells, u128);
    var frontier: Frontier = .empty;
    defer frontier.deinit(gpa);
    try frontier.put(gpa, .one(n), 1);
    var transitions: std.ArrayList(Transition) = .empty;
    defer transitions.deinit(gpa);
    for (0..rounds) |_| {
        var next: Frontier = .empty;
        defer next.deinit(gpa);
        var entries = frontier.iterator();
        while (entries.next()) |entry| {
            transitions.clearRetainingCapacity();
            try reference_transitions(entry.key_ptr, &transitions);
            for (transitions.items) |transition| {
                const slot = try next.getOrPut(gpa, transition.next);
                const prior = if (slot.found_existing) slot.value_ptr.* else 0;
                slot.value_ptr.* = std.math.add(u128, prior, entry.value_ptr.*) catch return null;
            }
        }
        std.mem.swap(Frontier, &frontier, &next);
    }
    var total: u128 = 0;
    var counts = frontier.valueIterator();
    while (counts.next()) |count| total = std.math.add(u128, total, count.*) catch return null;
    return total;
}

// commonware `compressed_counts_match_reference_enumeration`: the generator's compressed
// count of `rounds`-round scenarios matches the reference for 2 to 4 participants and 1 to 3
// rounds.
test "twins: compressed counts match the reference enumeration" {
    var n: u32 = 2;
    while (n <= 4) : (n += 1) {
        var rounds: u32 = 1;
        while (rounds <= rounds_max) : (rounds += 1) {
            const reference = try reference_count(n, rounds);
            try testing.expect(reference != null);
            var generator: Generator = .init(gpa, n);
            defer generator.deinit();
            const initial = generator_mod.CellState.from_cells(&.{n});
            const compressed: ?u128 = if (try generator.count(rounds)) |counts| blk: {
                defer Generator.free_counts(gpa, counts);
                break :blk counts[rounds].get(initial.boundaries).?;
            } else null;
            try testing.expectEqual(reference, compressed);
        }
    }
}

const empty_round: RoundScenario = .{ .leader = 0, .primary_mask = 0, .secondary_mask = 0 };

/// A scenario and its residual cells, as one set key.
const Entry = struct {
    len: u32 = 0,
    rounds: [rounds_max]RoundScenario = @splat(empty_round),
    cells: Cells = .{},
};
const EntrySet = std.AutoHashMapUnmanaged(Entry, void);

/// Every `rounds`-round scenario from one cell of `n` with its residual cells (commonware
/// `reference_scenarios`).
fn reference_scenarios(n: u32, rounds: u32, out: *EntrySet) !void {
    assert(rounds <= rounds_max);
    var frontier: EntrySet = .empty;
    defer frontier.deinit(gpa);
    try frontier.put(gpa, .{ .cells = .one(n) }, {});
    var transitions: std.ArrayList(Transition) = .empty;
    defer transitions.deinit(gpa);
    for (0..rounds) |_| {
        var next: EntrySet = .empty;
        defer next.deinit(gpa);
        var entries = frontier.keyIterator();
        while (entries.next()) |entry| {
            transitions.clearRetainingCapacity();
            try reference_transitions(&entry.cells, &transitions);
            for (transitions.items) |transition| {
                var extended = entry.*;
                extended.rounds[extended.len] = transition.round;
                extended.len += 1;
                extended.cells = transition.next;
                try next.put(gpa, extended, {});
            }
        }
        std.mem.swap(EntrySet, &frontier, &next);
    }
    var entries = frontier.keyIterator();
    while (entries.next()) |entry| try out.put(gpa, entry.*, {});
}

fn entry_of(generated: generator_mod.Generated) Entry {
    var entry: Entry = .{};
    assert(generated.rounds.len <= rounds_max);
    for (generated.rounds) |round| {
        entry.rounds[entry.len] = round;
        entry.len += 1;
    }
    for (generated.cells) |size| entry.cells.push(size);
    return entry;
}

// commonware `compressed_unranking_matches_reference_space`: generating every scenario
// (unranking each index of the compressed count) yields exactly the reference space, for 2
// participants over 3 rounds and 3 participants over 2.
test "twins: compressed unranking matches the reference space" {
    const shapes = [_][2]u32{ .{ 2, 3 }, .{ 3, 2 } };
    for (shapes) |shape| {
        const n, const rounds = shape;
        var generator: Generator = .init(gpa, n);
        defer generator.deinit();
        var rng = utils.rng.test_rng();
        const all = try generator.generate(&rng, rounds, std.math.maxInt(u32));
        defer generator_mod.free_generated(gpa, all);
        var generated: EntrySet = .empty;
        defer generated.deinit(gpa);
        for (all) |item| try generated.put(gpa, entry_of(item), {});
        var reference: EntrySet = .empty;
        defer reference.deinit(gpa);
        try reference_scenarios(n, rounds, &reference);
        try testing.expectEqual(reference.count(), generated.count());
        var keys = generated.keyIterator();
        while (keys.next()) |key| try testing.expect(reference.contains(key.*));
    }
}
