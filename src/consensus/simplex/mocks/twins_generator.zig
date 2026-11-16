//! The twins scenario generator (the private half of commonware `simplex/mocks/twins.rs`).
//!
//! In each round every non-leader participant takes one of four ordered roles: outside both
//! halves, visible to both, secondary only, or primary only. The leader is a singleton at
//! the end of its cell, visible to at least one half. A residual cell groups participants
//! with identical role history; a transition records only the next cell boundaries, and
//! its multiplicity counts the role choices that reach them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");

pub const participants_max = 64;

pub const RoundScenario = struct {
    /// The participant index leading this round.
    leader: u32,
    /// Which participants each twin half exchanges messages with (they may overlap).
    primary_mask: u64,
    secondary_mask: u64,
};

/// A generated canonical scenario and its residual cell sizes. Owns both.
pub const Generated = struct { rounds: []RoundScenario, cells: []u32 };

pub fn free_generated(gpa: Allocator, generated: []Generated) void {
    for (generated) |item| {
        gpa.free(item.rounds);
        gpa.free(item.cells);
    }
    gpa.free(generated);
}

/// Every bit in `[start, start + len)`.
pub fn mask_range(start: usize, len: usize) u64 {
    assert(start + len <= participants_max);
    if (len == 0) return 0;
    if (len == participants_max) return std.math.maxInt(u64);
    return ((@as(u64, 1) << @intCast(len)) - 1) << @intCast(start);
}

fn bit(index: usize) u64 {
    assert(index < participants_max);
    return @as(u64, 1) << @intCast(index);
}

pub const Range = struct { start: u32, len: u32 };

/// A canonical cell partition: bit `i` marks a boundary after participant `i`.
pub const CellState = struct {
    boundaries: u64 = 0,

    pub fn from_cells(cells: []const u32) CellState {
        var state: CellState = .{};
        var end: usize = 0;
        for (cells[0..cells.len -| 1]) |size| {
            end += size;
            state.boundaries |= bit(end - 1);
        }
        return state;
    }

    fn boundary_after(state: CellState, index: usize) bool {
        return index < participants_max and state.boundaries & bit(index) != 0;
    }

    /// The cells over `n` participants as contiguous ranges, into `out`.
    pub fn ranges(state: CellState, n: usize, out: *[participants_max]Range) []Range {
        assert(n > 0 and n <= participants_max);
        var count: usize = 0;
        var start: usize = 0;
        for (0..n - 1) |index| {
            if (!state.boundary_after(index)) continue;
            out[count] = .{ .start = @intCast(start), .len = @intCast(index + 1 - start) };
            count += 1;
            start = index + 1;
        }
        out[count] = .{ .start = @intCast(start), .len = @intCast(n - start) };
        assert(out[count].len > 0);
        return out[0 .. count + 1];
    }

    pub fn to_cells(state: CellState, gpa: Allocator, n: usize) ![]u32 {
        var buffer: [participants_max]Range = undefined;
        const cell_ranges = state.ranges(n, &buffer);
        const cells = try gpa.alloc(u32, cell_ranges.len);
        for (cells, cell_ranges) |*cell, range| cell.* = range.len;
        return cells;
    }

    /// The positive parts of the cell `[start, start + size)`, into `out`.
    fn parts_in_cell(state: CellState, start: usize, size: usize, out: []u32) []u32 {
        const end = start + size;
        var count: usize = 0;
        var part_start = start;
        for (start..end) |index| {
            if (index + 1 != end and !state.boundary_after(index)) continue;
            out[count] = @intCast(index + 1 - part_start);
            count += 1;
            part_start = index + 1;
        }
        assert(count > 0);
        return out[0..count];
    }

    fn add_local_boundaries(state: *CellState, start: usize, n: usize, parts: []const u32) void {
        var end = start;
        for (parts) |part| {
            end += part;
            if (end < n) state.boundaries |= bit(end - 1);
        }
        assert(end <= n);
    }
};

/// One cell's refinement: up to four role parts, plus the leader singleton in the leader
/// cell; `multiplicity` counts the ordered role choices with these sizes.
const LocalRefinement = struct {
    parts: [5]u32,
    len: u8,
    multiplicity: u128,

    fn slice(refinement: *const LocalRefinement) []const u32 {
        return refinement.parts[0..refinement.len];
    }
};

const TransitionEdge = struct { next: CellState, leader_cell: u32, multiplicity: u128 };

const TransitionSet = struct {
    edges: std.ArrayList(TransitionEdge) = .empty,
    /// Whether some multiplicity overflowed `u128` (counting treats it as overflow).
    overflowed: bool = false,
};

const Role = enum { outside, both, secondary, primary };

/// How many ordered role subsets cover `len` parts (`C(4, len)`).
fn role_subset_count(len: usize) u128 {
    return switch (len) {
        0 => 1,
        1 => 4,
        2 => 6,
        3 => 4,
        4 => 1,
        else => @panic("role bucket count exceeds role space"),
    };
}

/// The `rank`-th subset of `len` roles, in role order (masks ascending).
fn roles_from_rank(len: usize, rank: u128) [4]Role {
    var seen: u128 = 0;
    for (0..16) |mask| {
        if (@popCount(mask) != len) continue;
        if (seen == rank) {
            var roles: [4]Role = @splat(.outside);
            var next: usize = 0;
            for ([_]Role{ .outside, .both, .secondary, .primary }, 0..) |role, index| {
                if (mask & (@as(usize, 1) << @intCast(index)) == 0) continue;
                roles[next] = role;
                next += 1;
            }
            return roles;
        }
        seen += 1;
    }
    unreachable; // Proof: callers pass rank < role_subset_count(len).
}

fn apply_roles(start: usize, parts: []const u32, roles: []const Role, masks: *[2]u64) void {
    assert(parts.len == roles.len);
    var offset: usize = 0;
    for (parts, roles) |part, role| {
        const range = mask_range(start + offset, part);
        switch (role) {
            .outside => {},
            .both => {
                masks[0] |= range;
                masks[1] |= range;
            },
            .secondary => masks[1] |= range,
            .primary => masks[0] |= range,
        }
        offset += part;
    }
}

/// Steps `parts` (each at least 1, summing to their total) to the next composition in
/// lexicographic order; returns false after the last one.
fn next_composition(parts: []u32) bool {
    if (parts.len < 2) return false;
    var tail: u64 = parts[parts.len - 1];
    var index = parts.len - 1;
    while (index > 0) {
        index -= 1;
        const tail_parts = parts.len - 1 - index;
        if (tail > tail_parts) {
            parts[index] += 1;
            @memset(parts[index + 1 .. parts.len - 1], 1);
            parts[parts.len - 1] = @intCast(tail - 1 - (tail_parts - 1));
            return true;
        }
        tail += parts[index];
    }
    return false;
}

/// commonware `build_local_refinements`: compositions of the cell's non-leader members
/// into at most four parts, by part count then lexicographically.
fn build_local_refinements(gpa: Allocator, size: u32, is_leader: bool) ![]LocalRefinement {
    assert(size > 0);
    const available = if (is_leader) size - 1 else size;
    var refinements: std.ArrayList(LocalRefinement) = .empty;
    errdefer refinements.deinit(gpa);
    if (available == 0) try refinements.append(gpa, local_refinement(&.{}, is_leader));
    for (1..@min(available, 4) + 1) |count| {
        var parts: [4]u32 = @splat(1);
        parts[count - 1] = available - @as(u32, @intCast(count - 1));
        while (true) {
            try refinements.append(gpa, local_refinement(parts[0..count], is_leader));
            if (!next_composition(parts[0..count])) break;
        }
    }
    return refinements.toOwnedSlice(gpa);
}

fn local_refinement(parts: []const u32, is_leader: bool) LocalRefinement {
    assert(parts.len <= 4);
    var result: LocalRefinement = .{
        .parts = @splat(0),
        .len = @intCast(parts.len),
        .multiplicity = 0,
    };
    @memcpy(result.parts[0..parts.len], parts);
    const role_choices = role_subset_count(parts.len);
    if (is_leader) {
        result.parts[parts.len] = 1;
        result.len += 1;
    }
    // The leader is primary-only, secondary-only, or in both halves.
    result.multiplicity = if (is_leader) role_choices * 3 else role_choices;
    return result;
}

/// Steps `taken` (each at most its cell's size, summing to their total) to the next
/// assignment in lexicographic order; returns false after the last one.
fn next_assignment(taken: []u32, sizes: []const u32) bool {
    assert(taken.len == sizes.len);
    if (taken.len < 2) return false;
    var tail: u64 = taken[taken.len - 1];
    var index = taken.len - 1;
    while (index > 0) {
        index -= 1;
        if (tail > 0 and taken[index] < sizes[index]) {
            taken[index] += 1;
            fill_from_right(taken[index + 1 ..], sizes[index + 1 ..], tail - 1);
            return true;
        }
        tail += taken[index];
    }
    return false;
}

/// The lexicographically smallest assignment of `total` into `taken`: packed at the end.
fn fill_from_right(taken: []u32, sizes: []const u32, total: u64) void {
    var left = total;
    var index = taken.len;
    while (index > 0) {
        index -= 1;
        const take = @min(left, sizes[index]);
        taken[index] = @intCast(take);
        left -= take;
    }
    assert(left == 0);
}

/// commonware `compromised_sets_for_cells`: the first members of each cell, one set per
/// way to spread `faults` across the cells, in lexicographic order of per-cell counts.
pub fn compromised_sets(gpa: Allocator, cells: []const u32, faults: u32) ![][]u32 {
    assert(cells.len > 0 and cells.len <= participants_max);
    var capacity: u64 = 0;
    for (cells) |size| capacity += size;
    var sets: std.ArrayList([]u32) = .empty;
    errdefer free_sets(gpa, sets.items);
    defer sets.deinit(gpa);
    if (faults > capacity) return sets.toOwnedSlice(gpa);
    var taken_buffer: [participants_max]u32 = undefined;
    const taken = taken_buffer[0..cells.len];
    fill_from_right(taken, cells, faults);
    while (true) {
        const set = try gpa.alloc(u32, faults);
        var count: usize = 0;
        var start: u32 = 0;
        for (taken, cells) |take, size| {
            for (0..take) |offset| set[count + offset] = start + @as(u32, @intCast(offset));
            count += take;
            start += size;
        }
        assert(count == faults);
        sets.append(gpa, set) catch |err| {
            gpa.free(set);
            return err;
        };
        if (!next_assignment(taken, cells)) break;
    }
    return sets.toOwnedSlice(gpa);
}

pub fn free_sets(gpa: Allocator, sets: []const []u32) void {
    for (sets) |set| gpa.free(set);
    gpa.free(sets);
}

/// Floyd's sampling of `samples` distinct ranks below `total` (commonware
/// `sample_unique_indices`).
pub fn sample_unique(gpa: Allocator, rng: anytype, total: u128, samples: usize) ![]u128 {
    assert(samples <= total);
    const sampled = try gpa.alloc(u128, samples);
    errdefer gpa.free(sampled);
    var seen: std.AutoHashMapUnmanaged(u128, void) = .empty;
    defer seen.deinit(gpa);
    try seen.ensureTotalCapacity(gpa, @intCast(samples));
    for (sampled, 0..) |*sample, offset| {
        const index: u128 = total - samples + offset;
        const candidate = utils.rng.range_at_most(rng, u128, 0, index);
        if (seen.contains(candidate)) {
            assert(!seen.contains(index)); // Tail indices are unique.
            sample.* = index;
        } else {
            sample.* = candidate;
        }
        seen.putAssumeCapacity(sample.*, {});
    }
    return sampled;
}

/// Exact counts of scenario suffixes: `layers[r]` maps a cell state to the scenarios of
/// `r` more rounds from it.
const Counts = []std.AutoHashMapUnmanaged(u64, u128);

/// Enumerates and samples canonical scenarios for `n` participants, memoizing the
/// compressed transition DAG by cell state.
pub const Generator = struct {
    gpa: Allocator,
    n: u32,
    transitions: std.AutoHashMapUnmanaged(u64, TransitionSet) = .empty,
    /// Local refinements keyed by `2 * cell size + is_leader`.
    locals: std.AutoHashMapUnmanaged(u64, []LocalRefinement) = .empty,

    pub fn init(gpa: Allocator, n: u32) Generator {
        assert(n > 1 and n <= participants_max);
        return .{ .gpa = gpa, .n = n };
    }

    pub fn deinit(self: *Generator) void {
        var transitions = self.transitions.valueIterator();
        while (transitions.next()) |set| set.edges.deinit(self.gpa);
        self.transitions.deinit(self.gpa);
        var locals = self.locals.valueIterator();
        while (locals.next()) |refinements| self.gpa.free(refinements.*);
        self.locals.deinit(self.gpa);
        self.* = undefined;
    }

    /// Every canonical scenario of `rounds` rounds when at most `max_scenarios` exist,
    /// otherwise `max_scenarios` sampled without replacement. Panics when the count
    /// overflows `u128`.
    pub fn generate(self: *Generator, rng: anytype, rounds: u32, max_scenarios: u32) ![]Generated {
        assert(rounds > 0 and max_scenarios > 0);
        const counts = try self.count(rounds) orelse
            @panic("scenario space overflows u128; reduce rounds or participants");
        defer free_counts(self.gpa, counts);
        const total = counts[rounds].get(0).?;
        const ranks = if (total <= max_scenarios) blk: {
            const all = try self.gpa.alloc(u128, @intCast(total));
            for (all, 0..) |*rank, index| rank.* = index;
            break :blk all;
        } else try sample_unique(self.gpa, rng, total, max_scenarios);
        defer self.gpa.free(ranks);
        const generated = try self.gpa.alloc(Generated, ranks.len);
        var built: usize = 0;
        errdefer free_generated(self.gpa, generated[0..built]);
        for (generated, ranks) |*item, rank| {
            item.* = try self.scenario_from_rank(rounds, rank, counts);
            built += 1;
        }
        return generated;
    }

    /// Frees `counts` and reports the overflow.
    fn overflow(gpa: Allocator, counts: Counts) ?Counts {
        free_counts(gpa, counts);
        return null;
    }

    pub fn free_counts(gpa: Allocator, counts: Counts) void {
        for (counts) |*layer| layer.deinit(gpa);
        gpa.free(counts);
    }

    /// Exact suffix counts over the states reachable from the initial one, or null on
    /// overflow.
    pub fn count(self: *Generator, rounds: u32) !?Counts {
        const counts = try self.gpa.alloc(std.AutoHashMapUnmanaged(u64, u128), rounds + 1);
        for (counts) |*layer| layer.* = .empty;
        errdefer free_counts(self.gpa, counts);
        // Forward: the reachable states at each depth, kept as keys of `counts[rounds - d]`.
        try counts[rounds].put(self.gpa, 0, 0);
        for (0..rounds) |depth| {
            var states = counts[rounds - depth].keyIterator();
            while (states.next()) |state| {
                const set = try self.ensure_transitions(.{ .boundaries = state.* });
                if (set.overflowed) return overflow(self.gpa, counts);
                for (set.edges.items) |edge| {
                    try counts[rounds - depth - 1].put(self.gpa, edge.next.boundaries, 0);
                }
            }
        }
        // Backward: a state's count sums each edge's multiplicity times its suffix count.
        var last = counts[0].valueIterator();
        while (last.next()) |value| value.* = 1;
        for (1..rounds + 1) |remaining| {
            var states = counts[remaining].iterator();
            while (states.next()) |entry| {
                const set = self.transitions.getPtr(entry.key_ptr.*).?;
                var total: u128 = 0;
                for (set.edges.items) |edge| {
                    const suffix = counts[remaining - 1].get(edge.next.boundaries).?;
                    const product = @mulWithOverflow(edge.multiplicity, suffix);
                    if (product[1] != 0) return overflow(self.gpa, counts);
                    const sum = @addWithOverflow(total, product[0]);
                    if (sum[1] != 0) return overflow(self.gpa, counts);
                    total = sum[0];
                }
                entry.value_ptr.* = total;
            }
        }
        return counts;
    }

    /// Decodes scenario `rank` round by round: each edge's subtree holds `multiplicity *
    /// suffix` scenarios.
    fn scenario_from_rank(self: *Generator, rounds: u32, rank: u128, counts: Counts) !Generated {
        const scenario = try self.gpa.alloc(RoundScenario, rounds);
        errdefer self.gpa.free(scenario);
        var state: CellState = .{};
        var left = rank;
        for (scenario, 0..) |*round, depth| {
            const remaining = rounds - depth;
            const set = self.transitions.getPtr(state.boundaries).?;
            assert(!set.overflowed);
            const edge = for (set.edges.items) |edge| {
                const suffix = counts[remaining - 1].get(edge.next.boundaries).?;
                const subtree = edge.multiplicity * suffix;
                if (left < subtree) {
                    round.* = self.round_from_edge(state, edge, left / suffix);
                    left %= suffix;
                    break edge;
                }
                left -= subtree;
            } else @panic("canonical scenario rank out of bounds");
            state = edge.next;
        }
        return .{ .rounds = scenario, .cells = try state.to_cells(self.gpa, self.n) };
    }

    fn local_refinements(self: *Generator, size: u32, is_leader: bool) ![]const LocalRefinement {
        const key = @as(u64, size) * 2 + @intFromBool(is_leader);
        const entry = try self.locals.getOrPut(self.gpa, key);
        if (!entry.found_existing) {
            entry.value_ptr.* = build_local_refinements(self.gpa, size, is_leader) catch |err| {
                self.locals.removeByPtr(entry.key_ptr);
                return err;
            };
        }
        return entry.value_ptr.*;
    }

    /// The transitions out of `state`, built on first use.
    fn ensure_transitions(self: *Generator, state: CellState) !*const TransitionSet {
        if (self.transitions.getPtr(state.boundaries)) |set| return set;
        var buffer: [participants_max]Range = undefined;
        const cell_ranges = state.ranges(self.n, &buffer);
        var set: TransitionSet = .{};
        errdefer set.edges.deinit(self.gpa);
        var choices: [participants_max][]const LocalRefinement = undefined;
        for (0..cell_ranges.len) |leader_cell| {
            for (cell_ranges, 0..) |range, cell| {
                choices[cell] = try self.local_refinements(range.len, cell == leader_cell);
            }
            try self.combine(cell_ranges, choices[0..cell_ranges.len], leader_cell, &set);
        }
        try self.transitions.put(self.gpa, state.boundaries, set);
        return self.transitions.getPtr(state.boundaries).?;
    }

    /// commonware `build_transitions`: one edge per choice of a refinement in every cell,
    /// the last cell varying fastest.
    fn combine(
        self: *Generator,
        cell_ranges: []const Range,
        choices: []const []const LocalRefinement,
        leader_cell: usize,
        set: *TransitionSet,
    ) !void {
        assert(cell_ranges.len == choices.len);
        var indices: [participants_max]u32 = @splat(0);
        outer: while (true) {
            var multiplicity: u128 = 1;
            var next: CellState = .{};
            const chosen_indices = indices[0..choices.len];
            const overflowed = for (cell_ranges, choices, chosen_indices) |range, options, index| {
                const chosen = &options[index];
                const product = @mulWithOverflow(multiplicity, chosen.multiplicity);
                if (product[1] != 0) break true;
                multiplicity = product[0];
                next.add_local_boundaries(range.start, self.n, chosen.slice());
            } else false;
            if (overflowed) {
                set.overflowed = true;
            } else {
                const leader: u32 = @intCast(leader_cell);
                const edge: TransitionEdge = .{
                    .next = next,
                    .leader_cell = leader,
                    .multiplicity = multiplicity,
                };
                try set.edges.append(self.gpa, edge);
            }
            var cell = choices.len;
            while (cell > 0) {
                cell -= 1;
                indices[cell] += 1;
                if (indices[cell] < choices[cell].len) continue :outer;
                indices[cell] = 0;
            }
            return;
        }
    }

    /// Decodes `rank` as mixed-radix digits, one per cell in order, into a concrete round.
    fn round_from_edge(
        self: *Generator,
        state: CellState,
        edge: TransitionEdge,
        rank: u128,
    ) RoundScenario {
        var masks: [2]u64 = .{ 0, 0 };
        var leader: ?u32 = null;
        var left = rank;
        var buffer: [participants_max]Range = undefined;
        var parts_buffer: [participants_max]u32 = undefined;
        for (state.ranges(self.n, &buffer), 0..) |range, cell| {
            const parts = edge.next.parts_in_cell(range.start, range.len, &parts_buffer);
            if (cell != edge.leader_cell) {
                const space = role_subset_count(parts.len);
                const roles = roles_from_rank(parts.len, left % space);
                left /= space;
                apply_roles(range.start, parts, roles[0..parts.len], &masks);
                continue;
            }
            const others = parts.len - 1;
            const space = role_subset_count(others) * 3;
            const local = left % space;
            left /= space;
            const roles = roles_from_rank(others, local / 3);
            apply_roles(range.start, parts[0..others], roles[0..others], &masks);
            const index = range.start + range.len - 1;
            // The leader is primary-only, secondary-only, or in both halves.
            if (local % 3 != 1) masks[0] |= bit(index);
            if (local % 3 != 0) masks[1] |= bit(index);
            leader = index;
        }
        assert(left == 0); // The rank is fully consumed.
        return .{ .leader = leader.?, .primary_mask = masks[0], .secondary_mask = masks[1] };
    }
};
