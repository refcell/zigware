//! commonware `simplex/mocks/twins.rs` tests: the canonical scenario space, case
//! generation, routing, and the scripted elector. (The brute-force reference enumerator
//! that cross-checks multi-round counts is not ported; the single-round space is checked
//! against its closed form.)

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const utils = @import("utils");
const consensus_types = @import("../../types.zig");
const elector_mod = @import("../elector.zig");
const twins = @import("twins.zig");
const generator_mod = @import("twins_generator.zig");

const gpa = testing.allocator;
const View = consensus_types.View;
const Round = consensus_types.Round;
const TermLength = consensus_types.TermLength;
const RoundScenario = twins.RoundScenario;
const Generator = generator_mod.Generator;

fn range_mask(start: usize, len: usize) u64 {
    return generator_mod.mask_range(start, len);
}

/// A round and its residual cells, as a hashable key.
const Transition = struct { round: RoundScenario, cells: [8]u32, cells_len: usize };

fn transition(round: RoundScenario, cells: []const u32) Transition {
    var key: Transition = .{ .round = round, .cells = @splat(0), .cells_len = cells.len };
    @memcpy(key.cells[0..cells.len], cells);
    return key;
}

/// commonware `expected_single_round_transitions`: the closed form of one round's space.
fn expected_single_round(n: u32, out: *std.AutoHashMapUnmanaged(Transition, void)) !void {
    for (0..n) |outside| {
        const both = n - outside - 1;
        const leader: u32 = @intCast(outside + both);
        const mask = range_mask(outside, both) | (@as(u64, 1) << @intCast(leader));
        var cells: [5]u32 = undefined;
        var len: usize = 0;
        for ([_]usize{ outside, both, 1 }) |size| if (size > 0) {
            cells[len] = @intCast(size);
            len += 1;
        };
        const round: RoundScenario = .{
            .leader = leader,
            .primary_mask = mask,
            .secondary_mask = mask,
        };
        try out.put(gpa, transition(round, cells[0..len]), {});
    }
    for (0..n) |outside| for (0..n - outside) |both| {
        const remaining = n - outside - 1 - both;
        for (0..remaining + 1) |secondary| {
            const primary = remaining - secondary;
            const leader: u32 = @intCast(outside + both + secondary + primary);
            const bit = @as(u64, 1) << @intCast(leader);
            const shared = range_mask(outside, both);
            const secondary_mask = shared | range_mask(outside + both, secondary);
            const primary_mask = shared | range_mask(outside + both + secondary, primary);
            var cells: [5]u32 = undefined;
            var len: usize = 0;
            for ([_]usize{ outside, both, secondary, primary, 1 }) |size| if (size > 0) {
                cells[len] = @intCast(size);
                len += 1;
            };
            const placements = [_][2]u64{ .{ bit, 0 }, .{ 0, bit }, .{ bit, bit } };
            for (placements) |placement| {
                const round: RoundScenario = .{
                    .leader = leader,
                    .primary_mask = primary_mask | placement[0],
                    .secondary_mask = secondary_mask | placement[1],
                };
                try out.put(gpa, transition(round, cells[0..len]), {});
            }
        }
    };
}

test "generated single-round scenarios match the expected canonical space" {
    for (3..6) |n| {
        var expected: std.AutoHashMapUnmanaged(Transition, void) = .empty;
        defer expected.deinit(gpa);
        try expected_single_round(@intCast(n), &expected);
        var generator: Generator = .init(gpa, @intCast(n));
        defer generator.deinit();
        var rng = utils.rng.test_rng();
        const generated = try generator.generate(&rng, 1, std.math.maxInt(u32));
        defer generator_mod.free_generated(gpa, generated);
        // The generated set equals the expected one (commonware compares `HashSet`s).
        var distinct: std.AutoHashMapUnmanaged(Transition, void) = .empty;
        defer distinct.deinit(gpa);
        for (generated) |item| {
            const key = transition(item.rounds[0], item.cells);
            try testing.expect(expected.contains(key));
            try distinct.put(gpa, key, {});
        }
        try testing.expectEqual(expected.count(), distinct.count());
    }
}

test "every enumerated scenario is distinct and leaders are visible" {
    // commonware's unranking test sizes: the space grows quickly with rounds.
    const sizes = [_][2]u32{ .{ 2, 1 }, .{ 3, 1 }, .{ 4, 1 }, .{ 5, 1 }, .{ 2, 3 }, .{ 3, 2 } };
    for (sizes) |size| {
        const n = size[0];
        const rounds = size[1];
        var generator: Generator = .init(gpa, n);
        defer generator.deinit();
        var rng = utils.rng.test_rng();
        const generated = try generator.generate(&rng, rounds, std.math.maxInt(u32));
        defer generator_mod.free_generated(gpa, generated);
        var seen: std.AutoHashMapUnmanaged([3]RoundScenario, void) = .empty;
        defer seen.deinit(gpa);
        for (generated) |item| {
            const empty: RoundScenario = .{ .leader = 0, .primary_mask = 0, .secondary_mask = 0 };
            var key: [3]RoundScenario = @splat(empty);
            @memcpy(key[0..rounds], item.rounds);
            try testing.expect(!(try seen.getOrPut(gpa, key)).found_existing);
            for (item.rounds) |round| {
                const bit = @as(u64, 1) << @intCast(round.leader);
                try testing.expect((round.primary_mask | round.secondary_mask) & bit != 0);
            }
        }
    }
}

test "cell states round-trip cell partitions" {
    const cases = [_][]const u32{
        &.{5},            &.{ 1, 4 },    &.{ 2, 1, 2 },
        &.{ 1, 1, 1, 1 }, &.{ 3, 2, 1 },
    };
    for (cases) |cells| {
        var n: usize = 0;
        for (cells) |size| n += size;
        const state = generator_mod.CellState.from_cells(cells);
        const round_tripped = try state.to_cells(gpa, n);
        defer gpa.free(round_tripped);
        try testing.expectEqualSlices(u32, cells, round_tripped);
    }
}

test "the canonical scenario count reports overflow" {
    var generator: Generator = .init(gpa, 4);
    defer generator.deinit();
    try testing.expectEqual(null, try generator.count(40));
}

fn expect_sets(cells: []const u32, faults: u32, expected: []const []const u32) !void {
    const sets = try generator_mod.compromised_sets(gpa, cells, faults);
    defer generator_mod.free_sets(gpa, sets);
    try testing.expectEqual(expected.len, sets.len);
    for (expected, sets) |want, got| try testing.expectEqualSlices(u32, want, got);
}

test "compromised sets collapse symmetry cells" {
    try expect_sets(&.{3}, 1, &.{&.{0}});
    try expect_sets(&.{ 2, 1 }, 1, &.{ &.{2}, &.{0} });
    try expect_sets(&.{ 1, 1, 1 }, 1, &.{ &.{2}, &.{1}, &.{0} });
}

test "compromised sets spread several faults across cells" {
    try expect_sets(&.{ 3, 2 }, 2, &.{ &.{ 3, 4 }, &.{ 0, 3 }, &.{ 0, 1 } });
}

test "unique index sampling handles near-full ranges" {
    var rng = utils.rng.TestRng.init(9);
    const sampled = try generator_mod.sample_unique(gpa, &rng, 100_000, 99_999);
    defer gpa.free(sampled);
    var seen: std.AutoHashMapUnmanaged(u128, void) = .empty;
    defer seen.deinit(gpa);
    for (sampled) |index| {
        try testing.expect(index < 100_000);
        try testing.expect(!(try seen.getOrPut(gpa, index)).found_existing);
    }
    try testing.expectEqual(99_999, seen.count());
}

fn generate(framework: twins.Framework) ![]twins.Case {
    var rng = utils.rng.test_rng();
    return twins.cases(gpa, &rng, framework);
}

test "generated cases are deterministic" {
    const framework: twins.Framework = .{
        .participants = 5,
        .faults = 1,
        .rounds = 3,
        .mode = .sampled,
        .max_cases = 50,
    };
    const first = try generate(framework);
    defer twins.free_cases(gpa, first);
    const second = try generate(framework);
    defer twins.free_cases(gpa, second);
    try testing.expectEqual(first.len, second.len);
    for (first, second) |a, b| {
        try testing.expectEqualSlices(u32, a.compromised, b.compromised);
        try testing.expectEqualSlices(RoundScenario, a.scenario.rounds, b.scenario.rounds);
    }
}

test "sampled cases are unique" {
    const framework: twins.Framework = .{
        .participants = 7,
        .faults = 2,
        .rounds = 3,
        .mode = .sampled,
        .max_cases = 64,
    };
    const generated = try generate(framework);
    defer twins.free_cases(gpa, generated);
    try testing.expectEqual(64, generated.len);
    const Key = struct { rounds: [3]RoundScenario, compromised: [2]u32 };
    var seen: std.AutoHashMapUnmanaged(Key, void) = .empty;
    defer seen.deinit(gpa);
    for (generated) |case| {
        const key: Key = .{
            .rounds = case.scenario.rounds[0..3].*,
            .compromised = case.compromised[0..2].*,
        };
        try testing.expect(!(try seen.getOrPut(gpa, key)).found_existing);
    }
}

test "sustained cases repeat a single round" {
    const framework: twins.Framework = .{
        .participants = 5,
        .faults = 1,
        .rounds = 3,
        .mode = .sustained,
        .max_cases = 50,
    };
    const generated = try generate(framework);
    defer twins.free_cases(gpa, generated);
    try testing.expect(generated.len > 0);
    for (generated) |case| {
        try testing.expectEqual(3, case.scenario.rounds.len);
        for (case.scenario.rounds[1..]) |round| {
            try testing.expectEqual(case.scenario.rounds[0], round);
        }
    }
}

test "pruned scenarios vary across round positions" {
    var generator: Generator = .init(gpa, 5);
    defer generator.deinit();
    var rng = utils.rng.test_rng();
    const generated = try generator.generate(&rng, 3, 32);
    defer generator_mod.free_generated(gpa, generated);
    for (0..3) |position| {
        const first = generated[0].rounds[position];
        const varies = for (generated[1..]) |item| {
            if (!std.meta.eql(item.rounds[position], first)) break true;
        } else false;
        try testing.expect(varies);
    }
}

test "routes select each half, then both after the scripted rounds" {
    var rounds = [_]RoundScenario{
        .{ .leader = 3, .primary_mask = 0b1011, .secondary_mask = 0b0110 },
    };
    const scenario: twins.Scenario = .{ .rounds = &rounds };
    const one: TermLength = .one;
    try testing.expectEqual(.primary, scenario.route(.new(1), one, 0, 4));
    try testing.expectEqual(.both, scenario.route(.new(1), one, 1, 4));
    try testing.expectEqual(.secondary, scenario.route(.new(1), one, 2, 4));
    try testing.expectEqual(.primary, scenario.route(.new(1), one, 3, 4));
    try testing.expectEqual(.both, scenario.route(.new(2), one, 2, 4));
    const keys = [_]u32{ 0, 1, 2, 3 };
    const masks = scenario.masks(.new(1), one, 4);
    const primary = try twins.partition(gpa, u32, masks.primary, &keys);
    defer gpa.free(primary);
    try testing.expectEqualSlices(u32, &.{ 0, 1, 3 }, primary);
    const secondary = try twins.partition(gpa, u32, masks.secondary, &keys);
    defer gpa.free(secondary);
    try testing.expectEqualSlices(u32, &.{ 1, 2 }, secondary);
    var none = [_]RoundScenario{.{ .leader = 0, .primary_mask = 0b01, .secondary_mask = 0b01 }};
    const isolated: twins.Scenario = .{ .rounds = &none };
    try testing.expectEqual(.none, isolated.route(.new(1), one, 1, 3));
}

test "view helpers split at the term start modulo n" {
    const one: TermLength = .one;
    for (1..9) |view| {
        const split = view % 4;
        for (0..4) |sender| {
            const expected: twins.SplitTarget = if (sender < split) .primary else .secondary;
            try testing.expectEqual(expected, twins.view_route(.new(view), one, sender, 4));
        }
    }
}

const RoundRobin = elector_mod.RoundRobin(cryptography.Sha256);

test "the twins elector follows scripted leaders, then the fallback" {
    const framework: twins.Framework = .{
        .participants = 5,
        .faults = 1,
        .rounds = 3,
        .mode = .sampled,
        .max_cases = 1,
    };
    const generated = try generate(framework);
    defer twins.free_cases(gpa, generated);
    const scenario = generated[0].scenario;
    const fallback = try RoundRobin.default().build(gpa, 5);
    var elector = try twins.Elector(elector_mod.RoundRobinElector).init(gpa, fallback, scenario, 5);
    defer elector.deinit(gpa);
    var reference = try RoundRobin.default().build(gpa, 5);
    defer reference.deinit(gpa);
    for (scenario.rounds, 1..) |round, view| {
        const leader = elector.elect(.new(.new(0), .new(view)), {});
        try testing.expectEqual(round.leader, leader.get());
    }
    for (framework.rounds + 1..21) |view| {
        const round: Round = .new(.new(333), .new(view));
        try testing.expectEqual(reference.elect(round, {}), elector.elect(round, {}));
    }
}

test "the twins elector scripts one leader per term" {
    var rounds = [_]RoundScenario{
        .{ .leader = 0, .primary_mask = 0b001, .secondary_mask = 0b010 },
        .{ .leader = 2, .primary_mask = 0b100, .secondary_mask = 0b011 },
    };
    const term_length: TermLength = .new(utils.NonZero(u32).init(3).?);
    const config = RoundRobin.default().with_term(term_length, .from_secs(10), .new(0));
    const fallback = try config.build(gpa, 3);
    const Twins = twins.Elector(elector_mod.RoundRobinElector);
    var elector = try Twins.init(gpa, fallback, .{ .rounds = &rounds }, 3);
    defer elector.deinit(gpa);
    var reference = try config.build(gpa, 3);
    defer reference.deinit(gpa);
    for (1..7) |view| {
        const expected: u32 = if (view < 4) 0 else 2;
        try testing.expectEqual(expected, elector.elect(.new(.new(0), .new(view)), {}).get());
    }
    const round: Round = .new(.new(333), .new(7));
    try testing.expectEqual(reference.elect(round, {}), elector.elect(round, {}));
}
