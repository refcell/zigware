//! Twins scenario generator and executor helpers (commonware `simplex/mocks/twins.rs`),
//! after "Twins: BFT Systems Made Robust" (arXiv:2004.10617):
//! 1. generate primary and secondary recipient sets per round,
//! 2. combine them with a leader per round,
//! 3. arrange the rounds into multi-round scenarios, and
//! 4. run each scenario across compromised-node assignments.
//!
//! Unlike the paper's disjoint partitions, each half's recipients are an independent mask,
//! so a participant may be visible to both halves, one, or neither in a scripted round.
//! After the scripted prefix, traffic returns to all-to-all and election resumes through the
//! fallback elector. Participant sets are capped at 64 so sets fit in `u64` masks.
//!
//! Scenarios are generated in canonical unlabeled form. The generator tracks residual
//! symmetry cells (participants indistinguishable across the rounds so far) and counts
//! scenarios exactly over a compressed transition DAG whose edges carry multiplicities; a
//! rank decodes into a concrete round as mixed-radix digits in cell order. Campaigns larger
//! than the budget sample canonical scenarios uniformly without replacement, and each
//! scenario expands only into compromised assignments that differ up to symmetry.
//!
//! commonware's recursive helpers (compositions, the transition DFS, fault allocation) are
//! iterative here, enumerating in the same order. Randomness matches rand 0.10 for the same
//! generator (`range_at_most` and `runtime.rng.shuffle`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../../types.zig");
const generator_mod = @import("twins_generator.zig");

const View = consensus_types.View;
const Round = consensus_types.Round;
const Participant = consensus_types.Participant;
const TermLength = consensus_types.TermLength;

/// The most participants a scenario supports.
pub const participants_max = generator_mod.participants_max;

/// Which twin halves receive a message (p2p `simulated.SplitTarget`).
pub const SplitTarget = p2p.simulated.SplitTarget;

/// One round's adversarial setting: its leader and the participants each twin half
/// exchanges messages with (the masks may overlap).
pub const RoundScenario = generator_mod.RoundScenario;

/// Each half's recipients as participant-index masks.
pub const Masks = struct { primary: u64, secondary: u64 };

fn route_masks(masks: Masks, index: usize) SplitTarget {
    assert(index < participants_max);
    const bit = @as(u64, 1) << @intCast(index);
    const primary = masks.primary & bit != 0;
    const secondary = masks.secondary & bit != 0;
    if (primary and secondary) return .both;
    if (primary) return .primary;
    if (secondary) return .secondary;
    return .none;
}

/// A multi-round scenario. Owns its rounds.
pub const Scenario = struct {
    rounds: []RoundScenario,

    pub fn deinit(scenario: *Scenario, gpa: Allocator) void {
        gpa.free(scenario.rounds);
        scenario.* = undefined;
    }

    /// Each half's recipients at `view` among `n` participants: the scripted round of the
    /// term holding `view`, then everyone (eventual synchrony).
    pub fn masks(scenario: Scenario, view: View, term_length: TermLength, n: usize) Masks {
        assert(n > 0 and n <= participants_max);
        const index = term_index(view, term_length);
        if (index < scenario.rounds.len) {
            const round = scenario.rounds[index];
            return .{ .primary = round.primary_mask, .secondary = round.secondary_mask };
        }
        const all = generator_mod.mask_range(0, n);
        return .{ .primary = all, .secondary = all };
    }

    /// The twin half that receives a message from participant `sender` at `view`: both
    /// halves after the scripted rounds.
    pub fn route(
        scenario: Scenario,
        view: View,
        term_length: TermLength,
        sender: usize,
        n: usize,
    ) SplitTarget {
        assert(sender < n);
        const index = term_index(view, term_length);
        if (index >= scenario.rounds.len) return .both;
        return route_masks(scenario.masks(view, term_length, n), sender);
    }
};

/// The 0-based scripted round of `view`'s term (genesis shares round 0 with the first term).
pub fn term_index(view: View, term_length: TermLength) usize {
    return @intCast(view.term_index(term_length) -| 1);
}

/// The strict disjoint split of `n` participants at `term_start % n` for `view`'s term
/// (commonware `view_partitions`).
pub fn view_masks(view: View, term_length: TermLength, n: usize) Masks {
    assert(n > 0 and n <= participants_max);
    const split: usize = @intCast(view.term_start(term_length).get() % n);
    const masks: Masks = .{
        .primary = generator_mod.mask_range(0, split),
        .secondary = generator_mod.mask_range(split, n - split),
    };
    assert(masks.primary & masks.secondary == 0);
    return masks;
}

/// Routes participant `sender` by `view_masks` (commonware `view_route`).
pub fn view_route(view: View, term_length: TermLength, sender: usize, n: usize) SplitTarget {
    assert(sender < n);
    const target = route_masks(view_masks(view, term_length, n), sender);
    assert(target == .primary or target == .secondary);
    return target;
}

/// The participants selected by `mask`, in order (allocated from `gpa`).
pub fn partition(gpa: Allocator, comptime P: type, mask: u64, participants: []const P) ![]P {
    assert(participants.len <= participants_max);
    var group: std.ArrayList(P) = .empty;
    errdefer group.deinit(gpa);
    for (participants, 0..) |participant, index| {
        if (mask & (@as(u64, 1) << @intCast(index)) != 0) try group.append(gpa, participant);
    }
    return group.toOwnedSlice(gpa);
}

/// The index of `key` among `participants`, which must hold it.
pub fn index_of(comptime P: type, key: P, participants: []const P) usize {
    for (participants, 0..) |participant, index| {
        if (codec.order(P, participant, key) == .eq) return index;
    }
    @panic("sender missing from the participant list");
}

/// A built elector that follows a scenario's scripted leaders, one per term, then defers
/// to the built `fallback` elector `E` (commonware `ElectorState`). Owns `E`.
pub fn Elector(comptime E: type) type {
    return struct {
        const Self = @This();
        pub const mode = E.mode;
        pub const Input = E.Input;

        fallback: E,
        round_leaders: []Participant,

        /// Panics when a scenario leader is not among `participants`.
        pub fn init(gpa: Allocator, fallback: E, scenario: Scenario, participants: usize) !Self {
            const leaders = try gpa.alloc(Participant, scenario.rounds.len);
            for (leaders, scenario.rounds) |*leader, round| {
                if (round.leader >= participants) @panic("scenario leader out of bounds");
                leader.* = .init(round.leader);
            }
            return .{ .fallback = fallback, .round_leaders = leaders };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.round_leaders);
            if (@hasDecl(E, "deinit")) self.fallback.deinit(gpa);
            self.* = undefined;
        }

        pub fn terms(self: Self) @TypeOf(self.fallback.terms()) {
            return self.fallback.terms();
        }

        /// Scripted leaders never read `input`, so the fallback decides whether election
        /// needs a certificate.
        pub fn elect(self: Self, round: Round, input: Input) Participant {
            const index = term_index(round.view, self.fallback.terms().length);
            if (index < self.round_leaders.len) return self.round_leaders[index];
            // After the scripted prefix, resume the fallback (twins may still be elected).
            return self.fallback.elect(round, input);
        }
    };
}

/// How multi-round scenarios are built.
pub const Mode = enum {
    /// Each round chooses its own recipient sets and leader.
    sampled,
    /// One single-round pattern repeats across every round (a persistent split).
    sustained,
};

/// The parameters of a twins campaign.
pub const Framework = struct {
    /// At most 64.
    participants: u32,
    faults: u32,
    /// Adversarial rounds before the synchronous suffix.
    rounds: u32,
    mode: Mode,
    /// The most cases emitted, which also caps the canonical scenarios selected.
    max_cases: u32,
};

/// An executable case: compromised participant indices and a scenario. Owns both.
pub const Case = struct {
    compromised: []u32,
    scenario: Scenario,

    pub fn deinit(case: *Case, gpa: Allocator) void {
        gpa.free(case.compromised);
        case.scenario.deinit(gpa);
        case.* = undefined;
    }
};

pub fn free_cases(gpa: Allocator, cases_list: []Case) void {
    for (cases_list) |*case| case.deinit(gpa);
    gpa.free(cases_list);
}

/// Generates executable cases (commonware `cases`): every canonical scenario when they fit
/// in `max_cases`, otherwise a uniform sample without replacement, each expanded into its
/// symmetry-unique compromised assignments, then shuffled and truncated to `max_cases`.
/// Panics on an invalid framework or when the scenario count overflows `u128`.
pub fn cases(gpa: Allocator, rng: anytype, framework: Framework) ![]Case {
    if (framework.participants <= 1) @panic("participants must be > 1");
    if (framework.participants > participants_max) @panic("participants must be <= 64");
    if (framework.faults == 0) @panic("faults must be > 0");
    if (framework.faults >= framework.participants) {
        @panic("faults must be less than participants");
    }
    if (framework.rounds == 0) @panic("rounds must be > 0");
    if (framework.max_cases == 0) @panic("max_cases must be > 0");
    var generator: generator_mod.Generator = .init(gpa, framework.participants);
    defer generator.deinit();
    const generated_rounds = if (framework.mode == .sampled) framework.rounds else 1;
    const scenarios = try generator.generate(rng, generated_rounds, framework.max_cases);
    defer generator_mod.free_generated(gpa, scenarios);
    var result: std.ArrayList(Case) = .empty;
    errdefer {
        for (result.items) |*case| case.deinit(gpa);
        result.deinit(gpa);
    }
    for (scenarios) |generated| {
        const sets = try generator_mod.compromised_sets(gpa, generated.cells, framework.faults);
        defer generator_mod.free_sets(gpa, sets);
        for (sets) |compromised| {
            try result.ensureUnusedCapacity(gpa, 1);
            const rounds = try expand_rounds(gpa, generated.rounds, framework);
            errdefer gpa.free(rounds);
            const owned = try gpa.dupe(u32, compromised);
            const scenario: Scenario = .{ .rounds = rounds };
            result.appendAssumeCapacity(.{ .compromised = owned, .scenario = scenario });
        }
    }
    runtime.rng.shuffle(rng, Case, result.items);
    while (result.items.len > framework.max_cases) {
        var dropped = result.pop().?;
        dropped.deinit(gpa);
    }
    assert(result.items.len <= framework.max_cases);
    return result.toOwnedSlice(gpa);
}

/// The scenario's rounds, or its one round repeated in sustained mode.
fn expand_rounds(
    gpa: Allocator,
    rounds: []const RoundScenario,
    framework: Framework,
) ![]RoundScenario {
    if (framework.mode == .sampled) return gpa.dupe(RoundScenario, rounds);
    assert(rounds.len == 1);
    const repeated = try gpa.alloc(RoundScenario, framework.rounds);
    @memset(repeated, rounds[0]);
    return repeated;
}

test {
    _ = @import("twins_test.zig");
    _ = @import("twins_reference_test.zig");
}
