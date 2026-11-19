//! The simplex engine fuzz targets (commonware `simplex_ed25519`, `simplex_secp256r1`,
//! `simplex_bls12381_multisig_{minpk,minsig}`, and `simplex_bls12381_threshold_{minpk,minsig}`,
//! over `consensus/fuzz/src/lib.rs` `fuzz::<P, Standard>`), and commonware's
//! `simplex.rs` connected tests.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const testing = std.testing;
const build_options = @import("build_options");
const cryptography = @import("cryptography");
const math = @import("math");
const minifuzz = @import("invariants").minifuzz;
const fuzz_types = @import("types.zig");
const harness = @import("harness.zig");

const Input = harness.Input;
const targets = harness.targets;
const MinPk = cryptography.bls12381.primitives.MinPk;
const MinSig = cryptography.bls12381.primitives.MinSig;

/// commonware's `test_input`: a connected 4-node network with one disrupter (any scope).
pub fn test_input(seed: u64, containers: u64, term_length: u32) Input {
    return .{
        .seed = seed,
        .required_containers = containers,
        .term_length = .{ .length = term_length },
        .optimistic_views = term_length,
        .heterogeneous_optimism = true,
        .handoff = .wait,
        .degraded_network = false,
        .configuration = fuzz_types.n4f1c3,
        .partition = .connected,
        .strategy = .any_scope,
    };
}

/// Cases in each target's seeded fuzz, before `-Dfuzz-soak`. In Debug a run to view 10
/// takes about 1 s with ed25519, 4 s with secp256r1, and 10 s with BLS12-381, and a fuzzed
/// run needs up to 50 views; so in Debug only ed25519 runs its seeded fuzz by default, and
/// the others need `-Dslow-tests` or a soak (their seeded connected tests always run).
const search_limit = 2;

fn is_slow(comptime T: type) bool {
    return T != targets.Ed25519;
}

fn is_bls(comptime T: type) bool {
    return T != targets.Ed25519 and T != targets.Secp256r1;
}

/// One fuzz input against target `T` (commonware `fuzz::<P, Standard>` or
/// `fuzz::<P, Twinable>`).
pub fn Body(comptime T: type, comptime mode: harness.Mode) type {
    return struct {
        pub fn body(_: void, u: *minifuzz.Unstructured) anyerror!void {
            const input = try Input.draw(u);
            try harness.run(T, mode, testing.allocator, input);
        }
    };
}

fn seeded(comptime T: type, comptime mode: harness.Mode) !void {
    const quick = builtin.mode == .debug and !build_options.slow_tests;
    if (is_slow(T) and quick and build_options.fuzz_soak == 1) return error.SkipZigTest;
    // A twin run costs about four standard ones.
    const cases: u64 = if (mode == .twin) 1 else search_limit;
    const builder = (minifuzz.Builder{}).with_search_limit(cases * build_options.fuzz_soak);
    try builder.run(testing.allocator, {}, Body(T, mode).body);
}

/// Outside `--fuzz`, `std.testing.fuzz` runs the body once on an empty input, which is a
/// full run; Debug skips that for the slow schemes, whose connected tests cover the case.
fn coverage_guided(comptime T: type, comptime mode: harness.Mode) !void {
    const debug = builtin.mode == .debug and !build_options.slow_tests;
    if (!builtin.fuzz and debug and is_slow(T)) return error.SkipZigTest;
    try testing.fuzz({}, math.testing.smith_body(void, Body(T, mode).body), .{});
}

/// commonware's `test_*_connected` (1000 views there; 10 here, 3 for BLS12-381 in Debug).
/// A twin's disrupter signs every 100 ms of simulated time and honest validators verify each
/// vote, so in Debug a twin run of a scheme other than ed25519 costs 5 to 30 s even to view
/// 1; those run in ReleaseSafe (as CI does) or with `-Dslow-tests`.
fn connected(comptime T: type, comptime mode: harness.Mode) !void {
    const debug = builtin.mode == .debug and !build_options.slow_tests;
    if (debug and mode == .twin and is_slow(T)) return error.SkipZigTest;
    const views: u64 = if (debug and is_bls(T)) 3 else 10;
    try harness.run(T, mode, testing.allocator, test_input(0, views, 1));
}

test "simplex_ed25519: connected" {
    try connected(targets.Ed25519, .standard);
}

test "simplex_ed25519: stable leader connected" {
    // Multi-view terms with a small optimistic budget take the stable-leader path.
    var input = test_input(0, 10, 5);
    input.optimistic_views = 2;
    try harness.run(targets.Ed25519, .standard, testing.allocator, input);
}

test "simplex_ed25519 fuzz target (minifuzz)" {
    try seeded(targets.Ed25519, .standard);
}

test "simplex_ed25519 fuzz target (std fuzz)" {
    try coverage_guided(targets.Ed25519, .standard);
}

test "simplex_secp256r1: connected" {
    try connected(targets.Secp256r1, .standard);
}

test "simplex_secp256r1 fuzz target (minifuzz)" {
    try seeded(targets.Secp256r1, .standard);
}

test "simplex_secp256r1 fuzz target (std fuzz)" {
    try coverage_guided(targets.Secp256r1, .standard);
}

test "simplex_bls12381_multisig_minpk: connected" {
    try connected(targets.Multisig(MinPk), .standard);
}

test "simplex_bls12381_multisig_minpk fuzz target (minifuzz)" {
    try seeded(targets.Multisig(MinPk), .standard);
}

test "simplex_bls12381_multisig_minpk fuzz target (std fuzz)" {
    try coverage_guided(targets.Multisig(MinPk), .standard);
}

test "simplex_bls12381_multisig_minsig: connected" {
    try connected(targets.Multisig(MinSig), .standard);
}

test "simplex_bls12381_multisig_minsig fuzz target (minifuzz)" {
    try seeded(targets.Multisig(MinSig), .standard);
}

test "simplex_bls12381_multisig_minsig fuzz target (std fuzz)" {
    try coverage_guided(targets.Multisig(MinSig), .standard);
}

test "simplex_bls12381_threshold_minpk: connected" {
    try connected(targets.Threshold(MinPk), .standard);
}

test "simplex_bls12381_threshold_minpk fuzz target (minifuzz)" {
    try seeded(targets.Threshold(MinPk), .standard);
}

test "simplex_bls12381_threshold_minpk fuzz target (std fuzz)" {
    try coverage_guided(targets.Threshold(MinPk), .standard);
}

test "simplex_bls12381_threshold_minsig: connected" {
    try connected(targets.Threshold(MinSig), .standard);
}

test "simplex_bls12381_threshold_minsig fuzz target (minifuzz)" {
    try seeded(targets.Threshold(MinSig), .standard);
}

test "simplex_bls12381_threshold_minsig fuzz target (std fuzz)" {
    try coverage_guided(targets.Threshold(MinSig), .standard);
}

// The `_twin` targets: each Byzantine validator is a twin (an honest engine and a disrupter
// sharing its identity across a per-view network split).

test "simplex_ed25519_twin: connected" {
    try connected(targets.Ed25519, .twin);
}

test "simplex_ed25519_twin fuzz target (minifuzz)" {
    try seeded(targets.Ed25519, .twin);
}

test "simplex_ed25519_twin fuzz target (std fuzz)" {
    try coverage_guided(targets.Ed25519, .twin);
}

test "simplex_secp256r1_twin: connected" {
    try connected(targets.Secp256r1, .twin);
}

test "simplex_secp256r1_twin fuzz target (minifuzz)" {
    try seeded(targets.Secp256r1, .twin);
}

test "simplex_secp256r1_twin fuzz target (std fuzz)" {
    try coverage_guided(targets.Secp256r1, .twin);
}

test "simplex_bls12381_multisig_minpk_twin: connected" {
    try connected(targets.Multisig(MinPk), .twin);
}

test "simplex_bls12381_multisig_minpk_twin fuzz target (minifuzz)" {
    try seeded(targets.Multisig(MinPk), .twin);
}

test "simplex_bls12381_multisig_minpk_twin fuzz target (std fuzz)" {
    try coverage_guided(targets.Multisig(MinPk), .twin);
}

test "simplex_bls12381_multisig_minsig_twin: connected" {
    try connected(targets.Multisig(MinSig), .twin);
}

test "simplex_bls12381_multisig_minsig_twin fuzz target (minifuzz)" {
    try seeded(targets.Multisig(MinSig), .twin);
}

test "simplex_bls12381_multisig_minsig_twin fuzz target (std fuzz)" {
    try coverage_guided(targets.Multisig(MinSig), .twin);
}

test "simplex_bls12381_threshold_minpk_twin: connected" {
    try connected(targets.Threshold(MinPk), .twin);
}

test "simplex_bls12381_threshold_minpk_twin fuzz target (minifuzz)" {
    try seeded(targets.Threshold(MinPk), .twin);
}

test "simplex_bls12381_threshold_minpk_twin fuzz target (std fuzz)" {
    try coverage_guided(targets.Threshold(MinPk), .twin);
}

test "simplex_bls12381_threshold_minsig_twin: connected" {
    try connected(targets.Threshold(MinSig), .twin);
}

test "simplex_bls12381_threshold_minsig_twin fuzz target (minifuzz)" {
    try seeded(targets.Threshold(MinSig), .twin);
}

test "simplex_bls12381_threshold_minsig_twin fuzz target (std fuzz)" {
    try coverage_guided(targets.Threshold(MinSig), .twin);
}

// commonware `consensus/src/fuzz.rs` and `fuzz/simplex/connected.rs` (883eae27e): a generated
// `Plan` whose one scenario runs a connected `ConnectedPlan` on one `Scheme`, drawn in
// commonware's `Arbitrary` order.

/// commonware `fuzz::simplex::Scheme`, in its declaration order (the derived draw scales a
/// u32 into it).
pub const Scheme = enum {
    ed25519,
    secp256r1,
    multisig_min_pk,
    multisig_min_sig,
    threshold_min_pk,
    threshold_min_sig,

    /// Runs `input` against this scheme's target (commonware `Scheme::run`).
    pub fn run(self: Scheme, comptime mode: harness.Mode, input: Input) !void {
        assert(input.required_containers > 0);
        assert(input.term_length.length > 0);
        const gpa = testing.allocator;
        return switch (self) {
            .ed25519 => harness.run(targets.Ed25519, mode, gpa, input),
            .secp256r1 => harness.run(targets.Secp256r1, mode, gpa, input),
            .multisig_min_pk => harness.run(targets.Multisig(MinPk), mode, gpa, input),
            .multisig_min_sig => harness.run(targets.Multisig(MinSig), mode, gpa, input),
            .threshold_min_pk => harness.run(targets.Threshold(MinPk), mode, gpa, input),
            .threshold_min_sig => harness.run(targets.Threshold(MinSig), mode, gpa, input),
        };
    }
};

const Handoff = @TypeOf(harness.handoff_decisions[0]);

/// commonware `ConnectedPlan`: a seed, a boundary term length, and a handoff decision.
pub const ConnectedPlan = struct {
    seed: u64,
    term_length: u32,
    handoff: Handoff,

    /// commonware `TERM_LENGTH_BOUNDARIES`: single-view and multi-view terms.
    pub const term_length_boundaries = [_]u32{ 1, 5 };
    /// Containers each plan finalizes (commonware `CONTAINERS`).
    pub const containers = 30;

    /// commonware's hand-written `Arbitrary`: the term length, the handoff, then an 8-byte
    /// big-endian seed.
    pub fn arbitrary(u: *minifuzz.Unstructured) minifuzz.Error!ConnectedPlan {
        const term_length = try u.choose(u32, &term_length_boundaries);
        const handoff = try u.choose(Handoff, &harness.handoff_decisions);
        const seed = std.mem.readInt(u64, (try u.bytes(8))[0..8], .big);
        assert(term_length == 1 or term_length == 5);
        return .{ .seed = seed, .term_length = term_length, .handoff = handoff };
    }

    /// commonware `ConnectedPlan::run`: `connected_input` with the plan's handoff.
    pub fn run(self: ConnectedPlan, scheme: Scheme) !void {
        assert(self.term_length == 1 or self.term_length == 5);
        var input = test_input(self.seed, containers, self.term_length);
        input.handoff = self.handoff;
        assert(input.optimistic_views == self.term_length);
        try scheme.run(.standard, input);
    }
};

/// commonware `fuzz::Plan`: a generated scenario. Its only one is `Connected`.
pub const Plan = union(enum) {
    connected: struct { scheme: Scheme, plan: ConnectedPlan },

    /// The derived `Arbitrary` of `Plan(Scenario)`: the scenario's u32 tag (drawn even with one
    /// variant), then the variant's fields in order.
    pub fn arbitrary(u: *minifuzz.Unstructured) minifuzz.Error!Plan {
        const tag: u64 = try u.arbitrary(u32);
        assert((tag * 1) >> 32 == 0); // One variant: every tag selects `Connected`.
        const scheme = try u.arbitrary(Scheme);
        const plan = try u.arbitrary(ConnectedPlan);
        return .{ .connected = .{ .scheme = scheme, .plan = plan } };
    }

    /// Runs the scenario and checks its invariants (commonware `Plan::run`).
    pub fn run(self: Plan) !void {
        switch (self) {
            .connected => |connected_plan| try connected_plan.plan.run(connected_plan.scheme),
        }
    }
};

fn skip_unless_slow() error{SkipZigTest}!void {
    if (!build_options.slow_tests) return error.SkipZigTest;
}

fn plan_body(_: void, u: *minifuzz.Unstructured) anyerror!void {
    const plan = try u.arbitrary(Plan);
    try plan.run();
}

fn connected_plan_body(scheme: Scheme, u: *minifuzz.Unstructured) anyerror!void {
    const plan = try u.arbitrary(ConnectedPlan);
    try plan.run(scheme);
}

/// commonware's `minifuzz_connected`: 100 connected plans on `scheme`.
fn minifuzz_connected(scheme: Scheme) !void {
    try skip_unless_slow();
    const builder = (minifuzz.Builder{}).with_search_limit(100 * build_options.fuzz_soak);
    try builder.run(testing.allocator, scheme, connected_plan_body);
}

test "fuzz plan: draws commonware's order and runs an ed25519 connected plan" {
    // Scenario tag, scheme 0 (ed25519), term index 1 (5), handoff index 2 (vote), seed 7.
    const input = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 7 };
    var u: minifuzz.Unstructured = .init(&input);
    const plan = try Plan.arbitrary(&u);
    const connected_plan = plan.connected;
    try testing.expectEqual(Scheme.ed25519, connected_plan.scheme);
    try testing.expectEqual(@as(u32, 5), connected_plan.plan.term_length);
    try testing.expectEqual(Handoff.vote, connected_plan.plan.handoff);
    try testing.expectEqual(@as(u64, 7), connected_plan.plan.seed);
    // A plan needs its whole seed.
    var short: minifuzz.Unstructured = .init(input[0..17]);
    try testing.expectError(error.NotEnoughData, Plan.arbitrary(&short));
    try plan.run();
}

// commonware test_fuzz_plan
test "fuzz plan (minifuzz)" {
    try skip_unless_slow();
    const builder = (minifuzz.Builder{}).with_search_limit(8 * build_options.fuzz_soak);
    try builder.run(testing.allocator, {}, plan_body);
}

// commonware test_connected_boundaries
test "fuzz plan: connected boundaries" {
    try skip_unless_slow();
    for (std.enums.values(Scheme)) |scheme| {
        // The historical failure at both term lengths.
        for (ConnectedPlan.term_length_boundaries) |term_length| {
            const seed: u64 = 11_990_182_099_415_019_554;
            const plan: ConnectedPlan =
                .{ .seed = seed, .term_length = term_length, .handoff = .wait };
            try plan.run(scheme);
        }
        // Its shrunk seed (eight zero bytes) at every term length and handoff.
        for (ConnectedPlan.term_length_boundaries) |term_length| {
            for (harness.handoff_decisions) |handoff| {
                const plan: ConnectedPlan =
                    .{ .seed = 0, .term_length = term_length, .handoff = handoff };
                try plan.run(scheme);
            }
        }
    }
}

test "simplex_ed25519: minifuzz connected" {
    try minifuzz_connected(.ed25519);
}

test "simplex_secp256r1: minifuzz connected" {
    try minifuzz_connected(.secp256r1);
}

test "simplex_bls12381_multisig_minpk: minifuzz connected" {
    try minifuzz_connected(.multisig_min_pk);
}

test "simplex_bls12381_multisig_minsig: minifuzz connected" {
    try minifuzz_connected(.multisig_min_sig);
}

test "simplex_bls12381_threshold_minpk: minifuzz connected" {
    try minifuzz_connected(.threshold_min_pk);
}

test "simplex_bls12381_threshold_minsig: minifuzz connected" {
    try minifuzz_connected(.threshold_min_sig);
}
