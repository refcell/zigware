//! The simplex engine fuzz targets (commonware `simplex_ed25519`, `simplex_secp256r1`,
//! `simplex_bls12381_multisig_{minpk,minsig}`, and `simplex_bls12381_threshold_{minpk,minsig}`,
//! over `consensus/fuzz/src/lib.rs` `fuzz::<P, Standard>`), and commonware's
//! `simplex.rs` connected tests.

const std = @import("std");
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

/// One fuzz input against target `T` (commonware `fuzz::<P, Standard>`).
pub fn Body(comptime T: type) type {
    return struct {
        pub fn body(_: void, u: *minifuzz.Unstructured) anyerror!void {
            const input = try Input.draw(u);
            try harness.run(T, testing.allocator, input);
        }
    };
}

fn seeded(comptime T: type) !void {
    const quick = builtin.mode == .debug and !build_options.slow_tests;
    if (is_slow(T) and quick and build_options.fuzz_soak == 1) return error.SkipZigTest;
    const builder = (minifuzz.Builder{}).with_search_limit(search_limit * build_options.fuzz_soak);
    try builder.run(testing.allocator, {}, Body(T).body);
}

fn coverage_guided(comptime T: type) !void {
    try testing.fuzz({}, math.testing.smith_body(void, Body(T).body), .{});
}

/// commonware's `test_*_connected` (1000 views there; 10 here, 3 for BLS12-381 in Debug).
fn connected(comptime T: type) !void {
    const views: u64 = if (is_bls(T) and builtin.mode == .debug) 3 else 10;
    try harness.run(T, testing.allocator, test_input(0, views, 1));
}

test "simplex_ed25519: connected" {
    try connected(targets.Ed25519);
}

test "simplex_ed25519: stable leader connected" {
    // Multi-view terms with a small optimistic budget take the stable-leader path.
    var input = test_input(0, 10, 5);
    input.optimistic_views = 2;
    try harness.run(targets.Ed25519, testing.allocator, input);
}

test "simplex_ed25519 fuzz target (minifuzz)" {
    try seeded(targets.Ed25519);
}

test "simplex_ed25519 fuzz target (std fuzz)" {
    try coverage_guided(targets.Ed25519);
}

test "simplex_secp256r1: connected" {
    try connected(targets.Secp256r1);
}

test "simplex_secp256r1 fuzz target (minifuzz)" {
    try seeded(targets.Secp256r1);
}

test "simplex_secp256r1 fuzz target (std fuzz)" {
    try coverage_guided(targets.Secp256r1);
}

test "simplex_bls12381_multisig_minpk: connected" {
    try connected(targets.Multisig(MinPk));
}

test "simplex_bls12381_multisig_minpk fuzz target (minifuzz)" {
    try seeded(targets.Multisig(MinPk));
}

test "simplex_bls12381_multisig_minpk fuzz target (std fuzz)" {
    try coverage_guided(targets.Multisig(MinPk));
}

test "simplex_bls12381_multisig_minsig: connected" {
    try connected(targets.Multisig(MinSig));
}

test "simplex_bls12381_multisig_minsig fuzz target (minifuzz)" {
    try seeded(targets.Multisig(MinSig));
}

test "simplex_bls12381_multisig_minsig fuzz target (std fuzz)" {
    try coverage_guided(targets.Multisig(MinSig));
}

test "simplex_bls12381_threshold_minpk: connected" {
    try connected(targets.Threshold(MinPk));
}

test "simplex_bls12381_threshold_minpk fuzz target (minifuzz)" {
    try seeded(targets.Threshold(MinPk));
}

test "simplex_bls12381_threshold_minpk fuzz target (std fuzz)" {
    try coverage_guided(targets.Threshold(MinPk));
}

test "simplex_bls12381_threshold_minsig: connected" {
    try connected(targets.Threshold(MinSig));
}

test "simplex_bls12381_threshold_minsig fuzz target (minifuzz)" {
    try seeded(targets.Threshold(MinSig));
}

test "simplex_bls12381_threshold_minsig fuzz target (std fuzz)" {
    try coverage_guided(targets.Threshold(MinSig));
}
