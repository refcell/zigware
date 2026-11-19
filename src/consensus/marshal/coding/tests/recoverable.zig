//! The durability contracts on the coding variant (commonware `coding/mod.rs`, the
//! delivery-visibility, equivocated-certify, same-round re-verify, and later-view pruning
//! wrappers in lines 1355-1485), on `mocks/scenarios_recoverable.zig` over `CodingHarness`.
//! The proposed/verified/certified success wrappers run with the query scenarios.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const recoverable = @import("../../mocks/scenarios_recoverable.zig");
const harness = @import("../harness.zig");

const gpa = testing.allocator;
const H = harness.CodingHarness;

/// commonware's seeds 0..16 under `-Dslow-tests`; two otherwise, to keep Debug runs fast.
const contract_seeds: []const u64 = if (build_options.slow_tests)
    &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }
else
    &.{ 0, 1 };

test "coding delivery visibility implies recoverable after restart" {
    try recoverable.DeliveryVisibilityRecoverable(H).run(gpa, contract_seeds);
}

test "coding certify persists equivocated block" {
    try recoverable.CertifyPersistsEquivocated(H).run(gpa);
}

test "coding verified after restart reverify same round implies recoverable" {
    try recoverable.ReverifySameRound(H, .verified).run(gpa);
}

test "coding certify after restart reverify same round implies recoverable" {
    try recoverable.ReverifySameRound(H, .certified).run(gpa);
}

test "coding certify at later view survives earlier view pruning" {
    try recoverable.LaterViewSurvivesPruning(H).run(gpa);
}
