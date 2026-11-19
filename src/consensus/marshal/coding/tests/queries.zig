//! The query, subscription, and recoverability scenarios on the coding variant (commonware
//! `coding/mod.rs`, `test_coding_*` over `harness::*::<CodingHarness>`), on the shared
//! scenarios (mocks/scenarios_queries.zig, mocks/scenarios_recoverable.zig) over
//! `CodingHarness`.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const queries = @import("../../mocks/scenarios_queries.zig");
const recoverable = @import("../../mocks/scenarios_recoverable.zig");
const harness = @import("../harness.zig");

const gpa = testing.allocator;
const H = harness.CodingHarness;

test "coding get info basic queries present and missing" {
    try queries.GetInfoBasic(H).run(gpa);
}

test "coding get info latest progression multiple finalizations" {
    try queries.GetInfoLatestProgression(H).run(gpa);
}

test "coding get block by height and latest" {
    try queries.GetBlockByHeightAndLatest(H).run(gpa);
}

test "coding get block by commitment from sources and missing" {
    try queries.GetBlockByCommitment(H).run(gpa);
}

test "coding get finalization by height" {
    try queries.GetFinalizationByHeight(H).run(gpa);
}

test "coding subscribe basic block delivery" {
    try queries.SubscribeBasic(H).run(gpa);
}

test "coding subscribe multiple subscriptions" {
    try queries.SubscribeMultiple(H).run(gpa);
}

test "coding subscribe canceled subscriptions" {
    try queries.SubscribeCanceled(H).run(gpa);
}

test "coding subscribe blocks from different sources" {
    try queries.SubscribeDifferentSources(H).run(gpa);
}

test "coding ancestry stream" {
    try queries.AncestryStream(H).run(gpa);
}

test "coding init processed height" {
    try queries.InitProcessedHeight(H).run(gpa);
}

test "coding broadcast caches block" {
    try queries.BroadcastCachesBlock(H).run(gpa);
}

test "coding finalize same height different views" {
    try queries.FinalizeSameHeightDifferentViews(H).run(gpa);
}

test "coding hint finalized triggers fetch" {
    try queries.HintFinalizedTriggersFetch(H).run(gpa);
}

test "coding genesis emitted once" {
    try queries.GenesisEmittedOnce(H).run(gpa);
}

test "coding commitment fetch height hint mismatch wakes subscriber" {
    try queries.CommitmentFetchHeightHintMismatch(H).run(gpa);
}

test "coding prune finalized archives" {
    try queries.PruneFinalizedArchives(H).run(gpa);
}

test "coding floor retains processed predecessor" {
    try queries.FloorRetainsProcessedPredecessor(H).run(gpa);
}

test "coding reject stale block delivery after floor update" {
    try queries.RejectStaleBlockDeliveryAfterFloorUpdate(H).run(gpa);
}

test "coding sync height floor" {
    try queries.SyncHeightFloor(H).run(gpa);
}

/// commonware's seeds 0..16 under `-Dslow-tests`; two otherwise, to keep Debug runs fast.
const contract_seeds: []const u64 = if (build_options.slow_tests)
    &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }
else
    &.{ 0, 1 };

test "coding proposed success implies recoverable after restart" {
    try recoverable.SuccessRecoverable(H, .proposed).run(gpa, contract_seeds);
}

test "coding verified success implies recoverable after restart" {
    try recoverable.SuccessRecoverable(H, .verified).run(gpa, contract_seeds);
}

test "coding certified success implies recoverable after restart" {
    try recoverable.SuccessRecoverable(H, .certified).run(gpa, contract_seeds);
}
