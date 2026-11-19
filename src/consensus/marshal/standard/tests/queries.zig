//! The query and subscription scenarios on the standard variant (commonware `standard/mod.rs`
//! lines 563-631 and 2544-2591). commonware runs each on `InlineHarness` and
//! `DeferredHarness`, which only delegate to `StandardHarness`; here each runs once on it.

const std = @import("std");
const testing = std.testing;
const harness = @import("../../mocks/harness.zig");
const queries = @import("../../mocks/scenarios_queries.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;

test "standard get info basic queries present and missing" {
    try queries.GetInfoBasic(H).run(gpa);
}

test "standard get info latest progression multiple finalizations" {
    try queries.GetInfoLatestProgression(H).run(gpa);
}

test "standard get block by height and latest" {
    try queries.GetBlockByHeightAndLatest(H).run(gpa);
}

test "standard get block by commitment from sources and missing" {
    try queries.GetBlockByCommitment(H).run(gpa);
}

test "standard get finalization by height" {
    try queries.GetFinalizationByHeight(H).run(gpa);
}

test "standard subscribe basic block delivery" {
    try queries.SubscribeBasic(H).run(gpa);
}

test "standard subscribe multiple subscriptions" {
    try queries.SubscribeMultiple(H).run(gpa);
}

test "standard subscribe canceled subscriptions" {
    try queries.SubscribeCanceled(H).run(gpa);
}

test "standard subscribe blocks from different sources" {
    try queries.SubscribeDifferentSources(H).run(gpa);
}

test "standard ancestry stream" {
    try queries.AncestryStream(H).run(gpa);
}

test "standard init processed height" {
    try queries.InitProcessedHeight(H).run(gpa);
}

test "standard broadcast caches block" {
    try queries.BroadcastCachesBlock(H).run(gpa);
}

test "standard finalize same height different views" {
    try queries.FinalizeSameHeightDifferentViews(H).run(gpa);
}

test "standard hint finalized triggers fetch" {
    try queries.HintFinalizedTriggersFetch(H).run(gpa);
}

test "standard genesis emitted once" {
    try queries.GenesisEmittedOnce(H).run(gpa);
}

test "standard commitment fetch height hint mismatch wakes subscriber" {
    try queries.CommitmentFetchHeightHintMismatch(H).run(gpa);
}

test "standard prune finalized archives" {
    try queries.PruneFinalizedArchives(H).run(gpa);
}

test "standard floor retains processed predecessor" {
    try queries.FloorRetainsProcessedPredecessor(H).run(gpa);
}

test "standard reject stale block delivery after floor update" {
    try queries.RejectStaleBlockDeliveryAfterFloorUpdate(H).run(gpa);
}

test "standard sync height floor" {
    try queries.SyncHeightFloor(H).run(gpa);
}
