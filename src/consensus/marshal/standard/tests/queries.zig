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
