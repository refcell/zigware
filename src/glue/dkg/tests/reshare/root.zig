//! commonware `glue::dkg::tests::reshare` (mod.rs): reshare ceremonies end to end over many
//! epochs. Phase 1 runs the discovery network without state sync; see docs/lanes/glue.md.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const simulate = @import("../../../simulate/mod.zig");
const harness = @import("harness.zig");
const properties = @import("properties.zig");

const gpa = testing.allocator;
const S = harness.ValidatorState;

/// Runs a plan to `final_epoch`'s last block with commonware's successful-reshare properties
/// (`successful_reshare_plan`).
fn run_successful(engine: *harness.ReshareEngine, final_epoch: u64, seed: u64) !void {
    const exit: simulate.exit.ProcessedHeightAtLeast = .{
        .required = properties.final_height(final_epoch),
    };
    const signer: properties.SignerRegistered(S) = .{};
    var boundary = properties.BoundaryEpochInfos(S).init(gpa, final_epoch + 1);
    boundary.no_reveals = true;
    const continuity: properties.EpochInfoContinuity(S) = .{
        .gpa = gpa,
        .epochs = final_epoch + 1,
        .schedule = engine.schedule(),
    };
    const plan: harness.Plan = .{
        .engine = engine,
        .seed = seed,
        .link = harness.good_link,
        .crashes = &.{},
        .required_finalizations = 0,
        .exit_condition = .from(&exit),
        .timeout = .from_secs(60),
        .properties = &.{ .from(&signer), .from(&boundary), .from(&continuity) },
    };
    var result = try plan.run(gpa);
    result.deinit();
}

// commonware `reshare_e2e_single_participant_two_epochs`.
test "reshare e2e single participant two epochs" {
    var engine = try harness.ReshareEngine.with_committees(gpa, 1, &.{1}, 1);
    defer engine.deinit();
    try run_successful(&engine, 1, 0);
}

test {
    _ = build_options;
    _ = @import("properties_test.zig");
}
