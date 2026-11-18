//! The reshare actor (commonware `glue::dkg::reshare::actor`): a per-epoch driver for the
//! reshare ceremony. Ported so far: the actor core (setup and follower mode) and setup's and
//! inclusion's helpers.

const actor = @import("actor.zig");
pub const Actor = actor.Actor;
pub const Config = actor.Config;
pub const ContractError = actor.ContractError;
pub const Flow = actor.Flow;
pub const assert_types = actor.assert_types;
pub const artifact = @import("artifact.zig");
pub const dealing = @import("dealing.zig");
pub const inclusion = @import("inclusion.zig");
pub const inclusion_window = @import("inclusion_window.zig");
pub const setup = @import("setup.zig");
pub const run = @import("run.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("dealing_test.zig");
    _ = @import("artifact_test.zig");
    _ = @import("inclusion_window_test.zig");
    _ = @import("run_test.zig");
}
