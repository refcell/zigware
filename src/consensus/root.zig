//! consensus: Order opaque messages in a Byzantine environment.
//!
//! Zig port of commonware's `commonware-consensus` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/consensus). docs/lanes/
//! consensus-simplex.md tracks what is ported.

const std = @import("std");

pub const types = @import("types.zig");
pub const Epoch = types.Epoch;
pub const Height = types.Height;
pub const View = types.View;
pub const Round = types.Round;

pub const traits = @import("traits.zig");
pub const Handoff = traits.Handoff;
pub const Feedback = traits.Feedback;
pub const round = traits.round;
pub const reporter = @import("reporter.zig");
pub const Reporters = reporter.Reporters;
pub const simplex = @import("simplex/root.zig");
pub const aggregation = @import("aggregation/root.zig");
pub const marshal = @import("marshal/root.zig");

test {
    std.testing.refAllDecls(@This());
    // Until marshal/root.zig lands; then its `pub const coding` line runs these.
    _ = @import("marshal/coding/root.zig");
}
