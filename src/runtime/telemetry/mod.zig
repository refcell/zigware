//! Telemetry (commonware `runtime::telemetry`): metrics and traces.

const std = @import("std");

pub const metrics = @import("metrics/mod.zig");

test {
    std.testing.refAllDecls(@This());
}
