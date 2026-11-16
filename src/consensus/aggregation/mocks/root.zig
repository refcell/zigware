//! Mocks for aggregation tests (commonware `aggregation/mocks`).

const std = @import("std");

pub const application = @import("application.zig");
pub const Application = application.Application;
pub const Strategy = application.Strategy;
pub const monitor = @import("monitor.zig");
pub const Monitor = monitor.Monitor;
pub const provider = @import("provider.zig");
pub const Provider = provider.Provider;
pub const reporter = @import("reporter.zig");
pub const Reporter = reporter.Reporter;
pub const ReporterMailbox = reporter.Mailbox;
pub const scheme = @import("scheme.zig");

test {
    std.testing.refAllDecls(@This());
}
