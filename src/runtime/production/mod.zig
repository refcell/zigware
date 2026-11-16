//! The production runtime (commonware `runtime::tokio` and `runtime::iouring`): real time,
//! files on disk, and TCP. Storage and network run over any `std.Io`; the `Runner` owns a
//! `std.Io.Threaded`, since `std.Io.Uring` does not compile in Zig 0.17.1.

const std = @import("std");

pub const storage = @import("storage.zig");
pub const network = @import("network.zig");
pub const ring = @import("ring.zig");
pub const telemetry = @import("telemetry.zig");
pub const resolver = @import("resolver.zig");
pub const runner = @import("runner.zig");
pub const Runner = runner.Runner;
pub const Config = runner.Config;

test {
    std.testing.refAllDecls(@This());
    _ = @import("storage_test.zig");
    _ = @import("network_test.zig");
    _ = @import("runner_test.zig");
}
