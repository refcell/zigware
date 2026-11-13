//! The production runtime (commonware `runtime::tokio` and `runtime::iouring`): real time,
//! files on disk, and TCP, over any `std.Io` (`std.Io.Uring` on Linux, kqueue or
//! `std.Io.Threaded` elsewhere).

const std = @import("std");

pub const storage = @import("storage.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("storage_test.zig");
}
