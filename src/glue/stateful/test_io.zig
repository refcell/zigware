//! The I/O of glue stateful's actor, p2p, and probe tests: threaded (`std.testing.io`) except
//! while `run_on_deterministic` runs a test body on a deterministic runner. Test files and their
//! harnesses read `io` through this module instead of `std.testing.io`, so one switch moves a
//! test, and every helper it calls, onto simulated time.

const std = @import("std");
const assert = std.debug.assert;
const runtime = @import("runtime");

/// The I/O every switched test and harness uses.
pub var io: std.Io = std.testing.io;

/// Runs `body` with `io` on a deterministic runner, where sleeps are simulated and a lost
/// wakeup fails as `Stalled` or `Timeout` instead of hanging. `runtime.deterministic.soak`
/// runs it on `-Dfuzz-soak` runner seeds (one, the default seed, in a plain `zig build test`)
/// and prints the `-Dfuzz-seed` that replays a failing one.
pub fn run_on_deterministic(comptime body: fn () anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };
    try runtime.deterministic.soak(std.testing.allocator, config, {}, struct {
        fn run(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            assert(io.userdata == std.testing.io.userdata); // Runs do not nest.
            defer io = std.testing.io;
            io = runner.io();
            try try runner.start(struct {
                fn run(_: std.Io) anyerror!void {
                    try body();
                }
            }.run, .{runner.io()});
            assert(io.userdata == runner.io().userdata);
        }
    }.run);
}
