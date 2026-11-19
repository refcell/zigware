//! The I/O of glue stateful's actor, p2p, and probe tests: threaded (`std.testing.io`) except
//! while `run_on_deterministic` runs a test body on a deterministic runner. Test files and their
//! harnesses read `io` through this module instead of `std.testing.io`, so one switch moves a
//! test, and every helper it calls, onto simulated time.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const runtime = @import("runtime");

/// The I/O every switched test and harness uses.
pub var io: std.Io = std.testing.io;

/// Runs `body` with `io` on a deterministic runner, where sleeps are simulated and a lost
/// wakeup fails as `Stalled` or `Timeout` instead of hanging. Runs `fuzz_soak` runner seeds
/// from the runner's default (one, the default seed, in a plain `zig build test`), each mixed
/// with `-Dfuzz-seed`; a failure prints its seed and the `-Dfuzz-seed` that replays it alone.
pub fn run_on_deterministic(comptime body: fn () anyerror!void) !void {
    const default_seed = (runtime.deterministic.Config{}).seed;
    const seeds: u64 = build_options.fuzz_soak;
    assert(seeds > 0);
    for (0..seeds) |index| {
        const runner_seed = (default_seed + index) ^ build_options.fuzz_seed;
        run_on_seed(body, runner_seed) catch |err| {
            std.debug.print("deterministic runner seed={d} failed (replay: -Dfuzz-seed={d})\n", .{
                runner_seed, runner_seed ^ default_seed,
            });
            return err;
        };
    }
}

fn run_on_seed(comptime body: fn () anyerror!void, runner_seed: u64) !void {
    const config: runtime.deterministic.Config = .{
        .timeout_ns = 30 * std.time.ns_per_s,
        .seed = runner_seed,
    };
    var runner = try runtime.deterministic.Runner.init(std.testing.allocator, config);
    defer runner.deinit();
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
