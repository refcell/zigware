//! Runs a deterministic test body on every `-Dfuzz-soak` seed (`runtime.deterministic.soak`):
//! a plain `zig build test` runs it once on `config.seed`, a soak run on fresh seeds.

const std = @import("std");
const assert = std.debug.assert;
const deterministic = @import("runtime").deterministic;

/// `runner.start_context(body, args)` on a fresh runner per soak round.
pub fn run(
    gpa: std.mem.Allocator,
    config: deterministic.Config,
    comptime body: anytype,
    args: anytype,
) !void {
    comptime assert(@typeInfo(@TypeOf(body)) == .@"fn");
    const Args = @TypeOf(args);
    try deterministic.soak(gpa, config, args, struct {
        fn round(round_args: Args, runner: *deterministic.Runner) anyerror!void {
            try try runner.start_context(body, round_args);
        }
    }.round);
}

/// `runner.start(function, .{runner.io()})` on a fresh runner per soak round.
pub fn run_io(
    gpa: std.mem.Allocator,
    config: deterministic.Config,
    comptime function: fn (std.Io) anyerror!void,
) !void {
    try deterministic.soak(gpa, config, {}, struct {
        fn round(_: void, runner: *deterministic.Runner) anyerror!void {
            try (try runner.start(function, .{runner.io()}));
        }
    }.round);
}
