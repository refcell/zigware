//! commonware's `#[should_panic]` tests of the runtime's `deterministic.rs`, `lib.rs`,
//! `telemetry/metrics/mod.rs`, and `storage/header.rs`, as death tests (`utils.death`): each
//! body must abort the process with commonware's message (or zigware's assert).
//!
//! The `lib.rs` panics run on the deterministic runner. zigware has no `catch_panics`: a panic in
//! any task aborts the process, which is the outcome these tests check.

const std = @import("std");
const death = @import("utils").death;
const deterministic = @import("deterministic.zig");
const telemetry = @import("telemetry/mod.zig");
const header = @import("storage/header.zig");

const Context = deterministic.Context;
const assert_message = "reached unreachable code";

/// Runs `body(ctx)` as the root of a default deterministic runner.
fn run_root(comptime body: fn (Context) anyerror!void) !void {
    var runner = try deterministic.Runner.init(std.testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start_context(body, .{}));
}

/// Passes when a root running `body` panics with a message containing `expected`.
fn expect_root_panic(
    comptime src: std.builtin.SourceLocation,
    expected: []const u8,
    comptime body: fn (Context) anyerror!void,
) !void {
    try death.expect_panic(src, expected, struct {
        fn run() !void {
            try run_root(body);
        }
    }.run);
}

test "a timeout with a zero cycle is rejected (test_bad_timeout)" {
    try death.expect_panic(@src(), assert_message, struct {
        fn body() !void {
            var runner = try deterministic.Runner.init(std.testing.allocator, .{
                .timeout_ns = 1,
                .cycle_ns = 0,
            });
            runner.deinit();
        }
    }.body);
}

test "an empty child label panics (test_metrics_label_empty)" {
    try expect_root_panic(@src(), "label must match", struct {
        fn body(ctx: Context) !void {
            _ = ctx.child("");
        }
    }.body);
}

test "a child label starting with a digit panics (test_metrics_label_invalid_first_char)" {
    try expect_root_panic(@src(), "label must match", struct {
        fn body(ctx: Context) !void {
            _ = ctx.child("1invalid");
        }
    }.body);
}

test "a child label with a dash panics (test_metrics_label_invalid_char)" {
    try expect_root_panic(@src(), "label must match", struct {
        fn body(ctx: Context) !void {
            _ = ctx.child("invalid-label");
        }
    }.body);
}

test "the reserved runtime label panics (test_metrics_label_reserved_prefix)" {
    try expect_root_panic(@src(), "using runtime label is not allowed", struct {
        fn body(ctx: Context) !void {
            _ = ctx.child(telemetry.metrics.metrics_prefix);
        }
    }.body);
}

fn panic_blah(ctx: Context) anyerror!void {
    _ = ctx;
    @panic("blah");
}

fn sleep_forever(ctx: Context) !void {
    // Bounded: the spawned task's panic ends the process first.
    for (0..1_000_000) |_| try ctx.sleep(.fromMilliseconds(100));
}

test "a panic in a spawned task aborts the run (test_panic_aborts_spawn)" {
    try expect_root_panic(@src(), "blah", struct {
        fn body(ctx: Context) !void {
            _ = try ctx.child("panic").spawn(panic_blah, .{});
            try sleep_forever(ctx);
        }
    }.body);
}

test "the first of several task panics aborts the run (test_multiple_panics)" {
    try expect_root_panic(@src(), "boom", struct {
        fn boom(ctx: Context, index: u32) anyerror!void {
            _ = ctx;
            std.debug.panic("boom {d}", .{index});
        }

        fn body(ctx: Context) !void {
            for (1..4) |index| {
                _ = try ctx.child("panic").spawn(boom, .{@as(u32, @intCast(index))});
            }
            try sleep_forever(ctx);
        }
    }.body);
}

test "a panic in a dedicated task aborts the run (test_spawn_blocking_panic)" {
    try expect_root_panic(@src(), "blocking task panicked", struct {
        fn panicking(ctx: Context) anyerror!void {
            _ = ctx;
            @panic("blocking task panicked");
        }

        fn body(ctx: Context) !void {
            _ = try ctx.child("blocking").dedicated().spawn(panicking, .{});
            try sleep_forever(ctx);
        }
    }.body);
}

test "a duplicate metric of another type panics (test_duplicate_metrics_different_type_panics)" {
    try expect_root_panic(@src(), "registered with different type", struct {
        fn body(ctx: Context) !void {
            const raw = telemetry.metrics.raw;
            var counter = try ctx.child("a").register("test", "help", raw.Counter{});
            defer counter.deinit();
            var gauge = try ctx.child("a").register("test", "help", raw.Gauge{});
            defer gauge.deinit();
        }
    }.body);
}

test "a header over no blob versions panics (test_header_create_empty_versions)" {
    try death.expect_panic(@src(), assert_message, struct {
        fn body() !void {
            var region: [header.region_max]u8 = undefined;
            _ = header.create(.all, .{ .min = 1, .max = 0 }, &region);
        }
    }.body);
}
