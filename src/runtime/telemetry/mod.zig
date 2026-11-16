//! Telemetry (commonware `runtime::telemetry`): metrics and traces.

const std = @import("std");

pub const metrics = @import("metrics/mod.zig");
pub const traces = @import("traces/mod.zig");

test {
    std.testing.refAllDecls(@This());
}

const deterministic = @import("../deterministic.zig");

test "runner metrics (test_metrics on the deterministic runtime)" {
    var runner = try deterministic.Runner.init(std.testing.allocator, .{});
    defer runner.deinit();
    const Root = struct {
        fn run(io: std.Io, scope: *const metrics.Scope) !void {
            var counter = try scope.register("test", "test", metrics.raw.Counter{});
            defer counter.deinit();
            counter.metric().inc();
            var nested = try scope.child("nested").register("test", "test", metrics.raw.Counter{});
            defer nested.deinit();
            try io.sleep(.fromMilliseconds(1), .awake);
            nested.metric().inc();
            const text = try scope.encode(std.testing.allocator);
            defer std.testing.allocator.free(text);
            try std.testing.expect(metrics.has_metric_value(text, "test_total", 1));
            try std.testing.expect(std.mem.indexOf(u8, text, "nested_test_total 1") != null);
        }
    };
    const scope = runner.metrics();
    try std.testing.expectEqualStrings("", scope.prefix());
    try (try runner.start(Root.run, .{ runner.io(), &scope }));
    // Metrics released by the root are gone and the runtime's own remain; the registry carries
    // over to the next start.
    const text = try scope.encode(std.testing.allocator);
    defer std.testing.allocator.free(text);
    const expected = try std.fmt.allocPrint(std.testing.allocator,
        \\# HELP runtime_iterations Total number of iterations.
        \\# TYPE runtime_iterations counter
        \\runtime_iterations_total {d}
        \\# EOF
        \\
    , .{runner.iterations});
    defer std.testing.allocator.free(expected);
    try std.testing.expect(runner.iterations > 0);
    try std.testing.expectEqualStrings(expected, text);
}
