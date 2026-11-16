//! The fmt subscriber against lines `tracing_subscriber::fmt()` prints for the same events.

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const fmt = @import("ui").fmt;

const traces = zigware.runtime.telemetry.traces;

/// 2026-11-13T16:27:51.676445Z
const now_us: u64 = 1_794_587_271_676_445;

fn expect_line(ansi: bool, event: *const traces.Event, expected: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try fmt.write_event(&writer, ansi, now_us, event);
    try testing.expectEqualStrings(expected, writer.buffered());
}

test "fmt prints tracing's full format" {
    const event: traces.Event = .{
        .level = .info,
        .target = "indexer",
        .message = "stored finalization",
        .fields = &.{ .{ .name = "network", .value = "a4a1" }, .{ .name = "view", .value = "3" } },
        .span = null,
    };
    try expect_line(false, &event, "2026-11-13T16:27:51.676445Z  INFO indexer: " ++
        "stored finalization network=a4a1 view=3\n");
    try expect_line(true, &event, "\x1b[2m2026-11-13T16:27:51.676445Z\x1b[0m " ++
        "\x1b[32m INFO\x1b[0m \x1b[2mindexer\x1b[0m\x1b[2m:\x1b[0m stored finalization " ++
        "\x1b[3mnetwork\x1b[0m\x1b[2m=\x1b[0ma4a1 \x1b[3mview\x1b[0m\x1b[2m=\x1b[0m3\n");
}

test "fmt prints spans from the root, levels padded and colored" {
    var collector: traces.Collector = .init(testing.allocator, .{});
    defer collector.deinit();
    const outer = collector.tracer("x").span("outer", .{ .a = 1 });
    const inner = outer.child("inner", .{});
    const event: traces.Event = .{
        .level = .debug,
        .target = "commonware_p2p::dialer",
        .message = "dialed \x1b[31m",
        .fields = &.{},
        .span = &inner,
    };
    try expect_line(false, &event, "2026-11-13T16:27:51.676445Z DEBUG outer{a=1}:inner: " ++
        "commonware_p2p::dialer: dialed \\x1b[31m\n");
    try expect_line(true, &event, "\x1b[2m2026-11-13T16:27:51.676445Z\x1b[0m " ++
        "\x1b[34mDEBUG\x1b[0m \x1b[1mouter\x1b[0m\x1b[1m{\x1b[0m\x1b[3ma\x1b[0m" ++
        "\x1b[2m=\x1b[0m1\x1b[1m}\x1b[0m\x1b[2m:\x1b[0m\x1b[1minner\x1b[0m\x1b[2m:\x1b[0m " ++
        "\x1b[2mcommonware_p2p::dialer\x1b[0m\x1b[2m:\x1b[0m dialed \\x1b[31m\n");
}

test "fmt pads every level to five columns" {
    const cases = [_]struct { traces.Level, []const u8 }{
        .{ .trace, "TRACE" }, .{ .warn, " WARN" }, .{ .@"error", "ERROR" },
    };
    for (cases) |case| {
        const event: traces.Event = .{
            .level = case[0],
            .target = "t",
            .message = "m",
            .fields = &.{},
            .span = null,
        };
        var buffer: [128]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try fmt.write_event(&writer, false, now_us, &event);
        try testing.expectEqualStrings(case[1], writer.buffered()[28..33]);
    }
}

test "fmt follows NO_COLOR as tracing does" {
    try testing.expect(fmt.ansi_enabled(null));
    try testing.expect(fmt.ansi_enabled(""));
    try testing.expect(!fmt.ansi_enabled("1"));
}
