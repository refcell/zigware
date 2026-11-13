//! The OTLP status of a span (commonware `traces::status`).

const std = @import("std");
const traces = @import("mod.zig");
const assert = std.debug.assert;

/// A span's OTLP status.
pub const Status = union(enum) {
    unset,
    ok,
    /// The error description.
    @"error": []const u8,
};

/// Sets the span's status to `Ok`.
pub fn ok(span: *traces.Span) void {
    span.otel_status = .ok;
    assert(span.otel_status == .ok);
}

/// Sets the span's status to `Error` with `description`, recording `err` (when given) as the
/// span's `error` field. `description` must outlive the span.
pub fn @"error"(span: *traces.Span, description: []const u8, err: ?anyerror) void {
    if (err) |value| span.record("error", value);
    span.otel_status = .{ .@"error" = description };
    assert(span.otel_status == .@"error");
}

test "status sets the span status and error field" {
    var span = traces.Tracer.none.span("request", .{});
    try std.testing.expect(span.otel_status == .unset);
    ok(&span);
    try std.testing.expect(span.otel_status == .ok);
    @"error"(&span, "lookup failed", error.NotFound);
    try std.testing.expectEqualStrings("lookup failed", span.otel_status.@"error");
    try std.testing.expectEqualStrings("error", span.field_names[0]);
    try std.testing.expectEqualStrings("NotFound", span.field_value(0));
}
