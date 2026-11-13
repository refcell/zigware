//! Counters with a status label (commonware `metrics::status`).

const std = @import("std");
const raw = @import("raw.zig");
const registry = @import("registry.zig");
const scope_module = @import("scope.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Values of the status label.
pub const Status = enum {
    /// Processed successfully.
    success,
    /// Processing produced one of multiple valid results but did not satisfy the request.
    ambiguous,
    /// Processing failed.
    failure,
    /// Input was malformed or invalid in some way (a client error).
    invalid,
    /// Input was valid but intentionally not processed (rate limit, duplicate, ...).
    dropped,
    /// Processing returned no result before some deadline.
    timeout,

    /// The label value, commonware's variant name.
    pub fn label_value(status: Status) []const u8 {
        return switch (status) {
            .success => "Success",
            .ambiguous => "Ambiguous",
            .failure => "Failure",
            .invalid => "Invalid",
            .dropped => "Dropped",
            .timeout => "Timeout",
        };
    }
};

/// The status label set.
pub const Label = struct { status: Status };

/// The family backing a status `Counter`.
pub const Raw = raw.Family(Label, raw.Counter);

/// A registered counter with a status label.
pub const Counter = struct {
    registered: registry.Registered(Raw),

    pub fn register(
        scope: *const scope_module.Scope,
        name: []const u8,
        help: []const u8,
    ) Allocator.Error!Counter {
        return .{ .registered = try scope.family(Label, raw.Counter, name, help) };
    }

    pub fn clone(counter: Counter) Counter {
        return .{ .registered = counter.registered.clone() };
    }

    pub fn deinit(counter: *Counter) void {
        counter.registered.deinit();
        counter.* = undefined;
    }

    /// Increments the counter for `status`. Allocates only the first time a status is seen.
    pub fn inc(counter: Counter, status: Status) Allocator.Error!void {
        try counter.inc_by(status, 1);
    }

    pub fn inc_by(counter: Counter, status: Status, amount: u64) Allocator.Error!void {
        const entry = try counter.registered.metric().get_or_create(.{ .status = status });
        entry.inc_by(amount);
    }

    /// The count for `status` (0 before its first increment).
    pub fn get(counter: Counter, status: Status) u64 {
        const entry = counter.registered.metric().get(.{ .status = status }) orelse return 0;
        return entry.get();
    }

    /// A guard that increments the counter once on `finish` (commonware `CounterGuard`, which
    /// increments on drop): `var guard = counter.guard(.failure); defer guard.finish();`.
    pub fn guard(counter: Counter, status: Status) CounterGuard {
        return .{ .counter = counter.clone(), .status = status };
    }
};

pub const CounterGuard = struct {
    counter: Counter,
    status: Status,

    /// Changes the status the guard will increment.
    pub fn set(guard: *CounterGuard, status: Status) void {
        guard.status = status;
    }

    pub fn finish(guard: *CounterGuard) Allocator.Error!void {
        defer guard.counter.deinit();
        try guard.counter.inc(guard.status);
    }
};

const testing = std.testing;
const metrics = @import("mod.zig");

test "status counter encodes commonware's label values" {
    var registry_value: metrics.Registry = .init(testing.allocator);
    defer registry_value.deinit();
    const scope: metrics.Scope = .init(&registry_value);
    var counter = try Counter.register(&scope.child("handler"), "requests", "Requests by status");
    defer counter.deinit();
    try counter.inc(.success);
    try counter.inc_by(.timeout, 2);
    {
        var guard = counter.guard(.failure);
        guard.set(.invalid);
        try guard.finish();
    }
    try testing.expectEqual(@as(u64, 1), counter.get(.invalid));
    try testing.expectEqual(@as(u64, 0), counter.get(.dropped));
    const text = try scope.encode(testing.allocator);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        \\# HELP handler_requests Requests by status.
        \\# TYPE handler_requests counter
        \\handler_requests_total{status="Success"} 1
        \\handler_requests_total{status="Timeout"} 2
        \\handler_requests_total{status="Invalid"} 1
        \\# EOF
        \\
    , text);
}
