//! Metric handles that publish one writer's updates to a shared metric in batches (commonware
//! `metrics::batched`).
//!
//! A `Batched` handle keeps the writer's total and adds the total's change since the previous
//! publication to the shared metric after every `size` updates and on `deinit`. The shared
//! metric includes each update made before the writer's latest publication exactly once, and
//! none made after it. Writers that update one shared metric directly contend on its cache line
//! with every update; a handle per writer limits that to one shared update per batch.

const std = @import("std");
const raw = @import("raw.zig");
const registry = @import("registry.zig");
const assert = std.debug.assert;

/// A batched writer for a `raw.Counter` or `raw.Gauge`.
pub fn Batched(comptime M: type) type {
    comptime assert(M == raw.Counter or M == raw.Gauge);
    return struct {
        const Self = @This();
        /// The metric's value type, which also represents a change between two values.
        pub const Value = if (M == raw.Counter) u64 else i64;

        /// The shared metric's storage. The handle holds a reference to it but not its
        /// registration: the metric leaves the registry when its last `Registered` handle goes,
        /// and this writer does not publish to a fresh metric registered under the same name.
        box: *registry.Box(M),
        /// The writer's total.
        value: Value = 0,
        /// The writer's total at creation or at the latest publication.
        published: Value = 0,
        /// Updates since the latest publication.
        pending: u32 = 0,
        /// Updates per batch.
        size: u32,

        /// A handle that publishes to `shared`'s metric after every `size` updates. Every
        /// update counts toward a batch, including one that leaves the total unchanged.
        pub fn init(shared: registry.Registered(M), size: u32) Self {
            assert(size > 0);
            shared.box.retain();
            return .{ .box = shared.box, .size = size };
        }

        /// Publishes the unpublished change and releases the metric.
        pub fn deinit(batched: *Self) void {
            batched.publish();
            batched.box.release();
            batched.* = undefined;
        }

        /// The writer's total, including updates not yet published.
        pub fn get(batched: *const Self) Value {
            return batched.value;
        }

        pub fn inc(batched: *Self) void {
            batched.update(batched.value +% 1);
        }

        pub fn inc_by(batched: *Self, amount: Value) void {
            batched.update(batched.value +% amount);
        }

        pub fn dec(batched: *Self) void {
            comptime assert(M == raw.Gauge);
            batched.update(batched.value -% 1);
        }

        pub fn dec_by(batched: *Self, amount: Value) void {
            comptime assert(M == raw.Gauge);
            batched.update(batched.value -% amount);
        }

        pub fn set(batched: *Self, value: Value) void {
            comptime assert(M == raw.Gauge);
            batched.update(value);
        }

        fn publish(batched: *Self) void {
            if (batched.value != batched.published) {
                // Wrapping change, applied with the metric's wrapping add.
                const change = batched.value -% batched.published;
                batched.box.metric.inc_by(change);
                batched.published = batched.value;
            }
            batched.pending = 0;
        }

        fn update(batched: *Self, value: Value) void {
            assert(batched.pending < batched.size);
            batched.value = value;
            batched.pending += 1;
            if (batched.pending == batched.size) batched.publish();
            assert(batched.pending < batched.size);
        }
    };
}

const testing = std.testing;
const gpa = testing.allocator;
const metrics = @import("mod.zig");

test "counter publishes full batches" {
    var shared = try metrics.Counter.detached(gpa, .{});
    defer shared.deinit();
    var batched: Batched(raw.Counter) = .init(shared, 3);
    batched.inc();
    batched.inc();
    try testing.expectEqual(@as(u64, 0), shared.metric().get());
    try testing.expectEqual(@as(u64, 2), batched.get());
    batched.inc();
    try testing.expectEqual(@as(u64, 3), shared.metric().get());
    batched.inc();
    batched.inc();
    try testing.expectEqual(@as(u64, 3), shared.metric().get());
    batched.inc();
    try testing.expectEqual(@as(u64, 6), shared.metric().get());
    // Releasing the handle publishes a partial batch.
    batched.inc_by(5);
    try testing.expectEqual(@as(u64, 6), shared.metric().get());
    try testing.expectEqual(@as(u64, 11), batched.get());
    batched.deinit();
    try testing.expectEqual(@as(u64, 11), shared.metric().get());
}

test "gauge publishes the net change" {
    var shared = try metrics.Gauge.detached(gpa, .{});
    defer shared.deinit();
    var batched: Batched(raw.Gauge) = .init(shared, 2);
    defer batched.deinit();
    // Updates that cancel out publish nothing when their batch fills.
    batched.inc();
    batched.dec();
    try testing.expectEqual(@as(i64, 0), shared.metric().get());
    // A net decrease publishes a negative change.
    batched.dec_by(3);
    batched.inc();
    try testing.expectEqual(@as(i64, -2), shared.metric().get());
    // The second `set(5)` leaves the total unchanged but still completes the batch.
    batched.set(5);
    batched.set(5);
    try testing.expectEqual(@as(i64, 5), shared.metric().get());
}

test "handles publish independently" {
    var shared = try metrics.Gauge.detached(gpa, .{});
    defer shared.deinit();
    var first: Batched(raw.Gauge) = .init(shared, 1);
    defer first.deinit();
    first.inc_by(3);
    try testing.expectEqual(@as(i64, 3), shared.metric().get());
    // A handle created after another writer published adds only its own updates.
    var second: Batched(raw.Gauge) = .init(shared, 1);
    defer second.deinit();
    second.inc_by(4);
    try testing.expectEqual(@as(i64, 4), second.get());
    try testing.expectEqual(@as(i64, 7), shared.metric().get());
    var third: Batched(raw.Gauge) = .init(shared, 2);
    third.inc();
    try testing.expectEqual(@as(i64, 7), shared.metric().get());
    third.deinit();
    try testing.expectEqual(@as(i64, 8), shared.metric().get());
}

test "registration stays with the owner" {
    var registry_value: metrics.Registry = .init(gpa);
    defer registry_value.deinit();
    const scope: metrics.Scope = .init(&registry_value);
    var shared = try scope.gauge("keys", "Number of keys");
    var batched: Batched(raw.Gauge) = .init(shared, 1);
    defer batched.deinit();
    batched.inc_by(5);
    const before = try scope.encode(gpa);
    defer gpa.free(before);
    try testing.expect(metrics.has_metric_value(before, "keys", 5));
    // Releasing the owner's handle unregisters the metric even though the batched handle
    // still publishes to it; a metric registered again under the name is a new one.
    shared.deinit();
    const after = try scope.encode(gpa);
    defer gpa.free(after);
    var samples = metrics.metric_samples(after, "keys");
    try testing.expect(samples.next() == null);
    var fresh = try scope.gauge("keys", "Number of keys");
    defer fresh.deinit();
    batched.inc();
    try testing.expectEqual(@as(i64, 0), fresh.metric().get());
    try testing.expectEqual(@as(i64, 6), batched.get());
}
