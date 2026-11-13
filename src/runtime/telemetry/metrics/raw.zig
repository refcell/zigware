//! The metric types (commonware re-exports prometheus-client's as `metrics::raw`): `Counter`,
//! `Gauge`, `Histogram`, and `Family`. Recording never allocates: counters and gauges are one
//! atomic, a histogram is a fixed array behind a spin lock, and a family entry allocates only
//! the first time its label set is seen.
//!
//! A metric type declares `pub const metric_type: MetricType` and
//! `pub fn encode_samples(*Self, SampleEncoder) Writer.Error!void`, and may declare
//! `is_empty(*Self) bool` (a family with no entries writes no descriptor) and `deinit(*Self)`.

const std = @import("std");
const encoding = @import("encoding.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const MetricType = encoding.MetricType;
const SampleEncoder = encoding.SampleEncoder;

/// A lock for short critical sections that never block or yield. On the deterministic runtime a
/// fiber runs a critical section to its end before any other fiber runs, so it never spins; in
/// production it guards a few loads and stores. `std.Io.Mutex` would need an `Io` on every
/// record and handle release.
pub const SpinLock = struct {
    state: std.atomic.Mutex = .unlocked,

    pub fn lock(spin: *SpinLock) void {
        while (!spin.state.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn unlock(spin: *SpinLock) void {
        spin.state.unlock();
    }
};

/// A monotonically increasing `u64` (wrapping on overflow, like Rust's `AtomicU64::fetch_add`).
pub const Counter = struct {
    value: std.atomic.Value(u64) = .init(0),

    pub const metric_type: MetricType = .counter;

    pub fn inc(counter: *Counter) void {
        _ = counter.value.fetchAdd(1, .monotonic);
    }

    pub fn inc_by(counter: *Counter, amount: u64) void {
        _ = counter.value.fetchAdd(amount, .monotonic);
    }

    pub fn get(counter: *const Counter) u64 {
        return counter.value.load(.monotonic);
    }

    pub fn encode_samples(counter: *Counter, encoder: SampleEncoder) Writer.Error!void {
        try encoder.counter(counter.get());
    }
};

/// A signed `i64` that goes up and down (commonware's `GaugeValue` on 64-bit targets).
pub const Gauge = struct {
    value: std.atomic.Value(i64) = .init(0),

    pub const metric_type: MetricType = .gauge;

    pub fn inc(gauge: *Gauge) void {
        _ = gauge.value.fetchAdd(1, .monotonic);
    }

    pub fn dec(gauge: *Gauge) void {
        _ = gauge.value.fetchSub(1, .monotonic);
    }

    pub fn inc_by(gauge: *Gauge, amount: i64) void {
        _ = gauge.value.fetchAdd(amount, .monotonic);
    }

    pub fn dec_by(gauge: *Gauge, amount: i64) void {
        _ = gauge.value.fetchSub(amount, .monotonic);
    }

    /// Sets the gauge and returns its previous value.
    pub fn set(gauge: *Gauge, value: i64) i64 {
        return gauge.value.swap(value, .monotonic);
    }

    pub fn get(gauge: *const Gauge) i64 {
        return gauge.value.load(.monotonic);
    }

    /// Sets the gauge from any integer that converts losslessly (`GaugeExt::try_set`).
    pub fn try_set(gauge: *Gauge, value: anytype) error{Overflow}!i64 {
        const converted = std.math.cast(i64, value) orelse return error.Overflow;
        return gauge.set(converted);
    }

    /// Raises the gauge to at least `value` and returns its previous value (`try_set_max`).
    pub fn try_set_max(gauge: *Gauge, value: anytype) error{Overflow}!i64 {
        const converted = std.math.cast(i64, value) orelse return error.Overflow;
        return gauge.value.fetchMax(converted, .monotonic);
    }

    pub fn encode_samples(gauge: *Gauge, encoder: SampleEncoder) Writer.Error!void {
        try encoder.gauge(gauge.get());
    }
};

/// Most buckets a histogram holds, including the implicit `+Inf` bucket. Commonware's largest
/// layout (`Buckets.CRYPTOGRAPHY`) has 16.
pub const bucket_count_max = 32;

/// A classic Prometheus histogram with fixed bucket bounds, stored inline.
pub const Histogram = struct {
    lock: SpinLock = .{},
    /// Upper bounds in ascending order; the last is `f64` max, encoded as `+Inf`.
    bounds: [bucket_count_max]f64,
    /// Observations per bucket (not cumulative).
    counts: [bucket_count_max]u64,
    bucket_count: u8,
    sum: f64,
    count: u64,

    pub const metric_type: MetricType = .histogram;

    /// A histogram over `bounds` plus `+Inf` (prometheus-client's `Histogram::new`).
    pub fn init(bounds: []const f64) Histogram {
        assert(bounds.len < bucket_count_max);
        var histogram: Histogram = .{
            .bounds = undefined,
            .counts = @splat(0),
            .bucket_count = @intCast(bounds.len + 1),
            .sum = 0,
            .count = 0,
        };
        for (bounds, 0..) |bound, index| {
            if (index > 0) assert(bounds[index - 1] < bound);
            histogram.bounds[index] = bound;
        }
        histogram.bounds[bounds.len] = std.math.floatMax(f64);
        @memset(histogram.bounds[bounds.len + 1 ..], 0);
        return histogram;
    }

    /// Records `value` in the first bucket whose bound is at least `value`. `NaN` lands in the
    /// last bucket and `+inf` in none (it still counts toward `count` and `sum`), as upstream.
    pub fn observe(histogram: *Histogram, value: f64) void {
        histogram.lock.lock();
        defer histogram.lock.unlock();
        histogram.sum += value;
        histogram.count += 1;
        const buckets = histogram.bucket_count;
        assert(buckets > 0 and buckets <= bucket_count_max);
        if (std.math.isNan(value)) {
            histogram.counts[buckets - 1] += 1;
            return;
        }
        for (histogram.bounds[0..buckets], histogram.counts[0..buckets]) |bound, *count| {
            if (bound >= value) {
                count.* += 1;
                return;
            }
        }
    }

    pub fn get_sum(histogram: *Histogram) f64 {
        histogram.lock.lock();
        defer histogram.lock.unlock();
        return histogram.sum;
    }

    pub fn get_count(histogram: *Histogram) u64 {
        histogram.lock.lock();
        defer histogram.lock.unlock();
        return histogram.count;
    }

    pub fn encode_samples(histogram: *Histogram, encoder: SampleEncoder) Writer.Error!void {
        // Copy under the lock so the lines are one consistent snapshot.
        histogram.lock.lock();
        const snapshot = histogram.*;
        histogram.lock.unlock();
        const buckets = snapshot.bucket_count;
        try encoder.histogram(
            snapshot.sum,
            snapshot.count,
            snapshot.bounds[0..buckets],
            snapshot.counts[0..buckets],
        );
    }
};

/// A metric per label set `L` (a struct whose fields are the labels, see
/// `encoding.write_label_set`). Entries are keyed by their encoded label set and encoded in
/// insertion order (prometheus-client iterates a `HashMap`, in no stable order). Pointers
/// returned by `get_or_create` stay valid until that entry is removed or the family deinits.
pub fn Family(comptime L: type, comptime M: type) type {
    comptime assert(@typeInfo(L) == .@"struct");
    comptime assert(@hasDecl(M, "metric_type"));
    return struct {
        const Self = @This();

        gpa: Allocator,
        lock: SpinLock = .{},
        /// Copied into each new entry (a histogram's buckets, for example).
        prototype: M,
        entries: std.StringArrayHashMapUnmanaged(*M) = .empty,

        pub const metric_type: MetricType = M.metric_type;
        pub const Labels = L;
        pub const Metric = M;

        /// A family whose entries start as `M`'s defaults.
        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa, .prototype = .{} };
        }

        /// A family whose entries start as copies of `prototype`
        /// (prometheus-client's `Family::new_with_constructor`).
        pub fn init_with(gpa: Allocator, prototype: M) Self {
            return .{ .gpa = gpa, .prototype = prototype };
        }

        pub fn deinit(family: *Self) void {
            for (family.entries.keys(), family.entries.values()) |key, metric| {
                family.gpa.free(key);
                family.gpa.destroy(metric);
            }
            family.entries.deinit(family.gpa);
            family.* = undefined;
        }

        /// The entry for `labels`, created from the prototype on first use.
        pub fn get_or_create(family: *Self, labels: L) Allocator.Error!*M {
            var buffer: [encoding.label_set_size_max]u8 = undefined;
            const key = encode_key(&buffer, labels);
            family.lock.lock();
            defer family.lock.unlock();
            const slot = try family.entries.getOrPut(family.gpa, key);
            if (slot.found_existing) return slot.value_ptr.*;
            errdefer _ = family.entries.pop();
            const owned_key = try family.gpa.dupe(u8, key);
            errdefer family.gpa.free(owned_key);
            const metric = try family.gpa.create(M);
            metric.* = family.prototype;
            slot.key_ptr.* = owned_key;
            slot.value_ptr.* = metric;
            assert(family.entries.count() > 0);
            return metric;
        }

        /// The entry for `labels`, if it exists.
        pub fn get(family: *Self, labels: L) ?*M {
            var buffer: [encoding.label_set_size_max]u8 = undefined;
            const key = encode_key(&buffer, labels);
            family.lock.lock();
            defer family.lock.unlock();
            return family.entries.get(key);
        }

        /// Removes the entry for `labels`; returns whether it existed.
        pub fn remove(family: *Self, labels: L) bool {
            var buffer: [encoding.label_set_size_max]u8 = undefined;
            const key = encode_key(&buffer, labels);
            family.lock.lock();
            const removed = family.entries.fetchOrderedRemove(key);
            family.lock.unlock();
            const entry = removed orelse return false;
            family.gpa.free(entry.key);
            family.gpa.destroy(entry.value);
            return true;
        }

        pub fn count(family: *Self) usize {
            family.lock.lock();
            defer family.lock.unlock();
            return family.entries.count();
        }

        pub fn is_empty(family: *Self) bool {
            return family.count() == 0;
        }

        pub fn encode_samples(family: *Self, encoder: SampleEncoder) Writer.Error!void {
            family.lock.lock();
            defer family.lock.unlock();
            for (family.entries.keys(), family.entries.values()) |key, metric| {
                try metric.encode_samples(encoder.with_family(key));
            }
        }

        fn encode_key(buffer: *[encoding.label_set_size_max]u8, labels: L) []const u8 {
            var writer: Writer = .fixed(buffer);
            // Label sets are bounded by `label_set_size_max`; a longer one is a caller bug.
            encoding.write_label_set(&writer, labels) catch @panic("label set too long");
            return writer.buffered();
        }
    };
}

const testing = std.testing;

test "counter and gauge record" {
    var counter: Counter = .{};
    counter.inc();
    counter.inc_by(std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, 0), counter.get());
    var gauge: Gauge = .{};
    gauge.inc_by(5);
    gauge.dec();
    try testing.expectEqual(@as(i64, 4), gauge.set(-2));
    try testing.expectEqual(@as(i64, -2), try gauge.try_set_max(@as(u8, 7)));
    try testing.expectEqual(@as(i64, 7), try gauge.try_set_max(@as(u8, 3)));
    try testing.expectEqual(@as(i64, 7), gauge.get());
    try testing.expectError(error.Overflow, gauge.try_set(@as(u64, std.math.maxInt(u64))));
    try testing.expectEqual(@as(i64, 7), gauge.get());
}

test "histogram buckets like prometheus-client" {
    var histogram: Histogram = .init(&.{ 0.1, 1.0 });
    histogram.observe(0.1); // Inclusive upper bound.
    histogram.observe(0.5);
    histogram.observe(5.0);
    histogram.observe(std.math.nan(f64));
    histogram.observe(std.math.inf(f64));
    try testing.expectEqual(@as(u64, 5), histogram.get_count());
    try testing.expectEqualSlices(u64, &.{ 1, 1, 2 }, histogram.counts[0..3]);
}

test "family entries" {
    const Labels = struct { peer: []const u8 };
    var family: Family(Labels, Counter) = .init(testing.allocator);
    defer family.deinit();
    try testing.expect(family.is_empty());
    (try family.get_or_create(.{ .peer = "alice" })).inc();
    (try family.get_or_create(.{ .peer = "alice" })).inc_by(2);
    (try family.get_or_create(.{ .peer = "bob" })).inc();
    try testing.expectEqual(@as(u64, 3), family.get(.{ .peer = "alice" }).?.get());
    try testing.expect(family.get(.{ .peer = "carol" }) == null);
    try testing.expect(family.remove(.{ .peer = "alice" }));
    try testing.expect(!family.remove(.{ .peer = "alice" }));
    try testing.expectEqual(@as(usize, 1), family.count());
}

test "family allocation failures leave it consistent" {
    const Labels = struct { index: u32 };
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 2 });
    var family: Family(Labels, Gauge) = .init(failing.allocator());
    defer family.deinit();
    var index: u32 = 0;
    var created: u32 = 0;
    while (index < 4) : (index += 1) {
        _ = family.get_or_create(.{ .index = index }) catch continue;
        created += 1;
    }
    try testing.expect(created < 4);
    try testing.expectEqual(@as(usize, created), family.count());
}
