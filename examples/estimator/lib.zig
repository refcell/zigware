//! Simulate mechanism performance under realistic network conditions (commonware
//! `examples/estimator/src/lib.rs`): the `.lazy` DSL (`dsl.zig`), region latencies from
//! cloudping.co, peer distributions, and the statistics the estimator prints.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const zigware = @import("zigware");
const build_options = @import("build_options");
const rust = @import("rust.zig");

pub const dsl = @import("dsl.zig");
pub const Command = dsl.Command;
pub const Task = dsl.Task;
pub const Threshold = dsl.Threshold;
pub const Diagnostic = dsl.Diagnostic;
pub const parse_task = dsl.parse_task;
pub const calculate_threshold = dsl.calculate_threshold;
pub const can_command_advance = dsl.can_command_advance;
pub const validate = dsl.validate;

/// cloudping.co reports ping times (round trips), not one-way latency.
const cloudping_divisor: f64 = 2.0;

/// The commonware release this estimator ports, printed by `--version` like the crate's.
pub fn crate_version() []const u8 {
    return build_options.version;
}

/// Peers in one region and their optional bandwidth limits in bytes per second.
pub const RegionConfig = struct {
    count: u64,
    egress_cap: ?u64,
    ingress_cap: ?u64,
};

/// Regions in ascending byte order with their configuration (commonware's
/// `BTreeMap<Region, RegionConfig>`).
pub const Distribution = struct {
    pub const Entry = struct { region: []const u8, config: RegionConfig };

    entries: std.ArrayList(Entry) = .empty,

    pub fn deinit(distribution: *Distribution, gpa: Allocator) void {
        distribution.entries.deinit(gpa);
        distribution.* = undefined;
    }

    /// Inserts or replaces `region` (the region slice must outlive the distribution).
    pub fn put(
        distribution: *Distribution,
        gpa: Allocator,
        region: []const u8,
        config: RegionConfig,
    ) Allocator.Error!void {
        const items = distribution.entries.items;
        const index = std.sort.lowerBound(Entry, items, region, order_entry);
        if (index < items.len and std.mem.eql(u8, items[index].region, region)) {
            items[index].config = config;
            return;
        }
        try distribution.entries.insert(gpa, index, .{ .region = region, .config = config });
    }

    pub fn get(distribution: *const Distribution, region: []const u8) ?RegionConfig {
        const items = distribution.entries.items;
        const index = std.sort.binarySearch(Entry, items, region, order_entry) orelse
            return null;
        return items[index].config;
    }

    fn order_entry(region: []const u8, entry: Entry) std.math.Order {
        return std.mem.order(u8, region, entry.region);
    }
};

/// Average latency and jitter between two regions, in milliseconds.
pub const Behavior = struct { latency_ms: f64, jitter_ms: f64 };

/// Region-to-region behavior (commonware `Latencies`), sorted by origin then destination.
pub const Latencies = struct {
    pub const Entry = struct { from: []const u8, to: []const u8, behavior: Behavior };

    entries: []Entry,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(latencies: *Latencies) void {
        latencies.arena.deinit();
        latencies.* = undefined;
    }

    pub fn get(latencies: *const Latencies, from: []const u8, to: []const u8) ?Behavior {
        const key: Entry = .{ .from = from, .to = to, .behavior = undefined };
        const index = std.sort.binarySearch(Entry, latencies.entries, key, order_key) orelse
            return null;
        return latencies.entries[index].behavior;
    }

    fn order_key(key: Entry, entry: Entry) std.math.Order {
        return order_pair(key, entry);
    }

    fn order_pair(a: Entry, b: Entry) std.math.Order {
        const by_from = std.mem.order(u8, a.from, b.from);
        return if (by_from != .eq) by_from else std.mem.order(u8, a.to, b.to);
    }

    fn less_than(_: void, a: Entry, b: Entry) bool {
        return order_pair(a, b) == .lt;
    }
};

pub const p50_json = @embedFile("p50.json");
pub const p90_json = @embedFile("p90.json");

pub const LatencyError = error{ InvalidLatencyData, OutOfMemory };

/// The embedded cloudping.co P50 and P90 matrices (commonware `load_latency_data`).
pub fn load_latency_data(gpa: Allocator) LatencyError!Latencies {
    return populate_latency_map(gpa, p50_json, p90_json);
}

/// Latency is half the P50 ping; jitter is half the P90 - P50 spread. Pairs missing from
/// either matrix are skipped (commonware `populate_latency_map`).
pub fn populate_latency_map(
    gpa: Allocator,
    p50: []const u8,
    p90: []const u8,
) LatencyError!Latencies {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const p50_data = try parse_cloudping(allocator, p50);
    const p90_data = try parse_cloudping(allocator, p90);
    var entries: std.ArrayList(Latencies.Entry) = .empty;
    var origins = p50_data.iterator();
    while (origins.next()) |origin| {
        const inner_p50 = try as_object(origin.value_ptr.*);
        const inner_p90 = try as_object(p90_data.get(origin.key_ptr.*) orelse
            return error.InvalidLatencyData);
        var destinations = inner_p50.iterator();
        while (destinations.next()) |destination| {
            const lat90 = try as_number(inner_p90.get(destination.key_ptr.*) orelse continue);
            const lat50 = try as_number(destination.value_ptr.*);
            try entries.append(allocator, .{
                .from = origin.key_ptr.*,
                .to = destination.key_ptr.*,
                .behavior = .{
                    .latency_ms = lat50 / cloudping_divisor,
                    .jitter_ms = (lat90 - lat50) / cloudping_divisor,
                },
            });
        }
    }
    std.sort.pdq(Latencies.Entry, entries.items, {}, Latencies.less_than);
    for (entries.items[1..], entries.items[0 .. entries.items.len - 1]) |b, a| {
        if (Latencies.order_pair(a, b) != .lt) return error.InvalidLatencyData;
    }
    return .{ .entries = entries.items, .arena = arena };
}

/// The `data` object of a cloudping.co response.
fn parse_cloudping(allocator: Allocator, json: []const u8) LatencyError!std.json.ObjectMap {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, json, .{
        .duplicate_field_behavior = .use_last,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidLatencyData,
    };
    const data = (try as_object(root)).get("data") orelse return error.InvalidLatencyData;
    return as_object(data);
}

fn as_object(value: std.json.Value) LatencyError!std.json.ObjectMap {
    return switch (value) {
        .object => |object| object,
        else => error.InvalidLatencyData,
    };
}

fn as_number(value: std.json.Value) LatencyError!f64 {
    return switch (value) {
        .integer => |integer| @floatFromInt(integer),
        .float => |float| float,
        .number_string => |text| std.fmt.parseFloat(f64, text) catch error.InvalidLatencyData,
        else => error.InvalidLatencyData,
    };
}

/// The mean of `data`, or zero when empty.
pub fn mean(data: []const f64) f64 {
    if (data.len == 0) return 0.0;
    var sum: f64 = -0.0; // Rust's `f64: Sum` starts from negative zero.
    for (data) |value| sum += value;
    return sum / @as(f64, @floatFromInt(data.len));
}

/// The median of `data`, sorting it in place; zero when empty.
pub fn median(data: []f64) f64 {
    if (data.len == 0) return 0.0;
    for (data) |value| assert(!std.math.isNan(value));
    std.sort.pdq(f64, data, {}, std.sort.asc(f64));
    const mid = data.len / 2;
    if (data.len % 2 == 0) return (data[mid - 1] + data[mid]) / 2.0;
    return data[mid];
}

/// The population standard deviation of `data`, or null when empty.
pub fn std_dev(data: []const f64) ?f64 {
    if (data.len == 0) return null;
    const mean_value = mean(data);
    var sum: f64 = -0.0;
    for (data) |value| {
        const difference = mean_value - value;
        sum += difference * difference;
    }
    const variance = sum / @as(f64, @floatFromInt(data.len));
    return @sqrt(variance);
}

pub const PeersError = error{ TooFewPeers, TooManyPeers };

/// Total peers across regions; at least two (commonware `count_peers`).
pub fn count_peers(distribution: *const Distribution) PeersError!u64 {
    var peers: u64 = 0;
    for (distribution.entries.items) |entry| {
        peers = std.math.add(u64, peers, entry.config.count) catch return error.TooManyPeers;
    }
    if (peers <= 1) return error.TooFewPeers;
    return peers;
}

/// The region of the peer at `proposer` (commonware `calculate_proposer_region`).
pub fn calculate_proposer_region(proposer: u64, distribution: *const Distribution) []const u8 {
    var current: u64 = 0;
    for (distribution.entries.items) |entry| {
        const start = current;
        current += entry.config.count;
        if (proposer >= start and proposer < current) return entry.region;
    }
    std.debug.panic("Proposer index {d} out of bounds", .{proposer});
}

const testing = std.testing;

test "crate_version" {
    try testing.expect(crate_version().len > 0);
}

test "mean" {
    try testing.expectEqual(@as(f64, 0.0), mean(&.{}));
    try testing.expectEqual(@as(f64, 1.0), mean(&.{1.0}));
    try testing.expectEqual(@as(f64, 2.0), mean(&.{ 1.0, 2.0, 3.0 }));
    try testing.expectEqual(@as(f64, 20.0), mean(&.{ 10.0, 20.0, 30.0 }));
}

test "median" {
    try testing.expectEqual(@as(f64, 0.0), median(&.{}));
    var one = [_]f64{5.0};
    try testing.expectEqual(@as(f64, 5.0), median(&one));
    var three = [_]f64{ 1.0, 3.0, 2.0 };
    try testing.expectEqual(@as(f64, 2.0), median(&three));
    var four = [_]f64{ 1.0, 2.0, 3.0, 4.0 };
    try testing.expectEqual(@as(f64, 2.5), median(&four));
    var five = [_]f64{ 4.0, 1.0, 3.0, 2.0, 5.0 };
    try testing.expectEqual(@as(f64, 3.0), median(&five));
}

test "std_dev" {
    try testing.expectEqual(@as(?f64, null), std_dev(&.{}));
    try testing.expectEqual(@as(?f64, 0.0), std_dev(&.{1.0}));
    const result = std_dev(&.{ 1.0, 2.0, 3.0, 4.0, 5.0 }).?;
    try testing.expect(@abs(result - std.math.sqrt2) < 1e-10);
}

test "calculate_threshold" {
    try testing.expectEqual(@as(u64, 5), calculate_threshold(.{ .count = 5 }, 10));
    try testing.expectEqual(@as(u64, 5), calculate_threshold(.{ .percent = 0.5 }, 10));
    // ceil(3 * 0.67) = 3; ceil(5 * 0.67) = 4.
    try testing.expectEqual(@as(u64, 3), calculate_threshold(.{ .percent = 0.67 }, 3));
    try testing.expectEqual(@as(u64, 4), calculate_threshold(.{ .percent = 0.67 }, 5));
}

test "populate_latency_map" {
    const p50 =
        \\{"data": {"us-east-1": {"us-west-1": 50.0, "eu-west-1": 100}}}
    ;
    const p90 =
        \\{"data": {"us-east-1": {"us-west-1": 80.0, "eu-west-1": 150.0}}}
    ;
    var latencies = try populate_latency_map(testing.allocator, p50, p90);
    defer latencies.deinit();
    try testing.expectEqual(@as(usize, 2), latencies.entries.len);
    // P50 = 50 / 2 = 25, jitter = (P90 - P50) / 2 = (80 - 50) / 2 = 15.
    try testing.expectEqual(Behavior{ .latency_ms = 25.0, .jitter_ms = 15.0 }, latencies.get(
        "us-east-1",
        "us-west-1",
    ).?);
    try testing.expectEqual(Behavior{ .latency_ms = 50.0, .jitter_ms = 25.0 }, latencies.get(
        "us-east-1",
        "eu-west-1",
    ).?);
    try testing.expectEqual(@as(?Behavior, null), latencies.get("us-west-1", "us-east-1"));
}

test "embedded latency data covers every region pair" {
    var latencies = try load_latency_data(testing.allocator);
    defer latencies.deinit();
    try testing.expectEqual(@as(usize, 33 * 33), latencies.entries.len);
    // `"us-east-1": 16.312` from ca-central-1 in p50.json.
    const behavior = latencies.get("ca-central-1", "us-east-1").?;
    try testing.expectEqual(@as(f64, 16.312 / 2.0), behavior.latency_ms);
    try testing.expect(behavior.jitter_ms >= 0);
}

test "count_peers and calculate_proposer_region" {
    var distribution: Distribution = .{};
    defer distribution.deinit(testing.allocator);
    const one: RegionConfig = .{ .count = 1, .egress_cap = null, .ingress_cap = null };
    try distribution.put(testing.allocator, "us-east-1", one);
    try testing.expectError(error.TooFewPeers, count_peers(&distribution));
    const two: RegionConfig = .{ .count = 2, .egress_cap = null, .ingress_cap = null };
    try distribution.put(testing.allocator, "eu-west-1", two);
    try testing.expectEqual(@as(u64, 3), try count_peers(&distribution));
    try testing.expectEqualStrings("eu-west-1", calculate_proposer_region(0, &distribution));
    try testing.expectEqualStrings("eu-west-1", calculate_proposer_region(1, &distribution));
    try testing.expectEqualStrings("us-east-1", calculate_proposer_region(2, &distribution));
}

test {
    _ = rust;
    _ = @import("dsl_test.zig");
}
