//! Allocator statistics exported as metrics (commonware's `allocator::mimalloc::metrics`).
//!
//! `metrics` names each exported `Stats` field with its help text and kind, so a runtime can
//! register every series by iterating it.

const std = @import("std");
const Stats = @import("stats.zig").Stats;

/// How a statistic behaves over time.
pub const Kind = enum {
    /// A value that rises and falls.
    gauge,
    /// A cumulative total that only rises.
    counter,
};

/// One exported statistic.
pub const Metric = struct {
    /// Metric name, without any family prefix.
    name: []const u8,
    help: []const u8,
    kind: Kind,
    /// The `Stats` field it reads.
    field: []const u8,

    /// Reads the value from a snapshot.
    pub fn read(metric: Metric, stats: Stats) u64 {
        inline for (@typeInfo(Stats).@"struct".field_names) |name| {
            if (std.mem.eql(u8, name, metric.field)) return @field(stats, name);
        }
        unreachable; // Every metric names a field, checked at compile time below.
    }
};

fn entry(comptime name: []const u8, help: []const u8, kind: Kind) Metric {
    comptime std.debug.assert(@hasField(Stats, name));
    return .{ .name = name, .help = help, .kind = kind, .field = name };
}

/// The exported statistics.
pub const metrics = [_]Metric{
    entry("reserved_bytes", "Bytes the allocator reserved from the operating system", .gauge),
    entry("pinned_bytes", "Bytes of pinned reservations the allocator never purges", .gauge),
    entry("committed_bytes", "Bytes the allocator currently has committed", .gauge),
    entry("committed_peak_bytes", "Peak bytes the allocator has had committed", .gauge),
    entry(
        "allocated_bytes",
        "Bytes handed out to callers, as of each thread's last statistics merge",
        .gauge,
    ),
    entry("pages", "Allocator pages currently in use", .gauge),
    entry("threads", "Threads currently known to the allocator", .gauge),
    entry("arenas", "Arenas currently managed by the allocator", .gauge),
    entry(
        "purged_bytes",
        "Total bytes the allocator purged back to the operating system",
        .counter,
    ),
    entry("purge_calls", "Total purge operations performed by the allocator", .counter),
    entry(
        "mmap_calls",
        "Total memory mappings the allocator requested from the operating system",
        .counter,
    ),
    entry(
        "huge_allocations",
        "Total allocations larger than the allocator's largest size class",
        .counter,
    ),
    entry(
        "huge_bytes",
        "Total bytes of allocations larger than the allocator's largest size class",
        .counter,
    ),
};

test "metrics read their stats fields" {
    try std.testing.expectEqual(@as(usize, 13), metrics.len);
    var stats: Stats = .{};
    stats.huge_bytes = 7;
    stats.reserved_bytes = 3;
    try std.testing.expectEqual(@as(u64, 7), metrics[12].read(stats));
    try std.testing.expectEqual(@as(u64, 3), metrics[0].read(stats));
    for (metrics, 0..) |metric, index| {
        for (metrics[index + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, metric.name, other.name));
        }
    }
}
