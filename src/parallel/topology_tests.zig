//! Tests of `topology.zig`, ported from the model tests in commonware's
//! `parallel/src/topology.rs` (its Linux module) with the same layouts.

const std = @import("std");
const testing = std.testing;
const topology_module = @import("topology.zig");

const Topology = topology_module.Topology;
const CpuSet = topology_module.CpuSet;
const Group = topology_module.Group;
const List = topology_module.List;

const names = [_][]const u8{ "0", "1", "2", "3", "4", "5", "6", "7" };

/// A topology whose CPU `cpu` is in domain `domain_of(cpu)`, for CPUs `0..cpus`.
fn uniform(cpus: usize, comptime domain_of: fn (usize) usize) !Topology {
    var lists: [64]List = undefined;
    for (lists[0..cpus], 0..) |*pair, cpu| pair.* = .{ .cpu = cpu, .list = names[domain_of(cpu)] };
    return Topology.from_lists(lists[0..cpus]) orelse error.Rejected;
}

fn eighths(cpu: usize) usize {
    return cpu / 8;
}

fn quarters(cpu: usize) usize {
    return cpu / 4;
}

fn above_four(cpu: usize) usize {
    return @intFromBool(cpu >= 4);
}

fn expect_cpus(expected: []const usize, mask: CpuSet) !void {
    try testing.expect(CpuSet.of(expected).eql(mask));
}

test "reservations keep spare domain cpus" {
    const topology = try uniform(16, eighths);
    var homes: [2]?CpuSet = undefined;
    const groups = [_]Group{ .{ .width = 7, .home = 0 }, .{ .width = 1, .home = null } };
    const floating = topology.reservations(.range(0, 16), &groups, &homes);
    try testing.expect(CpuSet.range(0, 8).eql(homes[0].?));
    try testing.expectEqual(@as(?CpuSet, null), homes[1]);
    try testing.expect(CpuSet.range(8, 16).eql(floating.?));
}

test "reservations omit the floating mask at capacity" {
    const topology = try uniform(64, eighths);
    var groups: [10]Group = undefined;
    for (groups[0..8], 0..) |*group, home| group.* = .{ .width = 7, .home = @intCast(home) };
    groups[8] = .{ .width = 7, .home = null };
    groups[9] = .{ .width = 1, .home = null };
    var homes: [10]?CpuSet = undefined;
    const floating = topology.reservations(.range(0, 64), &groups, &homes);
    try testing.expectEqual(@as(?CpuSet, null), floating);
    for (homes[0..8], 0..) |mask, home| {
        try testing.expect(CpuSet.range(home * 8, home * 8 + 8).eql(mask.?));
    }
    for (homes[8..]) |mask| try testing.expectEqual(@as(?CpuSet, null), mask);
}

test "reservations keep restricted home masks" {
    const topology = try uniform(12, above_four);
    var homes: [2]?CpuSet = undefined;
    const allowed: CpuSet = .of(&.{ 0, 2, 3, 5, 7, 9, 11 });
    const narrow = [_]Group{ .{ .width = 5, .home = 0 }, .{ .width = 2, .home = null } };
    const floating = topology.reservations(allowed, &narrow, &homes);
    try expect_cpus(&.{ 0, 2, 3 }, homes[0].?);
    try expect_cpus(&.{ 5, 7, 9, 11 }, floating.?);

    const full = [_]Group{ .{ .width = 3, .home = 0 }, .{ .width = 3, .home = null } };
    try testing.expectEqual(@as(?CpuSet, null), topology.reservations(.range(0, 4), &full, &homes));
    try testing.expectEqual(@as(usize, 4), homes[0].?.count());
}

test "reservations float at exact capacity" {
    const topology = try uniform(8, quarters);
    var homes: [2]?CpuSet = undefined;
    const exact = [_]Group{ .{ .width = 3, .home = 0 }, .{ .width = 4, .home = null } };
    const floating = topology.reservations(.range(0, 8), &exact, &homes).?;
    try testing.expect(CpuSet.range(4, 8).eql(floating));
    const over = [_]Group{ .{ .width = 3, .home = 0 }, .{ .width = 5, .home = null } };
    try testing.expectEqual(@as(?CpuSet, null), topology.reservations(.range(0, 8), &over, &homes));
}

fn uneven(cpu: usize) usize {
    if (cpu < 8) return 0;
    if (cpu < 14) return 1;
    if (cpu < 19) return 2;
    return 3;
}

test "group width leaves slack in wide domains" {
    // Domains of 8, 6, 5, and 1 CPUs.
    const topology = try uniform(20, uneven);
    try testing.expectEqual(@as(?usize, 7), topology.group_width(.range(0, 20)));
    try testing.expectEqual(@as(?usize, 5), topology.group_width(.range(8, 20)));
    try testing.expectEqual(@as(?usize, 5), topology.group_width(.range(14, 20)));
    try testing.expectEqual(@as(?usize, null), topology.group_width(.of(&.{ 0, 8, 14, 19 })));
}

/// Scattered CPU ids listed out of order: domain 0 holds 9, 2, and 14, domain 1 holds 5, 11,
/// and 0, domain 2 holds 7, 12, and 3, and domain 3 holds 1 and 4.
fn scattered() !Topology {
    const pairs = [_][2]usize{
        .{ 9, 0 }, .{ 2, 0 },  .{ 5, 1 }, .{ 14, 0 }, .{ 11, 1 }, .{ 7, 2 },
        .{ 0, 1 }, .{ 12, 2 }, .{ 1, 3 }, .{ 3, 2 },  .{ 4, 3 },
    };
    var lists: [pairs.len]List = undefined;
    for (&lists, pairs) |*pair, entry| pair.* = .{ .cpu = entry[0], .list = names[entry[1]] };
    return Topology.from_lists(&lists) orelse error.Rejected;
}

test "partition assigns allowed cpus by domain" {
    const topology = try scattered();
    const allowed = [_]usize{ 14, 0, 9, 3, 5, 12 };
    const partition = topology.partition(.of(&allowed), allowed.len).?;
    try testing.expectEqual(@as(usize, 2), partition.width);
    try testing.expectEqualSlices(u16, &.{ 0, 1, 2 }, partition.homes[0..partition.len]);
    var covered: CpuSet = .empty;
    for (partition.homes[0..partition.len], partition.masks[0..partition.len]) |home, mask| {
        var cpus = mask.iterator();
        while (cpus.next()) |cpu| try testing.expectEqual(@as(?u16, home), topology.domain_of(cpu));
        covered = .{ .bits = covered.bits.unionWith(mask.bits) };
    }
    try testing.expect(CpuSet.of(&allowed).eql(covered));
}

test "partition rejects inexact geometry" {
    const topology = try scattered();
    const even = [_]usize{ 9, 14, 5, 0, 12, 3 };
    const outside = [_]usize{ 9, 14, 5, 0, 12, 3, 20 };
    const cases = [_]struct { allowed: []const usize, parallelism: usize }{
        .{ .allowed = &.{ 9, 14, 5, 11, 0, 12 }, .parallelism = 6 }, // uneven allowed domains
        .{ .allowed = &outside, .parallelism = 6 }, // an allowed CPU outside every domain
        .{ .allowed = &outside, .parallelism = 7 },
        .{ .allowed = &even, .parallelism = 4 }, // fewer workers than allowed CPUs
        .{ .allowed = &even, .parallelism = 8 }, // more workers than allowed CPUs
        .{ .allowed = &.{ 9, 14 }, .parallelism = 2 }, // a single allowed domain
        .{ .allowed = &.{ 9, 5, 12 }, .parallelism = 3 }, // one allowed CPU per domain
    };
    for (cases) |case| {
        try testing.expectEqual(null, topology.partition(.of(case.allowed), case.parallelism));
    }
}

test "from_lists rejects empty, single-domain, and out-of-range lists" {
    try testing.expectEqual(null, Topology.from_lists(&.{}));
    const single = [_]List{ .{ .cpu = 0, .list = "0-1" }, .{ .cpu = 1, .list = "0-1" } };
    try testing.expectEqual(null, Topology.from_lists(&single));
    const far = [_]List{
        .{ .cpu = 0, .list = "0" },
        .{ .cpu = topology_module.cpus_max, .list = "1" },
    };
    try testing.expectEqual(null, Topology.from_lists(&far));

    // A CPU missing from the lists has no domain, and neither does one past the table.
    const gap = [_]List{ .{ .cpu = 0, .list = "a" }, .{ .cpu = 2, .list = "b" } };
    const topology = Topology.from_lists(&gap).?;
    try testing.expectEqual(@as(?u16, 0), topology.domain_of(0));
    try testing.expectEqual(@as(?u16, null), topology.domain_of(1));
    try testing.expectEqual(@as(?u16, 1), topology.domain_of(2));
    try testing.expectEqual(@as(?u16, null), topology.domain_of(3));
}

test "detection covers every domain it reports" {
    // Hosts without sysfs or with one LLC have no topology; any detected one is consistent.
    const topology = Topology.detect(testing.io) orelse return;
    try testing.expect(topology.domains_len >= 2);
    for (0..topology.cpus_len) |cpu| {
        const domain = topology.domain_of(cpu) orelse continue;
        try testing.expect(topology.domains[domain].contains(cpu));
    }
}
