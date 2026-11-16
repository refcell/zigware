//! commonware `deployer::aws::create` tests: storage and name validation, and
//! availability-zone group selection.

const std = @import("std");
const testing = std.testing;
const aws = @import("mod.zig");
const create = @import("create.zig");
const Failure = @import("failure.zig").Failure;

fn instance(
    name: []const u8,
    region: []const u8,
    instance_type: []const u8,
    group: ?[]const u8,
) aws.InstanceConfig {
    return .{
        .name = name,
        .region = region,
        .availability_zone_group = group,
        .instance_type = instance_type,
        .storage_size = 10,
        .storage_class = "gp3",
        .binary = "binary",
        .config = "config.yaml",
        .profiling = false,
    };
}

fn config(
    monitoring_config: aws.MonitoringConfig,
    instances: []const aws.InstanceConfig,
) aws.Config {
    return .{
        .tag = "tag",
        .monitoring = monitoring_config,
        .instances = instances,
        .ports = &.{},
    };
}

fn monitoring(storage_class: []const u8, storage_iops: ?i32) aws.MonitoringConfig {
    return .{
        .instance_type = "c8g.4xlarge",
        .storage_size = 10,
        .storage_class = storage_class,
        .storage_iops = storage_iops,
        .dashboard = "dashboard.json",
    };
}

fn worker(storage_class: []const u8, storage_iops: ?i32) aws.InstanceConfig {
    var value = instance("worker", "us-east-1", "c8g.4xlarge", null);
    value.storage_class = storage_class;
    value.storage_iops = storage_iops;
    return value;
}

fn expect_failure(expected: Failure, actual: ?Failure) !void {
    try testing.expectEqualDeep(@as(?Failure, expected), actual);
}

test "monitoring io2 requires storage iops" {
    const cfg = config(monitoring("io2", null), &.{});
    try expect_failure(.{ .missing_storage_iops = .{
        .target = "monitoring",
        .storage_class = "io2",
    } }, create.validate_storage_config(&cfg));
}

test "instance io1 requires storage iops" {
    const cfg = config(monitoring("gp3", null), &.{worker("io1", null)});
    try expect_failure(.{ .missing_storage_iops = .{
        .target = "worker",
        .storage_class = "io1",
    } }, create.validate_storage_config(&cfg));
}

test "gp3 storage iops must be in range" {
    const cfg = config(monitoring("gp3", 0), &.{});
    try expect_failure(.{ .invalid_storage_iops = .{
        .target = "monitoring",
        .storage_class = "gp3",
        .storage_iops = 0,
    } }, create.validate_storage_config(&cfg));
}

test "io1 storage iops must be in range" {
    var big = worker("io1", 64_001);
    big.storage_size = 10_000;
    const cfg = config(monitoring("gp3", null), &.{big});
    try expect_failure(.{ .invalid_storage_iops = .{
        .target = "worker",
        .storage_class = "io1",
        .storage_iops = 64_001,
    } }, create.validate_storage_config(&cfg));
}

test "io1 storage iops are capped by storage size" {
    const cfg = config(monitoring("gp3", null), &.{worker("io1", 64_000)});
    try expect_failure(.{ .invalid_storage_iops = .{
        .target = "worker",
        .storage_class = "io1",
        .storage_iops = 64_000,
    } }, create.validate_storage_config(&cfg));
}

test "io2 storage iops must be in range" {
    const cfg = config(monitoring("io2", 256_001), &.{});
    try expect_failure(.{ .invalid_storage_iops = .{
        .target = "monitoring",
        .storage_class = "io2",
        .storage_iops = 256_001,
    } }, create.validate_storage_config(&cfg));
}

test "unsupported storage class rejects storage iops" {
    const cfg = config(monitoring("gp2", 3_000), &.{});
    try expect_failure(.{ .invalid_storage_iops = .{
        .target = "monitoring",
        .storage_class = "gp2",
        .storage_iops = 3_000,
    } }, create.validate_storage_config(&cfg));
}

test "unknown storage class is rejected" {
    const cfg = config(monitoring("gp9", null), &.{});
    try expect_failure(.{ .invalid_storage_class = .{
        .target = "monitoring",
        .storage_class = "gp9",
    } }, create.validate_storage_config(&cfg));
}

test "gp3 does not require storage iops" {
    const instances = [_]aws.InstanceConfig{instance("worker", "us-east-1", "c8g.4xlarge", null)};
    const cfg = config(monitoring("gp3", null), &instances);
    try testing.expectEqual(@as(?Failure, null), create.validate_storage_config(&cfg));
}

test "io2 accepts storage iops" {
    const cfg = config(monitoring("io2", 10_000), &.{});
    try testing.expectEqual(@as(?Failure, null), create.validate_storage_config(&cfg));
}

test "storage throughput must be in gp3 range" {
    var low = monitoring("gp3", null);
    low.storage_throughput = 124;
    const cfg = config(low, &.{});
    try expect_failure(.{ .invalid_storage_throughput = .{
        .target = "monitoring",
        .storage_throughput = 124,
    } }, create.validate_storage_config(&cfg));
}

test "storage throughput requires gp3" {
    var io2 = worker("io2", 10_000);
    io2.storage_throughput = 250;
    const cfg = config(monitoring("gp3", null), &.{io2});
    try expect_failure(.{ .unsupported_storage_throughput = .{
        .target = "worker",
        .storage_class = "io2",
    } }, create.validate_storage_config(&cfg));
}

test "gp3 accepts storage throughput" {
    var gp3 = monitoring("gp3", null);
    gp3.storage_throughput = 250;
    const cfg = config(gp3, &.{});
    try testing.expectEqual(@as(?Failure, null), create.validate_storage_config(&cfg));
}

test "gp3 storage throughput is capped by iops" {
    var gp3 = monitoring("gp3", null);
    gp3.storage_throughput = 2_000;
    const cfg = config(gp3, &.{});
    try expect_failure(.{ .invalid_storage_throughput = .{
        .target = "monitoring",
        .storage_throughput = 2_000,
    } }, create.validate_storage_config(&cfg));
}

test "valid names pass" {
    const instances = [_]aws.InstanceConfig{
        instance("validator-0", "us-east-1", "c8g.4xlarge", null),
        instance("Worker_1", "us-east-1", "c8g.4xlarge", null),
    };
    const cfg = config(monitoring("gp3", null), &instances);
    try testing.expectEqual(@as(?Failure, null), create.validate_names(&cfg));
}

test "invalid instance names rejected" {
    for ([_][]const u8{ "", "monitoring", "a b", "$(id)", "../x", "a.b", "\u{e9}" }) |name| {
        const instances = [_]aws.InstanceConfig{instance(name, "us-east-1", "c8g.4xlarge", null)};
        const cfg = config(monitoring("gp3", null), &instances);
        try expect_failure(.{ .invalid_instance_name = name }, create.validate_names(&cfg));
    }
}

test "invalid tags rejected" {
    for ([_][]const u8{ "", "../x", "/tmp" }) |tag| {
        var cfg = config(monitoring("gp3", null), &.{});
        cfg.tag = tag;
        try expect_failure(.{ .invalid_tag = tag }, create.validate_names(&cfg));
    }
}

test "duplicate instance names rejected" {
    const instances = [_]aws.InstanceConfig{
        instance("worker", "us-east-1", "c8g.4xlarge", null),
        instance("Worker", "us-west-2", "c8g.4xlarge", null),
    };
    const cfg = config(monitoring("gp3", null), &instances);
    try expect_failure(.{ .duplicate_instance_name = "Worker" }, create.validate_names(&cfg));
}

fn resources_in(comptime region: []const u8) create.RegionResources {
    return .{
        .region = region,
        .subnets = &.{
            .{ .az = region ++ "a", .id = "subnet-a" },
            .{ .az = region ++ "b", .id = "subnet-b" },
        },
        .az_support = &.{
            .{ .az = region ++ "a", .instance_types = &.{"c8g.4xlarge"} },
            .{ .az = region ++ "b", .instance_types = &.{ "c8g.4xlarge", "c8g.2xlarge" } },
        },
    };
}

test "az group selects mutually supported zone" {
    const resources = resources_in("us-east-1");
    const requested = [_][]const u8{ "c8g.2xlarge", "c8g.4xlarge" };
    const az = create.select_group_availability_zone(&resources, &requested).?;
    try testing.expectEqualStrings("us-east-1b", az);
}

test "grouped instances are restricted to selected subnet" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const instances = [_]aws.InstanceConfig{
        instance("chain-indexer", "us-east-1", "c8g.4xlarge", "indexers"),
        instance("metadata-indexer", "us-east-1", "c8g.2xlarge", "indexers"),
    };
    const resources = [_]create.RegionResources{resources_in("us-east-1")};
    var failure: ?Failure = null;
    const groups = try create.select_availability_zone_groups(
        arena.allocator(),
        &instances,
        &resources,
        &failure,
    );
    const allocator = arena.allocator();
    const subnets = try create.grouped_subnets(allocator, &instances[0], &resources[0], groups);
    try testing.expectEqualDeep(@as([]const create.Subnet, &.{
        .{ .az = "us-east-1b", .id = "subnet-b" },
    }), subnets);
}

test "ungrouped instances keep all subnets" {
    const resources = resources_in("us-east-1");
    const worker_instance = instance("worker", "us-east-1", "c8g.4xlarge", null);
    const gpa = testing.allocator;
    const subnets = try create.grouped_subnets(gpa, &worker_instance, &resources, &.{});
    try testing.expectEqualDeep(resources.subnets, subnets);
}

test "group without mutually supported zone is rejected" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const instances = [_]aws.InstanceConfig{
        instance("chain-indexer", "us-east-1", "c8g.4xlarge", "indexers"),
        instance("metadata-indexer", "us-east-1", "m8g.large", "indexers"),
    };
    const resources = [_]create.RegionResources{resources_in("us-east-1")};
    var failure: ?Failure = null;
    try testing.expectError(error.Invalid, create.select_availability_zone_groups(
        arena.allocator(),
        &instances,
        &resources,
        &failure,
    ));
    try expect_failure(.{ .availability_zone_group_unsupported = .{
        .region = "us-east-1",
        .group = "indexers",
        .instance_types = &.{ "c8g.4xlarge", "m8g.large" },
    } }, failure);
}

test "group name can be reused across regions" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const instances = [_]aws.InstanceConfig{
        instance("chain-indexer", "us-east-1", "c8g.4xlarge", "indexers"),
        instance("metadata-indexer", "us-west-2", "c8g.4xlarge", "indexers"),
    };
    const resources = [_]create.RegionResources{
        resources_in("us-east-1"),
        resources_in("us-west-2"),
    };
    var failure: ?Failure = null;
    const groups =
        try create.select_availability_zone_groups(allocator, &instances, &resources, &failure);
    const east = try create.grouped_subnets(allocator, &instances[0], &resources[0], groups);
    const west = try create.grouped_subnets(allocator, &instances[1], &resources[1], groups);
    try testing.expectEqualDeep(@as([]const create.Subnet, &.{
        .{ .az = "us-east-1a", .id = "subnet-a" },
    }), east);
    try testing.expectEqualDeep(@as([]const create.Subnet, &.{
        .{ .az = "us-west-2a", .id = "subnet-a" },
    }), west);
}

/// Counts how many launches run at once, per region and overall, like commonware's tests.
const Tracker = struct {
    pub const Error = error{LaunchFailed};
    const Counter = struct {
        active: std.atomic.Value(usize) = .init(0),
        max: std.atomic.Value(usize) = .init(0),

        fn enter(counter: *Counter) void {
            const count = counter.active.fetchAdd(1, .seq_cst) + 1;
            _ = counter.max.fetchMax(count, .seq_cst);
        }

        fn exit(counter: *Counter) void {
            _ = counter.active.fetchSub(1, .seq_cst);
        }
    };

    io: std.Io,
    regions: []const []const u8,
    ids: []const usize,
    completed: []?usize,
    east: Counter = .{},
    west: Counter = .{},
    other: Counter = .{},
    global: Counter = .{},
    monitoring_region: []const u8,
    monitoring_done: bool = false,
    fail_index: ?usize = null,

    fn counter_of(tracker: *Tracker, region: []const u8) *Counter {
        if (std.mem.eql(u8, region, "us-east-1")) return &tracker.east;
        if (std.mem.eql(u8, region, "us-west-2")) return &tracker.west;
        return &tracker.other;
    }

    fn occupy(tracker: *Tracker, regional: *Counter) void {
        regional.enter();
        tracker.global.enter();
        tracker.io.sleep(.fromMilliseconds(10), .awake) catch {};
        tracker.global.exit();
        regional.exit();
    }

    pub fn monitoring(tracker: *Tracker) Error!void {
        tracker.occupy(tracker.counter_of(tracker.monitoring_region));
        tracker.monitoring_done = true;
    }

    pub fn launch(tracker: *Tracker, index: usize) Error!void {
        tracker.occupy(tracker.counter_of(tracker.regions[index]));
        if (tracker.fail_index == index) return error.LaunchFailed;
        tracker.completed[index] = tracker.ids[index];
    }
};

test "create: launches are serial within each region" {
    const regions = [_][]const u8{ "us-west-2", "us-east-1", "us-west-2", "us-east-1" };
    var completed: [regions.len]?usize = @splat(null);
    var tracker: Tracker = .{
        .io = testing.io,
        .regions = &regions,
        .ids = &.{ 0, 1, 2, 3 },
        .completed = &completed,
        // A region with no launches.
        .monitoring_region = "monitoring",
    };
    const gpa = testing.allocator;
    try create.run_launches(Tracker, testing.io, gpa, &tracker, "monitoring", &regions);
    for (completed, 0..) |id, index| try testing.expectEqual(@as(?usize, index), id);
    try testing.expectEqual(@as(usize, 1), tracker.east.max.load(.seq_cst));
    try testing.expectEqual(@as(usize, 1), tracker.west.max.load(.seq_cst));
    try testing.expect(tracker.global.max.load(.seq_cst) > 1);
}

test "create: monitoring shares the binary region launch queue" {
    const regions = [_][]const u8{"us-east-1"};
    var completed: [regions.len]?usize = @splat(null);
    var tracker: Tracker = .{
        .io = testing.io,
        .regions = &regions,
        .ids = &.{0},
        .completed = &completed,
        .monitoring_region = "us-east-1",
    };
    const gpa = testing.allocator;
    try create.run_launches(Tracker, testing.io, gpa, &tracker, "us-east-1", &regions);
    try testing.expect(tracker.monitoring_done);
    try testing.expectEqual(@as(?usize, 0), completed[0]);
    try testing.expectEqual(@as(usize, 1), tracker.east.max.load(.seq_cst));
}

test "create: a failed launch stops its region's queue and is returned" {
    const regions = [_][]const u8{ "us-east-1", "us-east-1", "us-east-1" };
    var completed: [regions.len]?usize = @splat(null);
    var tracker: Tracker = .{
        .io = testing.io,
        .regions = &regions,
        .ids = &.{ 0, 1, 2 },
        .completed = &completed,
        .monitoring_region = "us-west-2",
        .fail_index = 1,
    };
    const gpa = testing.allocator;
    try testing.expectError(
        error.LaunchFailed,
        create.run_launches(Tracker, testing.io, gpa, &tracker, "us-west-2", &regions),
    );
    try testing.expectEqual(@as(?usize, 0), completed[0]);
    try testing.expectEqual(@as(?usize, null), completed[2]);
}
