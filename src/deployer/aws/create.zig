//! The checks and plans of commonware's `deployer::aws::create` that run before (or between)
//! AWS calls: configuration validation and availability-zone group selection.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const aws = @import("mod.zig");
const ec2 = @import("ec2.zig");
const Failure = @import("failure.zig").Failure;

/// Whether `name` matches `[A-Za-z0-9_-]+`.
pub fn is_valid_name(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    }
    return true;
}

/// Validates the deployment tag and instance names, which are written unescaped into paths,
/// YAML, shell scripts, S3 keys, and AWS tags. Instance names must also be unique ignoring
/// case (they name files on the operator's filesystem) and must not be `monitoring`.
pub fn validate_names(config: *const aws.Config) ?Failure {
    if (!is_valid_name(config.tag)) return .{ .invalid_tag = config.tag };
    for (config.instances, 0..) |instance, index| {
        const name = instance.name;
        if (std.mem.eql(u8, name, aws.monitoring_name) or !is_valid_name(name)) {
            return .{ .invalid_instance_name = name };
        }
        for (config.instances[0..index]) |earlier| {
            if (std.ascii.eqlIgnoreCase(earlier.name, name)) {
                return .{ .duplicate_instance_name = name };
            }
        }
    }
    return null;
}

/// Validates the storage of the monitoring instance, then of each binary instance, before any
/// key, S3, VPC, or instance resource is created.
pub fn validate_storage_config(config: *const aws.Config) ?Failure {
    const monitoring = config.monitoring;
    if (validate_storage(
        aws.monitoring_name,
        monitoring.storage_class,
        monitoring.storage_size,
        monitoring.storage_iops,
        monitoring.storage_throughput,
    )) |failure| return failure;
    for (config.instances) |instance| {
        if (validate_storage(
            instance.name,
            instance.storage_class,
            instance.storage_size,
            instance.storage_iops,
            instance.storage_throughput,
        )) |failure| return failure;
    }
    return null;
}

fn validate_storage(
    target: []const u8,
    storage_class: []const u8,
    storage_size: i32,
    storage_iops: ?i32,
    storage_throughput: ?i32,
) ?Failure {
    const volume_type = switch (ec2.parse_storage_class(target, storage_class)) {
        .ok => |volume_type| volume_type,
        .failure => |failure| return failure,
    };
    return ec2.validate_storage_options(
        target,
        volume_type,
        storage_size,
        storage_iops,
        storage_throughput,
    );
}

// --- Availability-zone groups ------------------------------------------------------------------

/// A subnet: its availability zone and ID.
pub const Subnet = struct { az: []const u8, id: []const u8 };

/// The instance types an availability zone offers.
pub const AzSupport = struct { az: []const u8, instance_types: []const []const u8 };

/// What `create` built in one region that AZ planning needs (commonware `RegionResources`).
pub const RegionResources = struct {
    region: []const u8,
    subnets: []const Subnet,
    az_support: []const AzSupport,

    fn supports(resources: *const RegionResources, az: []const u8, types: []const []const u8) bool {
        const support = for (resources.az_support) |support| {
            if (std.mem.eql(u8, support.az, az)) break support;
        } else return false;
        for (types) |wanted| {
            if (!contains(support.instance_types, wanted)) return false;
        }
        return true;
    }
};

/// The availability zone selected for a region and group. Group names are scoped by region,
/// since subnets and AZ support are region-local.
pub const GroupSelection = struct { region: []const u8, group: []const u8, az: []const u8 };

fn contains(items: []const []const u8, wanted: []const u8) bool {
    for (items) |item| if (std.mem.eql(u8, item, wanted)) return true;
    return false;
}

fn less(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// The first subnet's AZ that supports every type in `instance_types`.
pub fn select_group_availability_zone(
    resources: *const RegionResources,
    instance_types: []const []const u8,
) ?[]const u8 {
    for (resources.subnets) |subnet| {
        if (resources.supports(subnet.az, instance_types)) return subnet.az;
    }
    return null;
}

fn find_resources(resources: []const RegionResources, region: []const u8) *const RegionResources {
    for (resources) |*entry| if (std.mem.eql(u8, entry.region, region)) return entry;
    // Proof: create builds resources for every instance region before planning.
    unreachable;
}

/// Selects one mutually-supported AZ for each region and group, in first-use order. On a
/// group no AZ supports, sets `failure` and returns error.Invalid. Allocates from `arena`.
pub fn select_availability_zone_groups(
    arena: Allocator,
    instances: []const aws.InstanceConfig,
    resources: []const RegionResources,
    failure: *?Failure,
) (Allocator.Error || error{Invalid})![]const GroupSelection {
    var selected: std.ArrayList(GroupSelection) = .empty;
    for (instances, 0..) |instance, index| {
        const group = instance.availability_zone_group orelse continue;
        if (find_selection(selected.items, instance.region, group) != null) continue;
        // Every instance type of this region and group, sorted and distinct.
        var types: std.ArrayList([]const u8) = .empty;
        for (instances[index..]) |member| {
            const member_group = member.availability_zone_group orelse continue;
            if (!std.mem.eql(u8, member.region, instance.region)) continue;
            if (!std.mem.eql(u8, member_group, group)) continue;
            if (!contains(types.items, member.instance_type)) {
                try types.append(arena, member.instance_type);
            }
        }
        assert(types.items.len > 0);
        std.sort.pdq([]const u8, types.items, {}, less);
        const region = find_resources(resources, instance.region);
        const az = select_group_availability_zone(region, types.items) orelse {
            failure.* = .{ .availability_zone_group_unsupported = .{
                .region = instance.region,
                .group = group,
                .instance_types = types.items,
            } };
            return error.Invalid;
        };
        try selected.append(arena, .{ .region = instance.region, .group = group, .az = az });
    }
    return selected.items;
}

fn find_selection(
    selected: []const GroupSelection,
    region: []const u8,
    group: []const u8,
) ?[]const u8 {
    for (selected) |entry| {
        if (std.mem.eql(u8, entry.region, region) and std.mem.eql(u8, entry.group, group)) {
            return entry.az;
        }
    }
    return null;
}

/// The subnets `instance` may launch into: all of its region's for an ungrouped instance,
/// else those in its group's selected AZ. Allocates from `arena`.
pub fn grouped_subnets(
    arena: Allocator,
    instance: *const aws.InstanceConfig,
    resources: *const RegionResources,
    groups: []const GroupSelection,
) Allocator.Error![]const Subnet {
    const group = instance.availability_zone_group orelse return resources.subnets;
    // Proof: groups are selected for every grouped instance before launch.
    const az = find_selection(groups, instance.region, group) orelse unreachable;
    var subnets: std.ArrayList(Subnet) = .empty;
    for (resources.subnets) |subnet| {
        if (std.mem.eql(u8, subnet.az, az)) try subnets.append(arena, subnet);
    }
    assert(subnets.items.len > 0);
    return subnets.items;
}

/// Runs regional launch queues in parallel, with monitoring first in its region (commonware
/// `run_launches`). Launches in one region run one at a time in input order; regions run
/// concurrently. `Launcher` provides `Error`, `monitoring(*Launcher) Error!void`, and
/// `launch(*Launcher, index) Error!void`, and keeps each launch's result by its index. After a
/// failure, launches not yet started are skipped (commonware drops them with `try_join!`) and
/// the first error is returned.
pub fn run_launches(
    comptime Launcher: type,
    io: Io,
    gpa: Allocator,
    launcher: *Launcher,
    monitoring_region: []const u8,
    regions: []const []const u8,
) (Launcher.Error || Allocator.Error || Io.Cancelable)!void {
    assert(monitoring_region.len > 0);
    const order = try gpa.alloc(usize, regions.len);
    defer gpa.free(order);
    for (order, 0..) |*slot, index| slot.* = index;
    // Stable, so each region's queue keeps input order.
    std.sort.insertion(usize, order, regions, struct {
        fn less(names: []const []const u8, a: usize, b: usize) bool {
            return std.mem.order(u8, names[a], names[b]) == .lt;
        }
    }.less);
    var queues: Queues(Launcher) = .{ .launcher = launcher };
    var group: Io.Group = .init;
    defer group.cancel(io);
    var colocated: []const usize = &.{};
    var start: usize = 0;
    while (start < order.len) {
        const region = regions[order[start]];
        var end = start + 1;
        while (end < order.len and std.mem.eql(u8, regions[order[end]], region)) end += 1;
        const queue = order[start..end];
        if (std.mem.eql(u8, region, monitoring_region)) {
            colocated = queue;
        } else {
            group.async(io, Queues(Launcher).run, .{ &queues, queue });
        }
        start = end;
    }
    // Monitoring and its region's launches run here while the other regions run.
    if (launcher.monitoring()) {
        queues.run(colocated);
    } else |err| queues.fail(err);
    try group.await(io);
    if (queues.first_error) |err| return err;
    assert(!queues.failed.load(.acquire));
}

fn Queues(comptime Launcher: type) type {
    return struct {
        const Self = @This();
        launcher: *Launcher,
        failed: std.atomic.Value(bool) = .init(false),
        /// Written once, by the task that set `failed`; read after every task is done.
        first_error: ?Launcher.Error = null,

        fn run(self: *Self, queue: []const usize) void {
            for (queue) |index| {
                if (self.failed.load(.acquire)) return;
                self.launcher.launch(index) catch |err| return self.fail(err);
            }
        }

        fn fail(self: *Self, err: Launcher.Error) void {
            if (self.failed.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
                self.first_error = err;
            }
            assert(self.failed.load(.acquire));
        }
    };
}

test {
    _ = @import("create_test.zig");
}
