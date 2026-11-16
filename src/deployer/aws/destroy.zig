//! The `destroy` command (commonware `destroy.rs`): tears down everything tagged with a
//! deployment's tag, region by region, then marks the deployment destroyed. The deployment's
//! directory stays, so the tag cannot be deployed again.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const aws = @import("mod.zig");
const ec2_api = @import("ec2_api.zig");
const s3 = @import("s3.zig");
const Session = @import("session.zig").Session;

const log = std.log.scoped(.deployer);

/// Which deployment to destroy: by its configuration, or by its tag (using the regions its
/// metadata recorded).
pub const Target = union(enum) { config: []const u8, tag: []const u8 };

/// Tears down the deployment (commonware `destroy`). Regions are torn down concurrently: first
/// instances, security groups, subnets, route tables, peerings, gateways, and key pairs, then
/// each region's VPCs. A deployment already destroyed is left alone.
pub fn destroy(session: *Session, target: Target) !void {
    const tag, const regions = switch (target) {
        .config => |path| blk: {
            const config = try session.load_config(path);
            break :blk .{ config.tag, try session.regions_of(&config) };
        },
        .tag => |tag| blk: {
            const directory = try session.tag_directory(tag);
            const parts = [_][]const u8{ directory, aws.metadata_file_name };
            const path = try std.fs.path.join(session.arena, &parts);
            if (!session.exists(path)) return session.fail(.{ .metadata_not_found = tag });
            const text = try session.read_file(path);
            const metadata = aws.Metadata.parse(session.arena, text) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return session.fail(.{ .yaml = path }),
            };
            break :blk .{ tag, metadata.regions };
        },
    };
    log.info("loaded configuration: tag={s}", .{tag});
    const directory = try session.tag_directory(tag);
    if (!session.exists(directory)) return session.fail(.{ .deployment_does_not_exist = tag });
    const destroyed = try std.fs.path.join(session.arena, &.{ directory, aws.destroyed_file_name });
    if (session.exists(destroyed)) {
        log.warn("infrastructure already destroyed", .{});
        return;
    }
    try delete_deployment_data(session, tag);
    log.info("removing resources: regions={d}", .{regions.len});
    try for_each_region(session, tag, regions, remove_resources);
    try for_each_region(session, tag, regions, remove_vpcs);
    log.info("resources removed: regions={d}", .{regions.len});
    try session.write_file(destroyed, "");
    log.info("destruction complete: tag={s}", .{tag});
}

/// Deletes the deployment's S3 data (cached tools stay). Without a persisted bucket name the
/// cleanup is skipped: a fresh name would point at no bucket and leave the data behind.
/// Failures are logged, not fatal, as in commonware.
fn delete_deployment_data(session: *Session, tag: []const u8) !void {
    const persisted = try s3.get_bucket_name_if_exists(session.io, session.arena, session.home);
    const bucket = persisted orelse {
        log.warn("no bucket config found, skipping S3 cleanup", .{});
        return;
    };
    log.info("cleaning up S3 deployment data: bucket={s}", .{bucket});
    const prefix = try std.fmt.allocPrint(session.arena, s3.deployments_prefix ++ "/{s}/", .{tag});
    const failure = try s3.delete_prefix(try session.s3(), session.arena, bucket, prefix) orelse {
        log.info("deleted S3 deployment data: bucket={s} prefix={s}", .{ bucket, prefix });
        return;
    };
    if (s3.is_no_such_bucket_error(failure)) {
        log.info("bucket does not exist, skipping S3 cleanup: bucket={s}", .{bucket});
    } else {
        log.warn("failed to delete S3 deployment data, continuing with destroy: bucket={s} " ++
            "error={f}", .{ bucket, failure });
    }
}

const RegionJob = fn (*Session, *ec2_api.Ec2, []const u8, []const u8) anyerror!void;

/// Runs `job` for every region concurrently and returns the first error once all finish.
fn for_each_region(
    session: *Session,
    tag: []const u8,
    regions: []const []const u8,
    comptime job: RegionJob,
) !void {
    assert(regions.len > 0);
    const errors = try session.arena.alloc(?anyerror, regions.len);
    @memset(errors, null);
    var group: Io.Group = .init;
    defer group.cancel(session.io);
    for (regions, errors) |region, *slot| {
        group.async(session.io, run_job(job), .{ session, tag, region, slot });
    }
    try group.await(session.io);
    for (errors) |slot| if (slot) |err| return err;
}

fn run_job(comptime job: RegionJob) fn (*Session, []const u8, []const u8, *?anyerror) void {
    return struct {
        fn run(session: *Session, tag: []const u8, region: []const u8, slot: *?anyerror) void {
            var ec2 = session.ec2(region) catch |err| {
                slot.* = err;
                return;
            };
            job(session, &ec2, region, tag) catch |err| {
                slot.* = session.ec2_failed(&ec2, err);
            };
        }
    }.run;
}

/// The first pass in one region: everything but the VPCs.
fn remove_resources(
    session: *Session,
    ec2: *ec2_api.Ec2,
    region: []const u8,
    tag: []const u8,
) anyerror!void {
    log.info("created EC2 client: region={s}", .{region});
    const instance_ids = try ec2_api.find_instances_by_tag(ec2, tag);
    if (instance_ids.len > 0) {
        try ec2_api.terminate_instances(ec2, instance_ids);
        try ec2_api.wait_for_instances_terminated(ec2, instance_ids);
        log.info("terminated instances: region={s} count={d}", .{ region, instance_ids.len });
    }
    // Listed in every region, as commonware does, before the monitoring region's revokes.
    const groups = try ec2_api.find_security_groups_by_tag(ec2, tag);
    if (std.mem.eql(u8, region, aws.monitoring_region)) {
        try revoke_monitoring_rules(session, ec2, tag, groups);
    }
    for (try ec2_api.find_security_groups_by_tag(ec2, tag)) |group| {
        try ec2_api.wait_for_enis_deleted(ec2, group.id);
        log.info("ENIs deleted from security group: region={s} sg_id={s}", .{ region, group.id });
        try ec2_api.delete_security_group(ec2, group.id);
        log.info("deleted security group: region={s} sg_id={s}", .{ region, group.id });
    }
    for (try ec2_api.find_subnets_by_tag(ec2, tag)) |subnet_id| {
        try ec2_api.delete_subnet(ec2, subnet_id);
        log.info("deleted subnet: region={s} subnet_id={s}", .{ region, subnet_id });
    }
    for (try ec2_api.find_route_tables_by_tag(ec2, tag)) |route_table_id| {
        try ec2_api.delete_route_table(ec2, route_table_id);
        log.info("deleted route table: region={s} rt_id={s}", .{ region, route_table_id });
    }
    for (try ec2_api.find_vpc_peering_by_tag(ec2, tag)) |peering_id| {
        try ec2_api.delete_vpc_peering(ec2, peering_id);
        try ec2_api.wait_for_vpc_peering_deletion(ec2, peering_id);
        log.info("deleted VPC peering connection: region={s} id={s}", .{ region, peering_id });
    }
    for (try ec2_api.find_igws_by_tag(ec2, tag)) |igw_id| {
        if (try ec2_api.find_vpc_by_igw(ec2, igw_id)) |vpc_id| {
            try ec2_api.detach_igw(ec2, igw_id, vpc_id);
            log.info("detached internet gateway: region={s} igw_id={s}", .{ region, igw_id });
        }
        try ec2_api.delete_igw(ec2, igw_id);
        log.info("deleted internet gateway: region={s} igw_id={s}", .{ region, igw_id });
    }
    const key_name = try std.fmt.allocPrint(session.arena, "deployer-{s}", .{tag});
    try ec2_api.delete_key_pair(ec2, key_name);
    log.info("deleted key pair: region={s} key_name={s}", .{ region, key_name });
}

/// Revokes the monitoring group's logs, profiles, and traces rules for the binary group, so
/// both groups can be deleted. Failures are logged, as in commonware.
fn revoke_monitoring_rules(
    session: *Session,
    ec2: *ec2_api.Ec2,
    tag: []const u8,
    groups: []const ec2_api.SecurityGroup,
) !void {
    const binary_name = try std.fmt.allocPrint(session.arena, "{s}-binary", .{tag});
    var monitoring_sg: ?[]const u8 = null;
    var binary_sg: ?[]const u8 = null;
    for (groups) |group| {
        if (std.mem.eql(u8, group.name, tag)) monitoring_sg = group.id;
        if (std.mem.eql(u8, group.name, binary_name)) binary_sg = group.id;
    }
    const monitoring = monitoring_sg orelse return;
    const binary = binary_sg orelse return;
    const rules = [_]struct { []const u8, u16 }{
        .{ "logs", aws.logs_port },
        .{ "profiles", aws.profiles_port },
        .{ "traces", aws.traces_port },
    };
    for (rules) |rule| {
        ec2_api.revoke_group_ingress(ec2, monitoring, rule[1], binary) catch |err| switch (err) {
            error.AwsEc2 => {
                log.warn("failed to revoke {s} ingress rule between monitoring and binary " ++
                    "security groups: error={f}", .{ rule[0], ec2.failure.? });
                continue;
            },
            else => |e| return e,
        };
        log.info("revoked {s} ingress rule between monitoring and binary security groups: " ++
            "monitoring_sg={s} binary_sg={s}", .{ rule[0], monitoring, binary });
    }
}

/// The second pass in one region: the VPCs, once nothing depends on them.
fn remove_vpcs(
    session: *Session,
    ec2: *ec2_api.Ec2,
    region: []const u8,
    tag: []const u8,
) anyerror!void {
    assert(session.home.len > 0);
    for (try ec2_api.find_vpcs_by_tag(ec2, tag)) |vpc_id| {
        try ec2_api.delete_vpc(ec2, vpc_id);
        log.info("deleted VPC: region={s} vpc_id={s}", .{ region, vpc_id });
    }
}

test {
    _ = @import("destroy_test.zig");
}
