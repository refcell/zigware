//! The deployer's small commands (commonware `clean.rs` and `authorize.rs`).

const std = @import("std");
const assert = std.debug.assert;
const aws = @import("mod.zig");
const aws_utils = @import("utils.zig");
const ec2_api = @import("ec2_api.zig");
const s3 = @import("s3.zig");
const IpAddr = @import("../ip.zig").IpAddr;
const Session = @import("session.zig").Session;

const log = std.log.scoped(.deployer);

/// Deletes the shared bucket and its contents, then the bucket config (commonware `clean`).
/// Only a persisted bucket name is used: minting one here would orphan the real bucket.
pub fn clean(session: *Session) !void {
    const persisted = try s3.get_bucket_name_if_exists(session.io, session.arena, session.home);
    const bucket = persisted orelse {
        log.info("no bucket config found, nothing to clean", .{});
        return;
    };
    log.info("cleaning S3 bucket: bucket={s}", .{bucket});
    const client = try session.s3();
    if (try s3.delete_bucket_and_contents(client, session.arena, bucket)) |failure| {
        if (!s3.is_no_such_bucket_error(failure)) return session.fail(failure);
        log.info("bucket does not exist, nothing to clean: bucket={s}", .{bucket});
    } else {
        log.info("cleaned S3 bucket: bucket={s}", .{bucket});
    }
    try s3.delete_bucket_config(session.io, session.home);
    log.info("deleted bucket config: bucket={s}", .{bucket});
}

/// Checks that the deployment `tag` was created and not destroyed.
pub fn require_created(session: *Session, tag: []const u8) ![]const u8 {
    const directory = try session.tag_directory(tag);
    if (!session.exists(directory)) return session.fail(.{ .deployment_does_not_exist = tag });
    const created = try std.fs.path.join(session.arena, &.{ directory, aws.created_file_name });
    if (!session.exists(created)) return session.fail(.{ .deployment_not_complete = tag });
    const destroyed = try std.fs.path.join(session.arena, &.{ directory, aws.destroyed_file_name });
    if (session.exists(destroyed)) return session.fail(.{ .deployment_already_destroyed = tag });
    return directory;
}

/// Adds the deployer's public IP, or `ip`, to every security group of the deployment
/// (commonware `authorize`). Groups that already allow it are left alone. Returns the IDs of
/// the groups changed.
pub fn authorize(
    session: *Session,
    config_path: []const u8,
    ip: ?[]const u8,
) ![]const []const u8 {
    const config = try session.load_config(config_path);
    log.info("loaded configuration: tag={s}", .{config.tag});
    _ = try require_created(session, config.tag);
    const new_ip = if (ip) |text| try ipv4_text(session, text) else try session.public_ip();
    log.info("adding IP to existing security groups: ip={s}", .{new_ip});
    var buffer: [64]u8 = undefined;
    const cidr = try session.arena.dupe(u8, try aws_utils.exact_cidr(&buffer, new_ip));
    var changes: std.ArrayList([]const u8) = .empty;
    for (try session.regions_of(&config)) |region| {
        var ec2 = try session.ec2(region);
        log.info("created EC2 client: region={s}", .{region});
        const groups = ec2_api.find_security_groups_by_tag(&ec2, config.tag) catch |err| {
            return session.ec2_failed(&ec2, err);
        };
        for (groups) |group| {
            if (allows(group, cidr)) {
                log.info("IP already allowed: sg_id={s}", .{group.id});
                continue;
            }
            ec2_api.authorize_deployer_ingress(&ec2, group.id, cidr) catch |err| {
                return session.ec2_failed(&ec2, err);
            };
            log.info("added ingress rule for IP: sg_id={s}", .{group.id});
            try changes.append(session.arena, group.id);
        }
    }
    log.info("IP added to security groups: changes={d}", .{changes.items.len});
    return changes.items;
}

/// `text` as an IPv4 address in Rust's display form, or the failure commonware reports.
fn ipv4_text(session: *Session, text: []const u8) ![]const u8 {
    const parsed = IpAddr.parse(text) catch return session.fail(.ip_addr_parse);
    const display = try std.fmt.allocPrint(session.arena, "{f}", .{parsed});
    if (parsed != .v4) return session.fail(.{ .ip_addr_not_v4 = display });
    return display;
}

/// Whether `group` has the deployer's exact rule (all TCP ports) for `cidr`. An exact match
/// keeps a rule with other ports or protocols from hiding a missing one.
pub fn allows(group: ec2_api.SecurityGroup, cidr: []const u8) bool {
    assert(cidr.len > 0);
    for (group.ip_permissions) |permission| {
        if (!std.mem.eql(u8, permission.protocol, aws_utils.deployer_protocol)) continue;
        if (permission.from_port != aws_utils.deployer_min_port) continue;
        if (permission.to_port != aws_utils.deployer_max_port) continue;
        for (permission.cidrs) |allowed| if (std.mem.eql(u8, allowed, cidr)) return true;
    }
    return false;
}

test {
    _ = @import("commands_test.zig");
}
