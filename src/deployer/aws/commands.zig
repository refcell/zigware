//! The deployer's small commands (commonware `clean.rs`, `authorize.rs`, `list.rs`, and
//! `attach.rs`).

const std = @import("std");
const assert = std.debug.assert;
const aws = @import("mod.zig");
const aws_utils = @import("utils.zig");
const ec2_api = @import("ec2_api.zig");
const s3 = @import("s3.zig");
const deployments = @import("deployments.zig");
const cli = @import("../cli.zig");
const create_flow = @import("create_flow.zig");
const destroy_module = @import("destroy.zig");
const profile_module = @import("profile.zig");
const update_module = @import("update.zig");
const IpAddr = @import("../ip.zig").IpAddr;
const Session = @import("session.zig").Session;

const log = std.log.scoped(.deployer);

/// Runs a parsed `deployer aws` command (commonware `main`'s dispatch).
pub fn run(session: *Session, command: cli.Aws) !void {
    switch (command) {
        .create => |rollout| {
            try create_flow.create_deployment(session, rollout.config, rollout.concurrency);
        },
        .update => |rollout| {
            try update_module.update(session, rollout.config, rollout.concurrency);
        },
        .authorize => |arguments| _ = try authorize(session, arguments.config, arguments.ip),
        .destroy => |target| try destroy_module.destroy(session, switch (target) {
            .config => |path| .{ .config = path },
            .tag => |tag| .{ .tag = tag },
        }),
        .list => _ = try list(session),
        .clean => try clean(session),
        .profile => |arguments| try profile_module.profile(
            session,
            arguments.config,
            arguments.instance,
            arguments.duration_s,
            arguments.binary,
        ),
        .attach => |arguments| try attach(session, arguments.ip),
    }
}

/// Whether `command` calls AWS, and so needs credentials (`list` and `attach` read only the
/// local deployment directory).
pub fn needs_credentials(command: cli.Aws) bool {
    return switch (command) {
        .list, .attach => false,
        else => true,
    };
}

/// What commonware logs when `command` fails.
pub fn failure_message(command: cli.Aws) []const u8 {
    return switch (command) {
        .create => "failed to create EC2 deployment",
        .update => "failed to update EC2 deployment",
        .authorize => "failed to authorize EC2 deployment",
        .destroy => "failed to destroy EC2 deployment",
        .list => "failed to list deployments",
        .clean => "failed to clean S3 bucket",
        .profile => "failed to profile instance",
        .attach => "failed to attach to instance",
    };
}

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

/// The deployments not destroyed, newest first, each logged (commonware `list`). A missing
/// deployer directory or one with no deployments logs that and returns none.
pub fn list(session: *Session) ![]const aws.Metadata {
    var directory = try open_deployer_directory(session) orelse {
        log.info("no deployments found", .{});
        return &.{};
    };
    defer directory.close(session.io);
    const active = try deployments.load_deployments(
        session.arena,
        session.io,
        directory,
        .not_destroyed,
    );
    if (active.len == 0) log.info("no active deployments", .{});
    deployments.sort_newest_first(active);
    for (active) |metadata| {
        var buffer: [32]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try deployments.write_timestamp(&writer, metadata.created_at);
        log.info("tag={s} created_at={s} regions={f} instances={d}", .{
            metadata.tag,
            writer.buffered(),
            RegionList{ .regions = metadata.regions },
            metadata.instance_count,
        });
    }
    return active;
}

/// Prints regions as Rust's `Debug` prints a `Vec<String>`.
const RegionList = struct {
    regions: []const []const u8,

    pub fn format(list_value: RegionList, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeByte('[');
        for (list_value.regions, 0..) |region, index| {
            if (index > 0) try writer.writeAll(", ");
            try writer.print("\"{s}\"", .{region});
        }
        try writer.writeByte(']');
    }
};

/// Opens an interactive SSH session to the instance at `ip` in any created, not destroyed
/// deployment (commonware `attach`).
pub fn attach(session: *Session, ip: []const u8) !void {
    const address = deployments.normalize_ip(ip) catch return session.fail(.ip_addr_parse);
    const display = try std.fmt.allocPrint(session.arena, "{f}", .{address});
    var directory = try open_deployer_directory(session) orelse {
        return session.fail(.{ .instance_not_found = display });
    };
    defer directory.close(session.io);
    const found = try deployments.find_instance(session.arena, session.io, directory, address);
    const instance = found orelse return session.fail(.{ .instance_not_found = display });
    const tag_directory = try session.tag_directory(instance.tag);
    const key_name = try std.fmt.allocPrint(session.arena, "id_rsa_{s}", .{instance.tag});
    const key = try std.fs.path.join(session.arena, &.{ tag_directory, key_name });
    if (!session.exists(key)) return session.fail(.private_key_not_found);
    log.info("attaching to instance: tag={s} region={s} ip={s}", .{
        instance.tag, instance.region, display,
    });
    session.remote.attach(key, display) catch |err| {
        return session.remote_failed(err, display, "ssh");
    };
}

/// `{home}/.commonware_deployer`, or null when it does not exist.
fn open_deployer_directory(session: *Session) !?std.Io.Dir {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try deployments.deployer_directory(&buffer, session.home, null);
    assert(path.len > session.home.len);
    return std.Io.Dir.cwd().openDir(session.io, path, .{ .iterate = true }) catch |err| {
        return switch (err) {
            error.FileNotFound => null,
            error.Canceled => error.Canceled,
            else => session.fail(.{ .io = .{
                .path = try session.arena.dupe(u8, path),
                .err = err,
            } }),
        };
    };
}

test {
    _ = @import("commands_test.zig");
}
