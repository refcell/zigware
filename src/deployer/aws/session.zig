//! What every deployer command shares: the `Io`, allocators, home directory, credentials, and
//! HTTP transport, from which it makes a signed client per region. A command that fails for a
//! reason commonware reports as `deployer::aws::Error` returns `error.Failed` with the reason in
//! `Session.failure`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const aws = @import("mod.zig");
const client_module = @import("client.zig");
const deployments = @import("deployments.zig");
const ec2_api = @import("ec2_api.zig");
const sigv4 = @import("sigv4.zig");
const Failure = @import("failure.zig").Failure;

const Client = client_module.Client;

/// Where `public_ip` asks for the deployer's public IPv4 address (maintained by Cloudflare).
pub const public_ip_host = "ipv4.icanhazip.com";

/// Largest configuration, metadata, or hosts file read.
pub const file_size_max = deployments.file_size_max;

pub const Session = struct {
    io: Io,
    /// Scratch for retried requests.
    gpa: Allocator,
    /// Everything a command returns or keeps lives here.
    arena: Allocator,
    home: []const u8,
    credentials: sigv4.Credentials,
    transport: client_module.Transport,
    /// Why the command failed; the first failure wins when region jobs run concurrently.
    failure: ?Failure = null,
    failed: std.atomic.Value(bool) = .init(false),

    /// Records `failure` as the reason the command failed, unless one is already recorded.
    pub fn fail(session: *Session, failure: Failure) error{Failed} {
        if (session.failed.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
            session.failure = failure;
        }
        assert(session.failed.load(.acquire));
        return error.Failed;
    }

    /// A signed client for `region` (allocated from the arena, so it outlives the call).
    pub fn client(session: *Session, region: []const u8) !*const Client {
        assert(region.len > 0);
        const made = try session.arena.create(Client);
        made.* = .{
            .io = session.io,
            .transport = session.transport,
            .credentials = session.credentials,
            .region = try session.arena.dupe(u8, region),
        };
        return made;
    }

    pub fn ec2(session: *Session, region: []const u8) !ec2_api.Ec2 {
        return .{ .client = try session.client(region), .arena = session.arena };
    }

    /// The S3 client: the shared bucket lives in the monitoring region.
    pub fn s3(session: *Session) !*const Client {
        return session.client(aws.monitoring_region);
    }

    /// Turns `error.AwsEc2` from `ec2` into `error.Failed` with its failure.
    pub fn ec2_failed(session: *Session, caller: *const ec2_api.Ec2, err: anyerror) anyerror {
        if (err != error.AwsEc2) return err;
        return session.fail(.{ .aws_ec2 = caller.failure.? });
    }

    /// `{home}/.commonware_deployer/{tag}`.
    pub fn tag_directory(session: *Session, tag: []const u8) ![]const u8 {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try deployments.deployer_directory(&buffer, session.home, tag);
        return session.arena.dupe(u8, path);
    }

    pub fn exists(session: *Session, path: []const u8) bool {
        Io.Dir.cwd().access(session.io, path, .{}) catch return false;
        return true;
    }

    /// Reads a whole file, or fails the command with an IO error.
    pub fn read_file(session: *Session, path: []const u8) ![]const u8 {
        const limit: Io.Limit = .limited(file_size_max);
        return Io.Dir.cwd().readFileAlloc(session.io, path, session.arena, limit) catch |err| {
            return switch (err) {
                error.Canceled, error.OutOfMemory => |e| e,
                else => session.fail(.{ .io = .{ .path = path, .err = err } }),
            };
        };
    }

    /// Writes a whole file, or fails the command with an IO error.
    pub fn write_file(session: *Session, path: []const u8, data: []const u8) !void {
        Io.Dir.cwd().writeFile(session.io, .{ .sub_path = path, .data = data }) catch |err| {
            return switch (err) {
                error.Canceled => error.Canceled,
                else => session.fail(.{ .io = .{ .path = path, .err = err } }),
            };
        };
    }

    /// Loads a deployment configuration.
    pub fn load_config(session: *Session, path: []const u8) !aws.Config {
        const text = try session.read_file(path);
        return aws.Config.parse(session.arena, text) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => session.fail(.{ .yaml = path }),
        };
    }

    /// The deployer's public IPv4 address (commonware `get_public_ip`).
    pub fn public_ip(session: *Session) ![]const u8 {
        const request: client_module.Request = .{
            .method = "GET",
            .host = public_ip_host,
            .path = "/",
            .headers = &.{},
            .body = "",
        };
        const outcome = try session.transport.send(session.arena, &request);
        const response = switch (outcome) {
            .response => |response| response,
            else => return session.fail(.{ .io = .{
                .path = "https://" ++ public_ip_host,
                .err = error.ConnectionFailed,
            } }),
        };
        const ip = std.mem.trim(u8, response.body, " \t\r\n");
        if (response.status != 200 or ip.len == 0) return session.fail(.{ .io = .{
            .path = "https://" ++ public_ip_host,
            .err = error.UnexpectedResponse,
        } });
        return ip;
    }

    /// The regions a configuration touches: the monitoring region and each instance's,
    /// sorted and distinct.
    pub fn regions_of(session: *Session, config: *const aws.Config) ![]const []const u8 {
        var regions: std.ArrayList([]const u8) = .empty;
        try regions.append(session.arena, aws.monitoring_region);
        for (config.instances) |instance| {
            const known = for (regions.items) |region| {
                if (std.mem.eql(u8, region, instance.region)) break true;
            } else false;
            if (!known) try regions.append(session.arena, instance.region);
        }
        std.sort.pdq([]const u8, regions.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.less);
        assert(regions.items.len >= 1);
        return regions.items;
    }
};
