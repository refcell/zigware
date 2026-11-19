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
const aws_utils = @import("utils.zig");
const sigv4 = @import("sigv4.zig");
const Failure = @import("failure.zig").Failure;

const Client = client_module.Client;
const builtin = @import("builtin");

const log = std.log.scoped(.deployer);

/// Redirects `download` follows (reqwest's default limit).
pub const redirects_max: u32 = 10;
/// Wait between download attempts (commonware `RETRY_INTERVAL`; none in tests).
pub const download_retry_interval_ms: u64 = if (builtin.is_test) 0 else aws_utils.retry_interval_ms;

/// Where `public_ip` asks for the deployer's public IPv4 address (maintained by Cloudflare).
pub const public_ip_host = "ipv4.icanhazip.com";

/// Largest configuration, metadata, or hosts file read.
pub const file_size_max = deployments.file_size_max;

/// Commands on the instances, over SSH in production (`Ssh`) and recorded in tests.
pub const Remote = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        execute: *const fn (*anyopaque, []const u8, []const u8, []const u8) anyerror!void,
        poll: *const fn (
            *anyopaque,
            []const u8,
            []const u8,
            []const u8,
            aws_utils.ServiceState,
        ) anyerror!void,
        download: *const fn (
            *anyopaque,
            []const u8,
            []const u8,
            []const u8,
            []const u8,
        ) anyerror!void,
        attach: *const fn (*anyopaque, []const u8, []const u8) anyerror!void,
    };

    /// For commands that run nothing on instances: every call fails as SSH would.
    pub const none: Remote = .{ .context = undefined, .vtable = &.{
        .execute = struct {
            fn f(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8) anyerror!void {
                return error.SshFailed;
            }
        }.f,
        .poll = struct {
            fn f(
                _: *anyopaque,
                _: []const u8,
                _: []const u8,
                _: []const u8,
                _: aws_utils.ServiceState,
            ) anyerror!void {
                return error.SshFailed;
            }
        }.f,
        .download = struct {
            fn f(
                _: *anyopaque,
                _: []const u8,
                _: []const u8,
                _: []const u8,
                _: []const u8,
            ) anyerror!void {
                return error.SshFailed;
            }
        }.f,
        .attach = struct {
            fn f(_: *anyopaque, _: []const u8, _: []const u8) anyerror!void {
                return error.SshFailed;
            }
        }.f,
    } };

    /// Runs `command` on `ip` with the key at `key_file` (commonware `ssh_execute`).
    pub fn execute(
        remote: Remote,
        key_file: []const u8,
        ip: []const u8,
        command: []const u8,
    ) !void {
        assert(command.len > 0);
        return remote.vtable.execute(remote.context, key_file, ip, command);
    }

    /// Waits for `service` on `ip` to reach `wanted` (commonware `poll_service_*`).
    pub fn poll(
        remote: Remote,
        key_file: []const u8,
        ip: []const u8,
        service: []const u8,
        wanted: aws_utils.ServiceState,
    ) !void {
        return remote.vtable.poll(remote.context, key_file, ip, service, wanted);
    }

    /// Copies `remote_path` on `ip` to `local_path` (commonware `scp_download`).
    pub fn download(
        remote: Remote,
        key_file: []const u8,
        ip: []const u8,
        remote_path: []const u8,
        local_path: []const u8,
    ) !void {
        return remote.vtable.download(remote.context, key_file, ip, remote_path, local_path);
    }

    /// Opens an interactive shell on `ip` (commonware `ssh_attach`).
    pub fn attach(remote: Remote, key_file: []const u8, ip: []const u8) !void {
        assert(key_file.len > 0);
        assert(ip.len > 0);
        return remote.vtable.attach(remote.context, key_file, ip);
    }
};

/// The production `Remote`: `ssh` and `scp` processes, with commonware's retries.
pub const Ssh = struct {
    gpa: Allocator,
    io: Io,

    pub fn remote(ssh: *Ssh) Remote {
        return .{ .context = ssh, .vtable = &.{
            .execute = execute,
            .poll = poll,
            .download = download,
            .attach = attach,
        } };
    }

    fn attach(context: *anyopaque, key_file: []const u8, ip: []const u8) anyerror!void {
        const ssh: *Ssh = @ptrCast(@alignCast(context));
        return aws_utils.ssh_attach(ssh.io, key_file, ip);
    }

    fn execute(
        context: *anyopaque,
        key_file: []const u8,
        ip: []const u8,
        command: []const u8,
    ) anyerror!void {
        const ssh: *Ssh = @ptrCast(@alignCast(context));
        return aws_utils.ssh_execute(ssh.gpa, ssh.io, key_file, ip, command);
    }

    fn poll(
        context: *anyopaque,
        key_file: []const u8,
        ip: []const u8,
        service: []const u8,
        wanted: aws_utils.ServiceState,
    ) anyerror!void {
        const ssh: *Ssh = @ptrCast(@alignCast(context));
        return aws_utils.poll_service(ssh.gpa, ssh.io, key_file, ip, service, wanted);
    }

    fn download(
        context: *anyopaque,
        key_file: []const u8,
        ip: []const u8,
        remote_path: []const u8,
        local_path: []const u8,
    ) anyerror!void {
        const ssh: *Ssh = @ptrCast(@alignCast(context));
        return aws_utils.scp_download(ssh.gpa, ssh.io, key_file, ip, remote_path, local_path);
    }
};

/// Commands on the deployer's own machine (`ssh-keygen`, `docker`, `gzip`): processes in
/// production (`Processes`), recorded in tests.
pub const Local = struct {
    context: *anyopaque,
    run_fn: *const fn (*anyopaque, Allocator, []const []const u8) anyerror!?[]const u8,

    /// For commands that run nothing locally: every command fails to start.
    pub const none: Local = .{ .context = undefined, .run_fn = struct {
        fn f(_: *anyopaque, _: Allocator, _: []const []const u8) anyerror!?[]const u8 {
            return error.FileNotFound;
        }
    }.f };

    /// Runs `argv` to completion: null when it exits with status 0, else its output as
    /// commonware reports it (stderr, then stdout, each trimmed), allocated from `arena`.
    pub fn run(local: Local, arena: Allocator, argv: []const []const u8) !?[]const u8 {
        assert(argv.len > 0);
        assert(argv[0].len > 0);
        return local.run_fn(local.context, arena, argv);
    }
};

/// The production `Local`: child processes.
pub const Processes = struct {
    io: Io,

    pub fn local(processes: *Processes) Local {
        return .{ .context = processes, .run_fn = run };
    }

    fn run(context: *anyopaque, arena: Allocator, argv: []const []const u8) anyerror!?[]const u8 {
        const processes: *Processes = @ptrCast(@alignCast(context));
        const result = try std.process.run(arena, processes.io, .{
            .argv = argv,
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(1 << 20),
        });
        if (result.term == .exited and result.term.exited == 0) return null;
        const stderr = std.mem.trim(u8, result.stderr, &std.ascii.whitespace);
        const stdout = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
        if (stdout.len == 0) return stderr;
        if (stderr.len == 0) return stdout;
        return try std.fmt.allocPrint(arena, "{s}\n{s}", .{ stderr, stdout });
    }
};

pub const Session = struct {
    io: Io,
    /// Scratch for retried requests.
    gpa: Allocator,
    /// Everything a command returns or keeps lives here.
    arena: Allocator,
    home: []const u8,
    credentials: sigv4.Credentials,
    transport: client_module.Transport,
    remote: Remote = .none,
    local: Local = .none,
    /// Where commands put local scratch files (commonware uses `/tmp`).
    temp: []const u8 = "/tmp",
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

    /// Turns a remote command's `SshFailed` or `ServiceTimeout` into `error.Failed`.
    pub fn remote_failed(
        session: *Session,
        err: anyerror,
        ip: []const u8,
        service: []const u8,
    ) anyerror {
        return switch (err) {
            error.SshFailed => session.fail(.ssh_failed),
            error.ServiceTimeout => session.fail(.{ .service_timeout = .{
                .ip = ip,
                .service = service,
            } }),
            else => err,
        };
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
        Io.Dir.cwd().access(session.io, path, .{}) catch |err| {
            if (err == error.Canceled) session.io.recancel();
            return false;
        };
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

    /// Downloads `url` (HTTP or HTTPS) into `arena`, following redirects, with commonware's
    /// `download_file` retries; fails the command with `download_failed` after the last attempt.
    pub fn download(session: *Session, arena: Allocator, url: []const u8) ![]const u8 {
        assert(split_url(url) != null);
        for (0..aws_utils.max_download_attempts) |attempt| {
            if (try session.download_once(arena, url)) |body| {
                log.info("downloaded file: url={s} size={d}", .{ url, body.len });
                return body;
            }
            log.warn("download attempt failed: url={s} attempt={d}", .{ url, attempt + 1 });
            if (attempt + 1 < aws_utils.max_download_attempts) {
                try session.io.sleep(.fromMilliseconds(download_retry_interval_ms), .awake);
            }
        }
        return session.fail(.{ .download_failed = url });
    }

    /// One download attempt: the body of the first 2xx response, or null on failure.
    fn download_once(session: *Session, arena: Allocator, url: []const u8) !?[]const u8 {
        var location = url;
        for (0..redirects_max + 1) |_| {
            const target = split_url(location) orelse return null;
            const request: client_module.Request = .{
                .method = "GET",
                .scheme = target.scheme,
                .host = target.host,
                .path = target.path,
                .headers = &.{},
                .body = "",
            };
            const outcome = try session.transport.send(arena, &request);
            const response = switch (outcome) {
                .response => |response| response,
                else => return null,
            };
            if (response.status / 100 == 2) return response.body;
            const redirect = switch (response.status) {
                301, 302, 303, 307, 308 => response.header("location"),
                else => null,
            };
            const next = redirect orelse {
                log.warn("download failed: HTTP {d}: {s}", .{ response.status, location });
                return null;
            };
            location = if (std.mem.startsWith(u8, next, "/"))
                try std.fmt.allocPrint(session.arena, "{s}://{s}{s}", .{
                    target.scheme, target.host, next,
                })
            else
                try session.arena.dupe(u8, next);
        }
        log.warn("download failed: too many redirects: {s}", .{url});
        return null;
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

/// An HTTP or HTTPS URL's scheme, host, and path (with any query); null for other schemes.
fn split_url(url: []const u8) ?struct { scheme: []const u8, host: []const u8, path: []const u8 } {
    const scheme: []const u8 = for ([_][]const u8{ "https", "http" }) |name| {
        if (url.len > name.len + 3 and std.mem.startsWith(u8, url, name) and
            std.mem.eql(u8, url[name.len..][0..3], "://")) break name;
    } else return null;
    const rest = url[scheme.len + 3 ..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    if (slash == 0) return null;
    const path = if (slash == rest.len) "/" else rest[slash..];
    assert(path[0] == '/');
    return .{ .scheme = scheme, .host = rest[0..slash], .path = path };
}
