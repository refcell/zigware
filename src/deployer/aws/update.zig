//! The `update` command (commonware `update.rs`): uploads new binaries and configs, then
//! replaces them in place on every binary instance over SSH.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const aws = @import("mod.zig");
const ec2_api = @import("ec2_api.zig");
const s3 = @import("s3.zig");
const services = @import("services.zig");
const Session = @import("session.zig").Session;

const log = std.log.scoped(.deployer);

/// The command that downloads an instance's new binary and config (commonware's `format!`
/// string, byte for byte; the binary URL is the first argument, the config URL the second).
pub const download_template = services.expand(s3.wget ++
    \\ -O <home>/binary '{s}' &
    \\
++ s3.wget ++
    \\ -O <home>/config.conf '{s}' &
    \\wait
    \\
    \\# Verify all downloads succeeded
    \\for f in binary config.conf; do
    \\    if [ ! -f "<home>/$f" ]; then
    \\        echo "ERROR: Failed to download $f" >&2
    \\        exit 1
    \\    fi
    \\done
    \\
    \\# Ensure the binary is executable
    \\chmod +x <home>/binary
);

/// Updates the binary and config on every binary instance, at most `concurrency` at once
/// (commonware `update`).
pub fn update(session: *Session, config_path: []const u8, concurrency: u64) !void {
    assert(concurrency >= 1);
    const config = try session.load_config(config_path);
    const tag = config.tag;
    log.info("loaded configuration: tag={s}", .{tag});
    const directory = try session.tag_directory(tag);
    const created = try std.fs.path.join(session.arena, &.{ directory, aws.created_file_name });
    if (!session.exists(created)) return session.fail(.{ .deployment_not_complete = tag });
    const destroyed = try std.fs.path.join(session.arena, &.{ directory, aws.destroyed_file_name });
    if (session.exists(destroyed)) return session.fail(.{ .deployment_already_destroyed = tag });
    const key_name = try std.fmt.allocPrint(session.arena, "id_rsa_{s}", .{tag});
    const private_key = try std.fs.path.join(session.arena, &.{ directory, key_name });
    if (!session.exists(private_key)) return session.fail(.private_key_not_found);

    const bucket = try s3.get_bucket_name(session.io, session.arena, session.home);
    log.info("uploading unique binaries and configs to S3", .{});
    const client = try session.s3();
    const instances = config.instances;
    const uploaded = try s3.upload_instance_files(client, session.arena, bucket, tag, instances);
    const urls = switch (uploaded) {
        .ok => |urls| urls,
        .failure => |failure| return session.fail(failure),
    };
    log.info("uploaded all updated binaries and configs", .{});

    var targets: std.ArrayList(Target) = .empty;
    for (try session.regions_of(&config)) |region| {
        var ec2 = try session.ec2(region);
        const found = ec2_api.find_named_instances(&ec2, tag) catch |err| {
            return session.ec2_failed(&ec2, err);
        };
        for (found) |instance| {
            log.info("found instance: region={s} name={s} ip={s}", .{
                region, instance.name, instance.public_ip,
            });
            const known = for (urls) |url| {
                if (std.mem.eql(u8, url.name, instance.name)) break url;
            } else {
                // commonware logs this at error level; the test runner fails on error logs.
                log.warn("instance config not found in config file: name={s}", .{instance.name});
                continue;
            };
            try targets.append(session.arena, .{ .instance = instance, .urls = known });
        }
    }
    try update_all(session, private_key, targets.items, concurrency);
    log.info("update complete", .{});
}

const Target = struct { instance: ec2_api.NamedInstance, urls: s3.InstanceUrls };

/// Runs `update_instance` on every target with `concurrency` workers; the first failure is
/// returned once the workers stop (each stops taking targets after any failure).
fn update_all(
    session: *Session,
    private_key: []const u8,
    targets: []const Target,
    concurrency: u64,
) !void {
    if (targets.len == 0) return;
    const Pool = struct {
        session: *Session,
        private_key: []const u8,
        targets: []const Target,
        next: std.atomic.Value(usize) = .init(0),
        /// The first error's code; zero while none (error codes start at one).
        first_error: std.atomic.Value(u16) = .init(0),

        fn work(pool: *@This()) void {
            while (pool.first_error.load(.acquire) == 0) {
                const index = pool.next.fetchAdd(1, .acq_rel);
                if (index >= pool.targets.len) return;
                const target = pool.targets[index];
                update_instance(pool.session, pool.private_key, target) catch |err| {
                    const ip = target.instance.public_ip;
                    const reported = pool.session.remote_failed(err, ip, "binary");
                    const code = @intFromError(reported);
                    _ = pool.first_error.cmpxchgStrong(0, code, .acq_rel, .acquire);
                    return;
                };
                log.info("updated instance: name={s} ip={s}", .{
                    target.instance.name, target.instance.public_ip,
                });
            }
        }
    };
    var pool: Pool = .{ .session = session, .private_key = private_key, .targets = targets };
    var group: Io.Group = .init;
    defer group.cancel(session.io);
    const workers = @min(concurrency, targets.len);
    for (0..workers) |_| group.async(session.io, Pool.work, .{&pool});
    try group.await(session.io);
    const code = pool.first_error.load(.acquire);
    if (code != 0) return @errorFromInt(code);
}

/// Stops the binary, swaps in the new binary and config, and starts it again (commonware
/// `update_instance`).
fn update_instance(session: *Session, private_key: []const u8, target: Target) !void {
    const ip = target.instance.public_ip;
    const remote = session.remote;
    try remote.execute(private_key, ip, "sudo systemctl stop binary");
    try remote.poll(private_key, ip, "binary", .inactive);
    try remote.execute(private_key, ip, "rm -f " ++ services.home_directory ++ "/binary");
    try remote.execute(private_key, ip, "rm -f " ++ services.home_directory ++ "/config.conf");
    const download = try std.fmt.allocPrint(session.arena, download_template, .{
        target.urls.binary_url, target.urls.config_url,
    });
    try remote.execute(private_key, ip, download);
    try remote.execute(private_key, ip, "sudo systemctl start binary");
    try remote.poll(private_key, ip, "binary", .active);
}

test {
    _ = @import("update_test.zig");
}
