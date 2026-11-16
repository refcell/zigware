//! The `profile` command (commonware `profile.rs`): captures a CPU profile of an instance's
//! binary with samply, downloads it, and opens it locally with the debug binary's symbols.
//!
//! `capture` does everything up to opening the profile, so tests run it over scripted AWS
//! responses and a recorded `Remote`; `profile` adds the local `samply load`.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const aws = @import("mod.zig");
const ec2_api = @import("ec2_api.zig");
const s3 = @import("s3.zig");
const services = @import("services.zig");
const Session = @import("session.zig").Session;

const log = std.log.scoped(.deployer);

/// The script that installs samply if needed and records the binary for `duration_s` seconds
/// (commonware's `format!` string, byte for byte).
pub const script_template = services.expand("set -e\n\n" ++
    "# Download and extract samply if not present\n" ++
    "if [ ! -f <home>/samply ]; then\n    " ++ s3.wget ++
    \\ -O /tmp/samply.tar.xz '{s}'
    \\    tar -xJf /tmp/samply.tar.xz -C <home> --strip-components=1
    \\    chmod +x <home>/samply
    \\    rm /tmp/samply.tar.xz
    \\fi
    \\
    \\# Get binary PID
    \\PID=$(systemctl show --property MainPID binary.service | cut -d= -f2)
    \\if [ -z "$PID" ] || [ "$PID" -eq 0 ]; then
    \\    echo "ERROR: binary.service not running" >&2
    \\    exit 1
    \\fi
    \\
    \\echo "Profiling PID $PID for {d} seconds..."
    \\
    \\# Record profile (use timeout with SIGINT so samply saves the profile)
    \\rm -f /tmp/profile.json
    \\sudo timeout -s INT {d}s <home>/samply record -p $PID -s -o /tmp/profile.json || true
    \\sudo chown ubuntu:ubuntu /tmp/profile.json
    \\
    \\echo "Profile captured successfully"
    \\
);

/// Where the profile lands on the instance.
pub const remote_profile_path = "/tmp/profile.json";

/// What `capture` leaves locally for `samply load`.
pub const Capture = struct {
    /// `{temp}/profile-{instance}-{timestamp}.json`.
    profile_path: []const u8,
    /// `{temp}/symbols-{instance}-{timestamp}`, holding the debug binary as `binary`.
    symbol_dir: []const u8,
};

/// Captures a CPU profile of `instance_name` for `duration_s` seconds and opens it with
/// samply, symbolicated with `binary_path` (commonware `profile`).
pub fn profile(
    session: *Session,
    config_path: []const u8,
    instance_name: []const u8,
    duration_s: u64,
    binary_path: []const u8,
) !void {
    const captured = try capture(session, config_path, instance_name, duration_s, binary_path);
    log.info("opening profile with samply: binary={s} symbol_dir={s}", .{
        binary_path, captured.symbol_dir,
    });
    const argv: []const []const u8 = &.{
        "samply", "load", captured.profile_path, "--symbol-dir", captured.symbol_dir,
    };
    var child = std.process.spawn(session.io, .{ .argv = argv }) catch |err| {
        return session.fail(.{ .io = .{ .path = "samply", .err = err } });
    };
    const term = try child.wait(session.io);
    const ok = term == .exited and term.exited == 0;
    if (!ok) return session.fail(.{ .symbolication = "samply load failed" });
}

/// Everything `profile` does before `samply load`.
pub fn capture(
    session: *Session,
    config_path: []const u8,
    instance_name: []const u8,
    duration_s: u64,
    binary_path: []const u8,
) !Capture {
    assert(instance_name.len > 0);
    const config = try session.load_config(config_path);
    const tag = config.tag;
    log.info("loaded configuration: tag={s}", .{tag});
    const instance = for (config.instances) |instance| {
        if (std.mem.eql(u8, instance.name, instance_name)) break instance;
    } else return session.fail(.{ .instance_not_found = instance_name });
    const private_key = try deployment_key(session, tag);

    var ec2 = try session.ec2(instance.region);
    const found = ec2_api.find_running_instance_ip(&ec2, tag, instance_name) catch |err| {
        return session.ec2_failed(&ec2, err);
    };
    const ip = found orelse return session.fail(.{ .instance_not_found = instance_name });
    log.info("found instance: instance={s} ip={s}", .{ instance_name, ip });
    const architecture = ec2_api.detect_architecture(&ec2, instance.instance_type) catch |err| {
        return session.ec2_failed(&ec2, err);
    };
    log.info("detected architecture: architecture={s}", .{architecture.as_str()});
    const samply_url = try samply_presigned_url(session, architecture);

    const script = try std.fmt.allocPrint(session.arena, script_template, .{
        samply_url, duration_s, duration_s,
    });
    log.info("starting profile capture: instance={s} duration={d}", .{ instance_name, duration_s });
    session.remote.execute(private_key, ip, script) catch |err| {
        return session.remote_failed(err, ip, "binary");
    };
    log.info("profile capture complete", .{});

    const now_s: u64 = @intCast(@max(0, Io.Clock.real.now(session.io).toSeconds()));
    const profile_path = try std.fmt.allocPrint(session.arena, "{s}/profile-{s}-{d}.json", .{
        session.temp, instance_name, now_s,
    });
    session.remote.download(private_key, ip, remote_profile_path, profile_path) catch |err| {
        return session.remote_failed(err, ip, "binary");
    };
    log.info("downloaded profile: profile={s}", .{profile_path});
    const symbol_dir = try copy_symbols(session, binary_path, instance_name, now_s);
    return .{ .profile_path = profile_path, .symbol_dir = symbol_dir };
}

/// The deployment's private key, after checking it was created and not destroyed.
fn deployment_key(session: *Session, tag: []const u8) ![]const u8 {
    const directory = try session.tag_directory(tag);
    const created = try std.fs.path.join(session.arena, &.{ directory, aws.created_file_name });
    if (!session.exists(created)) return session.fail(.{ .deployment_not_complete = tag });
    const destroyed = try std.fs.path.join(session.arena, &.{ directory, aws.destroyed_file_name });
    if (session.exists(destroyed)) return session.fail(.{ .deployment_already_destroyed = tag });
    const key_name = try std.fmt.allocPrint(session.arena, "id_rsa_{s}", .{tag});
    const private_key = try std.fs.path.join(session.arena, &.{ directory, key_name });
    if (!session.exists(private_key)) return session.fail(.private_key_not_found);
    assert(private_key.len > directory.len);
    return private_key;
}

/// A presigned URL of samply's release archive in the shared bucket, uploading it from GitHub
/// first when the bucket lacks it.
fn samply_presigned_url(session: *Session, architecture: aws.Architecture) ![]const u8 {
    const bucket = try s3.get_bucket_name(session.io, session.arena, session.home);
    const client = try session.s3();
    if (try s3.ensure_bucket_exists(client, session.arena, bucket)) |failure| {
        return session.fail(failure);
    }
    var key: Io.Writer.Allocating = .init(session.arena);
    try services.write_samply_bin_s3_key(&key.writer, services.samply_version, architecture);
    const samply_key = key.written();
    switch (try s3.object_exists(client, session.arena, bucket, samply_key)) {
        .failure => |failure| return session.fail(failure),
        .ok => |exists| if (exists) {
            log.info("samply already in S3: key={s}", .{samply_key});
            const expires_s = s3.presign_duration_s;
            return s3.presign_url(client, session.arena, bucket, samply_key, expires_s);
        },
    }
    log.info("samply not in S3, downloading and uploading: key={s}", .{samply_key});
    var url: Io.Writer.Allocating = .init(session.arena);
    try services.write_samply_download_url(&url.writer, services.samply_version, architecture);
    // commonware stages the archive in the deployment directory; it is held in memory here.
    const archive = try session.download(url.written());
    const source: s3.UploadSource = .{ .static = archive };
    const expires_s = s3.presign_duration_s;
    const cached = try s3.cache_and_presign(
        client,
        session.arena,
        bucket,
        samply_key,
        source,
        expires_s,
    );
    return switch (cached) {
        .ok => |presigned| presigned,
        .failure => |failure| session.fail(failure),
    };
}

/// Copies the debug binary into a fresh symbol directory as `binary`, the name samply looks
/// for (the remote binary's name).
fn copy_symbols(
    session: *Session,
    binary_path: []const u8,
    instance_name: []const u8,
    now_s: u64,
) ![]const u8 {
    assert(binary_path.len > 0);
    const cwd = Io.Dir.cwd();
    const resolved = cwd.realPathFileAlloc(session.io, binary_path, session.arena) catch |err| {
        const format = "failed to resolve binary path: {t}";
        const why = try std.fmt.allocPrint(session.arena, format, .{err});
        return session.fail(.{ .symbolication = why });
    };
    const symbol_dir = try std.fmt.allocPrint(session.arena, "{s}/symbols-{s}-{d}", .{
        session.temp, instance_name, now_s,
    });
    cwd.createDirPath(session.io, symbol_dir) catch |err| {
        return session.fail(.{ .io = .{ .path = symbol_dir, .err = err } });
    };
    const copy = try std.fs.path.join(session.arena, &.{ symbol_dir, "binary" });
    cwd.copyFile(resolved, cwd, copy, session.io, .{}) catch |err| {
        const why = try std.fmt.allocPrint(session.arena, "failed to copy binary: {t}", .{err});
        return session.fail(.{ .symbolication = why });
    };
    assert(copy.len > symbol_dir.len);
    return symbol_dir;
}

test {
    _ = @import("profile_test.zig");
}
