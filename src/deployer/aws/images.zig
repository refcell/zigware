//! Caches container images as gzipped `docker save` tarballs in S3 (commonware `images.rs`).
//!
//! Instances download these tarballs through presigned URLs and `docker load` them, so they
//! never authenticate against a registry. `docker` and `gzip` run through `Session.local`.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const aws = @import("mod.zig");
const s3 = @import("s3.zig");
const services = @import("services.zig");
const Client = @import("client.zig").Client;
const Session = @import("session.zig").Session;

const log = std.log.scoped(.deployer);

/// Caches `image` for `architecture` in `bucket` and returns a presigned download URL. The
/// `docker save` work is skipped when the tarball is already cached (commonware
/// `cache_image`). Scratch tarballs go in `directory`.
pub fn cache_image(
    session: *Session,
    client: *const Client,
    bucket: []const u8,
    directory: []const u8,
    image: []const u8,
    architecture: aws.Architecture,
) ![]const u8 {
    assert(image.len > 0);
    const arena = session.arena;
    var key: Io.Writer.Allocating = .init(arena);
    try services.write_image_s3_key(&key.writer, image, architecture);
    const expires_s = s3.presign_duration_s;
    switch (try s3.object_exists(client, arena, bucket, key.written())) {
        .failure => |failure| return session.fail(failure),
        .ok => |exists| if (exists) {
            log.info("image already cached in S3: image={s} architecture={f}", .{
                image, architecture,
            });
            return s3.presign_url(client, arena, bucket, key.written(), expires_s);
        },
    }
    log.info("caching image to S3: image={s} architecture={f}", .{ image, architecture });
    var stem: Io.Writer.Allocating = .init(arena);
    try services.write_sanitized_image(&stem.writer, image);
    try stem.writer.print("-{s}.tar", .{architecture.as_str()});
    const tar_path = try std.fs.path.join(arena, &.{ directory, stem.written() });
    const gz_path = try std.fmt.allocPrint(arena, "{s}.gz", .{tar_path});
    const platform = try std.fmt.allocPrint(arena, "linux/{s}", .{architecture.as_str()});
    // Pull and save only the target platform: a bare `docker save` exports every manifest of
    // the tag's index and fails on platforms never pulled (see commonware's comment).
    try run_command(session, &.{ "docker", "pull", "--platform", platform, image });
    try run_command(session, &.{ "docker", "save", "--platform", platform, image, "-o", tar_path });
    // `gzip -f` replaces the tar with `{tar}.gz`.
    try run_command(session, &.{ "gzip", "-f", tar_path });
    const source: s3.UploadSource = .{ .file = gz_path };
    const object = key.written();
    const cached = try s3.cache_and_presign(client, arena, bucket, object, source, expires_s);
    const url = switch (cached) {
        .ok => |url| url,
        .failure => |failure| return session.fail(failure),
    };
    // Scratch; commonware ignores a failure too.
    Io.Dir.cwd().deleteFile(session.io, gz_path) catch |err| {
        if (err == error.Canceled) session.io.recancel();
    };
    return url;
}

/// Runs a local command, failing the command with commonware's `CommandFailed` text.
pub fn run_command(session: *Session, argv: []const []const u8) !void {
    assert(argv.len > 1);
    const output = session.local.run(session.arena, argv) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return session.fail(.{ .io = .{ .path = argv[0], .err = err } }),
    };
    const stderr = output orelse return;
    const command = try std.mem.join(session.arena, " ", argv);
    return session.fail(.{ .command_failed = .{ .command = command, .stderr = stderr } });
}
