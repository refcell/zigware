//! AWS credentials for the signed client: the first two providers of the SDK's default chain,
//! which commonware loads through `aws_config::defaults`. The environment
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) wins; otherwise the
//! profile `AWS_PROFILE` (default `default`) of the shared credentials file
//! (`AWS_SHARED_CREDENTIALS_FILE`, default `{home}/.aws/credentials`). The instance metadata,
//! SSO, and process providers are not ported: the deployer runs on an operator's machine.
//! Nothing here is logged.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Environ = std.process.Environ;
const sigv4 = @import("sigv4.zig");

const Credentials = sigv4.Credentials;

/// Credentials from the environment, when both the key ID and the secret are set.
pub fn from_environ(environ: *const Environ.Map) ?Credentials {
    const key_id = environ.get("AWS_ACCESS_KEY_ID") orelse return null;
    const secret = environ.get("AWS_SECRET_ACCESS_KEY") orelse return null;
    if (key_id.len == 0 or secret.len == 0) return null;
    const token = environ.get("AWS_SESSION_TOKEN");
    return .{
        .access_key_id = key_id,
        .secret_access_key = secret,
        .session_token = if (token) |value| if (value.len == 0) null else value else null,
    };
}

/// The credentials of `profile` in a shared credentials file (INI: `[profile]` sections of
/// `key = value` lines; `#` and `;` start comments). Values borrow `text`.
pub fn parse_profile(text: []const u8, profile: []const u8) ?Credentials {
    assert(profile.len > 0);
    var key_id: ?[]const u8 = null;
    var secret: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var in_profile = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        if (line[0] == '[') {
            const close = std.mem.indexOfScalar(u8, line, ']') orelse return null;
            const name = std.mem.trim(u8, line[1..close], " \t");
            in_profile = std.mem.eql(u8, name, profile);
            continue;
        }
        if (!in_profile) continue;
        const equals = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const value = std.mem.trim(u8, line[equals + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(key, "aws_access_key_id")) key_id = value;
        if (std.ascii.eqlIgnoreCase(key, "aws_secret_access_key")) secret = value;
        if (std.ascii.eqlIgnoreCase(key, "aws_session_token")) token = value;
    }
    const id = key_id orelse return null;
    const secret_key = secret orelse return null;
    if (id.len == 0 or secret_key.len == 0) return null;
    return .{ .access_key_id = id, .secret_access_key = secret_key, .session_token = token };
}

/// Credentials from the environment, else from the shared credentials file, else null
/// (allocates the file's contents from `arena`).
pub fn load(
    io: Io,
    arena: Allocator,
    environ: *const Environ.Map,
    home: []const u8,
) !?Credentials {
    if (from_environ(environ)) |credentials| return credentials;
    const path = environ.get("AWS_SHARED_CREDENTIALS_FILE") orelse
        try std.fmt.allocPrint(arena, "{s}/.aws/credentials", .{home});
    const text = Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20)) catch |err| {
        return switch (err) {
            error.Canceled, error.OutOfMemory => |e| e,
            else => null,
        };
    };
    const profile = environ.get("AWS_PROFILE") orelse "default";
    return parse_profile(text, if (profile.len == 0) "default" else profile);
}

const testing = std.testing;

test "credentials: the environment wins and needs both keys" {
    var environ: Environ.Map = .init(testing.allocator);
    defer environ.deinit();
    try testing.expectEqual(null, from_environ(&environ));
    try environ.put("AWS_ACCESS_KEY_ID", "id");
    try testing.expectEqual(null, from_environ(&environ));
    try environ.put("AWS_SECRET_ACCESS_KEY", "secret");
    try environ.put("AWS_SESSION_TOKEN", "");
    const found = from_environ(&environ).?;
    try testing.expectEqualStrings("id", found.access_key_id);
    try testing.expectEqual(null, found.session_token);
    try environ.put("AWS_SESSION_TOKEN", "token");
    try testing.expectEqualStrings("token", from_environ(&environ).?.session_token.?);
}

test "credentials: profiles parse from the shared credentials file" {
    const text =
        \\# shared credentials
        \\[default]
        \\aws_access_key_id = default-id
        \\aws_secret_access_key=default-secret
        \\
        \\[ work ]
        \\; a comment
        \\AWS_ACCESS_KEY_ID = work-id
        \\aws_secret_access_key = work-secret
        \\aws_session_token = work-token
        \\[empty]
        \\aws_access_key_id =
        \\aws_secret_access_key = s
    ;
    const default = parse_profile(text, "default").?;
    try testing.expectEqualStrings("default-id", default.access_key_id);
    try testing.expectEqualStrings("default-secret", default.secret_access_key);
    try testing.expectEqual(null, default.session_token);
    const work = parse_profile(text, "work").?;
    try testing.expectEqualStrings("work-id", work.access_key_id);
    try testing.expectEqualStrings("work-token", work.session_token.?);
    try testing.expectEqual(null, parse_profile(text, "empty"));
    try testing.expectEqual(null, parse_profile(text, "missing"));
    try testing.expectEqual(null, parse_profile("[default", "default"));
}

test "credentials: load falls back to the file named by the environment" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{
        .sub_path = "credentials",
        .data = "[ci]\naws_access_key_id = a\naws_secret_access_key = b\n",
    });
    var environ: Environ.Map = .init(testing.allocator);
    defer environ.deinit();
    const home = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    // No environment keys and no `{home}/.aws/credentials`.
    try testing.expectEqual(null, try load(io, arena, &environ, home));
    const path = try std.fmt.allocPrint(arena, "{s}/credentials", .{home});
    try environ.put("AWS_SHARED_CREDENTIALS_FILE", path);
    try testing.expectEqual(null, try load(io, arena, &environ, home)); // No `default` profile.
    try environ.put("AWS_PROFILE", "ci");
    try testing.expectEqualStrings("a", (try load(io, arena, &environ, home)).?.access_key_id);
}
