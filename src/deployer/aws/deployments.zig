//! The deployer's local state (commonware `deployer_directory`, `list.rs`, and `attach.rs`):
//! `$HOME/.commonware_deployer/{tag}` holds a deployment's key, `metadata.yaml`, `hosts.yaml`,
//! and the `created`/`destroyed` status files.
//!
//! Directory reads go through `std.Io.Dir` on the caller's `Io`; the matching and ordering
//! rules are pure and tested here against a temporary directory.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const aws = @import("mod.zig");
const IpAddr = @import("../ip.zig").IpAddr;

/// The deployer's directory under `home`.
pub const directory_name = ".commonware_deployer";
/// The hosts file `create` writes next to the metadata.
pub const hosts_file_name = "hosts.yaml";
/// Largest metadata or hosts file read.
pub const file_size_max = 1 << 20;

/// `{home}/.commonware_deployer`, or `{home}/.commonware_deployer/{tag}` (commonware
/// `deployer_directory`).
pub fn deployer_directory(
    buffer: []u8,
    home: []const u8,
    tag: ?[]const u8,
) error{NoSpaceLeft}![]const u8 {
    assert(home.len > 0);
    const base = try std.fmt.bufPrint(buffer, "{s}/" ++ directory_name, .{home});
    const name = tag orelse return base;
    assert(name.len > 0);
    const rest = try std.fmt.bufPrint(buffer[base.len..], "/{s}", .{name});
    return buffer[0 .. base.len + rest.len];
}

/// Which deployments to load: `list` shows every one not destroyed; `attach` also requires the
/// `created` marker.
pub const Filter = enum { not_destroyed, created };

fn exists(dir: Io.Dir, io: Io, sub_path: []const u8) bool {
    dir.access(io, sub_path, .{}) catch |err| {
        if (err == error.Canceled) io.recancel();
        return false;
    };
    return true;
}

/// The metadata of every deployment in `deployer_dir` passing `filter`, sorted by tag.
/// Deployments with a missing or malformed `metadata.yaml` are skipped, as commonware skips
/// them. Allocates from `arena`.
pub fn load_deployments(
    arena: Allocator,
    io: Io,
    deployer_dir: Io.Dir,
    filter: Filter,
) ![]aws.Metadata {
    var deployments: std.ArrayList(aws.Metadata) = .empty;
    var iterator = deployer_dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var tag_dir = deployer_dir.openDir(io, entry.name, .{}) catch |err| {
            if (err == error.Canceled) return err;
            continue;
        };
        defer tag_dir.close(io);
        if (exists(tag_dir, io, aws.destroyed_file_name)) continue;
        if (filter == .created and !exists(tag_dir, io, aws.created_file_name)) continue;
        const limit: Io.Limit = .limited(file_size_max);
        const text = tag_dir.readFileAlloc(io, aws.metadata_file_name, arena, limit) catch |err| {
            if (err == error.Canceled) return err;
            continue;
        };
        const metadata = aws.Metadata.parse(arena, text) catch continue;
        try deployments.append(arena, metadata);
    }
    // commonware sorts `attach`'s deployments by tag; `list` re-sorts by creation time.
    std.sort.pdq(aws.Metadata, deployments.items, {}, struct {
        fn less(_: void, a: aws.Metadata, b: aws.Metadata) bool {
            return std.mem.order(u8, a.tag, b.tag) == .lt;
        }
    }.less);
    return deployments.items;
}

/// Sorts deployments newest first (commonware `list`); equal times keep tag order.
pub fn sort_newest_first(deployments: []aws.Metadata) void {
    std.sort.insertion(aws.Metadata, deployments, {}, struct {
        fn less(_: void, a: aws.Metadata, b: aws.Metadata) bool {
            return a.created_at > b.created_at;
        }
    }.less);
}

/// Writes `seconds` since the epoch as `%Y-%m-%d %H:%M:%S` in UTC. (commonware formats in the
/// local time zone; zigware has no time zone database, so `list` prints UTC.)
pub fn write_timestamp(writer: *Io.Writer, seconds: u64) Io.Writer.Error!void {
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    try writer.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u32, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

// --- attach ------------------------------------------------------------------------------------

/// A deployed instance `attach` connects to.
pub const InstanceMatch = struct { tag: []const u8, region: []const u8, ip: IpAddr };

/// The address `attach` was given, normalized to Rust's display form (commonware
/// `normalize_ip`): equal addresses compare equal however they were written.
pub fn normalize_ip(text: []const u8) error{InvalidIp}!IpAddr {
    return IpAddr.parse(text);
}

/// The instance of deployment `tag` at `ip`: the monitoring instance's public address, else
/// the first host at `ip`.
pub fn find_host_match(tag: []const u8, hosts: *const aws.Hosts, ip: IpAddr) ?InstanceMatch {
    assert(tag.len > 0);
    if (hosts.monitoring.public.eql(ip)) {
        return .{ .tag = tag, .region = aws.monitoring_region, .ip = ip };
    }
    for (hosts.hosts) |host| {
        if (host.ip.eql(ip)) return .{ .tag = tag, .region = host.region, .ip = ip };
    }
    return null;
}

/// The instance at `ip` among the created, not destroyed deployments in `deployer_dir`,
/// trying deployments in tag order. Unreadable hosts files are skipped.
pub fn find_instance(
    arena: Allocator,
    io: Io,
    deployer_dir: Io.Dir,
    ip: IpAddr,
) !?InstanceMatch {
    const deployments = try load_deployments(arena, io, deployer_dir, .created);
    for (deployments) |metadata| {
        var tag_dir = deployer_dir.openDir(io, metadata.tag, .{}) catch |err| {
            if (err == error.Canceled) return err;
            continue;
        };
        defer tag_dir.close(io);
        const limit: Io.Limit = .limited(file_size_max);
        const text = tag_dir.readFileAlloc(io, hosts_file_name, arena, limit) catch |err| {
            if (err == error.Canceled) return err;
            continue;
        };
        const hosts = aws.Hosts.parse(arena, text) catch continue;
        if (find_host_match(metadata.tag, &hosts, ip)) |found| return found;
    }
    return null;
}

const testing = std.testing;

fn hosts_fixture() !aws.Hosts {
    return .{
        .monitoring = .{
            .public = try IpAddr.parse("2.2.2.2"),
            .private = try IpAddr.parse("10.0.0.1"),
        },
        .hosts = &.{},
    };
}

test "normalize ip" {
    var buffer: [64]u8 = undefined;
    const ip = try normalize_ip("2001:db8:0:0::1");
    try testing.expectEqualStrings("2001:db8::1", try std.fmt.bufPrint(&buffer, "{f}", .{ip}));
}

test "instance match" {
    const selected: InstanceMatch = .{
        .tag = "a",
        .region = "us-east-1",
        .ip = try IpAddr.parse("1.1.1.1"),
    };
    try testing.expectEqualStrings("a", selected.tag);
}

test "find host match" {
    var hosts = try hosts_fixture();
    const host: aws.Host = .{
        .name = "node",
        .region = "us-east-1",
        .ip = try IpAddr.parse("1.1.1.1"),
    };
    hosts.hosts = &.{host};
    const selected = find_host_match("tag", &hosts, try IpAddr.parse("1.1.1.1")).?;
    try testing.expectEqualStrings("tag", selected.tag);
    try testing.expectEqualStrings("us-east-1", selected.region);
    try testing.expect(find_host_match("tag", &hosts, try IpAddr.parse("1.1.1.2")) == null);
}

test "find monitoring match" {
    const hosts = try hosts_fixture();
    const selected = find_host_match("tag", &hosts, try IpAddr.parse("2.2.2.2")).?;
    try testing.expectEqualStrings("tag", selected.tag);
    try testing.expectEqualStrings(aws.monitoring_region, selected.region);
    // The monitoring instance's private address is not an attach target.
    try testing.expect(find_host_match("tag", &hosts, try IpAddr.parse("10.0.0.1")) == null);
}

test "deployer directory" {
    var buffer: [64]u8 = undefined;
    const base = try deployer_directory(&buffer, "/h", null);
    try testing.expectEqualStrings("/h/.commonware_deployer", base);
    const tagged = try deployer_directory(&buffer, "/h", "t");
    try testing.expectEqualStrings("/h/.commonware_deployer/t", tagged);
    var small: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, deployer_directory(&small, "/h", null));
}

test "timestamps print in UTC" {
    var buffer: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try write_timestamp(&writer, 1_700_000_000);
    try testing.expectEqualStrings("2023-11-14 22:13:20", writer.buffered());
    writer = .fixed(&buffer);
    try write_timestamp(&writer, 0);
    try testing.expectEqualStrings("1970-01-01 00:00:00", writer.buffered());
}

fn write_deployment(
    dir: Io.Dir,
    tag: []const u8,
    created_at: u64,
    files: []const []const u8,
) !void {
    const io = testing.io;
    try dir.createDirPath(io, tag);
    var tag_dir = try dir.openDir(io, tag, .{});
    defer tag_dir.close(io);
    var buffer: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    const metadata: aws.Metadata = .{
        .tag = tag,
        .created_at = created_at,
        .regions = &.{"us-east-1"},
        .instance_count = 1,
    };
    try metadata.write(&writer);
    try tag_dir.writeFile(io, .{ .sub_path = aws.metadata_file_name, .data = writer.buffered() });
    for (files) |name| try tag_dir.writeFile(io, .{ .sub_path = name, .data = "" });
}

test "deployments are filtered by their status files" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write_deployment(tmp.dir, "b", 10, &.{aws.created_file_name});
    try write_deployment(tmp.dir, "a", 20, &.{});
    try write_deployment(tmp.dir, "c", 30, &.{ aws.created_file_name, aws.destroyed_file_name });
    try tmp.dir.createDirPath(io, "broken");
    try tmp.dir.writeFile(io, .{ .sub_path = "broken/metadata.yaml", .data = "tag: [" });
    try tmp.dir.writeFile(io, .{ .sub_path = "stray-file", .data = "" });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const listed = try load_deployments(arena.allocator(), io, tmp.dir, .not_destroyed);
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("a", listed[0].tag);
    try testing.expectEqualStrings("b", listed[1].tag);
    sort_newest_first(listed);
    try testing.expectEqualStrings("a", listed[0].tag);
    const created = try load_deployments(arena.allocator(), io, tmp.dir, .created);
    try testing.expectEqual(@as(usize, 1), created.len);
    try testing.expectEqualStrings("b", created[0].tag);

    // attach finds the created deployment's hosts by address.
    var buffer: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    var hosts = try hosts_fixture();
    const host: aws.Host = .{ .name = "n", .region = "eu-west-1", .ip = try IpAddr.parse("::1") };
    hosts.hosts = &.{host};
    try hosts.write(&writer);
    try tmp.dir.writeFile(io, .{ .sub_path = "b/hosts.yaml", .data = writer.buffered() });
    const found = (try find_instance(arena.allocator(), io, tmp.dir, try normalize_ip("0::1"))).?;
    try testing.expectEqualStrings("b", found.tag);
    try testing.expectEqualStrings("eu-west-1", found.region);
    const absent = try find_instance(arena.allocator(), io, tmp.dir, try normalize_ip("::2"));
    try testing.expect(absent == null);
}
