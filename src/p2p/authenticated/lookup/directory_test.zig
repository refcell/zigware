//! Tests for the lookup directory (commonware `lookup/actors/tracker/directory.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
const types = @import("../../types.zig");
const directory_mod = @import("directory.zig");

const Key = cryptography.ed25519.PublicKey;
const Dir = directory_mod.Directory(Key);
const Entry = Dir.Tracked.PeerMap.Entry;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const TestRng = utils.rng.TestRng;
const gpa = testing.allocator;

fn key(seed: u64) Key {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn socket(a: u8, b: u8, c: u8, d: u8, port: u16) codec.SocketAddr {
    return .{ .ip = .{ .v4 = codec.Ipv4.init(a, b, c, d) }, .port = port };
}

fn local(port: u16) types.Address {
    return .{ .symmetric = socket(127, 0, 0, 1, port) };
}

fn ip(a: u8, b: u8, c: u8, d: u8) codec.IpAddr {
    return .{ .v4 = codec.Ipv4.init(a, b, c, d) };
}

const config: directory_mod.Config = .{
    .allow_private_ips = true,
    .allow_dns = true,
    .bypass_ip_check = false,
    .max_sets = 1,
    .peer_connection_cooldown = .from_millis(100),
    .block_duration = .from_secs(100),
};

const epoch: SystemTime = .UNIX_EPOCH;

/// A directory for `key(0)` with metrics under `directory` in `registry`.
fn init_dir(registry: *metrics.Registry, dir_config: directory_mod.Config) !Dir {
    const scope = metrics.Scope.init(registry).child("directory");
    return Dir.init(gpa, key(0), dir_config, &scope);
}

fn at_ms(ms: u64) SystemTime {
    return epoch.saturating_add(.from_millis(ms));
}

/// Tracks `entries` (sorted here) as primary at `index`; returns the teardown list.
fn track(dir: *Dir, index: u64, entries: []const Entry, secondary: []const Entry) !?[]Key {
    const primary = try sorted(entries);
    defer gpa.free(primary);
    const second = try sorted(secondary);
    defer gpa.free(second);
    return dir.track(index, .{ .primary = .init(primary), .secondary = .init(second) });
}

fn sorted(entries: []const Entry) ![]Entry {
    const copy = try gpa.dupe(Entry, entries);
    std.sort.pdq(Entry, copy, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return Key.order(a.key, b.key) == .lt;
        }
    }.less);
    return copy;
}

fn expect_kills(result: ?[]Key, expected: []const Key) !void {
    const kills = result.?;
    defer gpa.free(kills);
    try testing.expectEqual(expected.len, kills.len);
    for (expected, kills) |want, got| try testing.expect(Key.order(want, got) == .eq);
}

test "track returns only live peers for teardown" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const one: Entry = .{ .key = key(1), .value = local(1235) };
    const two: Entry = .{ .key = key(2), .value = local(1236) };
    const three: Entry = .{ .key = key(3), .value = local(1237) };
    try expect_kills(try track(&dir, 0, &.{ one, two }, &.{}), &.{});
    try expect_kills(try track(&dir, 1, &.{ two, three }, &.{}), &.{});
    try expect_kills(try track(&dir, 2, &.{three}, &.{}), &.{});
    try expect_kills(try track(&dir, 3, &.{three}, &.{}), &.{});
    // Repeated and older indices are ignored.
    try testing.expect(try track(&dir, 3, &.{three}, &.{}) == null);
    try testing.expect(try track(&dir, 1, &.{three}, &.{}) == null);
}

test "track kills a connected peer removed from every set" {
    var rng = TestRng.init(0);
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const pk1 = key(1);
    try expect_kills(try track(&dir, 0, &.{.{ .key = pk1, .value = local(1235) }}, &.{}), &.{});
    const metadata = dir.listen(&rng, epoch, pk1, ip(127, 0, 0, 1)).?;
    try testing.expect(dir.connect(epoch, pk1));
    const two: Entry = .{ .key = key(2), .value = local(1236) };
    try expect_kills(try track(&dir, 1, &.{two}, &.{}), &.{pk1});
    try testing.expect(!dir.peers.get(pk1).?.deletable());
    dir.release(metadata);
    try testing.expect(!dir.peers.contains(pk1));
    try testing.expect(Key.order(metadata.public_key(), pk1) == .eq);
}

test "secondary sets remain until eviction and primary wins overlap" {
    var two_sets = config;
    two_sets.max_sets = 2;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, two_sets);
    defer dir.deinit();
    const pk1 = key(1);
    const pk2 = key(2);
    const first: Entry = .{ .key = pk1, .value = local(1235) };
    const second: Entry = .{ .key = pk2, .value = local(1236) };
    try expect_kills(try track(&dir, 0, &.{first}, &.{ first, second }), &.{});
    // pk1 is primary only; pk2 secondary only.
    try testing.expectEqual(@as(usize, 1), dir.peers.get(pk1).?.primary_sets);
    try testing.expectEqual(@as(usize, 0), dir.peers.get(pk1).?.secondary_sets);
    try testing.expectEqual(@as(usize, 1), dir.peers.get(pk2).?.secondary_sets);
    const set = (try dir.peer_set(gpa, 0)).?;
    defer set.free(gpa);
    try testing.expectEqual(@as(usize, 1), set.secondary.len);

    try expect_kills(try track(&dir, 1, &.{}, &.{first}), &.{});
    const everyone = try dir.all(gpa);
    defer everyone.free(gpa);
    // pk1 is primary somewhere, so `all` lists it as primary.
    try testing.expectEqual(@as(usize, 1), everyone.primary.len);
    try testing.expectEqual(@as(usize, 1), everyone.secondary.len);

    try expect_kills(try track(&dir, 2, &.{}, &.{}), &.{});
    try testing.expect(!dir.peers.contains(pk2));
    try testing.expect(dir.peers.contains(pk1));
    try testing.expect(dir.eligible(epoch, pk1));
    try testing.expect(!dir.peers.get(pk1).?.is_outbound_target());
}

test "overwrite updates tracked peers only" {
    var rng = TestRng.init(0);
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const pk1 = key(1);
    try expect_kills(try track(&dir, 0, &.{.{ .key = pk1, .value = local(1235) }}, &.{}), &.{});
    try testing.expect(!dir.overwrite(pk1, local(1235)));
    try testing.expect(dir.overwrite(pk1, local(2000)));
    try testing.expect(!dir.overwrite(key(9), local(2000)));
    try testing.expect(!dir.overwrite(key(0), local(2000)));
    const dialed = dir.dial(&rng, epoch, pk1).?;
    try testing.expectEqual(@as(u16, 2000), dialed.ingress.socket.port);
    // A new address while reserved forces teardown on the next track.
    try testing.expect(dir.overwrite(pk1, local(3000)));
    try testing.expect(!dir.connect(epoch, pk1));
    dir.release(dialed.metadata);
}

test "blocked peers are not dialable, acceptable, listenable, or eligible" {
    var rng = TestRng.init(0);
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const pk1 = key(1);
    try expect_kills(try track(&dir, 0, &.{.{ .key = pk1, .value = local(1235) }}, &.{}), &.{});
    try testing.expect(try dir.block(epoch, pk1));
    try testing.expect(!try dir.block(epoch, pk1));
    try testing.expect(!try dir.block(epoch, key(0)));
    try testing.expect(!dir.eligible(epoch, pk1));
    try testing.expect(!dir.acceptable(epoch, pk1, ip(127, 0, 0, 1)));
    try testing.expect(dir.dial(&rng, epoch, pk1) == null);
    const ips = try dir.listenable(gpa, epoch);
    defer gpa.free(ips);
    try testing.expectEqual(@as(usize, 0), ips.len);
    const dialable = try dir.dialable(gpa, epoch);
    defer gpa.free(dialable.peers);
    try testing.expectEqual(@as(usize, 0), dialable.peers.len);
    try testing.expectEqual(at_ms(100_000), dialable.next_query_at.?);
    const blocked = try dir.blocked_peers(gpa, epoch);
    defer gpa.free(blocked);
    try testing.expectEqual(@as(usize, 1), blocked.len);
    try testing.expectEqual(at_ms(100_000), dir.next_unblock().?);

    // An expired block no longer applies, even before `unblock_expired` removes it.
    const later = at_ms(100_000);
    try testing.expect(dir.eligible(later, pk1));
    try testing.expect(try dir.block(later, pk1));
    try testing.expect(!dir.unblock_expired(later));
    try testing.expect(dir.unblock_expired(at_ms(200_000)));
    try testing.expect(dir.next_unblock() == null);
}

test "block with an unbounded duration saturates" {
    var unbounded = config;
    unbounded.block_duration = .max;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, unbounded);
    defer dir.deinit();
    try testing.expect(try dir.block(epoch, key(1)));
    try testing.expect(!dir.eligible(.{ .nanos_since_epoch = 1 << 100 }, key(1)));
}

test "blocking a peer before it is tracked" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const pk1 = key(1);
    try testing.expect(try dir.block(epoch, pk1));
    try expect_kills(try track(&dir, 0, &.{.{ .key = pk1, .value = local(1235) }}, &.{}), &.{});
    try testing.expect(!dir.eligible(epoch, pk1));
    try testing.expect(dir.eligible(at_ms(100_000), pk1));
}

test "reservations rate limit redials and set next_query_at" {
    var rng = TestRng.init(0);
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const pk1 = key(1);
    try expect_kills(try track(&dir, 0, &.{.{ .key = pk1, .value = local(1235) }}, &.{}), &.{});
    const empty = try dir.dialable(gpa, epoch);
    defer gpa.free(empty.peers);
    try testing.expectEqual(@as(usize, 1), empty.peers.len);
    const first = dir.dial(&rng, epoch, pk1).?;
    dir.release(first.metadata);
    try testing.expect(dir.dial(&rng, epoch, pk1) == null);
    const after = try dir.dialable(gpa, epoch);
    defer gpa.free(after.peers);
    try testing.expectEqual(@as(usize, 0), after.peers.len);
    const next = after.next_query_at.?;
    try testing.expect(next.order(at_ms(100)) != .lt and next.order(at_ms(200)) != .gt);
    try testing.expect(dir.dial(&rng, next, pk1) != null);
}

test "dns and private addresses follow the config" {
    var rng = TestRng.init(0);
    var strict = config;
    strict.allow_dns = false;
    strict.allow_private_ips = false;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, strict);
    defer dir.deinit();
    const host = utils.Hostname.literal("example.com");
    const dns: types.Address = .{ .asymmetric = .{
        .ingress = .{ .dns = .{ .host = host, .port = 8080 } },
        .egress = socket(8, 8, 8, 8, 9090),
    } };
    const private: Entry = .{ .key = key(2), .value = local(1236) };
    const named: Entry = .{ .key = key(1), .value = dns };
    try expect_kills(try track(&dir, 0, &.{ named, private }, &.{}), &.{});
    try testing.expect(dir.dial(&rng, epoch, key(1)) == null);
    try testing.expect(dir.dial(&rng, epoch, key(2)) == null);
    const ips = try dir.listenable(gpa, epoch);
    defer gpa.free(ips);
    try testing.expectEqual(@as(usize, 1), ips.len);
    try testing.expect(ips[0].order(ip(8, 8, 8, 8)) == .eq);
}

/// The value of `name`'s sample for `peer`, if any (commonware's `metric_value`).
fn metric_value(registry: *metrics.Registry, name: []const u8, peer: Key) !?i64 {
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    var prefix_buffer: [256]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buffer, "{s}{{peer=\"{f}\"}} ", .{ name, peer });
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        return try std.fmt.parseInt(i64, line[prefix.len..], 10);
    }
    return null;
}

fn has_value(registry: *metrics.Registry, name: []const u8, value: anytype) !bool {
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    return metrics.has_metric_value(text, name, value);
}

test "the connected metric tracks active peers" {
    // commonware `test_connected_metric_tracks_active_peers`, plus the tracked and reserved
    // gauges along the way.
    var rng = TestRng.init(0);
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const pk1 = key(1);
    try testing.expect(try has_value(&registry, "directory_tracked", 0));
    try expect_kills(try track(&dir, 0, &.{.{ .key = pk1, .value = local(1235) }}, &.{}), &.{});
    const reservation = dir.listen(&rng, at_ms(1_000), pk1, ip(127, 0, 0, 1)).?;
    try testing.expect(dir.connect(at_ms(1_234), pk1));
    const connected = "directory_connected";
    try testing.expectEqual(@as(?i64, 1_234), try metric_value(&registry, connected, pk1));
    try testing.expect(try has_value(&registry, "directory_tracked", 1));
    try testing.expect(try has_value(&registry, "directory_reserved", 1));
    dir.release(reservation);
    try testing.expectEqual(@as(?i64, null), try metric_value(&registry, connected, pk1));
    try testing.expect(try has_value(&registry, "directory_reserved", 0));
}

test "an address change of a secondary peer counts an update" {
    // commonware `test_track_updates_metric_for_secondary_address_change`.
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var three_sets = config;
    three_sets.max_sets = 3;
    var dir = try init_dir(&registry, three_sets);
    defer dir.deinit();
    const pk1 = key(1);
    const updates = "directory_updates_total";
    try expect_kills(try track(&dir, 0, &.{}, &.{.{ .key = pk1, .value = local(1235) }}), &.{});
    try testing.expectEqual(@as(?i64, null), try metric_value(&registry, updates, pk1));
    try expect_kills(try track(&dir, 1, &.{}, &.{.{ .key = pk1, .value = local(1236) }}), &.{});
    try testing.expectEqual(@as(?i64, 1), try metric_value(&registry, updates, pk1));
}

test "the blocked metric outlives the record until the block expires" {
    // commonware `test_unblock_expired_peer_removed_and_readded`.
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const pk1 = key(1);
    const blocked = "directory_blocked";
    const entry_1: Entry = .{ .key = pk1, .value = local(1235) };
    try testing.expectEqual(@as(?i64, null), try metric_value(&registry, blocked, pk1));
    try expect_kills(try track(&dir, 0, &.{entry_1}, &.{}), &.{});
    try testing.expect(try dir.block(at_ms(500), pk1));
    // block_duration is 100 s.
    try testing.expectEqual(@as(?i64, 100_500), try metric_value(&registry, blocked, pk1));
    // Evicting the only set deletes pk1's record; its block and series remain.
    try expect_kills(try track(&dir, 1, &.{.{ .key = key(2), .value = local(1236) }}, &.{}), &.{});
    try testing.expect(!dir.peers.contains(pk1));
    try testing.expect(try has_value(&registry, "directory_tracked", 1));
    try testing.expectEqual(@as(?i64, 100_500), try metric_value(&registry, blocked, pk1));
    try expect_kills(try track(&dir, 2, &.{entry_1}, &.{}), &.{});
    try testing.expect(!dir.eligible(at_ms(500), pk1));
    try testing.expectEqual(@as(?i64, 100_500), try metric_value(&registry, blocked, pk1));
    try testing.expect(dir.unblock_expired(at_ms(101_500)));
    try testing.expectEqual(@as(?i64, null), try metric_value(&registry, blocked, pk1));
}

test "the blocked metric covers several peers" {
    // commonware `test_blocked_metric_multiple_peers`.
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const peers = [_]Entry{
        .{ .key = key(1), .value = local(1235) },
        .{ .key = key(2), .value = local(1236) },
        .{ .key = key(3), .value = local(1237) },
    };
    try expect_kills(try track(&dir, 0, &peers, &.{}), &.{});
    for (peers) |peer| {
        try testing.expect(try dir.block(epoch, peer.key));
        const value = try metric_value(&registry, "directory_blocked", peer.key);
        try testing.expectEqual(@as(?i64, 100_000), value);
    }
    try testing.expect(!try dir.block(epoch, peers[0].key));
    try testing.expect(dir.unblock_expired(at_ms(101_000)));
    for (peers) |peer| {
        const value = try metric_value(&registry, "directory_blocked", peer.key);
        try testing.expectEqual(@as(?i64, null), value);
    }
}

test "blocking ourselves records nothing" {
    // commonware `test_block_myself_no_panic_on_expiry`.
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    try testing.expect(!try dir.block(epoch, key(0)));
    const value = try metric_value(&registry, "directory_blocked", key(0));
    try testing.expectEqual(@as(?i64, null), value);
    try testing.expect(!dir.unblock_expired(at_ms(101_000)));
}
