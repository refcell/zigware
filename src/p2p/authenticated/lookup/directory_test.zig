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

fn public(a: u8, b: u8, c: u8, d: u8, port: u16) types.Address {
    return .{ .symmetric = socket(a, b, c, d, port) };
}

/// Tracks `peer` alone as primary at index 0, which tears nothing down.
fn track_alone(dir: *Dir, peer: Key, address: types.Address) !void {
    try expect_kills(try track(dir, 0, &.{.{ .key = peer, .value = address }}, &.{}), &.{});
}

fn expect_ingress(dir: *const Dir, peer: Key, expected: types.Address) !void {
    const ingress = dir.peers.get(peer).?.ingress().?;
    try testing.expect(ingress.eql(expected.ingress()));
}

fn ip_listed(ips: []const codec.IpAddr, wanted: codec.IpAddr) bool {
    for (ips) |listed| if (listed.order(wanted) == .eq) return true;
    return false;
}

fn expect_listenable(dir: *const Dir, now: SystemTime, wanted: codec.IpAddr, listed: bool) !void {
    const ips = try dir.listenable(gpa, now);
    defer gpa.free(ips);
    try testing.expectEqual(listed, ip_listed(ips, wanted));
}

/// Whether `peer` is dialable at `now`, and that `next_query_at` matches `next`.
fn expect_dialable(dir: *const Dir, now: SystemTime, peer: Key, next: ?SystemTime) !bool {
    const dialable = try dir.dialable(gpa, now);
    defer gpa.free(dialable.peers);
    try testing.expectEqual(next, dialable.next_query_at);
    for (dialable.peers) |listed| if (Key.order(listed, peer) == .eq) return true;
    return false;
}

test "track overwrites addresses and ignores our own" {
    // commonware `test_track_overwrite`.
    var three_sets = config;
    three_sets.max_sets = 3;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, three_sets);
    defer dir.deinit();
    const pk1 = key(1);
    const pk2 = key(2);
    const updates = "directory_updates_total";
    const first: Entry = .{ .key = pk1, .value = local(1235) };
    const second: Entry = .{ .key = pk2, .value = local(1236) };
    try expect_kills(try track(&dir, 0, &.{ first, second }, &.{}), &.{});
    try testing.expect(dir.peers.get(key(0)).?.ingress() == null);
    try expect_ingress(&dir, pk1, local(1235));
    try expect_ingress(&dir, pk2, local(1236));
    try testing.expect(!dir.peers.contains(key(3)));
    try testing.expectEqual(@as(?i64, null), try metric_value(&registry, updates, pk1));
    try expect_kills(try track(&dir, 1, &.{.{ .key = pk1, .value = local(1238) }}, &.{}), &.{});
    try testing.expect(dir.peers.get(key(0)).?.ingress() == null);
    try expect_ingress(&dir, pk1, local(1238));
    try expect_ingress(&dir, pk2, local(1236));
    try testing.expectEqual(@as(?i64, 1), try metric_value(&registry, updates, pk1));
    // Our own address in a set never gives us an ingress.
    try expect_kills(try track(&dir, 2, &.{.{ .key = key(0), .value = local(1237) }}, &.{}), &.{});
    try testing.expect(dir.peers.get(key(0)).?.ingress() == null);
    try expect_ingress(&dir, pk1, local(1238));
    try expect_ingress(&dir, pk2, local(1236));
    try testing.expect(!dir.peers.contains(key(3)));
    try expect_kills(try track(&dir, 3, &.{.{ .key = key(0), .value = local(1234) }}, &.{}), &.{});
    try expect_kills(try track(&dir, 4, &.{.{ .key = key(0), .value = local(1237) }}, &.{}), &.{});
    try testing.expect(try track(&dir, 0, &.{ first, second }, &.{}) == null);
}

test "an address update with a conflicting secondary overlap keeps the primary" {
    // commonware `test_track_primary_wins_conflicting_overlap_when_updating_existing_address`.
    var rng = TestRng.init(0);
    var no_cooldown = config;
    no_cooldown.max_sets = 3;
    no_cooldown.peer_connection_cooldown = .zero;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, no_cooldown);
    defer dir.deinit();
    const pk1 = key(1);
    const old = public(8, 8, 8, 8, 1235);
    const new = public(9, 9, 9, 9, 2235);
    try expect_kills(try track(&dir, 0, &.{.{ .key = pk1, .value = old }}, &.{}), &.{});
    const reservation = dir.listen(&rng, epoch, pk1, ip(8, 8, 8, 8)).?;
    try testing.expect(dir.connect(epoch, pk1));
    const kills = try track(&dir, 1, &.{.{ .key = pk1, .value = new }}, &.{.{
        .key = pk1,
        .value = old,
    }});
    try expect_kills(kills, &.{pk1});
    try testing.expectEqual(@as(?u64, 1), dir.latest_set_index());
    const set = (try dir.peer_set(gpa, 1)).?;
    defer set.free(gpa);
    try testing.expectEqual(@as(usize, 1), set.primary.len);
    try testing.expect(Key.order(set.primary[0], pk1) == .eq);
    try expect_ingress(&dir, pk1, new);
    const everyone = try dir.all(gpa);
    defer everyone.free(gpa);
    try testing.expectEqual(@as(usize, 1), everyone.primary.len);
    try testing.expectEqual(@as(usize, 0), everyone.secondary.len);
    dir.release(reservation);
    try testing.expect(try expect_dialable(&dir, epoch, pk1, null));
    const dialed = dir.dial(&rng, epoch, pk1).?;
    try testing.expect(dialed.ingress.eql(new.ingress()));
    try expect_listenable(&dir, epoch, ip(9, 9, 9, 9), true);
    try expect_listenable(&dir, epoch, ip(8, 8, 8, 8), false);
    dir.release(dialed.metadata);
}

test "a blocked peer stays blocked across an address update" {
    // commonware `test_blocked_peer_remains_blocked_on_update`.
    var three_sets = config;
    three_sets.max_sets = 3;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, three_sets);
    defer dir.deinit();
    const pk1 = key(1);
    try expect_kills(try track(&dir, 0, &.{.{ .key = pk1, .value = local(1235) }}, &.{}), &.{});
    try testing.expect(try dir.block(epoch, pk1));
    try testing.expect(dir.blocked.contains(pk1));
    // Blocking lives in the directory, so the record keeps its address.
    try expect_ingress(&dir, pk1, local(1235));
    try expect_kills(try track(&dir, 1, &.{.{ .key = pk1, .value = local(2235) }}, &.{}), &.{});
    try testing.expect(dir.blocked.contains(pk1));
    try expect_ingress(&dir, pk1, local(2235));
    try testing.expect(dir.unblock_expired(at_ms(101_000)));
    try testing.expect(!dir.blocked.contains(pk1));
    try expect_ingress(&dir, pk1, local(2235));
}

test "asymmetric addresses dial the ingress and listen for the egress" {
    // commonware `test_asymmetric_addresses`.
    var three_sets = config;
    three_sets.max_sets = 3;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, three_sets);
    defer dir.deinit();
    const pk1 = key(1);
    const pk2 = key(2);
    const asymmetric: types.Address = .{ .asymmetric = .{
        .ingress = .{ .socket = socket(10, 0, 0, 1, 8080) },
        .egress = socket(192, 168, 1, 1, 9090),
    } };
    const host = utils.Hostname.literal("node.example.com");
    const dns: types.Address = .{ .asymmetric = .{
        .ingress = .{ .dns = .{ .host = host, .port = 8080 } },
        .egress = socket(192, 168, 1, 2, 9090),
    } };
    const entries = [_]Entry{ .{ .key = pk1, .value = asymmetric }, .{ .key = pk2, .value = dns } };
    try expect_kills(try track(&dir, 0, &entries, &.{}), &.{});
    try expect_ingress(&dir, pk1, asymmetric);
    try testing.expect(dir.peers.get(pk1).?.egress_ip().?.order(ip(192, 168, 1, 1)) == .eq);
    try expect_ingress(&dir, pk2, dns);
    try testing.expect(dir.peers.get(pk2).?.egress_ip().?.order(ip(192, 168, 1, 2)) == .eq);
    try expect_listenable(&dir, epoch, ip(192, 168, 1, 1), true);
    try expect_listenable(&dir, epoch, ip(192, 168, 1, 2), true);
    try expect_listenable(&dir, epoch, ip(10, 0, 0, 1), false);
}

test "a shared listenable IP stays while any of its peers is eligible" {
    // commonware `test_listenable_ip_collision_eligible_wins`.
    var three_sets = config;
    three_sets.max_sets = 3;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, three_sets);
    defer dir.deinit();
    const shared = ip(203, 0, 113, 1);
    const entries = [_]Entry{
        .{ .key = key(1), .value = public(203, 0, 113, 1, 8080) },
        .{ .key = key(2), .value = public(203, 0, 113, 1, 8081) },
    };
    try expect_kills(try track(&dir, 0, &entries, &.{}), &.{});
    try expect_listenable(&dir, epoch, shared, true);
    try testing.expect(try dir.block(epoch, key(1)));
    try expect_listenable(&dir, epoch, shared, true);
    try testing.expect(try dir.block(epoch, key(2)));
    try expect_listenable(&dir, epoch, shared, false);
}

test "an empty directory has nothing to dial and no query deadline" {
    // commonware `test_dialable_empty`.
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const dialable = try dir.dialable(gpa, epoch);
    defer gpa.free(dialable.peers);
    try testing.expectEqual(@as(usize, 0), dialable.peers.len);
    try testing.expectEqual(@as(?SystemTime, null), dialable.next_query_at);
}

test "an expired block no longer stops a dial before it is unblocked" {
    // commonware `test_dialable_expired_block_without_unblock`.
    var rng = TestRng.init(0);
    var short = config;
    short.max_sets = 3;
    short.peer_connection_cooldown = .from_millis(200);
    short.block_duration = .from_secs(1);
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, short);
    defer dir.deinit();
    const pk1 = key(1);
    try track_alone(&dir, pk1, public(8, 8, 8, 8, 1234));
    try testing.expect(try dir.block(epoch, pk1));
    try testing.expect(!try expect_dialable(&dir, epoch, pk1, at_ms(1_000)));
    // The block expired, but `unblock_expired` has not run: no stale hint either.
    try testing.expect(try expect_dialable(&dir, at_ms(2_000), pk1, null));
    const dialed = dir.dial(&rng, at_ms(2_000), pk1).?;
    dir.release(dialed.metadata);
}

test "overwrite ignores a peer evicted from every set" {
    // commonware `test_overwrite_peer_not_in_set`.
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, config);
    defer dir.deinit();
    const one: Entry = .{ .key = key(1), .value = public(8, 8, 8, 8, 1235) };
    const two: Entry = .{ .key = key(2), .value = public(9, 9, 9, 9, 1236) };
    try expect_kills(try track(&dir, 0, &.{one}, &.{}), &.{});
    try expect_kills(try track(&dir, 1, &.{two}, &.{}), &.{});
    try testing.expect(!dir.overwrite(key(1), public(10, 10, 10, 10, 1237)));
}

test "overwrite updates a blocked peer, which dials the new address once unblocked" {
    // commonware `test_overwrite_blocked_peer`.
    var three_sets = config;
    three_sets.max_sets = 3;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, three_sets);
    defer dir.deinit();
    const pk1 = key(1);
    try track_alone(&dir, pk1, public(8, 8, 8, 8, 1235));
    try testing.expect(try dir.block(epoch, pk1));
    try testing.expect(dir.overwrite(pk1, public(9, 9, 9, 9, 1236)));
    try expect_ingress(&dir, pk1, public(9, 9, 9, 9, 1236));
    const later = at_ms(101_000);
    try testing.expect(dir.unblock_expired(later));
    try expect_ingress(&dir, pk1, public(9, 9, 9, 9, 1236));
    try testing.expect(try expect_dialable(&dir, later, pk1, null));
}

test "dial rejects a DNS ingress set by overwrite while DNS is disabled" {
    // commonware `test_dial_rejects_dns_ingress_when_disabled_after_address_change`.
    var rng = TestRng.init(0);
    var no_dns = config;
    no_dns.max_sets = 3;
    no_dns.allow_dns = false;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var dir = try init_dir(&registry, no_dns);
    defer dir.deinit();
    const pk1 = key(1);
    try track_alone(&dir, pk1, public(8, 8, 8, 8, 8080));
    try testing.expect(try expect_dialable(&dir, epoch, pk1, null));
    const host = utils.Hostname.literal("node.example.com");
    const dns: types.Address = .{ .asymmetric = .{
        .ingress = .{ .dns = .{ .host = host, .port = 8080 } },
        .egress = socket(8, 8, 8, 8, 8080),
    } };
    try testing.expect(dir.overwrite(pk1, dns));
    try testing.expect(!try expect_dialable(&dir, epoch, pk1, null));
    try testing.expect(dir.dial(&rng, epoch, pk1) == null);
}
