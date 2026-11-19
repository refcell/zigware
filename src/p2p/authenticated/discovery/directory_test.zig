//! Tests of the discovery directory (commonware `discovery/actors/tracker/directory.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
const traces = @import("runtime").telemetry.traces;
const p2p_types = @import("../../types.zig");
const directory_mod = @import("directory.zig");
const types = @import("types.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const Key = cryptography.ed25519.PublicKey;
const Dir = directory_mod.Directory(Key);
const Info = Dir.Info;
const Ingress = p2p_types.Ingress;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const gpa = testing.allocator;

const namespace = "test";

fn key(seed: u64) Key {
    return PrivateKey.from_seed(seed).public_key();
}

fn socket(a: u8, b: u8, c: u8, d: u8, port: u16) Ingress {
    return .{ .socket = .{ .ip = .{ .v4 = codec.Ipv4.init(a, b, c, d) }, .port = port } };
}

fn info_at(seed: u64, ingress: Ingress, timestamp: u64) Info {
    const signer = PrivateKey.from_seed(seed);
    return Info.sign(signer.public_key(), namespace, ingress, timestamp, &signer);
}

fn my_info() Info {
    return info_at(0, socket(8, 8, 8, 8, 8080), 100);
}

fn config(max_sets: usize, allow_private_ips: bool) directory_mod.Config {
    return .{
        .allow_private_ips = allow_private_ips,
        .allow_dns = true,
        .max_sets = max_sets,
        .dial_fail_limit = 1,
        .peer_connection_cooldown = .from_millis(100),
        .block_duration = .from_secs(100),
    };
}

const epoch: SystemTime = .UNIX_EPOCH;

fn at_ms(ms: u64) SystemTime {
    return epoch.saturating_add(.from_millis(ms));
}

fn sorted(keys: []const Key) ![]Key {
    const copy = try gpa.dupe(Key, keys);
    std.sort.pdq(Key, copy, {}, Key.less_than);
    return copy;
}

/// Tracks `primary` and `secondary` (sorted here) at `index`; returns the teardown list.
fn track(dir: *Dir, index: u64, primary: []const Key, secondary: []const Key) !?[]Key {
    const first = try sorted(primary);
    defer gpa.free(first);
    const second = try sorted(secondary);
    defer gpa.free(second);
    return dir.track(index, .{ .primary = .init(first), .secondary = .init(second) });
}

fn expect_tracked(result: ?[]Key, kills: []const Key) !void {
    const got = result orelse return error.TestExpectedTracked;
    defer gpa.free(got);
    try testing.expectEqual(kills.len, got.len);
    for (kills, got) |want, have| try testing.expect(want.eql(have));
}

fn contains(keys: []const Key, peer: Key) bool {
    for (keys) |item| if (item.eql(peer)) return true;
    return false;
}

test "track kills a connected peer removed from every set" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(1, true), &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    const reservation = dir.listen(&rng, epoch, key(1)).?;
    dir.connect(epoch, key(1), false);
    try expect_tracked(try track(&dir, 1, &.{key(2)}, &.{}), &.{key(1)});
    try testing.expect(!dir.peers.get(key(1)).?.deletable());
    dir.release(reservation);
    try testing.expect(!dir.peers.contains(key(1)));
    try testing.expect(reservation.public_key().eql(key(1)));
}

test "blocking ourselves is ignored" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(3, false), &scope);
    defer dir.deinit();
    try testing.expect(!try dir.block(epoch, key(0)));
    try testing.expectEqual(@as(usize, 0), dir.blocked.count());
    try testing.expect(!dir.unblock_expired(at_ms(101_000)));
}

test "secondary sets remain until eviction" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(2, false), &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{key(4)}), &.{});
    try testing.expect(dir.eligible(epoch, key(4)));
    try expect_tracked(try track(&dir, 1, &.{key(2)}, &.{key(5)}), &.{});
    try testing.expect(dir.eligible(epoch, key(4)) and dir.eligible(epoch, key(5)));
    try expect_tracked(try track(&dir, 2, &.{key(3)}, &.{}), &.{});
    try testing.expect(!dir.peers.contains(key(4)));
    try testing.expect(dir.eligible(epoch, key(5)));
}

test "a peer in both roles is tracked as primary only" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(3, false), &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{ key(1), key(2) }, &.{ key(2), key(3) }), &.{});
    const set = (try dir.peer_set(gpa, 0)).?;
    defer set.free(gpa);
    try testing.expectEqual(@as(usize, 1), set.secondary.len);
    try testing.expect(set.secondary[0].eql(key(3)));
    try testing.expectEqual(@as(usize, 1), dir.peers.get(key(2)).?.primary_sets);
    try testing.expectEqual(@as(usize, 0), dir.peers.get(key(2)).?.secondary_sets);
    try testing.expectEqual(@as(usize, 1), dir.peers.get(key(3)).?.secondary_sets);
    var update = (try dir.latest_update(gpa)).?;
    defer update.deinit();
    try testing.expect(contains(update.latest.primary, key(2)));
    try testing.expect(!contains(update.latest.secondary, key(2)));
    try testing.expect(contains(update.all.primary, key(2)));
    try testing.expect(!contains(update.all.secondary, key(2)));
}

test "demotion from primary to secondary" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(2, false), &scope);
    defer dir.deinit();
    const x = key(1);
    const y = key(2);
    try expect_tracked(try track(&dir, 0, &.{x}, &.{y}), &.{});
    try expect_tracked(try track(&dir, 1, &.{y}, &.{x}), &.{});
    try testing.expectEqual(@as(usize, 1), dir.peers.get(x).?.primary_sets);
    try testing.expectEqual(@as(usize, 1), dir.peers.get(x).?.secondary_sets);
    const both = try dir.all(gpa);
    defer both.free(gpa);
    try testing.expectEqual(@as(usize, 2), both.primary.len);
    try testing.expectEqual(@as(usize, 0), both.secondary.len);

    // Index 2 evicts index 0, where X was primary.
    try expect_tracked(try track(&dir, 2, &.{y}, &.{x}), &.{});
    try testing.expectEqual(@as(usize, 0), dir.peers.get(x).?.primary_sets);
    try testing.expectEqual(@as(usize, 2), dir.peers.get(x).?.secondary_sets);
    try testing.expectEqual(@as(usize, 2), dir.peers.get(y).?.primary_sets);
    const after = try dir.all(gpa);
    defer after.free(gpa);
    try testing.expect(contains(after.primary, y) and contains(after.secondary, x));
    try testing.expect(!contains(after.primary, x) and !contains(after.secondary, y));
}

test "tracking needs increasing indices" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var collector = traces.Collector.init(gpa, .{});
    defer collector.deinit();
    var dir_config = config(3, false);
    dir_config.tracer = collector.tracer("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), dir_config, &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 5, &.{key(1)}, &.{}), &.{});
    try testing.expect(collector.get_by_level(.warn).is_empty());
    try testing.expect((try track(&dir, 5, &.{key(2)}, &.{})) == null);
    try testing.expect((try track(&dir, 4, &.{key(2)}, &.{})) == null);
    try testing.expectEqual(@as(?u64, 5), dir.latest_set_index());
    const warnings = collector.get_by_level(.warn);
    try testing.expectEqual(@as(usize, 2), warnings.len());
    const exists = warnings.get(0).?.metadata;
    try exists.expect_content_exact("peer set already exists");
    try exists.expect_field_exact("index", "5");
    const decreasing = warnings.get(1).?.metadata;
    try decreasing.expect_content_exact("index must monotonically increase");
    try decreasing.expect_field_exact("index", "4");
    try decreasing.expect_field_exact("last", "5");
}

test "a peer blocked before joining a set stays blocked" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(3, true), &scope);
    defer dir.deinit();
    const unknown = key(99);
    try testing.expect(try dir.block(epoch, unknown));
    try testing.expect(!try dir.block(epoch, unknown));
    try expect_tracked(try track(&dir, 0, &.{unknown}, &.{}), &.{});
    try testing.expect(!dir.eligible(epoch, unknown));
    try testing.expect(!dir.acceptable(epoch, unknown));
    try testing.expect(dir.listen(&rng, epoch, unknown) == null);
    const blocked = try dir.blocked_peers(gpa, epoch);
    defer gpa.free(blocked);
    try testing.expectEqual(@as(usize, 1), blocked.len);

    // After the block expires the peer is eligible again.
    const later = at_ms(100_001);
    try testing.expectEqual(@as(?SystemTime, at_ms(100_000)), dir.next_unblock());
    try testing.expect(dir.unblock_expired(later));
    try testing.expect(dir.next_unblock() == null);
    try testing.expect(dir.eligible(later, unknown));
    try testing.expect(dir.listen(&rng, later, unknown) != null);
}

test "blocked peers are neither dialable nor shared" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(3, true), &scope);
    defer dir.deinit();
    const peer = key(1);
    const other = key(2);
    try expect_tracked(try track(&dir, 0, &.{ peer, other }, &.{}), &.{});
    dir.update_peers(&.{
        info_at(1, socket(127, 0, 0, 1, 9001), 50),
        info_at(2, socket(127, 0, 0, 1, 9002), 50),
    });
    var dialable = try dir.dialable(gpa, epoch);
    try testing.expectEqual(@as(usize, 2), dialable.peers.len);
    gpa.free(dialable.peers);

    // Connect both so their info is sharable, then block one.
    for ([_]Key{ peer, other }) |each| {
        _ = dir.listen(&rng, epoch, each).?;
        dir.connect(epoch, each, false);
    }
    try testing.expect(try dir.block(epoch, peer));
    const bits = try types.BitMap.zeroes(gpa, 2);
    var bit_vec: types.BitVec = .{ .index = 0, .bits = bits };
    defer bit_vec.deinit(gpa);
    const shared = (try dir.infos(gpa, at_ms(100), &bit_vec)).?;
    defer gpa.free(shared);
    // `infos` shares what records hold; the tracker kills a blocked peer's connection.
    try testing.expectEqual(@as(usize, 2), shared.len);
    dialable = try dir.dialable(gpa, epoch);
    defer gpa.free(dialable.peers);
    try testing.expectEqual(@as(usize, 0), dialable.peers.len);
    try testing.expectEqual(@as(?SystemTime, at_ms(100_000)), dialable.next_query_at);
}

test "infos rejects a malformed bit vector and skips future timestamps" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(3, true), &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{ key(0), key(1), key(2) }, &.{}), &.{});
    dir.update_peers(&.{info_at(1, socket(127, 0, 0, 1, 9001), 50)});
    dir.update_peers(&.{info_at(2, socket(127, 0, 0, 1, 9002), 5_000)});
    for ([_]Key{ key(1), key(2) }) |each| {
        _ = dir.listen(&rng, epoch, each).?;
        dir.connect(epoch, each, false);
    }
    var short: types.BitVec = .{ .index = 0, .bits = try types.BitMap.zeroes(gpa, 2) };
    defer short.deinit(gpa);
    try testing.expect((try dir.infos(gpa, at_ms(1_000), &short)) == null);

    var unknown_index: types.BitVec = .{ .index = 7, .bits = try types.BitMap.zeroes(gpa, 2) };
    defer unknown_index.deinit(gpa);
    const none = (try dir.infos(gpa, at_ms(1_000), &unknown_index)).?;
    try testing.expectEqual(@as(usize, 0), none.len);
    gpa.free(none);

    // Ourselves (signed at 100) and peer 1 (at 50) are shared; peer 2 (at 5000) is not yet.
    var want_all: types.BitVec = .{ .index = 0, .bits = try types.BitMap.zeroes(gpa, 3) };
    defer want_all.deinit(gpa);
    const shared = (try dir.infos(gpa, at_ms(1_000), &want_all)).?;
    defer gpa.free(shared);
    try testing.expectEqual(@as(usize, 2), shared.len);
    for (shared) |item| try testing.expect(!item.public_key.eql(key(2)));
}

test "knowledge bits follow connections and gossip" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(3, true), &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{ key(0), key(1) }, &.{}), &.{});
    const self_slot: usize = if (Key.order(key(0), key(1)) == .lt) 0 else 1;
    // We know ourselves, not peer 1.
    var before = (try dir.random_bit_vec(gpa, &rng)).?;
    defer before.deinit(gpa);
    try testing.expect(before.bits.get(self_slot) and !before.bits.get(1 - self_slot));
    // Gossip about peer 1 makes it known.
    dir.update_peers(&.{info_at(1, socket(127, 0, 0, 1, 9001), 50)});
    var gossiped = (try dir.random_bit_vec(gpa, &rng)).?;
    defer gossiped.deinit(gpa);
    try testing.expect(gossiped.bits.get(1 - self_slot));
    // A failed dial reaches the fail limit (1), so we ask for its info again.
    dir.release(dir.dial(&rng, epoch, key(1)).?);
    var failed = (try dir.random_bit_vec(gpa, &rng)).?;
    defer failed.deinit(gpa);
    try testing.expect(!failed.bits.get(1 - self_slot));
    // A successful dial clears the failures.
    _ = dir.dial(&rng, at_ms(1_000), key(1)).?;
    dir.connect(epoch, key(1), true);
    var connected = (try dir.random_bit_vec(gpa, &rng)).?;
    defer connected.deinit(gpa);
    try testing.expect(connected.bits.get(1 - self_slot));
}

test "the reservation cooldown rate limits redials" {
    var rng = utils.rng.test_rng();
    const bootstrappers = [_]Dir.Bootstrapper{
        .{ .peer = key(1), .ingress = socket(127, 0, 0, 1, 9001) },
    };
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &bootstrappers, my_info(), config(3, true), &scope);
    defer dir.deinit();
    const reservation = dir.dial(&rng, epoch, key(1)).?;
    try testing.expect(reservation.dialer.ingress.eql(socket(127, 0, 0, 1, 9001)));
    dir.release(reservation);
    try testing.expect(dir.dial(&rng, epoch, key(1)) == null);
    const dialable = try dir.dialable(gpa, epoch);
    defer gpa.free(dialable.peers);
    try testing.expectEqual(@as(usize, 0), dialable.peers.len);
    const next = dialable.next_query_at.?;
    try testing.expect(next.order(at_ms(100)) != .lt and next.order(at_ms(200)) != .gt);
    try testing.expect(dir.dial(&rng, next, key(1)) != null);
}

test "dial rejects a peer demoted to secondary" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(1, true), &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    dir.update_peers(&.{info_at(1, socket(127, 0, 0, 1, 9001), 50)});
    try expect_tracked(try track(&dir, 1, &.{}, &.{key(1)}), &.{});
    try testing.expect(dir.dial(&rng, epoch, key(1)) == null);
    // Still acceptable inbound.
    try testing.expect(dir.listen(&rng, epoch, key(1)) != null);
}

test "dial rejects an ingress disallowed after an update" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(1, false), &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    dir.update_peers(&.{info_at(1, socket(8, 8, 4, 4, 9001), 50)});
    const snapshot = try dir.dialable(gpa, epoch);
    defer gpa.free(snapshot.peers);
    try testing.expectEqual(@as(usize, 1), snapshot.peers.len);
    // A newer record with a private address replaces the public one.
    dir.update_peers(&.{info_at(1, socket(10, 0, 0, 1, 9001), 60)});
    try testing.expect(dir.dial(&rng, epoch, key(1)) == null);
}

test "a bootstrapper stays after blocking and set eviction" {
    const bootstrappers = [_]Dir.Bootstrapper{
        .{ .peer = key(1), .ingress = socket(8, 8, 8, 8, 1) },
    };
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &bootstrappers, my_info(), config(1, false), &scope);
    defer dir.deinit();
    try testing.expect(try dir.block(epoch, key(1)));
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    try expect_tracked(try track(&dir, 1, &.{key(2)}, &.{}), &.{});
    try testing.expect(dir.peers.contains(key(1)));
    try testing.expect(!dir.eligible(epoch, key(1)));
    try testing.expect(dir.eligible(at_ms(100_000), key(1)));
}

/// The value of `name`'s sample for `peer`, if any (commonware's `metric_value`).
fn metric_value(text: []const u8, name: []const u8, peer: Key) !?i64 {
    var prefix_buffer: [256]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buffer, "{s}{{peer=\"{f}\"}} ", .{ name, peer });
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        return try std.fmt.parseInt(i64, line[prefix.len..], 10);
    }
    return null;
}

test "the connected metric tracks active peers" {
    // commonware `test_connected_metric_tracks_active_peers`, plus the tracked and reserved
    // gauges along the way.
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(3, false), &scope);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    const reservation = dir.listen(&rng, at_ms(1_000), key(1)).?;
    dir.connect(at_ms(1_234), key(1), false);
    {
        const text = try registry.encode(gpa);
        defer gpa.free(text);
        const connected = try metric_value(text, "directory_connected", key(1));
        try testing.expectEqual(@as(?i64, 1_234), connected);
        try testing.expect(metrics.has_metric_value(text, "directory_tracked", 1));
        try testing.expect(metrics.has_metric_value(text, "directory_reserved", 1));
    }
    dir.release(reservation);
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    try testing.expectEqual(@as(?i64, null), try metric_value(text, "directory_connected", key(1)));
    try testing.expect(metrics.has_metric_value(text, "directory_reserved", 0));
}

test "blocking records the expiry until it passes" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try Dir.init(gpa, &.{}, my_info(), config(3, false), &scope);
    defer dir.deinit();
    try testing.expect(try dir.block(at_ms(500), key(7)));
    {
        const text = try registry.encode(gpa);
        defer gpa.free(text);
        // block_duration is 100 s.
        const blocked = try metric_value(text, "directory_blocked", key(7));
        try testing.expectEqual(@as(?i64, 100_500), blocked);
    }
    try testing.expect(dir.unblock_expired(at_ms(100_500)));
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    try testing.expectEqual(@as(?i64, null), try metric_value(text, "directory_blocked", key(7)));
}

/// A directory over the shared registry `scope`, freed by the caller.
fn edge_dir(scope: *const metrics.Scope, dir_config: directory_mod.Config) !Dir {
    return Dir.init(gpa, &.{}, my_info(), dir_config, scope);
}

fn is_dialable(dir: *const Dir, at: SystemTime, peer: Key) !bool {
    const dialable = try dir.dialable(gpa, at);
    defer gpa.free(dialable.peers);
    return contains(dialable.peers, peer);
}

fn blocked_metric(dir: *Dir, peer: Key) bool {
    return dir.metrics.blocked.metric().get(.{ .peer = peer }) != null;
}

test "repeated blocks of tracked and unknown peers keep one block" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try edge_dir(&scope, config(3, false));
    defer dir.deinit();
    const tracked = key(50);
    const unknown = key(99);
    try expect_tracked(try track(&dir, 0, &.{tracked}, &.{}), &.{});
    try testing.expect(!blocked_metric(&dir, tracked));
    for ([_]Key{ tracked, unknown }) |peer| {
        try testing.expect(try dir.block(epoch, peer));
        try testing.expect(blocked_metric(&dir, peer));
        for (0..2) |_| {
            try testing.expect(!try dir.block(epoch, peer));
            try testing.expect(blocked_metric(&dir, peer));
        }
    }
    try testing.expectEqual(@as(usize, 2), dir.blocked.count());
}

test "a blocked peer takes updates and keeps them past its unblock" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try edge_dir(&scope, config(3, true));
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    try testing.expect(try dir.block(epoch, key(1)));
    try testing.expect(!try is_dialable(&dir, epoch, key(1)));
    dir.update_peers(&.{info_at(1, socket(127, 0, 0, 1, 9001), 200)});
    try testing.expect(dir.blocked.contains(key(1)));
    try testing.expect(dir.peers.get(key(1)).?.ingress() != null);
    const later = at_ms(101_000);
    try testing.expect(dir.unblock_expired(later));
    try testing.expect(!dir.blocked.contains(key(1)));
    try testing.expect(dir.peers.get(key(1)).?.ingress() != null);
    // Unblocked, the peer is dialable again.
    try testing.expect(try is_dialable(&dir, later, key(1)));
}

test "a blocked peer's info is not shared, even once unblocked" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try edge_dir(&scope, config(3, true));
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{ key(1), key(2) }, &.{}), &.{});
    dir.update_peers(&.{
        info_at(1, socket(127, 0, 0, 1, 9001), 0),
        info_at(2, socket(9, 9, 9, 9, 9090), 0),
    });
    const first = dir.dial(&rng, epoch, key(1)).?;
    dir.connect(epoch, key(1), true);
    const second = dir.dial(&rng, epoch, key(2)).?;
    dir.connect(epoch, key(2), true);
    defer dir.release(second);
    try testing.expect(dir.info(key(1)) != null);
    var bit_vec: types.BitVec = .{ .index = 0, .bits = try types.BitMap.zeroes(gpa, 2) };
    defer bit_vec.deinit(gpa);
    const both = (try dir.infos(gpa, at_ms(100), &bit_vec)).?;
    try testing.expectEqual(@as(usize, 2), both.len);
    gpa.free(both);
    // The tracker kills a blocked peer's connection, which releases it.
    try testing.expect(try dir.block(epoch, key(1)));
    dir.release(first);
    try testing.expectEqual(null, dir.info(key(1)));
    const shared = (try dir.infos(gpa, at_ms(100), &bit_vec)).?;
    defer gpa.free(shared);
    try testing.expectEqual(@as(usize, 1), shared.len);
    try testing.expect(shared[0].public_key.eql(key(2)));
    _ = dir.unblock_expired(at_ms(101_000));
    try testing.expectEqual(null, dir.info(key(1)));
}

test "an empty directory has nothing to dial and no next query" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir = try edge_dir(&scope, config(3, true));
    defer dir.deinit();
    const dialable = try dir.dialable(gpa, epoch);
    defer gpa.free(dialable.peers);
    try testing.expectEqual(@as(usize, 0), dialable.peers.len);
    try testing.expectEqual(@as(?SystemTime, null), dialable.next_query_at);
}

test "an expired block stops nothing before unblock runs, and a re-block applies" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir_config = config(3, true);
    dir_config.peer_connection_cooldown = .from_millis(200);
    dir_config.block_duration = .from_secs(1);
    var dir = try edge_dir(&scope, dir_config);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    dir.update_peers(&.{info_at(1, socket(127, 0, 0, 1, 9001), 200)});
    try testing.expect(try dir.block(epoch, key(1)));
    try testing.expect(!try is_dialable(&dir, epoch, key(1)));
    // Two seconds later the block has expired, though `unblock_expired` has not run.
    const later = at_ms(2_000);
    const dialable = try dir.dialable(gpa, later);
    defer gpa.free(dialable.peers);
    try testing.expect(contains(dialable.peers, key(1)));
    try testing.expectEqual(@as(?SystemTime, null), dialable.next_query_at);
    // A re-block then makes it undialable and unreservable again.
    try testing.expect(try dir.block(later, key(1)));
    try testing.expect(!try is_dialable(&dir, later, key(1)));
    try testing.expectEqual(null, dir.dial(&rng, later, key(1)));
}

test "an expired block does not prevent a reservation" {
    var rng = utils.rng.test_rng();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir_config = config(3, true);
    dir_config.block_duration = .from_secs(1);
    var dir = try edge_dir(&scope, dir_config);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    dir.update_peers(&.{info_at(1, socket(127, 0, 0, 1, 9001), 200)});
    try testing.expect(try dir.block(epoch, key(1)));
    dir.release(dir.dial(&rng, at_ms(2_000), key(1)).?);
}

test "a block that never expires saturates" {
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("directory");
    var dir_config = config(1, true);
    dir_config.block_duration = Duration.max;
    var dir = try edge_dir(&scope, dir_config);
    defer dir.deinit();
    try expect_tracked(try track(&dir, 0, &.{key(1)}, &.{}), &.{});
    try testing.expect(try dir.block(epoch, key(1)));
    try testing.expect(!dir.eligible(epoch, key(1)));
}
