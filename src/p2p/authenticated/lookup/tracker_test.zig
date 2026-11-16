//! Tests of the lookup tracker (commonware `lookup/actors/tracker/{actor,ingress}.rs` tests),
//! on the deterministic runtime. A connection's kill shows on its outbox; a reservation that
//! commonware drops is released explicitly.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const types = @import("../../types.zig");
const Outbox = @import("../outbox.zig").Outbox;
const tracker_mod = @import("tracker.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const Key = cryptography.ed25519.PublicKey;
const Tracker = tracker_mod.Tracker(Key);
const Entry = Tracker.PeerMap.Entry;
const gpa = testing.allocator;

fn key(seed: u64) Key {
    return PrivateKey.from_seed(seed).public_key();
}

fn v4(a: u8, b: u8, c: u8, d: u8) codec.IpAddr {
    return .{ .v4 = codec.Ipv4.init(a, b, c, d) };
}

fn socket(ip: codec.IpAddr, port: u16) codec.SocketAddr {
    return .{ .ip = ip, .port = port };
}

fn address(ip: codec.IpAddr, port: u16) types.Address {
    return .{ .symmetric = socket(ip, port) };
}

/// commonware's `test_config`: seed 0 is us.
fn test_config(bypass_ip_check: bool) Tracker.Config {
    return .{
        .public_key = key(0),
        .max_peers_per_set = 1024,
        .tracked_peer_sets = 2,
        .peer_connection_cooldown = .from_millis(200),
        .allow_private_ips = true,
        .allow_dns = true,
        .bypass_ip_check = bypass_ip_check,
        .block_duration = .from_secs(100),
    };
}

/// A map of `entries`, sorted into a caller-freed buffer.
fn peer_map(buffer: []Entry, entries: []const Entry) Tracker.PeerMap {
    @memcpy(buffer[0..entries.len], entries);
    const sorted = buffer[0..entries.len];
    std.sort.pdq(Entry, sorted, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return Key.order(a.key, b.key) == .lt;
        }
    }.less);
    return .init(sorted);
}

fn track(tracker: *Tracker, index: u64, entries: []const Entry) !void {
    var buffer: [8]Entry = undefined;
    const tracked = Tracker.Tracked.init_primary(peer_map(&buffer, entries));
    try testing.expectEqual(.ok, tracker.as_oracle().track(index, tracked));
}

fn overwrite(tracker: *Tracker, entries: []const Entry) !void {
    var buffer: [8]Entry = undefined;
    try testing.expectEqual(.ok, tracker.as_oracle().overwrite(peer_map(&buffer, entries)));
}

fn is_dialable(tracker: *Tracker, peer: Key) !bool {
    const dialable = try tracker.dialable(gpa);
    defer gpa.free(dialable.peers);
    for (dialable.peers) |candidate| {
        if (candidate.eql(peer)) return true;
    }
    return false;
}

fn killed(outbox: *Outbox) bool {
    const next = outbox.try_next() orelse return false;
    return next == .killed;
}

fn run(comptime function: anytype, args: anytype) !void {
    const timeout_ns = 600 * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = 0, .timeout_ns = timeout_ns };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()} ++ args));
}

/// A tracker with its unblock timer running, stopped and freed by `stop`.
const Harness = struct {
    tracker: Tracker,
    unblock: Io.Future(Io.Cancelable!void),

    fn start(harness: *Harness, io: Io, config: Tracker.Config) !void {
        harness.tracker = try .init(gpa, io, config);
        harness.unblock = try io.concurrent(Tracker.run_unblock, .{&harness.tracker});
    }

    fn stop(harness: *Harness, io: Io) void {
        harness.unblock.cancel(io) catch {};
        harness.tracker.close();
        harness.tracker.deinit();
    }
};

fn sleep_ms(io: Io, ms: i64) !void {
    try io.sleep(.fromMilliseconds(ms), .real);
}

fn connect_unauthorized(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    try testing.expect(!harness.tracker.connect(key(1), &outbox));
}

test "connecting an unauthorized peer fails" {
    try run(connect_unauthorized, .{});
}

fn block_standard(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const pk = key(1);
    try track(tracker, 0, &.{.{ .key = pk, .value = address(v4(127, 0, 0, 1), 1001) }});
    try testing.expect(try is_dialable(tracker, pk));
    try testing.expectEqual(.ok, tracker.as_oracle().block(pk));
    try testing.expect(!try is_dialable(tracker, pk));
    // Blocking again, and blocking an unknown peer, change nothing.
    try testing.expectEqual(.ok, tracker.as_oracle().block(pk));
    try testing.expect(!try is_dialable(tracker, pk));
    try testing.expectEqual(.ok, tracker.as_oracle().block(key(100)));
}

test "a blocked peer is not dialable, and repeat or unknown blocks are no-ops" {
    try run(block_standard, .{});
}

fn expect_blocked(subscription: *Tracker.BlockedSubscription, expected: []const Key) !void {
    const blocked = (try subscription.recv(gpa)).?;
    defer gpa.free(blocked);
    try testing.expectEqual(expected.len, blocked.len);
    for (expected, blocked) |want, got| try testing.expect(want.eql(got));
}

fn blocked_subscription(io: Io) !void {
    var harness: Harness = undefined;
    const config = test_config(false);
    try harness.start(io, config);
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const pk = key(1);
    try track(tracker, 0, &.{.{ .key = pk, .value = address(v4(127, 0, 0, 1), 1001) }});
    // A new subscription starts with the current, empty set.
    var blocked = try tracker.as_oracle().blocked();
    try expect_blocked(&blocked, &.{});
    _ = tracker.as_oracle().block(pk);
    try expect_blocked(&blocked, &.{pk});
    // A repeat block publishes nothing; a late subscriber starts from the current set.
    _ = tracker.as_oracle().block(pk);
    try sleep_ms(io, 10);
    try testing.expectEqual(null, try blocked.try_recv(gpa));
    var late = try tracker.as_oracle().blocked();
    try expect_blocked(&late, &.{pk});
    // Expiry clears the set for every subscriber.
    try sleep_ms(io, @intCast(config.block_duration.as_millis() + 10));
    try expect_blocked(&blocked, &.{});
    try expect_blocked(&late, &.{});
}

test "the blocked subscription tracks blocks and their expiry" {
    try run(blocked_subscription, .{});
}

fn listenable(io: Io, bypass_ip_check: bool) !void {
    var harness: Harness = undefined;
    // Peer 1 is us here, as in commonware's test.
    var config = test_config(bypass_ip_check);
    config.public_key = key(1);
    try harness.start(io, config);
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const ip_1 = v4(127, 0, 0, 1);
    const ip_2 = v4(127, 0, 0, 2);
    const ip_3 = v4(127, 0, 0, 3);
    for ([_]Key{ key(1), key(2), key(3) }, [_]codec.IpAddr{ ip_1, ip_2, ip_3 }) |pk, ip| {
        try testing.expect(!tracker.acceptable(pk, ip));
    }
    try track(tracker, 0, &.{
        .{ .key = key(1), .value = address(ip_1, 1001) },
        .{ .key = key(2), .value = address(ip_2, 1002) },
    });
    // Never ourselves; a tracked peer from its own IP, or any IP when bypassing the check.
    try testing.expect(!tracker.acceptable(key(1), ip_1));
    try testing.expect(tracker.acceptable(key(2), ip_2));
    try testing.expectEqual(bypass_ip_check, tracker.acceptable(key(2), ip_1));
    try testing.expect(!tracker.acceptable(key(3), ip_3));
    try testing.expect(tracker.registered(ip_2) and !tracker.registered(ip_1));
    _ = tracker.as_oracle().block(key(2));
    try testing.expect(!tracker.acceptable(key(2), ip_2));
    try testing.expect(!tracker.registered(ip_2));
}

test "only tracked peers are acceptable, from their IP unless the check is bypassed" {
    try run(listenable, .{false});
    try run(listenable, .{true});
}

fn listen(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const pk = key(1);
    const ip = v4(127, 0, 0, 1);
    try testing.expectEqual(null, tracker.listen(pk, ip));
    try track(tracker, 0, &.{.{ .key = pk, .value = address(ip, 8080) }});
    try testing.expect(tracker.acceptable(pk, ip));
    const reservation = tracker.listen(pk, ip).?;
    try testing.expect(!tracker.acceptable(pk, ip));
    try testing.expectEqual(null, tracker.listen(pk, ip));
    tracker.release(reservation);
    // After the release and the connection cooldown, the peer reserves again.
    try sleep_ms(io, 1_010);
    try testing.expect(tracker.listen(pk, ip) != null);
}

test "listen reserves a tracked peer once until released" {
    try run(listen, .{});
}

fn dial(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const boot = key(99);
    const boot_socket = socket(v4(127, 0, 0, 1), 9000);
    try track(tracker, 0, &.{.{ .key = boot, .value = .{ .symmetric = boot_socket } }});
    const dialable = try tracker.dialable(gpa);
    defer gpa.free(dialable.peers);
    try testing.expectEqual(1, dialable.peers.len);
    try testing.expect(dialable.peers[0].eql(boot));
    const reserved = tracker.dial(boot).?;
    try testing.expect(reserved.metadata == .dialer);
    try testing.expect(reserved.metadata.public_key().eql(boot));
    try testing.expect(reserved.ingress.eql(.{ .socket = boot_socket }));
    try testing.expectEqual(null, tracker.dial(key(100)));
}

test "dialable lists tracked peers and dial reserves them" {
    try run(dial, .{});
}

fn expect_keys(view: []const Key, expected: []const Key) !void {
    try testing.expectEqual(expected.len, view.len);
    for (expected, view) |want, got| try testing.expect(want.eql(got));
}

fn secondary_peers(io: Io, overlap: bool) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    var subscription = try tracker.as_oracle().subscribe();
    defer subscription.deinit();
    const primary_pk = key(1);
    const secondary_pk = if (overlap) primary_pk else key(2);
    const ip = v4(127, 0, 0, 1);
    const primary = [_]Entry{.{ .key = primary_pk, .value = address(ip, 9001) }};
    const secondary = [_]Entry{.{ .key = secondary_pk, .value = address(ip, 9002) }};
    const tracked: Tracker.Tracked = .{
        .primary = .init(&primary),
        .secondary = .init(&secondary),
    };
    try testing.expectEqual(.ok, tracker.as_oracle().track(0, tracked));
    var update = (try subscription.recv()).?;
    defer update.deinit();
    try testing.expectEqual(0, update.index);
    try expect_keys(update.latest.primary, &.{primary_pk});
    try expect_keys(update.all.primary, &.{primary_pk});
    // An overlapping key is tracked as primary only.
    const expected_secondary: []const Key = if (overlap) &.{} else &.{secondary_pk};
    try expect_keys(update.latest.secondary, expected_secondary);
    try expect_keys(update.all.secondary, expected_secondary);
    try testing.expect(try is_dialable(tracker, primary_pk));
    try testing.expect(try is_dialable(tracker, secondary_pk) == overlap);
    try testing.expect(tracker.acceptable(secondary_pk, ip));
    // An overlapping key is dialable (and the dial reserves it); a secondary one is not.
    const reserved = tracker.dial(secondary_pk);
    try testing.expectEqual(overlap, reserved != null);
    if (reserved) |dialed| tracker.release(dialed.metadata);
}

test "secondary peers are acceptable but not dialable, and overlaps are primary" {
    try run(secondary_peers, .{false});
    try run(secondary_peers, .{true});
}

fn block_kills_once(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const pk = key(1);
    const ip = v4(127, 0, 0, 1);
    try track(tracker, 0, &.{.{ .key = pk, .value = address(ip, 12345) }});
    const reservation = tracker.listen(pk, ip).?;
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    try testing.expect(tracker.connect(pk, &outbox));
    _ = tracker.as_oracle().block(pk);
    try testing.expect(killed(&outbox));
    // The mailbox is gone, so a second block reaches nothing (the kill stays sticky here).
    try testing.expectEqual(null, tracker.mailboxes.get(pk));
    _ = tracker.as_oracle().block(pk);
    tracker.release(reservation);
}

test "a block kills the connection and forgets its mailbox" {
    try run(block_kills_once, .{});
}

fn rollover(io: Io, keep: bool) !void {
    var harness: Harness = undefined;
    var config = test_config(false);
    config.tracked_peer_sets = 1;
    if (!keep) config.max_peers_per_set = 2;
    try harness.start(io, config);
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const ip_me = v4(127, 0, 0, 1);
    const ip_1 = v4(127, 0, 0, 2);
    const ip_2: codec.IpAddr = .{ .v6 = codec.Ipv6.localhost };
    const first = [_]Entry{
        .{ .key = key(0), .value = address(ip_me, 9000) },
        .{ .key = key(1), .value = address(ip_1, 9001) },
    };
    try track(tracker, 0, &first);
    try testing.expect(!tracker.registered(ip_me));
    try testing.expect(tracker.registered(ip_1) and !tracker.registered(ip_2));
    const reservation = tracker.listen(key(1), ip_1).?;
    defer tracker.release(reservation);
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    try testing.expect(tracker.connect(key(1), &outbox));
    const second_keep = [_]Entry{
        .{ .key = key(1), .value = address(ip_1, 9001) },
        .{ .key = key(2), .value = address(ip_2, 9002) },
    };
    const second_drop = [_]Entry{.{ .key = key(2), .value = address(ip_2, 9002) }};
    try track(tracker, 1, if (keep) &second_keep else &second_drop);
    try testing.expectEqual(keep, tracker.registered(ip_1));
    try testing.expect(tracker.registered(ip_2) and !tracker.registered(ip_me));
    // A peer dropped with the old set is killed; one still tracked stays.
    try testing.expectEqual(!keep, killed(&outbox));
}

test "a new peer set disconnects removed peers and keeps the rest" {
    try run(rollover, .{false});
    try run(rollover, .{true});
}

/// How a reserved peer's address changes before it connects.
const Change = enum { removed, tracked, overwritten };

fn reserved_then_changed(io: Io, change: Change) !void {
    var harness: Harness = undefined;
    var config = test_config(false);
    config.tracked_peer_sets = if (change == .removed) 1 else 2;
    try harness.start(io, config);
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const pk = key(1);
    const a = v4(8, 8, 8, 8);
    const b = v4(9, 9, 9, 9);
    try track(tracker, 0, &.{.{ .key = pk, .value = address(a, 1001) }});
    try testing.expect(tracker.registered(a));
    const reserved = tracker.dial(pk).?;
    defer tracker.release(reserved.metadata);
    try testing.expect(reserved.ingress.eql(.{ .socket = socket(a, 1001) }));
    switch (change) {
        .removed => try track(tracker, 1, &.{.{ .key = key(2), .value = address(b, 1002) }}),
        .tracked => try track(tracker, 1, &.{.{ .key = pk, .value = address(b, 1002) }}),
        .overwritten => try overwrite(tracker, &.{.{ .key = pk, .value = address(b, 1002) }}),
    }
    try testing.expect(!tracker.registered(a) and tracker.registered(b));
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    // The connect is rejected; the caller then ends the connection.
    try testing.expect(!tracker.connect(pk, &outbox));
}

test "a reserved peer is rejected on connect after removal or an address change" {
    for ([_]Change{ .removed, .tracked, .overwritten }) |change| {
        try run(reserved_then_changed, .{change});
    }
}

fn overwrite_inbound(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const pk = key(1);
    const a = v4(8, 8, 8, 8);
    const b = v4(9, 9, 9, 9);
    try track(tracker, 0, &.{.{ .key = pk, .value = address(a, 1001) }});
    try testing.expect(tracker.acceptable(pk, a) and !tracker.acceptable(pk, b));
    try overwrite(tracker, &.{.{ .key = pk, .value = address(b, 1002) }});
    try testing.expect(!tracker.registered(a) and tracker.registered(b));
    try testing.expect(!tracker.acceptable(pk, a) and tracker.acceptable(pk, b));
    // An inbound handshake from the old source IP is rejected.
    try testing.expectEqual(null, tracker.listen(pk, a));
    try testing.expect(tracker.listen(pk, b) != null);
    // Overwriting an untracked peer is ignored.
    try overwrite(tracker, &.{.{ .key = key(3), .value = address(a, 1003) }});
    try testing.expect(!tracker.registered(a));
}

test "overwrite moves the acceptable source IP and ignores untracked peers" {
    try run(overwrite_inbound, .{});
}

fn overwrite_dial(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const pk = key(1);
    const first = socket(v4(127, 0, 0, 1), 1001);
    const second = socket(v4(8, 8, 8, 8), 1002);
    try track(tracker, 0, &.{.{ .key = pk, .value = .{ .symmetric = first } }});
    const reserved = tracker.dial(pk).?;
    try testing.expect(reserved.ingress.eql(.{ .socket = first }));
    tracker.release(reserved.metadata);
    try overwrite(tracker, &.{.{ .key = pk, .value = .{ .symmetric = second } }});
    try sleep_ms(io, 1_010);
    const again = tracker.dial(pk).?;
    defer tracker.release(again.metadata);
    try testing.expect(again.ingress.eql(.{ .socket = second }));
}

test "dial uses the overwritten address" {
    try run(overwrite_dial, .{});
}

fn overwrite_blocked(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const a = v4(8, 8, 8, 8);
    const b = v4(9, 9, 9, 9);
    try track(tracker, 0, &.{
        .{ .key = key(0), .value = address(v4(127, 0, 0, 1), 9000) },
        .{ .key = key(1), .value = address(a, 9001) },
    });
    try testing.expect(tracker.registered(a));
    _ = tracker.as_oracle().block(key(1));
    try testing.expect(!tracker.registered(a));
    try overwrite(tracker, &.{.{ .key = key(1), .value = address(b, 9002) }});
    try testing.expect(!tracker.registered(a) and !tracker.registered(b));
}

test "an overwritten blocked peer stays out of the listener's set" {
    try run(overwrite_blocked, .{});
}

fn overwrite_batch(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(false));
    defer harness.stop(io);
    const tracker = &harness.tracker;
    const ip_1 = v4(8, 8, 8, 8);
    const ip_unchanged = v4(10, 10, 10, 10);
    try track(tracker, 0, &.{
        .{ .key = key(1), .value = address(ip_1, 1001) },
        .{ .key = key(2), .value = address(ip_unchanged, 1003) },
    });
    var outboxes: [2]Outbox = .{ .init(gpa, io, 1), .init(gpa, io, 1) };
    defer for (&outboxes) |*outbox| outbox.deinit();
    for ([_]Key{ key(1), key(2) }, [_]codec.IpAddr{ ip_1, ip_unchanged }, &outboxes) |pk, ip, *o| {
        _ = tracker.listen(pk, ip).?;
        try testing.expect(tracker.connect(pk, o));
    }
    try overwrite(tracker, &.{
        .{ .key = key(1), .value = address(v4(9, 9, 9, 9), 1002) },
        .{ .key = key(2), .value = address(ip_unchanged, 1003) },
        .{ .key = key(3), .value = address(ip_1, 1001) },
    });
    // Only the peer whose address changed is killed.
    try testing.expect(killed(&outboxes[0]));
    try testing.expect(!killed(&outboxes[1]));
    tracker.release(.{ .listener = key(1) });
    tracker.release(.{ .listener = key(2) });
}

test "overwrite kills only peers whose address changed" {
    try run(overwrite_batch, .{});
}

test "the peer set limit counts the local identity" {
    // commonware `test_peer_set_limit_includes_local_identity`: 3 identities > 2.
    const ip = v4(127, 0, 0, 1);
    const primary = [_]Entry{.{ .key = key(1), .value = address(ip, 1001) }};
    const secondary = [_]Entry{.{ .key = key(2), .value = address(ip, 1002) }};
    try testing.expectEqual(3, Tracker.set_size(&primary, &secondary, key(0)));
    try testing.expectEqual(2, Tracker.set_size(&primary, &secondary, key(1)));
    try testing.expectEqual(1, Tracker.set_size(&primary, &primary, key(1)));
}
