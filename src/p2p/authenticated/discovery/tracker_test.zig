//! Tests of the discovery tracker (commonware `discovery/actors/tracker/actor.rs` tests), on
//! the deterministic runtime. commonware's peer mailbox is an `Outbox` here: a kill shows as
//! `killed`, and gossip arrives as control frames holding an encoded `Payload`. A reservation
//! that commonware drops is released explicitly.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const p2p = @import("../../root.zig");
const p2p_types = @import("../../types.zig");
const Outbox = @import("../outbox.zig").Outbox;
const types = @import("types.zig");
const tracker_mod = @import("tracker.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const Key = cryptography.ed25519.PublicKey;
const Tracker = tracker_mod.Tracker(Key);
const Info = Tracker.Info;
const Payload = types.Payload(Key);
const Ingress = p2p_types.Ingress;
const SystemTime = utils.SystemTime;
const gpa = testing.allocator;

const namespace = "test_tracker_actor_namespace_IP";
const payload_config: types.PayloadConfig = .{
    .max_bit_vec = 1024,
    .max_peers = 64,
    .max_data_length = 1024,
};

fn key(seed: u64) Key {
    return PrivateKey.from_seed(seed).public_key();
}

fn localhost(port: u16) Ingress {
    return .{ .socket = .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port } };
}

fn now_ms(io: Io) u64 {
    return SystemTime.from_timestamp(Io.Clock.real.now(io)).epoch_millis();
}

fn info_at(seed: u64, ingress: Ingress, timestamp: u64) Info {
    const signer = PrivateKey.from_seed(seed);
    return Info.sign(signer.public_key(), namespace, ingress, timestamp, &signer);
}

/// commonware's `default_test_config`: seed 0 is us, at 127.0.0.1:0.
fn test_config(io: Io, bootstrappers: []const Tracker.Bootstrapper) Tracker.Config {
    return .{
        .myself = info_at(0, localhost(0), now_ms(io)),
        .bootstrappers = bootstrappers,
        .allow_private_ips = true,
        .allow_dns = true,
        .max_peers_per_set = 1024,
        .tracked_peer_sets = 2,
        .peer_connection_cooldown = .from_millis(200),
        .peer_gossip_max_count = 5,
        .dial_fail_limit = 1,
        .block_duration = .from_secs(100),
    };
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
    registry: metrics.Registry,
    tracker: Tracker,
    unblock: Io.Future(Io.Cancelable!void),

    fn start(harness: *Harness, io: Io, config: Tracker.Config) !void {
        harness.registry = metrics.Registry.init(gpa);
        errdefer harness.registry.deinit();
        const scope = metrics.Scope.init(&harness.registry).child("actor");
        harness.tracker = try .init(gpa, io, &scope, config);
        harness.unblock = try io.concurrent(Tracker.run_unblock, .{&harness.tracker});
    }

    fn stop(harness: *Harness, io: Io) void {
        harness.unblock.cancel(io) catch {};
        harness.tracker.close();
        harness.tracker.deinit();
        harness.registry.deinit();
    }

    fn oracle(harness: *Harness) Tracker.Oracle {
        return .{ .tracker = &harness.tracker };
    }

    /// Tracks `primary` (sorted here) at `index`.
    fn track(harness: *Harness, index: u64, primary: []const Key) !void {
        try harness.track_both(index, primary, &.{});
    }

    fn track_both(
        harness: *Harness,
        index: u64,
        primary: []const Key,
        secondary: []const Key,
    ) !void {
        const first = try sorted(primary);
        defer gpa.free(first);
        const second = try sorted(secondary);
        defer gpa.free(second);
        const tracked: p2p.TrackedPeers(Key) = .{
            .primary = .init(first),
            .secondary = .init(second),
        };
        try testing.expectEqual(.ok, harness.oracle().track(index, tracked));
    }

    /// commonware's `connect_to_peer`: a listener reservation, then a connection that must
    /// receive our greeting. The caller releases the returned reservation.
    fn connect(harness: *Harness, peer: Key, outbox: *Outbox) !Tracker.Metadata {
        const reservation = harness.tracker.listen(peer) orelse return error.TestReservationFailed;
        errdefer harness.tracker.release(reservation);
        if (harness.tracker.connect(peer, outbox, false) == null) return error.TestNoGreeting;
        return reservation;
    }

    fn is_dialable(harness: *Harness, peer: Key) !bool {
        const dialable = try harness.tracker.dialable(gpa);
        defer gpa.free(dialable.peers);
        for (dialable.peers) |candidate| if (candidate.eql(peer)) return true;
        return false;
    }
};

fn sorted(keys: []const Key) ![]Key {
    const copy = try gpa.dupe(Key, keys);
    std.sort.pdq(Key, copy, {}, Key.less_than);
    return copy;
}

/// The position of `peer` in the sorted set `keys`.
fn position(keys: []const Key, peer: Key) !u64 {
    const set = try sorted(keys);
    defer gpa.free(set);
    for (set, 0..) |candidate, index| if (candidate.eql(peer)) return index;
    return error.TestNotInSet;
}

/// The next gossip payload queued on `outbox`, decoded (the caller frees it), or null.
fn next_payload(outbox: *Outbox) !?Payload {
    const next = outbox.try_next() orelse return null;
    const frame = switch (next) {
        .frame => |frame| frame,
        else => return error.TestUnexpectedKill,
    };
    defer frame.release();
    return try codec.decode_cfg(Payload, gpa, frame.bytes, payload_config);
}

fn expect_bit_vec(outbox: *Outbox) !types.BitVec {
    var payload = (try next_payload(outbox)) orelse return error.TestExpectedBitVec;
    switch (payload) {
        .bit_vec => |bit_vec| return bit_vec,
        else => {
            payload.deinit(gpa);
            return error.TestExpectedBitVec;
        },
    }
}

fn expect_peers(outbox: *Outbox) ![]const Info {
    var payload = (try next_payload(outbox)) orelse return error.TestExpectedPeers;
    switch (payload) {
        .peers => |peers| return peers,
        else => {
            payload.deinit(gpa);
            return error.TestExpectedPeers;
        },
    }
}

fn killed(outbox: *Outbox) bool {
    const next = outbox.try_next() orelse return false;
    return next == .killed;
}

fn bit_vec_of(index: u64, size: u64, known: []const u64) !types.BitVec {
    var bits = try types.BitMap.zeroes(gpa, size);
    for (known) |bit| bits.set(bit, true);
    return .{ .index = index, .bits = bits };
}

fn connect_unauthorized(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    // Neither as listener nor as dialer.
    try testing.expectEqual(null, harness.tracker.connect(key(1), &outbox, false));
    try testing.expectEqual(null, harness.tracker.connect(key(1), &outbox, true));
}

test "connecting an unauthorized peer returns no greeting" {
    try run(connect_unauthorized, .{});
}

fn connect_authorized(io: Io) !void {
    var harness: Harness = undefined;
    const config = test_config(io, &.{});
    try harness.start(io, config);
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    const reservation = harness.tracker.listen(key(1)).?;
    defer harness.tracker.release(reservation);
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    const greeting = harness.tracker.connect(key(1), &outbox, false).?;
    try testing.expect(greeting.public_key.eql(key(0)));
    try testing.expect(greeting.ingress.eql(config.myself.ingress));
    try testing.expect(greeting.verify(namespace));
}

test "an authorized peer receives our greeting" {
    try run(connect_authorized, .{});
}

fn construct_no_sets(io: Io) !void {
    var harness: Harness = undefined;
    const boot = [_]Tracker.Bootstrapper{.{ .peer = key(99), .ingress = localhost(9999) }};
    try harness.start(io, test_config(io, &boot));
    defer harness.stop(io);
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    const reservation = try harness.connect(key(99), &outbox);
    defer harness.tracker.release(reservation);
    harness.tracker.construct(key(99));
    try testing.expectEqual(null, try next_payload(&outbox));
}

test "construct with no tracked sets sends nothing" {
    try run(construct_no_sets, .{});
}

fn bit_vec_unknown_index(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    const reservation = try harness.connect(key(1), &outbox);
    defer harness.tracker.release(reservation);
    var unknown: types.BitVec = .{ .index = 99, .bits = try types.BitMap.ones(gpa, 1) };
    defer unknown.deinit(gpa);
    harness.tracker.bit_vec(key(1), &unknown);
    try testing.expectEqual(null, try next_payload(&outbox));
}

test "a bit vector for an unknown index gets no peers" {
    try run(bit_vec_unknown_index, .{});
}

fn bit_vec_length_mismatch(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1), key(2) });
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    const reservation = try harness.connect(key(1), &outbox);
    defer harness.tracker.release(reservation);
    // The set has three peers, the vector two bits.
    var invalid: types.BitVec = .{ .index = 0, .bits = try types.BitMap.ones(gpa, 2) };
    defer invalid.deinit(gpa);
    harness.tracker.bit_vec(key(1), &invalid);
    try testing.expect(killed(&outbox));
}

test "a bit vector of the wrong length kills the sender" {
    try run(bit_vec_length_mismatch, .{});
}

fn block_standard(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    const reservation = try harness.connect(key(1), &outbox);
    defer harness.tracker.release(reservation);
    try testing.expectEqual(.ok, harness.oracle().block(key(1)));
    try testing.expect(killed(&outbox));
    try testing.expect(!try harness.is_dialable(key(1)));
    // A repeat block is accepted; the forgotten connection is not killed again.
    try testing.expectEqual(.ok, harness.oracle().block(key(1)));
}

test "blocking a connected peer kills it once and makes it undialable" {
    try run(block_standard, .{});
}

fn block_already_blocked(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    try testing.expectEqual(.ok, harness.oracle().block(key(1)));
    try testing.expectEqual(.ok, harness.oracle().block(key(1)));
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    // The rejection is a missing greeting, not a kill.
    try testing.expectEqual(null, harness.tracker.connect(key(1), &outbox, false));
    try testing.expect(!killed(&outbox));
}

test "blocking a blocked peer is a no-op and its connect gets no greeting" {
    try run(block_already_blocked, .{});
}

fn expect_blocked(subscription: *Tracker.BlockedSubscription, expected: []const Key) !void {
    const blocked = (try subscription.recv(gpa)).?;
    defer gpa.free(blocked);
    try testing.expectEqual(expected.len, blocked.len);
    for (expected, blocked) |want, got| try testing.expect(want.eql(got));
}

fn blocked_subscription(io: Io) !void {
    var harness: Harness = undefined;
    const config = test_config(io, &.{});
    try harness.start(io, config);
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    var blocked = try harness.oracle().blocked();
    try expect_blocked(&blocked, &.{});
    _ = harness.oracle().block(key(1));
    try expect_blocked(&blocked, &.{key(1)});
    // A repeat block publishes nothing; a late subscriber starts from the current set.
    _ = harness.oracle().block(key(1));
    try io.sleep(.fromMilliseconds(10), .real);
    try testing.expectEqual(null, try blocked.try_recv(gpa));
    var late = try harness.oracle().blocked();
    try expect_blocked(&late, &.{key(1)});
    // Expiry clears the set for every subscriber.
    const expiry_ms: i64 = @intCast(config.block_duration.as_millis() + 10);
    try io.sleep(.fromMilliseconds(expiry_ms), .real);
    try expect_blocked(&blocked, &.{});
    try expect_blocked(&late, &.{});
}

test "the blocked subscription tracks blocks and their expiry" {
    try run(blocked_subscription, .{});
}

fn removed_peer_killed(io: Io) !void {
    var harness: Harness = undefined;
    var config = test_config(io, &.{});
    config.tracked_peer_sets = 1;
    config.max_peers_per_set = 2;
    try harness.start(io, config);
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    const reservation = try harness.connect(key(1), &outbox);
    defer harness.tracker.release(reservation);
    harness.tracker.construct(key(1));
    var bit_vec = try expect_bit_vec(&outbox);
    bit_vec.deinit(gpa);
    // The next set evicts the only one holding the connected peer.
    try harness.track(1, &.{ key(0), key(2) });
    try testing.expect(killed(&outbox));
    try testing.expect(reservation.public_key().eql(key(1)));
}

test "a new set kills a connected peer it removes" {
    try run(removed_peer_killed, .{});
}

fn reserved_removed_rejected(io: Io) !void {
    var harness: Harness = undefined;
    var config = test_config(io, &.{});
    config.tracked_peer_sets = 1;
    try harness.start(io, config);
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    const reservation = harness.tracker.listen(key(1)).?;
    try testing.expect(reservation.public_key().eql(key(1)));
    try harness.track(1, &.{ key(0), key(2) });
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    try testing.expectEqual(null, harness.tracker.connect(key(1), &outbox, false));
    try testing.expect(!killed(&outbox));
    // Releasing the reservation deletes the evicted record: only key(2) stays tracked.
    harness.tracker.release(reservation);
    try expect_gauge(&harness, "actor_directory_tracked", 1);
}

fn expect_gauge(harness: *Harness, name: []const u8, value: i64) !void {
    const text = try metrics.Scope.init(&harness.registry).encode(gpa);
    defer gpa.free(text);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len <= name.len or !std.mem.startsWith(u8, line, name)) continue;
        if (line[name.len] != ' ') continue;
        return testing.expectEqual(value, try std.fmt.parseInt(i64, line[name.len + 1 ..], 10));
    }
    return error.TestGaugeMissing;
}

test "a reserved peer removed before connecting gets no greeting" {
    try run(reserved_removed_rejected, .{});
}

fn rollover_keeps_connected(io: Io) !void {
    var harness: Harness = undefined;
    var config = test_config(io, &.{});
    config.tracked_peer_sets = 1;
    try harness.start(io, config);
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    var outbox = Outbox.init(gpa, io, 1);
    defer outbox.deinit();
    const reservation = try harness.connect(key(1), &outbox);
    defer harness.tracker.release(reservation);
    try harness.track(1, &.{ key(0), key(1), key(2) });
    try testing.expectEqual(null, outbox.try_next());
    harness.tracker.construct(key(1));
    var bit_vec = try expect_bit_vec(&outbox);
    bit_vec.deinit(gpa);
}

test "a connected peer in the new set survives the old set's rollover" {
    try run(rollover_keeps_connected, .{});
}

fn learns_unknown_peer(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    try harness.track(0, &.{ key(0), key(1) });
    const timestamp = now_ms(io);
    const info = info_at(2, localhost(2002), timestamp);
    const set1 = [_]Key{ key(0), key(1), key(2) };
    try harness.track(1, &set1);
    harness.tracker.peers(&.{info});
    var outbox1 = Outbox.init(gpa, io, 1);
    defer outbox1.deinit();
    var outbox2 = Outbox.init(gpa, io, 1);
    defer outbox2.deinit();
    const r1 = try harness.connect(key(1), &outbox1);
    defer harness.tracker.release(r1);
    const r2 = try harness.connect(key(2), &outbox2);
    defer harness.tracker.release(r2);
    // key(1) knows us and itself, not key(2).
    const known = [_]u64{ try position(&set1, key(0)), try position(&set1, key(1)) };
    var bit_vec = try bit_vec_of(1, set1.len, &known);
    defer bit_vec.deinit(gpa);
    harness.tracker.bit_vec(key(1), &bit_vec);
    const peers = try expect_peers(&outbox1);
    defer gpa.free(peers);
    try testing.expectEqual(1, peers.len);
    try testing.expect(peers[0].public_key.eql(key(2)));
    try testing.expect(peers[0].ingress.eql(localhost(2002)));
    try testing.expectEqual(timestamp, peers[0].timestamp);
}

test "gossiped info for an unknown peer is shared in reply to bit vectors" {
    try run(learns_unknown_peer, .{});
}

fn rejects_older_info(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    const ts_new = now_ms(io);
    const set0 = [_]Key{ key(0), key(1), key(2) };
    try harness.track(0, &set0);
    var outbox1 = Outbox.init(gpa, io, 1);
    defer outbox1.deinit();
    var outbox2 = Outbox.init(gpa, io, 1);
    defer outbox2.deinit();
    const r1 = try harness.connect(key(1), &outbox1);
    defer harness.tracker.release(r1);
    const r2 = try harness.connect(key(2), &outbox2);
    defer harness.tracker.release(r2);
    harness.tracker.peers(&.{info_at(2, localhost(2002), ts_new)});
    harness.tracker.peers(&.{info_at(2, localhost(2002), ts_new -| 100)});
    const known = [_]u64{ try position(&set0, key(0)), try position(&set0, key(1)) };
    var bit_vec = try bit_vec_of(0, set0.len, &known);
    defer bit_vec.deinit(gpa);
    harness.tracker.bit_vec(key(1), &bit_vec);
    const peers = try expect_peers(&outbox1);
    defer gpa.free(peers);
    try testing.expectEqual(1, peers.len);
    try testing.expect(peers[0].public_key.eql(key(2)));
    try testing.expectEqual(ts_new, peers[0].timestamp);
}

test "gossip keeps the newer info of a known peer" {
    try run(rejects_older_info, .{});
}

fn bootstrapper_dialable(io: Io) !void {
    var harness: Harness = undefined;
    const boot = [_]Tracker.Bootstrapper{.{ .peer = key(99), .ingress = localhost(9000) }};
    try harness.start(io, test_config(io, &boot));
    defer harness.stop(io);
    const dialable = try harness.tracker.dialable(gpa);
    defer gpa.free(dialable.peers);
    try testing.expectEqual(1, dialable.peers.len);
    try testing.expect(dialable.peers[0].eql(key(99)));
    // Dialing it reserves its ingress; an unknown peer gets no reservation.
    const reservation = harness.tracker.dial(key(99)).?;
    defer harness.tracker.release(reservation);
    switch (reservation) {
        .dialer => |dialer| {
            try testing.expect(dialer.peer.eql(key(99)));
            try testing.expect(dialer.ingress.eql(localhost(9000)));
        },
        .listener => return error.TestExpectedDialer,
    }
    try testing.expectEqual(null, harness.tracker.dial(key(100)));
}

test "a bootstrapper is dialable with no sets and dials at its ingress" {
    try run(bootstrapper_dialable, .{});
}

fn expect_keys(got: []const Key, want: []const Key) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |expected, actual| try testing.expect(expected.eql(actual));
}

fn secondary_not_dialable(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    var subscription = try harness.oracle().subscribe();
    defer subscription.deinit();
    try harness.track_both(0, &.{key(1)}, &.{key(2)});
    var update = (try subscription.recv()).?;
    defer update.deinit();
    try testing.expectEqual(0, update.index);
    try expect_keys(update.latest.primary, &.{key(1)});
    try expect_keys(update.latest.secondary, &.{key(2)});
    try expect_keys(update.all.primary, update.latest.primary);
    try expect_keys(update.all.secondary, &.{key(2)});
    try testing.expect(harness.tracker.acceptable(key(2)));
    harness.tracker.peers(&.{info_at(2, localhost(9002), now_ms(io))});
    try testing.expect(!try harness.is_dialable(key(2)));
}

test "secondary peers are acceptable but never dialable" {
    try run(secondary_not_dialable, .{});
}

fn overlap_primary_only(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    var subscription = try harness.oracle().subscribe();
    defer subscription.deinit();
    try harness.track_both(0, &.{key(1)}, &.{key(1)});
    var update = (try subscription.recv()).?;
    defer update.deinit();
    try testing.expectEqual(0, update.index);
    try expect_keys(update.latest.primary, &.{key(1)});
    try expect_keys(update.latest.secondary, &.{});
    try expect_keys(update.all.primary, update.latest.primary);
    try expect_keys(update.all.secondary, &.{});
    try testing.expect(harness.tracker.acceptable(key(1)));
}

test "a peer in both roles is reported as primary only" {
    try run(overlap_primary_only, .{});
}

fn bit_vec_comprehensive(io: Io) !void {
    var harness: Harness = undefined;
    try harness.start(io, test_config(io, &.{}));
    defer harness.stop(io);
    var outbox1 = Outbox.init(gpa, io, 1);
    defer outbox1.deinit();
    // Unauthorized: no greeting, no kill.
    try testing.expectEqual(null, harness.tracker.connect(key(1), &outbox1, false));
    try testing.expect(!killed(&outbox1));
    const set0 = [_]Key{ key(0), key(1), key(2) };
    try harness.track(0, &set0);
    const r1 = try harness.connect(key(1), &outbox1);
    defer harness.tracker.release(r1);
    const me = try position(&set0, key(0));
    const peer1 = try position(&set0, key(1));
    harness.tracker.construct(key(1));
    var first = try expect_bit_vec(&outbox1);
    defer first.deinit(gpa);
    try testing.expectEqual(0, first.index);
    try testing.expectEqual(set0.len, first.bits.len());
    try testing.expect(first.bits.get(me) and !first.bits.get(peer1));
    // Learning key(1)'s info shows in the next bit vector.
    const peer1_info = info_at(1, localhost(1001), now_ms(io));
    harness.tracker.peers(&.{peer1_info});
    harness.tracker.construct(key(1));
    var updated = try expect_bit_vec(&outbox1);
    defer updated.deinit(gpa);
    try testing.expect(updated.bits.get(me) and updated.bits.get(peer1));
    // key(1) knows only us, so we send it its own info.
    var knowledge = try bit_vec_of(0, set0.len, &.{me});
    defer knowledge.deinit(gpa);
    harness.tracker.bit_vec(key(1), &knowledge);
    const peers = try expect_peers(&outbox1);
    defer gpa.free(peers);
    try testing.expectEqual(1, peers.len);
    try testing.expect(peers[0].public_key.eql(key(1)));
    try testing.expect(peers[0].ingress.eql(localhost(1001)));
    try evicts_and_alternates(&harness, io, &outbox1);
}

/// Sets 1 and 2 evict set 0 (two tracked sets), killing key(1); key(2)'s bit vectors then
/// name set 1 or set 2, both over 100 draws.
fn evicts_and_alternates(harness: *Harness, io: Io, outbox1: *Outbox) !void {
    try harness.track(1, &.{ key(0), key(2) });
    try harness.track(2, &.{ key(0), key(3) });
    try testing.expect(killed(outbox1));
    var outbox2 = Outbox.init(gpa, io, 1);
    defer outbox2.deinit();
    const r2 = try harness.connect(key(2), &outbox2);
    defer harness.tracker.release(r2);
    var seen: [3]bool = @splat(false);
    for (0..100) |_| {
        harness.tracker.construct(key(2));
        var bit_vec = try expect_bit_vec(&outbox2);
        defer bit_vec.deinit(gpa);
        try testing.expect(bit_vec.index == 1 or bit_vec.index == 2);
        seen[bit_vec.index] = true;
    }
    try testing.expect(seen[1] and seen[2] and !seen[0]);
}

test "bit vectors reflect knowledge, answer with missing info, and follow eviction" {
    try run(bit_vec_comprehensive, .{});
}
