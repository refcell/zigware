//! Tests of the discovery tracker's record (commonware `tracker/record.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const cryptography = @import("cryptography");
const p2p_types = @import("../../types.zig");
const record_mod = @import("record.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Record = record_mod.Record(PublicKey);
const Info = Record.Info;
const Ingress = p2p_types.Ingress;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;

const namespace = "test";

fn socket(port: u16) Ingress {
    return .{ .socket = .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port } };
}

fn peer_info(seed: u64, ingress: Ingress, timestamp: u64) Info {
    const signer = PrivateKey.from_seed(seed);
    return Info.sign(signer.public_key(), namespace, ingress, timestamp, &signer);
}

fn expect_info(expected: Info, actual: ?Info) !void {
    const got = actual orelse return error.TestExpectedInfo;
    try testing.expect(expected.ingress.eql(got.ingress));
    try testing.expectEqual(expected.timestamp, got.timestamp);
    try testing.expect(expected.public_key.eql(got.public_key));
    try testing.expect(expected.signature.eql(got.signature));
}

test "initial states: unknown, myself, and bootstrapper" {
    const unknown = Record.unknown();
    try testing.expect(unknown.address == .unknown and unknown.status == .inert);
    try testing.expect(!unknown.persistent and unknown.ingress() == null);
    try testing.expect(unknown.sharable() == null and unknown.want(0));
    try testing.expect(unknown.deletable() and !unknown.eligible());

    const mine = peer_info(0, socket(8080), 100);
    const myself = Record.myself(mine);
    try testing.expect(myself.persistent and myself.ingress().?.eql(mine.ingress));
    try expect_info(mine, myself.sharable());
    try testing.expect(!myself.want(0) and !myself.deletable() and !myself.eligible());

    const bootstrapper = Record.bootstrapper(socket(8080));
    try testing.expect(bootstrapper.persistent and bootstrapper.ingress().?.eql(socket(8080)));
    try testing.expect(bootstrapper.sharable() == null and bootstrapper.want(0));
    try testing.expect(!bootstrapper.deletable() and bootstrapper.eligible());
}

test "unknown and bootstrapper records become discovered" {
    const info = peer_info(1, socket(8080), 1000);
    var unknown = Record.unknown();
    try testing.expect(unknown.update(info));
    try testing.expect(unknown.ingress().?.eql(info.ingress));
    try testing.expect(unknown.sharable() == null and !unknown.persistent);

    var bootstrapper = Record.bootstrapper(socket(9000));
    try testing.expect(bootstrapper.update(info));
    try testing.expect(bootstrapper.ingress().?.eql(info.ingress));
    // A bootstrapper stays persistent after discovery.
    try testing.expect(bootstrapper.sharable() == null and bootstrapper.persistent);
}

test "discovered records take only newer timestamps" {
    var record = Record.unknown();
    const current = peer_info(1, socket(8080), 1000);
    try testing.expect(record.update(current));
    try testing.expect(!record.update(peer_info(1, socket(8081), 500)));
    try testing.expect(!record.update(peer_info(1, socket(8081), 1000)));
    try testing.expect(record.ingress().?.eql(current.ingress));
    const newer = peer_info(1, socket(8081), 2000);
    try testing.expect(record.update(newer));
    try testing.expect(record.ingress().?.eql(newer.ingress));

    var myself = Record.myself(peer_info(0, socket(8080), 1000));
    try testing.expect(!myself.update(peer_info(1, socket(8081), 2000)));
    try testing.expect(!myself.update(peer_info(0, socket(8081), 2000)));
    try testing.expect(myself.ingress().?.eql(socket(8080)));
}

test "set counts and deletability" {
    var unknown = Record.unknown();
    unknown.increment_primary();
    try testing.expect(!unknown.deletable());
    unknown.decrement_primary();
    try testing.expect(unknown.deletable());
    unknown.increment_secondary();
    try testing.expect(!unknown.deletable() and unknown.eligible());
    unknown.decrement_secondary();
    try testing.expect(unknown.deletable());

    var bootstrapper = Record.bootstrapper(socket(8080));
    bootstrapper.increment_primary();
    bootstrapper.decrement_primary();
    try testing.expect(!bootstrapper.deletable());

    var myself = Record.myself(peer_info(0, socket(8080), 1));
    try testing.expect(!myself.is_blockable() and bootstrapper.is_blockable());
    try testing.expect(unknown.is_blockable());
}

test "reserve, connect, and release" {
    var rng = utils.rng.test_rng();
    var record = Record.unknown();
    record.increment_primary();
    const interval = Duration.from_secs(1);
    const start: SystemTime = .UNIX_EPOCH;
    try testing.expectEqual(.reserved, record.reserve(&rng, start, interval));
    try testing.expectEqual(record_mod.Status.reserved, record.status);
    try testing.expectEqual(.unavailable, record.reserve(&rng, start, interval));
    record.connect();
    try testing.expectEqual(record_mod.Status.active, record.status);
    try testing.expectEqual(.unavailable, record.reserve(&rng, start, interval));
    record.release();
    try testing.expectEqual(record_mod.Status.inert, record.status);
    // The cooldown holds until `interval` has passed.
    try testing.expectEqual(.rate_limited, record.reserve(&rng, start, interval));
    const later = start.saturating_add(interval);
    try testing.expectEqual(.reserved, record.reserve(&rng, later, interval));
    record.release();

    // The next dial lands between one and two cooldowns later.
    const reservable = later.saturating_add(interval);
    try testing.expectEqual(reservable, record.next_reservable_at);
    try testing.expect(record.next_dial_at.order(reservable) != .lt);
    const latest = reservable.saturating_add(interval);
    try testing.expect(record.next_dial_at.order(latest) != .gt);

    var myself = Record.myself(peer_info(0, socket(8080), 1));
    try testing.expectEqual(.unavailable, myself.reserve(&rng, start, interval));
}

test "needs teardown after losing eligibility" {
    var rng = utils.rng.test_rng();
    var record = Record.unknown();
    record.increment_primary();
    try testing.expect(!record.needs_teardown());
    try testing.expectEqual(.reserved, record.reserve(&rng, .UNIX_EPOCH, .from_secs(1)));
    try testing.expect(!record.needs_teardown());
    record.decrement_primary();
    try testing.expect(record.needs_teardown());
    record.connect();
    try testing.expect(record.needs_teardown());
    record.release();
    try testing.expect(!record.needs_teardown());
}

test "sharable only for myself and connected discovered peers" {
    var rng = utils.rng.test_rng();
    try testing.expect(Record.unknown().sharable() == null);
    try testing.expect(Record.bootstrapper(socket(8080)).sharable() == null);
    const info = peer_info(1, socket(8080), 1000);
    var record = Record.unknown();
    record.increment_primary();
    try testing.expect(record.update(info));
    try testing.expect(record.sharable() == null);
    try testing.expectEqual(.reserved, record.reserve(&rng, .UNIX_EPOCH, .from_secs(1)));
    try testing.expect(record.sharable() == null);
    record.connect();
    try expect_info(info, record.sharable());
    record.release();
    try testing.expect(record.sharable() == null);
}

test "dial failures count only the held ingress" {
    var record = Record.unknown();
    record.dial_failure(socket(8080));
    try testing.expect(record.address == .unknown);
    try testing.expect(record.update(peer_info(1, socket(8080), 1000)));
    record.dial_failure(socket(8080));
    record.dial_failure(socket(8080));
    try testing.expectEqual(@as(usize, 2), record.address.discovered.fails);
    record.dial_failure(socket(8081));
    try testing.expectEqual(@as(usize, 2), record.address.discovered.fails);
    record.dial_success();
    try testing.expectEqual(@as(usize, 0), record.address.discovered.fails);
    record.dial_failure(socket(8080));
    try testing.expectEqual(@as(usize, 1), record.address.discovered.fails);
}

test "want depends on failures and connection" {
    var rng = utils.rng.test_rng();
    for ([_]usize{ 0, 1, 2 }) |min_fails| {
        try testing.expect(Record.unknown().want(min_fails));
        try testing.expect(Record.bootstrapper(socket(8080)).want(min_fails));
        try testing.expect(!Record.myself(peer_info(0, socket(8080), 1)).want(min_fails));
        var record = Record.unknown();
        record.increment_primary();
        try testing.expect(record.update(peer_info(1, socket(8080), 1000)));
        try testing.expectEqual(min_fails == 0, record.want(min_fails));
        for (0..min_fails) |_| record.dial_failure(socket(8080));
        try testing.expect(record.want(min_fails));
        try testing.expectEqual(.reserved, record.reserve(&rng, .UNIX_EPOCH, .from_secs(0)));
        record.connect();
        try testing.expect(!record.want(min_fails));
        record.release();
        try testing.expect(record.want(min_fails));
        record.dial_success();
        try testing.expectEqual(min_fails == 0, record.want(min_fails));
    }
}

test "dialable needs an inert outbound target with a valid ingress" {
    var rng = utils.rng.test_rng();
    const now: SystemTime = .UNIX_EPOCH;
    try testing.expect(Record.unknown().dialable(now, true, true) == .unavailable);
    var bootstrapper = Record.bootstrapper(socket(8080));
    try testing.expect(bootstrapper.dialable(now, true, true) == .now);
    // A private address needs `allow_private_ips`.
    try testing.expect(bootstrapper.dialable(now, false, true) == .unavailable);
    try testing.expectEqual(.reserved, bootstrapper.reserve(&rng, now, .from_secs(1)));
    try testing.expect(bootstrapper.dialable(now, true, true) == .unavailable);
    bootstrapper.release();
    const status = bootstrapper.dialable(now, true, true);
    try testing.expectEqual(bootstrapper.next_dial_at, status.after);

    // Secondary-only peers are accepted but never dialed.
    var secondary = Record.unknown();
    secondary.increment_secondary();
    try testing.expect(secondary.update(peer_info(1, socket(8080), 1000)));
    try testing.expect(secondary.dialable(now, true, true) == .unavailable);
    try testing.expect(secondary.acceptable());
}
