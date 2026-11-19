//! A peer known to the lookup tracker (commonware
//! `p2p/src/authenticated/lookup/actors/tracker/record.rs`): its address, connection status,
//! how many primary and secondary peer sets list it, and its reservation and dial schedule.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const codec = @import("codec");
const types = @import("../../types.zig");
const dialing = @import("../dialing.zig");

const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const DialStatus = dialing.DialStatus;
const ReserveResult = dialing.ReserveResult;

/// Where a peer is reachable.
pub const RecordAddress = union(enum) {
    /// The local node.
    myself,
    known: types.Address,
};

pub const Status = enum {
    /// Neither reserved nor connected.
    inert,
    /// Reserved for a connection attempt.
    reserved,
    /// Connected.
    active,
};

pub const Record = struct {
    address: RecordAddress,
    status: Status = .inert,
    /// The address changed while reserved or connected: the connection is torn down.
    stale_connection: bool = false,
    primary_sets: usize = 0,
    secondary_sets: usize = 0,
    /// Kept (and dialed) regardless of peer sets.
    persistent: bool,
    next_reservable_at: SystemTime = .UNIX_EPOCH,
    next_dial_at: SystemTime = .UNIX_EPOCH,

    pub fn known(address: types.Address) Record {
        return .{ .address = .{ .known = address }, .persistent = false };
    }

    pub fn myself() Record {
        return .{ .address = .myself, .persistent = true };
    }

    /// Replaces a known address. Returns whether it changed; a change marks a reserved or
    /// active connection stale.
    pub fn update(record: *Record, address: types.Address) bool {
        switch (record.address) {
            .myself => return false,
            .known => |*existing| {
                if (existing.eql(address)) return false;
                existing.* = address;
                if (record.is_reserved_or_connected()) record.stale_connection = true;
                return true;
            },
        }
    }

    pub fn increment_primary(record: *Record) void {
        record.primary_sets += 1;
    }

    pub fn decrement_primary(record: *Record) void {
        assert(record.primary_sets > 0);
        record.primary_sets -= 1;
    }

    pub fn increment_secondary(record: *Record) void {
        record.secondary_sets += 1;
    }

    pub fn decrement_secondary(record: *Record) void {
        assert(record.secondary_sets > 0);
        record.secondary_sets -= 1;
    }

    /// Reserves the peer for a connection at `now`; the next reservation waits `interval`
    /// and the next dial `interval` plus up to `interval` of jitter drawn from `rng`.
    pub fn reserve(
        record: *Record,
        rng: anytype,
        now: SystemTime,
        interval: Duration,
    ) ReserveResult {
        if (record.address == .myself or record.status != .inert) return .unavailable;
        if (now.order(record.next_reservable_at) == .lt) return .rate_limited;
        record.status = .reserved;
        record.stale_connection = false;
        record.next_reservable_at = now.saturating_add(interval);
        const jitter = dialing.divide(interval, 2);
        record.next_dial_at = record.next_reservable_at.add_jittered(rng, jitter);
        assert(record.next_dial_at.order(record.next_reservable_at) != .lt);
        return .reserved;
    }

    /// Promotes a reservation to a connection, unless the address changed meanwhile.
    pub fn connect(record: *Record) bool {
        assert(record.status == .reserved);
        if (record.stale_connection) return false;
        record.status = .active;
        return true;
    }

    pub fn release(record: *Record) void {
        assert(record.status != .inert);
        record.status = .inert;
        record.stale_connection = false;
    }

    pub fn is_blockable(record: *const Record) bool {
        return record.address != .myself;
    }

    pub fn is_reserved_or_connected(record: *const Record) bool {
        return record.status != .inert;
    }

    /// Whether a reservation or connection must be torn down.
    pub fn needs_teardown(record: *const Record) bool {
        return record.is_reserved_or_connected() and
            (record.stale_connection or !record.eligible());
    }

    /// Whether we dial this peer.
    pub fn is_outbound_target(record: *const Record) bool {
        return record.primary_sets > 0 or record.persistent;
    }

    pub fn dialable(
        record: *const Record,
        now: SystemTime,
        allow_private_ips: bool,
        allow_dns: bool,
    ) DialStatus {
        if (record.status != .inert or !record.is_outbound_target()) return .unavailable;
        const address = switch (record.address) {
            .known => |address| address,
            .myself => return .unavailable,
        };
        if (!address.ingress().is_valid(allow_private_ips, allow_dns)) return .unavailable;
        if (record.next_dial_at.order(now) == .gt) return .{ .after = record.next_dial_at };
        return .now;
    }

    /// Whether to accept an inbound connection from `source_ip`.
    pub fn acceptable(record: *const Record, source_ip: codec.IpAddr, bypass_ip_check: bool) bool {
        if (!record.eligible() or record.status != .inert) return false;
        if (bypass_ip_check) return true;
        return switch (record.address) {
            .known => |address| address.egress_ip().order(source_ip) == .eq,
            .myself => false,
        };
    }

    pub fn ingress(record: *const Record) ?types.Ingress {
        return switch (record.address) {
            .myself => null,
            .known => |address| address.ingress(),
        };
    }

    pub fn egress_ip(record: *const Record) ?codec.IpAddr {
        return switch (record.address) {
            .myself => null,
            .known => |address| address.egress_ip(),
        };
    }

    pub fn deletable(record: *const Record) bool {
        return record.primary_sets == 0 and record.secondary_sets == 0 and
            !record.persistent and record.status == .inert;
    }

    /// Whether the peer may hold a connection: known and listed in a set (or persistent).
    pub fn eligible(record: *const Record) bool {
        return switch (record.address) {
            .myself => false,
            .known => record.primary_sets > 0 or record.secondary_sets > 0 or record.persistent,
        };
    }
};

const testing = std.testing;
const Ipv4 = codec.Ipv4;
const TestRng = utils.rng.TestRng;
const death = utils.death;
const unreachable_code = "reached unreachable code";

fn socket(a: u8, b: u8, c: u8, d: u8, port: u16) codec.SocketAddr {
    return .{ .ip = .{ .v4 = Ipv4.init(a, b, c, d) }, .port = port };
}

fn test_address() types.Address {
    return .{ .symmetric = socket(54, 12, 1, 9, 8080) };
}

const epoch: SystemTime = .UNIX_EPOCH;

test "myself and known initial state" {
    const me = Record.myself();
    try testing.expect(me.address == .myself and me.status == .inert and me.persistent);
    try testing.expect(me.ingress() == null and !me.is_blockable());
    try testing.expect(!me.deletable() and !me.eligible());
    const known = Record.known(test_address());
    try testing.expect(known.status == .inert and !known.persistent);
    try testing.expect(known.ingress() != null and known.is_blockable());
    try testing.expect(known.deletable() and !known.eligible());
}

test "increment, decrement, and deletable" {
    var known = Record.known(test_address());
    known.increment_primary();
    try testing.expect(!known.deletable());
    known.decrement_primary();
    try testing.expect(known.deletable());
    var me = Record.myself();
    me.increment_primary();
    try testing.expect(!me.deletable());
    me.decrement_primary();
    try testing.expect(!me.deletable());
}

test "reserve, connect, and release" {
    var rng = TestRng.init(0);
    var record = Record.known(test_address());
    try testing.expectEqual(ReserveResult.reserved, record.reserve(&rng, epoch, .zero));
    try testing.expectEqual(ReserveResult.unavailable, record.reserve(&rng, epoch, .zero));
    try testing.expect(record.connect());
    try testing.expectEqual(Status.active, record.status);
    try testing.expectEqual(ReserveResult.unavailable, record.reserve(&rng, epoch, .zero));
    record.release();
    try testing.expectEqual(ReserveResult.reserved, record.reserve(&rng, epoch, .zero));
    record.release();
    try testing.expectEqual(Status.inert, record.status);
}

test "teardown after losing eligibility or address" {
    var rng = TestRng.init(0);
    var record = Record.known(test_address());
    record.increment_primary();
    try testing.expectEqual(ReserveResult.reserved, record.reserve(&rng, epoch, .zero));
    try testing.expect(!record.needs_teardown());
    record.decrement_primary();
    try testing.expect(record.needs_teardown());
    try testing.expect(record.connect());
    try testing.expect(record.needs_teardown());
    record.release();
    try testing.expect(!record.needs_teardown() and !record.is_reserved_or_connected());

    var moved = Record.known(test_address());
    moved.increment_primary();
    try testing.expectEqual(ReserveResult.reserved, moved.reserve(&rng, epoch, .zero));
    try testing.expect(moved.update(.{ .symmetric = socket(54, 12, 1, 10, 8081) }));
    try testing.expect(!moved.update(.{ .symmetric = socket(54, 12, 1, 10, 8081) }));
    try testing.expect(moved.needs_teardown());
    try testing.expect(!moved.connect());
    try testing.expectEqual(Status.reserved, moved.status);
    moved.release();
    try testing.expect(!moved.needs_teardown());
}

test "eligible and deletable through a connection" {
    var rng = TestRng.init(0);
    var record = Record.known(test_address());
    try testing.expect(!record.eligible());
    record.increment_primary();
    try testing.expect(record.eligible() and !record.deletable());
    _ = record.reserve(&rng, epoch, .zero);
    try testing.expect(record.connect());
    record.release();
    try testing.expect(!record.deletable());
    record.decrement_primary();
    try testing.expect(record.deletable() and !record.eligible());
    record.increment_secondary();
    try testing.expect(record.eligible() and !record.is_outbound_target());
    record.decrement_secondary();
}

test "acceptable checks eligibility, status, and source ip" {
    var rng = TestRng.init(0);
    const egress = codec.IpAddr{ .v4 = Ipv4.init(8, 8, 8, 8) };
    const wrong = codec.IpAddr{ .v4 = Ipv4.init(1, 2, 3, 4) };
    const address: types.Address = .{ .symmetric = socket(8, 8, 8, 8, 8080) };
    for ([_]bool{ false, true }) |bypass| {
        var record = Record.known(address);
        record.increment_primary();
        try testing.expect(record.acceptable(egress, bypass));
        try testing.expectEqual(bypass, record.acceptable(wrong, bypass));
        try testing.expect(!Record.known(address).acceptable(egress, bypass));
        _ = record.reserve(&rng, epoch, .zero);
        try testing.expect(!record.acceptable(egress, bypass));
        try testing.expect(record.connect());
        try testing.expect(!record.acceptable(egress, bypass));
        try testing.expect(!Record.myself().acceptable(egress, bypass));
    }
}

test "reserve schedules the next dial with jitter" {
    var rng = TestRng.init(0);
    var record = Record.known(test_address());
    record.increment_primary();
    try testing.expectEqual(DialStatus.now, record.dialable(epoch, true, true));
    const interval = Duration.from_secs(1);
    try testing.expectEqual(ReserveResult.reserved, record.reserve(&rng, epoch, interval));
    record.release();
    const after = record.dialable(epoch, true, true).after;
    try testing.expect(after.order(epoch.saturating_add(interval)) != .lt);
    try testing.expect(after.order(epoch.saturating_add(.from_secs(2))) != .gt);
}

test "reserve is rate limited until the interval passes" {
    var rng = TestRng.init(0);
    var record = Record.known(test_address());
    const interval = Duration.from_secs(5);
    try testing.expectEqual(ReserveResult.reserved, record.reserve(&rng, epoch, interval));
    record.release();
    try testing.expectEqual(ReserveResult.rate_limited, record.reserve(&rng, epoch, interval));
    const later = epoch.saturating_add(interval);
    try testing.expectEqual(ReserveResult.reserved, record.reserve(&rng, later, interval));
    record.release();

    // An effectively unbounded cooldown saturates instead of overflowing.
    var unbounded = Record.known(test_address());
    try testing.expectEqual(ReserveResult.reserved, unbounded.reserve(&rng, epoch, .max));
    unbounded.release();
    try testing.expectEqual(ReserveResult.rate_limited, unbounded.reserve(&rng, epoch, .max));
}

test "dialable checks the ingress" {
    const public = socket(8, 8, 8, 8, 8080);
    var record = Record.known(.{ .symmetric = public });
    record.increment_primary();
    try testing.expectEqual(DialStatus.now, record.dialable(epoch, false, true));

    const private_ingress: types.Address = .{ .asymmetric = .{
        .ingress = .{ .socket = socket(10, 0, 0, 1, 8080) },
        .egress = socket(8, 8, 8, 8, 9090),
    } };
    var private = Record.known(private_ingress);
    private.increment_primary();
    try testing.expectEqual(DialStatus.unavailable, private.dialable(epoch, false, true));
    try testing.expectEqual(DialStatus.now, private.dialable(epoch, true, true));

    const private_egress: types.Address = .{ .asymmetric = .{
        .ingress = .{ .socket = public },
        .egress = socket(10, 0, 0, 1, 9090),
    } };
    var egress = Record.known(private_egress);
    egress.increment_primary();
    try testing.expectEqual(DialStatus.now, egress.dialable(epoch, false, true));

    const host = utils.Hostname.literal("example.com");
    const dns: types.Address = .{ .asymmetric = .{
        .ingress = .{ .dns = .{ .host = host, .port = 8080 } },
        .egress = socket(8, 8, 8, 8, 9090),
    } };
    var named = Record.known(dns);
    named.increment_primary();
    try testing.expectEqual(DialStatus.now, named.dialable(epoch, false, true));
    try testing.expectEqual(DialStatus.unavailable, named.dialable(epoch, false, false));
}

test "lookup record: decrement_primary at zero panics" {
    // commonware `test_decrement_panics_at_zero`.
    try death.expect_panic(@src(), unreachable_code, struct {
        fn body() !void {
            var record = Record.known(test_address());
            try testing.expectEqual(0, record.primary_sets);
            record.decrement_primary();
        }
    }.body);
}

test "lookup record: connect from inert panics" {
    // commonware `test_connect_when_not_reserved_panics_from_inert`.
    try death.expect_panic(@src(), unreachable_code, struct {
        fn body() !void {
            var record = Record.known(test_address());
            _ = record.connect();
        }
    }.body);
}

test "lookup record: connect when active panics" {
    // commonware `test_connect_when_active_panics`.
    try death.expect_panic(@src(), unreachable_code, struct {
        fn body() !void {
            var rng = TestRng.init(0);
            var record = Record.known(test_address());
            try testing.expectEqual(.reserved, record.reserve(&rng, epoch, .zero));
            try testing.expect(record.connect());
            _ = record.connect();
        }
    }.body);
}

test "lookup record: release when inert panics" {
    // commonware `test_release_when_inert_panics`.
    try death.expect_panic(@src(), unreachable_code, struct {
        fn body() !void {
            var record = Record.known(test_address());
            record.release();
        }
    }.body);
}
