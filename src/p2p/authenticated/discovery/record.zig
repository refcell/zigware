//! A peer known to the discovery tracker (commonware
//! `p2p/src/authenticated/discovery/actors/tracker/record.rs`): what we know of its address,
//! its connection status, how many peer sets list it, and its reservation and dial schedule.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const p2p_types = @import("../../types.zig");
const dialing = @import("../dialing.zig");
const types = @import("types.zig");

const Ingress = p2p_types.Ingress;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const DialStatus = dialing.DialStatus;
const ReserveResult = dialing.ReserveResult;

pub const Status = enum {
    /// Neither reserved nor connected.
    inert,
    /// Reserved by a task establishing a connection.
    reserved,
    /// Connected; returns to `inert` when the connection closes.
    active,
};

pub fn Record(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Info = types.Info(P);

        /// What we know of the peer's address.
        pub const Address = union(enum) {
            /// Not yet known; may become `discovered`.
            unknown,
            /// The local node.
            myself: Info,
            /// Configured at startup; may become `discovered`.
            bootstrapper: Ingress,
            /// Learned from gossip, with the number of failed dials since.
            discovered: struct { info: Info, fails: usize },
        };

        address: Address,
        status: Status = .inert,
        /// Primary peer sets that list this peer.
        primary_sets: usize = 0,
        /// Secondary peer sets that list this peer.
        secondary_sets: usize = 0,
        /// Kept even when no peer set lists it.
        persistent: bool,
        /// The earliest time the peer may be reserved again.
        next_reservable_at: SystemTime = .UNIX_EPOCH,
        /// The earliest time the peer may be dialed.
        next_dial_at: SystemTime = .UNIX_EPOCH,

        pub fn unknown() Self {
            return .{ .address = .unknown, .persistent = false };
        }

        pub fn myself(info: Info) Self {
            return .{ .address = .{ .myself = info }, .persistent = true };
        }

        pub fn bootstrapper(address: Ingress) Self {
            return .{ .address = .{ .bootstrapper = address }, .persistent = true };
        }

        /// Adopts `info` unless this is us or it is not newer than what we hold. Returns
        /// whether the record changed.
        pub fn update(record: *Self, info: Info) bool {
            switch (record.address) {
                .myself => return false,
                .unknown, .bootstrapper => {},
                .discovered => |previous| {
                    if (previous.info.timestamp >= info.timestamp) return false;
                },
            }
            record.address = .{ .discovered = .{ .info = info, .fails = 0 } };
            return true;
        }

        pub fn increment_primary(record: *Self) void {
            record.primary_sets += 1;
        }

        pub fn decrement_primary(record: *Self) void {
            assert(record.primary_sets > 0);
            record.primary_sets -= 1;
        }

        pub fn increment_secondary(record: *Self) void {
            record.secondary_sets += 1;
        }

        pub fn decrement_secondary(record: *Self) void {
            assert(record.secondary_sets > 0);
            record.secondary_sets -= 1;
        }

        /// Whether we dial this peer: primary or persistent peers.
        pub fn is_outbound_target(record: *const Self) bool {
            return record.primary_sets > 0 or record.persistent;
        }

        /// Reserves an inert peer that is not us and past its cooldown; the next dial lands
        /// in `[now + interval, now + 2 * interval]`.
        pub fn reserve(
            record: *Self,
            rng: anytype,
            now: SystemTime,
            interval: Duration,
        ) ReserveResult {
            if (record.address == .myself or record.status != .inert) return .unavailable;
            if (now.order(record.next_reservable_at) == .lt) return .rate_limited;
            record.status = .reserved;
            record.next_reservable_at = now.saturating_add(interval);
            const half = dialing.divide(interval, 2);
            record.next_dial_at = record.next_reservable_at.add_jittered(rng, half);
            assert(record.next_dial_at.order(record.next_reservable_at) != .lt);
            return .reserved;
        }

        /// Marks a reserved peer connected.
        pub fn connect(record: *Self) void {
            assert(record.status == .reserved);
            record.status = .active;
        }

        /// Ends a reservation or connection.
        pub fn release(record: *Self) void {
            if (record.status == .inert) @panic("Cannot release an Inert peer");
            record.status = .inert;
        }

        /// Counts a failed dial to `ingress`, if it is still the address we hold.
        pub fn dial_failure(record: *Self, dialed: Ingress) void {
            switch (record.address) {
                .discovered => |*discovered| {
                    if (discovered.info.ingress.eql(dialed)) discovered.fails += 1;
                },
                else => {},
            }
        }

        /// Clears the failure count after a successful dial.
        pub fn dial_success(record: *Self) void {
            switch (record.address) {
                .discovered => |*discovered| discovered.fails = 0,
                else => {},
            }
        }

        /// Every peer but us can be blocked.
        pub fn is_blockable(record: *const Self) bool {
            return record.address != .myself;
        }

        /// Whether a reservation or connection must be torn down.
        pub fn needs_teardown(record: *const Self) bool {
            return record.status != .inert and !record.eligible();
        }

        /// Whether the peer can be dialed at `now`, later, or not at all.
        pub fn dialable(
            record: *const Self,
            now: SystemTime,
            allow_private_ips: bool,
            allow_dns: bool,
        ) DialStatus {
            if (record.status != .inert or !record.is_outbound_target()) return .unavailable;
            const address = switch (record.address) {
                .bootstrapper => |address| address,
                .discovered => |discovered| discovered.info.ingress,
                .unknown, .myself => return .unavailable,
            };
            if (!address.is_valid(allow_private_ips, allow_dns)) return .unavailable;
            if (record.next_dial_at.order(now) == .gt) return .{ .after = record.next_dial_at };
            return .now;
        }

        /// Whether we accept an inbound connection: eligible and neither reserved nor
        /// connected.
        pub fn acceptable(record: *const Self) bool {
            return record.eligible() and record.status == .inert;
        }

        pub fn ingress(record: *const Self) ?Ingress {
            return switch (record.address) {
                .unknown => null,
                .myself => |info| info.ingress,
                .bootstrapper => |ingress_value| ingress_value,
                .discovered => |discovered| discovered.info.ingress,
            };
        }

        /// Our own info, or a discovered peer's while we are connected to it.
        pub fn sharable(record: *const Self) ?Info {
            return switch (record.address) {
                .unknown, .bootstrapper => null,
                .myself => |info| info,
                .discovered => |discovered| if (record.status == .active)
                    discovered.info
                else
                    null,
            };
        }

        /// Whether to ask other peers for this peer's info: never for us, always when we have
        /// none, and otherwise when disconnected after at least `min_fails` failed dials.
        pub fn want(record: *const Self, min_fails: usize) bool {
            return switch (record.address) {
                .myself => false,
                .unknown, .bootstrapper => true,
                .discovered => |discovered| record.status != .active and
                    discovered.fails >= min_fails,
            };
        }

        pub fn deletable(record: *const Self) bool {
            return record.primary_sets == 0 and record.secondary_sets == 0 and
                !record.persistent and record.status == .inert;
        }

        /// Not us, and in a peer set or persistent.
        pub fn eligible(record: *const Self) bool {
            if (record.address == .myself) return false;
            return record.primary_sets > 0 or record.secondary_sets > 0 or record.persistent;
        }
    };
}

test {
    _ = @import("record_test.zig");
}
