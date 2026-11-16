//! The lookup tracker's view of every known peer (commonware
//! `p2p/src/authenticated/lookup/actors/tracker/directory.rs`): records, the tracked peer
//! sets (oldest evicted beyond `max_sets`), blocks, and reservations.
//!
//! Callers pass the current time and an RNG instead of a runtime context. Iteration follows
//! key order, so every result is deterministic (commonware sorts the same results).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const p2p = @import("../../root.zig");
const types = @import("../../types.zig");
const dialing = @import("../dialing.zig");
const SortedMap = @import("../../simulated/sorted_map.zig").SortedMap;
const sim_tracker = @import("../../simulated/tracker.zig");
const record_mod = @import("record.zig");

const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Record = record_mod.Record;

pub const Config = struct {
    allow_private_ips: bool,
    allow_dns: bool,
    bypass_ip_check: bool,
    /// Peer sets kept; tracking a newer one evicts the oldest.
    max_sets: usize,
    peer_connection_cooldown: Duration,
    block_duration: Duration,
};

/// Who holds a reservation: the dialer (outbound) or the listener (inbound).
pub fn Metadata(comptime P: type) type {
    return union(enum) {
        dialer: P,
        listener: P,

        pub fn public_key(metadata: @This()) P {
            return switch (metadata) {
                inline else => |peer| peer,
            };
        }
    };
}

/// Sorted primary and secondary keys owned by the caller.
pub fn Owned(comptime P: type) type {
    return sim_tracker.Tracker(P).Owned;
}

/// Peers to dial now, and when another may become dialable.
pub fn Dialable(comptime P: type) type {
    return struct { peers: []P, next_query_at: ?SystemTime };
}

pub fn Directory(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Tracked = p2p.AddressableTrackedPeers(P);
        pub const Peers = Owned(P);
        /// A peer-set change, as subscribers receive it.
        pub const Update = sim_tracker.Tracker(P).Update;
        const Sets = struct { primary: []P, secondary: []P };

        gpa: Allocator,
        config: Config,
        peers: SortedMap(P, Record) = .empty,
        peer_sets: SortedMap(u64, Sets) = .empty,
        /// Blocked peers and when each block ends.
        blocked: SortedMap(P, SystemTime) = .empty,

        pub fn init(gpa: Allocator, myself: P, config: Config) Allocator.Error!Self {
            assert(config.max_sets > 0);
            var directory: Self = .{ .gpa = gpa, .config = config };
            _ = try directory.peers.put(gpa, myself, Record.myself());
            return directory;
        }

        pub fn deinit(directory: *Self) void {
            for (directory.peer_sets.items()) |entry| directory.free_sets(entry.value);
            directory.peer_sets.deinit(directory.gpa);
            directory.peers.deinit(directory.gpa);
            directory.blocked.deinit(directory.gpa);
            directory.* = undefined;
        }

        fn free_sets(directory: *Self, sets: Sets) void {
            directory.gpa.free(sets.primary);
            directory.gpa.free(sets.secondary);
        }

        /// Ends a reservation or connection.
        pub fn release(directory: *Self, metadata: Metadata(P)) void {
            const peer = metadata.public_key();
            const record = directory.peers.get(peer) orelse return;
            record.release();
            directory.delete_if_needed(peer);
        }

        /// Promotes a reservation to a connection; false if its address changed meanwhile.
        pub fn connect(directory: *Self, peer: P) bool {
            return directory.peers.get(peer).?.connect();
        }

        /// Tracks `peers` at `index`, which must exceed every tracked index. Returns the peers
        /// whose reservation or connection must be torn down (sorted), or null when ignored.
        pub fn track(directory: *Self, index: u64, peers: Tracked) Allocator.Error!?[]P {
            if (directory.peer_sets.count() > 0) {
                const sets = directory.peer_sets.items();
                if (index <= sets[sets.len - 1].key) return null;
            }
            var kill: std.ArrayList(P) = .empty;
            defer kill.deinit(directory.gpa);
            for (peers.primary.entries) |entry| {
                const record = try directory.upsert(entry.key, entry.value, &kill);
                record.increment_primary();
            }
            var secondary: std.ArrayList(P) = .empty;
            defer secondary.deinit(directory.gpa);
            for (peers.secondary.entries) |entry| {
                if (contains_key(peers.primary, entry.key)) continue;
                const record = try directory.upsert(entry.key, entry.value, &kill);
                record.increment_secondary();
                try secondary.append(directory.gpa, entry.key);
            }
            const primary = try directory.gpa.alloc(P, peers.primary.entries.len);
            for (primary, peers.primary.entries) |*key, entry| key.* = entry.key;
            const sets: Sets = .{
                .primary = primary,
                .secondary = secondary.toOwnedSlice(directory.gpa) catch |err| {
                    directory.gpa.free(primary);
                    return err;
                },
            };
            _ = directory.peer_sets.put(directory.gpa, index, sets) catch |err| {
                directory.free_sets(sets);
                return err;
            };
            while (directory.peer_sets.count() > directory.config.max_sets) {
                try directory.evict_oldest(&kill);
            }
            const unique = sorted_unique(P, kill.items, less_than);
            return try directory.gpa.dupe(P, unique);
        }

        fn contains_key(map: Tracked.PeerMap, peer: P) bool {
            for (map.entries) |entry| if (P.order(entry.key, peer) == .eq) return true;
            return false;
        }

        /// The record for `peer` with `address`, created when new. An address change on a
        /// reserved or connected peer queues it for teardown.
        fn upsert(
            directory: *Self,
            peer: P,
            address: types.Address,
            kill: *std.ArrayList(P),
        ) Allocator.Error!*Record {
            if (directory.peers.get(peer)) |record| {
                if (record.update(address) and record.is_reserved_or_connected()) {
                    try kill.append(directory.gpa, peer);
                }
                return record;
            }
            return directory.peers.get_or_put(directory.gpa, peer, Record.known(address));
        }

        fn evict_oldest(directory: *Self, kill: *std.ArrayList(P)) Allocator.Error!void {
            const oldest = directory.peer_sets.items()[0];
            _ = directory.peer_sets.remove(oldest.key);
            defer directory.free_sets(oldest.value);
            for (oldest.value.primary) |peer| {
                directory.peers.get(peer).?.decrement_primary();
                try directory.queue_if_needs_teardown(peer, kill);
            }
            for (oldest.value.secondary) |peer| {
                directory.peers.get(peer).?.decrement_secondary();
                try directory.queue_if_needs_teardown(peer, kill);
            }
        }

        fn queue_if_needs_teardown(
            directory: *Self,
            peer: P,
            kill: *std.ArrayList(P),
        ) Allocator.Error!void {
            const record = directory.peers.get(peer) orelse return;
            if (record.needs_teardown()) try kill.append(directory.gpa, peer);
            directory.delete_if_needed(peer);
        }

        fn delete_if_needed(directory: *Self, peer: P) void {
            const record = directory.peers.get(peer) orelse return;
            if (record.deletable()) _ = directory.peers.remove(peer);
        }

        /// Updates a tracked peer's address. Returns whether it changed.
        pub fn overwrite(directory: *Self, peer: P, address: types.Address) bool {
            const record = directory.peers.get(peer) orelse return false;
            return record.update(address);
        }

        /// A copy of the sets at `index`.
        pub fn peer_set(directory: *const Self, gpa: Allocator, index: u64) Allocator.Error!?Peers {
            const sets = directory.peer_sets.get(index) orelse return null;
            const primary = try gpa.dupe(P, sets.primary);
            errdefer gpa.free(primary);
            return .{ .primary = primary, .secondary = try gpa.dupe(P, sets.secondary) };
        }

        pub fn latest_set_index(directory: *const Self) ?u64 {
            const sets = directory.peer_sets.items();
            if (sets.len == 0) return null;
            return sets[sets.len - 1].key;
        }

        /// The latest tracked set and every tracked peer, or null before the first set.
        pub fn latest_update(directory: *const Self, gpa: Allocator) Allocator.Error!?Update {
            const index = directory.latest_set_index() orelse return null;
            const latest = (try directory.peer_set(gpa, index)).?;
            errdefer latest.free(gpa);
            const every = try directory.all(gpa);
            return .{ .gpa = gpa, .index = index, .latest = latest, .all = every };
        }

        /// Every peer in a tracked set: primary when any set lists it as primary.
        pub fn all(directory: *const Self, gpa: Allocator) Allocator.Error!Peers {
            var primary: std.ArrayList(P) = .empty;
            errdefer primary.deinit(gpa);
            var secondary: std.ArrayList(P) = .empty;
            errdefer secondary.deinit(gpa);
            for (directory.peers.items()) |entry| {
                if (entry.value.primary_sets > 0) {
                    try primary.append(gpa, entry.key);
                } else if (entry.value.secondary_sets > 0) {
                    try secondary.append(gpa, entry.key);
                }
            }
            const primary_slice = try primary.toOwnedSlice(gpa);
            errdefer gpa.free(primary_slice);
            return .{ .primary = primary_slice, .secondary = try secondary.toOwnedSlice(gpa) };
        }

        /// Reserves `peer` for an outbound dial, returning its ingress.
        pub fn dial(
            directory: *Self,
            rng: anytype,
            now: SystemTime,
            peer: P,
        ) ?struct { metadata: Metadata(P), ingress: types.Ingress } {
            const record = directory.peers.get(peer) orelse return null;
            const config = directory.config;
            const status = record.dialable(now, config.allow_private_ips, config.allow_dns);
            if (status == .unavailable) return null;
            const ingress = record.ingress() orelse return null;
            const metadata = directory.reserve(rng, now, .{ .dialer = peer }) orelse return null;
            return .{ .metadata = metadata, .ingress = ingress };
        }

        /// Reserves `peer` for an inbound connection from `source_ip`.
        pub fn listen(
            directory: *Self,
            rng: anytype,
            now: SystemTime,
            peer: P,
            source_ip: codec.IpAddr,
        ) ?Metadata(P) {
            if (!directory.acceptable(now, peer, source_ip)) return null;
            return directory.reserve(rng, now, .{ .listener = peer });
        }

        fn reserve(
            directory: *Self,
            rng: anytype,
            now: SystemTime,
            metadata: Metadata(P),
        ) ?Metadata(P) {
            const peer = metadata.public_key();
            if (!directory.eligible(now, peer)) return null;
            const record = directory.peers.get(peer).?;
            const cooldown = directory.config.peer_connection_cooldown;
            return switch (record.reserve(rng, now, cooldown)) {
                .reserved => metadata,
                .rate_limited, .unavailable => null,
            };
        }

        fn is_blocked(directory: *const Self, now: SystemTime, peer: P) bool {
            const until = directory.blocked.get(peer) orelse return false;
            return until.order(now) == .gt;
        }

        /// Blocks `peer` for `block_duration`. Returns false if already blocked or ourselves.
        pub fn block(directory: *Self, now: SystemTime, peer: P) Allocator.Error!bool {
            if (directory.is_blocked(now, peer)) return false;
            if (directory.peers.get(peer)) |record| {
                if (!record.is_blockable()) return false;
            }
            const until = now.saturating_add(directory.config.block_duration);
            _ = try directory.blocked.put(directory.gpa, peer, until);
            return true;
        }

        pub fn eligible(directory: *const Self, now: SystemTime, peer: P) bool {
            if (directory.is_blocked(now, peer)) return false;
            const record = directory.peers.get(peer) orelse return false;
            return record.eligible();
        }

        /// Peers to dial now (sorted) and the earliest time another may become dialable.
        pub fn dialable(
            directory: *const Self,
            gpa: Allocator,
            now: SystemTime,
        ) Allocator.Error!Dialable(P) {
            var next_query_at: ?SystemTime = null;
            var peers: std.ArrayList(P) = .empty;
            errdefer peers.deinit(gpa);
            const config = directory.config;
            for (directory.peers.items()) |entry| {
                if (directory.blocked.get(entry.key)) |until| {
                    if (until.order(now) == .gt) {
                        next_query_at = dialing.earliest(next_query_at, until.*);
                        continue;
                    }
                }
                switch (entry.value.dialable(now, config.allow_private_ips, config.allow_dns)) {
                    .now => try peers.append(gpa, entry.key),
                    .after => |time| next_query_at = dialing.earliest(next_query_at, time),
                    .unavailable => {},
                }
            }
            return .{ .peers = try peers.toOwnedSlice(gpa), .next_query_at = next_query_at };
        }

        pub fn acceptable(
            directory: *const Self,
            now: SystemTime,
            peer: P,
            source_ip: codec.IpAddr,
        ) bool {
            if (directory.is_blocked(now, peer)) return false;
            const record = directory.peers.get(peer) orelse return false;
            return record.acceptable(source_ip, directory.config.bypass_ip_check);
        }

        /// Egress IPs of eligible, unblocked peers (sorted, unique) that may connect to us.
        pub fn listenable(
            directory: *const Self,
            gpa: Allocator,
            now: SystemTime,
        ) Allocator.Error![]codec.IpAddr {
            var ips: std.ArrayList(codec.IpAddr) = .empty;
            defer ips.deinit(gpa);
            for (directory.peers.items()) |entry| {
                if (directory.is_blocked(now, entry.key) or !entry.value.eligible()) continue;
                const ip = entry.value.egress_ip() orelse continue;
                if (!directory.config.allow_private_ips and !utils.net.is_global(ip)) continue;
                try ips.append(gpa, ip);
            }
            return gpa.dupe(codec.IpAddr, sorted_unique(codec.IpAddr, ips.items, ip_less_than));
        }

        /// Peers whose block has not expired, sorted.
        pub fn blocked_peers(
            directory: *const Self,
            gpa: Allocator,
            now: SystemTime,
        ) Allocator.Error![]P {
            var peers: std.ArrayList(P) = .empty;
            errdefer peers.deinit(gpa);
            for (directory.blocked.items()) |entry| {
                if (entry.value.order(now) == .gt) try peers.append(gpa, entry.key);
            }
            return peers.toOwnedSlice(gpa);
        }

        /// Forgets expired blocks. Returns whether any expired.
        pub fn unblock_expired(directory: *Self, now: SystemTime) bool {
            var any = false;
            var index: usize = 0;
            while (index < directory.blocked.count()) {
                const entry = directory.blocked.items()[index];
                if (entry.value.order(now) == .gt) {
                    index += 1;
                    continue;
                }
                _ = directory.blocked.remove(entry.key);
                any = true;
            }
            return any;
        }

        /// When the earliest block ends, if any peer is blocked.
        pub fn next_unblock(directory: *const Self) ?SystemTime {
            var next: ?SystemTime = null;
            for (directory.blocked.items()) |entry| next = dialing.earliest(next, entry.value);
            return next;
        }

        fn less_than(_: void, a: P, b: P) bool {
            return P.order(a, b) == .lt;
        }
    };
}

fn ip_less_than(_: void, a: codec.IpAddr, b: codec.IpAddr) bool {
    return a.order(b) == .lt;
}

/// Sorts `slice` in place and returns its unique prefix.
fn sorted_unique(
    comptime T: type,
    slice: []T,
    comptime less: fn (void, T, T) bool,
) []T {
    std.sort.pdq(T, slice, {}, less);
    var unique: usize = 0;
    for (slice) |item| {
        if (unique > 0 and !less({}, slice[unique - 1], item)) continue;
        slice[unique] = item;
        unique += 1;
    }
    assert(unique <= slice.len);
    return slice[0..unique];
}

test {
    _ = @import("directory_test.zig");
}
