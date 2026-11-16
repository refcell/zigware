//! The discovery tracker's view of every known peer (commonware
//! `p2p/src/authenticated/discovery/actors/tracker/directory.rs`): records, the tracked peer
//! sets with their knowledge bits, blocks, and reservations.
//!
//! Callers pass the current time and an RNG instead of a runtime context. Peers iterate in key
//! order, so results are deterministic (commonware sorts the same results).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
const traces = @import("runtime").telemetry.traces;
const p2p = @import("../../root.zig");
const p2p_types = @import("../../types.zig");
const dialing = @import("../dialing.zig");
const SortedMap = @import("../../simulated/sorted_map.zig").SortedMap;
const sim_tracker = @import("../../simulated/tracker.zig");
const types = @import("types.zig");
const record_mod = @import("record.zig");
const BitSet = @import("bit_set.zig").BitSet;

const Ingress = p2p_types.Ingress;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;

pub const Config = struct {
    allow_private_ips: bool,
    allow_dns: bool,
    /// Peer sets kept; tracking a newer one evicts the oldest.
    max_sets: usize,
    /// Failed dials before we ask other peers for a peer's info again.
    dial_fail_limit: usize,
    /// Minimum time between reservations of one peer.
    peer_connection_cooldown: Duration,
    block_duration: Duration,
    /// Under commonware's `actors::tracker::directory` target.
    tracer: traces.Tracer = .none,
};

/// Who holds a reservation: the dialer (with the ingress it dials) or the listener.
pub fn Metadata(comptime P: type) type {
    return union(enum) {
        dialer: struct { peer: P, ingress: Ingress },
        listener: P,

        pub fn public_key(metadata: @This()) P {
            return switch (metadata) {
                .dialer => |dialer| dialer.peer,
                .listener => |peer| peer,
            };
        }
    };
}

/// Peers to dial now, and when another may become dialable.
pub fn Dialable(comptime P: type) type {
    return struct { peers: []P, next_query_at: ?SystemTime };
}

/// The directory's metrics (commonware `discovery/actors/tracker/metrics.rs`). Recording never
/// fails an operation: a per-peer series whose label cannot be allocated goes unrecorded.
pub fn Metrics(comptime P: type) type {
    return struct {
        const Self = @This();
        /// Per-peer label.
        pub const Peer = struct { peer: P };
        const GaugeFamily = metrics.raw.Family(Peer, metrics.raw.Gauge);
        const CounterFamily = metrics.raw.Family(Peer, metrics.raw.Counter);

        /// Unique peers in all tracked sets, with bootstrappers and without ourselves.
        tracked: metrics.Gauge,
        /// Blocked peers (value = expiry time as epoch millis).
        blocked: metrics.Registered(GaugeFamily),
        /// Outstanding reservations.
        reserved: metrics.Gauge,
        /// Epoch millis when each connected peer became active.
        connected: metrics.Registered(GaugeFamily),
        /// Rate-limited reservations of each peer.
        limits: metrics.Registered(CounterFamily),
        /// Info updates of each peer.
        updates: metrics.Registered(CounterFamily),

        pub fn init(scope: *const metrics.Scope) Allocator.Error!Self {
            const tracked_help = "Total number of unique peers in all peer sets being tracked";
            var tracked = try scope.gauge("tracked", tracked_help);
            errdefer tracked.deinit();
            const blocked_help = "Blocked peers (value = expiry time as epoch millis)";
            var blocked = try scope.family(Peer, metrics.raw.Gauge, "blocked", blocked_help);
            errdefer blocked.deinit();
            var reserved = try scope.gauge("reserved", "Total number of outstanding reservations");
            errdefer reserved.deinit();
            const connected_help =
                "Unix timestamp in milliseconds when each connected peer became active";
            var connected = try scope.family(Peer, metrics.raw.Gauge, "connected", connected_help);
            errdefer connected.deinit();
            const limits_help =
                "Count of the number of rate-limited reservation events for each peer";
            var limits = try scope.family(Peer, metrics.raw.Counter, "limits", limits_help);
            errdefer limits.deinit();
            const updates_help = "Count of the number of updates for each peer";
            const updates = try scope.family(Peer, metrics.raw.Counter, "updates", updates_help);
            return .{
                .tracked = tracked,
                .blocked = blocked,
                .reserved = reserved,
                .connected = connected,
                .limits = limits,
                .updates = updates,
            };
        }

        pub fn deinit(self: *Self) void {
            self.tracked.deinit();
            self.blocked.deinit();
            self.reserved.deinit();
            self.connected.deinit();
            self.limits.deinit();
            self.updates.deinit();
            self.* = undefined;
        }

        /// Sets `peer`'s series in `family` to `millis`.
        fn set(family: *metrics.Registered(GaugeFamily), peer: P, millis: u64) void {
            const gauge = family.metric().get_or_create(.{ .peer = peer }) catch return;
            _ = gauge.try_set(millis) catch {};
        }

        fn count(family: *metrics.Registered(CounterFamily), peer: P) void {
            const counter = family.metric().get_or_create(.{ .peer = peer }) catch return;
            counter.inc();
        }
    };
}

pub fn Directory(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Record = record_mod.Record(P);
        pub const Info = types.Info(P);
        pub const Tracked = p2p.TrackedPeers(P);
        pub const Owned = sim_tracker.Tracker(P).Owned;
        pub const Update = sim_tracker.Tracker(P).Update;
        pub const Bootstrapper = struct { peer: P, ingress: Ingress };
        const Sets = struct { primary: BitSet(P), secondary: []P };

        gpa: Allocator,
        config: Config,
        peers: SortedMap(P, Record) = .empty,
        peer_sets: SortedMap(u64, Sets) = .empty,
        /// Blocked peers and when each block ends; kept even when a record is deleted.
        blocked: SortedMap(P, SystemTime) = .empty,
        metrics: Metrics(P),

        /// Records the bootstrappers and ourselves (overwriting a bootstrapper entry for us).
        pub fn init(
            gpa: Allocator,
            bootstrappers: []const Bootstrapper,
            myself: Info,
            config: Config,
            scope: *const metrics.Scope,
        ) Allocator.Error!Self {
            assert(config.max_sets > 0);
            var directory: Self = .{ .gpa = gpa, .config = config, .metrics = try .init(scope) };
            errdefer directory.deinit();
            for (bootstrappers) |entry| {
                _ = try directory.peers.put(gpa, entry.peer, .bootstrapper(entry.ingress));
            }
            _ = try directory.peers.put(gpa, myself.public_key, .myself(myself));
            // Excludes ourselves.
            _ = directory.metrics.tracked.metric().try_set(directory.peers.count() - 1) catch {};
            return directory;
        }

        pub fn deinit(directory: *Self) void {
            for (directory.peer_sets.items()) |*entry| directory.free_sets(&entry.value);
            directory.peer_sets.deinit(directory.gpa);
            directory.peers.deinit(directory.gpa);
            directory.blocked.deinit(directory.gpa);
            directory.metrics.deinit();
            directory.* = undefined;
        }

        fn free_sets(directory: *Self, sets: *Sets) void {
            sets.primary.deinit(directory.gpa);
            directory.gpa.free(sets.secondary);
        }

        /// Sets the knowledge bit of `peer` in every tracked set from its record.
        fn refresh_knowledge(directory: *Self, peer: P, record: *const Record) void {
            const known = !record.want(directory.config.dial_fail_limit);
            for (directory.peer_sets.items()) |*entry| _ = entry.value.primary.update(peer, known);
        }

        /// Ends a reservation or connection; a dialer's release counts as a failed dial.
        pub fn release(directory: *Self, metadata: Metadata(P)) void {
            const peer = metadata.public_key();
            const record = directory.peers.get(peer) orelse return;
            record.release();
            _ = directory.metrics.connected.metric().remove(.{ .peer = peer });
            directory.metrics.reserved.metric().dec();
            switch (metadata) {
                .dialer => |dialer| record.dial_failure(dialer.ingress),
                .listener => {},
            }
            directory.refresh_knowledge(peer, record);
            directory.delete_if_needed(peer);
        }

        /// Promotes a reservation of `peer` to a connection. Panics without a record or
        /// reservation.
        pub fn connect(directory: *Self, now: SystemTime, peer: P, dialer: bool) void {
            const record = directory.peers.get(peer).?;
            if (dialer) record.dial_success();
            record.connect();
            Metrics(P).set(&directory.metrics.connected, peer, now.epoch_millis());
            directory.refresh_knowledge(peer, record);
        }

        /// Adopts already-validated peer information for peers we track.
        pub fn update_peers(directory: *Self, updates: []const Info) void {
            for (updates) |update| {
                // Not rate limited: a malicious peer could replay old addresses to keep a new
                // one from propagating.
                const record = directory.peers.get(update.public_key) orelse continue;
                if (!record.update(update)) continue;
                Metrics(P).count(&directory.metrics.updates, update.public_key);
                const peer = update.public_key;
                directory.config.tracer.event(.debug, "updated peer record", .{ .peer = peer });
                directory.refresh_knowledge(update.public_key, record);
            }
        }

        /// Tracks `peers` at `index`, which must exceed every tracked index. Returns the peers
        /// whose reservation or connection must be torn down (sorted, caller-owned), or null
        /// when ignored.
        pub fn track(directory: *Self, index: u64, peers: Tracked) Allocator.Error!?[]P {
            const gpa = directory.gpa;
            const tracer = directory.config.tracer;
            if (directory.peer_sets.get(index) != null) {
                tracer.event(.warn, "peer set already exists", .{ .index = index });
                return null;
            }
            if (directory.latest_set_index()) |last| {
                if (index <= last) {
                    const message = "index must monotonically increase";
                    tracer.event(.warn, message, .{ .index = index, .last = last });
                    return null;
                }
            }
            const primary = try gpa.dupe(P, peers.primary.items);
            var bit_set = BitSet(P).init(gpa, primary) catch |err| {
                gpa.free(primary);
                return err;
            };
            var bit_set_owned = true;
            errdefer if (bit_set_owned) bit_set.deinit(gpa);
            var secondary: std.ArrayList(P) = .empty;
            defer secondary.deinit(gpa);
            for (peers.secondary.items) |peer| {
                if (bit_set.position(peer) == null) try secondary.append(gpa, peer);
            }
            // Create every record before counting, so a failed allocation changes no count.
            for (bit_set.ordered) |peer| try directory.add_unknown(peer);
            for (secondary.items) |peer| try directory.add_unknown(peer);
            try directory.peer_sets.ensure_unused_capacity(gpa, 1);
            const secondary_owned = try secondary.toOwnedSlice(gpa);
            for (bit_set.ordered, 0..) |peer, slot| {
                const record = directory.peers.get(peer).?;
                record.increment_primary();
                const known = !record.want(directory.config.dial_fail_limit);
                assert(bit_set.update_at(slot, known));
            }
            for (secondary_owned) |peer| directory.peers.get(peer).?.increment_secondary();
            const sets: Sets = .{ .primary = bit_set, .secondary = secondary_owned };
            // Proof: capacity for one insert was reserved above.
            assert((directory.peer_sets.put(gpa, index, sets) catch unreachable) == null);
            bit_set_owned = false;

            var kill: std.ArrayList(P) = .empty;
            defer kill.deinit(gpa);
            while (directory.peer_sets.count() > directory.config.max_sets) {
                try directory.evict_oldest(&kill);
            }
            std.sort.pdq(P, kill.items, {}, less_than);
            var unique: usize = 0;
            for (kill.items) |peer| {
                if (unique > 0 and P.order(kill.items[unique - 1], peer) == .eq) continue;
                kill.items[unique] = peer;
                unique += 1;
            }
            return try gpa.dupe(P, kill.items[0..unique]);
        }

        /// Creates an unknown record for `peer` unless it has one.
        fn add_unknown(directory: *Self, peer: P) Allocator.Error!void {
            if (directory.peers.get(peer) != null) return;
            _ = try directory.peers.put(directory.gpa, peer, .unknown());
            directory.metrics.tracked.metric().inc();
        }

        fn evict_oldest(directory: *Self, kill: *std.ArrayList(P)) Allocator.Error!void {
            var oldest = directory.peer_sets.items()[0];
            _ = directory.peer_sets.remove(oldest.key);
            const message = "removed oldest tracked peer sets";
            directory.config.tracer.event(.debug, message, .{ .index = oldest.key });
            defer directory.free_sets(&oldest.value);
            for (oldest.value.primary.ordered) |peer| {
                directory.peers.get(peer).?.decrement_primary();
                try directory.queue_if_ineligible(peer, kill);
            }
            for (oldest.value.secondary) |peer| {
                directory.peers.get(peer).?.decrement_secondary();
                try directory.queue_if_ineligible(peer, kill);
            }
        }

        fn queue_if_ineligible(directory: *Self, peer: P, kill: *std.ArrayList(P)) !void {
            const record = directory.peers.get(peer) orelse return;
            if (record.needs_teardown()) try kill.append(directory.gpa, peer);
            directory.delete_if_needed(peer);
        }

        fn delete_if_needed(directory: *Self, peer: P) void {
            const record = directory.peers.get(peer) orelse return;
            if (!record.deletable()) return;
            // The blocked series stays: the block outlives the record until it expires.
            _ = directory.peers.remove(peer);
            directory.metrics.tracked.metric().dec();
        }

        /// A copy of the sets at `index`.
        pub fn peer_set(directory: *const Self, gpa: Allocator, index: u64) !?Owned {
            const sets = directory.peer_sets.get(index) orelse return null;
            const primary = try gpa.dupe(P, sets.primary.ordered);
            errdefer gpa.free(primary);
            return .{ .primary = primary, .secondary = try gpa.dupe(P, sets.secondary) };
        }

        pub fn latest_set_index(directory: *const Self) ?u64 {
            const sets = directory.peer_sets.items();
            if (sets.len == 0) return null;
            return sets[sets.len - 1].key;
        }

        /// The newest set and every tracked peer, or null when nothing is tracked.
        pub fn latest_update(directory: *const Self, gpa: Allocator) !?Update {
            const index = directory.latest_set_index() orelse return null;
            const latest = (try directory.peer_set(gpa, index)).?;
            errdefer latest.free(gpa);
            const every = try directory.all(gpa);
            return .{ .gpa = gpa, .index = index, .latest = latest, .all = every };
        }

        /// Every peer in a tracked set: primary when any set lists it as primary.
        pub fn all(directory: *const Self, gpa: Allocator) Allocator.Error!Owned {
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

        /// Reserves `peer` for an outbound dial. Null when it is no longer dialable (the
        /// dialer works from an older snapshot) or cannot be reserved.
        pub fn dial(directory: *Self, rng: anytype, now: SystemTime, peer: P) ?Metadata(P) {
            const record = directory.peers.get(peer) orelse return null;
            const config = directory.config;
            const status = record.dialable(now, config.allow_private_ips, config.allow_dns);
            // The reservation enforces the cooldown, so only an unavailable peer stops here.
            if (status == .unavailable) return null;
            const ingress = record.ingress() orelse return null;
            const metadata: Metadata(P) = .{ .dialer = .{ .peer = peer, .ingress = ingress } };
            return directory.reserve(rng, now, metadata);
        }

        /// Reserves `peer` for an inbound connection.
        pub fn listen(directory: *Self, rng: anytype, now: SystemTime, peer: P) ?Metadata(P) {
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
                .reserved => reserved: {
                    directory.metrics.reserved.metric().inc();
                    break :reserved metadata;
                },
                .rate_limited => limited: {
                    Metrics(P).count(&directory.metrics.limits, peer);
                    break :limited null;
                },
                .unavailable => null,
            };
        }

        /// The knowledge bits of a random tracked set (caller-owned), or null when none.
        pub fn random_bit_vec(directory: *const Self, gpa: Allocator, rng: anytype) !?types.BitVec {
            const sets = directory.peer_sets.items();
            if (sets.len == 0) return null;
            // `IteratorRandom::choose` on an exact-size iterator: one index draw.
            const index = utils.rng.range_less_than(rng, usize, 0, sets.len);
            const entry = sets[index];
            return .{ .index = entry.key, .bits = try entry.value.primary.copy_knowledge(gpa) };
        }

        fn is_blocked(directory: *const Self, now: SystemTime, peer: P) bool {
            const until = directory.blocked.get(peer) orelse return false;
            return until.order(now) == .gt;
        }

        /// Blocks `peer` for `block_duration`, even without a record (the block applies when it
        /// joins a set). Returns false if already blocked or ourselves.
        pub fn block(directory: *Self, now: SystemTime, peer: P) Allocator.Error!bool {
            if (directory.is_blocked(now, peer)) return false;
            if (directory.peers.get(peer)) |record| {
                if (!record.is_blockable()) return false;
            }
            const until = now.saturating_add(directory.config.block_duration);
            _ = try directory.blocked.put(directory.gpa, peer, until);
            Metrics(P).set(&directory.metrics.blocked, peer, until.epoch_millis());
            return true;
        }

        /// Our info, or a connected peer's.
        pub fn info(directory: *const Self, peer: P) ?Info {
            const record = directory.peers.get(peer) orelse return null;
            return record.sharable();
        }

        /// The info we can share for the peers `bit_vec` lacks (caller-owned). Empty for an
        /// unknown index; null when the length does not match the set (malformed).
        pub fn infos(
            directory: *const Self,
            gpa: Allocator,
            now: SystemTime,
            bit_vec: *const types.BitVec,
        ) Allocator.Error!?[]Info {
            const tracer = directory.config.tracer;
            const index = bit_vec.index;
            const sets = directory.peer_sets.get(index) orelse {
                // Unknown indices are not errors; they are ignored.
                tracer.event(.debug, "requested peer set not found", .{ .index = index });
                return try gpa.alloc(Info, 0);
            };
            const primary = sets.primary.ordered;
            if (bit_vec.bits.len() != primary.len) {
                tracer.event(.debug, "bit vector length mismatch", .{
                    .index = index,
                    .expected = primary.len,
                    .actual = bit_vec.bits.len(),
                });
                return null;
            }
            const now_millis = now.epoch_millis();
            var result: std.ArrayList(Info) = .empty;
            errdefer result.deinit(gpa);
            for (primary, 0..) |peer, slot| {
                if (bit_vec.bits.get(slot)) continue;
                const shared = directory.info(peer) orelse continue;
                // Info signed slightly in the future (within the synchrony bound) could get us
                // blocked by peers with skewed clocks; share only info no newer than now.
                if (shared.timestamp > now_millis) continue;
                try result.append(gpa, shared);
            }
            return try result.toOwnedSlice(gpa);
        }

        /// In a peer set (or persistent), not blocked, and not us.
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

        /// Whether we accept an inbound connection from `peer`.
        pub fn acceptable(directory: *const Self, now: SystemTime, peer: P) bool {
            if (directory.is_blocked(now, peer)) return false;
            const record = directory.peers.get(peer) orelse return false;
            return record.acceptable();
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
                directory.config.tracer.event(.debug, "unblocked peer", .{ .peer = entry.key });
                _ = directory.metrics.blocked.metric().remove(.{ .peer = entry.key });
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

test {
    _ = @import("directory_test.zig");
}
