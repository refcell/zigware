//! The lookup tracker (commonware `lookup/actors/tracker/{actor,ingress}.rs`): the directory
//! behind a lock, each connected peer's outbox (to kill it), peer-set subscribers, the blocked
//! set, and the IPs the listener accepts.
//!
//! commonware runs this as an actor fed by a mailbox; here every mailbox message is a method
//! that runs in the caller's task under the lock, in the same order of effects. The listener's
//! `ring` of registered IPs becomes `registered_ips`, refreshed exactly where the actor sends
//! the listener a new set. `run_unblock` is the actor's unblock timer.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
const p2p = @import("../../root.zig");
const types = @import("../../types.zig");
const SortedMap = @import("../../simulated/sorted_map.zig").SortedMap;
const Unbounded = @import("../../simulated/channel.zig").Unbounded;
const Watch = @import("../../utils/watch.zig").Watch;
const IoRng = @import("../../utils/io_rng.zig").IoRng;
const Outbox = @import("../outbox.zig").Outbox;
const directory_mod = @import("directory.zig");

const Feedback = p2p.Feedback;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;

pub fn Tracker(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Directory = directory_mod.Directory(P);
        pub const Metadata = directory_mod.Metadata(P);
        pub const Dialable = directory_mod.Dialable(P);
        pub const Owned = directory_mod.Owned(P);
        pub const Update = Directory.Update;
        pub const Tracked = Directory.Tracked;
        pub const PeerMap = Tracked.PeerMap;
        pub const PeerSetSubscription = Unbounded(Update).Receiver;
        pub const BlockedSubscription = Watch(P).Subscription;
        /// A dial reservation and the address to dial.
        pub const Dial = struct { metadata: Metadata, ingress: types.Ingress };

        pub const Config = struct {
            public_key: P,
            max_peers_per_set: usize,
            tracked_peer_sets: usize,
            peer_connection_cooldown: Duration,
            allow_private_ips: bool,
            allow_dns: bool,
            bypass_ip_check: bool,
            block_duration: Duration,
        };

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        /// Signaled on a block and on close, for `run_unblock`.
        condition: Io.Condition = .init,
        closed: bool = false,
        me: P,
        max_peers_per_set: usize,
        directory: Directory,
        /// The outbox of each connected peer.
        mailboxes: SortedMap(P, *Outbox) = .empty,
        subscribers: std.ArrayList(Unbounded(Update).Sender) = .empty,
        blocked: Watch(P),
        /// Egress IPs the listener accepts (sorted, unique), as last sent to the listener.
        registered_ips: []codec.IpAddr = &.{},

        /// Metrics register under `scope` (commonware's tracker context): the directory's
        /// under its `directory` child.
        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: *const metrics.Scope,
            config: Config,
        ) Allocator.Error!Self {
            assert(config.max_peers_per_set > 0);
            assert(config.tracked_peer_sets > 0);
            const directory_scope = scope.child("directory");
            const directory = try Directory.init(gpa, config.public_key, .{
                .allow_private_ips = config.allow_private_ips,
                .allow_dns = config.allow_dns,
                .bypass_ip_check = config.bypass_ip_check,
                .max_sets = config.tracked_peer_sets,
                .peer_connection_cooldown = config.peer_connection_cooldown,
                .block_duration = config.block_duration,
            }, &directory_scope);
            return .{
                .gpa = gpa,
                .io = io,
                .me = config.public_key,
                .max_peers_per_set = config.max_peers_per_set,
                .directory = directory,
                .blocked = .init(gpa, io),
            };
        }

        /// Call after every task using the tracker has stopped.
        pub fn deinit(tracker: *Self) void {
            for (tracker.subscribers.items) |*subscriber| subscriber.deinit();
            tracker.subscribers.deinit(tracker.gpa);
            tracker.mailboxes.deinit(tracker.gpa);
            tracker.blocked.deinit();
            tracker.directory.deinit();
            tracker.gpa.free(tracker.registered_ips);
            tracker.* = undefined;
        }

        /// Stops `run_unblock`, kills every connection, and ends the subscriptions.
        pub fn close(tracker: *Self) void {
            tracker.lock();
            defer tracker.unlock();
            tracker.closed = true;
            for (tracker.mailboxes.items()) |entry| entry.value.kill();
            tracker.mailboxes.deinit(tracker.gpa);
            tracker.mailboxes = .empty;
            for (tracker.subscribers.items) |*subscriber| subscriber.deinit();
            tracker.subscribers.clearRetainingCapacity();
            tracker.blocked.close();
            tracker.condition.broadcast(tracker.io);
        }

        fn lock(tracker: *Self) void {
            tracker.mutex.lockUncancelable(tracker.io);
        }

        fn unlock(tracker: *Self) void {
            tracker.mutex.unlock(tracker.io);
        }

        fn now(tracker: *const Self) SystemTime {
            return SystemTime.from_timestamp(Io.Clock.real.now(tracker.io));
        }

        fn rng(tracker: *const Self) IoRng {
            return .{ .io = tracker.io };
        }

        /// Recomputes the IPs the listener accepts (commonware `listener.set(listenable())`).
        /// On allocation failure the previous set stays.
        fn refresh_listenable(tracker: *Self) void {
            const ips = tracker.directory.listenable(tracker.gpa, tracker.now()) catch return;
            tracker.gpa.free(tracker.registered_ips);
            tracker.registered_ips = ips;
        }

        /// Whether the listener accepts a connection from `ip` (its registered-IP check).
        pub fn registered(tracker: *Self, ip: codec.IpAddr) bool {
            tracker.lock();
            defer tracker.unlock();
            const ips = tracker.registered_ips;
            var low: usize = 0;
            var high: usize = ips.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (ips[middle].order(ip)) {
                    .lt => low = middle + 1,
                    .gt => high = middle,
                    .eq => return true,
                }
            }
            assert(low <= ips.len);
            return false;
        }

        /// Marks a reserved `peer` connected through `outbox`. False when the peer is no
        /// longer eligible or its address changed; the caller then ends the connection
        /// (commonware `Message::Connect`, which kills the peer).
        pub fn connect(tracker: *Self, peer: P, outbox: *Outbox) bool {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed or !tracker.directory.eligible(tracker.now(), peer)) return false;
            if (!tracker.directory.connect(tracker.now(), peer)) return false;
            _ = tracker.mailboxes.put(tracker.gpa, peer, outbox) catch return false;
            return true;
        }

        /// Peers to dial now and when to ask again (caller-owned).
        pub fn dialable(tracker: *Self, gpa: Allocator) Allocator.Error!Dialable {
            tracker.lock();
            defer tracker.unlock();
            return tracker.directory.dialable(gpa, tracker.now());
        }

        /// Reserves `peer` for the dialer and returns the address to dial.
        pub fn dial(tracker: *Self, peer: P) ?Dial {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return null;
            const reserved = tracker.directory.dial(tracker.rng(), tracker.now(), peer) orelse
                return null;
            return .{ .metadata = reserved.metadata, .ingress = reserved.ingress };
        }

        /// Whether the listener should complete a handshake with `peer` from `source_ip`.
        pub fn acceptable(tracker: *Self, peer: P, source_ip: codec.IpAddr) bool {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return false;
            return tracker.directory.acceptable(tracker.now(), peer, source_ip);
        }

        /// Reserves `peer` for the listener.
        pub fn listen(tracker: *Self, peer: P, source_ip: codec.IpAddr) ?Metadata {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return null;
            return tracker.directory.listen(tracker.rng(), tracker.now(), peer, source_ip);
        }

        /// Ends a reservation or connection (commonware `Message::Release`, sent when a
        /// `Reservation` drops).
        pub fn release(tracker: *Self, metadata: Metadata) void {
            tracker.lock();
            defer tracker.unlock();
            _ = tracker.mailboxes.remove(metadata.public_key());
            tracker.directory.release(metadata);
        }

        fn kill_peer(tracker: *Self, peer: P) void {
            const outbox = tracker.mailboxes.remove(peer) orelse return;
            outbox.kill();
        }

        /// Tracks `peers` at `index` (commonware `AddressableManager::track`). Panics when
        /// the set, counting us, exceeds `max_peers_per_set`.
        pub fn track(tracker: *Self, index: u64, peers: Tracked) Feedback {
            const count = set_size(peers.primary.entries, peers.secondary.entries, tracker.me);
            if (count > tracker.max_peers_per_set) {
                std.debug.panic("peer set too large: {d} > {d}", .{
                    count,
                    tracker.max_peers_per_set,
                });
            }
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return .closed;
            const kills = (tracker.directory.track(index, peers) catch return .closed) orelse
                return .ok;
            defer tracker.gpa.free(kills);
            for (kills) |peer| tracker.kill_peer(peer);
            tracker.refresh_listenable();
            tracker.notify_subscribers();
            return .ok;
        }

        /// Updates the addresses of tracked peers, killing each peer whose address changed
        /// (commonware `AddressableManager::overwrite`).
        pub fn overwrite(tracker: *Self, peers: PeerMap) Feedback {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return .closed;
            var any_changed = false;
            for (peers.entries) |entry| {
                if (!tracker.directory.overwrite(entry.key, entry.value)) continue;
                any_changed = true;
                tracker.kill_peer(entry.key);
            }
            if (any_changed) tracker.refresh_listenable();
            return .ok;
        }

        /// Sends every subscriber its own copy of the latest update, dropping closed ones.
        fn notify_subscribers(tracker: *Self) void {
            var index: usize = 0;
            while (index < tracker.subscribers.items.len) {
                const subscriber = &tracker.subscribers.items[index];
                const update = (tracker.directory.latest_update(tracker.gpa) catch return).?;
                // A failed send releases the update.
                if (subscriber.send(update) catch false) {
                    index += 1;
                    continue;
                }
                subscriber.deinit();
                _ = tracker.subscribers.swapRemove(index);
            }
        }

        /// A copy of the sets tracked at `index`.
        pub fn peer_set(tracker: *Self, gpa: Allocator, index: u64) !?Owned {
            tracker.lock();
            defer tracker.unlock();
            return tracker.directory.peer_set(gpa, index);
        }

        /// Peer-set updates, starting with the latest one, if any.
        pub fn subscribe(tracker: *Self) !PeerSetSubscription {
            tracker.lock();
            defer tracker.unlock();
            var pair = try Unbounded(Update).init(tracker.gpa, tracker.io);
            errdefer {
                pair.sender.deinit();
                pair.receiver.deinit();
            }
            if (tracker.closed) {
                pair.sender.deinit();
                return pair.receiver;
            }
            if (try tracker.directory.latest_update(tracker.gpa)) |update| {
                assert(try pair.sender.send(update));
            }
            try tracker.subscribers.append(tracker.gpa, pair.sender);
            return pair.receiver;
        }

        /// Blocks `peer` and kills its connection (commonware `Blocker::block`).
        pub fn block(tracker: *Self, peer: P) Feedback {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return .closed;
            const at = tracker.now();
            if (tracker.directory.block(at, peer) catch return .closed) {
                tracker.publish_blocked(at);
                tracker.refresh_listenable();
                tracker.condition.broadcast(tracker.io);
            }
            tracker.kill_peer(peer);
            return .ok;
        }

        /// The blocked set, starting with the current one.
        pub fn blocked_subscription(tracker: *Self) BlockedSubscription {
            return tracker.blocked.subscribe(true);
        }

        fn publish_blocked(tracker: *Self, at: SystemTime) void {
            const blocked = tracker.directory.blocked_peers(tracker.gpa, at) catch return;
            defer tracker.gpa.free(blocked);
            _ = tracker.blocked.publish(blocked) catch {};
        }

        /// Unblocks peers as their blocks expire, until `close` or cancelation.
        pub fn run_unblock(tracker: *Self) Io.Cancelable!void {
            try tracker.mutex.lock(tracker.io);
            defer tracker.unlock();
            // Publish the initial (empty) set so subscribers start from it.
            tracker.publish_blocked(tracker.now());
            while (!tracker.closed) {
                const at = tracker.now();
                if (tracker.directory.unblock_expired(at)) {
                    tracker.refresh_listenable();
                    tracker.publish_blocked(at);
                }
                const next = tracker.directory.next_unblock() orelse {
                    try tracker.condition.wait(tracker.io, &tracker.mutex);
                    continue;
                };
                const raw: Io.Timestamp = .fromNanoseconds(@intCast(next.nanos_since_epoch));
                const timeout: Io.Timeout = .{ .deadline = .{ .raw = raw, .clock = .real } };
                tracker.condition.waitTimeout(tracker.io, &tracker.mutex, timeout) catch |err| {
                    switch (err) {
                        error.Timeout => {},
                        error.Canceled => return error.Canceled,
                    }
                };
            }
        }

        /// Counts identities across two sorted peer maps, plus `me` when absent from both
        /// (`sizing.peer_set_size` over map keys).
        pub fn set_size(
            primary: []const PeerMap.Entry,
            secondary: []const PeerMap.Entry,
            me: P,
        ) usize {
            var p: usize = 0;
            var s: usize = 0;
            var count: usize = 0;
            var contains_me = false;
            while (p < primary.len or s < secondary.len) : (count += 1) {
                const peer = if (p == primary.len)
                    secondary[s].key
                else if (s == secondary.len)
                    primary[p].key
                else switch (P.order(primary[p].key, secondary[s].key)) {
                    .lt, .eq => primary[p].key,
                    .gt => secondary[s].key,
                };
                if (p < primary.len and P.order(primary[p].key, peer) == .eq) p += 1;
                if (s < secondary.len and P.order(secondary[s].key, peer) == .eq) s += 1;
                if (P.order(me, peer) == .eq) contains_me = true;
            }
            assert(count <= primary.len + secondary.len);
            return count + @intFromBool(!contains_me);
        }

        /// The handle applications use to track, inspect, and block peers.
        pub fn as_oracle(tracker: *Self) Oracle {
            return .{ .tracker = tracker };
        }

        /// The handle applications use to track, inspect, and block peers (commonware
        /// `tracker::Oracle`): `Provider`, `AddressableManager`, and `Blocker`.
        pub const Oracle = struct {
            pub const PublicKey = P;

            tracker: *Self,

            pub fn track(oracle: Oracle, index: u64, peers: Tracked) Feedback {
                return oracle.tracker.track(index, peers);
            }

            pub fn overwrite(oracle: Oracle, peers: PeerMap) Feedback {
                return oracle.tracker.overwrite(peers);
            }

            pub fn peer_set(oracle: Oracle, gpa: Allocator, index: u64) !?Owned {
                return oracle.tracker.peer_set(gpa, index);
            }

            pub fn subscribe(oracle: Oracle) !PeerSetSubscription {
                return oracle.tracker.subscribe();
            }

            pub fn block(oracle: Oracle, peer: P) Feedback {
                return oracle.tracker.block(peer);
            }

            /// Fallible like simulated's `Control.blocked`, as the `Blocker` contract
            /// requires; subscribing to the watch itself cannot fail.
            pub fn blocked(oracle: Oracle) Allocator.Error!BlockedSubscription {
                return oracle.tracker.blocked_subscription();
            }
        };

        comptime {
            p2p.assert_manager(Oracle);
            p2p.assert_blocker(Oracle);
        }
    };
}

test {
    _ = @import("tracker_test.zig");
}
