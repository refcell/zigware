//! The discovery tracker (commonware `discovery/actors/tracker/{actor,ingress}.rs`): the
//! directory behind a lock, each connected peer's outbox (for gossip and kills), peer-set
//! subscribers, and the blocked set.
//!
//! commonware runs this as an actor fed by a mailbox; here every mailbox message is a method
//! that runs in the caller's task under the lock, in the same order of effects. `run_unblock`
//! is the actor's unblock timer.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
const traces = @import("runtime").telemetry.traces;
const p2p = @import("../../root.zig");
const sizing = @import("../../sizing.zig");
const SortedMap = @import("../../simulated/sorted_map.zig").SortedMap;
const Unbounded = @import("../../simulated/channel.zig").Unbounded;
const Watch = @import("../../utils/watch.zig").Watch;
const IoRng = @import("../../utils/io_rng.zig").IoRng;
const shuffle = @import("../../utils/shuffle.zig");
const outbox_mod = @import("../outbox.zig");
const types = @import("types.zig");
const directory_mod = @import("directory.zig");

const Feedback = p2p.Feedback;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Outbox = outbox_mod.Outbox;
const Frame = outbox_mod.Frame;

pub fn Tracker(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Directory = directory_mod.Directory(P);
        pub const Info = types.Info(P);
        pub const Metadata = directory_mod.Metadata(P);
        pub const Dialable = directory_mod.Dialable(P);
        pub const Bootstrapper = Directory.Bootstrapper;
        pub const Owned = Directory.Owned;
        pub const Update = Directory.Update;
        pub const PeerSetSubscription = Unbounded(Update).Receiver;
        pub const BlockedSubscription = Watch(P).Subscription;

        pub const Config = struct {
            /// Our own signed info, sent as the greeting.
            myself: Info,
            bootstrappers: []const Bootstrapper,
            allow_private_ips: bool,
            allow_dns: bool,
            max_peers_per_set: usize,
            tracked_peer_sets: usize,
            peer_connection_cooldown: Duration,
            peer_gossip_max_count: usize,
            dial_fail_limit: usize,
            block_duration: Duration,
            /// The directory's tracer.
            tracer: traces.Tracer = .none,
        };

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        /// Signaled on a block and on close, for `run_unblock`.
        condition: Io.Condition = .init,
        closed: bool = false,
        me: P,
        max_peers_per_set: usize,
        peer_gossip_max_count: usize,
        directory: Directory,
        /// The outbox of each connected peer.
        mailboxes: SortedMap(P, *Outbox) = .empty,
        subscribers: std.ArrayList(Unbounded(Update).Sender) = .empty,
        blocked: Watch(P),

        /// Registers the directory's metrics under `scope.child("directory")`.
        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: *const metrics.Scope,
            config: Config,
        ) Allocator.Error!Self {
            assert(config.max_peers_per_set > 0);
            const directory_scope = scope.child("directory");
            const directory = try Directory.init(gpa, config.bootstrappers, config.myself, .{
                .allow_private_ips = config.allow_private_ips,
                .allow_dns = config.allow_dns,
                .max_sets = config.tracked_peer_sets,
                .dial_fail_limit = config.dial_fail_limit,
                .peer_connection_cooldown = config.peer_connection_cooldown,
                .block_duration = config.block_duration,
                .tracer = config.tracer,
            }, &directory_scope);
            return .{
                .gpa = gpa,
                .io = io,
                .me = config.myself.public_key,
                .max_peers_per_set = config.max_peers_per_set,
                .peer_gossip_max_count = config.peer_gossip_max_count,
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

        /// Marks a reserved `peer` connected through `outbox` and returns our greeting, or
        /// null when the peer is no longer eligible (commonware `Message::Connect`).
        pub fn connect(tracker: *Self, peer: P, outbox: *Outbox, dialer: bool) ?Info {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed or !tracker.directory.eligible(tracker.now(), peer)) return null;
            tracker.directory.connect(tracker.now(), peer, dialer);
            _ = tracker.mailboxes.put(tracker.gpa, peer, outbox) catch return null;
            return tracker.directory.info(tracker.me).?;
        }

        /// Sends `peer` a bit vector of a random tracked set, which also serves as a ping
        /// (commonware `Message::Construct`).
        pub fn construct(tracker: *Self, peer: P) void {
            tracker.lock();
            defer tracker.unlock();
            if (!tracker.directory.eligible(tracker.now(), peer)) return tracker.kill_peer(peer);
            const outbox = (tracker.mailboxes.get(peer) orelse return).*;
            const random = tracker.directory.random_bit_vec(tracker.gpa, tracker.rng());
            var known = (random catch return) orelse return;
            defer known.deinit(tracker.gpa);
            tracker.send(outbox, .{ .bit_vec = known });
        }

        /// Answers `peer`'s bit vector with the info it lacks, at most
        /// `peer_gossip_max_count` entries chosen at random (commonware `Message::BitVec`).
        pub fn bit_vec(tracker: *Self, peer: P, received: *const types.BitVec) void {
            tracker.lock();
            defer tracker.unlock();
            const at = tracker.now();
            if (!tracker.directory.eligible(at, peer)) return tracker.kill_peer(peer);
            const outbox = (tracker.mailboxes.get(peer) orelse return).*;
            const infos = (tracker.directory.infos(tracker.gpa, at, received) catch return) orelse
                return tracker.kill_peer(peer);
            defer tracker.gpa.free(infos);
            var selected: []Info = infos;
            if (infos.len > tracker.peer_gossip_max_count) {
                const max = tracker.peer_gossip_max_count;
                // commonware's `partial_shuffle(max)` then `truncate(max)` keeps the head.
                _ = shuffle.partial_shuffle(Info, infos, tracker.rng(), max);
                selected = infos[0..max];
            }
            if (selected.len > 0) tracker.send(outbox, .{ .peers = selected });
        }

        /// Encodes `payload` and queues it on `outbox` ahead of data; dropped when full.
        fn send(tracker: *Self, outbox: *Outbox, payload: types.Payload(P)) void {
            const bytes = codec.encode(types.Payload(P), tracker.gpa, payload) catch return;
            const frame = Frame.adopt(tracker.gpa, bytes) catch return;
            defer frame.release();
            _ = outbox.send_control(frame);
        }

        /// Adopts already-validated peer info (commonware `Message::Peers`).
        pub fn peers(tracker: *Self, infos: []const Info) void {
            tracker.lock();
            defer tracker.unlock();
            tracker.directory.update_peers(infos);
        }

        /// Peers to dial now and when to ask again (caller-owned).
        pub fn dialable(tracker: *Self, gpa: Allocator) Allocator.Error!Dialable {
            tracker.lock();
            defer tracker.unlock();
            return tracker.directory.dialable(gpa, tracker.now());
        }

        /// Reserves `peer` for the dialer.
        pub fn dial(tracker: *Self, peer: P) ?Metadata {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return null;
            return tracker.directory.dial(tracker.rng(), tracker.now(), peer);
        }

        /// Whether the listener should complete a handshake with `peer`.
        pub fn acceptable(tracker: *Self, peer: P) bool {
            tracker.lock();
            defer tracker.unlock();
            return !tracker.closed and tracker.directory.acceptable(tracker.now(), peer);
        }

        /// Reserves `peer` for the listener.
        pub fn listen(tracker: *Self, peer: P) ?Metadata {
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return null;
            return tracker.directory.listen(tracker.rng(), tracker.now(), peer);
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

        /// Tracks `peers` at `index` (commonware `Manager::track`). Panics when the set,
        /// counting us, exceeds `max_peers_per_set`.
        pub fn track(tracker: *Self, index: u64, tracked: p2p.TrackedPeers(P)) Feedback {
            const count = sizing.peer_set_size(
                P,
                tracked.primary.items,
                tracked.secondary.items,
                tracker.me,
            );
            if (count > tracker.max_peers_per_set) {
                std.debug.panic("peer set too large: {d} > {d}", .{
                    count,
                    tracker.max_peers_per_set,
                });
            }
            tracker.lock();
            defer tracker.unlock();
            if (tracker.closed) return .closed;
            const kills = (tracker.directory.track(index, tracked) catch return .closed) orelse
                return .ok;
            defer tracker.gpa.free(kills);
            for (kills) |peer| tracker.kill_peer(peer);
            tracker.notify_subscribers();
            return .ok;
        }

        /// Sends every subscriber its own copy of the latest update, dropping closed ones.
        fn notify_subscribers(tracker: *Self) void {
            var index: usize = 0;
            while (index < tracker.subscribers.items.len) {
                const subscriber = &tracker.subscribers.items[index];
                const update = (tracker.directory.latest_update(tracker.gpa) catch return).?;
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
                if (tracker.directory.unblock_expired(at)) tracker.publish_blocked(at);
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

        /// The handle applications use to track, inspect, and block peers (commonware
        /// `tracker::Oracle`): `Provider`, `Manager`, and `Blocker`.
        pub const Oracle = struct {
            pub const PublicKey = P;

            tracker: *Self,

            pub fn track(oracle: Oracle, index: u64, tracked: p2p.TrackedPeers(P)) Feedback {
                return oracle.tracker.track(index, tracked);
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

            /// Never fails here; the error union matches every `Blocker` (simulated's
            /// allocates), so callers `try` it alike.
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
