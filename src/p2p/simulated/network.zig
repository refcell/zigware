//! A simulated p2p network (commonware `p2p/src/simulated/network.rs` and `ingress.rs`).
//!
//! Peers register channels and get a rate-limited `Sender` and a `Receiver` per channel.
//! Messages travel over directed links with sampled latency (normal around `latency` with
//! standard deviation `jitter`, in whole milliseconds) and a success rate; optional per-peer
//! bandwidth limits share capacity max-min fairly (`transmitter`). Two peers exchange messages
//! only while each tracks the other in its peer sets (`tracker`), as on an authenticated
//! network, and blocked pairs are cut off when `disconnect_on_block`.
//!
//! Differences from commonware, all deterministic per seed:
//! - Operations run in the caller's task under one `Io.Mutex` instead of on an actor fed by
//!   an ingress queue; a single `run` task drives the transmitter and timed deliveries. Send
//!   and topology changes therefore apply in call order, as in commonware, but `priority`
//!   cannot reorder sends that commonware would have batched together.
//! - A link delivers into the recipient's channel at `deliver_at` directly, instead of over a
//!   socket the runtime would carry; arrival times and per-link order are the same.
//! - Latency is drawn with Box-Muller from the runtime RNG, not `rand_distr`'s ziggurat, so
//!   individual samples differ from commonware's for the same seed.
//! - `deinit` the network after every sender, control, oracle, and manager is gone.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils_pkg = @import("utils");
const p2p = @import("../root.zig");
const sizing = @import("../sizing.zig");
const limited = @import("../utils/limited.zig");
const Watch = @import("../utils/watch.zig").Watch;
const Quota = @import("../rate_limit.zig").Quota;
const SortedMap = @import("sorted_map.zig").SortedMap;
const Unbounded = @import("channel.zig").Unbounded;
const tracker_mod = @import("tracker.zig");
const transmitter = @import("transmitter.zig");

const Duration = utils_pkg.Duration;
const SystemTime = utils_pkg.SystemTime;
const Channel = p2p.Channel;
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;

pub const Error = error{ NetworkClosed, LinkingSelf, LinkExists, LinkMissing };

/// Overhead from prepending a channel identifier to an application payload.
pub const max_payload_overhead: u32 = @sizeOf(Channel);
/// Largest supported application payload.
pub const max_size_limit: u32 = std.math.maxInt(u32) - max_payload_overhead;

pub const Config = struct {
    /// Largest application payload a sender accepts (at most `max_size_limit`).
    max_size: u32,
    /// Most distinct identities at one peer-set index; a peer tracking a set through its own
    /// manager counts itself.
    max_peers_per_set: usize,
    /// Drop messages between peers when either blocks the other.
    disconnect_on_block: bool,
    /// Peer sets each peer keeps; tracking a newer one evicts the oldest.
    tracked_peer_sets: usize,
};

/// Link behavior from a sender to a receiver.
pub const Link = struct {
    /// Mean latency for the delivery of a message.
    latency: Duration,
    /// Standard deviation of the latency.
    jitter: Duration,
    /// Probability that a message is delivered, in `[0, 1]`.
    success_rate: f64,
};

/// Draws from the runtime RNG through `std.Io`.
const IoRng = struct {
    io: Io,

    pub fn next_u64(rng: IoRng) u64 {
        var bytes: [8]u8 = undefined;
        rng.io.random(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }

    pub fn next_u32(rng: IoRng) u32 {
        return @truncate(rng.next_u64());
    }

    pub fn fill_bytes(rng: IoRng, dest: []u8) void {
        rng.io.random(dest);
    }
};

/// A normal sample with `mean` and `deviation` (Box-Muller), in the same unit.
fn sample_normal(rng: IoRng, mean: f64, deviation: f64) f64 {
    if (deviation == 0) return mean;
    const u1_value = 1.0 - utils_pkg.rng.float64(rng); // (0, 1]
    const u2_value = utils_pkg.rng.float64(rng);
    const radius = @sqrt(-2.0 * @log(u1_value));
    return mean + deviation * radius * @cos(2.0 * std.math.pi * u2_value);
}

/// Milliseconds as a `Duration`, saturating like Rust's `f64 as u64` (negative is zero).
fn latency_from_ms(ms: f64) Duration {
    if (!(ms > 0)) return Duration.zero;
    const max: f64 = @floatFromInt(std.math.maxInt(u64));
    return Duration.from_millis(if (ms >= max) std.math.maxInt(u64) else @intFromFloat(ms));
}

/// A payload shared by every recipient of one send.
const Payload = struct {
    refs: u32,
    len: usize,
    bytes: []u8,
};

pub fn Network(comptime P: type) type {
    return struct {
        const Self = @This();
        const Tracker = tracker_mod.Tracker(P);
        const Transmitter = transmitter.State(P, *Payload);
        const Pair = Transmitter.Pair;
        const Message = p2p.Message(P);
        const Mailbox = Unbounded(Message);

        pub const PublicKey = P;
        pub const Sender = limited.LimitedSender(UnlimitedSender, Connected);
        pub const PeerSetSubscription = Tracker.Subscription;
        pub const PeerSetUpdate = Tracker.Update;
        pub const OwnedPeers = Tracker.Owned;

        const Registration = struct { mailbox: Mailbox.Sender, generation: u64 };

        const Peer = struct {
            tracker: Tracker,
            channels: SortedMap(Channel, Registration) = .empty,
            /// Peers this one may expand `Recipients.all` to.
            connected: Watch(P),
            /// Peers this one blocks.
            blocked: Watch(P),
        };

        const LinkState = struct { latency_ms: f64, jitter_ms: f64, success_rate: f64 };

        const Delivery = struct {
            deliver_at: SystemTime,
            sequence: u64,
            origin: P,
            recipient: P,
            channel: Channel,
            payload: *Payload,

            fn order(_: void, a: Delivery, b: Delivery) std.math.Order {
                const by_time = a.deliver_at.order(b.deliver_at);
                return if (by_time != .eq) by_time else std.math.order(a.sequence, b.sequence);
            }
        };

        gpa: Allocator,
        io: Io,
        config: Config,
        max_retained_peers: usize,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        closed: bool = false,
        next_generation: u64 = 0,
        peers: SortedMap(P, *Peer) = .empty,
        links: SortedMap(Pair, LinkState) = .empty,
        network_tracker: Tracker,
        blocks: SortedMap(Pair, void) = .empty,
        transmitter: Transmitter,
        deliveries: std.PriorityQueue(Delivery, void, Delivery.order) = .empty,
        delivery_sequence: u64 = 0,

        /// Creates a network. Panics when `max_size` exceeds `max_size_limit`.
        pub fn init(gpa: Allocator, io: Io, config: Config) Allocator.Error!*Self {
            if (config.max_size > max_size_limit) @panic("maximum frame size overflow");
            assert(config.max_peers_per_set > 0);
            assert(config.tracked_peer_sets > 0);
            const network = try gpa.create(Self);
            network.* = .{
                .gpa = gpa,
                .io = io,
                .config = config,
                .max_retained_peers = sizing.max_retained_peers(
                    config.max_peers_per_set,
                    config.tracked_peer_sets,
                    0,
                ),
                .network_tracker = .init(gpa, io),
                .transmitter = .init(gpa),
            };
            return network;
        }

        /// Creates a network that tracks `primary` and `secondary` at peer-set id 0.
        pub fn init_with_peers(
            gpa: Allocator,
            io: Io,
            config: Config,
            peers: p2p.TrackedPeers(P),
        ) Allocator.Error!*Self {
            const network = try init(gpa, io, config);
            errdefer network.deinit();
            network.lock();
            defer network.unlock();
            _ = try network.register_tracked_peer_set(null, 0, peers);
            return network;
        }

        pub fn deinit(network: *Self) void {
            const gpa = network.gpa;
            for (network.peers.items()) |entry| {
                const peer = entry.value;
                for (peer.channels.items()) |*channel| channel.value.mailbox.deinit();
                peer.channels.deinit(gpa);
                peer.tracker.deinit();
                peer.connected.deinit();
                peer.blocked.deinit();
                gpa.destroy(peer);
            }
            network.peers.deinit(gpa);
            network.links.deinit(gpa);
            network.blocks.deinit(gpa);
            network.network_tracker.deinit();
            network.transmitter.deinit();
            while (network.deliveries.pop()) |delivery| network.release(delivery.payload);
            network.deliveries.deinit(gpa);
            gpa.destroy(network);
        }

        pub fn oracle(network: *Self) Oracle {
            return .{ .network = network };
        }

        fn lock(network: *Self) void {
            network.mutex.lockUncancelable(network.io);
        }

        fn unlock(network: *Self) void {
            network.mutex.unlock(network.io);
        }

        fn now(network: *const Self) SystemTime {
            return SystemTime.from_timestamp(Io.Clock.real.now(network.io));
        }

        /// Stops `run`, makes later sends report `closed`, and ends every receiver: each
        /// returns the messages it already holds, then `NetworkClosed`.
        pub fn close(network: *Self) void {
            network.lock();
            defer network.unlock();
            network.closed = true;
            for (network.peers.items()) |entry| {
                const peer = entry.value;
                for (peer.channels.items()) |*channel| channel.value.mailbox.deinit();
                peer.channels.deinit(network.gpa);
                peer.channels = .empty;
            }
            network.condition.broadcast(network.io);
        }

        /// Drives transmissions and deliveries until `close` or cancelation. Messages move only
        /// while this runs; spawn it on the runtime (`io.concurrent(Network.run, .{network})`).
        pub fn run(network: *Self) (Io.Cancelable || Allocator.Error)!void {
            try network.mutex.lock(network.io);
            defer network.unlock();
            while (!network.closed) {
                try network.tick(network.now());
                const deadline = network.next_deadline() orelse {
                    try network.condition.wait(network.io, &network.mutex);
                    continue;
                };
                const raw: Io.Timestamp = .fromNanoseconds(@intCast(deadline.nanos_since_epoch));
                const timeout: Io.Timeout = .{ .deadline = .{ .raw = raw, .clock = .real } };
                network.condition.waitTimeout(network.io, &network.mutex, timeout) catch |err| {
                    switch (err) {
                        error.Timeout => {},
                        error.Canceled => return error.Canceled,
                    }
                };
            }
        }

        fn next_deadline(network: *const Self) ?SystemTime {
            const transmit = network.transmitter.next();
            const delivery = if (network.deliveries.peek()) |d| d.deliver_at else null;
            const a = transmit orelse return delivery;
            const b = delivery orelse return a;
            return if (a.order(b) == .gt) b else a;
        }

        /// Advances the transmitter and hands over every delivery due by `at`.
        fn tick(network: *Self, at: SystemTime) Allocator.Error!void {
            var completions: Transmitter.Completions = .empty;
            defer completions.deinit(network.gpa);
            try network.transmitter.advance(at, &completions);
            try network.process_completions(completions.items);
            while (network.deliveries.peek()) |next| {
                if (next.deliver_at.order(at) == .gt) break;
                const delivery = network.deliveries.pop().?;
                try network.deliver(delivery);
            }
        }

        /// Queues delivered completions on their link (dropping those whose link is gone).
        fn process_completions(
            network: *Self,
            completions: []const Transmitter.Completion,
        ) Allocator.Error!void {
            for (completions) |completion| {
                const pair: Pair = .{
                    .origin = completion.origin,
                    .recipient = completion.recipient,
                };
                const deliver_at = completion.deliver_at orelse {
                    network.release(completion.message);
                    continue;
                };
                if (!network.links.contains(pair)) {
                    network.release(completion.message);
                    continue;
                }
                try network.deliveries.push(network.gpa, .{
                    .deliver_at = deliver_at,
                    .sequence = network.delivery_sequence,
                    .origin = completion.origin,
                    .recipient = completion.recipient,
                    .channel = completion.channel,
                    .payload = completion.message,
                });
                network.delivery_sequence += 1;
            }
            if (completions.len > 0) network.condition.broadcast(network.io);
        }

        /// Hands a message to the recipient's channel, dropping it when the channel is missing
        /// or its receiver is gone.
        fn deliver(network: *Self, delivery: Delivery) Allocator.Error!void {
            defer network.release(delivery.payload);
            const peer = network.peers.get(delivery.recipient) orelse return;
            const registration = peer.*.channels.get(delivery.channel) orelse return;
            const payload = try network.gpa.dupe(u8, delivery.payload.bytes);
            const message: Message = .{
                .peer = delivery.origin,
                .payload = payload,
                .gpa = network.gpa,
            };
            _ = try registration.mailbox.send(message);
        }

        fn release(network: *Self, payload: *Payload) void {
            assert(payload.refs > 0);
            payload.refs -= 1;
            if (payload.refs > 0) return;
            network.gpa.free(payload.bytes);
            network.gpa.destroy(payload);
        }

        /// The peer for `public_key`, created with the network-wide peer sets when new.
        fn ensure_peer(network: *Self, public_key: P) Allocator.Error!*Peer {
            if (network.peers.get(public_key)) |peer| return peer.*;
            const peer = try network.gpa.create(Peer);
            errdefer network.gpa.destroy(peer);
            peer.* = .{
                .tracker = try network.network_tracker.fork(),
                .connected = .init(network.gpa, network.io),
                .blocked = .init(network.gpa, network.io),
            };
            _ = try network.peers.put(network.gpa, public_key, peer);
            try network.publish_connected(public_key, peer);
            assert(try peer.blocked.publish(&.{}));
            return peer;
        }

        /// Whether `peer` tracks `other`.
        fn tracks(network: *const Self, peer: P, other: P) bool {
            const state = network.peers.get(peer) orelse return false;
            return state.*.tracker.contains(other);
        }

        fn is_connectable(network: *const Self, origin: P, recipient: P) bool {
            return network.tracks(origin, recipient) and network.tracks(recipient, origin);
        }

        /// Peers `sender` expands `Recipients.all` to: those it tracks that track it back.
        fn connected_peers_for(network: *const Self, gpa: Allocator, sender: P) ![]P {
            var result: std.ArrayList(P) = .empty;
            errdefer result.deinit(gpa);
            const peer = network.peers.get(sender) orelse return result.toOwnedSlice(gpa);
            for (peer.*.tracker.peers()) |entry| {
                if (P.order(entry.key, sender) == .eq) continue;
                if (network.tracks(entry.key, sender)) try result.append(gpa, entry.key);
            }
            return result.toOwnedSlice(gpa);
        }

        fn publish_connected(network: *Self, public_key: P, peer: *Peer) Allocator.Error!void {
            const connected = try network.connected_peers_for(network.gpa, public_key);
            defer network.gpa.free(connected);
            _ = try peer.connected.publish(connected);
        }

        /// Republishes every peer's connected list after membership changes.
        fn broadcast_peer_list(network: *Self) Allocator.Error!void {
            for (network.peers.items()) |entry| {
                try network.publish_connected(entry.key, entry.value);
            }
        }

        fn notify_blocked(network: *Self, from: P) Allocator.Error!void {
            const peer = network.peers.get(from) orelse return;
            var blocked: std.ArrayList(P) = .empty;
            defer blocked.deinit(network.gpa);
            for (network.blocks.items()) |entry| {
                if (P.order(entry.key.origin, from) == .eq) {
                    try blocked.append(network.gpa, entry.key.recipient);
                }
            }
            _ = try peer.*.blocked.publish(blocked.items);
        }

        /// Tracks `peers` at `id` for `owner` (or network-wide). Returns whether `id` was newer
        /// than every set already tracked there.
        fn register_tracked_peer_set(
            network: *Self,
            owner: ?P,
            id: u64,
            peers: p2p.TrackedPeers(P),
        ) Allocator.Error!bool {
            const owner_tracker = try network.tracker_of(owner);
            if (!owner_tracker.accepts(id)) return false;
            const primary = peers.primary.items;
            const count = sizing.peer_set_size(P, primary, peers.secondary.items, owner);
            if (count > network.config.max_peers_per_set) @panic("peer set too large");
            for (peers.primary.items) |peer| _ = try network.ensure_peer(peer);
            for (peers.secondary.items) |peer| _ = try network.ensure_peer(peer);
            const limit = network.config.tracked_peer_sets;
            if (owner == null) {
                for (network.peers.items()) |entry| {
                    const tracker = &entry.value.tracker;
                    if (tracker.accepts(id)) try tracker.track(id, peers, limit);
                }
            }
            try (try network.tracker_of(owner)).track(id, peers, limit);
            try network.broadcast_peer_list();
            return true;
        }

        fn tracker_of(network: *Self, owner: ?P) Allocator.Error!*Tracker {
            const key = owner orelse return &network.network_tracker;
            return &(try network.ensure_peer(key)).tracker;
        }

        /// Sends `payload` from `origin` on `channel` to `recipients` through the links.
        fn send_payload(
            network: *Self,
            channel: Channel,
            origin: P,
            recipients: p2p.Recipients(P),
            parts: []const []const u8,
        ) Allocator.Error!void {
            const bytes = try std.mem.concat(network.gpa, u8, parts);
            const payload = network.gpa.create(Payload) catch |err| {
                network.gpa.free(bytes);
                return err;
            };
            payload.* = .{ .refs = 1, .len = bytes.len, .bytes = bytes };
            defer network.release(payload);
            const all = if (recipients == .all)
                try network.connected_peers_for(network.gpa, origin)
            else
                null;
            defer if (all) |list| network.gpa.free(list);
            const targets: []const P = all orelse recipients.peers();
            for (targets) |recipient| try network.send_one(channel, origin, recipient, payload);
            network.condition.broadcast(network.io);
        }

        fn send_one(
            network: *Self,
            channel: Channel,
            origin: P,
            recipient: P,
            payload: *Payload,
        ) Allocator.Error!void {
            if (P.order(origin, recipient) == .eq) return;
            if (!network.is_connectable(origin, recipient)) return;
            const forward: Pair = .{ .origin = origin, .recipient = recipient };
            const backward: Pair = .{ .origin = recipient, .recipient = origin };
            const blocked = network.blocks.contains(forward) or network.blocks.contains(backward);
            if (network.config.disconnect_on_block and blocked) return;
            const link = network.links.get(forward) orelse return;
            const rng: IoRng = .{ .io = network.io };
            const latency = latency_from_ms(sample_normal(rng, link.latency_ms, link.jitter_ms));
            const should_deliver = utils_pkg.rng.bernoulli(rng, link.success_rate);
            payload.refs += 1;
            var completions: Transmitter.Completions = .empty;
            defer completions.deinit(network.gpa);
            try network.transmitter.enqueue(
                network.now(),
                origin,
                recipient,
                channel,
                payload,
                latency,
                should_deliver,
                &completions,
            );
            try network.process_completions(completions.items);
        }

        /// Registers `channel` for `public_key`, replacing (and closing) an earlier registration.
        fn register(network: *Self, public_key: P, channel: Channel, quota: Quota) !Registered {
            const pair = try Mailbox.init(network.gpa, network.io);
            var mailbox = pair.receiver;
            errdefer mailbox.deinit();
            var sender_mailbox = pair.sender;
            var registered = false;
            errdefer if (!registered) sender_mailbox.deinit();
            const burst: usize = quota.burst_size();
            const capacity = std.math.mul(usize, network.max_retained_peers, burst) catch
                @panic("channel capacity must fit in usize");
            const generation = blk: {
                network.lock();
                defer network.unlock();
                if (network.closed) return error.NetworkClosed;
                const peer = try network.ensure_peer(public_key);
                network.next_generation += 1;
                const registration: Registration = .{
                    .mailbox = sender_mailbox,
                    .generation = network.next_generation,
                };
                if (try peer.channels.put(network.gpa, channel, registration)) |replaced| {
                    var old = replaced.mailbox;
                    old.deinit();
                }
                registered = true;
                break :blk network.next_generation;
            };
            const unlimited: UnlimitedSender = .{
                .network = network,
                .me = public_key,
                .channel = channel,
                .generation = generation,
            };
            const connected: Connected = .{ .network = network, .me = public_key };
            const sender = try Sender.init(network.gpa, network.io, unlimited, quota, connected);
            const receiver: Receiver = .{ .mailbox = mailbox, .capacity_value = capacity };
            return .{ .sender = sender, .receiver = receiver };
        }

        pub const Registered = struct { sender: Sender, receiver: Receiver };

        /// The network's unlimited sender for one registered channel.
        pub const UnlimitedSender = struct {
            pub const PublicKey = P;

            network: *Self,
            me: P,
            channel: Channel,
            generation: u64,

            /// Panics when the message exceeds the configured `max_size`.
            pub fn send(
                sender: UnlimitedSender,
                recipients: p2p.Recipients(P),
                parts: []const []const u8,
                priority: bool,
            ) Unreliable(Feedback) {
                _ = priority;
                const network = sender.network;
                var len: usize = 0;
                for (parts) |part| len += part.len;
                if (len > network.config.max_size) @panic("message too large");
                network.lock();
                defer network.unlock();
                if (network.closed or !sender.is_active()) return .new(.closed);
                network.send_payload(sender.channel, sender.me, recipients, parts) catch
                    return .rejected;
                return .new(.ok);
            }

            fn is_active(sender: UnlimitedSender) bool {
                const peer = sender.network.peers.get(sender.me) orelse return false;
                const registration = peer.*.channels.get(sender.channel) orelse return false;
                return registration.generation == sender.generation;
            }
        };

        /// Known peers of one sender, for `Recipients.all` (tracked peers, not liveness).
        pub const Connected = struct {
            pub const PublicKey = P;
            pub const Subscription = Watch(P).Subscription;

            network: *Self,
            me: P,

            pub fn peers(connected: Connected, gpa: Allocator) ![]P {
                connected.network.lock();
                defer connected.network.unlock();
                return connected.network.connected_peers_for(gpa, connected.me);
            }

            pub fn subscribe(connected: Connected) Subscription {
                const network = connected.network;
                network.lock();
                defer network.unlock();
                const peer = network.peers.get(connected.me).?;
                return peer.*.connected.subscribe(true);
            }
        };

        /// Receives the messages of one registered channel.
        pub const Receiver = struct {
            pub const PublicKey = P;

            mailbox: Mailbox.Receiver,
            capacity_value: usize,

            /// The next message (free it with `deinit`), or `NetworkClosed` once the network
            /// or a newer registration of the channel closed this one.
            pub fn recv(receiver: *Receiver) (Io.Cancelable || error{NetworkClosed})!Message {
                return (try receiver.mailbox.recv()) orelse error.NetworkClosed;
            }

            /// The next message if one has arrived: `Empty` when none has, `Disconnected` once
            /// the network or a newer registration closed this channel and it is drained.
            pub fn try_recv(receiver: *Receiver) error{ Empty, Disconnected }!Message {
                return receiver.mailbox.try_recv();
            }

            /// Messages this receiver holds before it may drop arrivals.
            pub fn capacity(receiver: *const Receiver) usize {
                assert(receiver.capacity_value > 0);
                return receiver.capacity_value;
            }

            pub fn deinit(receiver: *Receiver) void {
                receiver.mailbox.deinit();
                receiver.* = undefined;
            }
        };

        /// Modifies the network: links, bandwidth, blocks, controls, and managers.
        pub const Oracle = struct {
            network: *Self,

            /// The control interface of `me`.
            pub fn control(oracle_value: Oracle, me: P) Control {
                return .{ .network = oracle_value.network, .me = me };
            }

            /// The network-wide peer-set manager: sets reach every peer, including later ones.
            pub fn manager(oracle_value: Oracle) Manager {
                return .{ .network = oracle_value.network, .owner = null };
            }

            /// Adds a directed link. Fails for a self link or an existing link.
            pub fn add_link(oracle_value: Oracle, sender: P, receiver: P, link: Link) !void {
                assert(link.success_rate >= 0 and link.success_rate <= 1);
                if (P.order(sender, receiver) == .eq) return error.LinkingSelf;
                const network = oracle_value.network;
                network.lock();
                defer network.unlock();
                if (network.closed) return error.NetworkClosed;
                _ = try network.ensure_peer(sender);
                _ = try network.ensure_peer(receiver);
                const pair: Pair = .{ .origin = sender, .recipient = receiver };
                if (network.links.contains(pair)) return error.LinkExists;
                const ns_per_ms: f64 = std.time.ns_per_ms;
                _ = try network.links.put(network.gpa, pair, .{
                    .latency_ms = @as(f64, @floatFromInt(link.latency.as_nanos())) / ns_per_ms,
                    .jitter_ms = @as(f64, @floatFromInt(link.jitter.as_nanos())) / ns_per_ms,
                    .success_rate = link.success_rate,
                });
            }

            /// Removes a directed link. Messages already in flight on it still arrive.
            pub fn remove_link(oracle_value: Oracle, sender: P, receiver: P) !void {
                const network = oracle_value.network;
                network.lock();
                defer network.unlock();
                if (network.closed) return error.NetworkClosed;
                const pair: Pair = .{ .origin = sender, .recipient = receiver };
                if (network.links.remove(pair) == null) return error.LinkMissing;
            }

            /// Sets `peer`'s bandwidth limits in bytes per second (null is unlimited).
            pub fn limit_bandwidth(
                oracle_value: Oracle,
                peer: P,
                egress: ?u64,
                ingress: ?u64,
            ) !void {
                const network = oracle_value.network;
                network.lock();
                defer network.unlock();
                if (network.closed) return error.NetworkClosed;
                _ = try network.ensure_peer(peer);
                var completions: Transmitter.Completions = .empty;
                defer completions.deinit(network.gpa);
                try network.transmitter.limit(network.now(), peer, egress, ingress, &completions);
                try network.process_completions(completions.items);
                network.condition.broadcast(network.io);
            }

            /// Every `(blocker, blocked)` pair, ascending, owned by the caller.
            pub fn blocked(oracle_value: Oracle, gpa: Allocator) ![]Pair {
                const network = oracle_value.network;
                network.lock();
                defer network.unlock();
                const result = try gpa.alloc(Pair, network.blocks.count());
                for (network.blocks.items(), result) |entry, *pair| pair.* = entry.key;
                return result;
            }

            /// Lifts a block of `to` by `from`.
            pub fn unblock(oracle_value: Oracle, from: P, to: P) !void {
                const network = oracle_value.network;
                network.lock();
                defer network.unlock();
                if (network.closed) return error.NetworkClosed;
                const pair: Pair = .{ .origin = from, .recipient = to };
                if (network.blocks.remove(pair) != null) try network.notify_blocked(from);
            }
        };

        /// One peer's view: register channels, manage its own peer sets, block peers.
        pub const Control = struct {
            pub const PublicKey = P;

            network: *Self,
            me: P,

            /// Registers `channel`, returning its sender and receiver.
            pub fn register(control: Control, channel: Channel, quota: Quota) !Registered {
                return control.network.register(control.me, channel, quota);
            }

            /// A manager whose sets reach this peer alone.
            pub fn manager(control: Control) Manager {
                return .{ .network = control.network, .owner = control.me };
            }

            /// Forgets every peer set this peer tracks, as a restart does.
            pub fn reset_peer_sets(control: Control) !void {
                const network = control.network;
                network.lock();
                defer network.unlock();
                const peer = try network.ensure_peer(control.me);
                peer.tracker.deinit();
                peer.tracker = .init(network.gpa, network.io);
                try network.broadcast_peer_list();
            }

            /// Blocks `peer` (commonware `Blocker::block`).
            pub fn block(control: Control, peer: P) Feedback {
                const network = control.network;
                network.lock();
                defer network.unlock();
                if (network.closed) return .closed;
                const pair: Pair = .{ .origin = control.me, .recipient = peer };
                const inserted = network.blocks.put(network.gpa, pair, {}) catch return .closed;
                if (inserted == null) {
                    _ = network.ensure_peer(control.me) catch return .closed;
                    network.notify_blocked(control.me) catch return .closed;
                }
                return .ok;
            }

            /// A subscription to the set of peers this peer blocks; it first yields the current
            /// set (commonware `Blocker::blocked`).
            pub fn blocked(control: Control) !Watch(P).Subscription {
                const network = control.network;
                network.lock();
                defer network.unlock();
                const peer = try network.ensure_peer(control.me);
                return peer.blocked.subscribe(true);
            }
        };

        /// Tracks peer sets for one peer, or network-wide (`owner == null`).
        pub const Manager = struct {
            pub const PublicKey = P;

            network: *Self,
            owner: ?P,

            /// Tracks `peers` at `id`; ignored unless `id` is newer than every set tracked here.
            pub fn track(manager: Manager, id: u64, peers: p2p.TrackedPeers(P)) Feedback {
                const network = manager.network;
                network.lock();
                defer network.unlock();
                if (network.closed) return .closed;
                const owner = manager.owner;
                _ = network.register_tracked_peer_set(owner, id, peers) catch return .closed;
                return .ok;
            }

            /// A copy of the set tracked at `id`, owned by the caller (`free(gpa)`).
            pub fn peer_set(manager: Manager, gpa: Allocator, id: u64) !?OwnedPeers {
                const network = manager.network;
                network.lock();
                defer network.unlock();
                return (try network.tracker_of(manager.owner)).peer_set(gpa, id);
            }

            /// A subscription to peer-set updates; it first yields the current one, if any.
            pub fn subscribe(manager: Manager) !PeerSetSubscription {
                const network = manager.network;
                network.lock();
                defer network.unlock();
                return (try network.tracker_of(manager.owner)).subscribe();
            }
        };
    };
}
