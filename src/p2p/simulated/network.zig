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
//! - Latency is drawn with `rand_distr`'s ziggurat `Normal` (`normal.zig`), so a link gives
//!   commonware's samples for the same RNG stream; the stream itself also feeds the runtime's
//!   scheduler, whose task order differs from commonware's actor.
//! - `deinit` the network after every sender, control, oracle, and manager is gone.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils_pkg = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
const traces = @import("runtime").telemetry.traces;
const p2p = @import("../root.zig");
const sizing = @import("../sizing.zig");
const limited = @import("../utils/limited.zig");
const split_mod = @import("split.zig");
const Watch = @import("../utils/watch.zig").Watch;
const Quota = @import("../rate_limit.zig").Quota;
const SortedMap = @import("sorted_map.zig").SortedMap;
const Unbounded = @import("channel.zig").Unbounded;
const tracker_mod = @import("tracker.zig");
const transmitter = @import("transmitter.zig");
const normal = @import("normal.zig");
const labels = @import("metrics.zig");
const Normal = normal.Normal;

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
    /// Where `messages_sent` and `messages_received` are registered (commonware's network
    /// context); none without it.
    scope: ?metrics.Scope = null,
    /// Where tracing events go, under commonware's `simulated::network` target.
    tracer: traces.Tracer = .none,
};

const target = "commonware_p2p::simulated::network";

/// Link behavior from a sender to a receiver.
pub const Link = struct {
    /// Mean latency for the delivery of a message.
    latency: Duration,
    /// Standard deviation of the latency.
    jitter: Duration,
    /// Probability that a message is delivered, in `[0, 1]`.
    success_rate: f64,
};

const IoRng = @import("../utils/io_rng.zig").IoRng;

/// Whether a message on a link with `success_rate` is delivered (commonware
/// `Probability::sample`): certain outcomes draw nothing from the RNG. Panics when the rate
/// is not exactly a 64-bit threshold, as commonware's `probability!` fails to compile.
fn sample_success(rng: IoRng, success_rate: f64) bool {
    assert(success_rate >= 0 and success_rate <= 1);
    const probability = utils_pkg.Probability.from_f64(success_rate) orelse
        @panic("success rate is not representable as a probability");
    return probability.sample(rng);
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
        const Label = labels.Message(P);
        const Family = metrics.raw.Family(Label, metrics.raw.Counter);

        /// Messages sent once a link to the recipient exists, and messages a link delivered.
        const Families = struct {
            sent: metrics.Registered(Family),
            received: metrics.Registered(Family),

            fn init(scope: *const metrics.Scope) Allocator.Error!Families {
                const Counter = metrics.raw.Counter;
                var sent = try scope.family(Label, Counter, "messages_sent", "messages sent");
                errdefer sent.deinit();
                const name = "messages_received";
                const received = try scope.family(Label, Counter, name, "messages received");
                return .{ .sent = sent, .received = received };
            }

            fn deinit(families: *Families) void {
                families.sent.deinit();
                families.received.deinit();
            }

            fn count(family: *metrics.Registered(Family), label: Label) Allocator.Error!void {
                (try family.metric().get_or_create(label)).inc();
            }
        };

        pub const PublicKey = P;
        pub const Limited = limited.LimitedSender(UnlimitedSender, Connected);
        pub const PeerSetSubscription = Tracker.Subscription;
        pub const PeerSetUpdate = Tracker.Update;
        pub const OwnedPeers = Tracker.Owned;
        pub const BlockedSubscription = Watch(P).Subscription;

        const Registration = struct { mailbox: Mailbox.Sender, generation: u64 };

        const Peer = struct {
            tracker: Tracker,
            channels: SortedMap(Channel, Registration) = .empty,
            /// Peers this one may expand `Recipients.all` to.
            connected: Watch(P),
            /// Peers this one blocks.
            blocked: Watch(P),
        };

        const LinkState = struct { sampler: Normal, success_rate: f64 };

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
        families: ?Families,
        tracer: traces.Tracer,

        /// Creates a network. Panics when `max_size` exceeds `max_size_limit`.
        pub fn init(gpa: Allocator, io: Io, config: Config) Allocator.Error!*Self {
            if (config.max_size > max_size_limit) @panic("maximum frame size overflow");
            assert(config.max_peers_per_set > 0);
            assert(config.tracked_peer_sets > 0);
            const network = try gpa.create(Self);
            errdefer gpa.destroy(network);
            var families: ?Families = if (config.scope) |*scope| try .init(scope) else null;
            errdefer if (families) |*registered| registered.deinit();
            const tracer = config.tracer.with_target(target);
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
                .families = families,
                .tracer = tracer,
            };
            network.network_tracker.tracer = tracer;
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
            if (network.families) |*families| families.deinit();
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
                const fields = .{ .origin = pair.origin, .recipient = pair.recipient };
                const deliver_at = completion.deliver_at orelse {
                    network.tracer.event(.trace, "message dropped before delivery", fields);
                    network.release(completion.message);
                    continue;
                };
                if (!network.links.contains(pair)) {
                    // The link was removed before the message was delivered.
                    network.tracer.event(.trace, "missing link for completion", fields);
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
            const channel = delivery.channel;
            if (network.families) |*families| {
                const label: Label = .new(delivery.origin, delivery.recipient, channel);
                try Families.count(&families.received, label);
            }
            const peer = network.peers.get(delivery.recipient) orelse return;
            const registration = peer.*.channels.get(channel) orelse {
                network.tracer.event(.trace, "dropping message", .{
                    .recipient = delivery.recipient,
                    .channel = channel,
                    .reason = "missing channel",
                });
                return;
            };
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
            const max = network.config.max_peers_per_set;
            if (count > max) std.debug.panic("peer set too large: {d} > {d}", .{ count, max });
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
            const reason = network.drop_reason(origin, recipient);
            if (reason) |text| {
                const message = "dropping message";
                const fields = .{ .origin = origin, .recipient = recipient, .reason = text };
                network.tracer.event(.trace, message, fields);
                return;
            }
            const forward: Pair = .{ .origin = origin, .recipient = recipient };
            const link = network.links.get(forward).?;
            // A link to the recipient approximates an open connection.
            if (network.families) |*families| {
                try Families.count(&families.sent, .new(origin, recipient, channel));
            }
            const rng: IoRng = .{ .io = network.io };
            const latency = latency_from_ms(link.sampler.sample(rng));
            const should_deliver = sample_success(rng, link.success_rate);
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

        /// Why a message from `origin` to `recipient` is dropped before its link, if it is.
        fn drop_reason(network: *const Self, origin: P, recipient: P) ?[]const u8 {
            if (P.order(origin, recipient) == .eq) return "self";
            if (!network.is_connectable(origin, recipient)) return "not tracked by both peers";
            const forward: Pair = .{ .origin = origin, .recipient = recipient };
            const backward: Pair = .{ .origin = recipient, .recipient = origin };
            const blocked = network.blocks.contains(forward) or network.blocks.contains(backward);
            if (network.config.disconnect_on_block and blocked) return "blocked";
            if (!network.links.contains(forward)) return "no link";
            return null;
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
                    const fields = .{ .public_key = public_key, .channel = channel };
                    network.tracer.event(.warn, "overwriting existing channel", fields);
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
            const sender: Sender = .{
                .limited = try .init(network.gpa, network.io, unlimited, quota, connected),
            };
            const receiver: Receiver = .{ .mailbox = mailbox, .capacity_value = capacity };
            return .{ .sender = sender, .receiver = receiver };
        }

        pub const Registered = struct {
            sender: Sender,
            receiver: Receiver,

            pub fn deinit(registered: *Registered) void {
                registered.sender.deinit();
                registered.receiver.deinit();
            }
        };

        /// The rate-limited sender of one registered channel (commonware `Sender`).
        pub const Sender = struct {
            pub const PublicKey = P;
            pub const Checked = Limited.Checked;

            limited: Limited,

            pub fn check(sender: *Sender, recipients: p2p.Recipients(P)) !p2p.Check(Checked) {
                return sender.limited.check(recipients);
            }

            /// The recipients attempted (caller-owned), as `LimitedSender.send`.
            pub fn send(
                sender: *Sender,
                recipients: p2p.Recipients(P),
                parts: []const []const u8,
                priority: bool,
            ) ![]P {
                return sender.limited.send(recipients, parts, priority);
            }

            pub fn clone(sender: *const Sender) Sender {
                return .{ .limited = sender.limited.clone() };
            }

            pub fn deinit(sender: *Sender) void {
                sender.limited.deinit();
                sender.* = undefined;
            }

            /// Splits this sender (consumed) into a primary and a secondary half; each half's
            /// sends go wherever `forwarder` redirects them (see `split.zig`).
            pub fn split_with(
                sender: Sender,
                forwarder: anytype,
            ) split_mod.Halves(SplitSender(@TypeOf(forwarder))) {
                return SplitSender(@TypeOf(forwarder)).split(sender.limited, forwarder);
            }
        };

        pub fn SplitSender(comptime F: type) type {
            return split_mod.SplitSender(Limited, F);
        }

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
            /// The routing task of the split this receiver is a half of, if any.
            splitter: ?*Splitter = null,

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
                if (receiver.splitter) |splitter| splitter.release();
                receiver.* = undefined;
            }

            /// Splits this receiver (consumed) into a primary and a secondary half: a task
            /// routes each message by `router.route(*const Message) SplitTarget`, and ends once
            /// the network closes this channel or both halves are released (commonware
            /// `Receiver::split_with`). Both halves keep this receiver's capacity.
            pub fn split_with(
                receiver: Receiver,
                gpa: Allocator,
                io: Io,
                router: anytype,
            ) !split_mod.Halves(Receiver) {
                var primary = try Mailbox.init(gpa, io);
                errdefer primary.sender.deinit();
                errdefer primary.receiver.deinit();
                var secondary = try Mailbox.init(gpa, io);
                errdefer secondary.sender.deinit();
                errdefer secondary.receiver.deinit();
                const splitter = try gpa.create(Splitter);
                errdefer gpa.destroy(splitter);
                splitter.* = .{ .gpa = gpa, .io = io, .task = undefined };
                const Route = Routing(@TypeOf(router));
                splitter.task = try io.concurrent(Route.run, .{
                    gpa, receiver, primary.sender, secondary.sender, router,
                });
                const capacity_value = receiver.capacity_value;
                return .{
                    .primary = .{
                        .mailbox = primary.receiver,
                        .capacity_value = capacity_value,
                        .splitter = splitter,
                    },
                    .secondary = .{
                        .mailbox = secondary.receiver,
                        .capacity_value = capacity_value,
                        .splitter = splitter,
                    },
                };
            }
        };

        /// The routing task shared by the two halves of a split receiver; the last half
        /// released stops it.
        pub const Splitter = struct {
            gpa: Allocator,
            io: Io,
            /// Halves still alive.
            halves: std.atomic.Value(u32) = .init(2),
            task: Io.Future(void),

            fn release(splitter: *Splitter) void {
                const before = splitter.halves.fetchSub(1, .acq_rel);
                assert(before == 1 or before == 2);
                if (before != 1) return;
                splitter.task.cancel(splitter.io);
                splitter.gpa.destroy(splitter);
            }
        };

        fn Routing(comptime R: type) type {
            return struct {
                fn run(
                    gpa: Allocator,
                    source: Receiver,
                    primary: Mailbox.Sender,
                    secondary: Mailbox.Sender,
                    router: R,
                ) void {
                    var source_owned = source;
                    var primary_owned = primary;
                    var secondary_owned = secondary;
                    defer {
                        primary_owned.deinit();
                        secondary_owned.deinit();
                        source_owned.deinit();
                    }
                    while (true) {
                        const message = (source_owned.mailbox.recv() catch return) orelse return;
                        switch (router.route(&message)) {
                            .none => release_message(message),
                            .primary => hand_off(primary_owned, message),
                            .secondary => hand_off(secondary_owned, message),
                            .both => {
                                if (copy_message(gpa, message)) |copy| {
                                    hand_off(primary_owned, copy);
                                } else |_| {}
                                hand_off(secondary_owned, message);
                            },
                        }
                        if (primary_owned.is_closed() and secondary_owned.is_closed()) return;
                    }
                }
            };
        }

        fn release_message(message: Message) void {
            var owned = message;
            owned.deinit();
        }

        /// Hands `message` to a split half; a closed half releases it.
        fn hand_off(half: Mailbox.Sender, message: Message) void {
            // Unbounded sends only fail to allocate, and then leave the message with us.
            _ = half.send(message) catch release_message(message);
        }

        fn copy_message(gpa: Allocator, message: Message) Allocator.Error!Message {
            const payload = try gpa.dupe(u8, message.payload);
            return .{ .peer = message.peer, .payload = payload, .gpa = gpa };
        }

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

            /// The network-wide peer sets as an `AddressableManager` that ignores addresses.
            pub fn socket_manager(oracle_value: Oracle) SocketManager {
                return .{ .manager = oracle_value.manager() };
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
                const latency_ms = normal.duration_ms(link.latency);
                const jitter_ms = normal.duration_ms(link.jitter);
                // A Duration is finite, so the deviation is valid.
                const sampler = Normal.init(latency_ms, jitter_ms) catch unreachable;
                _ = try network.links.put(network.gpa, pair, .{
                    .sampler = sampler,
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

            /// This peer's own peer sets as an `AddressableManager` that ignores addresses.
            pub fn socket_manager(control: Control) SocketManager {
                return .{ .manager = control.manager() };
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
            pub fn blocked(control: Control) !BlockedSubscription {
                const network = control.network;
                network.lock();
                defer network.unlock();
                const peer = try network.ensure_peer(control.me);
                return peer.blocked.subscribe(true);
            }
        };

        /// Tracks peer sets for one peer, or network-wide (`owner == null`).
        /// A `Manager` taking peers with addresses (commonware `SocketManager`): the simulated
        /// network does not use addresses, so `track` drops them and `overwrite` does nothing.
        pub const SocketManager = struct {
            pub const PublicKey = P;
            pub const Tracked = p2p.AddressableTrackedPeers(P);
            pub const PeerMap = Tracked.PeerMap;

            manager: Manager,

            /// Tracks the keys of `peers` at `id`, as `Manager.track`.
            pub fn track(socket_manager: SocketManager, id: u64, peers: Tracked) Feedback {
                const gpa = socket_manager.manager.network.gpa;
                const primary = keys_of(gpa, peers.primary) catch return .closed;
                defer gpa.free(primary);
                const secondary = keys_of(gpa, peers.secondary) catch return .closed;
                defer gpa.free(secondary);
                const tracked: p2p.TrackedPeers(P) = .{
                    .primary = .init(primary),
                    .secondary = .init(secondary),
                };
                return socket_manager.manager.track(id, tracked);
            }

            /// Every address is valid here, so there is nothing to overwrite.
            pub fn overwrite(socket_manager: SocketManager, peers: PeerMap) Feedback {
                _ = socket_manager;
                _ = peers;
                return .ok;
            }

            pub fn peer_set(socket_manager: SocketManager, gpa: Allocator, id: u64) !?OwnedPeers {
                return socket_manager.manager.peer_set(gpa, id);
            }

            pub fn subscribe(socket_manager: SocketManager) !PeerSetSubscription {
                return socket_manager.manager.subscribe();
            }

            /// The keys of `map`, ascending as the map's.
            fn keys_of(gpa: Allocator, map: PeerMap) Allocator.Error![]P {
                const keys = try gpa.alloc(P, map.entries.len);
                for (map.entries, keys) |entry, *peer| peer.* = entry.key;
                return keys;
            }
        };

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
