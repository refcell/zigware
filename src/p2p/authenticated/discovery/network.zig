//! A discovery network (commonware `discovery/network.rs` and the dialer, listener, and spawner
//! actors): dials bootstrappers and gossiped peers, accepts inbound peers, authenticates every
//! connection with the stream upgrader, and runs each connection as a `Peer`.
//!
//! commonware runs these as actors; here the dialer, listener, unblock timer, handshakes, and
//! connections are tasks in one group that `run` owns, and the tracker and router are locked
//! shared state.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const stream = @import("stream");
const p2p = @import("../../root.zig");
const p2p_types = @import("../../types.zig");
const sizing = @import("../../sizing.zig");
const rate_limit = @import("../../rate_limit.zig");
const IoRng = @import("../../utils/io_rng.zig").IoRng;
const shuffle = @import("../../utils/shuffle.zig");
const data = @import("../data.zig");
const router_mod = @import("../router.zig");
const channels_mod = @import("../channels.zig");
const Outbox = @import("../outbox.zig").Outbox;
const config_mod = @import("config.zig");
const tracker_mod = @import("tracker.zig");
const peer_mod = @import("peer.zig");

const Ingress = p2p_types.Ingress;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const IpAddress = Io.net.IpAddress;

/// Suffix of the tracker's signed messages.
const tracker_suffix = "_TRACKER";
/// Suffix of stream authentication.
const stream_suffix = "_STREAM";
/// Suffix of signed discovery address records.
const ip_suffix = "_IP";
/// Handshake rate limits group IPv4 /24 and IPv6 /48 subnets.
const subnet_ipv4_bits = 24;
const subnet_ipv6_bits = 48;
/// Accepted connections between sweeps of idle rate-limiter entries.
const cleanup_interval: u32 = 16_384;
/// Consecutive accept failures after which the listener stops.
const accept_failures_max: u32 = 1024;

pub fn Network(comptime U: type, comptime Transport: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = U.PublicKey;
        const P = PublicKey;
        pub const Config = config_mod.Config(U);
        pub const Tracker = tracker_mod.Tracker(P);
        pub const Oracle = Tracker.Oracle;
        pub const Router = router_mod.Router(P);
        pub const Channels = channels_mod.Channels(P);
        pub const Registered = Channels.Registered;
        pub const Sender = Channels.Sender;
        pub const Receiver = Channels.Receiver;
        const Peer = peer_mod.Peer(P);
        const Metadata = Tracker.Metadata;
        const Upgrader = stream.utils.Timeout(U);
        const Stream = @FieldType(Transport.Connection, "stream");
        const Sink = @FieldType(Transport.Connection, "sink");
        const Upgraded = U.Connection(Stream, Sink);
        const IpLimiter = rate_limit.KeyedRateLimiter(codec.IpAddr);

        gpa: Allocator,
        io: Io,
        transport: *Transport,
        config: Config,
        upgrader: Upgrader,
        /// `namespace ++ "_STREAM"`, owned.
        stream_namespace: []u8,
        /// `namespace ++ "_TRACKER_IP"`, owned; the verifier borrows it.
        ip_namespace: []u8,
        /// Gossip shares the stream with data, so frames fit the larger of the two.
        max_frame_size: u32,
        router: Router,
        channels: Channels,
        tracker: Tracker,
        peer_config: Peer.Config,
        /// The dialer, listener, unblock timer, handshakes, and connections.
        tasks: Io.Group = .init,
        /// Inbound handshakes in flight.
        handshakes: std.atomic.Value(u32) = .init(0),

        /// Creates a network; register channels, then `run` it. Panics when the payload limit
        /// or the gossip bound exceeds the stream limit.
        pub fn create(gpa: Allocator, io: Io, transport: *Transport, config: Config) !*Self {
            if (config.max_message_size > data.max_size(U.max_size)) {
                @panic("maximum message size exceeds stream limit");
            }
            const gossip = std.math.cast(u32, config.max_gossip_size()) orelse
                @panic("gossip size must fit in u32");
            if (gossip > U.max_size) @panic("largest peer discovery message exceeds stream limit");
            const data_frame = config.max_message_size + data.max_payload_overhead;
            const network = try gpa.create(Self);
            errdefer gpa.destroy(network);
            const stream_namespace =
                try std.mem.concat(gpa, u8, &.{ config.namespace, stream_suffix });
            errdefer gpa.free(stream_namespace);
            const ip_namespace =
                try std.mem.concat(gpa, u8, &.{ config.namespace, tracker_suffix, ip_suffix });
            errdefer gpa.free(ip_namespace);
            const timeout_ns: i96 = @intCast(config.handshake_timeout.as_nanos());
            const timeout: Io.Duration = .{ .nanoseconds = timeout_ns };
            network.* = .{
                .gpa = gpa,
                .io = io,
                .transport = transport,
                .config = config,
                .upgrader = .init(config.upgrader, timeout),
                .stream_namespace = stream_namespace,
                .ip_namespace = ip_namespace,
                .max_frame_size = @max(data_frame, gossip),
                .router = undefined,
                .channels = undefined,
                .tracker = undefined,
                .peer_config = make_peer_config(&config, ip_namespace),
            };
            network.router = try Router.init(gpa, io);
            errdefer network.router.deinit();
            network.tracker = try Tracker.init(gpa, io, network.tracker_config());
            errdefer network.tracker.deinit();
            const max_peers = try retained_peers(gpa, &network.config);
            network.channels = .init(gpa, io, &network.router, config.max_message_size, max_peers);
            return network;
        }

        /// Frees the network after `run` returned (or was never called). Deinitialize every
        /// registered sender first; receivers may outlive the network.
        pub fn destroy(network: *Self) void {
            const gpa = network.gpa;
            network.channels.deinit();
            network.router.deinit();
            network.tracker.deinit();
            gpa.free(network.stream_namespace);
            gpa.free(network.ip_namespace);
            gpa.destroy(network);
        }

        fn make_peer_config(config: *const Config, ip_namespace: []const u8) Peer.Config {
            return .{
                .gossip_bit_vec_frequency = config.gossip_bit_vec_frequency,
                .send_batch_size = config.send_batch_size,
                .max_message_size = config.max_message_size,
                .max_bit_vec = config.max_peers_per_set,
                .max_peers = config.peer_gossip_max_count,
                .verifier = .{
                    .me = config.upgrader.public_key(),
                    .peer_gossip_max_count = config.peer_gossip_max_count,
                    .synchrony_bound = config.synchrony_bound,
                    .ip_namespace = ip_namespace,
                },
            };
        }

        /// Our info, signed now under the gossip namespace with the upgrader's identity.
        fn tracker_config(network: *const Self) Tracker.Config {
            const config = &network.config;
            const timestamp = now_time(network.io).epoch_millis();
            const signer = &config.upgrader.handshake.signer;
            const myself = Tracker.Info.sign(
                config.upgrader.public_key(),
                network.ip_namespace,
                config.dialable,
                timestamp,
                signer,
            );
            return .{
                .myself = myself,
                .bootstrappers = config.bootstrappers,
                .allow_private_ips = config.allow_private_ips,
                .allow_dns = config.allow_dns,
                .max_peers_per_set = config.max_peers_per_set,
                .tracked_peer_sets = config.tracked_peer_sets,
                .peer_connection_cooldown = config.peer_connection_cooldown,
                .peer_gossip_max_count = config.peer_gossip_max_count,
                .dial_fail_limit = config.dial_fail_limit,
                .block_duration = config.block_duration,
            };
        }

        /// Each tracked set may hold `max_peers_per_set` identities; distinct bootstrappers
        /// other than us persist outside that window.
        fn retained_peers(gpa: Allocator, config: *const Config) Allocator.Error!usize {
            const local = config.upgrader.public_key();
            const keys = try gpa.alloc(P, config.bootstrappers.len);
            defer gpa.free(keys);
            var count: usize = 0;
            for (config.bootstrappers) |bootstrapper| {
                if (P.order(bootstrapper.peer, local) == .eq) continue;
                keys[count] = bootstrapper.peer;
                count += 1;
            }
            std.sort.pdq(P, keys[0..count], {}, less_than);
            var unique: usize = 0;
            for (keys[0..count], 0..) |key, index| {
                if (index > 0 and P.order(keys[index - 1], key) == .eq) continue;
                unique += 1;
            }
            const sets = config.tracked_peer_sets;
            return sizing.max_retained_peers(config.max_peers_per_set, sets, unique);
        }

        fn less_than(_: void, a: P, b: P) bool {
            return P.order(a, b) == .lt;
        }

        /// Registers `channel` with a per-peer `quota` (commonware `Network::register`); call
        /// before `run`. Panics on a duplicate channel.
        pub fn register(network: *Self, channel: p2p.Channel, quota: rate_limit.Quota) !Registered {
            return network.channels.register(channel, quota);
        }

        /// Tracks, inspects, and blocks peers.
        pub fn oracle(network: *Self) Oracle {
            return .{ .tracker = &network.tracker };
        }

        /// Listens, dials, and serves connections until canceled. Receivers then drain and
        /// report `NetworkClosed`, and senders report `closed`.
        pub fn run(network: *Self) !void {
            const io = network.io;
            defer network.shutdown();
            const listener = try network.transport.bind(network.config.listen);
            defer listener.deinit();
            defer network.tasks.cancel(io);
            try network.tasks.concurrent(io, Tracker.run_unblock, .{&network.tracker});
            try network.tasks.concurrent(io, listen_loop, .{ network, listener });
            try network.tasks.concurrent(io, dial_loop, .{network});
            try network.tasks.await(io);
        }

        fn shutdown(network: *Self) void {
            network.tracker.close();
            network.router.close();
            for (network.channels.entries()) |entry| entry.value.queue.close();
        }

        fn now_time(io: Io) SystemTime {
            return SystemTime.from_timestamp(Io.Clock.real.now(io));
        }

        fn deadline_at(time: SystemTime) Io.Clock.Timestamp {
            const raw: Io.Timestamp = .fromNanoseconds(@intCast(time.nanos_since_epoch));
            return .{ .raw = raw, .clock = .real };
        }

        /// Accepts connections and starts a handshake for each one within the limits.
        fn listen_loop(network: *Self, listener: *Transport.Listener) Io.Cancelable!void {
            const config = &network.config;
            var per_ip: IpLimiter =
                .init(network.gpa, network.io, config.allowed_handshake_rate_per_ip);
            defer per_ip.deinit();
            var per_subnet: IpLimiter =
                .init(network.gpa, network.io, config.allowed_handshake_rate_per_subnet);
            defer per_subnet.deinit();
            var accepted_count: u32 = 0;
            var failures: u32 = 0;
            while (failures < accept_failures_max) {
                var accepted = listener.accept() catch |err| {
                    if (err == error.Canceled) return error.Canceled;
                    failures += 1;
                    continue;
                };
                failures = 0;
                if (accepted_count > cleanup_interval) {
                    per_ip.retain_recent();
                    per_subnet.retain_recent();
                    accepted_count = 0;
                }
                accepted_count += 1;
                if (!network.admit(&per_ip, &per_subnet, accepted.address)) {
                    accepted.deinit();
                    continue;
                }
                const in_flight = network.handshakes.fetchAdd(1, .monotonic);
                if (in_flight >= config.max_concurrent_handshakes) {
                    _ = network.handshakes.fetchSub(1, .monotonic);
                    accepted.deinit();
                    continue;
                }
                network.tasks.concurrent(network.io, handshake, .{ network, accepted }) catch {
                    _ = network.handshakes.fetchSub(1, .monotonic);
                    accepted.deinit();
                };
            }
        }

        /// Whether an inbound connection from `address` passes the IP policy and both rate
        /// limits (each limit is charged even when the other rejects).
        fn admit(
            network: *Self,
            per_ip: *IpLimiter,
            per_subnet: *IpLimiter,
            address: IpAddress,
        ) bool {
            const ip = to_ip(address);
            if (!network.config.allow_private_ips and !utils.net.is_global(ip)) return false;
            const ip_limited = (per_ip.check_key(ip) catch return false) != null;
            const mask = utils.net.SubnetMask.init(subnet_ipv4_bits, subnet_ipv6_bits);
            const subnet = utils.net.subnet(ip, mask).addr;
            const subnet_limited = (per_subnet.check_key(subnet) catch return false) != null;
            return !ip_limited and !subnet_limited;
        }

        /// Admits only peers the tracker accepts, before the handshake completes.
        const Bouncer = struct {
            tracker: *Tracker,

            pub fn admit(bouncer: Bouncer, peer: P) Io.Cancelable!bool {
                return bouncer.tracker.acceptable(peer);
            }
        };

        fn handshake(network: *Self, accepted: Transport.Accepted) Io.Cancelable!void {
            defer _ = network.handshakes.fetchSub(1, .monotonic);
            const bouncer: Bouncer = .{ .tracker = &network.tracker };
            var upgraded = network.upgrader.listen(
                network.gpa,
                network.io,
                network.stream_namespace,
                network.max_frame_size,
                bouncer,
                accepted.stream,
                accepted.sink,
            ) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                return;
            };
            const metadata = network.tracker.listen(upgraded.peer) orelse {
                upgraded.deinit(network.gpa);
                return;
            };
            return network.serve(upgraded.peer, &upgraded.connection, metadata);
        }

        /// Runs an authenticated connection to `peer` under its reservation, then releases
        /// both (commonware's spawner).
        fn serve(
            network: *Self,
            peer: P,
            connection: *Upgraded,
            metadata: Metadata,
        ) Io.Cancelable!void {
            const gpa = network.gpa;
            var outbox = Outbox.init(gpa, network.io, @intCast(network.config.mailbox_size));
            var result: Io.Cancelable!void = {};
            if (network.tracker.connect(peer, &outbox, metadata == .dialer)) |greeting| {
                if (network.router.ready(peer, &outbox) catch false) {
                    Peer.run(
                        gpa,
                        network.io,
                        &network.peer_config,
                        peer,
                        greeting,
                        &connection.sender,
                        &connection.receiver,
                        &outbox,
                        &network.tracker,
                        &network.channels,
                    ) catch |err| {
                        if (err == error.Canceled) result = error.Canceled;
                    };
                    network.router.release(peer, &outbox);
                }
            }
            // Nothing references the outbox once the router and tracker release it.
            outbox.kill();
            network.tracker.release(metadata);
            outbox.deinit();
            connection.deinit(gpa);
            return result;
        }

        /// Dials one dialable peer every `dial_frequency`, refreshing the shuffled queue from
        /// the tracker when it runs out.
        fn dial_loop(network: *Self) Io.Cancelable!void {
            const gpa = network.gpa;
            const io = network.io;
            var queue: std.ArrayList(P) = .empty;
            defer queue.deinit(gpa);
            var deadline = now_time(io);
            while (true) {
                try deadline_at(deadline).wait(io);
                const now = now_time(io);
                var next_query_at: ?SystemTime = null;
                if (queue.items.len == 0) {
                    if (network.tracker.dialable(gpa)) |dialable| {
                        queue.deinit(gpa);
                        queue = .fromOwnedSlice(dialable.peers);
                        shuffle.shuffle(P, queue.items, IoRng{ .io = io });
                        next_query_at = dialable.next_query_at;
                    } else |_| {}
                }
                const empty = queue.items.len == 0;
                deadline = next_deadline(&network.config, now, empty, next_query_at);
                while (queue.pop()) |peer| {
                    const metadata = network.tracker.dial(peer) orelse continue;
                    network.tasks.concurrent(io, dial_peer, .{ network, metadata }) catch
                        network.tracker.release(metadata);
                    break;
                }
            }
        }

        /// With peers queued, dial again after `dial_frequency`; otherwise ask the tracker
        /// again when it expects a peer to become dialable, within `[dial_frequency,
        /// max(dial_frequency, peer_connection_cooldown)]`.
        fn next_deadline(
            config: *const Config,
            now: SystemTime,
            empty: bool,
            next_query_at: ?SystemTime,
        ) SystemTime {
            const min = now.saturating_add(config.dial_frequency);
            if (!empty) return min;
            const cooled = now.saturating_add(config.peer_connection_cooldown);
            const max = if (cooled.order(min) == .lt) min else cooled;
            const target = next_query_at orelse max;
            if (target.order(min) == .lt) return min;
            if (target.order(max) == .gt) return max;
            return target;
        }

        fn dial_peer(network: *Self, metadata: Metadata) Io.Cancelable!void {
            const target = metadata.dialer;
            const address = resolve(target.ingress, network.config.allow_private_ips) orelse {
                network.tracker.release(metadata);
                return;
            };
            const dialed = network.transport.dial(address) catch |err| {
                network.tracker.release(metadata);
                if (err == error.Canceled) return error.Canceled;
                return;
            };
            var upgraded = network.upgrader.dial(
                network.gpa,
                network.io,
                network.stream_namespace,
                network.max_frame_size,
                target.peer,
                dialed.stream,
                dialed.sink,
            ) catch |err| {
                network.tracker.release(metadata);
                if (err == error.Canceled) return error.Canceled;
                return;
            };
            return network.serve(target.peer, &upgraded, metadata);
        }
    };
}

/// The address to dial for `ingress`. DNS ingress needs a resolver, which the runtime does
/// not provide yet, so it is never dialed.
fn resolve(ingress: Ingress, allow_private_ips: bool) ?IpAddress {
    return switch (ingress) {
        .socket => |socket| {
            if (!allow_private_ips and !utils.net.is_global(socket.ip)) return null;
            return to_address(socket);
        },
        .dns => null,
    };
}

pub fn to_ip(address: IpAddress) codec.IpAddr {
    return switch (address) {
        .ip4 => |ip4| .{ .v4 = .{ .octets = ip4.bytes } },
        .ip6 => |ip6| .{ .v6 = .{ .octets = ip6.bytes } },
    };
}

pub fn to_address(socket: codec.SocketAddr) IpAddress {
    return switch (socket.ip) {
        .v4 => |v4| .{ .ip4 = .{ .bytes = v4.octets, .port = socket.port } },
        .v6 => |v6| .{ .ip6 = .{ .bytes = v6.octets, .port = socket.port } },
    };
}

test {
    _ = @import("network_test.zig");
}
