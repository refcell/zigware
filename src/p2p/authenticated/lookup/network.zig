//! A lookup network (commonware `lookup/network.rs` and the dialer, listener, and spawner
//! actors): dials tracked peers at their known addresses, accepts inbound peers from their
//! registered IPs, authenticates every connection with the stream upgrader, and runs each
//! connection as a `Peer`.
//!
//! commonware runs these as actors; here the dialer, listener, unblock timer, handshakes, and
//! connections are tasks in one group that `run` owns, and the tracker and router are locked
//! shared state (as in `discovery`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
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
const discovery_network = @import("../discovery/network.zig");
const config_mod = @import("config.zig");
const tracker_mod = @import("tracker.zig");
const peer_mod = @import("peer.zig");
const labels = @import("metrics.zig");

const Ingress = p2p_types.Ingress;
const SystemTime = utils.SystemTime;
const IpAddress = Io.net.IpAddress;
pub const to_ip = discovery_network.to_ip;
pub const to_address = discovery_network.to_address;

/// Suffix of stream authentication.
const stream_suffix = "_STREAM";
/// Handshake rate limits group IPv4 /24 and IPv6 /48 subnets.
const subnet_ipv4_bits = 24;
const subnet_ipv6_bits = 48;
/// Accepted connections between sweeps of idle rate-limiter entries.
const cleanup_interval: u32 = 16_384;
/// Consecutive accept failures after which the listener stops.
const accept_failures_max: u32 = 1024;

/// The listener's and dialer's counters (commonware `lookup/actors/{listener,dialer}.rs`),
/// under the network scope's `listener` and `dialer` children.
pub fn Counters(comptime P: type) type {
    return struct {
        const Self = @This();
        const PeerFamily = metrics.raw.Family(labels.Peer(P), metrics.raw.Counter);

        handshakes_blocked: metrics.Counter,
        handshakes_concurrent_rate_limited: metrics.Counter,
        handshakes_ip_rate_limited: metrics.Counter,
        handshakes_subnet_rate_limited: metrics.Counter,
        /// Dial attempts made to each peer.
        attempts: metrics.Registered(PeerFamily),

        pub fn init(scope: metrics.Scope) Allocator.Error!Self {
            const listener = scope.child("listener");
            var blocked = try listener.counter(
                "handshakes_blocked",
                "number of handshake attempts blocked because the IP was not registered",
            );
            errdefer blocked.deinit();
            var concurrent = try listener.counter(
                "handshake_concurrent_rate_limited",
                "number of handshake attempts dropped because maximum concurrent handshakes " ++
                    "was reached",
            );
            errdefer concurrent.deinit();
            var ip = try listener.counter(
                "handshake_ip_rate_limited",
                "number of handshake attempts dropped because an IP exceeded its rate limit",
            );
            errdefer ip.deinit();
            var subnet = try listener.counter(
                "handshake_subnet_rate_limited",
                "number of handshake attempts dropped because a subnet exceeded its rate limit",
            );
            errdefer subnet.deinit();
            const dialer = scope.child("dialer");
            const attempts_help = "The number of dial attempts made to each peer";
            const attempts =
                try dialer.family(labels.Peer(P), metrics.raw.Counter, "attempts", attempts_help);
            return .{
                .handshakes_blocked = blocked,
                .handshakes_concurrent_rate_limited = concurrent,
                .handshakes_ip_rate_limited = ip,
                .handshakes_subnet_rate_limited = subnet,
                .attempts = attempts,
            };
        }

        pub fn deinit(counters: *Self) void {
            counters.handshakes_blocked.deinit();
            counters.handshakes_concurrent_rate_limited.deinit();
            counters.handshakes_ip_rate_limited.deinit();
            counters.handshakes_subnet_rate_limited.deinit();
            counters.attempts.deinit();
            counters.* = undefined;
        }

        /// Counts a dial attempt; an attempt whose label cannot be allocated goes unrecorded.
        pub fn attempt(counters: *Self, peer: P) void {
            const counter = counters.attempts.metric().get_or_create(.{ .peer = peer }) catch
                return;
            counter.inc();
        }
    };
}

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
        /// The largest frame: a payload of `max_message_size` and its data overhead.
        max_frame_size: u32,
        router: Router,
        channels: Channels,
        tracker: Tracker,
        peer_config: Peer.Config,
        counters: Counters(P),
        families: Peer.Families,
        /// The dialer, listener, unblock timer, handshakes, and connections.
        tasks: Io.Group = .init,
        /// Inbound handshakes in flight.
        handshakes: std.atomic.Value(u32) = .init(0),

        /// Creates a network; register channels, then `run` it. Metrics register under `scope`
        /// (commonware's network context, such as `context.child("network")`). Panics when the
        /// payload limit exceeds the stream limit.
        pub fn create(
            gpa: Allocator,
            io: Io,
            transport: *Transport,
            scope: metrics.Scope,
            config: Config,
        ) !*Self {
            if (config.max_message_size > data.max_size(U.max_size)) {
                @panic("maximum message size exceeds stream limit");
            }
            const max_frame_size = std.math.add(
                u32,
                config.max_message_size,
                data.max_payload_overhead,
            ) catch @panic("maximum frame size overflow");
            const network = try gpa.create(Self);
            errdefer gpa.destroy(network);
            const stream_namespace =
                try std.mem.concat(gpa, u8, &.{ config.namespace, stream_suffix });
            errdefer gpa.free(stream_namespace);
            const timeout_ns: i96 = @intCast(config.handshake_timeout.as_nanos());
            network.* = .{
                .gpa = gpa,
                .io = io,
                .transport = transport,
                .config = config,
                .upgrader = .init(config.upgrader, .{ .nanoseconds = timeout_ns }),
                .stream_namespace = stream_namespace,
                .max_frame_size = max_frame_size,
                .router = undefined,
                .channels = undefined,
                .tracker = undefined,
                .peer_config = .{
                    .ping_frequency = config.ping_frequency,
                    .send_batch_size = config.send_batch_size,
                    .max_message_size = config.max_message_size,
                },
                .counters = try .init(scope),
                .families = undefined,
            };
            errdefer network.counters.deinit();
            network.families = try .init(scope);
            errdefer network.families.deinit();
            network.router = try Router.init(gpa, io);
            errdefer network.router.deinit();
            const tracker_scope = scope.child("tracker");
            network.tracker = try Tracker.init(gpa, io, &tracker_scope, network.tracker_config());
            errdefer network.tracker.deinit();
            const sets = config.tracked_peer_sets;
            const max_peers = sizing.max_retained_peers(config.max_peers_per_set, sets, 0);
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
            network.counters.deinit();
            network.families.deinit();
            gpa.free(network.stream_namespace);
            gpa.destroy(network);
        }

        fn tracker_config(network: *const Self) Tracker.Config {
            const config = &network.config;
            return .{
                .public_key = config.upgrader.public_key(),
                .max_peers_per_set = config.max_peers_per_set,
                .tracked_peer_sets = config.tracked_peer_sets,
                .peer_connection_cooldown = config.peer_connection_cooldown,
                .allow_private_ips = config.allow_private_ips,
                .allow_dns = config.allow_dns,
                .bypass_ip_check = config.bypass_ip_check,
                .block_duration = config.block_duration,
            };
        }

        /// Registers `channel` with a per-peer `quota` (commonware `Network::register`); call
        /// before `run`. Panics on a duplicate channel.
        pub fn register(network: *Self, channel: p2p.Channel, quota: rate_limit.Quota) !Registered {
            return network.channels.register(channel, quota);
        }

        /// Tracks peers with their addresses, inspects, and blocks them.
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

        /// Accepts connections and starts a handshake for each one from a registered IP
        /// within the limits.
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
                const ip = to_ip(accepted.address);
                if (!network.registered(ip)) {
                    network.counters.handshakes_blocked.metric().inc();
                    accepted.deinit();
                    continue;
                }
                if (accepted_count > cleanup_interval) {
                    per_ip.retain_recent();
                    per_subnet.retain_recent();
                    accepted_count = 0;
                }
                accepted_count += 1;
                if (!network.admit(&per_ip, &per_subnet, ip)) {
                    accepted.deinit();
                    continue;
                }
                const in_flight = network.handshakes.fetchAdd(1, .monotonic);
                if (in_flight >= config.max_concurrent_handshakes) {
                    _ = network.handshakes.fetchSub(1, .monotonic);
                    network.counters.handshakes_concurrent_rate_limited.metric().inc();
                    accepted.deinit();
                    continue;
                }
                network.tasks.concurrent(network.io, handshake, .{ network, accepted }) catch {
                    _ = network.handshakes.fetchSub(1, .monotonic);
                    accepted.deinit();
                };
            }
        }

        /// Whether the listener takes a connection from `ip`: a global IP (or private ones
        /// allowed) that a tracked peer uses, unless the IP check is bypassed.
        fn registered(network: *Self, ip: codec.IpAddr) bool {
            const config = &network.config;
            if (!config.allow_private_ips and !utils.net.is_global(ip)) return false;
            return config.bypass_ip_check or network.tracker.registered(ip);
        }

        /// Whether an inbound connection from `ip` passes both rate limits (each limit is
        /// charged even when the other rejects).
        fn admit(
            network: *Self,
            per_ip: *IpLimiter,
            per_subnet: *IpLimiter,
            ip: codec.IpAddr,
        ) bool {
            const ip_limited = (per_ip.check_key(ip) catch return false) != null;
            if (ip_limited) network.counters.handshakes_ip_rate_limited.metric().inc();
            const mask = utils.net.SubnetMask.init(subnet_ipv4_bits, subnet_ipv6_bits);
            const subnet = utils.net.subnet(ip, mask).addr;
            const subnet_limited = (per_subnet.check_key(subnet) catch return false) != null;
            if (subnet_limited) network.counters.handshakes_subnet_rate_limited.metric().inc();
            return !ip_limited and !subnet_limited;
        }

        /// Admits only peers the tracker accepts from the connection's IP, before the
        /// handshake completes.
        const Bouncer = struct {
            tracker: *Tracker,
            source_ip: codec.IpAddr,

            pub fn admit(bouncer: Bouncer, peer: P) Io.Cancelable!bool {
                return bouncer.tracker.acceptable(peer, bouncer.source_ip);
            }
        };

        fn handshake(network: *Self, accepted: Transport.Accepted) Io.Cancelable!void {
            defer _ = network.handshakes.fetchSub(1, .monotonic);
            const source_ip = to_ip(accepted.address);
            const bouncer: Bouncer = .{ .tracker = &network.tracker, .source_ip = source_ip };
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
            const metadata = network.tracker.listen(upgraded.peer, source_ip) orelse {
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
            if (network.tracker.connect(peer, &outbox)) {
                if (network.router.ready(peer, &outbox) catch false) {
                    Peer.run(
                        gpa,
                        network.io,
                        &network.peer_config,
                        &network.families,
                        peer,
                        &connection.sender,
                        &connection.receiver,
                        &outbox,
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
                    const reserved = network.tracker.dial(peer) orelse continue;
                    network.counters.attempt(peer);
                    network.tasks.concurrent(io, dial_peer, .{ network, reserved }) catch
                        network.tracker.release(reserved.metadata);
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

        fn dial_peer(network: *Self, reserved: Tracker.Dial) Io.Cancelable!void {
            const peer = reserved.metadata.public_key();
            const allow_private_ips = network.config.allow_private_ips;
            const address = resolve(reserved.ingress, allow_private_ips) orelse {
                network.tracker.release(reserved.metadata);
                return;
            };
            const dialed = network.transport.dial(address) catch |err| {
                network.tracker.release(reserved.metadata);
                if (err == error.Canceled) return error.Canceled;
                return;
            };
            var upgraded = network.upgrader.dial(
                network.gpa,
                network.io,
                network.stream_namespace,
                network.max_frame_size,
                peer,
                dialed.stream,
                dialed.sink,
            ) catch |err| {
                network.tracker.release(reserved.metadata);
                if (err == error.Canceled) return error.Canceled;
                return;
            };
            return network.serve(peer, &upgraded, reserved.metadata);
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

test {
    _ = @import("network_test.zig");
    _ = @import("network_oracle_test.zig");
    _ = @import("network_lifecycle_test.zig");
    _ = @import("network_address_test.zig");
    _ = @import("network_handshake_test.zig");
}
