//! One authenticated discovery connection (commonware `discovery/actors/peer/actor.rs` and
//! `authenticated/connection.rs`): a sender task that sends our greeting, then pings and
//! batches queued frames, and a receiver task that checks the peer's greeting, delivers data
//! to channels, and hands gossip to the tracker. The connection ends when either task does.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const p2p = @import("../../root.zig");
const rate_limit = @import("../../rate_limit.zig");
const outbox_mod = @import("../outbox.zig");
const Throttle = @import("../throttle.zig").Throttle;
const channels_mod = @import("../channels.zig");
const types = @import("types.zig");
const tracker_mod = @import("tracker.zig");
const labels = @import("metrics.zig");
const metrics = @import("runtime").telemetry.metrics;
const traces = @import("runtime").telemetry.traces;

const Channel = p2p.Channel;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Outbox = outbox_mod.Outbox;
const Frame = outbox_mod.Frame;
const Counter = metrics.raw.Counter;

pub const Error = error{
    /// The tracker or network ended the connection.
    Killed,
    MissingGreeting,
    DuplicateGreeting,
    GreetingMismatch,
    InvalidChannel,
} || types.Error;

pub fn Peer(comptime P: type) type {
    return struct {
        pub const Tracker = tracker_mod.Tracker(P);
        pub const Channels = channels_mod.Channels(P);
        pub const Info = types.Info(P);
        const Payload = types.Payload(P);
        pub const Label = labels.Message(P);
        pub const Family = metrics.raw.Family(Label, Counter);

        pub const Config = struct {
            /// How often we send a bit vector (also the keep-alive ping).
            gossip_bit_vec_frequency: Duration,
            /// Most queued frames passed to one `send_many`.
            send_batch_size: usize,
            /// Largest application payload accepted.
            max_message_size: u32,
            /// Most bits in a received bit vector.
            max_bit_vec: u64,
            /// Most entries in a received peer list.
            max_peers: usize,
            verifier: types.InfoVerifier(P),
            /// Under commonware's `actors::peer::actor` target.
            tracer: traces.Tracer = .none,
        };

        /// The message counters of every connection (commonware's spawner metrics), under the
        /// network scope's `spawner` child.
        pub const Families = struct {
            sent: metrics.Registered(Family),
            received: metrics.Registered(Family),
            rate_limited: metrics.Registered(Family),

            pub fn init(scope: metrics.Scope) Allocator.Error!Families {
                const spawner = scope.child("spawner");
                var sent = try spawner.family(Label, Counter, "messages_sent", "messages sent");
                errdefer sent.deinit();
                const received_help = "messages received";
                var received =
                    try spawner.family(Label, Counter, "messages_received", received_help);
                errdefer received.deinit();
                const limited_help = "messages rate limited";
                const rate_limited =
                    try spawner.family(Label, Counter, "messages_rate_limited", limited_help);
                return .{ .sent = sent, .received = received, .rate_limited = rate_limited };
            }

            pub fn deinit(families: *Families) void {
                families.sent.deinit();
                families.received.deinit();
                families.rate_limited.deinit();
                families.* = undefined;
            }
        };

        /// One connection's series. Message series are never removed, so the pointers stay
        /// valid while the families live (commonware's `get_or_create_owned`).
        const Meters = struct {
            sent_greeting: *Counter,
            sent_bit_vec: *Counter,
            sent_peers: *Counter,
            received_greeting: *Counter,
            invalid: *Counter,
            received_bit_vec: *Counter,
            limited_bit_vec: *Counter,
            received_peers: *Counter,
            limited_peers: *Counter,

            fn init(families: *Families, peer: P) Allocator.Error!Meters {
                const sent = families.sent.metric();
                const received = families.received.metric();
                const limited = families.rate_limited.metric();
                return .{
                    .sent_greeting = try sent.get_or_create(.new_greeting(peer)),
                    .sent_bit_vec = try sent.get_or_create(.new_bit_vec(peer)),
                    .sent_peers = try sent.get_or_create(.new_peers(peer)),
                    .invalid = try received.get_or_create(.new_invalid(peer)),
                    .received_greeting = try received.get_or_create(.new_greeting(peer)),
                    .received_bit_vec = try received.get_or_create(.new_bit_vec(peer)),
                    .limited_bit_vec = try limited.get_or_create(.new_bit_vec(peer)),
                    .received_peers = try received.get_or_create(.new_peers(peer)),
                    .limited_peers = try limited.get_or_create(.new_peers(peer)),
                };
            }
        };

        /// Inbound throttle and queue, and the sent counter, of one channel for this
        /// connection. The send task reads only `channel` and `sent`.
        const Route = struct {
            channel: Channel,
            throttle: Throttle,
            queue: *Channels.Queue,
            sent: *Counter,
        };

        /// Runs the connection until either side ends it; `sender` and `receiver` are the
        /// halves of an authenticated stream connection.
        pub fn run(
            gpa: Allocator,
            io: Io,
            config: *const Config,
            families: *Families,
            peer: P,
            greeting: Info,
            sender: anytype,
            receiver: anytype,
            outbox: *Outbox,
            tracker: *Tracker,
            channels: *const Channels,
        ) anyerror!void {
            assert(config.send_batch_size > 0);
            const meters = try Meters.init(families, peer);
            const routes = try routes_init(gpa, io, channels, families, peer);
            defer routes_deinit(gpa, routes);
            const Loops = Halves(@TypeOf(sender), @TypeOf(receiver));
            const Outcome = union(enum) { send: anyerror!void, recv: anyerror!void };
            var buffer: [2]Outcome = undefined;
            var select: Io.Select(Outcome) = .init(io, &buffer);
            defer while (select.cancel()) |_| {};
            try select.concurrent(.send, Loops.send_loop, .{
                gpa, io, config, &meters, routes, peer, greeting, sender, outbox, tracker,
            });
            try select.concurrent(.recv, Loops.recv_loop, .{
                gpa, io, config, &meters, routes, peer, receiver, tracker,
            });
            return switch (try select.await()) {
                inline else => |result| result,
            };
        }

        fn now_time(io: Io) SystemTime {
            return SystemTime.from_timestamp(Io.Clock.real.now(io));
        }

        fn deadline_at(time: SystemTime) Io.Clock.Timestamp {
            const raw: Io.Timestamp = .fromNanoseconds(@intCast(time.nanos_since_epoch));
            return .{ .raw = raw, .clock = .real };
        }

        /// Counts a frame as sent: data by its channel, gossip by its payload prefix.
        fn count_sent(meters: *const Meters, routes: []const Route, frame: *const Frame) void {
            assert(frame.bytes.len > 0);
            const channel = frame.channel orelse {
                switch (frame.bytes[0]) {
                    types.bit_vec_prefix => meters.sent_bit_vec.inc(),
                    types.peers_prefix => meters.sent_peers.inc(),
                    else => unreachable, // Proof: the tracker queues only gossip as control.
                }
                return;
            };
            for (routes) |route| {
                if (route.channel == channel) return route.sent.inc();
            }
            unreachable; // Proof: senders exist only for registered channels.
        }

        /// The send and receive tasks for stream halves of types `S` and `R`.
        fn Halves(comptime S: type, comptime R: type) type {
            return struct {
                /// Sends the greeting, then a bit vector every `gossip_bit_vec_frequency` and every
                /// queued frame (control before high before low), batched.
                fn send_loop(
                    gpa: Allocator,
                    io: Io,
                    config: *const Config,
                    meters: *const Meters,
                    routes: []const Route,
                    peer: P,
                    greeting: Info,
                    sender: S,
                    outbox: *Outbox,
                    tracker: *Tracker,
                ) anyerror!void {
                    const encoded = try codec.encode(Payload, gpa, .{ .greeting = greeting });
                    defer gpa.free(encoded);
                    meters.sent_greeting.inc();
                    try sender.send(encoded);
                    const frames = try gpa.alloc(*Frame, config.send_batch_size);
                    defer gpa.free(frames);
                    const parts = try gpa.alloc([]const u8, config.send_batch_size);
                    defer gpa.free(parts);
                    // Gossip starts immediately.
                    var deadline = now_time(io);
                    while (true) {
                        const now = now_time(io);
                        if (now.order(deadline) != .lt) {
                            tracker.construct(peer);
                            deadline = now.saturating_add(config.gossip_bit_vec_frequency);
                        }
                        const first = switch (try outbox.next(deadline_at(deadline))) {
                            .killed => return error.Killed,
                            .deadline => continue,
                            .frame => |frame| frame,
                        };
                        var count: usize = 1;
                        frames[0] = first;
                        defer for (frames[0..count]) |frame| frame.release();
                        while (count < frames.len) {
                            const next = outbox.try_next() orelse break;
                            switch (next) {
                                .killed => return error.Killed,
                                .deadline => unreachable, // Proof: try_next never waits.
                                .frame => |frame| frames[count] = frame,
                            }
                            count += 1;
                        }
                        for (frames[0..count], parts[0..count]) |frame, *part| {
                            count_sent(meters, routes, frame);
                            part.* = frame.bytes;
                        }
                        try sender.send_many(parts[0..count]);
                    }
                }

                /// Receives until an error: the greeting first, then data, bit vectors, and peers.
                fn recv_loop(
                    gpa: Allocator,
                    io: Io,
                    config: *const Config,
                    meters: *const Meters,
                    routes: []Route,
                    peer: P,
                    receiver: R,
                    tracker: *Tracker,
                ) anyerror!void {
                    // Half the gossip frequency allows for jitter at message boundaries.
                    const half = @max(config.gossip_bit_vec_frequency.as_nanos() / 2, 1);
                    const quota = rate_limit.Quota.with_period(.from_nanos_saturating(half)).?;
                    var bit_vec_throttle: Throttle =
                        .init(gpa, io, quota, meters.received_bit_vec, meters.limited_bit_vec);
                    defer bit_vec_throttle.deinit();
                    var peers_throttle: Throttle =
                        .init(gpa, io, quota, meters.received_peers, meters.limited_peers);
                    defer peers_throttle.deinit();
                    const cfg: types.PayloadConfig = .{
                        .max_bit_vec = config.max_bit_vec,
                        .max_peers = config.max_peers,
                        .max_data_length = config.max_message_size,
                    };
                    var greeted = false;
                    var first_bit_vec = true;
                    var first_peers = true;
                    while (true) {
                        const message = try receiver.recv();
                        const tracer = config.tracer;
                        var payload = codec.decode_cfg(Payload, gpa, message, cfg) catch |err| {
                            meters.invalid.inc();
                            const fields = .{ .err = err, .peer = peer };
                            tracer.event(.debug, "failed to decode message", fields);
                            return err;
                        };
                        defer payload.deinit(gpa);
                        if (payload == .greeting) {
                            meters.received_greeting.inc();
                            try greet(io, config, peer, tracker, greeted, &payload.greeting);
                            greeted = true;
                            continue;
                        }
                        if (!greeted) {
                            const message_missing = "expected greeting as first message";
                            tracer.event(.debug, message_missing, .{ .peer = peer });
                            return error.MissingGreeting;
                        }
                        switch (payload) {
                            .greeting => unreachable, // Proof: handled above.
                            .data => |data| try deliver(gpa, config, meters, routes, peer, data),
                            .bit_vec => |*bit_vec| {
                                // The first bit vector and peer list follow the greeting at once.
                                try bit_vec_throttle.receive(!first_bit_vec);
                                first_bit_vec = false;
                                tracker.bit_vec(peer, bit_vec);
                            },
                            .peers => |peers| {
                                try peers_throttle.receive(!first_peers);
                                first_peers = false;
                                try config.verifier.validate(now_time(io), peers);
                                tracker.peers(peers);
                            },
                        }
                    }
                }
            };
        }

        fn routes_init(
            gpa: Allocator,
            io: Io,
            channels: *const Channels,
            families: *Families,
            peer: P,
        ) ![]Route {
            const entries = channels.entries();
            const routes = try gpa.alloc(Route, entries.len);
            errdefer gpa.free(routes);
            var count: usize = 0;
            errdefer routes_deinit_some(routes[0..count]);
            for (routes, entries) |*route, entry| {
                const label: Label = .new_data(peer, entry.key);
                const received = try families.received.metric().get_or_create(label);
                const limited = try families.rate_limited.metric().get_or_create(label);
                const sent = try families.sent.metric().get_or_create(label);
                route.* = .{
                    .channel = entry.key,
                    .throttle = .init(gpa, io, entry.value.quota, received, limited),
                    .queue = entry.value.queue,
                    .sent = sent,
                };
                count += 1;
            }
            assert(count == entries.len);
            return routes;
        }

        fn routes_deinit_some(routes: []Route) void {
            for (routes) |*route| route.throttle.deinit();
        }

        fn routes_deinit(gpa: Allocator, routes: []Route) void {
            routes_deinit_some(routes);
            gpa.free(routes);
        }

        /// Paces `data` by its channel's quota, then queues an owned copy for the receiver
        /// (dropped when the queue is full). An unregistered channel counts as invalid and
        /// ends the connection.
        /// Checks the peer's greeting, which must come once and carry its own key, and adopts
        /// its info.
        fn greet(
            io: Io,
            config: *const Config,
            peer: P,
            tracker: *Tracker,
            greeted: bool,
            info: *const Info,
        ) !void {
            const tracer = config.tracer;
            if (greeted) {
                tracer.event(.debug, "received duplicate greeting", .{ .peer = peer });
                return error.DuplicateGreeting;
            }
            if (!info.public_key.eql(peer)) {
                tracer.event(.debug, "greeting public key mismatch", .{
                    .peer = peer,
                    .greeting_pk = info.public_key,
                });
                return error.GreetingMismatch;
            }
            try config.verifier.validate_info(now_time(io), info);
            tracker.peers(&.{info.*});
        }

        fn deliver(
            gpa: Allocator,
            config: *const Config,
            meters: *const Meters,
            routes: []Route,
            peer: P,
            data: types.Data,
        ) !void {
            for (routes) |*route| {
                if (route.channel != data.channel) continue;
                try route.throttle.receive(true);
                const payload = try gpa.dupe(u8, data.message);
                _ = route.queue.enqueue(.{ .peer = peer, .payload = payload, .gpa = gpa });
                return;
            }
            meters.invalid.inc();
            const fields = .{ .peer = peer, .channel = data.channel };
            config.tracer.event(.debug, "invalid channel", fields);
            return error.InvalidChannel;
        }
    };
}

test {
    _ = @import("peer_test.zig");
}
