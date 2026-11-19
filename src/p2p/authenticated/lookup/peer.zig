//! One authenticated lookup connection (commonware `lookup/actors/peer/actor.rs` and
//! `authenticated/connection.rs`): a sender task that pings every `ping_frequency` and batches
//! queued frames, and a receiver task that delivers data to channels and paces the peer's
//! pings. The connection ends when either task does.

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
const labels = @import("metrics.zig");
const metrics = @import("runtime").telemetry.metrics;

const Channel = p2p.Channel;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Outbox = outbox_mod.Outbox;
const Frame = outbox_mod.Frame;
const Counter = metrics.raw.Counter;

pub const Error = error{
    /// The tracker or network ended the connection.
    Killed,
    InvalidChannel,
};

/// A ping on the wire.
const ping_bytes = [_]u8{types.ping_prefix};

pub fn Peer(comptime P: type) type {
    return struct {
        pub const Channels = channels_mod.Channels(P);
        pub const Label = labels.Message(P);
        pub const Family = metrics.raw.Family(Label, Counter);

        pub const Config = struct {
            /// How often we ping the peer.
            ping_frequency: Duration,
            /// Most frames (pings included) passed to one `send_many`.
            send_batch_size: usize,
            /// Largest application payload accepted.
            max_message_size: u32,
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
            sent_ping: *Counter,
            received_ping: *Counter,
            limited_ping: *Counter,
            invalid: *Counter,

            fn init(families: *Families, peer: P) Allocator.Error!Meters {
                const ping: Label = .new_ping(peer);
                return .{
                    .sent_ping = try families.sent.metric().get_or_create(ping),
                    .received_ping = try families.received.metric().get_or_create(ping),
                    .limited_ping = try families.rate_limited.metric().get_or_create(ping),
                    .invalid = try families.received.metric().get_or_create(.new_invalid(peer)),
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
            sender: anytype,
            receiver: anytype,
            outbox: *Outbox,
            channels: *const Channels,
        ) anyerror!void {
            assert(config.send_batch_size > 0);
            assert(config.ping_frequency.as_nanos() > 0);
            const meters = try Meters.init(families, peer);
            const routes = try routes_init(gpa, io, channels, families, peer);
            defer routes_deinit(gpa, routes);
            const Loops = Halves(@TypeOf(sender), @TypeOf(receiver));
            const Outcome = union(enum) { send: anyerror!void, recv: anyerror!void };
            var buffer: [2]Outcome = undefined;
            var select: Io.Select(Outcome) = .init(io, &buffer);
            defer while (select.cancel()) |_| {};
            try select.concurrent(.send, Loops.send_loop, .{
                gpa, io, config, &meters, routes, sender, outbox,
            });
            try select.concurrent(.recv, Loops.recv_loop, .{
                gpa, io, config, &meters, routes, peer, receiver,
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

        fn count_sent(routes: []const Route, frame: *const Frame) void {
            // Proof: the router queues only data frames, and senders exist only for
            // registered channels.
            const channel = frame.channel.?;
            for (routes) |route| {
                if (route.channel == channel) return route.sent.inc();
            }
            unreachable;
        }

        /// The send and receive tasks for stream halves of types `S` and `R`.
        fn Halves(comptime S: type, comptime R: type) type {
            return struct {
                /// Sends a ping every `ping_frequency` and every queued frame (high before
                /// low), batched.
                fn send_loop(
                    gpa: Allocator,
                    io: Io,
                    config: *const Config,
                    meters: *const Meters,
                    routes: []const Route,
                    sender: S,
                    outbox: *Outbox,
                ) anyerror!void {
                    const frames = try gpa.alloc(*Frame, config.send_batch_size);
                    defer gpa.free(frames);
                    const parts = try gpa.alloc([]const u8, config.send_batch_size);
                    defer gpa.free(parts);
                    var deadline = now_time(io).saturating_add(config.ping_frequency);
                    while (true) {
                        // A due ping leads the batch, then queued frames fill it.
                        var pinged = false;
                        var count: usize = 0;
                        defer for (frames[0..count]) |frame| frame.release();
                        if (now_time(io).order(deadline) != .lt) {
                            pinged = true;
                            meters.sent_ping.inc();
                            deadline = now_time(io).saturating_add(config.ping_frequency);
                        } else {
                            frames[0] = switch (try outbox.next(deadline_at(deadline))) {
                                .killed => return error.Killed,
                                .deadline => continue,
                                .frame => |frame| frame,
                            };
                            count = 1;
                        }
                        const room = config.send_batch_size - @intFromBool(pinged);
                        while (count < room) {
                            switch (outbox.try_next() orelse break) {
                                .killed => return error.Killed,
                                .deadline => unreachable, // Proof: try_next never waits.
                                .frame => |frame| frames[count] = frame,
                            }
                            count += 1;
                        }
                        const offset = @intFromBool(pinged);
                        if (pinged) parts[0] = &ping_bytes;
                        for (frames[0..count], parts[offset..][0..count]) |frame, *part| {
                            count_sent(routes, frame);
                            part.* = frame.bytes;
                        }
                        try sender.send_many(parts[0 .. offset + count]);
                    }
                }

                /// Receives until an error: data goes to its channel, and pings are paced
                /// to two per `ping_frequency`.
                fn recv_loop(
                    gpa: Allocator,
                    io: Io,
                    config: *const Config,
                    meters: *const Meters,
                    routes: []Route,
                    peer: P,
                    receiver: R,
                ) anyerror!void {
                    // Half the ping frequency allows for jitter at message boundaries.
                    const half = @max(config.ping_frequency.as_nanos() / 2, 1);
                    const quota = rate_limit.Quota.with_period(.from_nanos_saturating(half)).?;
                    var ping_throttle: Throttle =
                        .init(gpa, io, quota, meters.received_ping, meters.limited_ping);
                    defer ping_throttle.deinit();
                    const max_data_length: usize = config.max_message_size;
                    while (true) {
                        const bytes = try receiver.recv();
                        // The message borrows `bytes`; `deliver` copies data out.
                        const message =
                            codec.decode_cfg(types.Message, gpa, bytes, max_data_length) catch |err|
                                {
                                    meters.invalid.inc();
                                    return err;
                                };
                        switch (message) {
                            .data => |data| try deliver(gpa, meters, routes, peer, data),
                            .ping => try ping_throttle.receive(true),
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
        fn deliver(
            gpa: Allocator,
            meters: *const Meters,
            routes: []Route,
            peer: P,
            data: @FieldType(types.Message, "data"),
        ) !void {
            for (routes) |*route| {
                if (route.channel != data.channel) continue;
                try route.throttle.receive(true);
                const payload = try gpa.dupe(u8, data.message);
                _ = route.queue.enqueue(.{ .peer = peer, .payload = payload, .gpa = gpa });
                return;
            }
            meters.invalid.inc();
            return error.InvalidChannel;
        }
    };
}

test {
    _ = @import("peer_test.zig");
}
