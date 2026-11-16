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

const Channel = p2p.Channel;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Outbox = outbox_mod.Outbox;
const Frame = outbox_mod.Frame;

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
        };

        /// Inbound throttle and queue of one channel for this connection.
        const Route = struct { channel: Channel, throttle: Throttle, queue: *Channels.Queue };

        /// Runs the connection until either side ends it; `sender` and `receiver` are the
        /// halves of an authenticated stream connection.
        pub fn run(
            gpa: Allocator,
            io: Io,
            config: *const Config,
            peer: P,
            greeting: Info,
            sender: anytype,
            receiver: anytype,
            outbox: *Outbox,
            tracker: *Tracker,
            channels: *const Channels,
        ) anyerror!void {
            assert(config.send_batch_size > 0);
            const Loops = Halves(@TypeOf(sender), @TypeOf(receiver));
            const Outcome = union(enum) { send: anyerror!void, recv: anyerror!void };
            var buffer: [2]Outcome = undefined;
            var select: Io.Select(Outcome) = .init(io, &buffer);
            defer while (select.cancel()) |_| {};
            try select.concurrent(.send, Loops.send_loop, .{
                gpa, io, config, peer, greeting, sender, outbox, tracker,
            });
            try select.concurrent(.recv, Loops.recv_loop, .{
                gpa, io, config, peer, receiver, tracker, channels,
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

        /// The send and receive tasks for stream halves of types `S` and `R`.
        fn Halves(comptime S: type, comptime R: type) type {
            return struct {
                /// Sends the greeting, then a bit vector every `gossip_bit_vec_frequency` and every
                /// queued frame (control before high before low), batched.
                fn send_loop(
                    gpa: Allocator,
                    io: Io,
                    config: *const Config,
                    peer: P,
                    greeting: Info,
                    sender: S,
                    outbox: *Outbox,
                    tracker: *Tracker,
                ) anyerror!void {
                    const encoded = try codec.encode(Payload, gpa, .{ .greeting = greeting });
                    defer gpa.free(encoded);
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
                        for (frames[0..count], parts[0..count]) |frame, *part| part.* = frame.bytes;
                        try sender.send_many(parts[0..count]);
                    }
                }

                /// Receives until an error: the greeting first, then data, bit vectors, and peers.
                fn recv_loop(
                    gpa: Allocator,
                    io: Io,
                    config: *const Config,
                    peer: P,
                    receiver: R,
                    tracker: *Tracker,
                    channels: *const Channels,
                ) anyerror!void {
                    const routes = try routes_init(gpa, io, channels);
                    defer routes_deinit(gpa, routes);
                    // Half the gossip frequency allows for jitter at message boundaries.
                    const half = @max(config.gossip_bit_vec_frequency.as_nanos() / 2, 1);
                    const quota = rate_limit.Quota.with_period(.from_nanos_saturating(half)).?;
                    var bit_vec_throttle: Throttle = .init(gpa, io, quota);
                    defer bit_vec_throttle.deinit();
                    var peers_throttle: Throttle = .init(gpa, io, quota);
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
                        var payload = try codec.decode_cfg(Payload, gpa, message, cfg);
                        defer payload.deinit(gpa);
                        if (payload == .greeting) {
                            if (greeted) return error.DuplicateGreeting;
                            greeted = true;
                            const info = &payload.greeting;
                            if (!info.public_key.eql(peer)) return error.GreetingMismatch;
                            try config.verifier.validate_info(now_time(io), info);
                            tracker.peers(&.{info.*});
                            continue;
                        }
                        if (!greeted) return error.MissingGreeting;
                        switch (payload) {
                            .greeting => unreachable, // Proof: handled above.
                            .data => |data| try deliver(gpa, routes, peer, data),
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

        fn routes_init(gpa: Allocator, io: Io, channels: *const Channels) ![]Route {
            const entries = channels.entries();
            const routes = try gpa.alloc(Route, entries.len);
            for (routes, entries) |*route, entry| {
                route.* = .{
                    .channel = entry.key,
                    .throttle = .init(gpa, io, entry.value.quota),
                    .queue = entry.value.queue,
                };
            }
            return routes;
        }

        fn routes_deinit(gpa: Allocator, routes: []Route) void {
            for (routes) |*route| route.throttle.deinit();
            gpa.free(routes);
        }

        /// Paces `data` by its channel's quota, then queues an owned copy for the receiver
        /// (dropped when the queue is full). An unregistered channel ends the connection.
        fn deliver(gpa: Allocator, routes: []Route, peer: P, data: types.Data) !void {
            for (routes) |*route| {
                if (route.channel != data.channel) continue;
                try route.throttle.receive(true);
                const payload = try gpa.dupe(u8, data.message);
                _ = route.queue.enqueue(.{ .peer = peer, .payload = payload, .gpa = gpa });
                return;
            }
            return error.InvalidChannel;
        }
    };
}
