//! The batcher actor's test harness (commonware `actors/batcher/mod.rs` test helpers): one
//! batcher on the deterministic runtime fed by test channels, with a recording blocker,
//! reporter, and relay. Generic over the scheme so tests run on every fixture.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const assert = std.debug.assert;
const actor = @import("actor");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const lookahead = @import("../../lookahead.zig");
const actor_mod = @import("actor.zig");
const voter_ingress = @import("../voter/ingress.zig");
const config_mod = @import("../../config.zig");

const Digest = cryptography.Sha256.Digest;
const Key = cryptography.ed25519.PublicKey;
const gpa = testing.allocator;
const Ed25519 = @import("../../scheme/ed25519.zig").Scheme(Digest);

/// The batcher test harness over scheme `S`, whose fixtures `make` builds
/// (`make(S, gpa, rng, namespace, n)`).
pub fn Kit(comptime S: type, comptime make: anytype) type {
    return struct {
        pub const ActivityType = types.Activity(S, Digest);
        const NetMessage = p2p.Message(Key);
        pub const VoterMessage = voter_ingress.Message(S, Digest);

        pub const Log = struct {
            blocked: std.ArrayList(Key) = .empty,
            reported: u32 = 0,
            /// Each reported activity's kind and view, in order.
            activities: std.ArrayList(Seen) = .empty,

            /// Each forward the relay was asked to send (commonware `MockRelay::broadcasts`).
            forwards: std.ArrayList(Forward) = .empty,

            const Seen = struct { tag: std.meta.Tag(ActivityType), view: u64 };
            pub const Forward = struct { digest: Digest, view: u64, peers: []Key };

            pub fn deinit(self: *Log) void {
                self.blocked.deinit(gpa);
                self.activities.deinit(gpa);
                for (self.forwards.items) |forward| gpa.free(forward.peers);
                self.forwards.deinit(gpa);
            }

            pub fn count(self: *const Log, tag: std.meta.Tag(ActivityType), view: u64) usize {
                var total: usize = 0;
                for (self.activities.items) |seen| {
                    total += @intFromBool(seen.tag == tag and seen.view == view);
                }
                return total;
            }
        };

        const Blocker = struct {
            log: *Log,
            pub const PublicKey = Key;
            pub fn block(self: Blocker, peer: Key) actor.Feedback {
                self.log.blocked.append(gpa, peer) catch @panic("out of memory");
                return .ok;
            }
        };

        const Reporter = struct {
            log: *Log,
            pub const Activity = ActivityType;
            pub fn report(self: Reporter, activity: ActivityType) actor.Feedback {
                self.log.reported += 1;
                const tag = std.meta.activeTag(activity);
                const seen: Log.Seen = .{ .tag = tag, .view = activity.view().get() };
                self.log.activities.append(gpa, seen) catch @panic("out of memory");
                return .ok;
            }
        };

        const Relay = struct {
            log: *Log,
            pub fn broadcast(
                self: Relay,
                digest: Digest,
                plan: lookahead.Plan(Key),
            ) actor.Feedback {
                const forward = switch (plan) {
                    .forward => |forward| forward,
                    .prepare, .propose => return .ok,
                };
                const peers = gpa.dupe(Key, forward.recipients.some) catch @panic("out of memory");
                const entry: Log.Forward = .{
                    .digest = digest,
                    .view = forward.round.view.get(),
                    .peers = peers,
                };
                self.log.forwards.append(gpa, entry) catch @panic("out of memory");
                return .ok;
            }
        };

        /// A network receiver fed by the test.
        pub const NetReceiver = struct {
            buffer: [16]NetMessage = undefined,
            queue: Io.Queue(NetMessage) = undefined,
            io: Io,

            pub fn init(self: *NetReceiver, io: Io) void {
                self.* = .{ .io = io };
                self.queue = .init(&self.buffer);
            }

            pub fn deliver(self: *NetReceiver, peer: Key, payload: []u8) !void {
                try self.queue.putOne(self.io, .{ .peer = peer, .payload = payload, .gpa = gpa });
            }

            pub fn recv(self: *NetReceiver) Io.Cancelable!?NetMessage {
                return self.queue.getOne(self.io) catch |err| switch (err) {
                    error.Canceled => error.Canceled,
                    error.Closed => null,
                };
            }
        };

        fn Params(
            comptime Sch: type,
            comptime D: type,
            comptime B: type,
            comptime Re: type,
            comptime Rl: type,
            comptime N: type,
        ) type {
            return struct {
                pub const Scheme = Sch;
                pub const Digest = D;
                pub const Blocker = B;
                pub const Reporter = Re;
                pub const Relay = Rl;
                pub const Strategy = parallel.Sequential;
                pub const Receiver = N;
            };
        }
        pub const P = Params(S, Digest, Blocker, Reporter, Relay, NetReceiver);
        pub const Batcher = actor_mod.Actor(P);

        pub fn config(scheme: *const S, log: *Log) actor_mod.Config(P) {
            return .{
                .scheme = scheme,
                .blocker = .{ .log = log },
                .reporter = .{ .log = log },
                .track_historical_votes = false,
                .relay = .{ .log = log },
                .strategy = parallel.sequential,
                .view_retention = .new(10),
                .skip = .disabled,
                .epoch = .new(0),
                .mailbox_size = 16,
                .lookahead = .{
                    .term_length = .new(utils.NonZero(u32).init(1).?),
                    .optimistic_views = .new(0),
                },
                .forward = .disabled,
                .floor = .zero(),
            };
        }

        /// One batcher (participant 0, of 4 by default) running against test channels.
        /// Must not move once started: the receivers' queues point into themselves.
        pub const Harness = struct {
            io: Io,
            fixture: cryptography.certificate.mocks.Fixture(S),
            /// Participant 0's member-only scheme, when `Options.member_only` is set.
            local: ?S = null,
            log: Log = .{},
            batcher: Batcher = undefined,
            mailbox: Batcher.Mailbox = undefined,
            voter: actor.mailbox.Receiver(VoterMessage) = undefined,
            votes: NetReceiver = undefined,
            certificates: NetReceiver = undefined,
            future: Io.Future(RunResult) = undefined,

            const RunResult = @typeInfo(@TypeOf(Batcher.run)).@"fn".return_type.?;

            pub fn start(self: *Harness, io: Io) !void {
                return self.start_scoped(io, null);
            }

            /// Starts with historical votes kept (commonware `track_historical_votes`).
            pub fn start_historical(self: *Harness, io: Io) !void {
                return self.start_with(io, null, .{ .track_historical_votes = true });
            }

            pub const Options = struct {
                track_historical_votes: bool = false,
                term_length: u32 = 1,
                optimistic_views: u64 = 0,
                participants: u32 = 4,
                /// Enables skipping with this timeout (commonware `SkipPolicy::Enabled`).
                skip_timeout_s: ?u64 = null,
                forward: config_mod.ForwardPolicy = .disabled,
                /// Participant 0 keeps its membership but cannot sign (commonware
                /// `Scheme::member`).
                member_only: bool = false,
                view_retention: u64 = 10,
                /// The view the batcher restores from (commonware `floor`).
                floor: u64 = 0,
            };

            /// Starts with the batcher's metrics registered under `scope`, if any.
            pub fn start_scoped(
                self: *Harness,
                io: Io,
                scope: ?runtime.telemetry.metrics.Scope,
            ) !void {
                return self.start_with(io, scope, .{});
            }

            pub fn start_with(
                self: *Harness,
                io: Io,
                scope: ?runtime.telemetry.metrics.Scope,
                options: Options,
            ) !void {
                var rng = utils.rng.test_rng();
                assert(options.participants >= 4);
                const n = options.participants;
                const fixture = try make(S, gpa, &rng, "batcher", n);
                self.* = .{ .io = io, .fixture = fixture };
                // Member-only setup builds an ed25519 committee; other schemes don't use it.
                if (comptime S != Ed25519) assert(!options.member_only);
                if (comptime S == Ed25519) if (options.member_only) {
                    const set = try fixture.schemes[0].participants().clone(gpa);
                    self.local = (try S.member(gpa, "batcher", set, fixture.participants[0])).?;
                };
                const scheme = if (self.local) |*local| local else &fixture.schemes[0];
                var cfg = config(scheme, &self.log);
                cfg.scope = scope;
                if (options.skip_timeout_s) |seconds| {
                    cfg.skip = .{ .enabled = .{ .timeout = .from_secs(seconds) } };
                }
                cfg.track_historical_votes = options.track_historical_votes;
                cfg.forward = options.forward;
                cfg.view_retention = .new(options.view_retention);
                cfg.floor = .new(options.floor);
                cfg.lookahead = .{
                    .term_length = .new(utils.NonZero(u32).init(options.term_length).?),
                    .optimistic_views = .new(options.optimistic_views),
                };
                self.batcher, self.mailbox = try Batcher.init(gpa, io, cfg);
                const voter = try actor.mailbox.new(VoterMessage, gpa, io, 16);
                self.voter = voter.receiver;
                self.votes.init(io);
                self.certificates.init(io);
                const voter_mailbox: voter_ingress.Mailbox(S, Digest) = .{ .sender = voter.sender };
                self.future = try io.concurrent(Batcher.run, .{
                    &self.batcher, voter_mailbox, &self.votes, &self.certificates,
                });
            }

            pub fn stop(self: *Harness) void {
                _ = self.future.cancel(self.io) catch {};
                self.voter.deinit();
                self.mailbox.deinit();
                self.batcher.deinit();
                self.log.deinit();
                if (self.local) |*local| local.deinit(gpa);
                self.fixture.deinit(gpa);
            }

            /// Receives voter messages until a verified certificate arrives.
            pub fn next_certificate(self: *Harness) !VoterMessage {
                for (0..8) |_| {
                    const message = (try self.voter.recv()) orelse return error.Closed;
                    if (message == .verified) return message;
                }
                return error.NoCertificate;
            }
        };
    };
}
