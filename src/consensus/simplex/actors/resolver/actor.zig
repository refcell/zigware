//! The resolver actor (commonware `actors/resolver/actor.rs`): fetches missing certificates
//! from peers through the p2p resolver engine, serves its own, and hands what it recovers to
//! the voter.
//!
//! `P` declares `Scheme`, `Digest`, `Blocker` (a p2p blocker that also reports its blocked
//! set), `Strategy`, `NetSender`, and `NetReceiver` (the resolver channel). Commonware's
//! `select_loop!` over the mailbox and the handler becomes one `Inbox`. Events go to `tracer`
//! under commonware's target (spans are not ported); the engine's metrics go to the scope
//! `run` receives.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const p2p = @import("p2p");
const resolver = @import("resolver");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ask = @import("../ask.zig");
const context = @import("../context.zig");
const inbox_mod = @import("../inbox.zig");
const voter_ingress = @import("../voter/ingress.zig");
const ingress = @import("ingress.zig");
const state_mod = @import("state.zig");

const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const TermLength = consensus_types.TermLength;
const Duration = utils.Duration;
const Ask = ask.Ask;
const Key = ingress.Handler.Key;
const HandlerMessage = ingress.HandlerMessage;
const Effect = state_mod.Effect;
const oneshot = utils.channel.oneshot;
const Scope = runtime.telemetry.metrics.Scope;
const Tracer = runtime.telemetry.traces.Tracer;

/// The tracing target of the resolver's events (commonware's module path).
pub const trace_target = "commonware_consensus::simplex::actors::resolver";

pub fn Config(comptime P: type) type {
    return struct {
        scheme: *const P.Scheme,
        blocker: P.Blocker,
        strategy: P.Strategy,
        epoch: Epoch,
        mailbox_size: u32,
        fetch_timeout: Duration,
        fetch_retry_delay: Duration,
        term_length: TermLength,
    };
}

/// A peer provider with one fixed peer set (commonware `p2p::utils::StaticProvider`): its
/// subscription yields the set once, then stays open.
pub fn StaticProvider(comptime PublicKey: type) type {
    return struct {
        const Self = @This();

        io: Io,
        id: u64,
        /// Sorted and deduplicated; borrowed for the provider's lifetime.
        peers: []const PublicKey,

        pub const Update = struct {
            index: u64,
            peers: []const PublicKey,

            pub fn view(update: Update) p2p.PeerSetUpdate(PublicKey) {
                const Tracked = p2p.TrackedPeers(PublicKey);
                const tracked = Tracked.init_primary(.{ .items = update.peers });
                return .{ .index = update.index, .latest = tracked, .all = tracked };
            }

            pub fn deinit(update: *Update) void {
                update.* = undefined;
            }
        };

        pub const Subscription = struct {
            provider: Self,
            sent: bool = false,

            /// The peer set first, then waits until canceled.
            pub fn recv(subscription: *Subscription) Io.Cancelable!?Update {
                if (!subscription.sent) {
                    subscription.sent = true;
                    const provider = subscription.provider;
                    return .{ .index = provider.id, .peers = provider.peers };
                }
                // The set never changes: wait for cancelation.
                while (true) try subscription.provider.io.sleep(.fromSeconds(3600), .awake);
            }

            pub fn deinit(subscription: *Subscription) void {
                subscription.* = undefined;
            }
        };

        pub fn subscribe(self: Self) Allocator.Error!Subscription {
            assert(self.peers.len > 0);
            return .{ .provider = self };
        }
    };
}

pub fn Actor(comptime P: type) type {
    return struct {
        const Self = @This();
        const S = P.Scheme;
        const D = P.Digest;
        const State = state_mod.State(S, D);
        const Certificate = types.Certificate(S, D);
        pub const Message = ingress.Message(S, D);
        pub const Mailbox = ingress.Mailbox(S, D);
        const VoterMailbox = voter_ingress.Mailbox(S, D);
        const Provider = StaticProvider(S.PublicKey);
        const Engine = resolver.p2p.Engine(resolver.p2p.engine.Params(
            S.PublicKey,
            Provider,
            P.Blocker,
            ingress.Handler,
            ingress.Handler,
            P.NetSender,
            P.NetReceiver,
        ));
        const EngineMailbox = Engine.Mailbox;
        const Fetch = resolver.Fetch(Key, Ask);
        const Predicate = resolver.Predicate(Key, Ask);

        const Event = union(enum) {
            mailbox: Message,
            handler: HandlerMessage,
            closed,
        };

        fn release(event: Event) void {
            switch (event) {
                .mailbox => |message| Message.discard(message),
                .handler => |message| HandlerMessage.discard(message),
                .closed => {},
            }
        }

        const Inbox = inbox_mod.Inbox(Event, 64, release);

        gpa: Allocator,
        io: Io,
        scheme: *const S,
        blocker: P.Blocker,
        strategy: P.Strategy,
        epoch: Epoch,
        mailbox_size: u32,
        fetch_timeout: Duration,
        fetch_retry_delay: Duration,
        state: State,
        mailbox_receiver: actor.mailbox.Receiver(Message),
        /// Receives the resolver's events; the engine sets it from its context.
        tracer: Tracer = .none,

        pub fn init(gpa: Allocator, io: Io, cfg: Config(P)) !struct { Self, Mailbox } {
            assert(cfg.mailbox_size > 0);
            const pair = try actor.mailbox.new(Message, gpa, io, cfg.mailbox_size);
            const self: Self = .{
                .gpa = gpa,
                .io = io,
                .scheme = cfg.scheme,
                .blocker = cfg.blocker,
                .strategy = cfg.strategy,
                .epoch = cfg.epoch,
                .mailbox_size = cfg.mailbox_size,
                .fetch_timeout = cfg.fetch_timeout,
                .fetch_retry_delay = cfg.fetch_retry_delay,
                .state = .init(gpa, cfg.term_length),
                .mailbox_receiver = pair.receiver,
            };
            assert(self.state.replaying);
            return .{ self, .{ .sender = pair.sender } };
        }

        pub fn deinit(self: *Self) void {
            self.mailbox_receiver.deinit();
            self.state.deinit();
            self.* = undefined;
        }

        /// Runs until the mailbox closes or the task is canceled. Takes ownership of the voter
        /// mailbox and the resolver channel; engine metrics register under `scope`.
        pub fn run(
            self: *Self,
            scope: Scope,
            voter: VoterMailbox,
            sender: P.NetSender,
            receiver: P.NetReceiver,
        ) !void {
            var voter_mailbox = voter;
            defer voter_mailbox.deinit();
            const participants = self.scheme.participants();
            const me: ?S.PublicKey = if (self.scheme.me()) |membership|
                participants.key(membership.index()).?.*
            else
                null;
            // Every handler entry is one message the network admitted on the resolver
            // channel, so hold as many as the channel does.
            const handler_size = std.math.cast(u32, receiver.capacity()) orelse
                std.math.maxInt(u32);
            const gpa = self.gpa;
            var handler_pair = try actor.mailbox.new(HandlerMessage, gpa, self.io, handler_size);
            defer handler_pair.receiver.deinit();
            const handler: ingress.Handler = .{
                .gpa = self.gpa,
                .io = self.io,
                .sender = &handler_pair.sender,
            };
            const provider: Provider = .{
                .io = self.io,
                .id = self.epoch.get(),
                .peers = participants.items,
            };
            var spawned = try Engine.spawn(self.gpa, self.io, scope, .{
                .peer_provider = provider,
                .blocker = self.blocker,
                .consumer = handler,
                .producer = handler,
                .mailbox_size = self.mailbox_size,
                .me = me,
                .fetch_timeout = self.fetch_timeout,
                .fetch_retry_delay = self.fetch_retry_delay,
                .priority_requests = true,
                .priority_responses = false,
            }, sender, receiver);
            defer {
                spawned.mailbox.deinit();
                _ = spawned.future.cancel(self.io) catch {};
                // The engine is gone, so nothing holds the handler sender any more.
                handler_pair.sender.deinit();
            }
            var inbox: Inbox = undefined;
            inbox.init(self.io);
            defer inbox.shutdown();
            try inbox.forward(.mailbox, &self.mailbox_receiver);
            try inbox.forward(.handler, &handler_pair.receiver);
            // Runs for the actor's lifetime; each turn handles one message.
            while (true) {
                switch (try inbox.next()) {
                    .closed => return self.tracer.event(.debug, "mailbox closed, stopping", .{}),
                    .mailbox => |message| try self.handle_mailbox(spawned.mailbox, message),
                    .handler => |message| {
                        if (message.response_closed()) {
                            HandlerMessage.discard(message);
                            continue;
                        }
                        try self.handle_resolver(message, voter_mailbox, spawned.mailbox);
                    },
                }
            }
        }

        /// Applies one mailbox message (taking ownership). `engine` is the p2p engine's mailbox,
        /// or any resolver with the same `fetch`/`fetch_all`/`fetch_targeted`/`retain` (tests).
        pub fn handle_mailbox(self: *Self, engine: anytype, message: Message) !void {
            defer Message.discard(message);
            var effects: std.ArrayList(Effect) = .empty;
            defer effects.deinit(self.gpa);
            switch (message) {
                .updated => |updated| try self.state.updated(&updated.certificate, &effects),
                .certified => |certified| {
                    try self.state.certified(&certified.notarization, certified.success, &effects);
                },
                .resolve => |request| {
                    const proposal, const view = .{ request.proposal, request.view };
                    return self.resolve(engine, proposal, view, request.kind, request.target);
                },
                .replayed => try self.state.replayed(&effects),
            }
            try self.apply_effects(engine, effects.items);
        }

        /// Applies the state's effects to the resolver: retires first, then one fetch batch.
        /// Every retire predicate is monotonic, so issuing the batch last leaves the same asks
        /// open.
        pub fn apply_effects(self: *Self, engine: anytype, effects: []const Effect) !void {
            var fetches: std.ArrayList(Fetch) = .empty;
            defer fetches.deinit(self.gpa);
            for (effects) |effect| switch (effect) {
                .fetch => |missing| try fetches.append(self.gpa, self.fetch(missing.view)),
                .settled => |settled| _ = try engine.retain(.init(Settled{
                    .kind = settled.kind,
                    .start = settled.start.get(),
                    .end = settled.end.get(),
                }, Settled.keep)),
                .finalized => |view| _ = try engine.retain(.init(view.get(), keep_above)),
                .raised => |view| _ = try engine.retain(.init(view.get(), keep_raised)),
            };
            if (fetches.items.len > 0) _ = try engine.fetch_all(fetches.items);
        }

        const Settled = struct {
            kind: ask.Kind,
            start: u64,
            end: u64,

            fn keep(settled: Settled, key: Key, subscriber: Ask) bool {
                const view = key.get();
                if (subscriber.kind != settled.kind) return true;
                return view < settled.start or view > settled.end;
            }
        };

        fn keep_above(finalized: u64, key: Key, subscriber: Ask) bool {
            _ = subscriber;
            return key.get() > finalized;
        }

        /// Only background asks retire at the floor: a proposal may name ancestry below it.
        fn keep_raised(floor: u64, key: Key, subscriber: Ask) bool {
            return subscriber.until != .floor or key.get() > floor;
        }

        /// A background fetch for the nullification covering `view`.
        fn fetch(self: *const Self, view: View) Fetch {
            const subscriber = Ask.backfill();
            // State only emits a fetch for a gap unsettled at issuance.
            assert(!self.state.settled(view, subscriber.kind));
            return .{ .key = .init(view.get()), .subscriber = subscriber };
        }

        /// Fetches missing proposal ancestry, from `target` alone when given.
        fn resolve(
            self: *Self,
            engine: anytype,
            proposal: View,
            view: View,
            kind: ask.Kind,
            target: ?S.PublicKey,
        ) !void {
            if (view.get() >= proposal.get() or self.state.settled(view, kind)) return;
            const item: Fetch = .{ .key = .init(view.get()), .subscriber = Ask.ancestry(kind) };
            if (target) |peer| {
                _ = try engine.fetch_targeted(item, &.{peer});
            } else {
                _ = try engine.fetch(item);
            }
        }

        /// Decodes and verifies a response for `view`: any certificate an honest peer could
        /// serve for the view is valid, even one answering the other kind.
        pub fn validate(self: *Self, view: View, data: []const u8) !?Certificate {
            const cfg = self.scheme.certificate_codec_config();
            var incoming = codec.decode_cfg(Certificate, self.gpa, data, cfg) catch |err|
                switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return null,
                };
            errdefer incoming.deinit(self.gpa);
            const servable = switch (incoming) {
                .nullification => |*nullification| nullification.view().covers(
                    view,
                    self.state.term(),
                ),
                .notarization, .finalization => incoming.view().get() >= view.get(),
            };
            const received = incoming.view();
            if (!servable) {
                self.tracer.event(.debug, "certificate below requested view", .{
                    .view = view.get(),
                    .received = received.get(),
                });
                incoming.deinit(self.gpa);
                return null;
            }
            if (incoming.epoch() != self.epoch) {
                self.tracer.event(.debug, "rejecting certificate from different epoch", .{
                    .view = view.get(),
                    .epoch = incoming.epoch().get(),
                    .expected = self.epoch.get(),
                });
                incoming.deinit(self.gpa);
                return null;
            }
            var rng: context.IoRng = .{ .io = self.io };
            if (!try incoming.verify(self.gpa, &rng, self.scheme, self.strategy)) {
                const failed = "certificate failed verification";
                self.tracer.event(.debug, failed, .{ .view = view.get() });
                incoming.deinit(self.gpa);
                return null;
            }
            self.tracer.event(.debug, "received certificate for request", .{
                .view = view.get(),
                .received = received.get(),
            });
            return incoming;
        }

        fn settled_count(self: *const Self, view: View, asks: []const Ask) usize {
            var count: usize = 0;
            for (asks) |item| {
                if (self.state.settled(view, item.kind)) count += 1;
            }
            assert(count <= asks.len);
            return count;
        }

        /// Handles a message from the p2p engine (taking ownership).
        pub fn handle_resolver(
            self: *Self,
            message: HandlerMessage,
            voter: anytype,
            engine: anytype,
        ) !void {
            switch (message) {
                .deliver => |deliver| try self.handle_deliver(deliver, voter, engine),
                .produce => |produce| {
                    var response = produce.response;
                    const certificate = self.state.produce(produce.view) orelse {
                        // A dropped response answers the peer at once instead of a timeout.
                        return response.deinit();
                    };
                    const bytes = try self.gpa.dupe(u8, certificate);
                    response.send(.{ .bytes = bytes, .gpa = self.gpa }) catch self.gpa.free(bytes);
                },
            }
        }

        fn handle_deliver(
            self: *Self,
            deliver: @FieldType(HandlerMessage, "deliver"),
            voter: anytype,
            engine: anytype,
        ) !void {
            defer self.gpa.free(deliver.data);
            defer self.gpa.free(deliver.asks);
            var response = deliver.response;
            const view = deliver.view;
            // Ignoring is key-wide: only skip validation once every kind at the view settled.
            if (self.state.key_settled(view)) return response.send(.ignored) catch {};
            var parsed = try self.validate(view, deliver.data) orelse
                return response.send(.invalid) catch {};
            errdefer parsed.deinit(self.gpa);
            const asks = deliver.asks;
            const settled_before = self.settled_count(view, asks);
            // A failed notarization stays valid evidence but satisfies no repair ask.
            const obsolete = parsed == .notarization and
                self.state.uncertifiable(parsed.notarization.view());
            var effects: std.ArrayList(Effect) = .empty;
            defer effects.deinit(self.gpa);
            if (!obsolete) try self.state.updated(&parsed, &effects);
            if (settled_before == asks.len) {
                // Dropping the verdict retires this settled snapshot without scoring the peer.
                response.deinit();
            } else {
                const settled_after = self.settled_count(view, asks);
                const outcome: resolver.Outcome = if (settled_after == asks.len)
                    .{ .resolved = .complete }
                else if (settled_after > settled_before)
                    .{ .resolved = .partial }
                else
                    .unresolved;
                response.send(outcome) catch {};
            }
            try self.apply_effects(engine, effects.items);
            if (obsolete) return parsed.deinit(self.gpa);
            try voter.recovered(self.gpa, parsed);
        }
    };
}
