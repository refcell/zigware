//! The DKG probe actor (commonware `glue/src/dkg/probe/actor/{mod,service}.rs` and
//! `mailbox.rs`): drives `Discovery` from its mailbox, the boundary channel, and a retry
//! deadline, then serves boundary material to other joining peers.
//!
//! commonware's `select_loop!` over the mailbox, the network receiver, and the retry sleep is
//! one simplex `Inbox` fed by two pumps, popped with `next_until(deadline)` while a retry is
//! armed (as in `glue.stateful.probe`). Discovery runs until a source is attached and no
//! subscriber waits. The service phase then answers latest-finalization, boundary
//! finalization, and boundary block requests from the source, blocks peers that send an
//! invalid request, answers subscriptions with the artifact (or closes them without one), and
//! ignores later attachments.
//!
//! Contracts (comptime), declared by `Probe`'s parameter `P`:
//! - `Scheme`, `Variant`, `Manager`, `Blocker`: as for `Discovery`.
//! - `Source`: `latest_finalization(gpa)`, `get_finalization(gpa, height)`, and
//!   `get_block(gpa, height)`, each `!?T` owned by the caller, and optionally `deinit`.
//!   `MarshalSource` adapts marshal's mailbox.
//! - `NetSender`: `send(recipients, parts, priority) ![]PublicKey` (attempted, caller-owned);
//!   `NetReceiver`: `recv() !p2p.Message(PublicKey)`. Both optionally declare `deinit`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const consensus = @import("consensus");
const p2p = @import("p2p");
const utils = @import("utils");
const discovery_mod = @import("discovery.zig");
const wire = @import("wire.zig");

const oneshot = utils.channel.oneshot;
const inbox_mod = consensus.simplex.actors.inbox;
const Epoch = consensus.Epoch;
const Height = consensus.Height;

/// A message to the probe (commonware `probe::mailbox::Message`).
pub fn Request(comptime Artifact: type, comptime Source: type) type {
    return union(enum) {
        const Self = @This();

        /// A subscription to the artifact.
        subscribe: oneshot.Sender(Artifact),
        /// A source from which to serve peers; the probe owns it.
        attach: Source,

        pub const Overflow = std.Deque(Self);

        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            overflow.pushBack(gpa, message) catch |err| {
                discard(message);
                return err;
            };
        }

        pub fn discard(message: Self) void {
            switch (message) {
                .subscribe => |sender| {
                    var owned = sender;
                    owned.deinit();
                },
                .attach => |source| release(Source, source),
            }
        }
    };
}

fn release(comptime T: type, value: T) void {
    if (comptime @hasDecl(T, "deinit")) {
        var owned = value;
        owned.deinit();
    }
}

/// Handle to the probe's mailbox (commonware `probe::Mailbox`).
pub fn Mailbox(comptime Artifact: type, comptime Source: type) type {
    return struct {
        const Self = @This();
        pub const Message = Request(Artifact, Source);

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(Message),

        pub fn clone(self: Self) Self {
            return .{ .gpa = self.gpa, .io = self.io, .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        /// Subscribes to the artifact. The first live subscriber starts discovery; dropping
        /// the receiver cancels the subscription. If discovery already resolved, the receiver
        /// gets the cached artifact at once. If the probe stopped, or serves without an
        /// artifact, the receiver closes without a value.
        pub fn subscribe(self: Self) Allocator.Error!oneshot.Receiver(Artifact) {
            const pair = try oneshot.channel(Artifact, self.gpa, self.io);
            _ = self.sender.enqueue(.{ .subscribe = pair.sender }) catch |err| {
                var receiver = pair.receiver;
                receiver.deinit();
                return err;
            };
            return pair.receiver;
        }

        /// Attaches a source from which the probe serves peers' requests. With subscribers
        /// pending, service starts once they are resolved or dropped. A source node can attach
        /// without subscribing, so it serves without sending discovery requests.
        pub fn attach(self: Self, source: Source) Allocator.Error!void {
            _ = try self.sender.enqueue(.{ .attach = source });
        }
    };
}

/// The probe actor (commonware `probe::Actor`). `P` declares `Scheme`, `Variant`, `Manager`,
/// `Source`, `Blocker`, `NetSender`, and `NetReceiver` (see the contracts above).
pub fn Probe(comptime P: type) type {
    return struct {
        const Self = @This();
        const S = P.Scheme;
        const V = P.Variant;
        const Source = P.Source;
        const NetSender = P.NetSender;
        const NetReceiver = P.NetReceiver;
        pub const PublicKey = S.PublicKey;
        pub const Discovery = discovery_mod.Discovery(P);
        pub const Artifact = Discovery.Artifact;
        pub const Finalization = Discovery.Finalization;
        pub const ProbeMailbox = Mailbox(Artifact, Source);
        pub const Message = ProbeMailbox.Message;
        const NetMessage = p2p.Message(PublicKey);

        /// The mailbox pump's item: a request, or the end of the mailbox, after which the pump
        /// stops without closing the inbox.
        const MailboxItem = union(enum) { request: Message, drained };
        const Event = union(enum) {
            mailbox: MailboxItem,
            network: NetMessage,
            closed,
        };
        const Inbox = inbox_mod.Inbox(Event, 8, release_event);

        const MailboxPump = struct {
            receiver: actor.mailbox.Receiver(Message),
            drained: bool = false,

            pub fn recv(pump: *MailboxPump) Io.Cancelable!MailboxItem {
                if (pump.drained) return error.Canceled; // Ends the pump quietly.
                const message = try pump.receiver.recv() orelse {
                    pump.drained = true;
                    return .drained;
                };
                return .{ .request = message };
            }
        };

        /// The probe's configuration (commonware `probe::Config`, without the runtime context;
        /// `strategy` and the rng go to `run`).
        pub const Config = struct {
            discovery: Discovery.Config,
            /// How long to wait before another boundary responder or re-solicitation.
            retry_timeout_ns: u64,
            mailbox_size: u32,
        };

        gpa: Allocator,
        io: Io,
        discovery: Discovery,
        retry_timeout_ns: u64,
        mailbox: MailboxPump,
        net_sender: NetSender,
        net_receiver: NetReceiver,
        source: ?Source = null,
        inbox: Inbox = undefined,

        pub const Created = struct { probe: *Self, mailbox: ProbeMailbox };

        /// A probe on the boundary channel (`net_sender`, `net_receiver`), which it owns, and
        /// its mailbox. Start it with `run`; free it with `deinit` once `run` returned.
        pub fn init(
            gpa: Allocator,
            io: Io,
            config: Config,
            net_sender: NetSender,
            net_receiver: NetReceiver,
        ) !Created {
            assert(config.retry_timeout_ns > 0);
            assert(config.mailbox_size > 0);
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            const pair = try actor.mailbox.new(Message, gpa, io, config.mailbox_size);
            self.* = .{
                .gpa = gpa,
                .io = io,
                .discovery = .init(gpa, config.discovery),
                .retry_timeout_ns = config.retry_timeout_ns,
                .mailbox = .{ .receiver = pair.receiver },
                .net_sender = net_sender,
                .net_receiver = net_receiver,
            };
            return .{ .probe = self, .mailbox = .{ .gpa = gpa, .io = io, .sender = pair.sender } };
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.mailbox.receiver.deinit();
            self.discovery.deinit();
            if (self.source) |source| release(Source, source);
            release(NetSender, self.net_sender);
            release(NetReceiver, self.net_receiver);
            self.* = undefined;
            gpa.destroy(self);
        }

        /// Runs discovery, then service, until the network receiver closes, the mailbox closes
        /// or the snapshot cannot be activated during discovery, or the task is canceled.
        /// `rng` and `strategy` verify certificates; `strategy` also decodes blocks.
        pub fn run(self: *Self, rng: anytype, strategy: anytype) !void {
            self.inbox.init(self.io);
            defer self.inbox.shutdown();
            try self.inbox.forward(.mailbox, &self.mailbox);
            try self.inbox.forward(.network, &self.net_receiver);
            // A probe stopped during discovery closes its pending subscriptions, as dropping
            // commonware's actor does.
            const discovered = self.discover(rng, strategy) catch |err| {
                self.discovery.drop_subscribers();
                if (err == error.Canceled) return;
                return err;
            };
            if (!discovered) return self.discovery.drop_subscribers();
            assert(self.source != null);
            self.serve() catch |err| switch (err) {
                error.Canceled => return,
                else => return err,
            };
        }

        fn now_ns(self: *const Self) i96 {
            return Io.Timestamp.now(self.io, .awake).nanoseconds;
        }

        /// The discovery loop; true once it hands off to service.
        fn discover(self: *Self, rng: anytype, strategy: anytype) !bool {
            var deadline = self.now_ns() + self.retry_timeout_ns;
            while (!self.discovery.finished()) {
                const next = if (self.discovery.retrying())
                    try self.inbox.next_until(deadline)
                else
                    try self.inbox.next();
                const event = next orelse {
                    // The retry deadline elapsed.
                    try self.discovery.retry(&self.net_sender);
                    deadline = self.now_ns() + self.retry_timeout_ns;
                    continue;
                };
                const sent = switch (event) {
                    .closed => return false,
                    .mailbox => |item| switch (item) {
                        .drained => return false,
                        .request => |request| switch (request) {
                            .subscribe => |response| self.discovery.subscribe(
                                response,
                                &self.net_sender,
                            ) catch |err| switch (err) {
                                // Drops every pending subscriber when the probe is freed.
                                error.BootstrapActivation => return false,
                                else => return err,
                            },
                            .attach => |source| self.attach(source),
                        },
                    },
                    .network => |received| try self.discover_network(received, rng, strategy),
                };
                if (sent) deadline = self.now_ns() + self.retry_timeout_ns;
            }
            return true;
        }

        fn discover_network(
            self: *Self,
            received: NetMessage,
            rng: anytype,
            strategy: anytype,
        ) !bool {
            var message = received;
            defer message.deinit();
            return self.discovery.receive(
                message.peer,
                message.payload,
                &self.net_sender,
                rng,
                strategy,
            );
        }

        fn attach(self: *Self, source: Source) bool {
            if (self.source) |old| release(Source, old);
            self.source = source;
            self.discovery.attach();
            return false;
        }

        /// The service loop, until the network receiver closes.
        fn serve(self: *Self) !void {
            while (true) {
                const event = try self.inbox.next();
                switch (event) {
                    .closed => return,
                    .mailbox => |item| switch (item) {
                        .drained => {},
                        .request => |request| switch (request) {
                            .subscribe => |response| try self.answer_subscription(response),
                            .attach => |source| release(Source, source),
                        },
                    },
                    .network => |received| {
                        var message = received;
                        defer message.deinit();
                        try self.answer(message.peer, message.payload);
                    },
                }
            }
        }

        /// Serves the artifact if one was discovered; dropping the sender closes the
        /// subscription.
        fn answer_subscription(self: *Self, response: oneshot.Sender(Artifact)) !void {
            var owned = response;
            const artifact = if (self.discovery.artifact) |*artifact| artifact else {
                return owned.deinit();
            };
            try Discovery.deliver(self.gpa, &owned, artifact);
        }

        /// Answers a peer's request from the source, if it has the material; blocks a peer
        /// whose request does not decode and ignores responses.
        fn answer(self: *Self, peer: PublicKey, payload: []const u8) !void {
            const request = wire.read_request(self.gpa, payload) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                _ = self.discovery.blocker.block(peer); // An invalid boundary request.
                return;
            } orelse return;
            const source = &self.source.?;
            switch (request) {
                .latest => {
                    var finalization = try source.latest_finalization(self.gpa) orelse return;
                    defer finalization.deinit(self.gpa);
                    try self.respond(peer, .{ .latest_response = finalization });
                },
                .boundary => |epoch| {
                    const height = self.boundary_height(epoch) orelse return;
                    var finalization = try source.get_finalization(self.gpa, height) orelse return;
                    defer finalization.deinit(self.gpa);
                    try self.respond(peer, .{ .boundary_response = finalization });
                },
                .block => |epoch| {
                    const height = self.boundary_height(epoch) orelse return;
                    var block = try source.get_block(self.gpa, height) orelse return;
                    defer block.deinit();
                    const response: wire.Message(S, V).BlockResponse = .{
                        .epoch = epoch,
                        .block = block,
                    };
                    try self.respond(peer, .{ .block_response = response });
                },
            }
        }

        /// The height of the boundary block that carries `epoch`'s info: the last block of
        /// the previous epoch. Epoch zero has none.
        fn boundary_height(self: *const Self, epoch: Epoch) ?Height {
            const previous = epoch.previous() orelse return null;
            return self.discovery.epocher.last(previous);
        }

        fn respond(self: *Self, peer: PublicKey, message: wire.Message(S, V)) !void {
            const bytes = try message.encode(self.gpa);
            defer self.gpa.free(bytes);
            const attempted = try self.net_sender.send(.{ .one = peer }, &.{bytes}, false);
            self.gpa.free(attempted);
        }

        fn release_event(event: Event) void {
            switch (event) {
                .closed => {},
                .mailbox => |item| switch (item) {
                    .drained => {},
                    .request => |request| Message.discard(request),
                },
                .network => |received| {
                    var message = received;
                    message.deinit();
                },
            }
        }
    };
}

/// A probe `Source` over marshal's mailbox `M` (`consensus.marshal.core.Mailbox(S, V)`).
/// Marshal's replies are allocated by the mailbox's allocator, which must be the probe's.
pub fn MarshalSource(comptime M: type) type {
    return struct {
        const Self = @This();

        mailbox: M,

        pub fn deinit(self: *Self) void {
            self.mailbox.deinit();
            self.* = undefined;
        }

        /// The finalization of marshal's latest finalized height (commonware
        /// `stateful::probe::sample::latest_finalization`).
        pub fn latest_finalization(self: Self, gpa: Allocator) !?M.M.Finalization {
            _ = gpa;
            const info = try self.mailbox.get_info(.latest) orelse return null;
            return self.mailbox.get_finalization(info.height);
        }

        pub fn get_finalization(self: Self, gpa: Allocator, height: Height) !?M.M.Finalization {
            _ = gpa;
            return self.mailbox.get_finalization(height);
        }

        pub fn get_block(self: Self, gpa: Allocator, height: Height) !?M.M.Block {
            _ = gpa;
            return self.mailbox.get_block(.{ .height = height });
        }
    };
}
