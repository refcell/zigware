//! The probe actor (commonware `glue/src/stateful/probe/actor` and `mailbox.rs`): drives
//! `Discovery` from its mailbox, the probe channel, and a retry deadline, then serves peers.
//!
//! commonware's `select_loop!` over the mailbox, the network receiver, and the retry sleep is
//! one simplex `Inbox` fed by two pumps, popped with `next_until(deadline)` while a retry is
//! armed. Discovery runs until a source is attached and no subscriber waits; the service phase
//! then answers each `Request` with the source's latest finalization, blocks peers that send an
//! invalid tag, answers subscriptions with the floor (or closes them without one), and ignores
//! later attachments.
//!
//! Contracts (comptime), declared by `Probe`'s parameter `P`:
//! - `Scheme` and `Digest`: the certificate scheme and the finalized commitment.
//! - `Provider`: `scoped(epoch) ?Scoped(S)` and `scheme(epoch) ?*const S`.
//! - `Source`: `latest_finalization(gpa) !?Finalization` (the caller owns the result), and
//!   optionally `deinit`. `MarshalSource` adapts marshal's mailbox.
//! - `Blocker`: `block(peer) Feedback`.
//! - `NetSender`: `send(recipients, parts, priority) ![]PublicKey` (attempted, caller-owned);
//!   `NetReceiver`: `recv() !p2p.Message(PublicKey)`. Both optionally declare `deinit`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const consensus = @import("consensus");
const p2p = @import("p2p");
const utils = @import("utils");
const discovery_mod = @import("discovery.zig");
const wire = @import("wire.zig");

const oneshot = utils.channel.oneshot;
const inbox_mod = consensus.simplex.actors.inbox;

/// A message to the probe (commonware `probe::mailbox::Message`).
pub fn Request(comptime S: type, comptime D: type, comptime Source: type) type {
    return union(enum) {
        const Self = @This();
        pub const Floor = discovery_mod.Floor(S, D);

        /// A subscription to the floor.
        subscribe: oneshot.Sender(Floor),
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
                .attach => |source| release_source(Source, source),
            }
        }
    };
}

fn release_source(comptime Source: type, source: Source) void {
    if (comptime @hasDecl(Source, "deinit")) {
        var owned = source;
        owned.deinit();
    }
}

fn release(comptime T: type, value: *T) void {
    if (comptime @hasDecl(T, "deinit")) value.deinit();
}

/// Handle to the probe's mailbox (commonware `probe::Mailbox`).
pub fn Mailbox(comptime S: type, comptime D: type, comptime Source: type) type {
    return struct {
        const Self = @This();
        pub const Message = Request(S, D, Source);
        pub const Floor = Message.Floor;

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

        /// Subscribes to the floor. The receiver resolves at once if a floor is selected;
        /// otherwise, while discovering, the subscription starts a request round if no other
        /// subscriber waits. Dropping the receiver cancels it. In service, a probe without a
        /// floor closes the receiver.
        pub fn subscribe(self: Self) Allocator.Error!oneshot.Receiver(Floor) {
            const pair = try oneshot.channel(Floor, self.gpa, self.io);
            _ = self.sender.enqueue(.{ .subscribe = pair.sender }) catch |err| {
                var receiver = pair.receiver;
                receiver.deinit();
                return err;
            };
            return pair.receiver;
        }

        /// Attaches a source from which the probe answers peers' requests, once no
        /// subscriber awaits a floor. Attachments after service starts are ignored.
        pub fn attach(self: Self, source: Source) Allocator.Error!void {
            _ = try self.sender.enqueue(.{ .attach = source });
        }
    };
}

/// The probe's configuration (commonware `probe::Config`, without the runtime context).
pub fn Config(comptime Provider: type, comptime Blocker: type) type {
    return struct {
        provider: Provider,
        blocker: Blocker,
        mailbox_size: u32,
        /// Lowest epoch whose finalizations are accepted; its committee is solicited.
        minimum_epoch: consensus.Epoch,
        /// Time to wait for a complete sample before starting a new request round.
        retry_timeout_ns: u64,
    };
}

/// The probe actor. `P` declares `Scheme`, `Digest`, `Provider`, `Source`, `Blocker`,
/// `NetSender`, and `NetReceiver` (see the contracts above).
pub fn Probe(comptime P: type) type {
    return struct {
        const Self = @This();
        const S = P.Scheme;
        const D = P.Digest;
        const Provider = P.Provider;
        const Source = P.Source;
        const Blocker = P.Blocker;
        const NetSender = P.NetSender;
        const NetReceiver = P.NetReceiver;
        pub const PublicKey = S.PublicKey;
        pub const Discovery = discovery_mod.Discovery(S, D, Provider);
        pub const ProbeMailbox = Mailbox(S, D, Source);
        pub const Message = ProbeMailbox.Message;
        pub const Floor = Message.Floor;
        const NetMessage = p2p.Message(PublicKey);

        /// The mailbox pump's item: a request, or the end of the mailbox (commonware's
        /// `mailbox_drained`), after which the pump stops without closing the inbox.
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

        gpa: Allocator,
        io: Io,
        discovery: Discovery,
        blocker: Blocker,
        retry_timeout_ns: u64,
        mailbox: MailboxPump,
        net_sender: NetSender,
        net_receiver: NetReceiver,
        source: ?Source = null,
        inbox: Inbox = undefined,

        pub const Created = struct { probe: *Self, mailbox: ProbeMailbox };

        /// A probe on the probe channel (`net_sender`, `net_receiver`), which it owns, and its
        /// mailbox. Start it with `run`; free it with `deinit` once `run` returned.
        pub fn init(
            gpa: Allocator,
            io: Io,
            config: Config(Provider, Blocker),
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
                .discovery = .init(gpa, config.provider, config.minimum_epoch),
                .blocker = config.blocker,
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
            if (self.source) |source| release_source(Source, source);
            release(NetSender, &self.net_sender);
            release(NetReceiver, &self.net_receiver);
            self.* = undefined;
            gpa.destroy(self);
        }

        /// Runs discovery, then service, until the network receiver closes, the mailbox
        /// closes during discovery, or the task is canceled. `rng` and `strategy` verify
        /// certificates.
        pub fn run(self: *Self, rng: anytype, strategy: anytype) !void {
            self.inbox.init(self.io);
            defer self.inbox.shutdown();
            try self.inbox.forward(.mailbox, &self.mailbox);
            try self.inbox.forward(.network, &self.net_receiver);
            const discovered = self.discover(rng, strategy) catch |err| switch (err) {
                error.Canceled => return,
                else => return err,
            };
            if (!discovered) return;
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
                    // The retry deadline elapsed without a complete sample.
                    try self.solicit();
                    deadline = self.now_ns() + self.retry_timeout_ns;
                    continue;
                };
                switch (event) {
                    .closed => return false,
                    .mailbox => |item| switch (item) {
                        .drained => return false,
                        .request => |request| switch (request) {
                            .subscribe => |sender| if (try self.discovery.subscribe(sender)) {
                                try self.solicit();
                                deadline = self.now_ns() + self.retry_timeout_ns;
                            },
                            .attach => |source| self.attach(source),
                        },
                    },
                    .network => |received| {
                        var message = received;
                        defer message.deinit();
                        const peer = message.peer;
                        const verdict = try self.discovery.receive(
                            peer,
                            message.payload,
                            rng,
                            strategy,
                        );
                        if (verdict == .block) _ = self.blocker.block(peer);
                    },
                }
            }
            return true;
        }

        fn attach(self: *Self, source: Source) void {
            if (self.source) |old| release_source(Source, old);
            self.source = source;
            self.discovery.attach();
        }

        /// Starts a request round, soliciting the minimum epoch's committee.
        fn solicit(self: *Self) !void {
            const committee = self.discovery.request_round() orelse return;
            assert(committee.len > 0);
            const request = [_]u8{@backingInt(wire.Tag.request)};
            const recipients: p2p.Recipients(PublicKey) = .{ .some = committee };
            const attempted = try self.net_sender.send(recipients, &.{&request}, false);
            self.gpa.free(attempted);
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
                            .subscribe => |sender| try self.answer_subscription(sender),
                            .attach => |source| release_source(Source, source),
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

        /// Serves the floor if one was selected; dropping the sender closes the subscription.
        fn answer_subscription(self: *Self, sender: oneshot.Sender(Floor)) !void {
            var owned = sender;
            const floor = self.discovery.selected_floor() orelse return owned.deinit();
            const copy = floor.clone(self.gpa) catch |err| {
                owned.deinit();
                return err;
            };
            const value: Floor = .{ .finalization = copy, .gpa = self.gpa };
            owned.send(value) catch value.discard();
        }

        /// Answers a peer's request with the source's latest finalization, if any; blocks a
        /// peer whose message has no valid tag and ignores replies.
        fn answer(self: *Self, peer: PublicKey, payload: []const u8) !void {
            if (payload.len == 0 or payload[0] > @backingInt(wire.Tag.response)) {
                _ = self.blocker.block(peer);
                return;
            }
            if (payload[0] != @backingInt(wire.Tag.request)) return;
            var finalization = try self.source.?.latest_finalization(self.gpa) orelse return;
            defer finalization.deinit(self.gpa);
            const WireMessage = wire.Message(S, struct {
                pub const Commitment = D;
            });
            const bytes = try codec.encode(WireMessage, self.gpa, .{ .response = finalization });
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

/// A probe `Source` over marshal's mailbox `M` (`consensus.marshal.core.Mailbox(S, V)`): the
/// finalization of marshal's latest finalized height (commonware `latest_finalization`).
pub fn MarshalSource(comptime M: type) type {
    return struct {
        const Self = @This();

        mailbox: M,

        pub fn deinit(self: *Self) void {
            self.mailbox.deinit();
            self.* = undefined;
        }

        pub fn latest_finalization(self: Self, gpa: Allocator) !?M.M.Finalization {
            _ = gpa; // Marshal's reply is allocated by the mailbox's allocator.
            const info = try self.mailbox.get_info(.latest) orelse return null;
            return self.mailbox.get_finalization(info.height);
        }
    };
}
