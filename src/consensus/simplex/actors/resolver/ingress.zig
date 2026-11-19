//! Messages to the simplex resolver actor (commonware `actors/resolver/ingress.rs`).
//!
//! When the mailbox is full, overflow keeps the latest finalization (dropping everything it
//! covers), keeps every `replayed`, and merges repeats: one update per view and kind, one
//! certification verdict per view, and one resolve per request (an untargeted repeat widens a
//! targeted one).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const resolver = @import("resolver");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ask = @import("../ask.zig");

const View = consensus_types.View;
const oneshot = utils.channel.oneshot;
const Produced = resolver.p2p.Produced;
const Span = @import("runtime").telemetry.traces.Span;

pub fn Message(comptime S: type, comptime D: type) type {
    return union(enum) {
        const Self = @This();
        const Certificate = types.Certificate(S, D);
        const Notarization = types.Notarization(S, D);

        /// A certificate the voter recorded (owned, allocated with `gpa`).
        updated: struct { gpa: Allocator, certificate: Certificate },
        /// A certification verdict for a notarization (owned, allocated with `gpa`).
        certified: struct { gpa: Allocator, notarization: Notarization, success: bool },
        /// Missing proposal ancestry; `target` restricts the fetch to one peer.
        resolve: struct { proposal: View, view: View, kind: ask.Kind, target: ?S.PublicKey },
        /// Journal replay finished.
        replayed,

        pub const Overflow = Pending(S, D);

        pub fn view(self: Self) View {
            return switch (self) {
                .updated => |updated| updated.certificate.view(),
                .certified => |certified| certified.notarization.view(),
                .resolve => |resolve| resolve.view,
                .replayed => .zero(),
            };
        }

        /// Releases a message the mailbox drops.
        pub fn discard(message: Self) void {
            switch (message) {
                .updated => |updated| {
                    var certificate = updated.certificate;
                    certificate.deinit(updated.gpa);
                },
                .certified => |certified| {
                    var notarization = certified.notarization;
                    notarization.deinit(certified.gpa);
                },
                .resolve, .replayed => {},
            }
        }

        fn is_finalization(self: Self) bool {
            return self == .updated and self.updated.certificate == .finalization;
        }

        /// Whether `new` repeats `old` (merging an untargeted resolve into a targeted one).
        fn absorbs(old: *Self, new: Self) bool {
            switch (new) {
                .updated => |updated| {
                    if (old.* != .updated) return false;
                    const certificate = old.updated.certificate;
                    return certificate.view() == updated.certificate.view() and
                        std.meta.activeTag(certificate) == std.meta.activeTag(updated.certificate);
                },
                .certified => |certified| {
                    if (old.* != .certified) return false;
                    return old.certified.notarization.view() == certified.notarization.view();
                },
                .resolve => |resolve| {
                    if (old.* != .resolve) return false;
                    const existing = &old.resolve;
                    if (existing.proposal != resolve.proposal) return false;
                    if (existing.view != resolve.view) return false;
                    if (existing.kind != resolve.kind) return false;
                    if (resolve.target == null) existing.target = null;
                    return true;
                },
                .replayed => return false,
            }
        }

        /// The overflow policy (commonware `Policy::handle`).
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            if (message == .replayed) return overflow.messages.pushBack(gpa, message);
            const new_view = message.view();
            if (overflow.finalization) |old| {
                if (old.view().get() >= new_view.get()) return discard(message);
            }
            if (message.is_finalization()) {
                overflow.retain_above(new_view);
                if (overflow.finalization) |old| discard(old);
                overflow.finalization = message;
                return;
            }
            for (0..overflow.messages.len) |index| {
                const old = overflow.messages.atPtr(index);
                if (absorbs(old, message)) return discard(message);
            }
            try overflow.messages.pushBack(gpa, message);
        }
    };
}

/// Messages held while the resolver's mailbox is full (commonware `Pending`).
pub fn Pending(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const M = Message(S, D);

        finalization: ?M = null,
        messages: std.Deque(M) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.finalization) |message| M.discard(message);
            while (self.messages.popFront()) |message| M.discard(message);
            self.messages.deinit(gpa);
            self.* = undefined;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.finalization == null and self.messages.len == 0;
        }

        /// Drops messages at or below `view`, keeping every `replayed`.
        fn retain_above(self: *Self, view: View) void {
            const count = self.messages.len;
            for (0..count) |_| {
                const message = self.messages.popFront().?;
                if (message != .replayed and message.view().get() <= view.get()) {
                    M.discard(message);
                    continue;
                }
                self.messages.pushBackAssumeCapacity(message);
            }
            assert(self.messages.len <= count);
        }

        /// Hands the finalization first, then the rest, until the mailbox is full again.
        pub fn drain(self: *Self, pusher: anytype) void {
            if (self.finalization) |finalization| {
                self.finalization = null;
                if (pusher.push(finalization)) |rejected| {
                    self.finalization = rejected;
                    return;
                }
            }
            while (self.messages.popFront()) |message| {
                if (pusher.push(message)) |rejected| {
                    self.messages.pushFrontAssumeCapacity(rejected);
                    break;
                }
            }
        }
    };
}

/// The resolver's mailbox (commonware `resolver::Mailbox`).
pub fn Mailbox(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const M = Message(S, D);

        sender: actor.mailbox.Sender(M),

        pub fn clone(self: Self) Self {
            return .{ .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        /// Hands over `certificate` (allocated with `gpa`). It may be sent more than once.
        pub fn updated(
            self: Self,
            gpa: Allocator,
            certificate: types.Certificate(S, D),
        ) Allocator.Error!void {
            _ = try self.sender.enqueue(.{
                .updated = .{ .gpa = gpa, .certificate = certificate },
            });
        }

        /// Hands over a certification verdict with its `notarization` (allocated with `gpa`).
        pub fn certified(
            self: Self,
            gpa: Allocator,
            notarization: types.Notarization(S, D),
            success: bool,
        ) Allocator.Error!void {
            _ = try self.sender.enqueue(.{ .certified = .{
                .gpa = gpa,
                .notarization = notarization,
                .success = success,
            } });
        }

        /// Journal replay is complete; background repair may start.
        pub fn replayed(self: Self) Allocator.Error!void {
            _ = try self.sender.enqueue(.replayed);
        }

        /// Requests missing proposal ancestry, from `target` alone when given.
        pub fn resolve(
            self: Self,
            proposal: consensus_types.View,
            view: consensus_types.View,
            kind: ask.Kind,
            target: ?S.PublicKey,
        ) Allocator.Error!void {
            assert(proposal.get() >= view.get() or kind == .nullification);
            _ = try self.sender.enqueue(.{ .resolve = .{
                .proposal = proposal,
                .view = view,
                .kind = kind,
                .target = target,
            } });
        }
    };
}

/// A request from the p2p resolver engine to the resolver actor (commonware `HandlerMessage`).
pub const HandlerMessage = union(enum) {
    const Self = @This();

    /// A peer's response for `view`; `data` and `asks` are owned (allocated with `gpa`).
    deliver: struct {
        gpa: Allocator,
        view: View,
        data: []u8,
        asks: []ask.Ask,
        response: oneshot.Sender(resolver.Outcome),
        /// The span of the fetch that asked for `view` (commonware's first subscriber's
        /// span), owned (allocated with `gpa`) and a root, so it outlives the fetch.
        span: ?*Span = null,
    },
    /// A peer asks for the certificate this node serves for `view`.
    produce: struct { view: View, response: oneshot.Sender(Produced) },

    pub const Overflow = HandlerPending;

    /// Whether the requester stopped waiting for this response.
    pub fn response_closed(self: Self) bool {
        return switch (self) {
            .deliver => |deliver| deliver.response.is_closed(),
            .produce => |produce| produce.response.is_closed(),
        };
    }

    pub fn discard(message: Self) void {
        switch (message) {
            .deliver => |deliver| {
                var response = deliver.response;
                response.deinit();
                deliver.gpa.free(deliver.data);
                deliver.gpa.free(deliver.asks);
                if (deliver.span) |span| deliver.gpa.destroy(span);
            },
            .produce => |produce| {
                var response = produce.response;
                response.deinit();
            },
        }
    }

    /// Drops produce requests, so the serve backlog stays bounded by the ready queue (peers
    /// can ask a less loaded peer), and deliveries nobody waits for.
    pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
        if (message == .produce or message.response_closed()) return discard(message);
        assert(message == .deliver);
        try overflow.messages.pushBack(gpa, message);
    }
};

/// Deliveries retained while the handler's ready queue is full (commonware `HandlerPending`).
pub const HandlerPending = struct {
    const Self = @This();

    messages: std.Deque(HandlerMessage) = .empty,

    pub const empty: Self = .{};

    pub fn deinit(self: *Self, gpa: Allocator) void {
        while (self.messages.popFront()) |message| HandlerMessage.discard(message);
        self.messages.deinit(gpa);
        self.* = undefined;
    }

    pub fn is_empty(self: *const Self) bool {
        return self.messages.len == 0;
    }

    /// Hands deliveries still awaited, in order, until the mailbox is full again.
    pub fn drain(self: *Self, pusher: anytype) void {
        while (self.messages.popFront()) |message| {
            if (message.response_closed()) {
                HandlerMessage.discard(message);
                continue;
            }
            if (pusher.push(message)) |rejected| {
                self.messages.pushFrontAssumeCapacity(rejected);
                break;
            }
        }
    }
};

/// The p2p resolver engine's consumer and producer: forwards both to the resolver actor
/// (commonware `Handler`). Keys are views as `U64`. The engine never releases its consumer
/// or producer, so the handler borrows the actor's sender, which outlives the engine.
pub const Handler = struct {
    const Self = @This();
    pub const Key = utils.sequence.U64;
    pub const Value = []const u8;
    pub const Subscriber = ask.Ask;
    pub const Outcome = resolver.Outcome;

    gpa: Allocator,
    io: Io,
    sender: *const actor.mailbox.Sender(HandlerMessage),

    /// Hands a copy of `value` to the actor; the receiver yields its verdict.
    pub fn deliver(
        self: Self,
        delivery: resolver.Delivery(Key, ask.Ask),
        value: []const u8,
    ) Allocator.Error!oneshot.Receiver(Outcome) {
        assert(delivery.subscribers.len > 0);
        const pair = try oneshot.channel(Outcome, self.gpa, self.io);
        errdefer {
            var sender = pair.sender;
            var receiver = pair.receiver;
            sender.deinit();
            receiver.deinit();
        }
        const data = try self.gpa.dupe(u8, value);
        errdefer self.gpa.free(data);
        const asks = try self.gpa.dupe(ask.Ask, delivery.subscribers);
        errdefer self.gpa.free(asks);
        // Processing runs under the first subscriber's fetch span (commonware keeps a clone).
        const first: ?*const Span = if (delivery.spans.len > 0) delivery.spans[0] else null;
        const span = try resolver.own_span(self.gpa, first);
        errdefer resolver.free_span(self.gpa, span);
        _ = try self.sender.enqueue(.{ .deliver = .{
            .gpa = self.gpa,
            .view = .new(delivery.key.get()),
            .data = data,
            .asks = asks,
            .response = pair.sender,
            .span = span,
        } });
        return pair.receiver;
    }

    /// Asks the actor for the certificate it serves at `key`; a closed receiver means none.
    pub fn produce(self: Self, key: Key) Allocator.Error!oneshot.Receiver(Produced) {
        const pair = try oneshot.channel(Produced, self.gpa, self.io);
        _ = try self.sender.enqueue(.{
            .produce = .{ .view = .new(key.get()), .response = pair.sender },
        });
        return pair.receiver;
    }
};
