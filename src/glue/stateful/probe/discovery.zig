//! The probe's discovery and service state (commonware `glue/src/stateful/probe/actor/
//! discovery.rs` and `service.rs`), without I/O: the actor's driver feeds it mailbox messages
//! and peer messages and performs the sends and blocks it returns.
//!
//! See `probe/mod.zig` for the protocol: a subscription starts a request round when none is
//! waiting; replies from awaited committee members are judged (ignored, blocked, or recorded);
//! `f + 1` judgeable replies select the floor, which every waiting subscriber receives. Once a
//! marshal is attached and no subscriber waits, the probe serves peers instead.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus = @import("consensus");
const utils = @import("utils");
const sample_mod = @import("sample.zig");
const wire = @import("wire.zig");

const Epoch = consensus.Epoch;
const oneshot = utils.channel.oneshot;

/// A floor delivered to a subscriber; the receiver owns it (`deinit`), and the channel frees an
/// unreceived one.
pub fn Floor(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Finalization = consensus.simplex.types.Finalization(S, D);

        finalization: Finalization,
        gpa: Allocator,

        pub fn deinit(self: *Self) void {
            self.finalization.deinit(self.gpa);
            self.* = undefined;
        }

        pub fn discard(self: Self) void {
            var owned = self;
            owned.deinit();
        }
    };
}

/// What the driver does with a peer's message.
pub const Verdict = enum {
    /// Nothing: a request, a duplicate, an unjudgeable or out-of-range reply.
    ignore,
    /// Block the peer: malformed, sent by a non-participant, or failing verification.
    block,
    /// The reply joined the sample.
    recorded,
};

/// Discovery over scheme `S`, digest `D`, and an epoch scheme provider `P` (`scoped(epoch)
/// ?Scoped(S)`, `scheme(epoch) ?*const S`).
pub fn Discovery(comptime S: type, comptime D: type, comptime P: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = S.PublicKey;
        pub const Sample = sample_mod.Sample(S, D);
        pub const Finalization = Sample.Finalization;
        pub const FloorValue = Floor(S, D);
        const Proposal = consensus.simplex.types.Proposal(D);

        gpa: Allocator,
        provider: P,
        sample: Sample,
        subscribers: std.ArrayList(oneshot.Sender(FloorValue)) = .empty,
        attached: bool = false,

        pub fn init(gpa: Allocator, provider: P, minimum_epoch: Epoch) Self {
            return .{ .gpa = gpa, .provider = provider, .sample = .init(gpa, minimum_epoch) };
        }

        pub fn deinit(self: *Self) void {
            for (self.subscribers.items) |*subscriber| subscriber.deinit();
            self.subscribers.deinit(self.gpa);
            self.sample.deinit();
            self.* = undefined;
        }

        /// Drops subscribers whose receivers are gone (commonware's `retain(!is_closed)`).
        pub fn retain_open(self: *Self) void {
            var kept: usize = 0;
            for (self.subscribers.items) |subscriber| {
                var owned = subscriber;
                if (owned.is_closed()) {
                    owned.deinit();
                    continue;
                }
                self.subscribers.items[kept] = owned;
                kept += 1;
            }
            self.subscribers.shrinkRetainingCapacity(kept);
        }

        /// Whether discovery is over: a marshal is attached and no subscriber waits.
        pub fn finished(self: *Self) bool {
            self.retain_open();
            return self.attached and self.subscribers.items.len == 0;
        }

        /// Whether the retry deadline is armed: no floor yet and a subscriber waits.
        pub fn retrying(self: *Self) bool {
            self.retain_open();
            return self.sample.get_floor() == null and self.subscribers.items.len > 0;
        }

        pub fn attach(self: *Self) void {
            self.attached = true;
        }

        /// Takes a subscription. Returns true when it starts a request round (the driver
        /// then calls `request_round` and rearms the retry deadline).
        pub fn subscribe(self: *Self, response: oneshot.Sender(FloorValue)) !bool {
            var owned = response;
            if (self.sample.get_floor()) |floor| {
                try self.send_floor(&owned, floor);
                return false;
            }
            self.retain_open();
            const solicit = self.subscribers.items.len == 0;
            self.subscribers.append(self.gpa, owned) catch |err| {
                owned.deinit();
                return err;
            };
            return solicit;
        }

        /// Starts a request round: clears the sample and returns the minimum epoch's
        /// committee to solicit (borrowed from the provider), or null when that epoch has no
        /// known scheme.
        pub fn request_round(self: *Self) ?[]const PublicKey {
            self.sample.reset();
            const scheme = self.provider.scheme(self.sample.minimum_epoch) orelse return null;
            return scheme.participants().as_slice();
        }

        /// Judges `payload` from `peer`, recording a valid reply and delivering the floor once
        /// the sample resolves. `rng` and `strategy` verify certificates.
        pub fn receive(
            self: *Self,
            peer: PublicKey,
            payload: []const u8,
            rng: anytype,
            strategy: anytype,
        ) Allocator.Error!Verdict {
            // Skip unawaited replies before decoding, so duplicates cost no certificate work
            // and are never blocked.
            if (!self.sample.awaits(peer)) return .ignore;
            var finalization = (self.decode(payload) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .block,
            }) orelse return .ignore;
            var owned = true;
            defer if (owned) finalization.deinit(self.gpa);
            const verdict = try self.verify(peer, &finalization, rng, strategy);
            if (verdict != .recorded) return verdict;
            self.retain_open();
            if (self.subscribers.items.len == 0) {
                // Discovery paused: replies are verified but not recorded.
                self.sample.reset();
                return .ignore;
            }
            owned = false;
            try self.sample.record(peer, finalization);
            try self.select();
            return .recorded;
        }

        /// Decodes a reply, reading its certificate with the codec config of the epoch its
        /// proposal claims. Null for a request, an epoch below the minimum, or an epoch with
        /// no known scheme.
        fn decode(self: *Self, payload: []const u8) codec.Error!?Finalization {
            var reader = codec.Reader.init(payload);
            const tag = try reader.read_byte();
            switch (tag) {
                @backingInt(wire.Tag.request) => return null,
                @backingInt(wire.Tag.response) => {},
                else => return error.InvalidEnum,
            }
            const proposal = try Proposal.read(self.gpa, &reader, {});
            if (proposal.epoch().get() < self.sample.minimum_epoch.get()) return null;
            const scoped = self.provider.scoped(proposal.epoch()) orelse return null;
            const cfg = scoped.certificate_codec_config();
            const certificate = try codec.read_cfg(S.Certificate, self.gpa, &reader, cfg);
            errdefer codec.free(S.Certificate, self.gpa, certificate);
            if (reader.remaining() != 0) return error.ExtraData;
            return .{ .proposal = proposal, .certificate = certificate };
        }

        /// Blocks a non-participant of the minimum epoch's committee or a reply failing
        /// verification under its own epoch's scheme; ignores one either scheme cannot judge.
        fn verify(
            self: *Self,
            peer: PublicKey,
            finalization: *const Finalization,
            rng: anytype,
            strategy: anytype,
        ) Allocator.Error!Verdict {
            const minimum = self.sample.minimum_epoch;
            const scheme = self.provider.scheme(minimum) orelse return .ignore;
            if (scheme.participants().position(peer) == null) return .block;
            const scoped = self.provider.scoped(finalization.epoch()) orelse return .ignore;
            if (!try finalization.verify(self.gpa, rng, scoped, strategy)) return .block;
            return .recorded;
        }

        /// Selects the floor once the sample resolves and delivers it to every subscriber.
        fn select(self: *Self) Allocator.Error!void {
            const scheme = self.provider.scheme(self.sample.minimum_epoch) orelse return;
            const Judge = struct {
                provider: *const P,
                pub fn judgeable(judge: @This(), finalization: *const Finalization) bool {
                    return judge.provider.scoped(finalization.epoch()) != null;
                }
            };
            const committee = scheme.participants().len();
            const judge: Judge = .{ .provider = &self.provider };
            const floor = try self.sample.select(committee, judge) orelse return;
            for (self.subscribers.items) |*subscriber| try self.send_floor(subscriber, floor);
            self.subscribers.clearRetainingCapacity();
            assert(self.sample.get_floor() != null);
        }

        /// Sends a copy of `floor` to `subscriber`, releasing the sender; a dropped receiver
        /// frees the copy.
        fn send_floor(
            self: *Self,
            subscriber: *oneshot.Sender(FloorValue),
            floor_value: *const Finalization,
        ) Allocator.Error!void {
            const clone = floor_value.clone(self.gpa) catch |err| {
                subscriber.deinit();
                return err;
            };
            const value: FloorValue = .{ .finalization = clone, .gpa = self.gpa };
            subscriber.send(value) catch value.discard(); // The subscriber left.
        }

        /// The floor selected during discovery, if any, for the service phase.
        pub fn selected_floor(self: *const Self) ?*const Finalization {
            return self.sample.get_floor();
        }
    };
}

test {
    std.testing.refAllDecls(@This());
}
