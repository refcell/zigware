//! A Byzantine actor that disrupts consensus with malformed and mutated messages on all three
//! channels (commonware `consensus/fuzz/src/disrupter.rs`).
//!
//! Every 100 ms of simulated time it sends something (a signed vote for a drawn proposal,
//! equivocating proposals, random bytes, or a flood of proposals at one victim), then handles
//! one received message: a vote, certificate, or resolver message it answers with a mutated
//! copy and a re-signed vote. It tracks the highest views it has seen to aim its proposals.
//!
//! commonware selects over the three receivers and a 100 ms timer. The runtime here has no
//! select, so the disrupter polls the receivers in order (`try_recv`) and takes the first
//! message; with none waiting it acts as on commonware's timer. It then sleeps 100 ms as
//! commonware does after every select. Randomness comes from the runtime (`io.random`), as
//! commonware's comes from the deterministic context.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const simplex = @import("../simplex/root.zig");
const IoRng = @import("../simplex/actors/context.zig").IoRng;
const fuzz_types = @import("types.zig");
const strategy_mod = @import("strategy.zig");

const Digest = fuzz_types.Digest;
const Strategy = strategy_mod.Strategy;
const Views = strategy_mod.Views;
const Proposal = simplex.types.Proposal(Digest);
const sampling = utils.rng;
const Key = cryptography.ed25519.PublicKey;
const Recipients = p2p.Recipients(Key);
const Sha256 = cryptography.Sha256;
/// The mock applications' relay, through which a skipping proposal's contents travel.
pub const Relay = simplex.mocks.relay.Relay(Digest, Key);
/// The mock application's contents: `(Round, parent payload, u64)` encoded.
const contents_max = consensus_types.Round.max_encode_size + codec.fixed_size(Digest).? + 8;

const timeout: Io.Duration = .fromMilliseconds(100);
const latest_proposals_min = 10;
const latest_proposals_max = 100;

pub fn Disrupter(comptime S: type) type {
    return struct {
        const Self = @This();
        const Vote = simplex.types.Vote(S, Digest);
        const Certificate = simplex.types.Certificate(S, Digest);
        const Notarize = simplex.types.Notarize(S, Digest);
        const Finalize = simplex.types.Finalize(S, Digest);
        const Nullify = simplex.types.Nullify(S);

        gpa: Allocator,
        io: Io,
        scheme: *const S,
        strategy: Strategy,
        fault_offset: u64,
        views: Views = .{},
        /// The latest proposals seen in notarize votes, oldest first (a ring).
        proposals: [latest_proposals_max]Proposal = undefined,
        proposals_head: usize = 0,
        proposals_len: usize = 0,
        /// Beyond commonware: the two highest-view proposals the relay delivered, highest
        /// first (`observe`), and the view of the last skipping proposal sent.
        observed: [2]?Observed = .{ null, null },
        observed_mutex: Io.Mutex = .init,
        skipped_view: u64 = 0,
        relay: ?*Relay = null,

        pub fn init(gpa: Allocator, io: Io, scheme: *const S, strategy: Strategy) Self {
            const source: IoRng = .{ .io = io };
            return .{
                .gpa = gpa,
                .io = io,
                .scheme = scheme,
                .strategy = strategy,
                .fault_offset = source.next_u64(),
            };
        }

        fn rng(self: *const Self) IoRng {
            return .{ .io = self.io };
        }

        /// Runs until a channel closes or the task is canceled. `votes`, `certificates`, and
        /// `resolver` point at channels with a `sender` and a `receiver`.
        pub fn run(self: *Self, votes: anytype, certificates: anytype, resolver: anytype) void {
            // Each iteration sleeps 100 ms of simulated time; cancelation ends it.
            while (true) {
                self.act(votes, certificates, resolver);
                if (!(self.receive(votes, certificates, resolver) catch return)) {
                    self.send_random_vote(&votes.sender, .all);
                    self.send_random_message(&certificates.sender);
                    self.send_random_message(&resolver.sender);
                }
                self.send_skip_proposal(&votes.sender);
                self.io.sleep(timeout, .awake) catch return;
            }
        }

        fn act(self: *Self, votes: anytype, certificates: anytype, resolver: anytype) void {
            switch (byte(self.rng()) % 7) {
                0 => self.send_random_vote(&votes.sender, .all),
                1 => self.send_proposal(&votes.sender),
                2 => {
                    // Equivocation: two different proposals.
                    self.send_proposal(&votes.sender);
                    self.send_proposal(&votes.sender);
                },
                3 => self.send_random_message(&certificates.sender),
                4 => self.send_random_message(&resolver.sender),
                5 => self.flood_victim(&votes.sender),
                else => {
                    self.send_proposal(&votes.sender);
                    self.send_random_message(&certificates.sender);
                    self.send_random_message(&resolver.sender);
                },
            }
        }

        /// Handles the first waiting message, if any. Fails once a channel disconnects.
        fn receive(
            self: *Self,
            votes: anytype,
            certificates: anytype,
            resolver: anytype,
        ) error{Disconnected}!bool {
            if (try poll(&votes.receiver)) |message| {
                var owned = message;
                defer owned.deinit();
                self.handle_vote(&votes.sender, owned.payload);
                return true;
            }
            if (try poll(&certificates.receiver)) |message| {
                var owned = message;
                defer owned.deinit();
                self.handle_certificate(&certificates.sender, owned.payload);
                return true;
            }
            if (try poll(&resolver.receiver)) |message| {
                var owned = message;
                defer owned.deinit();
                self.handle_resolver(&resolver.sender, owned.payload);
                return true;
            }
            return false;
        }

        fn poll(receiver: anytype) error{Disconnected}!?Received(@TypeOf(receiver)) {
            return receiver.try_recv() catch |err| switch (err) {
                error.Empty => null,
                error.Disconnected => error.Disconnected,
            };
        }

        fn push_proposal(self: *Self, proposal: Proposal) void {
            if (self.proposals_len == latest_proposals_max) self.pop_proposal();
            const index = (self.proposals_head + self.proposals_len) % latest_proposals_max;
            self.proposals[index] = proposal;
            self.proposals_len += 1;
            assert(self.proposals_len <= latest_proposals_max);
        }

        fn pop_proposal(self: *Self) void {
            assert(self.proposals_len > 0);
            self.proposals_head = (self.proposals_head + 1) % latest_proposals_max;
            self.proposals_len -= 1;
        }

        fn proposal_at(self: *const Self, index: usize) Proposal {
            assert(index < self.proposals_len);
            return self.proposals[(self.proposals_head + index) % latest_proposals_max];
        }

        fn prune_proposals(self: *Self) void {
            const views = self.views;
            const active = (@max(views.notarized, views.vote) -| views.finalized) +| 1;
            const keep = @min(@max(active, latest_proposals_min), latest_proposals_max);
            while (self.proposals_len > keep) self.pop_proposal();
        }

        fn current_view(self: *const Self) u64 {
            const views = self.views;
            const certified = @max(views.finalized, views.nullified);
            return @max(@max(views.vote, views.notarized), certified);
        }

        /// Whether the disrupter misbehaves in `view`: every view for `any_scope`, else
        /// `fault_rounds` of every `fault_rounds_bound` views from a random offset.
        fn is_faulty_view(self: *const Self, view: u64) bool {
            const bounds = self.strategy.fault_bounds() orelse return true;
            if (bounds.fault_rounds_bound == 0) return false;
            const faults = @min(bounds.fault_rounds, bounds.fault_rounds_bound);
            if (faults == 0) return false;
            return (self.fault_offset +% view) % bounds.fault_rounds_bound < faults;
        }

        /// A proposal from a recent one or a drawn one, at a drawn view and parent.
        fn get_proposal(self: *Self) Proposal {
            const r = self.rng();
            const index = self.strategy.repeated_proposal_index(r, self.proposals_len);
            const source = if (index) |i|
                self.proposal_at(i)
            else
                self.strategy.random_proposal(r, self.views);
            const view = self.strategy.random_view_for_proposal(r, self.views);
            var based = self.views;
            based.vote = view;
            const parent = self.strategy.random_parent_view(r, based);
            const proposal: Proposal =
                .init(.new(fuzz_types.epoch, .new(view)), .new(parent), source.payload);
            self.prune_proposals();
            return proposal;
        }

        fn mutated_proposal(self: *Self, proposal: Proposal) Proposal {
            return self.strategy.mutate_proposal(self.rng(), proposal, self.views);
        }

        /// Up to 255 random bytes.
        fn random_bytes(self: *Self, buffer: *[255]u8) []const u8 {
            const len = byte(self.rng());
            self.io.random(buffer[0..len]);
            return buffer[0..len];
        }

        /// Sends `bytes` to `recipients`, ignoring the outcome (commonware `let _ = send`).
        fn send(self: *Self, sender: anytype, recipients: Recipients, bytes: []const u8) void {
            const sent = sender.send(recipients, &.{bytes}, true) catch return;
            self.gpa.free(sent);
        }

        fn send_encoded(
            self: *Self,
            sender: anytype,
            recipients: Recipients,
            comptime T: type,
            value: T,
        ) void {
            const bytes = codec.encode(T, self.gpa, value) catch return;
            defer self.gpa.free(bytes);
            self.send(sender, recipients, bytes);
        }

        fn send_vote(self: *Self, sender: anytype, recipients: Recipients, vote: ?Vote) void {
            if (vote) |signed| self.send_encoded(sender, recipients, Vote, signed);
        }

        fn sign_notarize(self: *Self, proposal: Proposal) ?Vote {
            const signed = Notarize.sign(self.gpa, self.scheme, proposal) catch return null;
            return .{ .notarize = signed orelse return null };
        }

        fn sign_finalize(self: *Self, proposal: Proposal) ?Vote {
            const signed = Finalize.sign(self.gpa, self.scheme, proposal) catch return null;
            return .{ .finalize = signed orelse return null };
        }

        fn sign_nullify(self: *Self) ?Vote {
            const view = self.strategy.mutate_nullify_view(self.rng(), self.views);
            const round: consensus_types.Round = .new(fuzz_types.epoch, .new(view));
            const signed = Nullify.sign(self.gpa, self.scheme, round) catch return null;
            return .{ .nullify = signed orelse return null };
        }

        fn handle_vote(self: *Self, sender: anytype, bytes: []const u8) void {
            var reader: codec.Reader = .init(bytes);
            const vote = codec.read(Vote, self.gpa, &reader) catch return;
            defer codec.free(Vote, self.gpa, vote);
            self.views.vote = @max(self.views.vote, vote.view().get());
            if (vote == .notarize) self.push_proposal(vote.notarize.proposal);
            if (!self.is_faulty_view(self.views.vote)) return;
            if (sampling.bernoulli(self.rng(), 0.5)) {
                const mutated = mutate_bytes(self.rng(), bytes, self.gpa) catch return;
                defer self.gpa.free(mutated);
                self.send(sender, .all, mutated);
            }
            const answer = switch (vote) {
                .notarize => |v| self.sign_notarize(self.mutated_proposal(v.proposal)),
                .finalize => |v| self.sign_finalize(self.mutated_proposal(v.proposal)),
                .nullify => self.sign_nullify(),
            };
            self.send_vote(sender, .all, answer);
        }

        fn handle_certificate(self: *Self, sender: anytype, bytes: []const u8) void {
            var reader: codec.Reader = .init(bytes);
            const cfg = self.scheme.certificate_codec_config();
            var certificate = codec.read_cfg(Certificate, self.gpa, &reader, cfg) catch return;
            defer certificate.deinit(self.gpa);
            const view = certificate.view().get();
            const seen = switch (certificate) {
                .notarization => &self.views.notarized,
                .nullification => &self.views.nullified,
                .finalization => &self.views.finalized,
            };
            seen.* = @max(seen.*, view);
            if (!self.is_faulty_view(view)) return;
            if (sampling.bernoulli(self.rng(), 0.5)) {
                self.send_mutated(sender, bytes);
            }
        }

        fn send_mutated(self: *Self, sender: anytype, bytes: []const u8) void {
            const mutated = self.strategy.mutate_bytes(self.rng(), self.gpa, bytes) catch return;
            defer self.gpa.free(mutated);
            self.send(sender, .all, mutated);
        }

        fn handle_resolver(self: *Self, sender: anytype, bytes: []const u8) void {
            if (!self.is_faulty_view(self.current_view())) return;
            if (sampling.bernoulli(self.rng(), 0.5)) {
                self.send_mutated(sender, bytes);
            }
        }

        /// Sends ten mutated proposals to one random other participant.
        fn flood_victim(self: *Self, sender: anytype) void {
            if (!self.is_faulty_view(self.current_view())) return;
            const me = (self.scheme.me() orelse return).index().get();
            const participants = self.scheme.participants().as_slice();
            if (participants.len <= 1) return;
            assert(me < participants.len);
            // A random index among the others, skipping `me`.
            var victim = sampling.range_less_than(self.rng(), usize, 0, participants.len - 1);
            if (victim >= me) victim += 1;
            assert(victim != me);
            for (0..10) |_| {
                const proposal = self.mutated_proposal(self.get_proposal());
                self.send_encoded(sender, .{ .one = participants[victim] }, Proposal, proposal);
            }
        }

        /// A relay listener: notes each proposal's view and payload. The disrupter handles
        /// one network message per 100 ms, so its views lag the network; the relay is
        /// immediate.
        pub fn observe(context: *anyopaque, payload: Digest, contents: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(context));
            var reader: codec.Reader = .init(contents);
            const round = consensus_types.Round.read(self.gpa, &reader, {}) catch return;
            const view = round.view.get();
            self.observed_mutex.lockUncancelable(self.io);
            defer self.observed_mutex.unlock(self.io);
            const seen: Observed = .{ .view = view, .payload = payload };
            const highest = self.observed[0] orelse {
                self.observed[0] = seen;
                return;
            };
            if (view > highest.view) {
                self.observed = .{ seen, highest };
            } else if (view < highest.view) {
                const second = self.observed[1];
                if (second == null or second.?.view < view) self.observed[1] = seen;
            }
            assert(self.observed[1] == null or self.observed[1].?.view < self.observed[0].?.view);
        }

        fn latest_observed(self: *Self) [2]?Observed {
            self.observed_mutex.lockUncancelable(self.io);
            defer self.observed_mutex.unlock(self.io);
            return self.observed;
        }

        /// Beyond commonware: once per proposed view `h`, proposes view `h + 1` over the
        /// proposal below `h`, skipping view `h` (usually notarized, not nullified), with
        /// contents the mock applications accept. Honest validators must refuse it (a missing
        /// nullification); one that notarizes it trips `invalid_notarize_parent`. Without
        /// the relay (or its contents) the proposal would never get past verification.
        fn send_skip_proposal(self: *Self, sender: anytype) void {
            const relay = self.relay orelse return;
            const observed = self.latest_observed();
            const highest = observed[0] orelse return;
            const parent = observed[1] orelse return;
            const target = highest.view + 1;
            if (target <= self.skipped_view) return;
            if (!self.is_faulty_view(target)) return;
            self.skipped_view = target;
            assert(parent.view + 1 < target);
            const round: consensus_types.Round = .new(fuzz_types.epoch, .new(target));
            var nonce: [8]u8 = undefined;
            self.io.random(&nonce);
            var buffer: [contents_max]u8 = undefined;
            var writer: codec.Writer = .init(&buffer);
            round.write(&writer);
            codec.write(Digest, parent.payload, &writer);
            codec.write(u64, std.mem.readInt(u64, &nonce, .little), &writer);
            const contents = writer.written();
            const payload = Sha256.hash(&.{contents});
            const me = self.scheme.me() orelse return;
            const key = self.scheme.participants().as_slice()[me.index().get()];
            relay.broadcast(key, .all, payload, contents);
            const proposal: Proposal = .init(round, .new(parent.view), payload);
            self.send_vote(sender, .all, self.sign_notarize(proposal));
        }

        fn send_proposal(self: *Self, sender: anytype) void {
            if (!self.is_faulty_view(self.current_view())) return;
            const proposal = self.mutated_proposal(self.get_proposal());
            self.send_encoded(sender, .all, Proposal, proposal);
        }

        fn send_random_message(self: *Self, sender: anytype) void {
            if (!self.is_faulty_view(self.current_view())) return;
            var buffer: [255]u8 = undefined;
            self.send(sender, .all, self.random_bytes(&buffer));
        }

        fn send_random_vote(self: *Self, sender: anytype, recipients: Recipients) void {
            if (!self.is_faulty_view(self.current_view())) return;
            const proposal = self.get_proposal();
            switch (message_kind(self.rng())) {
                .notarize => self.send_vote(sender, recipients, self.sign_notarize(
                    self.mutated_proposal(proposal),
                )),
                .finalize => self.send_vote(sender, recipients, self.sign_finalize(
                    self.mutated_proposal(proposal),
                )),
                .nullify => self.send_vote(sender, recipients, self.sign_nullify()),
                .random => {
                    var buffer: [255]u8 = undefined;
                    self.send(sender, recipients, self.random_bytes(&buffer));
                },
            }
        }
    };
}

/// A proposal the relay delivered.
const Observed = struct { view: u64, payload: Digest };

/// The message type a receiver's `try_recv` yields.
fn Received(comptime Pointer: type) type {
    const Receiver = std.meta.Child(Pointer);
    const Return = @typeInfo(@TypeOf(Receiver.try_recv)).@"fn".return_type.?;
    return @typeInfo(Return).error_union.payload;
}

/// `rng.random::<u8>()`.
fn byte(rng: anytype) u8 {
    return @truncate(rng.next_u32());
}

fn message_kind(rng: anytype) fuzz_types.Message {
    return switch (byte(rng) % 4) {
        0 => .notarize,
        1 => .finalize,
        2 => .nullify,
        else => .random,
    };
}

/// One byte of `input` incremented, decremented, inverted, zeroed, or set (commonware
/// `mutate_bytes`); empty input becomes one zero byte. Caller owns the result.
fn mutate_bytes(rng: anytype, input: []const u8, gpa: Allocator) ![]u8 {
    if (input.len == 0) return gpa.dupe(u8, &.{0});
    const result = try gpa.dupe(u8, input);
    const index = sampling.range_less_than(rng, usize, 0, result.len);
    switch (byte(rng) % 5) {
        0 => result[index] +%= 1,
        1 => result[index] -%= 1,
        2 => result[index] ^= 0xff,
        3 => result[index] = 0,
        else => result[index] = 0xff,
    }
    return result;
}
