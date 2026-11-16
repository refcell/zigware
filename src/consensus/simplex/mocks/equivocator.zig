//! A Byzantine leader that sends different proposals to different nodes (commonware
//! `simplex/mocks/equivocator.rs`): after each notarization or finalization it learns of,
//! when it leads the next view, it notarizes one proposal for a random victim and a
//! conflicting one for everyone else, relaying both payloads.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const p2p = @import("p2p");
const consensus_types = @import("../../types.zig");
const types = @import("../types.zig");
const context = @import("../actors/context.zig");
const relay_mod = @import("relay.zig");

const View = consensus_types.View;
const Epoch = consensus_types.Epoch;
const Round = consensus_types.Round;

/// `S` signs, `H` hashes payloads, `P` is the peer key, and `E` is a built elector.
pub fn Equivocator(comptime S: type, comptime H: type, comptime P: type, comptime E: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;
        const Vote = types.Vote(S, D);
        const Certificate = types.Certificate(S, D);
        const Proposal = types.Proposal(D);
        const Relay = relay_mod.Relay(D, P);
        /// Encoded payload contents: a round, a parent digest, and a random u64 (the mock
        /// application's encoding).
        const contents_max = Round.max_encode_size + D.fixed_size + 8;

        gpa: Allocator,
        io: Io,
        scheme: *const S,
        elector: E,
        epoch: Epoch,
        relay: *Relay,
        /// Views whose certificate was already answered (grows for the mock's lifetime, as
        /// in commonware).
        sent: std.AutoHashMapUnmanaged(View, void) = .empty,

        pub fn init(
            gpa: Allocator,
            io: Io,
            scheme: *const S,
            elector: E,
            epoch: Epoch,
            relay: *Relay,
        ) Self {
            assert(scheme.me() != null);
            return .{
                .gpa = gpa,
                .io = io,
                .scheme = scheme,
                .elector = elector,
                .epoch = epoch,
                .relay = relay,
            };
        }

        pub fn deinit(self: *Self) void {
            self.sent.deinit(self.gpa);
            self.* = undefined;
        }

        /// Reads certificates from `certificates` and equivocates on `votes` until the
        /// channel closes or the task is canceled.
        pub fn run(self: *Self, votes: anytype, certificates: anytype) void {
            const cfg = self.scheme.certificate_codec_config();
            // Runs until the network closes or the task is canceled.
            while (true) {
                var message = certificates.recv() catch return;
                defer message.deinit();
                const bytes = message.payload;
                const certificate = codec.decode_cfg(Certificate, self.gpa, bytes, cfg) catch
                    continue;
                defer codec.free(Certificate, self.gpa, certificate);
                // Nullifications are skipped to avoid tracking complexity, as in commonware.
                const view, const parent, const signed = switch (certificate) {
                    .nullification => continue,
                    inline .notarization, .finalization => |*value| .{
                        value.view(),
                        value.proposal.payload,
                        &value.certificate,
                    },
                };
                const entry = self.sent.getOrPut(self.gpa, view) catch return;
                if (entry.found_existing) continue;
                const next: Round = .new(self.epoch, view.next());
                const leader = self.elector.elect(next, elector_input(signed));
                if (leader.get() != self.signer()) continue;
                self.equivocate(votes, next, view, parent);
            }
        }

        fn elector_input(certificate: *const S.Certificate) E.Input {
            if (E.Input == void) return {};
            return certificate;
        }

        fn signer(self: *const Self) u32 {
            const me = self.scheme.me().?;
            assert(me == .signer);
            return me.index().get();
        }

        /// Notarizes proposal A for one random victim and proposal B for every other peer.
        fn equivocate(self: *Self, votes: anytype, round: Round, view: View, parent: D) void {
            const keys = self.scheme.participants().items;
            assert(keys.len > 1);
            const me = self.signer();
            const rng: context.IoRng = .{ .io = self.io };
            // A uniform index among the peers other than this one.
            var victim: u32 = @intCast(rng.next_u64() % (keys.len - 1));
            if (victim >= me) victim += 1;
            assert(victim != me);
            const proposal_a = self.propose(round, view, parent, keys[me]);
            const proposal_b = self.propose(round, view, parent, keys[me]);
            self.send(votes, proposal_a, .{ .one = keys[victim] });
            var others: [64]P = undefined;
            var count: usize = 0;
            for (keys, 0..) |key, index| {
                if (index == me or index == victim) continue;
                others[count] = key;
                count += 1;
            }
            self.send(votes, proposal_b, .{ .some = others[0..count] });
        }

        /// Builds and relays a payload on `parent` (the mock application's encoding).
        fn propose(self: *Self, round: Round, view: View, parent: D, me: P) Proposal {
            const rng: context.IoRng = .{ .io = self.io };
            var buffer: [contents_max]u8 = undefined;
            var writer: codec.Writer = .init(&buffer);
            round.write(&writer);
            codec.write(D, parent, &writer);
            codec.write(u64, rng.next_u64(), &writer);
            const contents = writer.written();
            const digest = H.hash(&.{contents});
            self.relay.broadcast(me, .all, digest, contents);
            assert(round.view.get() == view.get() + 1);
            return .init(round, view, digest);
        }

        fn send(
            self: *Self,
            votes: anytype,
            proposal: Proposal,
            recipients: p2p.Recipients(P),
        ) void {
            const Notarize = @FieldType(Vote, "notarize");
            const signed = Notarize.sign(self.gpa, self.scheme, proposal) catch return;
            const vote: Vote = .{ .notarize = signed.? };
            const bytes = codec.encode(Vote, self.gpa, vote) catch return;
            defer self.gpa.free(bytes);
            const sent = votes.send(recipients, &.{bytes}, true) catch return;
            self.gpa.free(sent);
        }
    };
}
