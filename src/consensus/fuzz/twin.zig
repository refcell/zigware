//! How a twin's two halves share one identity's channels (commonware `consensus/fuzz/src/
//! lib.rs` `run_with_twin_mutator`): for each view's term, the participants split in two at
//! `term_start % n` (simplex `twins.view_masks`). Votes and certificates the primary half
//! sends reach only the first group and those of the secondary half only the second;
//! inbound votes and certificates reach the half of their sender's group. Resolver traffic
//! passes through unchanged, to both halves. Messages that do not decode keep their
//! recipients on the way out and reach neither half on the way in.
//!
//! The engine takes one sender type for all three channels, so one `Forwarder` (and one
//! `Router`) type serves every channel and switches on its `Kind`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const consensus_types = @import("../types.zig");
const simplex = @import("../simplex/root.zig");
const fuzz_types = @import("types.zig");

const Key = cryptography.ed25519.PublicKey;
const Recipients = p2p.Recipients(Key);
const SplitOrigin = p2p.simulated.SplitOrigin;
const SplitTarget = p2p.simulated.SplitTarget;
const View = consensus_types.View;
const TermLength = consensus_types.TermLength;
const twins = simplex.mocks.twins;

/// Which channel a forwarder or router serves.
pub const Kind = enum { votes, certificates, resolver };

/// The split shared by every channel of every twin. Must not move while channels use it.
pub fn Splitter(comptime S: type) type {
    return struct {
        const Self = @This();
        const Vote = simplex.types.Vote(S, fuzz_types.Digest);
        const Certificate = simplex.types.Certificate(S, fuzz_types.Digest);

        gpa: Allocator,
        /// The participants, sorted (the fixture's order).
        keys: []const Key,
        term_length: TermLength,
        certificate_cfg: codec.Cfg(S.Certificate),

        /// The view of a vote or certificate, or null when `bytes` does not decode (and for
        /// resolver traffic).
        fn view_of(self: *const Self, kind: Kind, bytes: []const u8) ?View {
            switch (kind) {
                .votes => {
                    const vote = codec.decode(Vote, self.gpa, bytes) catch return null;
                    defer codec.free(Vote, self.gpa, vote);
                    return vote.view();
                },
                .certificates => {
                    var certificate = codec.decode_cfg(
                        Certificate,
                        self.gpa,
                        bytes,
                        self.certificate_cfg,
                    ) catch return null;
                    defer certificate.deinit(self.gpa);
                    return certificate.view();
                },
                .resolver => return null,
            }
        }

        /// commonware `view_partitions`: the participants before and from `term_start % n`.
        fn groups(self: *const Self, view: View) struct { []const Key, []const Key } {
            const masks = twins.view_masks(view, self.term_length, self.keys.len);
            const split: usize = @popCount(masks.primary);
            // The primary group is a prefix of the participants.
            assert(masks.primary == (@as(u64, 1) << @intCast(split)) - 1);
            assert(masks.primary | masks.secondary == (@as(u64, 1) << @intCast(self.keys.len)) - 1);
            return .{ self.keys[0..split], self.keys[split..] };
        }

        pub fn forwarder(self: *const Self, kind: Kind) Forwarder {
            return .{ .splitter = self, .kind = kind };
        }

        pub fn router(self: *const Self, kind: Kind) Router {
            return .{ .splitter = self, .kind = kind };
        }

        pub const Forwarder = struct {
            splitter: *const Self,
            kind: Kind,

            pub fn forward(
                f: Forwarder,
                origin: SplitOrigin,
                recipients: Recipients,
                message: []const u8,
            ) ?Recipients {
                const view = f.splitter.view_of(f.kind, message) orelse return recipients;
                const primary, const secondary = f.splitter.groups(view);
                return .{ .some = switch (origin) {
                    .primary => primary,
                    .secondary => secondary,
                } };
            }
        };

        pub const Router = struct {
            splitter: *const Self,
            kind: Kind,

            pub fn route(r: Router, message: *const p2p.Message(Key)) SplitTarget {
                if (r.kind == .resolver) return .both;
                const view = r.splitter.view_of(r.kind, message.payload) orelse return .none;
                const keys = r.splitter.keys;
                // Proof: the simulated network only delivers from registered participants.
                const sender = for (keys, 0..) |key, index| {
                    if (key.order(message.peer) == .eq) break index;
                } else unreachable;
                return twins.view_route(view, r.splitter.term_length, sender, keys.len);
            }
        };
    };
}

const testing = std.testing;
const utils = @import("utils");

test "twin halves split votes at the term start" {
    const gpa = testing.allocator;
    const S = simplex.scheme.ed25519.Scheme(fuzz_types.Digest);
    var rng = utils.rng.test_rng();
    var fixture = try simplex.scheme.ed25519.fixture(fuzz_types.Digest, gpa, &rng, "twin", 4);
    defer fixture.deinit(gpa);
    const splitter: Splitter(S) = .{
        .gpa = gpa,
        .keys = fixture.participants,
        .term_length = .one,
        .certificate_cfg = fixture.verifier.certificate_codec_config(),
    };
    // View 6 splits 4 participants at 6 % 4 = 2.
    const Nullify = simplex.types.Nullify(S);
    const nullify = (try Nullify.sign(gpa, &fixture.schemes[3], .new(fuzz_types.epoch, .new(6)))).?;
    const Vote = simplex.types.Vote(S, fuzz_types.Digest);
    const bytes = try codec.encode(Vote, gpa, .{ .nullify = nullify });
    defer gpa.free(bytes);
    const votes = splitter.forwarder(.votes);
    const primary = votes.forward(.primary, .all, bytes).?;
    try testing.expectEqualSlices(Key, fixture.participants[0..2], primary.some);
    const secondary = votes.forward(.secondary, .all, bytes).?;
    try testing.expectEqualSlices(Key, fixture.participants[2..], secondary.some);
    // Undecodable messages keep their recipients; resolver traffic always does.
    try testing.expectEqual(Recipients.all, votes.forward(.primary, .all, "junk").?);
    const resolver = splitter.forwarder(.resolver);
    try testing.expectEqual(Recipients.all, resolver.forward(.primary, .all, bytes).?);
    // Inbound votes reach the half of their sender's group.
    for (fixture.participants, 0..) |peer, index| {
        const message: p2p.Message(Key) = .{ .peer = peer, .payload = bytes };
        const expected: SplitTarget = if (index < 2) .primary else .secondary;
        try testing.expectEqual(expected, splitter.router(.votes).route(&message));
        try testing.expectEqual(SplitTarget.both, splitter.router(.resolver).route(&message));
        const junk: p2p.Message(Key) = .{ .peer = peer, .payload = "junk" };
        try testing.expectEqual(SplitTarget.none, splitter.router(.votes).route(&junk));
    }
}
