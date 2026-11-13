//! Types used in simplex (commonware `consensus/src/simplex/types.rs`).
//!
//! Messages are generic over a signing scheme `S` and a digest `D`. Here `S` needs only its
//! wire types: `S.Signature` (fixed-size, carried in attestations) and `S.Certificate`
//! (whose codec config is the config of every certificate-carrying message).
//!
//! - `Proposal(D)`: a round, the parent view, and the payload digest.
//! - Votes: `Notarize(S, D)`, `Nullify(S)`, `Finalize(S, D)`, each with an `Attestation`.
//! - Certificates: `Notarization(S, D)`, `Nullification(S)`, `Finalization(S, D)`.
//! - Faults: `ConflictingNotarize`, `ConflictingFinalize`, `NullifyFinalize`.
//! - Unions: `Vote`, `Certificate`, `Artifact` (storage), and `Activity` (reporting), each a
//!   `u8` tag and the variant (`tagged.zig`).
//! - `Context(D, P)`: what consensus hands the application with a payload.
//! - `Subject(D)`: what a vote or certificate signs.
//!
//! Signing, verification, and assembly come with the scheme implementations.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus_types = @import("../types.zig");
const tagged = @import("tagged.zig");
const cryptography = @import("cryptography");
const namespace_mod = @import("scheme/namespace.zig");

const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const Round = consensus_types.Round;
const Participant = consensus_types.Participant;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;

pub const Attestation = cryptography.certificate.Attestation;

/// commonware's `Attestation::arbitrary`: `Participant::arbitrary`, then the signature.
fn arbitrary_attestation(
    comptime S: type,
    gpa: Allocator,
    u: *Unstructured,
) ArbitraryError!Attestation(S) {
    const signer = Participant.init(u.int(u32));
    const signature = try codec.arbitrary.value(S.Signature, gpa, u);
    return .init(signer, signature);
}

/// Metadata consensus gives the application with a payload: the round, its leader, and the
/// parent (view and digest) the payload builds on.
pub fn Context(comptime D: type, comptime P: type) type {
    return struct {
        const Self = @This();

        round: Round,
        leader: P,
        parent: struct { View, D },

        pub const max_encode_size: usize = Round.max_encode_size + codec.fixed_size(P).? +
            View.max_encode_size + codec.fixed_size(D).?;

        pub fn epoch(self: Self) Epoch {
            return self.round.epoch;
        }

        pub fn view(self: Self) View {
            return self.round.view;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.round == b.round and codec.order(P, a.leader, b.leader) == .eq and
                a.parent[0] == b.parent[0] and codec.order(D, a.parent[1], b.parent[1]) == .eq;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.round.write(writer);
            codec.write(P, self.leader, writer);
            self.parent[0].write(writer);
            codec.write(D, self.parent[1], writer);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.round.encode_size() + codec.fixed_size(P).? +
                self.parent[0].encode_size() + codec.fixed_size(D).?;
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const round = try Round.read(gpa, reader, {});
            const leader = try codec.read(P, gpa, reader);
            const parent_view = try View.read(gpa, reader, {});
            const parent_digest = try codec.read(D, gpa, reader);
            return .{ .round = round, .leader = leader, .parent = .{ parent_view, parent_digest } };
        }
    };
}

/// A proposed payload: the round it is proposed in, the parent's view, and the payload.
/// Orders by round, then parent, then payload (commonware's derived `Ord`).
pub fn Proposal(comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Digest = D;

        round: Round,
        parent: View,
        payload: D,

        pub const max_encode_size: usize = Round.max_encode_size + View.max_encode_size +
            codec.fixed_size(D).?;

        pub fn init(round: Round, parent: View, payload: D) Self {
            return .{ .round = round, .parent = parent, .payload = payload };
        }

        pub fn epoch(self: Self) Epoch {
            return self.round.epoch;
        }

        pub fn view(self: Self) View {
            return self.round.view;
        }

        pub fn order(a: Self, b: Self) std.math.Order {
            const by_round = Round.order(a.round, b.round);
            if (by_round != .eq) return by_round;
            const by_parent = View.order(a.parent, b.parent);
            if (by_parent != .eq) return by_parent;
            return codec.order(D, a.payload, b.payload);
        }

        pub fn eql(a: Self, b: Self) bool {
            return order(a, b) == .eq;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.round.write(writer);
            self.parent.write(writer);
            codec.write(D, self.payload, writer);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.round.encode_size() + self.parent.encode_size() +
                codec.fixed_size(D).?;
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const round = try Round.read(gpa, reader, {});
            const parent = try View.read(gpa, reader, {});
            return init(round, parent, try codec.read(D, gpa, reader));
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const round = try Round.arbitrary(gpa, u);
            const parent = try View.arbitrary(gpa, u);
            return init(round, parent, try codec.arbitrary.value(D, gpa, u));
        }
    };
}

/// What a vote or certificate signs.
pub fn Subject(comptime D: type) type {
    return union(enum) {
        const Self = @This();
        pub const Digest = D;
        pub const Namespace = namespace_mod.Namespace;
        pub const message_max_size: usize = Proposal(D).max_encode_size;

        notarize: *const Proposal(D),
        nullify: Round,
        finalize: *const Proposal(D),

        pub fn view(self: Self) View {
            return switch (self) {
                .notarize, .finalize => |proposal| proposal.round.view,
                .nullify => |round| round.view,
            };
        }

        /// The signed message, written into `buffer`: the encoded proposal, or the encoded
        /// round for nullify.
        pub fn message_to(self: Self, buffer: *[message_max_size]u8) []u8 {
            return switch (self) {
                .notarize, .finalize => |proposal| codec.encode_to(Proposal(D), proposal.*, buffer),
                .nullify => |round| codec.encode_to(Round, round, buffer),
            };
        }

        /// The signed message (`certificate::Subject::message`); the caller frees it.
        pub fn message(self: Self, gpa: Allocator) Allocator.Error![]u8 {
            var buffer: [message_max_size]u8 = undefined;
            const encoded = self.message_to(&buffer);
            assert(encoded.len > 0 and encoded.len <= message_max_size);
            return gpa.dupe(u8, encoded);
        }

        /// The namespace this subject signs under (`certificate::Subject::namespace`).
        pub fn namespace(self: Self, derived: *const Namespace) []const u8 {
            return derived.of(self);
        }
    };
}

const ProposalKind = enum { notarize, finalize };

/// Copies a certificate (`Clone`), deep when it owns memory.
fn clone_certificate(
    comptime S: type,
    gpa: Allocator,
    certificate: *const S.Certificate,
) Allocator.Error!S.Certificate {
    if (comptime !codec.owns_memory(S.Certificate)) return certificate.*;
    return certificate.clone(gpa);
}

/// The attestations of `votes`, which must be non-empty, assembled into a certificate.
fn assemble_votes(
    comptime S: type,
    gpa: Allocator,
    scheme: *const S,
    votes: anytype,
    strategy: anytype,
) (cryptography.certificate.AssemblyError || Allocator.Error)!S.Certificate {
    assert(votes.len > 0);
    const attestations = try gpa.alloc(Attestation(S), votes.len);
    defer gpa.free(attestations);
    for (votes, attestations) |vote, *attestation| attestation.* = vote.attestation;
    assert(attestations.len == votes.len);
    return scheme.assemble(gpa, attestations, strategy);
}

/// A nullify subject in the scheme's own subject type (the round carries no digest).
fn nullify_subject(comptime S: type, round: Round) S.Subject {
    return .{ .nullify = round };
}

/// A vote over a proposal (`Notarize` or `Finalize`): the proposal and an attestation.
fn ProposalVote(comptime S: type, comptime D: type, comptime kind: ProposalKind) type {
    return struct {
        const Self = @This();
        pub const vote_kind = kind;

        proposal: Proposal(D),
        attestation: Attestation(S),

        pub const max_encode_size: usize = Proposal(D).max_encode_size +
            Attestation(S).max_encode_size;

        pub fn round(self: Self) Round {
            return self.proposal.round;
        }

        pub fn epoch(self: Self) Epoch {
            return self.proposal.round.epoch;
        }

        pub fn view(self: Self) View {
            return self.proposal.round.view;
        }

        pub fn signer(self: Self) Participant {
            return self.attestation.signer;
        }

        /// What this vote signs.
        pub fn subject(self: *const Self) Subject(D) {
            return @unionInit(Subject(D), @tagName(kind), &self.proposal);
        }

        /// Signs a vote for `proposal`, or returns null when `scheme` cannot sign.
        pub fn sign(
            gpa: Allocator,
            scheme: *const S,
            proposal: Proposal(D),
        ) Allocator.Error!?Self {
            const signed = @unionInit(Subject(D), @tagName(kind), &proposal);
            const attestation = try scheme.sign(gpa, signed) orelse return null;
            assert(attestation.signer.get() < scheme.participants().len());
            return .{ .proposal = proposal, .attestation = attestation };
        }

        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: *const S,
            strategy: anytype,
        ) Allocator.Error!bool {
            const attestation = &self.attestation;
            return scheme.verify_attestation(gpa, rng, self.subject(), attestation, strategy);
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.proposal.eql(b.proposal) and a.attestation.eql(b.attestation);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.proposal.write(writer);
            self.attestation.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.proposal.encode_size() + self.attestation.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const proposal = try Proposal(D).read(gpa, reader, {});
            return .{ .proposal = proposal, .attestation = try .read(gpa, reader, {}) };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const proposal = try Proposal(D).arbitrary(gpa, u);
            return .{ .proposal = proposal, .attestation = try arbitrary_attestation(S, gpa, u) };
        }
    };
}

/// A vote to notarize a proposal.
pub fn Notarize(comptime S: type, comptime D: type) type {
    return ProposalVote(S, D, .notarize);
}

/// A vote to finalize a proposal.
pub fn Finalize(comptime S: type, comptime D: type) type {
    return ProposalVote(S, D, .finalize);
}

/// A vote to skip (nullify) a round.
pub fn Nullify(comptime S: type) type {
    return struct {
        const Self = @This();

        round: Round,
        attestation: Attestation(S),

        pub const max_encode_size: usize = Round.max_encode_size + Attestation(S).max_encode_size;

        pub fn epoch(self: Self) Epoch {
            return self.round.epoch;
        }

        pub fn view(self: Self) View {
            return self.round.view;
        }

        pub fn signer(self: Self) Participant {
            return self.attestation.signer;
        }

        /// Signs a nullify vote for `round`, or returns null when `scheme` cannot sign.
        pub fn sign(gpa: Allocator, scheme: *const S, round: Round) Allocator.Error!?Self {
            const signed = nullify_subject(S, round);
            const attestation = try scheme.sign(gpa, signed) orelse return null;
            assert(attestation.signer.get() < scheme.participants().len());
            return .{ .round = round, .attestation = attestation };
        }

        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: *const S,
            strategy: anytype,
        ) Allocator.Error!bool {
            const signed = nullify_subject(S, self.round);
            return scheme.verify_attestation(gpa, rng, signed, &self.attestation, strategy);
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.round == b.round and a.attestation.eql(b.attestation);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.round.write(writer);
            self.attestation.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.round.encode_size() + self.attestation.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const round = try Round.read(gpa, reader, {});
            return .{ .round = round, .attestation = try .read(gpa, reader, {}) };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const round = try Round.arbitrary(gpa, u);
            return .{ .round = round, .attestation = try arbitrary_attestation(S, gpa, u) };
        }
    };
}

/// A certificate over a proposal (`Notarization` or `Finalization`).
fn ProposalCertificate(comptime S: type, comptime D: type, comptime kind: ProposalKind) type {
    return struct {
        const Self = @This();
        pub const Cfg = codec.Cfg(S.Certificate);
        pub const certificate_kind = kind;

        proposal: Proposal(D),
        certificate: S.Certificate,

        /// An upper bound for a committee of at most `participants`.
        pub fn max_encode_size_for(participants: u32) usize {
            return S.max_certificate_size(participants) + Proposal(D).max_encode_size;
        }

        pub fn round(self: Self) Round {
            return self.proposal.round;
        }

        pub fn epoch(self: Self) Epoch {
            return self.proposal.round.epoch;
        }

        pub fn view(self: Self) View {
            return self.proposal.round.view;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.proposal.eql(b.proposal) and a.certificate.eql(&b.certificate);
        }

        /// What this certificate signs.
        pub fn subject(self: *const Self) Subject(D) {
            return @unionInit(Subject(D), @tagName(kind), &self.proposal);
        }

        /// Assembles a non-empty list of votes for one proposal (`from_notarizes`,
        /// `from_finalizes`).
        pub fn from_votes(
            gpa: Allocator,
            scheme: *const S,
            votes: []const ProposalVote(S, D, kind),
            strategy: anytype,
        ) (cryptography.certificate.AssemblyError || Allocator.Error)!Self {
            const certificate = try assemble_votes(S, gpa, scheme, votes, strategy);
            return .{ .proposal = votes[0].proposal, .certificate = certificate };
        }

        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: anytype,
            strategy: anytype,
        ) Allocator.Error!bool {
            const certificate = &self.certificate;
            return scheme.verify_certificate(gpa, rng, self.subject(), certificate, strategy);
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            const certificate = try clone_certificate(S, gpa, &self.certificate);
            return .{ .proposal = self.proposal, .certificate = certificate };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.proposal.write(writer);
            codec.write(S.Certificate, self.certificate, writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.proposal.encode_size() +
                codec.encode_size(S.Certificate, self.certificate);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const proposal = try Proposal(D).read(gpa, reader, {});
            const certificate = try codec.read_cfg(S.Certificate, gpa, reader, cfg);
            return .{ .proposal = proposal, .certificate = certificate };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            codec.free(S.Certificate, gpa, self.certificate);
            self.* = undefined;
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const proposal = try Proposal(D).arbitrary(gpa, u);
            const certificate = try codec.arbitrary.value(S.Certificate, gpa, u);
            return .{ .proposal = proposal, .certificate = certificate };
        }
    };
}

/// A quorum of notarize votes for a proposal.
pub fn Notarization(comptime S: type, comptime D: type) type {
    return ProposalCertificate(S, D, .notarize);
}

/// A quorum of finalize votes for a proposal.
pub fn Finalization(comptime S: type, comptime D: type) type {
    return ProposalCertificate(S, D, .finalize);
}

/// A quorum of nullify votes for a round.
pub fn Nullification(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Cfg = codec.Cfg(S.Certificate);

        round: Round,
        certificate: S.Certificate,

        pub fn max_encode_size_for(participants: u32) usize {
            return S.max_certificate_size(participants) + Round.max_encode_size;
        }

        pub fn epoch(self: Self) Epoch {
            return self.round.epoch;
        }

        pub fn view(self: Self) View {
            return self.round.view;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.round == b.round and a.certificate.eql(&b.certificate);
        }

        /// Assembles a non-empty list of nullify votes for one round (`from_nullifies`).
        pub fn from_votes(
            gpa: Allocator,
            scheme: *const S,
            votes: []const Nullify(S),
            strategy: anytype,
        ) (cryptography.certificate.AssemblyError || Allocator.Error)!Self {
            const certificate = try assemble_votes(S, gpa, scheme, votes, strategy);
            return .{ .round = votes[0].round, .certificate = certificate };
        }

        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: anytype,
            strategy: anytype,
        ) Allocator.Error!bool {
            const signed = nullify_subject(S, self.round);
            return scheme.verify_certificate(gpa, rng, signed, &self.certificate, strategy);
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            const certificate = try clone_certificate(S, gpa, &self.certificate);
            return .{ .round = self.round, .certificate = certificate };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.round.write(writer);
            codec.write(S.Certificate, self.certificate, writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.round.encode_size() + codec.encode_size(S.Certificate, self.certificate);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const round = try Round.read(gpa, reader, {});
            const certificate = try codec.read_cfg(S.Certificate, gpa, reader, cfg);
            return .{ .round = round, .certificate = certificate };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            codec.free(S.Certificate, gpa, self.certificate);
            self.* = undefined;
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const round = try Round.arbitrary(gpa, u);
            const certificate = try codec.arbitrary.value(S.Certificate, gpa, u);
            return .{ .round = round, .certificate = certificate };
        }
    };
}

pub const faults = @import("faults.zig");
pub const ConflictingNotarize = faults.ConflictingNotarize;
pub const ConflictingFinalize = faults.ConflictingFinalize;
pub const NullifyFinalize = faults.NullifyFinalize;

/// An individual vote.
pub fn Vote(comptime S: type, comptime D: type) type {
    return union(enum(u8)) {
        const Self = @This();

        notarize: Notarize(S, D),
        nullify: Nullify(S),
        finalize: Finalize(S, D),

        pub const max_encode_size: usize = 1 + @max(
            Notarize(S, D).max_encode_size,
            Nullify(S).max_encode_size,
            Finalize(S, D).max_encode_size,
        );

        pub fn epoch(self: Self) Epoch {
            return tagged.epoch(self);
        }

        pub fn view(self: Self) View {
            return tagged.view(self);
        }

        pub fn eql(a: Self, b: Self) bool {
            return tagged.eql(a, b);
        }

        pub fn signer(self: Self) Participant {
            return switch (self) {
                inline else => |vote| vote.attestation.signer,
            };
        }

        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: *const S,
            strategy: anytype,
        ) Allocator.Error!bool {
            return switch (self.*) {
                inline else => |*vote| vote.verify(gpa, rng, scheme, strategy),
            };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            tagged.write(Self, self, writer);
        }

        pub fn encode_size(self: Self) usize {
            return tagged.encode_size(Self, self);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return tagged.read(Self, "consensus::simplex::Vote", gpa, reader, {});
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            return tagged.arbitrary(Self, gpa, u);
        }
    };
}

/// A certificate assembled from a quorum of votes.
pub fn Certificate(comptime S: type, comptime D: type) type {
    return union(enum(u8)) {
        const Self = @This();
        pub const Cfg = codec.Cfg(S.Certificate);

        notarization: Notarization(S, D),
        nullification: Nullification(S),
        finalization: Finalization(S, D),

        pub fn max_encode_size_for(participants: u32) usize {
            const notarization = Notarization(S, D).max_encode_size_for(participants);
            const nullification = Nullification(S).max_encode_size_for(participants);
            return 1 + @max(notarization, nullification);
        }

        pub fn epoch(self: Self) Epoch {
            return tagged.epoch(self);
        }

        pub fn view(self: Self) View {
            return tagged.view(self);
        }

        pub fn eql(a: Self, b: Self) bool {
            return tagged.eql(a, b);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            tagged.write(Self, self, writer);
        }

        pub fn encode_size(self: Self) usize {
            return tagged.encode_size(Self, self);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            return tagged.read(Self, "consensus::simplex::Certificate", gpa, reader, cfg);
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            tagged.deinit(Self, self, gpa);
        }

        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: anytype,
            strategy: anytype,
        ) Allocator.Error!bool {
            return switch (self.*) {
                inline else => |*certificate| certificate.verify(gpa, rng, scheme, strategy),
            };
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return switch (self.*) {
                inline else => |*certificate, tag| @unionInit(
                    Self,
                    @tagName(tag),
                    try certificate.clone(gpa),
                ),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            return tagged.arbitrary(Self, gpa, u);
        }
    };
}

/// A local certification outcome for a notarized round (`Artifact::Certification`).
pub const Certification = struct {
    round: Round,
    certified: bool,

    pub const max_encode_size: usize = Round.max_encode_size + 1;

    pub fn epoch(self: Certification) Epoch {
        return self.round.epoch;
    }

    pub fn view(self: Certification) View {
        return self.round.view;
    }

    pub fn eql(a: Certification, b: Certification) bool {
        return a.round == b.round and a.certified == b.certified;
    }

    pub fn write(self: Certification, writer: *codec.Writer) void {
        self.round.write(writer);
        codec.write(bool, self.certified, writer);
    }

    pub fn encode_size(self: Certification) usize {
        return self.round.encode_size() + 1;
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Certification {
        const round = try Round.read(gpa, reader, {});
        return .{ .round = round, .certified = try codec.read(bool, gpa, reader) };
    }

    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Certification {
        const round = try Round.arbitrary(gpa, u);
        return .{ .round = round, .certified = u.boolean() };
    }
};

/// Every consensus artifact (votes, certificates, certification outcomes), for storage.
pub fn Artifact(comptime S: type, comptime D: type) type {
    return union(enum(u8)) {
        const Self = @This();
        pub const Cfg = codec.Cfg(S.Certificate);

        notarize: Notarize(S, D),
        notarization: Notarization(S, D),
        certification: Certification,
        nullify: Nullify(S),
        nullification: Nullification(S),
        finalize: Finalize(S, D),
        finalization: Finalization(S, D),

        pub fn from_vote(vote: Vote(S, D)) Self {
            return switch (vote) {
                .notarize => |v| .{ .notarize = v },
                .nullify => |v| .{ .nullify = v },
                .finalize => |v| .{ .finalize = v },
            };
        }

        pub fn from_certificate(certificate: Certificate(S, D)) Self {
            return switch (certificate) {
                .notarization => |v| .{ .notarization = v },
                .nullification => |v| .{ .nullification = v },
                .finalization => |v| .{ .finalization = v },
            };
        }

        pub fn epoch(self: Self) Epoch {
            return tagged.epoch(self);
        }

        pub fn view(self: Self) View {
            return tagged.view(self);
        }

        pub fn eql(a: Self, b: Self) bool {
            return tagged.eql(a, b);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            tagged.write(Self, self, writer);
        }

        pub fn encode_size(self: Self) usize {
            return tagged.encode_size(Self, self);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            return tagged.read(Self, "consensus::simplex::Artifact", gpa, reader, cfg);
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            tagged.deinit(Self, self, gpa);
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            return tagged.arbitrary(Self, gpa, u);
        }
    };
}

/// Activity reported to the application: votes, certificates, certifications, and faults.
/// Reports are not exhaustive (votes below the activity window are dropped unreported).
pub fn Activity(comptime S: type, comptime D: type) type {
    return union(enum(u8)) {
        const Self = @This();
        pub const Cfg = codec.Cfg(S.Certificate);

        notarize: Notarize(S, D),
        notarization: Notarization(S, D),
        /// A notarization that was certified locally.
        certification: Notarization(S, D),
        nullify: Nullify(S),
        nullification: Nullification(S),
        finalize: Finalize(S, D),
        finalization: Finalization(S, D),
        conflicting_notarize: ConflictingNotarize(S, D),
        conflicting_finalize: ConflictingFinalize(S, D),
        nullify_finalize: NullifyFinalize(S, D),

        /// Whether the activity was verified by consensus before it was reported (only
        /// certificates are).
        pub fn verified(self: Self) bool {
            return switch (self) {
                .notarization, .certification, .nullification, .finalization => true,
                else => false,
            };
        }

        pub fn epoch(self: Self) Epoch {
            return tagged.epoch(self);
        }

        pub fn view(self: Self) View {
            return tagged.view(self);
        }

        pub fn eql(a: Self, b: Self) bool {
            return tagged.eql(a, b);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            tagged.write(Self, self, writer);
        }

        pub fn encode_size(self: Self) usize {
            return tagged.encode_size(Self, self);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            return tagged.read(Self, "consensus::simplex::Activity", gpa, reader, cfg);
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            tagged.deinit(Self, self, gpa);
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            return tagged.arbitrary(Self, gpa, u);
        }
    };
}

/// Items keyed by signer, at most one per signer, for a committee of `participants`
/// (commonware `AttributableMap`). Slots are allocated on the first insert.
pub fn AttributableMap(comptime T: type) type {
    return struct {
        const Self = @This();

        participants: u32,
        data: []?T = &.{},
        added: u32 = 0,

        pub fn init(participants: u32) Self {
            return .{ .participants = participants };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.data);
            self.* = undefined;
        }

        /// Drops every item and releases the slots.
        pub fn clear(self: *Self, gpa: Allocator) void {
            gpa.free(self.data);
            self.data = &.{};
            self.added = 0;
        }

        /// Inserts `item` under its signer. Returns false when the signer is out of range or
        /// already has an item.
        pub fn insert(self: *Self, gpa: Allocator, item: T) Allocator.Error!bool {
            const index = item.signer().get();
            if (index >= self.participants) return false;
            if (self.data.len == 0) {
                self.data = try gpa.alloc(?T, self.participants);
                @memset(self.data, null);
            }
            assert(self.data.len == self.participants);
            if (self.data[index] != null) return false;
            self.data[index] = item;
            self.added += 1;
            assert(self.added <= self.participants);
            return true;
        }

        pub fn len(self: Self) u32 {
            return self.added;
        }

        pub fn is_empty(self: Self) bool {
            return self.added == 0;
        }

        pub fn get(self: *const Self, signer: Participant) ?*const T {
            if (signer.get() >= self.data.len) return null;
            if (self.data[signer.get()]) |*item| return item;
            return null;
        }

        /// Items in signer order.
        pub fn iterator(self: *const Self) Iterator {
            return .{ .data = self.data };
        }

        pub const Iterator = struct {
            data: []const ?T,
            index: usize = 0,

            pub fn next(it: *Iterator) ?*const T {
                while (it.index < it.data.len) {
                    defer it.index += 1;
                    if (it.data[it.index]) |*item| return item;
                }
                return null;
            }
        };
    };
}

test {
    _ = @import("types_test.zig");
}
