//! Attributable faults (commonware `simplex::types` `ConflictingNotarize`,
//! `ConflictingFinalize`, `NullifyFinalize`): two signed messages from one signer in one round
//! that an honest participant never produces together.
//!
//! `init` asserts the evidence is well formed; `read` rejects malformed evidence as
//! `Invalid`. Commonware's `Arbitrary` impls do neither, so `arbitrary` builds the pair as
//! drawn (used only to encode conformance values).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus_types = @import("../types.zig");
const types = @import("types.zig");

const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const Participant = consensus_types.Participant;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;

/// Two votes of kind `V` (notarize or finalize) for different proposals in one round.
fn Conflicting(comptime V: type, comptime context: []const u8) type {
    return struct {
        const Self = @This();

        first: V,
        second: V,

        pub fn init(first: V, second: V) Self {
            assert(first.round() == second.round());
            assert(first.signer().get() == second.signer().get());
            assert(!first.proposal.eql(second.proposal));
            return .{ .first = first, .second = second };
        }

        fn valid(first: V, second: V) bool {
            return first.signer().get() == second.signer().get() and
                first.round() == second.round() and
                !first.proposal.eql(second.proposal);
        }

        pub fn signer(self: Self) Participant {
            return self.first.signer();
        }

        /// Whether both conflicting signatures are valid, proving Byzantine behavior.
        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: anytype,
            strategy: anytype,
        ) Allocator.Error!bool {
            if (!try self.first.verify(gpa, rng, scheme, strategy)) return false;
            return self.second.verify(gpa, rng, scheme, strategy);
        }

        pub fn epoch(self: Self) Epoch {
            return self.first.epoch();
        }

        pub fn view(self: Self) View {
            return self.first.view();
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.first.eql(b.first) and a.second.eql(b.second);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.first.write(writer);
            self.second.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.first.encode_size() + self.second.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const first = try V.read(gpa, reader, {});
            const second = try V.read(gpa, reader, {});
            if (!valid(first, second)) return reader.invalid(context, invalid_message);
            return .{ .first = first, .second = second };
        }

        const invalid_message = if (V.vote_kind == .notarize)
            "invalid conflicting notarize"
        else
            "invalid conflicting finalize";

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const first = try V.arbitrary(gpa, u);
            return .{ .first = first, .second = try V.arbitrary(gpa, u) };
        }
    };
}

/// Two notarize votes from one signer for different proposals in one round.
pub fn ConflictingNotarize(comptime S: type, comptime D: type) type {
    return Conflicting(types.Notarize(S, D), "consensus::simplex::ConflictingNotarize");
}

/// Two finalize votes from one signer for different proposals in one round.
pub fn ConflictingFinalize(comptime S: type, comptime D: type) type {
    return Conflicting(types.Finalize(S, D), "consensus::simplex::ConflictingFinalize");
}

/// A nullify and a finalize vote from one signer in one round.
pub fn NullifyFinalize(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const NullifyVote = types.Nullify(S);
        const FinalizeVote = types.Finalize(S, D);

        nullify: NullifyVote,
        finalize: FinalizeVote,

        pub fn init(nullify: NullifyVote, finalize: FinalizeVote) Self {
            assert(nullify.round == finalize.round());
            assert(nullify.signer().get() == finalize.signer().get());
            return .{ .nullify = nullify, .finalize = finalize };
        }

        pub fn signer(self: Self) Participant {
            return self.nullify.signer();
        }

        /// Whether both signatures are valid, proving Byzantine behavior.
        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: anytype,
            strategy: anytype,
        ) Allocator.Error!bool {
            if (!try self.nullify.verify(gpa, rng, scheme, strategy)) return false;
            return self.finalize.verify(gpa, rng, scheme, strategy);
        }

        pub fn epoch(self: Self) Epoch {
            return self.nullify.epoch();
        }

        pub fn view(self: Self) View {
            return self.nullify.view();
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.nullify.eql(b.nullify) and a.finalize.eql(b.finalize);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.nullify.write(writer);
            self.finalize.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.nullify.encode_size() + self.finalize.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const nullify = try NullifyVote.read(gpa, reader, {});
            const finalize = try FinalizeVote.read(gpa, reader, {});
            const same_signer = nullify.signer().get() == finalize.signer().get();
            if (!same_signer or nullify.round != finalize.round()) {
                const context = "consensus::simplex::NullifyFinalize";
                return reader.invalid(context, "mismatched signatures");
            }
            return .{ .nullify = nullify, .finalize = finalize };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const nullify = try NullifyVote.arbitrary(gpa, u);
            return .{ .nullify = nullify, .finalize = try FinalizeVote.arbitrary(gpa, u) };
        }
    };
}
