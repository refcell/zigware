//! Lazy vote verification and certificate construction for one round (commonware
//! `actors/batcher/verifier.rs`).
//!
//! Votes wait unverified until enough of them could form a quorum. Then the batch is
//! assembled optimistically (one certificate check instead of one per vote); when that
//! fails, the votes are verified individually to find the bad ones. Votes the batcher signed
//! itself arrive verified.
//!
//! Commonware offloads construction to the strategy's thread pool; here it runs inline and
//! the scheme operations take the strategy directly.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");

const Participant = consensus_types.Participant;
const Round = consensus_types.Round;
const Attestation = cryptography.certificate.Attestation;

/// The result of one construction attempt.
pub fn Batch(comptime C: type) type {
    return struct {
        const Self = @This();

        /// Votes verified by this attempt.
        processed: usize,
        /// Signers whose votes failed verification, sorted.
        invalid: []Participant,
        certificate: ?C,
        /// Whether optimistic assembly failed and fell back to per-vote verification.
        fallback: bool,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.invalid);
            if (self.certificate) |*certificate| certificate.deinit(gpa);
            self.* = undefined;
        }
    };
}

/// Attestations toward one certificate, split by whether they are verified.
fn Certification(comptime Context: type, comptime S: type) type {
    return struct {
        const Self = @This();
        const Entry = struct { context: Context, attestation: Attestation(S) };

        quorum: u32,
        complete: bool = false,
        pending: std.ArrayList(Entry) = .empty,
        verified: std.ArrayList(Entry) = .empty,

        fn init(quorum: u32) Self {
            assert(quorum > 0);
            return .{ .quorum = quorum };
        }

        fn deinit(self: *Self, gpa: Allocator) void {
            assert(!self.complete or self.pending.items.len == 0);
            self.pending.deinit(gpa);
            self.verified.deinit(gpa);
            self.* = undefined;
        }

        fn add(
            self: *Self,
            gpa: Allocator,
            context: Context,
            attestation: Attestation(S),
            is_verified: bool,
        ) Allocator.Error!void {
            if (self.complete) return;
            const list = if (is_verified) &self.verified else &self.pending;
            if (list.capacity == 0) {
                const batchable = is_verified or S.is_batchable();
                const room = self.quorum -| @as(u32, @intCast(self.verified.items.len));
                try list.ensureTotalCapacityPrecise(gpa, if (batchable) @max(room, 1) else 1);
            }
            try list.append(gpa, .{ .context = context, .attestation = attestation });
            assert(list.items.len > 0);
        }

        fn has_constructable_quorum(self: *const Self) bool {
            return !self.complete and self.verified.items.len >= self.quorum;
        }

        fn should_construct(self: *const Self) bool {
            if (self.complete) return false;
            const verified = self.verified.items.len;
            const pending = self.pending.items.len;
            if (verified >= self.quorum) return true;
            if (pending == 0) return false;
            return !S.is_batchable() or verified + pending >= self.quorum;
        }

        fn mark_complete(self: *Self, gpa: Allocator) void {
            self.pending.clearAndFree(gpa);
            self.verified.clearAndFree(gpa);
            self.complete = true;
            assert(!self.should_construct());
        }

        /// Keeps only attestations whose context equals `context`.
        fn retain(self: *Self, context: Context) void {
            for ([_]*std.ArrayList(Entry){ &self.pending, &self.verified }) |list| {
                var kept: usize = 0;
                for (list.items) |entry| {
                    if (!entry.context.eql(context)) continue;
                    list.items[kept] = entry;
                    kept += 1;
                }
                assert(kept <= list.items.len);
                list.shrinkRetainingCapacity(kept);
            }
        }

        fn attestations(gpa: Allocator, entries: []const Entry) ![]Attestation(S) {
            const result = try gpa.alloc(Attestation(S), entries.len);
            for (entries, result) |entry, *attestation| attestation.* = entry.attestation;
            assert(result.len == entries.len);
            return result;
        }
    };
}

/// What the round knows about its proposal.
pub fn ProposalState(comptime D: type) type {
    return union(enum) {
        const Self = @This();

        unknown,
        /// From the leader's own notarize vote.
        leader: types.Proposal(D),
        /// From a certificate (or our own finalize vote): authoritative.
        certificate: types.Proposal(D),

        pub fn proposal(self: *const Self) ?*const types.Proposal(D) {
            return switch (self.*) {
                .unknown => null,
                .leader, .certificate => |*known| known,
            };
        }

        /// Moves to `next` when it is an upgrade; returns the new proposal when it changed.
        fn update(self: *Self, next: Self) ?*const types.Proposal(D) {
            const allowed = switch (self.*) {
                .unknown => next != .unknown,
                .leader => next == .certificate,
                .certificate => false,
            };
            if (!allowed) return null;
            const before = self.proposal();
            const changed = before == null or !before.?.eql(next.proposal().?.*);
            self.* = next;
            assert(self.* != .unknown);
            return if (changed) self.proposal().? else null;
        }
    };
}

pub const ProposalUpdate = struct {
    changed: bool,
    /// Whether a different proposal was known before.
    replaced: bool,
};

pub fn Verifier(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const Proposal = types.Proposal(D);
        const Certificate = types.Certificate(S, D);
        pub const Kind = std.meta.Tag(Certificate);

        scheme: *const S,
        round: Round,
        leader_index: ?Participant = null,
        proposal_state: ProposalState(D) = .unknown,
        notarize: Certification(Proposal, S),
        nullify: Certification(Round, S),
        finalize: Certification(Proposal, S),

        pub fn init(round: Round, scheme: *const S, quorum: u32) Self {
            assert(quorum > 0);
            assert(quorum <= scheme.participants().len());
            return .{
                .scheme = scheme,
                .round = round,
                .notarize = .init(quorum),
                .nullify = .init(quorum),
                .finalize = .init(quorum),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.notarize.deinit(gpa);
            self.nullify.deinit(gpa);
            self.finalize.deinit(gpa);
            self.* = undefined;
        }

        pub fn participants(self: *const Self) @TypeOf(self.scheme.participants()) {
            return self.scheme.participants();
        }

        pub fn leader(self: *const Self) ?Participant {
            return self.leader_index;
        }

        pub fn proposal(self: *const Self) ?*const Proposal {
            return self.proposal_state.proposal();
        }

        pub fn has_certificate(self: *const Self, kind: Kind) bool {
            return switch (kind) {
                .notarization => self.notarize.complete,
                .nullification => self.nullify.complete,
                .finalization => self.finalize.complete,
            };
        }

        pub fn record_certificate(self: *Self, gpa: Allocator, kind: Kind) void {
            switch (kind) {
                .notarization => self.notarize.mark_complete(gpa),
                .nullification => self.nullify.mark_complete(gpa),
                .finalization => self.finalize.mark_complete(gpa),
            }
            assert(self.has_certificate(kind));
        }

        fn try_set_proposal_from_leader(self: *Self, notarize: *const types.Notarize(S, D)) void {
            const leader_index = self.leader_index orelse return;
            if (leader_index.get() != notarize.signer().get()) return;
            _ = self.set_proposal(.{ .leader = notarize.proposal });
        }

        /// Upgrades the known proposal, dropping attestations for any other proposal.
        pub fn set_proposal(self: *Self, next: ProposalState(D)) ProposalUpdate {
            const replaced = self.proposal() != null;
            const updated = self.proposal_state.update(next) orelse {
                return .{ .changed = false, .replaced = false };
            };
            self.notarize.retain(updated.*);
            self.finalize.retain(updated.*);
            assert(self.proposal() != null);
            return .{ .changed = true, .replaced = replaced };
        }

        pub fn add(self: *Self, gpa: Allocator, vote: types.Vote(S, D), verified: bool) !void {
            switch (vote) {
                .notarize => |*notarize| {
                    self.try_set_proposal_from_leader(notarize);
                    if (self.proposal()) |known| if (!known.eql(notarize.proposal)) return;
                    const attestation = notarize.attestation;
                    try self.notarize.add(gpa, notarize.proposal, attestation, verified);
                },
                .nullify => |nullify| {
                    try self.nullify.add(gpa, nullify.round, nullify.attestation, verified);
                },
                .finalize => |finalize| {
                    if (self.proposal()) |known| if (!known.eql(finalize.proposal)) return;
                    const attestation = finalize.attestation;
                    try self.finalize.add(gpa, finalize.proposal, attestation, verified);
                },
            }
        }

        /// Sets the round's leader; `notarize` is the leader's vote if one arrived first.
        pub fn set_leader(
            self: *Self,
            leader_index: Participant,
            notarize: ?*const types.Notarize(S, D),
        ) void {
            if (self.leader_index) |existing| {
                assert(existing.get() == leader_index.get()); // Leader changed within round.
                return;
            }
            self.leader_index = leader_index;
            const vote = notarize orelse return;
            assert(vote.signer().get() == leader_index.get());
            self.try_set_proposal_from_leader(vote);
        }

        pub fn try_construct_notarization(
            self: *Self,
            gpa: Allocator,
            rng: anytype,
            strategy: anytype,
        ) !?Batch(Certificate) {
            if (self.proposal_state == .unknown and !self.notarize.has_constructable_quorum()) {
                return null;
            }
            return construct(.notarization, &self.notarize, self.scheme, gpa, rng, strategy);
        }

        pub fn try_construct_nullification(
            self: *Self,
            gpa: Allocator,
            rng: anytype,
            strategy: anytype,
        ) !?Batch(Certificate) {
            return construct(.nullification, &self.nullify, self.scheme, gpa, rng, strategy);
        }

        pub fn try_construct_finalization(
            self: *Self,
            gpa: Allocator,
            rng: anytype,
            strategy: anytype,
        ) !?Batch(Certificate) {
            if (self.proposal_state == .unknown and !self.finalize.has_constructable_quorum()) {
                return null;
            }
            return construct(.finalization, &self.finalize, self.scheme, gpa, rng, strategy);
        }

        fn Context(comptime kind: Kind) type {
            return if (kind == .nullification) Round else Proposal;
        }

        fn subject_of(comptime kind: Kind, context: *const Context(kind)) types.Subject(D) {
            return switch (kind) {
                .notarization => .{ .notarize = context },
                .nullification => .{ .nullify = context.* },
                .finalization => .{ .finalize = context },
            };
        }

        fn wrap(
            comptime kind: Kind,
            context: Context(kind),
            certificate: S.Certificate,
        ) Certificate {
            return switch (kind) {
                .notarization => .{ .notarization = .{
                    .proposal = context,
                    .certificate = certificate,
                } },
                .nullification => .{ .nullification = .{
                    .round = context,
                    .certificate = certificate,
                } },
                .finalization => .{ .finalization = .{
                    .proposal = context,
                    .certificate = certificate,
                } },
            };
        }

        fn construct(
            comptime kind: Kind,
            certification: *Certification(Context(kind), S),
            scheme: *const S,
            gpa: Allocator,
            rng: anytype,
            strategy: anytype,
        ) !?Batch(Certificate) {
            if (!certification.should_construct()) return null;
            const quorum = certification.quorum;
            if (certification.verified.items.len >= quorum) {
                certification.pending.clearRetainingCapacity();
            }
            const processed = certification.pending.items.len;
            const total = processed + certification.verified.items.len;
            assert(total > 0);
            const first = if (certification.verified.items.len > 0)
                certification.verified.items[0]
            else
                certification.pending.items[0];
            const context = first.context;
            const subject = subject_of(kind, &context);
            const Cert = Certification(Context(kind), S);
            const pending = try Cert.attestations(gpa, certification.pending.items);
            defer gpa.free(pending);
            const verified = try Cert.attestations(gpa, certification.verified.items);
            defer gpa.free(verified);
            var fallback = false;
            var result = if (total >= quorum) result: {
                const assembled = try scheme.optimistic_assemble(
                    gpa,
                    rng,
                    subject,
                    pending,
                    verified,
                    strategy,
                );
                switch (assembled) {
                    .certificate => |certificate| {
                        certification.mark_complete(gpa);
                        return .{
                            .processed = processed,
                            .invalid = &.{},
                            .certificate = wrap(kind, context, certificate),
                            .fallback = false,
                        };
                    },
                    .verification => {
                        fallback = true;
                        break :result assembled.verification;
                    },
                }
            } else try scheme.verify_attestations(gpa, rng, subject, pending, strategy);
            defer gpa.free(result.verified);
            certification.pending.clearRetainingCapacity();
            return finish(kind, certification, scheme, gpa, context, verified, &result, .{
                .processed = processed,
                .fallback = fallback,
                .strategy = strategy,
            });
        }

        fn finish(
            comptime kind: Kind,
            certification: *Certification(Context(kind), S),
            scheme: *const S,
            gpa: Allocator,
            context: Context(kind),
            prior: []const Attestation(S),
            result: *cryptography.certificate.Verification(S),
            options: anytype,
        ) !?Batch(Certificate) {
            const invalid = result.invalid;
            errdefer gpa.free(invalid);
            var certificate: ?Certificate = null;
            if (prior.len + result.verified.len >= certification.quorum) {
                const combined = try std.mem.concat(
                    gpa,
                    Attestation(S),
                    &.{ prior, result.verified },
                );
                defer gpa.free(combined);
                const assembled = scheme.assemble(gpa, combined, options.strategy) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    @panic("verified quorum must assemble");
                };
                certificate = wrap(kind, context, assembled);
                certification.mark_complete(gpa);
            } else {
                for (result.verified) |attestation| {
                    try certification.verified.append(gpa, .{
                        .context = context,
                        .attestation = attestation,
                    });
                }
            }
            return .{
                .processed = options.processed,
                .invalid = invalid,
                .certificate = certificate,
                .fallback = options.fallback,
            };
        }
    };
}

test {
    _ = @import("verifier_test.zig");
}
