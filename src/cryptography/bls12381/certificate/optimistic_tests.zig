//! Tests of the shared `optimistic_assemble` on the BLS12-381 threshold and multisig schemes
//! (commonware `cryptography/src/certificate.rs` tests: `Recording`, `RecordingCalls`, and
//! the optimistic assembly tests that count the scheme calls it makes).

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const parallel = @import("parallel");
const base = @import("../../certificate.zig");
const ed25519 = @import("../../ed25519.zig");
const primitives = @import("../primitives/root.zig");
const threshold = @import("threshold.zig");
const multisig = @import("multisig.zig");
const TestSubject = @import("threshold_tests.zig").TestSubject;

const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const MinPk = primitives.MinPk;
const MinSig = primitives.MinSig;
const Private = primitives.group.Private;
const ops = primitives.ops;
const sequential = parallel.sequential;
const gpa = testing.allocator;

const subject: TestSubject = .{ .bytes = "subject" };
const other_subject: TestSubject = .{ .bytes = "other-subject" };

const threshold_namespace = "_COMMONWARE_CRYPTOGRAPHY_CERTIFICATE_THRESHOLD_OPTIMISTIC_ASSEMBLE";
const multisig_namespace = "_COMMONWARE_CRYPTOGRAPHY_CERTIFICATE_MULTISIG_OPTIMISTIC_ASSEMBLE";
const multisig_pop_namespace =
    "_COMMONWARE_CRYPTOGRAPHY_CERTIFICATE_MULTISIG_OPTIMISTIC_ASSEMBLE_POP";

fn Threshold(comptime V: type) type {
    return threshold.Scheme(TestSubject, N3f1, ed25519.PublicKey, V);
}

fn Multisig(comptime V: type) type {
    return multisig.Scheme(TestSubject, N3f1, ed25519.PublicKey, V);
}

/// commonware's `RecordingCalls`: the signer lists passed to attestation verification, and
/// how many times the scheme assembled and verified a certificate.
const Calls = struct {
    attestations: std.ArrayList([]Participant) = .empty,
    assemblies: u32 = 0,
    certificates: u32 = 0,

    fn record(self: *Calls, signers: []Participant) Allocator.Error!void {
        errdefer gpa.free(signers);
        try self.attestations.append(gpa, signers);
    }

    fn reset(self: *Calls) void {
        for (self.attestations.items) |signers| gpa.free(signers);
        self.attestations.clearRetainingCapacity();
        self.assemblies = 0;
        self.certificates = 0;
    }

    fn deinit(self: *Calls) void {
        self.reset();
        self.attestations.deinit(gpa);
        self.* = undefined;
    }

    /// Asserts the recorded signer lists equal `expected`.
    fn expect_attestations(self: *const Calls, expected: []const []const u32) !void {
        try testing.expectEqual(expected.len, self.attestations.items.len);
        for (expected, self.attestations.items) |want, got| {
            try testing.expectEqual(want.len, got.len);
            for (want, got) |index, signer| try testing.expectEqual(index, signer.get());
        }
    }
};

/// commonware's `Recording`: a scheme that records its calls into `calls` and forwards them
/// to `inner`, converting attestations between its own type and `inner`'s.
fn Recording(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Subject = S.Subject;
        pub const Faults = S.Faults;
        pub const PublicKey = S.PublicKey;
        pub const Signature = S.Signature;
        pub const Certificate = S.Certificate;
        pub const Attestation = base.Attestation(Self);
        pub const Verification = base.Verification(Self);
        pub const Assembled = base.Assembled(Self);

        inner: *const S,
        calls: *Calls,

        fn inner_one(attestation: Attestation) base.Attestation(S) {
            return .{ .signer = attestation.signer, .signature = attestation.signature };
        }

        fn outer(attestation: base.Attestation(S)) Attestation {
            return .{ .signer = attestation.signer, .signature = attestation.signature };
        }

        fn inner_all(
            allocator: Allocator,
            attestations: []const Attestation,
        ) Allocator.Error![]base.Attestation(S) {
            const out = try allocator.alloc(base.Attestation(S), attestations.len);
            for (attestations, out) |attestation, *item| item.* = inner_one(attestation);
            return out;
        }

        fn signers_of(attestations: []const Attestation) Allocator.Error![]Participant {
            const out = try gpa.alloc(Participant, attestations.len);
            for (attestations, out) |attestation, *signer| signer.* = attestation.signer;
            return out;
        }

        pub fn me(self: *const Self) ?base.Membership {
            return self.inner.me();
        }

        pub fn participants(self: *const Self) *const utils.ordered.Set(PublicKey) {
            return self.inner.participants();
        }

        pub fn sign(
            self: *const Self,
            allocator: Allocator,
            item: Subject,
        ) Allocator.Error!?Attestation {
            const attestation = (try self.inner.sign(allocator, item)) orelse return null;
            return outer(attestation);
        }

        pub fn verify_attestation(
            self: *const Self,
            allocator: Allocator,
            rng: anytype,
            item: Subject,
            attestation: *const Attestation,
            strategy: anytype,
        ) Allocator.Error!bool {
            const signers = try gpa.alloc(Participant, 1);
            signers[0] = attestation.signer;
            try self.calls.record(signers);
            const converted = inner_one(attestation.*);
            return self.inner.verify_attestation(allocator, rng, item, &converted, strategy);
        }

        pub fn verify_attestations(
            self: *const Self,
            allocator: Allocator,
            rng: anytype,
            item: Subject,
            attestations: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Verification {
            try self.calls.record(try signers_of(attestations));
            const converted = try inner_all(allocator, attestations);
            defer allocator.free(converted);
            var result = try self.inner.verify_attestations(
                allocator,
                rng,
                item,
                converted,
                strategy,
            );
            errdefer result.deinit(allocator);
            const verified = try allocator.alloc(Attestation, result.verified.len);
            for (result.verified, verified) |attestation, *out| out.* = outer(attestation);
            allocator.free(result.verified);
            return .{ .verified = verified, .invalid = result.invalid };
        }

        pub fn optimistic_assemble(
            self: *const Self,
            allocator: Allocator,
            rng: anytype,
            item: Subject,
            pending: []const Attestation,
            verified: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Assembled {
            return base.optimistic_assemble(
                self,
                allocator,
                rng,
                item,
                pending,
                verified,
                strategy,
            );
        }

        pub fn assemble(
            self: *const Self,
            allocator: Allocator,
            attestations: []const Attestation,
            strategy: anytype,
        ) (base.AssemblyError || Allocator.Error)!Certificate {
            self.calls.assemblies += 1;
            const converted = try inner_all(allocator, attestations);
            defer allocator.free(converted);
            return self.inner.assemble(allocator, converted, strategy);
        }

        pub fn verify_certificate(
            self: *const Self,
            allocator: Allocator,
            rng: anytype,
            item: Subject,
            certificate: *const Certificate,
            strategy: anytype,
        ) Allocator.Error!bool {
            self.calls.certificates += 1;
            return self.inner.verify_certificate(allocator, rng, item, certificate, strategy);
        }

        pub fn is_batchable() bool {
            return S.is_batchable();
        }

        pub fn is_attributable() bool {
            return S.is_attributable();
        }
    };
}

/// commonware's `threshold_signers`: `n` signing schemes over a trusted dealing.
fn threshold_signers(comptime V: type, rng: anytype, n: u32) !base.mocks.Fixture(Threshold(V)) {
    return threshold.fixture(Threshold(V), gpa, rng, threshold_namespace, n);
}

/// commonware's `multisig_signers`: `n` identity keys and `n` BLS keys, each with a checked
/// proof of possession, and one signing scheme per BLS key. The caller frees the slice and
/// each scheme.
fn multisig_signers(comptime V: type, rng: anytype, n: u32) ![]Multisig(V) {
    const S = Multisig(V);
    const pairs = try gpa.alloc(S.Participants.Pair, n);
    defer gpa.free(pairs);
    const keys = try gpa.alloc(Private, n);
    defer gpa.free(keys);
    for (pairs) |*pair| pair[0] = ed25519.PrivateKey.random(rng).public_key();
    for (keys, pairs) |*key, *pair| {
        key.* = Private.random(rng);
        pair[1] = ops.compute_public(V, key.*);
        const proof = ops.sign_proof_of_possession(V, key.*, multisig_pop_namespace);
        try ops.verify_proof_of_possession(V, pair[1], multisig_pop_namespace, proof);
    }
    var map = try S.Participants.init(gpa, pairs);
    defer map.deinit(gpa);
    const schemes = try gpa.alloc(S, n);
    for (keys, schemes) |key, *scheme| {
        const copy = try multisig.clone_participants(gpa, &map);
        scheme.* = (try S.signer(gpa, multisig_namespace, copy, key)).?;
    }
    return schemes;
}

/// commonware's `expected_halves`: the signer lists of the two halves the fallback verifies.
fn expect_halves(calls: *const Calls, len: u32) !void {
    const middle = std.math.divCeil(u32, len, 2) catch unreachable;
    try testing.expectEqual(@as(usize, if (middle == len) 1 else 2), calls.attestations.items.len);
    for (calls.attestations.items, 0..) |signers, half| {
        const start: u32 = if (half == 0) 0 else middle;
        const end: u32 = if (half == 0) middle else len;
        try testing.expectEqual(end - start, signers.len);
        for (signers, start..) |signer, index| try testing.expectEqual(index, signer.get());
    }
}

fn sign_all(
    comptime S: type,
    schemes: []const S,
    item: TestSubject,
) ![]Recording(S).Attestation {
    const out = try gpa.alloc(Recording(S).Attestation, schemes.len);
    for (schemes, out) |*scheme, *attestation| {
        attestation.* = Recording(S).outer((try scheme.sign(gpa, item)).?);
    }
    return out;
}

fn expect_certificate(comptime S: type, scheme: *const S, certificate: *const S.Certificate) !void {
    var rng = utils.test_rng();
    try testing.expect(try scheme.verify_certificate(gpa, &rng, subject, certificate, sequential));
    try testing.expect(!try scheme.verify_certificate(
        gpa,
        &rng,
        other_subject,
        certificate,
        sequential,
    ));
}

fn take_certificate(comptime S: type, result: base.Assembled(S)) !S.Certificate {
    switch (result) {
        .certificate => |certificate| return certificate,
        .verification => |verification| {
            var owned = verification;
            owned.deinit(gpa);
            return error.TestExpectedCertificate;
        },
    }
}

fn take_verification(comptime S: type, result: base.Assembled(S)) !base.Verification(S) {
    switch (result) {
        .verification => |verification| return verification,
        .certificate => |certificate| {
            var owned = certificate;
            base.deinit_certificate(S.Certificate, gpa, &owned);
            return error.TestExpectedVerification;
        },
    }
}

fn expect_invalid(invalid: []const Participant, expected: []const u32) !void {
    try testing.expectEqual(expected.len, invalid.len);
    for (expected, invalid) |index, signer| try testing.expectEqual(index, signer.get());
}

fn threshold_success(comptime V: type) !void {
    const S = Threshold(V);
    const R = Recording(S);
    var rng = utils.test_rng();
    var fixture = try threshold_signers(V, &rng, 5);
    defer fixture.deinit(gpa);
    const quorum = N3f1.quorum(fixture.schemes.len);
    const attestations = try sign_all(S, fixture.schemes[0..quorum], subject);
    defer gpa.free(attestations);
    const inner = try R.inner_all(gpa, attestations);
    defer gpa.free(inner);
    var expected = try fixture.schemes[0].assemble(gpa, inner, sequential);
    defer expected.deinit(gpa);
    var calls: Calls = .{};
    defer calls.deinit();
    const verifier: R = .{ .inner = &fixture.schemes[0], .calls = &calls };

    const prior = attestations[0..1];
    var certificate = try take_certificate(R, try verifier.optimistic_assemble(
        gpa,
        &rng,
        subject,
        attestations[1..],
        prior,
        sequential,
    ));
    defer certificate.deinit(gpa);
    try testing.expect(certificate.eql(&expected));
    try testing.expectEqual(0, calls.attestations.items.len);
    try expect_certificate(S, &fixture.schemes[0], &certificate);

    // Threshold recovery uses the lowest quorum of signer indices.
    const unused_bad = R.outer((try fixture.schemes[quorum].sign(gpa, other_subject)).?);
    const pending = try std.mem.concat(gpa, R.Attestation, &.{ attestations, &.{unused_bad} });
    defer gpa.free(pending);
    var again = try take_certificate(
        R,
        try verifier.optimistic_assemble(gpa, &rng, subject, pending, &.{}, sequential),
    );
    defer again.deinit(gpa);
    try testing.expect(again.eql(&expected));
    try testing.expectEqual(0, calls.attestations.items.len);
}

test "optimistic assemble: threshold recovers exact certificate with verified attestations" {
    try threshold_success(MinPk);
    try threshold_success(MinSig);
}

fn multisig_uses_one_certificate_check(comptime V: type) !void {
    const S = Multisig(V);
    const R = Recording(S);
    var rng = utils.test_rng();
    const schemes = try multisig_signers(V, &rng, 5);
    defer {
        for (schemes) |*scheme| scheme.deinit(gpa);
        gpa.free(schemes);
    }
    const quorum = N3f1.quorum(schemes.len);
    const attestations = try sign_all(S, schemes[0..quorum], subject);
    defer gpa.free(attestations);
    var calls: Calls = .{};
    defer calls.deinit();
    const verifier: R = .{ .inner = &schemes[0], .calls = &calls };

    var certificate = try take_certificate(R, try verifier.optimistic_assemble(
        gpa,
        &rng,
        subject,
        attestations[1..],
        attestations[0..1],
        sequential,
    ));
    defer certificate.deinit(gpa);
    try testing.expectEqual(1, calls.certificates);
    try testing.expectEqual(0, calls.attestations.items.len);
    try expect_certificate(S, &schemes[0], &certificate);
}

test "optimistic assemble: multisig uses one certificate check" {
    try multisig_uses_one_certificate_check(MinPk);
    try multisig_uses_one_certificate_check(MinSig);
}

test "optimistic assemble: rejected certificate verifies pending halves directly" {
    const S = Threshold(MinPk);
    const R = Recording(S);
    for ([_]u32{ 1, 5, 7 }) |n| {
        var rng = utils.test_rng();
        var fixture = try threshold_signers(MinPk, &rng, n);
        defer fixture.deinit(gpa);
        var calls: Calls = .{};
        defer calls.deinit();
        const verifier: R = .{ .inner = &fixture.schemes[0], .calls = &calls };
        const quorum = N3f1.quorum(n);
        const pending = try sign_all(S, fixture.schemes[0..quorum], other_subject);
        defer gpa.free(pending);
        var verification = try take_verification(
            R,
            try verifier.optimistic_assemble(gpa, &rng, subject, pending, &.{}, sequential),
        );
        defer verification.deinit(gpa);
        try testing.expectEqual(0, verification.verified.len);
        try testing.expectEqual(quorum, verification.invalid.len);
        for (verification.invalid, 0..) |signer, index| {
            try testing.expectEqual(index, signer.get());
        }
        try expect_halves(&calls, quorum);
    }
}

test "optimistic assemble: malformed assembly falls back to pending halves" {
    const S = Threshold(MinPk);
    const R = Recording(S);
    var rng = utils.test_rng();
    var fixture = try threshold_signers(MinPk, &rng, 5);
    defer fixture.deinit(gpa);
    const quorum = N3f1.quorum(fixture.schemes.len);
    for ([_]u32{ quorum, @intCast(fixture.schemes.len) }) |count| {
        var calls: Calls = .{};
        defer calls.deinit();
        const verifier: R = .{ .inner = &fixture.schemes[0], .calls = &calls };
        const pending = try sign_all(S, fixture.schemes[0..count], subject);
        defer gpa.free(pending);
        // commonware stores a one-byte encoding; a fixed-size signature takes invalid bytes.
        pending[0].signature = .from_bytes(@splat(0xff));
        assert(pending[0].signature.get() == null);
        var verification = try take_verification(
            R,
            try verifier.optimistic_assemble(gpa, &rng, subject, pending, &.{}, sequential),
        );
        defer verification.deinit(gpa);
        try testing.expectEqual(count - 1, verification.verified.len);
        try expect_invalid(verification.invalid, &.{0});
        try expect_halves(&calls, count);
        if (count > quorum) {
            var certificate = try verifier.assemble(gpa, verification.verified, sequential);
            defer certificate.deinit(gpa);
            try testing.expect(try verifier.verify_certificate(
                gpa,
                &rng,
                subject,
                &certificate,
                sequential,
            ));
        }
    }
}

test "optimistic assemble: retains verified inputs" {
    const S = Threshold(MinPk);
    const R = Recording(S);
    var rng = utils.test_rng();
    var fixture = try threshold_signers(MinPk, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    var prior: std.ArrayList(R.Attestation) = .empty;
    defer prior.deinit(gpa);
    for (schemes[0..2]) |*scheme| {
        try prior.append(gpa, R.outer((try scheme.sign(gpa, subject)).?));
    }
    const accepted = R.outer((try schemes[2].sign(gpa, subject)).?);
    const rejected = R.outer((try schemes[3].sign(gpa, other_subject)).?);
    var calls: Calls = .{};
    defer calls.deinit();
    const verifier: R = .{ .inner = &schemes[0], .calls = &calls };
    var verification = try take_verification(R, try verifier.optimistic_assemble(
        gpa,
        &rng,
        subject,
        &.{ accepted, rejected },
        prior.items,
        sequential,
    ));
    defer verification.deinit(gpa);
    try testing.expectEqual(1, verification.verified.len);
    try testing.expect(verification.verified[0].eql(accepted));
    try expect_invalid(verification.invalid, &.{rejected.signer.get()});
    try calls.expect_attestations(&.{ &.{accepted.signer.get()}, &.{rejected.signer.get()} });

    try prior.appendSlice(gpa, verification.verified);
    calls.reset();
    const replacement = R.outer((try schemes[4].sign(gpa, subject)).?);
    var replaced = try verifier.verify_attestations(
        gpa,
        &rng,
        subject,
        &.{replacement},
        sequential,
    );
    defer replaced.deinit(gpa);
    try testing.expectEqual(1, replaced.verified.len);
    try testing.expect(replaced.verified[0].eql(replacement));
    try testing.expectEqual(0, replaced.invalid.len);
    try calls.expect_attestations(&.{&.{replacement.signer.get()}});
    try prior.appendSlice(gpa, replaced.verified);
    var certificate = try verifier.assemble(gpa, prior.items, sequential);
    defer certificate.deinit(gpa);
    try testing.expect(try verifier.verify_certificate(
        gpa,
        &rng,
        subject,
        &certificate,
        sequential,
    ));
}

test "optimistic assemble: with verified votes" {
    const S = Threshold(MinPk);
    const R = Recording(S);
    var rng = utils.test_rng();
    var fixture = try threshold_signers(MinPk, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = N3f1.quorum(schemes.len);
    const attestations = try sign_all(S, schemes[0..quorum], subject);
    defer gpa.free(attestations);
    for ([_]u32{ 0, 1, 2 }) |pending_len| {
        // Retained votes are authenticated for this configuration and subject.
        // The remaining votes cover empty, singleton, and evenly split inputs.
        const split = quorum - pending_len;
        const inner = try R.inner_all(gpa, attestations[0..split]);
        defer gpa.free(inner);
        var prior = try schemes[0].verify_attestations(gpa, &rng, subject, inner, sequential);
        defer prior.deinit(gpa);
        try testing.expectEqual(0, prior.invalid.len);
        const retained = try gpa.alloc(R.Attestation, prior.verified.len);
        defer gpa.free(retained);
        for (prior.verified, retained) |attestation, *out| out.* = R.outer(attestation);
        var calls: Calls = .{};
        defer calls.deinit();
        const verifier: R = .{ .inner = &schemes[0], .calls = &calls };
        var certificate = try take_certificate(R, try verifier.optimistic_assemble(
            gpa,
            &rng,
            subject,
            attestations[split..],
            retained,
            sequential,
        ));
        defer certificate.deinit(gpa);

        // Pending votes require certificate authentication, even when most
        // inputs are already verified. A verified-only quorum needs assembly alone.
        try testing.expectEqual(1, calls.assemblies);
        try testing.expectEqual(@intFromBool(pending_len != 0), calls.certificates);
        try testing.expectEqual(0, calls.attestations.items.len);
        try testing.expect(try schemes[0].verify_certificate(
            gpa,
            &rng,
            subject,
            &certificate,
            sequential,
        ));
    }
}

/// Signs with each scheme, over `other_subject` for positions at or after `bad_from`.
fn sign_mixed(
    comptime S: type,
    schemes: []const S,
    bad_from: usize,
) ![]Recording(S).Attestation {
    const out = try gpa.alloc(Recording(S).Attestation, schemes.len);
    for (schemes, out, 0..) |*scheme, *attestation, index| {
        const item = if (index >= bad_from) other_subject else subject;
        attestation.* = Recording(S).outer((try scheme.sign(gpa, item)).?);
    }
    return out;
}

const RetryState = struct {
    fixture: base.mocks.Fixture(Threshold(MinPk)),
    calls: *Calls,
    prior: std.ArrayList(Recording(Threshold(MinPk)).Attestation) = .empty,
    rng: *@TypeOf(utils.test_rng()),
};

/// The first attempt: the local vote is retained, and `failures` peers vote for another
/// subject.
fn retry_initial(state: *RetryState, failures: u32) !void {
    const S = Threshold(MinPk);
    const R = Recording(S);
    const schemes = state.fixture.schemes;
    const quorum = N3f1.quorum(schemes.len);
    const verifier: R = .{ .inner = &schemes[0], .calls = state.calls };
    const own_vote = (try schemes[0].sign(gpa, subject)).?;
    var own = try schemes[0].verify_attestations(gpa, state.rng, subject, &.{own_vote}, sequential);
    defer own.deinit(gpa);
    try testing.expectEqual(0, own.invalid.len);
    for (own.verified) |attestation| try state.prior.append(gpa, R.outer(attestation));
    // Index `i` of `schemes[1..quorum]` is bad when `i + 1 >= quorum - failures`.
    const pending = try sign_mixed(S, schemes[1..quorum], quorum - failures - 1);
    defer gpa.free(pending);
    var result = try take_verification(R, try verifier.optimistic_assemble(
        gpa,
        state.rng,
        subject,
        pending,
        state.prior.items,
        sequential,
    ));
    defer result.deinit(gpa);
    try testing.expectEqual(failures, result.invalid.len);
    try state.prior.appendSlice(gpa, result.verified);
    try testing.expectEqual(quorum - failures, state.prior.items.len);
}

/// A new faulty signer mixed with any honest replacements: the candidate fails
/// authentication, so the fallback identifies the bad vote.
fn retry_replacements(state: *RetryState, failures: u32) !void {
    const S = Threshold(MinPk);
    const R = Recording(S);
    const schemes = state.fixture.schemes;
    const quorum = N3f1.quorum(schemes.len);
    const verifier: R = .{ .inner = &schemes[0], .calls = state.calls };
    const pending = try sign_mixed(S, schemes[quorum .. quorum + failures], failures - 1);
    defer gpa.free(pending);
    const invalid = pending[pending.len - 1].signer;
    state.calls.reset();
    var result = try take_verification(R, try verifier.optimistic_assemble(
        gpa,
        state.rng,
        subject,
        pending,
        state.prior.items,
        sequential,
    ));
    defer result.deinit(gpa);
    try expect_invalid(result.invalid, &.{invalid.get()});
    try testing.expectEqual(failures - 1, result.verified.len);
    try testing.expectEqual(1, state.calls.assemblies);
    try testing.expectEqual(1, state.calls.certificates);
    try testing.expectEqual(pending.len, state.calls.attestations.items.len);
    for (pending, state.calls.attestations.items) |vote, signers| {
        try testing.expectEqual(1, signers.len);
        try testing.expectEqual(vote.signer.get(), signers[0].get());
    }
    try state.prior.appendSlice(gpa, result.verified);
    try testing.expectEqual(quorum - 1, state.prior.items.len);
}

/// The last honest replacement completes the same authenticated subject.
fn retry_complete(state: *RetryState, failures: u32) !void {
    const S = Threshold(MinPk);
    const R = Recording(S);
    const schemes = state.fixture.schemes;
    const quorum = N3f1.quorum(schemes.len);
    const verifier: R = .{ .inner = &schemes[0], .calls = state.calls };
    const replacement = R.outer((try schemes[quorum + failures].sign(gpa, subject)).?);
    state.calls.reset();
    var certificate = try take_certificate(R, try verifier.optimistic_assemble(
        gpa,
        state.rng,
        subject,
        &.{replacement},
        state.prior.items,
        sequential,
    ));
    defer certificate.deinit(gpa);
    try testing.expectEqual(1, state.calls.assemblies);
    try testing.expectEqual(1, state.calls.certificates);
    try testing.expectEqual(0, state.calls.attestations.items.len);
    try expect_certificate(S, &schemes[0], &certificate);
}

test "optimistic assemble: retries with replacements" {
    var rng = utils.test_rng();
    var fixture = try threshold_signers(MinPk, &rng, 10);
    defer fixture.deinit(gpa);
    for ([_]u32{ 1, 2 }) |failures| {
        // Ten participants permit three faulty signers across these attempts.
        var calls: Calls = .{};
        defer calls.deinit();
        var state: RetryState = .{ .fixture = fixture, .calls = &calls, .rng = &rng };
        defer state.prior.deinit(gpa);
        try retry_initial(&state, failures);
        try retry_replacements(&state, failures);
        try retry_complete(&state, failures);
    }
}

test "optimistic assemble: below quorum" {
    const S = Threshold(MinPk);
    const R = Recording(S);
    var rng = utils.test_rng();
    var fixture = try threshold_signers(MinPk, &rng, 5);
    defer fixture.deinit(gpa);
    const pending = try sign_all(S, fixture.schemes[0..2], subject);
    defer gpa.free(pending);
    var calls: Calls = .{};
    defer calls.deinit();
    const verifier: R = .{ .inner = &fixture.schemes[0], .calls = &calls };
    var verification = try take_verification(
        R,
        try verifier.optimistic_assemble(gpa, &rng, subject, pending, &.{}, sequential),
    );
    defer verification.deinit(gpa);
    try testing.expectEqual(pending.len, verification.verified.len);
    for (pending, verification.verified) |want, got| try testing.expect(want.eql(got));
    try testing.expectEqual(0, verification.invalid.len);
    try expect_halves(&calls, @intCast(pending.len));
}

test "optimistic assemble: unknown pending signer" {
    const S = Threshold(MinPk);
    const R = Recording(S);
    var rng = utils.test_rng();
    var fixture = try threshold_signers(MinPk, &rng, 5);
    defer fixture.deinit(gpa);
    const quorum = N3f1.quorum(fixture.schemes.len);
    const pending = try sign_all(S, fixture.schemes[0..quorum], subject);
    defer gpa.free(pending);
    pending[0].signer = .init(999);
    var calls: Calls = .{};
    defer calls.deinit();
    const verifier: R = .{ .inner = &fixture.schemes[0], .calls = &calls };
    var verification = try take_verification(
        R,
        try verifier.optimistic_assemble(gpa, &rng, subject, pending, &.{}, sequential),
    );
    defer verification.deinit(gpa);
    try testing.expectEqual(quorum - 1, verification.verified.len);
    try expect_invalid(verification.invalid, &.{999});
    try calls.expect_attestations(&.{ &.{ 999, 1 }, &.{ 2, 3 } });
}
