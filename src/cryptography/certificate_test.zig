//! Tests for `certificate.zig` (commonware `certificate.rs`), run against the ed25519
//! scheme. commonware's bls12381 threshold and multisig cases belong with the bls12381
//! schemes.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const certificate = @import("certificate.zig");
const ed25519 = @import("ed25519.zig");

const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const Signers = certificate.Signers;
const sequential = parallel.sequential;
const gpa = testing.allocator;

fn participants_of(comptime values: []const u32) [values.len]Participant {
    var out: [values.len]Participant = undefined;
    for (&out, values) |*participant, value| participant.* = .init(value);
    return out;
}

fn expect_signers(signers: *const Signers, expected: []const u32) !void {
    var iter = signers.iter();
    for (expected) |value| try testing.expectEqual(value, iter.next().?.get());
    try testing.expectEqual(null, iter.next());
    try testing.expectEqual(expected.len, signers.count());
}

test "certificate max individual certificate size" {
    // The bound covers every signature and never decreases as the committee grows.
    const signature_size = ed25519.Signature.fixed_size;
    var previous: usize = 0;
    for ([_]u32{ 0, 1, 7, 8, 9, 127, 128 }) |n| {
        const indices = try gpa.alloc(Participant, n);
        defer gpa.free(indices);
        for (indices, 0..) |*index, value| index.* = .from_usize(value);
        var signers = try Signers.init(gpa, n, indices);
        defer signers.deinit(gpa);
        const signers_size = codec.encode_size(Signers, signers);
        try testing.expectEqual(Signers.max_encode_size(n), signers_size);
        const size = certificate.max_individual_certificate_size(n, signature_size);
        const prefix = codec.varint.max_u32_varint_size;
        try testing.expectEqual(signers_size + prefix + n * signature_size, size);
        try testing.expect(size >= previous);
        previous = size;
    }

    // Counts up to `u32::MAX` fit the signature length prefix.
    const n: usize = std.math.maxInt(u32);
    try testing.expectEqual(
        8 + (n + 7) / 8 + 5 + n * signature_size,
        certificate.max_individual_certificate_size(std.math.maxInt(u32), signature_size),
    );
}

test "certificate signers new" {
    var signers = try Signers.init(gpa, 6, &participants_of(&.{ 0, 3, 5 }));
    defer signers.deinit(gpa);
    try expect_signers(&signers, &.{ 0, 3, 5 });

    // Indices may arrive in any order.
    var unsorted = try Signers.init(gpa, 4, &participants_of(&.{ 2, 1 }));
    defer unsorted.deinit(gpa);
    try expect_signers(&unsorted, &.{ 1, 2 });

    const out_of_bounds = participants_of(&.{ 0, 4 });
    try testing.expectError(error.UnknownSigner, Signers.init(gpa, 4, &out_of_bounds));
    const duplicate = participants_of(&.{ 0, 0, 1 });
    try testing.expectError(error.DuplicateSigner, Signers.init(gpa, 4, &duplicate));
}

test "certificate signers from a set and require" {
    var set = try utils.ordered.Set(u32).from_dedup(gpa, &.{ 0, 1, 2, 3 });
    defer set.deinit(gpa);
    var signers = try Signers.from_set(gpa, &set, &participants_of(&.{ 0, 2, 3 }));
    defer signers.deinit(gpa);
    try signers.require(3);
    try testing.expectEqual(3, signers.count());
    var short = try Signers.from_set(gpa, &set, &participants_of(&.{ 0, 2 }));
    defer short.deinit(gpa);
    try testing.expectError(error.InsufficientAttestations, short.require(3));

    // The set bounds the signers.
    var empty = try utils.ordered.Set(u32).from_dedup(gpa, &.{});
    defer empty.deinit(gpa);
    const first = participants_of(&.{0});
    try testing.expectError(error.UnknownSigner, Signers.from_set(gpa, &empty, &first));
}

test "certificate signers codec round trip and participant limit" {
    var signers = try Signers.init(gpa, 9, &participants_of(&.{ 1, 6 }));
    defer signers.deinit(gpa);
    const encoded = try codec.encode(Signers, gpa, signers);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(Signers, gpa, encoded, 9);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&signers));

    var eight = try Signers.init(gpa, 8, &participants_of(&.{ 0, 3, 7 }));
    defer eight.deinit(gpa);
    const bytes = try codec.encode(Signers, gpa, eight);
    defer gpa.free(bytes);
    // More participants than the bound fail; the exact bound and a looser one succeed.
    try testing.expectError(error.InvalidLength, codec.decode_cfg(Signers, gpa, bytes, 2));
    for ([_]usize{ 8, 10 }) |bound| {
        var value = try codec.decode_cfg(Signers, gpa, bytes, bound);
        value.deinit(gpa);
    }
}

/// commonware's `ed25519_fixture::TestSubject`.
const TestSubject = struct {
    pub const Namespace = certificate.BytesNamespace;

    bytes: []const u8,

    pub fn namespace(_: TestSubject, derived: *const Namespace) []const u8 {
        return derived.bytes;
    }

    pub fn message(self: TestSubject, allocator: Allocator) Allocator.Error![]u8 {
        return allocator.dupe(u8, self.bytes);
    }
};

const Scheme = ed25519.certificate.Scheme(TestSubject, N3f1);
const Attestation = Scheme.Attestation;
const Fixture = certificate.mocks.Fixture(Scheme);

const bisect_namespace = "test-bisect";
const good: TestSubject = .{ .bytes = "good message" };
const bad: TestSubject = .{ .bytes = "bad message" };
const subject: TestSubject = .{ .bytes = "subject" };
const other_subject: TestSubject = .{ .bytes = "other-subject" };

fn setup(rng: anytype, n: u32) !Fixture {
    return ed25519.certificate.fixture(Scheme, gpa, rng, bisect_namespace, n);
}

fn sign_all(fixture: *const Fixture, item: TestSubject, count: usize) ![]Attestation {
    const attestations = try gpa.alloc(Attestation, count);
    for (fixture.schemes[0..count], attestations) |*scheme, *attestation| {
        attestation.* = (try scheme.sign(gpa, item)).?;
    }
    return attestations;
}

fn make_certificate(fixture: *const Fixture, item: TestSubject) !Scheme.Certificate {
    const attestations = try sign_all(fixture, item, fixture.schemes.len);
    defer gpa.free(attestations);
    return fixture.schemes[0].assemble(gpa, attestations, sequential);
}

test "certificate membership reports index and signing" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(&rng, 4);
    defer fixture.deinit(gpa);
    const participants = fixture.verifier.participants();
    const signer = fixture.schemes[0].me().?;
    const index = signer.index();
    const key = participants.key(index).?.*;

    var member = (try Scheme.member(gpa, bisect_namespace, try participants.clone(gpa), key)).?;
    defer member.deinit(gpa);
    try testing.expect(member.me().?.eql(.{ .member = index }));
    try testing.expectEqual(index, member.me().?.index());
    try testing.expectEqual(null, member.me().?.signer_index());
    try testing.expect(signer.eql(.{ .signer = index }));
    try testing.expectEqual(index, signer.signer_index().?);
    try testing.expectEqual(null, fixture.verifier.me());
}

fn expect_bisect(
    fixture: *const Fixture,
    subjects: []const TestSubject,
    expected: []const bool,
) !void {
    var rng = utils.rng.test_rng();
    var cert = try make_certificate(fixture, good);
    defer cert.deinit(gpa);
    const items = try gpa.alloc(Scheme.Item, subjects.len);
    defer gpa.free(items);
    for (items, subjects) |*item, value| item.* = .{ .subject = value, .certificate = &cert };
    const out = try gpa.alloc(bool, subjects.len);
    defer gpa.free(out);
    const verifier = &fixture.verifier;
    try certificate.verify_certificates_bisect(verifier, gpa, &rng, items, out, sequential);
    try testing.expectEqualSlices(bool, expected, out);
}

test "certificate bisect" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(&rng, 4);
    defer fixture.deinit(gpa);
    try expect_bisect(&fixture, &.{}, &.{});
    try expect_bisect(&fixture, &@as([5]TestSubject, @splat(good)), &@as([5]bool, @splat(true)));
    try expect_bisect(
        &fixture,
        &.{ good, bad, good, bad, good, good, bad, bad },
        &.{ true, false, true, false, true, true, false, false },
    );
    try expect_bisect(&fixture, &@as([4]TestSubject, @splat(bad)), &@as([4]bool, @splat(false)));
    try expect_bisect(&fixture, &.{good}, &.{true});
    try expect_bisect(&fixture, &.{bad}, &.{false});
}

test "certificate scoped verifies and into scheme" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(&rng, 4);
    defer fixture.deinit(gpa);
    var cert = try make_certificate(&fixture, good);
    defer cert.deinit(gpa);
    const Scoped = certificate.Scoped(Scheme);
    const as_verifier = Scoped.verifier(&fixture.verifier);
    const as_scheme = Scoped.scheme(&fixture.schemes[0]);

    // Both scopes verify a valid certificate.
    try testing.expect(try as_verifier.verify_certificate(gpa, &rng, good, &cert, sequential));
    try testing.expect(try as_scheme.verify_certificate(gpa, &rng, good, &cert, sequential));
    const items = [_]Scheme.Item{.{ .subject = good, .certificate = &cert }};
    try testing.expect(try as_verifier.verify_certificates(gpa, &rng, &items, sequential));
    try testing.expectEqual(Scheme.is_batchable(), Scoped.is_batchable());
    try testing.expectEqual(
        fixture.schemes[0].certificate_codec_config(),
        as_verifier.certificate_codec_config(),
    );
    for ([_]u32{ 0, 4, 128 }) |participants| {
        try testing.expectEqual(
            Scheme.max_certificate_size(participants),
            Scoped.max_certificate_size(participants),
        );
    }
    try testing.expectEqual(
        Scheme.certificate_codec_config_unbounded(),
        Scoped.certificate_codec_config_unbounded(),
    );

    // A verify-only scope never yields its scheme; a full scope always does.
    try testing.expectEqual(null, as_verifier.into_scheme());
    try testing.expect(as_scheme.into_scheme() != null);
    const provider = certificate.ConstantProvider(Scheme).init(&fixture.schemes[0]);
    try testing.expect(provider.scoped({}) != null);
    try testing.expect(provider.scheme({}) != null);
}

fn expect_signers_of(attestations: []const Attestation, expected: []const Attestation) !void {
    try testing.expectEqual(expected.len, attestations.len);
    for (attestations, expected) |actual, wanted| try testing.expect(actual.eql(wanted));
}

test "certificate optimistic assemble with individual inputs" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(&rng, 5);
    defer fixture.deinit(gpa);
    const verifier = &fixture.verifier;
    var empty = try verifier.optimistic_assemble(gpa, &rng, subject, &.{}, &.{}, sequential);
    defer empty.deinit(gpa);
    try testing.expectEqual(0, empty.verification.verified.len);
    try testing.expectEqual(0, empty.verification.invalid.len);

    const pending = try sign_all(&fixture, subject, 5);
    defer gpa.free(pending);
    var certified = try verifier.optimistic_assemble(gpa, &rng, subject, pending, &.{}, sequential);
    defer certified.deinit(gpa);
    const valid = &certified.certificate;
    try testing.expect(try verifier.verify_certificate(gpa, &rng, subject, valid, sequential));

    // One attestation over another subject is reported, and the rest still certify.
    pending[0] = (try fixture.schemes[0].sign(gpa, other_subject)).?;
    var result = try verifier.optimistic_assemble(gpa, &rng, subject, pending, &.{}, sequential);
    defer result.deinit(gpa);
    const verification = &result.verification;
    try testing.expectEqualSlices(Participant, &.{pending[0].signer}, verification.invalid);
    try expect_signers_of(verification.verified, pending[1..]);
    var cert = try verifier.assemble(gpa, verification.verified, sequential);
    defer cert.deinit(gpa);
    try testing.expect(try verifier.verify_certificate(gpa, &rng, subject, &cert, sequential));
}

test "certificate optimistic assemble requires a quorum" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(&rng, 5);
    defer fixture.deinit(gpa);
    const verifier = &fixture.verifier;
    const quorum = N3f1.quorum(5);
    const attestations = try sign_all(&fixture, subject, quorum);
    defer gpa.free(attestations);

    // Both pending-only and verified-only inputs require quorum. On failure, the result
    // contains only pending attestations, never retained inputs.
    for ([_]usize{ 0, quorum - 1, quorum }) |count| {
        for ([_]usize{ 0, count }) |pending_len| {
            const pending = attestations[0..pending_len];
            const verified = attestations[pending_len..count];
            var result = try verifier.optimistic_assemble(
                gpa,
                &rng,
                subject,
                pending,
                verified,
                sequential,
            );
            defer result.deinit(gpa);
            try testing.expectEqual(count == quorum, result == .certificate);
            switch (result) {
                .certificate => |*cert| try testing.expect(
                    try verifier.verify_certificate(gpa, &rng, subject, cert, sequential),
                ),
                .verification => |verification| {
                    try expect_signers_of(verification.verified, pending);
                    try testing.expectEqual(0, verification.invalid.len);
                },
            }
        }
    }
}

test "certificate optimistic assemble with an empty committee" {
    var rng = utils.rng.test_rng();
    const set = try Scheme.Participants.init(gpa, &.{});
    var verifier = try Scheme.verifier(gpa, bisect_namespace, set);
    defer verifier.deinit(gpa);
    var fixture = try setup(&rng, 1);
    defer fixture.deinit(gpa);
    const unknown = (try fixture.schemes[0].sign(gpa, subject)).?;
    for ([_][]const Attestation{ &.{}, &.{unknown} }) |pending| {
        var result = try verifier.optimistic_assemble(
            gpa,
            &rng,
            subject,
            pending,
            &.{},
            sequential,
        );
        defer result.deinit(gpa);
        try testing.expectEqual(0, result.verification.verified.len);
        try testing.expectEqual(pending.len, result.verification.invalid.len);
        const invalid = result.verification.invalid;
        if (pending.len > 0) try testing.expectEqual(unknown.signer, invalid[0]);
    }
}

test "certificate generic optimistic assemble falls back to verifying halves" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(&rng, 7);
    defer fixture.deinit(gpa);
    const verifier = &fixture.verifier;
    const pending = try sign_all(&fixture, subject, 7);
    defer gpa.free(pending);

    // A valid candidate certifies at once.
    var certified = try certificate.optimistic_assemble(
        verifier,
        gpa,
        &rng,
        subject,
        pending,
        @as([]const Attestation, &.{}),
        sequential,
    );
    defer certified.deinit(gpa);
    try testing.expect(certified == .certificate);

    // A rejected candidate verifies each half and reports the faulty signers.
    pending[1] = (try fixture.schemes[1].sign(gpa, other_subject)).?;
    pending[5] = (try fixture.schemes[5].sign(gpa, other_subject)).?;
    const pool = try parallel.ThreadPool.create(gpa, testing.io, .{ .threads = 2 });
    defer pool.destroy();
    var result = try certificate.optimistic_assemble(
        verifier,
        gpa,
        &rng,
        subject,
        pending,
        @as([]const Attestation, &.{}),
        parallel.Rayon.init(pool),
    );
    defer result.deinit(gpa);
    const invalid = result.verification.invalid;
    try testing.expectEqual(2, invalid.len);
    try testing.expectEqual(pending[1].signer, invalid[0]);
    try testing.expectEqual(pending[5].signer, invalid[1]);
    try testing.expectEqual(5, result.verification.verified.len);
}
