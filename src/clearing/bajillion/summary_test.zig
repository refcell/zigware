//! Tests of `summary.zig` (commonware `bajillion/summary.rs` tests, and the genesis part of the
//! ledger vector in `bajillion/tests.rs`).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const storage = @import("storage");
const utils = @import("utils");
const mod = @import("mod.zig");
const summary = @import("summary.zig");
const t = @import("testing.zig");

const Sha256 = t.Sha256;
const Digest = t.Digest;
const PublicKey = t.PublicKey;
const TestSummary = summary.Summary(Sha256);
const Processed = summary.Processed(Digest);
const Deposit = mod.Deposit(PublicKey, u64);
const Forced = mod.ForcedWithdrawal(PublicKey, u64);
const Scheme = cryptography.ed25519.certificate.Scheme(TestSummary, utils.N3f1);
const gpa = testing.allocator;

/// The summary before the first close, on top of balances with a fixed root.
fn genesis() TestSummary {
    return TestSummary.genesis(PublicKey, u64, Sha256.hash(&.{"balances"}));
}

fn digest_hex(comptime text: []const u8) Digest {
    var digest: Digest = undefined;
    _ = std.fmt.hexToBytes(&digest.bytes, text) catch unreachable; // Proof: valid test hex.
    return digest;
}

fn expect_roundtrip(comptime T: type, value: T) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqual(value.encode_size(), encoded.len);
    const decoded = try codec.decode_cfg(T, gpa, encoded, {});
    try testing.expect(decoded.eql(value));
}

/// Returns `hash` extended by `H(hash || request)` for each of `requests`.
fn chain(comptime R: type, hash: Digest, requests: []const R) Digest {
    var result = hash;
    for (requests) |request| {
        const encoded = codec.encode_fixed(R, request);
        result = Sha256.hash(&.{ &result.bytes, &encoded });
    }
    return result;
}

test "summary: genesis and digest" {
    const start = genesis();
    try testing.expectEqual(@as(u64, 0), start.epoch);
    try testing.expect(start.parent.eql(.empty));
    try testing.expect(start.balances.eql(Sha256.hash(&.{"balances"})));
    var empty = try mod.Matrix(PublicKey, Sha256, u64).empty(gpa);
    defer empty.deinit();
    try testing.expect(start.matrix.eql(empty.root()));
    const Encoding = storage.qmdb.value.Fixed(mod.Payout(PublicKey, u64));
    const log = storage.qmdb.keyless.initial_root(storage.mmr.Family, Encoding, Sha256);
    try testing.expect(start.payouts.eql(.{ .size = 1, .root = log }));
    try expect_roundtrip(TestSummary, start);

    // Every field changes the digest and decodes back unchanged.
    const other = Sha256.hash(&.{"other"});
    var changed: [10]TestSummary = @splat(start);
    changed[0].epoch = 1;
    changed[1].parent = other;
    changed[2].matrix = other;
    changed[3].balances = other;
    changed[4].payouts.size = 2;
    changed[5].payouts.root = other;
    changed[6].deposits.count = 1;
    changed[7].deposits.hash = other;
    changed[8].forced_withdrawals.count = 1;
    changed[9].forced_withdrawals.hash = other;
    for (changed) |value| {
        try testing.expect(!value.digest().eql(start.digest()));
        try expect_roundtrip(TestSummary, value);
    }

    // A payouts size the log cannot reach does not decode.
    var beyond = start;
    beyond.payouts.size = storage.mmr.Family.max_leaves + 1;
    const encoded = try codec.encode(TestSummary, gpa, beyond);
    defer gpa.free(encoded);
    try testing.expectError(error.Invalid, codec.decode_cfg(TestSummary, gpa, encoded, {}));
}

test "summary: ledger vector genesis" {
    // The empty balances database's root, the payout log's initial root, and the summary
    // before the first close, pinned by commonware's ledger vector.
    const balances = digest_hex("4e051a8ba89ab421a291d4b906848b2e0f80402175824a056cc3cc00efc4cc65");
    const start = TestSummary.genesis(PublicKey, u64, balances);
    const log = digest_hex("97f9a47536a9ff3eda91ef4e53351d365e104280df46dbcc5dddc7adfabcef2c");
    try testing.expect(start.payouts.root.eql(log));
    try testing.expectEqual(@as(u64, 1), start.payouts.size);
    const digest = digest_hex("dc78896a8eab075c7672d704b58798ff2687447dc6132852a86f007847bf5af0");
    try testing.expect(start.digest().eql(digest));

    // The deposit queue's running hash after bob's deposit of 5, chained from genesis.
    const bob: Deposit = .{ .account = t.account(1), .amount = 5 };
    const deposits = start.deposits.next(Sha256, Deposit, &.{bob});
    const expected = digest_hex("e3a81ed35a6c131dc7ea391436b14bc6bc9882a0cf7d815fbd936179601427b4");
    try testing.expect(deposits.hash.eql(expected));
}

test "summary: certificate covers the encoding in the summary namespace" {
    const start = genesis();
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const message = try start.message(gpa);
    defer gpa.free(message);
    const encoded = try codec.encode(TestSummary, gpa, start);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, encoded, message);
    try testing.expectEqualSlices(u8, namespace.summary, start.namespace(&namespace));
}

test "summary: running hashes chain processed requests" {
    const start = genesis();
    try testing.expect(start.deposits.eql(Processed.start));
    try testing.expect(start.forced_withdrawals.eql(Processed.start));
    try testing.expect(Processed.start.hash.eql(.empty));
    const first: Deposit = .{ .account = t.account(0), .amount = 5 };
    const second: Deposit = .{ .account = t.account(1), .amount = 7 };

    // One request extends the hash by H(hash || request).
    const one = Processed.start.next(Sha256, Deposit, &.{first});
    try testing.expectEqual(@as(u64, 1), one.count);
    const encoded = codec.encode_fixed(Deposit, first);
    try testing.expect(one.hash.eql(Sha256.hash(&.{ &Processed.start.hash.bytes, &encoded })));
    try testing.expect(one.hash.eql(chain(Deposit, .empty, &.{first})));
    try expect_roundtrip(Processed, one);

    // A close that processes nothing carries its parent's hash.
    const none = one.next(Sha256, Deposit, &.{});
    try testing.expectEqual(@as(u64, 0), none.count);
    try testing.expect(none.hash.eql(one.hash));

    // Two closes chain to the hash of one close processing both batches.
    const both = Processed.start.next(Sha256, Deposit, &.{ first, second });
    const next = one.next(Sha256, Deposit, &.{second});
    try testing.expectEqual(@as(u64, 2), both.count);
    try testing.expectEqual(@as(u64, 1), next.count);
    try testing.expect(next.hash.eql(both.hash));

    // Reordering or repeating requests changes the hash.
    const reversed = Processed.start.next(Sha256, Deposit, &.{ second, first });
    const repeated = Processed.start.next(Sha256, Deposit, &.{ first, first });
    try testing.expect(!reversed.hash.eql(both.hash));
    try testing.expect(!repeated.hash.eql(one.hash));

    // Forced withdrawals chain the same way over their own encoding.
    const forced: Forced = .{ .account = t.account(2), .amount = 3 };
    const chained = Processed.start.next(Sha256, Forced, &.{forced});
    try testing.expect(chained.hash.eql(chain(Forced, .empty, &.{forced})));
}

/// Assembles a certificate over `subject` from every scheme's attestation.
fn certify(schemes: []const Scheme, subject: TestSummary) !Scheme.Certificate {
    var attestations: [4]Scheme.Attestation = undefined;
    for (schemes, attestations[0..schemes.len]) |*scheme, *attestation| {
        attestation.* = (try scheme.sign(gpa, subject)).?;
    }
    return schemes[0].assemble(gpa, attestations[0..schemes.len], parallel.sequential);
}

fn test_summary(parent: Digest) TestSummary {
    return .{
        .epoch = 1,
        .parent = parent,
        .matrix = Sha256.hash(&.{"matrix"}),
        .balances = Sha256.hash(&.{"after"}),
        .payouts = .{ .size = 3, .root = Sha256.hash(&.{"payouts"}) },
        .deposits = .{ .count = 2, .hash = Sha256.hash(&.{"deposits"}) },
        .forced_withdrawals = .{ .count = 1, .hash = Sha256.hash(&.{"forced withdrawals"}) },
    };
}

const Verify = struct {
    rng: *utils.rng.TestRng,
    verifier: *const Scheme,

    fn call(
        self: Verify,
        value: TestSummary,
        certificate: *const Scheme.Certificate,
        parent: Digest,
        deposits: summary.CountRange,
        forced_withdrawals: summary.CountRange,
    ) !void {
        return value.verify(
            gpa,
            self.rng,
            self.verifier,
            certificate,
            1,
            parent,
            deposits,
            forced_withdrawals,
            parallel.sequential,
        );
    }
};

fn range(min: u64, max: u64) summary.CountRange {
    return .{ .min = min, .max = max };
}

test "summary: verify checks every field before the certificate" {
    var rng = utils.rng.test_rng();
    const fixtures = cryptography.ed25519.certificate;
    var fixture = try fixtures.fixture(Scheme, gpa, &rng, t.namespace_bytes, 4);
    defer fixture.deinit(gpa);
    const parent = genesis().digest();
    const value = test_summary(parent);
    var certificate = try certify(fixture.schemes, value);
    defer certificate.deinit(gpa);
    var other = try certify(fixture.schemes, genesis());
    defer other.deinit(gpa);
    const v: Verify = .{ .rng = &rng, .verifier = &fixture.verifier };

    // Each count may lie anywhere from the queue's required count to its length.
    try v.call(value, &certificate, parent, range(0, 2), range(1, 1));
    try v.call(value, &certificate, parent, range(2, 5), range(0, 3));

    // Every other refusal comes before the certificate's.
    for ([_]*const Scheme.Certificate{ &certificate, &other }) |cert| {
        var wrong = value;
        wrong.epoch = 2;
        const wrong_epoch = v.call(wrong, cert, parent, range(0, 2), range(0, 1));
        try testing.expectError(error.WrongEpoch, wrong_epoch);
        const wrong_parent = v.call(value, cert, .empty, range(0, 2), range(0, 1));
        try testing.expectError(error.WrongParent, wrong_parent);
        const counts = [_][2]summary.CountRange{
            .{ range(3, 4), range(0, 1) },
            .{ range(0, 1), range(0, 1) },
            .{ range(0, 2), range(2, 2) },
        };
        for (counts) |pair| {
            const result = v.call(value, cert, parent, pair[0], pair[1]);
            try testing.expectError(error.InvalidCount, result);
        }
    }

    // A summary that differs in its payouts size or root is not certified.
    var changed: [2]TestSummary = @splat(value);
    changed[0].payouts.size = 4;
    changed[1].payouts.root = Sha256.hash(&.{"other"});
    for (changed) |different| {
        const result = v.call(different, &certificate, parent, range(0, 2), range(0, 1));
        try testing.expectError(error.InvalidCertificate, result);
    }
    const result = v.call(value, &other, parent, range(0, 2), range(0, 1));
    try testing.expectError(error.InvalidCertificate, result);
}
