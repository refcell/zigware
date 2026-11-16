//! Tests for the golden eVRF keys. commonware tests these keys only through the golden DKG
//! and bulletproofs paths, so these check the Schnorr signatures against signatures from a
//! Rust run (`PrivateKey::random(test_rng())`), plus the codec and verification rules.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const hex = @import("formatting").hex_literal;
const evrf = @import("evrf.zig");
const transcript = @import("../../../transcript.zig");

const PrivateKey = evrf.PrivateKey;
const PublicKey = evrf.PublicKey;
const Signature = evrf.Signature;
const gpa = testing.allocator;

fn test_key() PrivateKey {
    var rng = utils.test_rng();
    return PrivateKey.random(&rng);
}

test "evrf keys: signatures match commonware" {
    @setEvalBranchQuota(20_000);
    const key = test_key();
    const private = hex("7f6f2ccdb23f2abb7b69278e947c01c6160a31cf02c19d06d0f6e5ab1d768b15");
    const public = hex("6bfb93450486a31bdb7ca55a2da315523894f55dea49210377d93610b216479b");
    const signature = hex("521f10092e73cd92b55098ebfc6970784b460eb21e91c531b58e4fd989faa52e" ++
        "d20291349743f5bab1025cce73fa5f769a92f79fec34f7a97c8f3fe729273f1b");
    const signature_empty = hex(
        "5799e0c4c5df74e28cf23b26013fa304f0ce0be3e39df5b0806a9d130bd0d1cc" ++
            "dc484e12ede10f0ee8d7acc27772e2182c17af75dab5a038e8193408c35a0015",
    );
    try testing.expectEqualSlices(u8, &private, &codec.encode_fixed(PrivateKey, key));
    try testing.expectEqualSlices(u8, &public, &key.public_key().raw);
    const signed = key.sign("namespace", "message");
    try testing.expectEqualSlices(u8, &signature, &signed.raw);
    try testing.expectEqualSlices(u8, &signature_empty, &key.sign("", "").raw);
    try testing.expect(key.public_key().verify("namespace", "message", &signed));
}

test "evrf keys: verification rejects every mismatch" {
    const key = test_key();
    const public = key.public_key();
    const signed = key.sign("namespace", "message");
    try testing.expect(!public.verify("namespace", "other", &signed));
    try testing.expect(!public.verify("other", "message", &signed));
    const other = PrivateKey.from_seed(7);
    try testing.expect(!other.public_key().verify("namespace", "message", &signed));
    for ([_]usize{ 0, 31, 32, 63 }) |position| {
        var tampered = signed;
        tampered.raw[position] ^= 1;
        try testing.expect(!public.verify("namespace", "message", &tampered));
    }
    // A non-canonical commitment point or response is rejected, not reduced.
    var bad_point = signed;
    @memset(bad_point.raw[0..32], 0xff);
    try testing.expect(!public.verify("namespace", "message", &bad_point));
    var bad_scalar = signed;
    @memset(bad_scalar.raw[32..], 0xff);
    try testing.expect(!public.verify("namespace", "message", &bad_scalar));
}

test "evrf keys: codec round trips and rejects invalid encodings" {
    const key = test_key();
    const private_bytes = codec.encode_fixed(PrivateKey, key);
    const decoded = try codec.decode(PrivateKey, gpa, &private_bytes);
    try testing.expect(decoded.eql(&key));

    const public = key.public_key();
    const public_bytes = codec.encode_fixed(PublicKey, public);
    const decoded_public = try codec.decode(PublicKey, gpa, &public_bytes);
    try testing.expect(decoded_public.eql(public));
    try testing.expect(decoded_public.point.eql(public.point));

    const signed = key.sign("namespace", "message");
    const signature_bytes = codec.encode_fixed(Signature, signed);
    try testing.expect((try codec.decode(Signature, gpa, &signature_bytes)).eql(signed));

    const high: [32]u8 = @splat(0xff);
    try testing.expectError(error.Invalid, codec.decode(PublicKey, gpa, &high));
    try testing.expectError(error.Invalid, codec.decode(PrivateKey, gpa, &high));
    try testing.expectError(error.EndOfBuffer, codec.decode(PublicKey, gpa, high[0..31]));
}

test "evrf keys: vrf_recv agrees with the dealer's side" {
    var rng = utils.test_rng();
    const dealer = PrivateKey.random(&rng);
    const receiver = PrivateKey.random(&rng);
    var t = transcript.Transcript.init("evrf", .v1);
    t.commit("round");
    const summary = t.summarize();
    const received = receiver.vrf_recv(summary, dealer.public_key());
    const sent = evrf.banderwagon.vrf_send(
        &summary.bytes,
        dealer.public_key().point,
        receiver.public_key().point,
        dealer.inner.expose().*,
    );
    try testing.expect(received.eql(sent));
}

test "evrf keys: formatting redacts the private key" {
    var buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{test_key()});
    try testing.expectEqualStrings("PrivateKey([REDACTED])", text);
}

// commonware `evrf/mod.rs` tests: vrf_batch_checked through check_batch.

const parallel = @import("parallel");
const shared = @import("../../conformance_test.zig");
const G1 = @import("../../primitives/group.zig").G1;
const Transcript = transcript.Transcript;
const Summary = transcript.Summary;
const Setup = evrf.Setup;
const VrfCommitments = evrf.VrfCommitments;
const Set = utils.ordered.Set;

const batch_namespace = "vrf-batch-checked-test";

/// One dealer's proven outputs to three receivers.
const Dealt = struct {
    sender: PublicKey,
    nonce: Summary,
    outputs: utils.ordered.Map(PublicKey, @import("../../primitives/group.zig").Scalar),
    commitments: VrfCommitments,

    fn init(
        rng: *utils.rng.TestRng,
        setup: *const Setup,
        outer: *const Transcript,
        dealer: PrivateKey,
        receivers: []const PublicKey,
    ) !Dealt {
        var nonce: Summary = undefined;
        rng.fill_bytes(&nonce.bytes);
        const sender = dealer.public_key();
        var t = outer.fork("dealer vrf");
        t.commit(&sender.raw);
        const outputs, const commitments = try dealer.vrf_batch_checked(
            gpa,
            rng,
            setup,
            &t,
            nonce,
            receivers,
            parallel.sequential,
        );
        return .{
            .sender = sender,
            .nonce = nonce,
            .outputs = outputs,
            .commitments = commitments,
        };
    }

    fn deinit(self: *Dealt) void {
        self.outputs.deinit(gpa);
        self.commitments.deinit(gpa);
    }

    fn entry(self: *const Dealt) VrfCommitments.Entry {
        return .{
            .sender = self.sender,
            .msg = &self.nonce.bytes,
            .commitments = &self.commitments,
        };
    }
};

fn random_publics(rng: *utils.rng.TestRng, out: []PublicKey) void {
    for (out) |*public| public.* = PrivateKey.random(rng).public_key();
}

fn check(
    rng: *utils.rng.TestRng,
    setup: *const Setup,
    outer: *const Transcript,
    receivers: []const PublicKey,
    entries: []const VrfCommitments.Entry,
) !utils.ordered.Map(PublicKey, utils.ordered.Map(PublicKey, G1)) {
    var players = try Set(PublicKey).init(gpa, receivers);
    defer players.deinit(gpa);
    return VrfCommitments.check_batch(gpa, rng, setup, outer, &players, entries);
}

fn deinit_checked(checked: *utils.ordered.Map(PublicKey, utils.ordered.Map(PublicKey, G1))) void {
    for (checked.values) |*value| value.deinit(gpa);
    checked.keys.deinit(gpa);
    gpa.free(checked.values);
}

fn expect_commitments(
    expected: utils.ordered.Map(PublicKey, G1),
    actual: utils.ordered.Map(PublicKey, G1),
) !void {
    try testing.expect(expected.keys.eql(actual.keys));
    for (expected.values, actual.values) |a, b| try testing.expect(a.eql(b));
}

test "evrf: vrf_batch_checked round trips through check_batch" {
    try shared.skip_slow();
    var rng = utils.test_rng();
    var setup = try Setup.init(gpa, 3);
    defer setup.deinit(gpa);
    const dealer = PrivateKey.random(&rng);
    var receivers: [3]PrivateKey = undefined;
    for (&receivers) |*receiver| receiver.* = PrivateKey.random(&rng);
    // Receivers in reverse key order: the outputs come back sorted.
    var publics: [3]PublicKey = undefined;
    for (&publics, receivers) |*public, receiver| public.* = receiver.public_key();
    std.mem.sort(PublicKey, &publics, {}, PublicKey.less_than);
    std.mem.reverse(PublicKey, &publics);
    const outer = Transcript.init(batch_namespace, .v1);
    var dealt = try Dealt.init(&rng, &setup, &outer, dealer, &publics);
    defer dealt.deinit();
    var players = try Set(PublicKey).init(gpa, &publics);
    defer players.deinit(gpa);
    try testing.expect(dealt.outputs.keys.eql(players));
    try testing.expect(dealt.commitments.commitments.keys.eql(players));
    for (receivers) |receiver| {
        const output = dealt.outputs.get_value(receiver.public_key()).?;
        try testing.expect(output.eql(receiver.vrf_recv(dealt.nonce, dealt.sender)));
    }
    var checked = try check(&rng, &setup, &outer, &publics, &.{dealt.entry()});
    defer deinit_checked(&checked);
    try testing.expectEqual(1, checked.len());
    try expect_commitments(dealt.commitments.commitments, checked.get_value(dealt.sender).?.*);
}

test "evrf: check_batch rejects perturbed commitments" {
    try shared.skip_slow();
    var rng = utils.test_rng();
    var setup = try Setup.init(gpa, 3);
    defer setup.deinit(gpa);
    const dealer = PrivateKey.random(&rng);
    var publics: [3]PublicKey = undefined;
    random_publics(&rng, &publics);
    const outer = Transcript.init(batch_namespace, .v1);
    var dealt = try Dealt.init(&rng, &setup, &outer, dealer, &publics);
    defer dealt.deinit();
    dealt.commitments.perturb(publics[0], G1.generator);
    var checked = try check(&rng, &setup, &outer, &publics, &.{dealt.entry()});
    defer deinit_checked(&checked);
    try testing.expectEqual(0, checked.len());
}

test "evrf: check_batch rejects a short pedersen_to_plain vector" {
    try shared.skip_slow();
    var rng = utils.test_rng();
    var setup = try Setup.init(gpa, 3);
    defer setup.deinit(gpa);
    const dealer = PrivateKey.random(&rng);
    var publics: [3]PublicKey = undefined;
    random_publics(&rng, &publics);
    const outer = Transcript.init(batch_namespace, .v1);
    var dealt = try Dealt.init(&rng, &setup, &outer, dealer, &publics);
    defer dealt.deinit();
    // Drop the last proof: the dealer must be rejected, not verified on a prefix.
    const proofs = dealt.commitments.proof.pedersen_to_plain;
    dealt.commitments.proof.pedersen_to_plain = try gpa.realloc(proofs, proofs.len - 1);
    try testing.expect(dealt.commitments.proof.pedersen_to_plain.len <
        dealt.commitments.commitments.len());
    var checked = try check(&rng, &setup, &outer, &publics, &.{dealt.entry()});
    defer deinit_checked(&checked);
    try testing.expectEqual(0, checked.len());
}

test "evrf: check_batch falls back to each dealer on failure" {
    try shared.skip_slow();
    var rng = utils.test_rng();
    var setup = try Setup.init(gpa, 3);
    defer setup.deinit(gpa);
    const dealers = [2]PrivateKey{ PrivateKey.random(&rng), PrivateKey.random(&rng) };
    var publics: [3]PublicKey = undefined;
    random_publics(&rng, &publics);
    const outer = Transcript.init(batch_namespace, .v1);
    var good = try Dealt.init(&rng, &setup, &outer, dealers[0], &publics);
    defer good.deinit();
    var bad = try Dealt.init(&rng, &setup, &outer, dealers[1], &publics);
    defer bad.deinit();
    // Tamper with the second dealer so the batch fails and the halving search runs.
    bad.commitments.perturb(publics[0], G1.generator);
    const entries = [_]VrfCommitments.Entry{ good.entry(), bad.entry() };
    var checked = try check(&rng, &setup, &outer, &publics, &entries);
    defer deinit_checked(&checked);
    try testing.expectEqual(1, checked.len());
    try expect_commitments(good.commitments.commitments, checked.get_value(good.sender).?.*);
    try testing.expect(checked.get_value(bad.sender) == null);
}

test "evrf: setup codec round trip" {
    try shared.skip_slow();
    var setup = try Setup.init(gpa, 3);
    defer setup.deinit(gpa);
    const bytes = try codec.encode(Setup, gpa, setup);
    defer gpa.free(bytes);
    var decoded = try codec.decode_cfg(Setup, gpa, bytes, 3);
    defer decoded.deinit(gpa);
    try testing.expectEqual(setup.max_players, decoded.max_players);
    const again = try codec.encode(Setup, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
    // A different max_players is rejected.
    try testing.expectError(error.Invalid, codec.decode_cfg(Setup, gpa, bytes, 4));
}
