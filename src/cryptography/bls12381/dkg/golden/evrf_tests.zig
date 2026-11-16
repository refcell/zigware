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
