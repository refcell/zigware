//! Tests for `pedersen_to_plain.zig` (commonware `zk/pedersen_to_plain.rs` `fuzz` and `test`
//! modules): codec roundtrips, and the prover plan over BLS12-381 G1, where an honest proof
//! verifies and every tweak (claims, masks, responses, namespace) is rejected.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const math = @import("math");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const p2p = @import("pedersen_to_plain.zig");
const Transcript = @import("../transcript.zig").Transcript;
const group = @import("../bls12381/primitives/group.zig");

const Unstructured = minifuzz.Unstructured;
const gpa = testing.allocator;

const namespace = "_COMMONWARE_CRYPTOGRAPHY_ZK_PEDERSEN_TO_PLAIN";
const bad_namespace = "_COMMONWARE_CRYPTOGRAPHY_ZK_PEDERSEN_TO_PLAIN_BUT_DIFFERENT";

const F = group.Scalar;
const G = group.G1;
const S = math.synthetic.Synthetic(F, G);

fn test_setup() p2p.Setup(G) {
    return .{
        .value_generator = G.generator,
        .blinding_generator = G.hash_to_group(namespace, "blinding generator"),
    };
}

const Prover = struct {
    setup: p2p.Setup(G),
    claim: p2p.Claim(G),
    proof: p2p.Proof(F, G),
    bad_namespace: bool = false,
    honest: bool = true,

    fn init(setup: p2p.Setup(G), value: F, blinding: F) Prover {
        const witness: p2p.Witness(F) = .{ .value = value, .blinding = blinding };
        const claim = witness.claim(G, setup);
        var rng = utils.test_rng();
        var transcript = Transcript.init(namespace, .v1);
        const proof = p2p.prove(G, &rng, &transcript, setup, claim, witness);
        return .{ .setup = setup, .claim = claim, .proof = proof };
    }

    fn tweak_plain_claim(self: *Prover, delta: F) void {
        if (delta.eql(F.zero)) return;
        self.honest = false;
        self.claim.plain = self.claim.plain.add(self.setup.value_generator.mul(delta));
    }

    fn tweak_pedersen_claim(self: *Prover, value_delta: F, blinding_delta: F) void {
        if (value_delta.eql(F.zero) and blinding_delta.eql(F.zero)) return;
        self.honest = false;
        const delta = self.setup.value_generator.mul(value_delta)
            .add(self.setup.blinding_generator.mul(blinding_delta));
        self.claim.pedersen = self.claim.pedersen.add(delta);
    }

    fn tweak_mask(self: *Prover, tweak_plain: bool, delta: G) void {
        if (delta.eql(G.zero)) return;
        self.honest = false;
        const mask = if (tweak_plain) &self.proof.plain_mask else &self.proof.pedersen_mask;
        mask.* = mask.add(delta);
    }

    fn tweak_response(self: *Prover, tweak_value: bool, delta: F) void {
        if (delta.eql(F.zero)) return;
        self.honest = false;
        const response = if (tweak_value)
            &self.proof.value_response
        else
            &self.proof.blinding_response;
        response.* = response.add(delta);
    }

    fn set_bad_namespace(self: *Prover) void {
        self.honest = false;
        self.bad_namespace = true;
    }

    fn verify(self: *const Prover) !bool {
        var rng = utils.test_rng();
        var transcript = Transcript.init(if (self.bad_namespace) bad_namespace else namespace, .v1);
        var virtual = try p2p.Setup(G).virtual_setup(gpa, F);
        defer virtual.deinit(gpa);
        var equation = try p2p.verify(G, gpa, &rng, &transcript, &virtual, self.claim, self.proof);
        defer equation.deinit(gpa);
        return (try self.setup.eval(gpa, F, equation)).eql(G.zero);
    }
};

/// commonware's `fuzz::Plan`: a value and blinding, then maybe one malicious tweak.
fn plan_body(_: void, u: *Unstructured) anyerror!void {
    const value = try u.arbitrary(F);
    const blinding = try u.arbitrary(F);
    var prover = Prover.init(test_setup(), value, blinding);
    if (try u.arbitrary(bool)) {
        const choice = try u.arbitrary(u8);
        if (choice < 51) {
            prover.tweak_plain_claim(try u.arbitrary(F));
        } else if (choice < 102) {
            const value_delta = try u.arbitrary(F);
            prover.tweak_pedersen_claim(value_delta, try u.arbitrary(F));
        } else if (choice < 153) {
            const tweak_plain = try u.arbitrary(bool);
            prover.tweak_mask(tweak_plain, try u.arbitrary(G));
        } else if (choice < 204) {
            const tweak_value = try u.arbitrary(bool);
            prover.tweak_response(tweak_value, try u.arbitrary(F));
        } else {
            prover.set_bad_namespace();
        }
    }
    const verified = try prover.verify();
    if (prover.honest and !verified) return error.HonestProofRejected;
    if (!prover.honest and verified) return error.MaliciousProofAccepted;
}

test "pedersen_to_plain fuzz plan (minifuzz)" {
    try (minifuzz.Builder{}).with_search_limit(64).run(gpa, {}, plan_body);
}

test "pedersen_to_plain fuzz plan (std fuzz)" {
    try testing.fuzz({}, math.testing.smith_body(void, plan_body), .{});
}

test "pedersen_to_plain prover tweaks cover no-ops and failures" {
    const setup = test_setup();
    const three = F.from_u64(3);
    const five = F.from_u64(5);
    var honest = Prover.init(setup, three, five);
    honest.tweak_plain_claim(F.zero);
    honest.tweak_pedersen_claim(F.zero, F.zero);
    honest.tweak_mask(true, G.zero);
    honest.tweak_response(false, F.zero);
    try testing.expect(honest.honest);
    try testing.expect(try honest.verify());

    for (0..5) |tweak| {
        var prover = Prover.init(setup, three, five);
        switch (tweak) {
            0 => prover.tweak_plain_claim(F.one),
            1 => prover.tweak_pedersen_claim(F.one, F.one),
            2 => prover.tweak_mask(false, G.generator),
            3 => prover.tweak_response(true, F.one),
            else => prover.set_bad_namespace(),
        }
        try testing.expect(!prover.honest);
        try testing.expect(!try prover.verify());
    }
}

const TF = math.testing.F;
const TG = math.testing.G;

fn expect_roundtrip(comptime T: type, value: T) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    const decoded = try codec.decode(T, gpa, encoded);
    try testing.expect(value.eql(decoded));
    const again = try codec.encode(T, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, encoded, again);
}

fn codec_body(_: void, u: *Unstructured) anyerror!void {
    const value_generator = try u.arbitrary(TG);
    try expect_roundtrip(p2p.Setup(TG), .{
        .value_generator = value_generator,
        .blinding_generator = try u.arbitrary(TG),
    });
    const plain = try u.arbitrary(TG);
    try expect_roundtrip(p2p.Claim(TG), .{ .plain = plain, .pedersen = try u.arbitrary(TG) });
    var proof: p2p.Proof(TF, TG) = undefined;
    proof.plain_mask = try u.arbitrary(TG);
    proof.pedersen_mask = try u.arbitrary(TG);
    proof.value_response = try u.arbitrary(TF);
    proof.blinding_response = try u.arbitrary(TF);
    try expect_roundtrip(p2p.Proof(TF, TG), proof);
}

test "pedersen_to_plain codec roundtrip (minifuzz)" {
    try minifuzz.run(gpa, {}, codec_body);
}
