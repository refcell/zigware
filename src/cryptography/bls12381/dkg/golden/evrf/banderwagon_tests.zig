//! Tests for the golden eVRF over Banderwagon (commonware `evrf/banderwagon.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const hex = @import("formatting").hex_literal;
const parallel = @import("parallel");
const circuit = @import("../../../../zk/circuit.zig");
const bp = @import("../../../../zk/bulletproofs.zig").circuit;
const Transcript = @import("../../../../transcript.zig").Transcript;
const G1 = @import("../../../primitives/group.zig").G1;
const banderwagon = @import("../../../../banderwagon.zig");
const evrf = @import("banderwagon.zig");
const shared = @import("../../../conformance_test.zig");

const F = evrf.F;
const G = evrf.G;
const Base = banderwagon.Base;
const Var = banderwagon.Var;
const Context = banderwagon.Context;
const gpa = testing.allocator;

test "evrf banderwagon: send and recv agree" {
    var rng = utils.test_rng();
    for (0..8) |_| {
        const x_send = F.random(&rng);
        const x_recv = F.random(&rng);
        const sender = G.generator.mul(x_send);
        const receiver = G.generator.mul(x_recv);
        const sent = evrf.vrf_send("msg", sender, receiver, x_send);
        try testing.expect(sent.eql(evrf.vrf_recv("msg", sender, x_recv)));
    }
}

// The first test_rng keys and the output commonware computes for them (a Rust run).
test "evrf banderwagon: output matches commonware" {
    var rng = utils.test_rng();
    const x_send = F.random(&rng);
    const x_recv = F.random(&rng);
    const output = evrf.vrf_recv("msg", G.generator.mul(x_send), x_recv);
    const expected = hex("165831885747c4ca8454a589f3896204b0a626e85f8ae7d3577f3e66d9a49d9b");
    try testing.expectEqualSlices(u8, &expected, &output.to_bytes());
}

test "evrf banderwagon: agreement survives serialization" {
    var rng = utils.test_rng();
    const x_send = F.random(&rng);
    const x_recv = F.random(&rng);
    const sender_bytes = codec.encode_fixed(G, G.generator.mul(x_send));
    const receiver_bytes = codec.encode_fixed(G, G.generator.mul(x_recv));
    const sender = try codec.decode(G, gpa, &sender_bytes);
    const receiver = try codec.decode(G, gpa, &receiver_bytes);
    const sent = evrf.vrf_send("msg", sender, receiver, x_send);
    try testing.expect(sent.eql(evrf.vrf_recv("msg", sender, x_recv)));
}

test "evrf banderwagon: output depends on the message" {
    var rng = utils.test_rng();
    const x = F.random(&rng);
    const sender = G.generator.mul(F.random(&rng));
    try testing.expect(!evrf.vrf_recv("a", sender, x).eql(evrf.vrf_recv("b", sender, x)));
}

fn random_receivers(rng: anytype, out: []G) void {
    for (out) |*receiver| receiver.* = G.generator.mul(F.random(rng));
}

const Built = struct {
    valued: ?circuit.ValuedCircuit(Base),
    structure: circuit.Circuit(Base),
    outputs: [3]circuit.CircuitIdx,

    fn deinit(self: *Built) void {
        if (self.valued) |*valued| valued.deinit(gpa) else self.structure.deinit(gpa);
    }
};

/// Builds the gadget for up to three receivers, as a prover (`secret` set) or a verifier.
fn build(sender: G, receivers: []const G, secret: ?F) !Built {
    std.debug.assert(receivers.len <= 3);
    var outputs: [3]Base = undefined;
    if (secret) |x| {
        for (receivers, outputs[0..receivers.len]) |receiver, *output| {
            output.* = evrf.vrf_send("msg", sender, receiver, x);
        }
    }
    const mode: circuit.Mode = if (secret == null) .verifier else .prover;
    var ctx: Context = try .init(gpa, evrf.capacity(@intCast(receivers.len)), mode);
    errdefer ctx.deinit(gpa);
    var output_vars: [3]Var = undefined;
    const known: ?[]const Base = if (secret == null) null else outputs[0..receivers.len];
    const vars = output_vars[0..receivers.len];
    try evrf.build_circuit(gpa, &ctx, sender, receivers, "msg", secret, known, vars);
    // The capacity is exact.
    try testing.expectEqual(ctx.capacity.nodes, ctx.nodes.items.len);
    try testing.expectEqual(ctx.capacity.constants, ctx.constants.items.len);
    try testing.expectEqual(ctx.capacity.witnesses, ctx.witness_count);
    try testing.expectEqual(ctx.capacity.assertions, ctx.assertions.items.len);
    var built: Built = .{ .valued = null, .structure = undefined, .outputs = undefined };
    if (secret == null) {
        built.structure, const indices = try ctx.finish(gpa, vars);
        defer gpa.free(indices);
        @memcpy(built.outputs[0..indices.len], indices);
    } else {
        const valued, const indices = try ctx.finish_valued(gpa, vars);
        defer gpa.free(indices);
        built.valued = valued;
        built.structure = valued.circuit;
        @memcpy(built.outputs[0..indices.len], indices);
    }
    return built;
}

test "evrf banderwagon: the prover circuit commits the outputs" {
    // Circuit witness generation is slow in Debug builds.
    try shared.skip_slow();
    var rng = utils.test_rng();
    const x = F.random(&rng);
    const sender = G.generator.mul(x);
    var receivers: [3]G = undefined;
    random_receivers(&rng, &receivers);
    var bp_circuit, var witness = try evrf.vrf_batch_checked(gpa, "msg", x, &receivers);
    defer bp_circuit.deinit(gpa);
    defer witness.deinit(gpa);
    try testing.expect(witness.is_satisfied(&bp_circuit));
    // The committed values are the receivers' outputs, in order.
    try testing.expectEqual(receivers.len, witness.values.len);
    for (receivers, witness.values) |receiver, value| {
        try testing.expect(value.eql(evrf.vrf_send("msg", sender, receiver, x)));
    }
}

test "evrf banderwagon: prover and verifier build the same circuit" {
    // Circuit witness generation is slow in Debug builds.
    try shared.skip_slow();
    var rng = utils.test_rng();
    const x = F.random(&rng);
    const sender = G.generator.mul(x);
    var receivers: [2]G = undefined;
    random_receivers(&rng, &receivers);
    var prover, var witness = try evrf.vrf_batch_checked(gpa, "msg", x, &receivers);
    defer prover.deinit(gpa);
    defer witness.deinit(gpa);
    var verifier = try evrf.vrf_batch_checked_circuit(gpa, "msg", sender, &receivers);
    defer verifier.deinit(gpa);
    const prover_bytes = try bp.encode_write_only(gpa, prover);
    defer gpa.free(prover_bytes);
    const verifier_bytes = try bp.encode_write_only(gpa, verifier);
    defer gpa.free(verifier_bytes);
    try testing.expectEqualSlices(u8, prover_bytes, verifier_bytes);
    // The verifier's capacity is exact too.
    var built = try build(sender, &receivers, null);
    built.deinit();
}

test "evrf banderwagon: binding rejects the negated public key" {
    var rng = utils.test_rng();
    const x = F.random(&rng);
    const negated_sender = G.generator.mul(x).neg();
    var receivers: [1]G = undefined;
    random_receivers(&rng, &receivers);
    // The outputs are computed against the negated key too, so only the key binding fails.
    var built = try build(negated_sender, &receivers, x);
    defer built.deinit();
    try testing.expect(!built.valued.?.is_satisfied());
}

const Verification = struct {
    rng: *utils.rng.TestRng,
    transcript: *Transcript,
    circuit: *const evrf.Circuit,
    claim: bp.Claim(G1),
    proof: bp.Proof(Base, G1),

    fn equation(
        self: Verification,
        allocator: std.mem.Allocator,
        virtual: *const bp.Setup(Synthetic),
    ) !?Synthetic {
        return bp.verify(
            G1,
            allocator,
            self.rng,
            self.transcript,
            virtual,
            self.circuit,
            self.claim,
            self.proof,
        );
    }
};

const Synthetic = @import("math").synthetic.Synthetic(Base, G1);
const test_dst = "_COMMONWARE_CRYPTOGRAPHY_GOLDEN_BANDERWAGON_TEST";

test "evrf banderwagon: prove and verify roundtrip" {
    try shared.skip_slow();
    var rng = utils.test_rng();
    const x = F.random(&rng);
    var receivers: [1]G = undefined;
    random_receivers(&rng, &receivers);
    var bp_circuit, var witness = try evrf.vrf_batch_checked(gpa, "msg", x, &receivers);
    defer bp_circuit.deinit(gpa);
    defer witness.deinit(gpa);
    // Size the setup to the circuit.
    const padded = try std.math.ceilPowerOfTwo(usize, @max(bp_circuit.internal_vars, 1));
    const lg_len: u8 = @intCast(@ctz(padded));
    var setup = try bp.Setup(G1).hashed(gpa, test_dst, lg_len, G1.generator);
    defer setup.deinit(gpa);
    var claim = try witness.claim(G1, gpa, &setup);
    defer claim.deinit(gpa);
    var prover_transcript = Transcript.init(test_dst, .v1);
    var proof = (try bp.prove(
        G1,
        gpa,
        &rng,
        &prover_transcript,
        &setup,
        &bp_circuit,
        claim,
        &witness,
        parallel.sequential,
    )).?;
    defer proof.deinit(gpa);
    var verifier_transcript = Transcript.init(test_dst, .v1);
    const verification: Verification = .{
        .rng = &rng,
        .transcript = &verifier_transcript,
        .circuit = &bp_circuit,
        .claim = claim,
        .proof = proof,
    };
    const residue = try setup.eval(gpa, Base, verification, Verification.equation);
    try testing.expect(residue.?.eql(G1.zero));
}
