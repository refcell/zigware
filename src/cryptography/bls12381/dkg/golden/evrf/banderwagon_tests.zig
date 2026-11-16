//! Tests for the golden eVRF over Banderwagon (commonware `evrf/banderwagon.rs` tests). The
//! tests that need bulletproofs (`prove_and_verify_roundtrip`, and the converted circuit
//! encoding) check the `zk.circuit` the conversion starts from instead.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const hex = @import("formatting").hex_literal;
const circuit = @import("../../../../zk/circuit.zig");
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
    var built = try build(sender, &receivers, x);
    defer built.deinit();
    const valued = built.valued.?;
    try testing.expect(valued.is_satisfied());
    for (receivers, built.outputs) |receiver, index| {
        try testing.expect(valued.get(index).eql(evrf.vrf_send("msg", sender, receiver, x)));
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
    var prover = try build(sender, &receivers, x);
    defer prover.deinit();
    var verifier = try build(sender, &receivers, null);
    defer verifier.deinit();
    const a = prover.structure;
    const b = verifier.structure;
    try testing.expectEqual(a.witnesses, b.witnesses);
    try testing.expectEqual(a.constants.len, b.constants.len);
    for (a.constants, b.constants) |left, right| try testing.expect(left.eql(right));
    try testing.expectEqualSlices(circuit.CircuitNode, a.nodes, b.nodes);
    try testing.expectEqualSlices([2]circuit.CircuitIdx, a.assertions, b.assertions);
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
