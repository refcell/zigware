//! Tests for the bulletproofs circuit argument (commonware `zk/bulletproofs/circuit.rs` `fuzz`
//! and `test` modules): matrix and circuit encodings, `zk.circuit` conversion, random R1CS
//! satisfaction, setup roundtrips, the prove/verify fuzz plan, and batched checks.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const math = @import("math");
const parallel = @import("parallel");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const bp = @import("circuit.zig");
const ipa = @import("ipa.zig");
const zkc = @import("zkc.zig");
const zk = @import("../circuit.zig");
const zk_test = @import("../circuit_test.zig");
const Transcript = @import("../../transcript.zig").Transcript;

const F = math.testing.F;
const G = math.testing.G;
const S = math.synthetic.Synthetic(F, G);
const Matrix = bp.SparseMatrix(F);
const Circuit = bp.Circuit(F);
const Setup = bp.Setup(G);
const Witness = bp.Witness(F);
const Claim = bp.Claim(G);
const Proof = bp.Proof(F, G);
const Unstructured = minifuzz.Unstructured;
const gpa = testing.allocator;

const namespace = "_COMMONWARE_CRYPTOGRAPHY_ZK_BULLETPROOFS_CIRCUIT";
const setup_pairs = 64;

fn f(value: u64) F {
    return F.from_u64(value);
}

/// commonware's `test_setup`: multiples 1..=131 of the generator; the first 128 are the
/// `(G_i, H_i)` pairs, then `Q`, `B`, and `B~`.
fn test_setup() !Setup {
    var generators: [2 * setup_pairs + 3]G = undefined;
    for (&generators, 1..) |*generator, i| generator.* = G.generator.mul(f(i));
    var pairs: [setup_pairs][2]G = undefined;
    for (&pairs, 0..) |*pair, i| pair.* = .{ generators[2 * i], generators[2 * i + 1] };
    return .{
        .ipa = try ipa.Setup(G).init(gpa, generators[2 * setup_pairs], &pairs),
        .value_generator = generators[2 * setup_pairs + 1],
        .blinding_generator = generators[2 * setup_pairs + 2],
    };
}

fn encode(comptime T: type, value: T) ![]u8 {
    if (comptime @hasDecl(T, "read")) return codec.encode(T, gpa, value);
    return bp.encode_write_only(gpa, value);
}

const Verification = struct {
    rng: *utils.rng.TestRng,
    transcript: *Transcript,
    circuit: *const Circuit,
    claim: Claim,
    proof: Proof,

    fn equation(self: Verification, allocator: Allocator, virtual: *const bp.Setup(S)) !?S {
        return bp.verify(
            G,
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

/// Proves then verifies with one rng, as commonware's `prove_and_verify`; a failed prove
/// counts as rejection.
fn prove_and_verify(
    setup: *const Setup,
    circuit: *const Circuit,
    claim: Claim,
    witness: *const Witness,
) !bool {
    var rng = utils.test_rng();
    var prover_transcript = Transcript.init(namespace, .v1);
    const sequential = parallel.sequential;
    const result = try bp.prove(
        G,
        gpa,
        &rng,
        &prover_transcript,
        setup,
        circuit,
        claim,
        witness,
        sequential,
    );
    var proof = result orelse return false;
    defer proof.deinit(gpa);
    var verifier_transcript = Transcript.init(namespace, .v1);
    const verification: Verification = .{
        .rng = &rng,
        .transcript = &verifier_transcript,
        .circuit = circuit,
        .claim = claim,
        .proof = proof,
    };
    const value = try setup.eval(gpa, F, verification, Verification.equation);
    return if (value) |point| point.eql(G.zero) else false;
}

/// `y = a x^2 + b x + c` over committed `(x, y)`, with one gate `x * x`.
fn quadratic_circuit(a: F, b: F, c: F) !Circuit {
    var weights: Matrix = .{};
    errdefer weights.deinit(gpa);
    try weights.set(gpa, 0, 1, F.one); // Bind l_0 = x.
    try weights.set(gpa, 0, 3, F.one.neg());
    try weights.set(gpa, 1, 1, F.one); // Bind r_0 = x.
    try weights.set(gpa, 1, 4, F.one.neg());
    try weights.set(gpa, 2, 0, c); // Enforce y = a x^2 + b x + c.
    try weights.set(gpa, 2, 1, b);
    try weights.set(gpa, 2, 2, F.one.neg());
    try weights.set(gpa, 2, 5, a);
    return Circuit.init(gpa, 2, weights).?;
}

/// commonware's `Case`: a quadratic circuit and a witness that satisfies it when `valid`.
const Case = struct {
    circuit: Circuit,
    witness: Witness,
    valid: bool,

    fn arbitrary(u: *Unstructured) !Case {
        const a = try u.arbitrary(F);
        const b = try u.arbitrary(F);
        const c = try u.arbitrary(F);
        const x = try u.arbitrary(F);
        const valid = try u.arbitrary(bool);
        var y = a.mul(x).mul(x).add(b.mul(x)).add(c);
        if (!valid) {
            var tweak = try u.arbitrary(F);
            if (tweak.eql(F.zero)) tweak = F.one;
            y = y.add(tweak);
        }
        const blind_x = try u.arbitrary(F);
        const blinding: [2]F = .{ blind_x, try u.arbitrary(F) };
        var witness = (try Witness.init(gpa, &.{ x, y }, &blinding, &.{x}, &.{x}, &.{x.mul(x)})).?;
        errdefer witness.deinit(gpa);
        const case: Case = .{
            .circuit = try quadratic_circuit(a, b, c),
            .witness = witness,
            .valid = valid,
        };
        if (case.witness.is_satisfied(&case.circuit) != valid) return error.CaseValidityMismatch;
        return case;
    }

    fn deinit(case: *Case) void {
        case.circuit.deinit(gpa);
        case.witness.deinit(gpa);
    }
};

fn verify_matches_satisfaction(setup: *const Setup, case: *const Case) !void {
    var claim = try case.witness.claim(G, gpa, setup);
    defer claim.deinit(gpa);
    const verified = try prove_and_verify(setup, &case.circuit, claim, &case.witness);
    try testing.expectEqual(case.witness.is_satisfied(&case.circuit), verified);
}

fn build_valued(plan: *const zk_test.Plan) !zk.ValuedCircuit(F) {
    var ctx = try zk.Context(F).init(gpa, .uniform(256), .prover);
    plan.build(&ctx);
    const valued, const indices = try ctx.finish_valued(gpa, &.{});
    gpa.free(indices);
    return valued;
}

/// Converting preserves satisfaction (committing a random subset of witnesses); a satisfied
/// conversion proves and verifies, and tampering with a commitment breaks verification.
fn zkc_conversion_preserves_satisfaction(
    setup: *const Setup,
    plan: *const zk_test.Plan,
    u: *Unstructured,
) !void {
    var valued = try build_valued(plan);
    defer valued.deinit(gpa);
    var committed: std.ArrayList(zk.CircuitIdx) = .empty;
    defer committed.deinit(gpa);
    for (0..valued.circuit.witnesses) |i| {
        if (try u.arbitrary(bool)) try committed.append(gpa, .{ .witness = @intCast(i) });
    }
    var rng = utils.test_rng();
    var circuit, var witness = try zkc.zkc_to_circuit_and_witness(
        F,
        gpa,
        &rng,
        &valued,
        committed.items,
    );
    defer circuit.deinit(gpa);
    defer witness.deinit(gpa);
    const satisfied = witness.is_satisfied(&circuit);
    try testing.expectEqual(plan.satisfied, satisfied);
    if (!satisfied) return;
    try testing.expect(circuit.internal_vars <= setup_pairs);
    var claim = try witness.claim(G, gpa, setup);
    defer claim.deinit(gpa);
    try testing.expect(try prove_and_verify(setup, &circuit, claim, &witness));
    if (committed.items.len == 0) return;
    const j = try u.choose_index(committed.items.len);
    const original = claim.commitments[j];
    claim.commitments[j] = original.add(setup.value_generator);
    try testing.expect(!try prove_and_verify(setup, &circuit, claim, &witness));
    claim.commitments[j] = original;
}

/// commonware's `fuzz::Plan`: a quadratic case, or a `zk.circuit` conversion.
fn plan_body(setup: *const Setup, u: *Unstructured) anyerror!void {
    switch (u.int_in_range(u8, 0, 1)) {
        0 => {
            var case = try Case.arbitrary(u);
            defer case.deinit();
            try verify_matches_satisfaction(setup, &case);
        },
        else => {
            const plan = zk_test.Plan.arbitrary(u);
            try zkc_conversion_preserves_satisfaction(setup, &plan, u);
        },
    }
}

test "bulletproofs circuit fuzz plan (minifuzz)" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    try minifuzz.run(gpa, @as(*const Setup, &setup), plan_body);
}

test "bulletproofs circuit fuzz plan (std fuzz)" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    const body = math.testing.smith_body(*const Setup, plan_body);
    try testing.fuzz(@as(*const Setup, &setup), body, .{});
}

fn zkc_body(setup: *const Setup, u: *Unstructured) anyerror!void {
    const plan = zk_test.Plan.arbitrary(u);
    try zkc_conversion_preserves_satisfaction(setup, &plan, u);
}

test "bulletproofs zkc conversion preserves satisfaction (minifuzz)" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    try minifuzz.run(gpa, @as(*const Setup, &setup), zkc_body);
}

test "bulletproofs sparse matrix encoding binds dimensions" {
    const matrix: Matrix = .{};
    var wider: Matrix = .{};
    wider.pad(1, 0);
    var taller: Matrix = .{};
    taller.pad(0, 1);
    const encodings = [_][]u8{
        try encode(Matrix, matrix),
        try encode(Matrix, wider),
        try encode(Matrix, taller),
    };
    defer for (encodings) |bytes| gpa.free(bytes);
    try testing.expect(!std.mem.eql(u8, encodings[0], encodings[1]));
    try testing.expect(!std.mem.eql(u8, encodings[0], encodings[2]));
    try testing.expect(!std.mem.eql(u8, encodings[1], encodings[2]));
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, encodings[0]);
}

test "bulletproofs distinct valid circuits encode differently" {
    var no_vars: Matrix = .{};
    no_vars.pad(1, 0);
    var none = Circuit.init(gpa, 0, no_vars).?;
    defer none.deinit(gpa);
    var one_var: Matrix = .{};
    one_var.pad(4, 0);
    var one = Circuit.init(gpa, 0, one_var).?;
    defer one.deinit(gpa);
    try testing.expectEqual(0, none.internal_vars);
    try testing.expectEqual(1, one.internal_vars);
    try testing.expect(none.is_satisfied(&.{}, &.{}, &.{}));
    try testing.expect(!one.is_satisfied(&.{}, &.{}, &.{}));
    try testing.expect(one.is_satisfied(&.{}, &.{F.zero}, &.{F.zero}));
    const a = try encode(Circuit, none);
    defer gpa.free(a);
    const b = try encode(Circuit, one);
    defer gpa.free(b);
    try testing.expect(!std.mem.eql(u8, a, b));
    var bad: Matrix = .{};
    bad.pad(3, 0);
    try testing.expect(Circuit.init(gpa, 0, bad) == null);
}

test "bulletproofs converted circuits bind internal vars" {
    var ctx_one = try zk.Context(F).init(gpa, .uniform(16), .verifier);
    {
        const a = zk.Var(F).witness_value(&ctx_one, F.zero);
        const b = zk.Var(F).witness_value(&ctx_one, F.zero);
        const product = a.mul(b);
        product.assert_eq(product);
    }
    var zk_one, const indices_one = try ctx_one.finish(gpa, &.{});
    defer zk_one.deinit(gpa);
    gpa.free(indices_one);
    var one = try zkc.zkc_to_circuit(F, gpa, &zk_one, &.{});
    defer one.deinit(gpa);

    var ctx_two = try zk.Context(F).init(gpa, .uniform(16), .verifier);
    {
        const w0 = zk.Var(F).witness_value(&ctx_two, F.zero);
        const w1 = zk.Var(F).witness_value(&ctx_two, F.zero);
        const w2 = zk.Var(F).witness_value(&ctx_two, F.zero);
        w1.assert_eq(w1);
        w0.assert_eq(w0);
        w2.assert_eq(w2);
    }
    var zk_two, const indices_two = try ctx_two.finish(gpa, &.{});
    defer zk_two.deinit(gpa);
    gpa.free(indices_two);
    var two = try zkc.zkc_to_circuit(F, gpa, &zk_two, &.{});
    defer two.deinit(gpa);

    try testing.expectEqual(1, one.internal_vars);
    try testing.expectEqual(2, two.internal_vars);
    const weights_one = try encode(Matrix, one.weights);
    defer gpa.free(weights_one);
    const weights_two = try encode(Matrix, two.weights);
    defer gpa.free(weights_two);
    try testing.expectEqualSlices(u8, weights_one, weights_two);
    const circuit_one = try encode(Circuit, one);
    defer gpa.free(circuit_one);
    const circuit_two = try encode(Circuit, two);
    defer gpa.free(circuit_two);
    try testing.expect(!std.mem.eql(u8, circuit_one, circuit_two));
}

test "bulletproofs zkc conversion preserves committed order" {
    var ctx = try zk.Context(F).init(gpa, .uniform(16), .prover);
    {
        const a = zk.Var(F).witness_value(&ctx, f(1));
        const b = zk.Var(F).witness_value(&ctx, f(2));
        a.mul(b).assert_eq(zk.Var(F).constant(&ctx, f(2)));
    }
    var valued, const indices = try ctx.finish_valued(gpa, &.{});
    defer valued.deinit(gpa);
    gpa.free(indices);
    var rng = utils.test_rng();
    const committed: [3]zk.CircuitIdx = .{
        .{ .witness = 1 },
        .{ .witness = 0 },
        .{ .witness = 1 },
    };
    var circuit, var witness = try zkc.zkc_to_circuit_and_witness(
        F,
        gpa,
        &rng,
        &valued,
        &committed,
    );
    defer circuit.deinit(gpa);
    defer witness.deinit(gpa);
    try testing.expect(witness.is_satisfied(&circuit));
    try testing.expectEqualSlices(F, &.{ f(2), f(1), f(2) }, witness.values);
}

test "bulletproofs zkc conversion handles a long add doubling chain" {
    // A shared add chain (x = x + x, repeated) must convert in time and memory linear in
    // its length, not exponential.
    const depth = 64;
    var expected = F.one;
    for (0..depth) |_| expected = expected.add(expected);
    var ctx = try zk.Context(F).init(gpa, .uniform(256), .prover);
    {
        var x = zk.Var(F).witness_value(&ctx, F.one);
        for (0..depth) |_| x = x.add(x);
        x.assert_eq(zk.Var(F).constant(&ctx, expected));
    }
    var valued, const indices = try ctx.finish_valued(gpa, &.{});
    defer valued.deinit(gpa);
    gpa.free(indices);
    const committed: [1]zk.CircuitIdx = .{.{ .witness = 0 }};
    var rng = utils.test_rng();
    var circuit, var witness = try zkc.zkc_to_circuit_and_witness(
        F,
        gpa,
        &rng,
        &valued,
        &committed,
    );
    defer circuit.deinit(gpa);
    defer witness.deinit(gpa);
    try testing.expect(witness.is_satisfied(&circuit));
}

/// Random R1CS `(A z) * (B z) = C z` with `N` variables and `M` constraints, laid out as a
/// circuit: it is satisfied exactly when every constraint holds.
fn r1cs_body(_: void, u: *Unstructured) anyerror!void {
    const n = 2;
    const m = 4;
    var a: [m][n]F = undefined;
    var b: [m][n]F = undefined;
    var c: [m][n]F = undefined;
    var z: [n]F = undefined;
    for ([_]*[m][n]F{ &a, &b, &c }) |matrix| {
        for (matrix) |*row| for (row) |*value| {
            value.* = try u.arbitrary(F);
        };
    }
    for (&z) |*value| value.* = try u.arbitrary(F);
    var left: [m]F = @splat(F.zero);
    var right: [m]F = @splat(F.zero);
    var satisfied = true;
    for (0..m) |i| {
        var accumulator = F.zero;
        for (0..n) |j| {
            left[i] = left[i].add(a[i][j].mul(z[j]));
            right[i] = right[i].add(b[i][j].mul(z[j]));
            accumulator = accumulator.add(c[i][j].mul(z[j]));
        }
        satisfied = satisfied and accumulator.eql(left[i].mul(right[i]));
    }
    var weights: Matrix = .{};
    errdefer weights.deinit(gpa);
    var row: usize = 0;
    for ([_]*const [m][n]F{ &a, &b, &c }, 0..) |matrix, block| {
        for (0..m) |i| {
            try weights.set(gpa, row, 1 + n + block * m + i, F.one.neg());
            for (0..n) |j| try weights.set(gpa, row, 1 + j, matrix[i][j]);
            row += 1;
        }
    }
    var circuit = Circuit.init(gpa, n, weights).?;
    defer circuit.deinit(gpa);
    try testing.expectEqual(satisfied, circuit.is_satisfied(&z, &left, &right));
}

test "bulletproofs random r1cs satisfaction (minifuzz)" {
    try minifuzz.run(gpa, {}, r1cs_body);
}

test "bulletproofs setup roundtrip" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    const encoded = try encode(Setup, setup);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(Setup, gpa, encoded, .{ setup.ipa.g.len, {} });
    defer decoded.deinit(gpa);
    try testing.expect(setup.ipa.eql(decoded.ipa));
    try testing.expect(setup.value_generator.eql(decoded.value_generator));
    try testing.expect(setup.blinding_generator.eql(decoded.blinding_generator));
    const again = try encode(Setup, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, encoded, again);
}

// An over-long claim (more commitments than the circuit commits) must be rejected even
// though a proof was generated against it.
test "bulletproofs verify rejects an over-long claim" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    const x = f(3);
    const y = x.mul(x).add(x).add(F.one);
    var circuit = try quadratic_circuit(F.one, F.one, F.one);
    defer circuit.deinit(gpa);
    var witness = (try Witness.init(
        gpa,
        &.{ x, y },
        &.{ F.zero, F.zero },
        &.{x},
        &.{x},
        &.{x.mul(x)},
    )).?;
    defer witness.deinit(gpa);
    const honest = try witness.claim(G, gpa, &setup);
    defer gpa.free(honest.commitments);
    const commitments: [3]G = .{
        honest.commitments[0],
        honest.commitments[1],
        G.generator.mul(f(9)),
    };
    const claim: Claim = .{ .commitments = @constCast(&commitments) };

    var rng = utils.test_rng();
    var prover_transcript = Transcript.init("verify-rejects-over-long-claim", .v1);
    const sequential = parallel.sequential;
    var proof = (try bp.prove(
        G,
        gpa,
        &rng,
        &prover_transcript,
        &setup,
        &circuit,
        claim,
        &witness,
        sequential,
    )).?;
    defer proof.deinit(gpa);
    var verifier_transcript = Transcript.init("verify-rejects-over-long-claim", .v1);
    const verification: Verification = .{
        .rng = &rng,
        .transcript = &verifier_transcript,
        .circuit = &circuit,
        .claim = claim,
        .proof = proof,
    };
    try testing.expect(try setup.eval(gpa, F, verification, Verification.equation) == null);
}

const Batch = struct {
    transcripts: []Transcript,
    circuit: *const Circuit,
    claims: []const Claim,
    proofs: []const Proof,

    fn equations(
        self: Batch,
        allocator: Allocator,
        virtual: *const bp.Setup(S),
        rng: *utils.rng.TestRng,
    ) !?[]?S {
        const out = try allocator.alloc(?S, self.claims.len);
        @memset(out, null);
        for (
            out,
            self.transcripts,
            self.claims,
            self.proofs,
        ) |*equation, *transcript, claim, proof| {
            equation.* = try bp.verify(
                G,
                allocator,
                rng,
                transcript,
                virtual,
                self.circuit,
                claim,
                proof,
            );
        }
        return out;
    }
};

test "bulletproofs batched checks find the invalid items" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    var circuit = try quadratic_circuit(f(2), f(3), f(5));
    defer circuit.deinit(gpa);
    var claims: [5]Claim = undefined;
    var proofs: [5]Proof = undefined;
    var rng = utils.test_rng();
    for (&claims, &proofs, 0..) |*claim, *proof, i| {
        const x = f(i + 1);
        const y = f(2).mul(x).mul(x).add(f(3).mul(x)).add(f(5));
        var witness = (try Witness.init(
            gpa,
            &.{ x, y },
            &.{ f(7), f(i) },
            &.{x},
            &.{x},
            &.{x.mul(x)},
        )).?;
        defer witness.deinit(gpa);
        claim.* = try witness.claim(G, gpa, &setup);
        var transcript = Transcript.init(namespace, .v1);
        proof.* = (try bp.prove(
            G,
            gpa,
            &rng,
            &transcript,
            &setup,
            &circuit,
            claim.*,
            &witness,
            parallel.sequential,
        )).?;
    }
    defer for (&claims, &proofs) |*claim, *proof| {
        claim.deinit(gpa);
        proof.deinit(gpa);
    };
    // Items 1 and 3 claim a commitment the proof does not open; item 4 has the wrong arity.
    claims[1].commitments[0] = claims[1].commitments[0].add(setup.value_generator);
    claims[3].commitments[1] = claims[3].commitments[1].add(setup.blinding_generator);
    const short: Claim = .{ .commitments = claims[4].commitments[0..1] };
    const batch_claims: [5]Claim = .{ claims[0], claims[1], claims[2], claims[3], short };
    var transcripts: [5]Transcript = @splat(Transcript.init(namespace, .v1));
    const batch: Batch = .{
        .transcripts = &transcripts,
        .circuit = &circuit,
        .claims = &batch_claims,
        .proofs = &proofs,
    };
    const verdicts = (try setup.eval_check_batched(gpa, F, &rng, batch, Batch.equations)).?;
    defer gpa.free(verdicts);
    try testing.expectEqualSlices(bool, &.{ true, false, true, false, false }, verdicts);
}
