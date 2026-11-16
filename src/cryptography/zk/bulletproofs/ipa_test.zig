//! Tests for `ipa.zig` (commonware `zk/bulletproofs/ipa.rs` `fuzz` module): codec roundtrips
//! of arbitrary setups, claims, and proofs, and the prover plan, where an honest proof must
//! verify and every malicious tweak (product, length, round commitments, namespace) must not.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const math = @import("math");
const parallel = @import("parallel");
const minifuzz = @import("invariants").minifuzz;
const ipa = @import("ipa.zig");
const Transcript = @import("../../transcript.zig").Transcript;

const F = math.testing.F;
const G = math.testing.G;
const S = math.synthetic.Synthetic(F, G);
const Setup = ipa.Setup(G);
const Claim = ipa.Claim(F, G);
const Proof = ipa.Proof(F, G);
const Witness = ipa.Witness(F);
const Unstructured = minifuzz.Unstructured;
const gpa = testing.allocator;

const vector_lg_max: u8 = 5;
const vector_len_max: usize = 1 << vector_lg_max;
const setup_vector_len_max: usize = 2 * vector_len_max;
const generator_count: usize = 2 * setup_vector_len_max + 1;
const namespace = "_COMMONWARE_CRYPTOGRAPHY_ZK_BULLETPROOFS_IPA";
const bad_namespace = "_COMMONWARE_CRYPTOGRAPHY_ZK_BULLETPROOFS_IPA_BUT_DIFFERENT";

/// commonware's `test_setup`: generator multiples 1..=129, the first as `Q`.
pub fn test_setup() !Setup {
    var generators: [generator_count]G = undefined;
    for (&generators, 1..) |*generator, i| generator.* = G.generator.mul(F.from_u64(i));
    var pairs: [setup_vector_len_max][2]G = undefined;
    for (&pairs, 0..) |*pair, i| pair.* = .{ generators[1 + 2 * i], generators[2 + 2 * i] };
    return Setup.init(gpa, generators[0], &pairs);
}

fn prove(setup: *const Setup, claim: Claim, witness: *const Witness) !Proof {
    var transcript = Transcript.init(namespace, .v1);
    const proof = try ipa.prove(G, gpa, &transcript, setup, claim, witness, parallel.sequential);
    return proof orelse error.ProvingFailed;
}

const Prover = struct {
    setup: *const Setup,
    witness: Witness,
    claim: Claim,
    proof: Proof,
    bad_namespace: bool = false,
    honest: bool = true,

    fn init(setup: *const Setup, y: F, a: []const F, b: []const F) !Prover {
        const result = try Witness.init_with_claim(G, gpa, setup, y, a, b);
        var witness, const claim = result orelse return error.WitnessRejected;
        errdefer witness.deinit(gpa);
        return .{
            .setup = setup,
            .witness = witness,
            .claim = claim,
            .proof = try prove(setup, claim, &witness),
        };
    }

    fn deinit(self: *Prover) void {
        self.witness.deinit(gpa);
        self.proof.deinit(gpa);
        self.* = undefined;
    }

    fn reprove(self: *Prover, claim: Claim) !void {
        const proof = try prove(self.setup, claim, &self.witness);
        self.proof.deinit(gpa);
        self.proof = proof;
    }

    /// Moves `delta` from the product into the commitment, `(c - d) w Q + (P + d Q)`, which
    /// only verifies if the challenge `w` is not applied to the product generator.
    fn tweak_product(self: *Prover, delta: F) !void {
        if (delta.eql(F.zero)) return;
        self.honest = false;
        self.claim.product = self.claim.product.sub(delta);
        self.claim.commitment = self.claim.commitment.add(self.setup.product_generator.mul(delta));
        try self.reprove(self.claim);
    }

    /// Zero-pads the witness to twice its length and proves that; the proof no longer
    /// matches the claimed length.
    fn increase_length(self: *Prover) !void {
        self.honest = false;
        const longer_log_len = self.claim.log_len + 1;
        const longer_len = @as(usize, 1) << @intCast(longer_log_len);
        const len = self.witness.a.len;
        self.witness.a = try gpa.realloc(self.witness.a, longer_len);
        @memset(self.witness.a[len..], F.zero);
        self.witness.b = try gpa.realloc(self.witness.b, longer_len);
        @memset(self.witness.b[len..], F.zero);
        var longer_claim = self.claim;
        longer_claim.log_len = longer_log_len;
        try self.reprove(longer_claim);
    }

    fn tweak_l_r_coms(self: *Prover, u: *Unstructured) !void {
        if (self.proof.l_r_coms.len == 0) return;
        const round = u.int_in_range(usize, 0, self.proof.l_r_coms.len - 1);
        const tweak_left = try u.arbitrary(bool);
        const delta = try u.arbitrary(G);
        if (delta.eql(G.zero)) return;
        self.honest = false;
        const side: usize = if (tweak_left) 0 else 1;
        const point = &self.proof.l_r_coms[round][side];
        point.* = point.add(delta);
    }

    const Check = struct { namespace: []const u8, claim: Claim, proof: Proof };

    fn equation(check: Check, allocator: Allocator, virtual: *const ipa.Setup(S)) !?S {
        var transcript = Transcript.init(check.namespace, .v1);
        return ipa.verify(G, allocator, &transcript, virtual, check.claim, check.proof);
    }

    fn verify(self: *const Prover) !bool {
        const check: Check = .{
            .namespace = if (self.bad_namespace) bad_namespace else namespace,
            .claim = self.claim,
            .proof = self.proof,
        };
        const result = try self.setup.eval(gpa, F, check, equation);
        return if (result) |value| value.eql(G.zero) else false;
    }
};

/// commonware's `fuzz::Plan`: a power-of-two length up to 32, `y`, and the vectors.
const Plan = struct {
    len: usize,
    y: F,
    a: [vector_len_max]F,
    b: [vector_len_max]F,

    fn arbitrary(u: *Unstructured) !Plan {
        const lg_len = u.int_in_range(u8, 0, vector_lg_max);
        var plan: Plan = .{
            .len = @as(usize, 1) << @intCast(lg_len),
            .y = try u.arbitrary(F),
            .a = undefined,
            .b = undefined,
        };
        for (plan.a[0..plan.len]) |*a_i| a_i.* = try u.arbitrary(F);
        for (plan.b[0..plan.len]) |*b_i| b_i.* = try u.arbitrary(F);
        return plan;
    }

    fn run(plan: *const Plan, setup: *const Setup, u: *Unstructured) !void {
        var prover = try Prover.init(setup, plan.y, plan.a[0..plan.len], plan.b[0..plan.len]);
        defer prover.deinit();
        // Is the prover going to be malicious at all?
        if (try u.arbitrary(bool)) {
            const choice = try u.arbitrary(u8);
            if (choice < 64) {
                try prover.tweak_product(try u.arbitrary(F));
            } else if (choice < 128) {
                try prover.increase_length();
            } else if (choice < 192) {
                try prover.tweak_l_r_coms(u);
            } else {
                prover.bad_namespace = true;
                prover.honest = false;
            }
        }
        const verified = try prover.verify();
        if (prover.honest and !verified) return error.HonestProofRejected;
        if (!prover.honest and verified) return error.MaliciousProofAccepted;
    }
};

pub fn plan_body(setup: *const Setup, u: *Unstructured) anyerror!void {
    const plan = try Plan.arbitrary(u);
    try plan.run(setup, u);
}

test "ipa fuzz plan: honest proofs verify, tweaked ones do not (minifuzz)" {
    // Minutes in Debug, so it runs in optimized builds (CI's ReleaseSafe job) or -Dslow-tests.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    var setup = try test_setup();
    defer setup.deinit(gpa);
    try minifuzz.run(gpa, @as(*const Setup, &setup), plan_body);
}

test "ipa fuzz plan (std fuzz)" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    const body = math.testing.smith_body(*const Setup, plan_body);
    try testing.fuzz(@as(*const Setup, &setup), body, .{});
}

test "ipa prover tweaks cover edge paths" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    const f = F.from_u64;

    var honest = try Prover.init(&setup, f(1), &.{f(3)}, &.{f(4)});
    defer honest.deinit();
    try honest.tweak_product(F.zero);
    var empty = Unstructured.init(&.{});
    try honest.tweak_l_r_coms(&empty);
    try testing.expect(honest.honest);
    try testing.expect(try honest.verify());

    for (0..4) |tweak| {
        var prover = try Prover.init(&setup, f(1), &.{ f(3), f(5) }, &.{ f(4), f(6) });
        defer prover.deinit();
        switch (tweak) {
            0 => try prover.tweak_product(f(1)),
            1 => try prover.increase_length(),
            2 => {
                var u = Unstructured.init(&.{ 1, 1, 0, 0, 0, 0, 0, 0, 0 });
                try prover.tweak_l_r_coms(&u);
            },
            else => {
                prover.bad_namespace = true;
                prover.honest = false;
            },
        }
        try testing.expect(!prover.honest);
        try testing.expect(!try prover.verify());
    }
}

test "ipa rejects mismatched witnesses and short setups" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    const f = F.from_u64;
    const three: [3]F = .{ f(1), f(2), f(3) };
    try testing.expect(try Witness.init(gpa, &three, &three) == null);
    try testing.expect(try Witness.init(gpa, &.{}, &.{}) == null);
    const long: [2 * setup_vector_len_max]F = @splat(f(1));
    try testing.expect(try Witness.init_with_claim(G, gpa, &setup, f(1), &long, &long) == null);
    try testing.expect(setup.supports(6) and !setup.supports(7) and !setup.supports(200));

    var prover = try Prover.init(&setup, f(2), &.{ f(3), f(5) }, &.{ f(4), f(6) });
    defer prover.deinit();
    var claim = prover.claim;
    claim.log_len = 2;
    var transcript = Transcript.init(namespace, .v1);
    const strategy = parallel.sequential;
    const proof = try ipa.prove(G, gpa, &transcript, &setup, claim, &prover.witness, strategy);
    try testing.expect(proof == null);
}

test "ipa proofs do not depend on the strategy" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    var a: [vector_len_max]F = undefined;
    var b: [vector_len_max]F = undefined;
    for (&a, &b, 0..) |*a_i, *b_i, i| {
        a_i.* = F.from_u64(3 * i + 1);
        b_i.* = F.from_u64(7 * i + 2);
    }
    var prover = try Prover.init(&setup, F.from_u64(9), &a, &b);
    defer prover.deinit();
    const pool = try parallel.ThreadPool.create(gpa, testing.io, .{ .threads = 3 });
    defer pool.destroy();
    var transcript = Transcript.init(namespace, .v1);
    const rayon = parallel.Rayon.init(pool);
    const result = try ipa.prove(G, gpa, &transcript, &setup, prover.claim, &prover.witness, rayon);
    var proof = result.?;
    defer proof.deinit(gpa);
    try testing.expect(proof.eql(prover.proof));
    try testing.expect(try prover.verify());
}

/// arbitrary's `Vec<(G, G)>`: a continue flag before each pair.
fn arbitrary_pairs(u: *Unstructured, list: *std.ArrayList([2]G)) !void {
    const flags_max = u.len() + 1;
    var flags: usize = 0;
    while (flags < flags_max and try u.arbitrary(bool)) : (flags += 1) {
        const first = try u.arbitrary(G);
        try list.append(gpa, .{ first, try u.arbitrary(G) });
    }
}

fn expect_roundtrip(comptime T: type, value: T, cfg: codec.Cfg(T)) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(T, gpa, encoded, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(value.eql(decoded));
    const again = try codec.encode(T, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, encoded, again);
}

fn codec_body(_: void, u: *Unstructured) anyerror!void {
    var pairs: std.ArrayList([2]G) = .empty;
    defer pairs.deinit(gpa);
    try arbitrary_pairs(u, &pairs);
    var setup = try Setup.init(gpa, try u.arbitrary(G), pairs.items);
    defer setup.deinit(gpa);
    try expect_roundtrip(Setup, setup, .{ setup.g.len, {} });

    const claim: Claim = .{
        .commitment = try u.arbitrary(G),
        .product = try u.arbitrary(F),
        .y = try u.arbitrary(F),
        .log_len = try u.arbitrary(u8),
    };
    const claim_bytes = try codec.encode(Claim, gpa, claim);
    defer gpa.free(claim_bytes);
    try testing.expect(claim.eql(try codec.decode(Claim, gpa, claim_bytes)));

    pairs.clearRetainingCapacity();
    const rounds = u.int_in_range(usize, 0, 63);
    for (0..rounds) |_| {
        const first = try u.arbitrary(G);
        try pairs.append(gpa, .{ first, try u.arbitrary(G) });
    }
    var summary: ipa.Summary = undefined;
    u.fill(&summary.bytes);
    const proof: Proof = .{
        .l_r_coms = pairs.items,
        .transcript_summary = summary,
        .a_final = try u.arbitrary(F),
        .b_final = try u.arbitrary(F),
    };
    const max_len: usize = if (rounds == 0) 0 else @as(usize, 1) << @intCast(rounds);
    try expect_roundtrip(Proof, proof, .{ max_len, .{ {}, {} } });
}

test "ipa codec roundtrip (minifuzz)" {
    // Minutes in Debug, so it runs in optimized builds (CI's ReleaseSafe job) or -Dslow-tests.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    try minifuzz.run(gpa, {}, codec_body);
}

test "ipa proof decoding bounds the rounds by the length" {
    var setup = try test_setup();
    defer setup.deinit(gpa);
    const f = F.from_u64;
    const a: [4]F = .{ f(3), f(5), f(7), f(9) };
    const b: [4]F = .{ f(4), f(6), f(8), f(10) };
    var prover = try Prover.init(&setup, f(1), &a, &b);
    defer prover.deinit();
    const encoded = try codec.encode(Proof, gpa, prover.proof);
    defer gpa.free(encoded);
    // Four elements take two rounds; a bound of 3 allows only one.
    const too_short = codec.decode_cfg(Proof, gpa, encoded, .{ 3, .{ {}, {} } });
    try testing.expectError(error.InvalidLength, too_short);
    var decoded = try codec.decode_cfg(Proof, gpa, encoded, .{ 4, .{ {}, {} } });
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(prover.proof));
}
