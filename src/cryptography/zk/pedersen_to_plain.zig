//! Proof that a Pedersen commitment and a plain commitment hide the same value (commonware
//! `zk/pedersen_to_plain.rs`).
//!
//! With value generator `B` and blinding generator `B~`, the claim holds `plain = v B` and
//! `pedersen = v B + r B~`. The prover shows knowledge of `v` and `r` with a Schnorr-style
//! sigma protocol made non-interactive through a `Transcript`: masks `k B` and `k B + s B~`,
//! a challenge `c`, and responses `k + c v`, `s + c r`.
//!
//! `verify` returns a `Synthetic` equation over a virtual setup (generator 0 is `B`, 1 is
//! `B~`) that is zero for a valid proof, so it can be batched with other equations. Wire
//! formats match commonware byte for byte.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const math = @import("math");
const Transcript = @import("../transcript.zig").Transcript;

const algebra = math.algebra;
const Synthetic = math.synthetic.Synthetic;

/// The value generator `B` and blinding generator `B~`.
pub fn Setup(comptime G: type) type {
    return struct {
        const Self = @This();

        value_generator: G,
        blinding_generator: G,

        pub const Cfg = codec.Cfg(G);

        /// The virtual setup `verify` takes: generator 0 for `B`, 1 for `B~`.
        pub fn virtual_setup(gpa: Allocator, comptime F: type) !Setup(Synthetic(F, G)) {
            const S = Synthetic(F, G);
            var value = try S.generator(gpa, 0);
            errdefer value.deinit(gpa);
            return .{ .value_generator = value, .blinding_generator = try S.generator(gpa, 1) };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (comptime @hasDecl(G, "deinit")) {
                self.value_generator.deinit(gpa);
                self.blinding_generator.deinit(gpa);
            }
            self.* = undefined;
        }

        /// Evaluates an equation from `verify` against these generators.
        pub fn eval(self: Self, gpa: Allocator, comptime F: type, equation: Synthetic(F, G)) !G {
            const generators: [2]G = .{ self.value_generator, self.blinding_generator };
            return equation.eval(gpa, &generators);
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.value_generator.eql(b.value_generator) and
                a.blinding_generator.eql(b.blinding_generator);
        }

        pub const fixed_size = 2 * codec.fixed_size(G).?;

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(G, self.value_generator, writer);
            codec.write(G, self.blinding_generator, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            comptime assert(!codec.owns_memory(G));
            const value_generator = try codec.read_cfg(G, gpa, reader, cfg);
            return .{
                .value_generator = value_generator,
                .blinding_generator = try codec.read_cfg(G, gpa, reader, cfg),
            };
        }
    };
}

/// The committed value and its blinding factor.
pub fn Witness(comptime F: type) type {
    return struct {
        const Self = @This();

        value: F,
        blinding: F,

        /// The honest claim: `plain = v B`, `pedersen = v B + r B~`.
        pub fn claim(self: Self, comptime G: type, setup: Setup(G)) Claim(G) {
            const plain = setup.value_generator.mul(self.value);
            return .{
                .plain = plain,
                .pedersen = plain.add(setup.blinding_generator.mul(self.blinding)),
            };
        }
    };
}

/// The public statement: the plain and Pedersen commitments.
pub fn Claim(comptime G: type) type {
    return struct {
        const Self = @This();

        plain: G,
        pedersen: G,

        pub const Cfg = codec.Cfg(G);

        pub fn eql(a: Self, b: Self) bool {
            return a.plain.eql(b.plain) and a.pedersen.eql(b.pedersen);
        }

        pub const fixed_size = 2 * codec.fixed_size(G).?;

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(G, self.plain, writer);
            codec.write(G, self.pedersen, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            comptime assert(!codec.owns_memory(G));
            const plain = try codec.read_cfg(G, gpa, reader, cfg);
            return .{ .plain = plain, .pedersen = try codec.read_cfg(G, gpa, reader, cfg) };
        }
    };
}

/// The masks and responses of the sigma protocol.
pub fn Proof(comptime F: type, comptime G: type) type {
    return struct {
        const Self = @This();

        plain_mask: G,
        pedersen_mask: G,
        value_response: F,
        blinding_response: F,

        pub const Cfg = struct { codec.Cfg(G), codec.Cfg(F) };

        pub fn eql(a: Self, b: Self) bool {
            return a.plain_mask.eql(b.plain_mask) and a.pedersen_mask.eql(b.pedersen_mask) and
                a.value_response.eql(b.value_response) and
                a.blinding_response.eql(b.blinding_response);
        }

        pub const fixed_size = 2 * codec.fixed_size(G).? + 2 * codec.fixed_size(F).?;

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(G, self.plain_mask, writer);
            codec.write(G, self.pedersen_mask, writer);
            codec.write(F, self.value_response, writer);
            codec.write(F, self.blinding_response, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            comptime assert(!codec.owns_memory(G) and !codec.owns_memory(F));
            var self: Self = undefined;
            self.plain_mask = try codec.read_cfg(G, gpa, reader, cfg[0]);
            self.pedersen_mask = try codec.read_cfg(G, gpa, reader, cfg[0]);
            self.value_response = try codec.read_cfg(F, gpa, reader, cfg[1]);
            self.blinding_response = try codec.read_cfg(F, gpa, reader, cfg[1]);
            return self;
        }
    };
}

/// Commits the encoding of the fixed-size `value` to `transcript`.
fn commit_encoded(comptime T: type, transcript: *Transcript, value: T) void {
    const size = comptime codec.fixed_size(T) orelse @compileError("expected a fixed-size type");
    var buffer: [size]u8 = undefined;
    const bytes = codec.encode_to(T, value, &buffer);
    assert(bytes.len == size);
    transcript.commit(bytes);
}

fn draw_challenge(comptime F: type, transcript: *const Transcript) F {
    var noise = transcript.noise("challenge");
    return F.random(&noise);
}

/// Proves that `claim` opens to `witness`, bound to the transcript; `rng` draws the masks.
pub fn prove(
    comptime G: type,
    rng: anytype,
    transcript: *Transcript,
    setup: Setup(G),
    claim: Claim(G),
    witness: Witness(G.Scalar),
) Proof(G.Scalar, G) {
    const F = G.Scalar;
    comptime algebra.assert_crypto_group(G);
    commit_encoded(Claim(G), transcript, claim);
    const value_mask = F.random(rng);
    const blinding_mask = F.random(rng);
    const plain_mask = setup.value_generator.mul(value_mask);
    const pedersen_mask = plain_mask.add(setup.blinding_generator.mul(blinding_mask));
    commit_encoded(G, transcript, plain_mask);
    commit_encoded(G, transcript, pedersen_mask);
    const challenge = draw_challenge(F, transcript);
    return .{
        .plain_mask = plain_mask,
        .pedersen_mask = pedersen_mask,
        .value_response = value_mask.add(challenge.mul(witness.value)),
        .blinding_response = blinding_mask.add(challenge.mul(witness.blinding)),
    };
}

/// The equation for `proof` against `claim` and a virtual `setup`, replaying the transcript:
/// `(P_m + c P - z_v B) + rho (Q_m + c Q - z_v B - z_r B~)`, with `rho` drawn from `rng`.
/// It is zero for a valid proof. The caller owns the result.
pub fn verify(
    comptime G: type,
    gpa: Allocator,
    rng: anytype,
    transcript: *Transcript,
    setup: *const Setup(Synthetic(G.Scalar, G)),
    claim: Claim(G),
    proof: Proof(G.Scalar, G),
) !Synthetic(G.Scalar, G) {
    const F = G.Scalar;
    const S = Synthetic(F, G);
    comptime algebra.assert_crypto_group(G);
    commit_encoded(Claim(G), transcript, claim);
    commit_encoded(G, transcript, proof.plain_mask);
    commit_encoded(G, transcript, proof.pedersen_mask);
    const challenge = draw_challenge(F, transcript);

    var plain_valid = try S.init_concrete(gpa, &.{
        .{ .weight = F.one, .point = proof.plain_mask },
        .{ .weight = challenge, .point = claim.plain },
    });
    defer plain_valid.deinit(gpa);
    try add_scaled(S, gpa, &plain_valid, setup.value_generator, proof.value_response.neg());
    var out = try S.init_concrete(gpa, &.{
        .{ .weight = F.one, .point = proof.pedersen_mask },
        .{ .weight = challenge, .point = claim.pedersen },
    });
    errdefer out.deinit(gpa);
    try add_scaled(S, gpa, &out, setup.value_generator, proof.value_response.neg());
    try add_scaled(S, gpa, &out, setup.blinding_generator, proof.blinding_response.neg());
    plain_valid.mul_assign(F.random(rng));
    try out.add_assign(gpa, plain_valid);
    return out;
}

/// `out += point * weight` for a synthetic `point`.
fn add_scaled(comptime S: type, gpa: Allocator, out: *S, point: S, weight: anytype) !void {
    var scaled = try point.clone(gpa);
    defer scaled.deinit(gpa);
    scaled.mul_assign(weight);
    try out.add_assign(gpa, scaled);
}
