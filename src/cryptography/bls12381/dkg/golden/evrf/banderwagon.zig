//! The golden DKG eVRF over the Banderwagon group (commonware
//! `bls12381/dkg/golden/evrf/banderwagon.rs`).
//!
//! For a `(sender, receiver, msg)` triple, two independent generators `(t0, t1)` are hashed
//! from the canonical encodings, and the ECDH shared point `s` keys the output: the dealer
//! computes `[x] receiver`, the receiver `[x] sender`, the same group element. The output is
//! `beta x^2([k] t0) + x^2([k] t1)` with `k = x^2(s)`. Every coordinate read is a squared
//! abscissa, which does not depend on which of a quotient element's two representatives a
//! point holds.
//!
//! `build_circuit` records the gadget that proves the outputs for a batch of receivers on a
//! `zk.circuit` context, in commonware's operation order; the bulletproofs conversion
//! (`vrf_batch_checked`, `vrf_batch_checked_circuit`) wraps it once crypto's bulletproofs
//! lands.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const banderwagon = @import("../../../../banderwagon.zig");
const circuit = @import("../../../../zk/circuit.zig");

pub const F = banderwagon.F;
pub const G = banderwagon.G;
const GVar = banderwagon.GVar;
const Base = banderwagon.Base;
const Var = banderwagon.Var;
const BoolVar = banderwagon.BoolVar;
const Context = banderwagon.Context;

const beta_dst = "_COMMONWARE_CRYPTOGRAPHY_GOLDEN_BANDERWAGON_BETA";
const point_dst = "_COMMONWARE_CRYPTOGRAPHY_GOLDEN_BANDERWAGON_POINT_HASH";

pub const secret_window: u32 = 4;
pub const output_window: u32 = 3;

/// The fixed field element mixing the two hashed generators into the output.
fn beta() Base {
    return Base.map(beta_dst, "");
}

/// The two generators for a triple, hashed from the points' canonical encodings
/// (`sender || receiver || msg || i`).
pub fn point_hash(sender: G, receiver: G, msg: []const u8) [2]G {
    const sender_bytes = codec.encode_fixed(G, sender);
    const receiver_bytes = codec.encode_fixed(G, receiver);
    const zero = [1]u8{0};
    const one = [1]u8{1};
    return .{
        G.hash_to_group_parts(point_dst, &.{ &sender_bytes, &receiver_bytes, msg, &zero }),
        G.hash_to_group_parts(point_dst, &.{ &sender_bytes, &receiver_bytes, msg, &one }),
    };
}

/// `beta x^2([k] t0) + x^2([k] t1)` with `k = x^2([x] shared_base)`.
fn vrf_output(t0: G, t1: G, shared_base: G, x: F) Base {
    const k = shared_base.scalar_mul_x_squared_f(x);
    const t0k = t0.scalar_mul_x_squared_base(k);
    const t1k = t1.scalar_mul_x_squared_base(k);
    return beta().mul(t0k).add(t1k);
}

/// The output as the dealer, holding `x` with `sender = [x] G`.
pub fn vrf_send(msg: []const u8, sender: G, receiver: G, x: F) Base {
    const t0, const t1 = point_hash(sender, receiver, msg);
    return vrf_output(t0, t1, receiver, x);
}

/// The output as the receiver, holding its own `x`: the shared point `[x] sender` is the
/// element the dealer derived as `[x_dealer] receiver`.
pub fn vrf_recv(msg: []const u8, sender: G, x: F) Base {
    const receiver = G.generator.mul(x);
    const t0, const t1 = point_hash(sender, receiver, msg);
    return vrf_output(t0, t1, sender, x);
}

/// The exact context capacity `build_circuit` needs for `receivers` receivers.
pub fn capacity(receivers: u32) circuit.Capacity {
    assert(receivers >= 1);
    return .{
        .constants = 2537 + 7001 * receivers,
        .witnesses = 381 + 724 * receivers,
        .nodes = 5947 + 14352 * receivers,
        .assertions = 382 + 847 * receivers,
    };
}

/// Records the VRF gadget into `ctx` and returns each receiver's committed output var in
/// `output_vars`. The structure is the same for a verifier, which passes null `secret`
/// and `outputs` (their witness values are never read).
pub fn build_circuit(
    gpa: Allocator,
    ctx: *Context,
    sender: G,
    receivers: []const G,
    msg: []const u8,
    secret: ?F,
    outputs: ?[]const Base,
    output_vars: []Var,
) Allocator.Error!void {
    assert(output_vars.len == receivers.len);
    assert(outputs == null or outputs.?.len == receivers.len);
    assert((secret == null) == (ctx.mode == .verifier));
    for (output_vars, 0..) |*output_var, index| {
        output_var.* = Var.witness_value(ctx, if (outputs) |known| known[index] else Base.zero);
    }

    // The secret's bits are the witness (see `banderwagon.F`), allocated once and reused
    // for every base so a single exponent drives every use.
    var x_bits: [F.bit_count]BoolVar = undefined;
    for (&x_bits, (secret orelse F.zero).bits()) |*bit, value| {
        bit.* = BoolVar.witness_value(ctx, value);
    }
    const x_bases = try gpa.alloc(G, receivers.len + 1);
    defer gpa.free(x_bases);
    x_bases[0] = G.generator;
    @memcpy(x_bases[1..], receivers);
    const x_points = try gpa.alloc(GVar, x_bases.len);
    defer gpa.free(x_points);
    try banderwagon.scalar_mul_many_in_circuit(gpa, secret_window, x_bases, &x_bits, x_points);
    // Bind the full public key: the quotient-aware equality rejects `-sender`, which shares
    // its squared abscissa.
    x_points[0].assert_eq(GVar.constant(sender));

    const beta_var = Var.native(beta());
    for (receivers, x_points[1..], output_vars) |receiver, shared, output_var| {
        const t0, const t1 = point_hash(sender, receiver, msg);
        const k = shared.x_squared();
        const k_bits = banderwagon.scalar_bits_le(ctx, k);
        const t_bases = [2]G{ t0, t1 };
        var t_points: [2]GVar = undefined;
        try banderwagon.scalar_mul_many_in_circuit(
            gpa,
            output_window,
            &t_bases,
            &k_bits,
            &t_points,
        );
        const t0k = t_points[0].x_squared();
        const t1k = t_points[1].x_squared();
        beta_var.mul(t0k).add(t1k).assert_eq(output_var);
    }
}

test {
    _ = @import("banderwagon_tests.zig");
}
