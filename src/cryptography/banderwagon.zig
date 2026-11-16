//! The Banderwagon prime-order group (commonware `cryptography/src/banderwagon.rs`).
//!
//! `G` holds a point on the Bandersnatch twisted Edwards curve
//! `a x^2 + y^2 = 1 + d x^2 y^2` (`a = -5`) over the BLS12-381 scalar field, so it is cheap
//! to use inside BLS12-381 circuits. The full curve group is `Z/2 x Z/2 x Z/r`; Banderwagon
//! keeps the subgroup of order `2r` (checked on decode: `1 - a x^2` is a square) and
//! quotients it by `{O, (0, -1)}`, identifying `(x, y)` with `(-x, -y)`. A group element
//! therefore has many in-memory representatives (projective scalings of either twin), and
//! equality, the codec, and the circuit gadgets all see through them.
//!
//! `F` is the scalar field `Z/r`. `GVar` is a point inside a `zk.circuit` over the base
//! field, with complete affine addition; `scalar_bits_le` decomposes a circuit scalar into
//! canonical bits. Every gadget performs its circuit operations in commonware's order, so
//! circuits match node for node.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const math = @import("math");
const minifuzz = @import("invariants").minifuzz;
const group = @import("bls12381/primitives/group.zig");
const circuit = @import("zk/circuit.zig");

const algebra = math.algebra;
const Unstructured = minifuzz.Unstructured;

/// The base field: the BLS12-381 scalar field.
pub const Base = group.Scalar;
pub const Context = circuit.Context(Base);
pub const Var = circuit.Var(Base);
pub const BoolVar = circuit.BoolVar(Base);
const Selector = circuit.Selector(Base);

/// Bit-length of the base field modulus `p` (`ceil(log2 p)`).
pub const scalar_bits: u32 = 255;

/// A scalar exponent for `G`: an element of `Z/r`, kept canonical in `[0, r)`.
///
/// In circuit the secret is witnessed directly as its `bit_count` little-endian bits with
/// no canonicity constraint: every use feeds them into a scalar multiplication, which is
/// well defined modulo `r`, so an alias `>= r` of the same residue gives the same result.
pub const F = struct {
    value: u256,

    /// The bit-width of `r`.
    pub const bit_count: u32 = 253;
    pub const fixed_size: usize = 32;
    /// The prime order of the Banderwagon group.
    pub const r: u256 = 0x1cfb69d4ca675f52_0cce760202687600_ff8f870074190471_74fd06b52876e7e1;
    pub const zero: F = .{ .value = 0 };
    pub const one: F = .{ .value = 1 };

    /// Rejection sampling draws `bit_count`-bit candidates, accepted with probability
    /// `r / 2^253 > 0.9`; this many failures in a row has probability below `2^-200`.
    const random_attempts_max = 64;

    comptime {
        assert(r >> (bit_count - 1) == 1);
        assert(r % 2 == 1);
    }

    pub fn from_u64(value: u64) F {
        return .{ .value = value };
    }

    /// The integer of little-endian 64-bit `limbs`, reduced modulo `r`.
    pub fn from_limbs(words: [4]u64) F {
        return .{ .value = limbs_to_int(words) % r };
    }

    pub fn limbs(self: F) [4]u64 {
        assert(self.value < r);
        return int_to_limbs(self.value);
    }

    /// The little-endian bits of the integer, `bit_count` of them.
    pub fn bits(self: F) [bit_count]bool {
        assert(self.value < r);
        var out: [bit_count]bool = undefined;
        for (&out, 0..) |*bit, index| bit.* = (self.value >> @intCast(index)) & 1 == 1;
        return out;
    }

    /// A uniform element of `[0, r)` by rejection sampling `rng.next_u64` limbs (`Random`).
    pub fn random(rng: anytype) F {
        var attempt: u32 = 0;
        while (attempt < random_attempts_max) : (attempt += 1) {
            var candidate: [4]u64 = undefined;
            for (&candidate) |*limb| limb.* = rng.next_u64();
            candidate[3] &= (@as(u64, 1) << (bit_count - 192)) - 1;
            const value = limbs_to_int(candidate);
            if (value < r) return .{ .value = value };
        }
        @panic("banderwagon::F rejection sampling failed repeatedly");
    }

    /// An arbitrary 256-bit integer reduced modulo `r`.
    pub fn arbitrary(u: *Unstructured) minifuzz.Error!F {
        var candidate: [4]u64 = undefined;
        for (&candidate) |*limb| limb.* = try u.arbitrary(u64);
        return from_limbs(candidate);
    }

    pub fn add(a: F, b: F) F {
        assert(a.value < r and b.value < r);
        // Both are below r < 2^253, so the sum fits and one subtraction reduces it.
        const sum = a.value + b.value;
        const result: F = .{ .value = if (sum >= r) sum - r else sum };
        assert(result.value < r);
        return result;
    }

    pub fn neg(a: F) F {
        assert(a.value < r);
        return .{ .value = if (a.value == 0) 0 else r - a.value };
    }

    pub fn sub(a: F, b: F) F {
        return a.add(b.neg());
    }

    pub fn mul(a: F, b: F) F {
        assert(a.value < r and b.value < r);
        const product = @as(u512, a.value) * @as(u512, b.value);
        const result: F = .{ .value = @intCast(product % r) };
        assert(result.value < r);
        return result;
    }

    /// Fermat inversion, `a^(r - 2)`; `inv(0) == 0`.
    pub fn inv(a: F) F {
        const exponent = int_to_limbs(r - 2);
        return algebra.exp(F, a, &exponent);
    }

    pub fn eql(a: F, b: F) bool {
        return a.value == b.value;
    }

    /// The canonical little-endian integer.
    pub fn write(self: F, writer: *codec.Writer) void {
        assert(self.value < r);
        var bytes: [fixed_size]u8 = undefined;
        std.mem.writeInt(u256, &bytes, self.value, .little);
        writer.write_bytes(&bytes);
    }

    /// Rejects non-canonical encodings (`>= r`).
    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!F {
        const bytes = try reader.take_array(fixed_size);
        const value = std.mem.readInt(u256, bytes, .little);
        if (value >= r) return reader.invalid("banderwagon::F", "scalar not canonical");
        return .{ .value = value };
    }

    comptime {
        algebra.assert_field(F);
    }
};

fn limbs_to_int(limbs: [4]u64) u256 {
    var value: u256 = 0;
    for (limbs, 0..) |limb, index| value |= @as(u256, limb) << @intCast(64 * index);
    return value;
}

fn int_to_limbs(value: u256) [4]u64 {
    var out: [4]u64 = undefined;
    for (&out, 0..) |*limb, index| limb.* = @truncate(value >> @intCast(64 * index));
    assert(limbs_to_int(out) == value);
    return out;
}

/// Base field element from blst Montgomery limbs (how commonware writes the constants).
fn montgomery(comptime limbs: [4]u64) Base {
    return .{ .fr = .{ .limbs_value = limbs } };
}

/// The Bandersnatch twisted Edwards `a` coefficient, `-5`.
pub const curve_a = montgomery(.{
    0xffff_fff4_0000_000c, 0xece3_b023_ffec_4ff3,
    0x66b6_2060_7396_203f, 0x6f23_d7e5_f361_df62,
});

/// The Bandersnatch twisted Edwards `d` coefficient.
pub const curve_d = montgomery(.{
    0xa8dc_ed1b_47a2_c730, 0x381c_065a_ad3c_ccc7,
    0x53ff_52e1_1883_51f8, 0x362e_8d63_990f_e940,
});

/// The canonical little-endian limbs of a base field element (the integer `scale`
/// multiplies by, matching the in-circuit `scalar_bits_le` decomposition).
fn scalar_limbs(x: Base) [4]u64 {
    return int_to_limbs(x.to_int());
}

/// A Banderwagon group element in extended projective coordinates (`x y = t z`).
pub const G = struct {
    x: Base,
    y: Base,
    t: Base,
    z: Base,

    pub const Scalar = F;
    /// One base field element: the abscissa `u = (X / Z) Sign(Y / Z)`.
    pub const fixed_size: usize = group.scalar_length;

    /// The identity, the twisted Edwards neutral element `(0, 1)`.
    pub const zero: G = .{ .x = Base.zero, .y = Base.one, .t = Base.zero, .z = Base.one };

    /// The prime-order Bandersnatch generator.
    pub const generator: G = .{
        // x = 0x29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18
        .x = montgomery(.{
            0xec26_27e1_e7ab_47f5, 0x3e63_de48_4f01_aa9c,
            0xfe0f_5c3b_5394_6dc4, 0x2d71_920b_aeb2_cfcd,
        }),
        // y = 0x2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166
        .y = montgomery(.{
            0x4e30_593e_1895_bd34, 0x156d_738f_32af_be4b,
            0x45ef_0b1c_cdeb_75f4, 0x6a7c_ca00_37d2_e71f,
        }),
        // t = x * y
        .t = montgomery(.{
            0x5a92_e8f6_97ad_b6b9, 0xf138_8d46_06b1_4609,
            0x101c_7836_40a6_4516, 0x1e9a_e707_3cc7_a9fc,
        }),
        .z = Base.one,
    };

    /// Same group element: the affine `x : y` ratios match, `x1 y2 == x2 y1`. This absorbs
    /// both projective scaling and the `(x, y) ~ (-x, -y)` quotient. Meaningful only for
    /// valid subgroup elements.
    pub fn eql(a: G, b: G) bool {
        return a.x.mul(b.y).eql(b.x.mul(a.y));
    }

    pub fn add(a: G, b: G) G {
        const x1_y2 = a.x.mul(b.y);
        const y1_x2 = a.y.mul(b.x);
        const y1_y2 = a.y.mul(b.y);
        const x1_x2 = a.x.mul(b.x);
        const z1_z2 = a.z.mul(b.z);
        const t1_t2 = a.t.mul(b.t);

        const x_sum = x1_y2.add(y1_x2);
        const y_difference = y1_y2.sub(x1_x2.mul(curve_a));
        const d_t1_t2 = t1_t2.mul(curve_d);
        const z_minus_d_t = z1_z2.sub(d_t1_t2);
        const z_plus_d_t = z1_z2.add(d_t1_t2);
        return .{
            .x = x_sum.mul(z_minus_d_t),
            .y = y_difference.mul(z_plus_d_t),
            .t = x_sum.mul(y_difference),
            .z = z_minus_d_t.mul(z_plus_d_t),
        };
    }

    pub fn neg(a: G) G {
        return .{ .x = a.x.neg(), .y = a.y, .t = a.t.neg(), .z = a.z };
    }

    pub fn sub(a: G, b: G) G {
        return a.add(b.neg());
    }

    pub fn double(a: G) G {
        const x_sq = a.x.square();
        const y_sq = a.y.square();
        const z_sq_twice = a.z.square().double();
        const a_x_sq = x_sq.mul(curve_a);
        const x_plus_y_sq = a.x.add(a.y).square().sub(x_sq).sub(y_sq);
        const g = a_x_sq.add(y_sq);
        const f = g.sub(z_sq_twice);
        const h = a_x_sq.sub(y_sq);
        return .{
            .x = x_plus_y_sq.mul(f),
            .y = g.mul(h),
            .t = x_plus_y_sq.mul(h),
            .z = f.mul(g),
        };
    }

    pub fn mul(self: G, scalar: F) G {
        const limbs = scalar.limbs();
        return algebra.scale(G, self, &limbs);
    }

    pub fn msm(points: []const G, scalars: []const F) G {
        return algebra.msm_naive(G, F, points, scalars);
    }

    /// The affine coordinates `(x / z, y / z)` of this representative.
    pub fn affine(self: G) [2]Base {
        assert(!self.z.eql(Base.zero));
        const z_inv = self.z.inv();
        return .{ self.x.mul(z_inv), self.y.mul(z_inv) };
    }

    /// The serialized abscissa `x Sign(y)`, equal for both twins.
    fn abscissa(self: G) Base {
        const x, const y = self.affine();
        return if (y.is_positive()) x else x.neg();
    }

    pub fn write(self: G, writer: *codec.Writer) void {
        self.abscissa().write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!G {
        const x = Base.read(gpa, reader, .allow_zero) catch |err| return switch (err) {
            error.Invalid => reader.invalid("Banderwagon", "x not a canonical field element"),
            else => err,
        };
        return from_x(x) orelse reader.invalid("Banderwagon", "point not in subgroup");
    }

    /// The group element whose serialization has abscissa `x`, or null when `x` fails
    /// the subgroup check or lies off the curve. The recovered `y` is the positive root.
    pub fn from_x(x: Base) ?G {
        const x_sq = x.square();
        // y^2 = (1 - a x^2) / (1 - d x^2).
        const numerator = Base.one.sub(x_sq.mul(curve_a));
        const denominator = Base.one.sub(x_sq.mul(curve_d));
        // Subgroup check: 1 - a x^2 must be a square.
        if (!numerator.is_square()) return null;
        var y = numerator.mul(denominator.inv()).sqrt() orelse return null;
        if (!y.is_positive()) y = y.neg();
        assert(y.is_positive());
        return .{ .x = x, .y = y, .t = x.mul(y), .z = Base.one };
    }

    /// The canonical representative (positive `y`, `z = 1`), so two values of the same
    /// element become bit-identical.
    pub fn canonicalize(self: G) G {
        return from_x(self.abscissa()) orelse
            @panic("a valid subgroup element re-derives from its abscissa");
    }

    /// The squared affine abscissa of `[scalar] self`, a function of the group element.
    pub fn scalar_mul_x_squared_base(self: G, scalar: Base) Base {
        const limbs = scalar_limbs(scalar);
        const x, _ = algebra.scale(G, self, &limbs).affine();
        return x.square();
    }

    /// The squared affine abscissa of `[x] self` for an `F` exponent.
    pub fn scalar_mul_x_squared_f(self: G, x: F) Base {
        const abscissa_value, _ = self.mul(x).affine();
        return abscissa_value.square();
    }

    /// Try-and-increment hash to the group: the first `counter` for which
    /// `Base.map(dst, message || counter_be64)` is a valid abscissa. Not constant time; the
    /// inputs are public in every intended use.
    pub fn hash_to_group(dst: []const u8, message: []const u8) G {
        var counter: u64 = 0;
        // Each attempt succeeds with probability about 1/4.
        while (counter < hash_attempts_max) : (counter += 1) {
            var counter_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter_bytes, counter, .big);
            const x = Base.map_parts(dst, &.{ message, &counter_bytes });
            if (from_x(x)) |point| return point;
        }
        @panic("banderwagon hash_to_group failed repeatedly");
    }

    /// `(3/4)^1024` is below `2^-400`.
    const hash_attempts_max: u64 = 1024;

    /// In-circuit `[scalar] self` for a public point; the scalar is decomposed into
    /// canonical bits (`scalar_bits_le`).
    pub fn scalar_mul(self: G, ctx: *Context, scalar: Var) GVar {
        const bits = scalar_bits_le(ctx, scalar);
        return GVar.constant(self).mul_bits(&bits);
    }

    /// In-circuit squared abscissa of `[scalar] self`.
    pub fn scalar_mul_x_squared(self: G, ctx: *Context, scalar: Var) Var {
        const x = self.scalar_mul(ctx, scalar).x;
        return x.mul(x);
    }

    /// In-circuit `[bits] self` where the scalar is given directly as little-endian bits.
    pub fn scalar_mul_bits(self: G, bits: []const BoolVar) GVar {
        return GVar.constant(self).mul_bits(bits);
    }

    comptime {
        algebra.assert_crypto_group(G);
    }
};

/// In-circuit fixed-base scalar multiplication of several public bases by one shared bit
/// decomposition, `window` bits at a time: `out[i] = [bits] bases[i]`. The selector
/// monomials of each window are built once and reused for every base.
pub fn scalar_mul_many_in_circuit(
    gpa: Allocator,
    comptime window: u32,
    bases: []const G,
    bits: []const BoolVar,
    out: []GVar,
) Allocator.Error!void {
    comptime assert(window >= 1 and window <= 8);
    assert(out.len == bases.len);
    for (out) |*accumulator| accumulator.* = GVar.identity;
    const shifted = try gpa.dupe(G, bases);
    defer gpa.free(shifted);
    var start: usize = 0;
    while (start < bits.len) : (start += window) {
        const chunk = bits[start..@min(start + window, bits.len)];
        assert(chunk.len >= 1 and chunk.len <= window);
        var selector = try Selector.init(gpa, chunk);
        defer selector.deinit(gpa);
        for (out, shifted) |*accumulator, base| {
            accumulator.* = accumulator.add(try select_window(gpa, selector, base, chunk.len));
        }
        for (shifted) |*base| {
            for (0..chunk.len) |_| base.* = base.double();
        }
    }
}

/// The selected multiple `[0 .. 2^len) * base` of one window, from canonical constants.
fn select_window(gpa: Allocator, selector: Selector, base: G, len: usize) Allocator.Error!GVar {
    assert(len >= 1 and len <= 8);
    const count = @as(usize, 1) << @intCast(len);
    var xs: [256]Base = undefined;
    var ys: [256]Base = undefined;
    var point = G.zero;
    for (xs[0..count], ys[0..count]) |*x, *y| {
        x.*, y.* = point.canonicalize().affine();
        point = point.add(base);
    }
    const x = try selector.select_constant(gpa, xs[0..count]);
    const y = try selector.select_constant(gpa, ys[0..count]);
    return .{ .x = x, .y = y };
}

/// A Banderwagon point in a circuit, in affine coordinates (inversions are cheap there).
pub const GVar = struct {
    x: Var,
    y: Var,

    /// The twisted Edwards neutral element `(0, 1)`.
    pub const identity: GVar = .{ .x = Var.zero, .y = Var.one };

    /// A public point as native constants: its canonical affine coordinates, so the
    /// constants depend on the group element, not on the representative held.
    pub fn constant(point: G) GVar {
        const x, const y = point.canonicalize().affine();
        return .{ .x = Var.native(x), .y = Var.native(y) };
    }

    /// Complete affine addition with six multiplications:
    /// `x3 = (x1 y2 + y1 x2) / (1 + d x1 x2 y1 y2)`,
    /// `y3 = (y1 y2 - a x1 x2) / (1 - d x1 x2 y1 y2)`. The curve is complete (`a` square,
    /// `d` not), so the denominators never vanish on subgroup points.
    pub fn add(self: GVar, other: GVar) GVar {
        const a = Var.native(curve_a);
        const d = Var.native(curve_d);
        const x1_x2 = self.x.mul(other.x);
        const y1_y2 = self.y.mul(other.y);
        const sum_1 = self.x.add(self.y);
        const sum_2 = other.x.add(other.y);
        const u = sum_1.mul(sum_2);
        const ab = x1_x2.mul(y1_y2);
        const c = d.mul(ab);
        const x_numerator = u.sub(x1_x2).sub(y1_y2);
        const a_x1_x2 = a.mul(x1_x2);
        const y_numerator = y1_y2.sub(a_x1_x2);
        const x_denominator = Var.one.add(c);
        const y_denominator = Var.one.sub(c);
        const x = x_numerator.div(x_denominator);
        const y = y_numerator.div(y_denominator);
        return .{ .x = x, .y = y };
    }

    /// `on_true` when `bit` is set, else `on_false`, coordinate by coordinate.
    fn select(bit: BoolVar, on_true: GVar, on_false: GVar) GVar {
        const x = bit.select(on_true.x, on_false.x);
        const y = bit.select(on_true.y, on_false.y);
        return .{ .x = x, .y = y };
    }

    /// Constrains `self` and `other` to be the same group element: `x1 y2 == x2 y1`, which
    /// accepts either twin representative.
    pub fn assert_eq(self: GVar, other: GVar) void {
        const left = self.x.mul(other.y);
        const right = other.x.mul(self.y);
        left.assert_eq(right);
    }

    /// The squared affine abscissa.
    pub fn x_squared(self: GVar) Var {
        return self.x.mul(self.x);
    }

    /// Double-and-add over little-endian bits; complete addition needs no special cases.
    fn mul_bits(self: GVar, bits: []const BoolVar) GVar {
        var accumulator = identity;
        var current = self;
        for (bits) |bit| {
            const added = accumulator.add(current);
            accumulator = select(bit, added, accumulator);
            current = current.add(current);
        }
        return accumulator;
    }
};

/// Decomposes `x` into its canonical little-endian bits: fresh boolean witnesses bound by
/// recomposition (`sum b_i 2^i == x` in the field) and canonicity (the integer is `< p`).
/// Without the range check a prover could use the alias `x + p`, which scales a point to
/// a different result because the group order does not divide `p`.
pub fn scalar_bits_le(ctx: *Context, x: Var) [scalar_bits]BoolVar {
    const BitOf = struct {
        source: Var,
        index: u32,
        pub fn call(self: @This(), values: circuit.Values(Base)) bool {
            return (self.source.value(values).to_int() >> @intCast(self.index)) & 1 == 1;
        }
    };
    var bits: [scalar_bits]BoolVar = undefined;
    for (&bits, 0..) |*bit, index| {
        bit.* = BoolVar.witness(ctx, BitOf{ .source = x, .index = @intCast(index) });
    }

    // Recomposition: each term scales a bit by a constant.
    var accumulator = Var.zero;
    var power = Base.one;
    for (bits) |bit| {
        accumulator = accumulator.add(bit.var_value().mul(Var.native(power)));
        power = power.double();
    }
    accumulator.assert_eq(x);

    // Canonicity, value <= p - 1: walk from the top bit with `run` = "every 1-bit of
    // p - 1 so far was matched"; at a 0-bit of p - 1 a still-running value must be 0.
    const largest = Base.one.neg().to_int();
    var run = BoolVar.constant(true);
    var index: u32 = scalar_bits;
    while (index > 0) {
        index -= 1;
        if ((largest >> @intCast(index)) & 1 == 1) {
            run = run.@"and"(bits[index]);
        } else {
            run.@"and"(bits[index]).assert_eq(BoolVar.constant(false));
        }
    }
    assert(index == 0);
    return bits;
}

test {
    _ = @import("banderwagon_tests.zig");
}
