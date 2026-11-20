//! Hashing and mapping to BLS12-381 G1 and G2 (RFC 9380).
//!
//! `map_to_curve` is the simplified SWU map onto the isogenous curve E1' (11-isogeny)
//! or E2' (3-isogeny) followed by the isogeny map onto E; the EIP-2537 MAP
//! precompiles apply it to one field element and then clear the cofactor. The full
//! hash_to_curve suites BLS12381G1_XMD:SHA-256_SSWU_RO_ and BLS12381G2_XMD:SHA-256_SSWU_RO_
//! are provided with expand_message_xmd and hash_to_field. Variable time.

const std = @import("std");
const assert = std.debug.assert;
const fields = @import("fields.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const fp8 = @import("fp8.zig");
const sha256 = @import("sha256.zig");

const Fp = fields.Fp;
const Fp2 = fields.Fp2;

/// expand_message_xmd output bound: 255 SHA-256 blocks (RFC 9380 section 5.3.1).
pub const expand_length_max = 255 * sha256.digest_length;
pub const dst_length_max = 255;

pub const ExpandError = error{ OutputTooLong, DstTooLong };

/// expand_message_xmd with SHA-256 into `out` (its length is len_in_bytes).
pub fn expand_message_xmd(message: []const u8, dst: []const u8, out: []u8) ExpandError!void {
    return expand_message_xmd_parts(&.{message}, dst, out);
}

/// expand_message_xmd of the concatenation of `parts`, without materializing it.
pub fn expand_message_xmd_parts(
    parts: []const []const u8,
    dst: []const u8,
    out: []u8,
) ExpandError!void {
    if (out.len > expand_length_max or out.len > 65535) return error.OutputTooLong;
    if (dst.len > dst_length_max) return error.DstTooLong;
    assert(out.len > 0);
    const block_count = std.math.divCeil(usize, out.len, sha256.digest_length) catch unreachable;
    const dst_length_byte = [1]u8{@intCast(dst.len)};
    const length_bytes = [2]u8{ @intCast(out.len >> 8), @truncate(out.len) };
    var hasher = sha256.Hasher.init();
    hasher.update(&@as([sha256.block_length]u8, @splat(0)));
    for (parts) |part| hasher.update(part);
    hasher.update(&length_bytes);
    hasher.update(&.{0});
    hasher.update(dst);
    hasher.update(&dst_length_byte);
    const b0 = hasher.final();
    var previous: sha256.Digest = @splat(0);
    for (0..block_count) |index| {
        var input: sha256.Digest = undefined;
        for (&input, b0, previous) |*byte, a, b| byte.* = a ^ b;
        hasher = sha256.Hasher.init();
        hasher.update(&input);
        hasher.update(&.{@intCast(index + 1)});
        hasher.update(dst);
        hasher.update(&dst_length_byte);
        previous = hasher.final();
        const start = index * sha256.digest_length;
        const end = @min(out.len, start + sha256.digest_length);
        @memcpy(out[start..end], previous[0 .. end - start]);
    }
}

/// hash_to_field for Fp with count = 2 (L = 64).
pub fn hash_to_field_fp(message: []const u8, dst: []const u8) ExpandError![2]Fp {
    return hash_to_field_fp_parts(&.{message}, dst);
}

fn hash_to_field_fp_parts(parts: []const []const u8, dst: []const u8) ExpandError![2]Fp {
    var bytes: [128]u8 = undefined;
    try expand_message_xmd_parts(parts, dst, &bytes);
    return .{ fields.fp_from_bytes_wide(bytes[0..64]), fields.fp_from_bytes_wide(bytes[64..128]) };
}

/// hash_to_field for Fp2 with count = 2 (L = 64, m = 2).
pub fn hash_to_field_fp2(message: []const u8, dst: []const u8) ExpandError![2]Fp2 {
    return hash_to_field_fp2_parts(&.{message}, dst);
}

fn hash_to_field_fp2_parts(parts: []const []const u8, dst: []const u8) ExpandError![2]Fp2 {
    var bytes: [256]u8 = undefined;
    try expand_message_xmd_parts(parts, dst, &bytes);
    var out: [2]Fp2 = undefined;
    for (&out, 0..) |*element, index| {
        const chunk = bytes[index * 128 ..][0..128];
        element.* = .{
            .c0 = fields.fp_from_bytes_wide(chunk[0..64]),
            .c1 = fields.fp_from_bytes_wide(chunk[64..128]),
        };
    }
    return out;
}

fn sgn0(comptime F: type, value: F) bool {
    if (F == Fp) return fields.fp_sgn0(value);
    return value.sgn0();
}

fn SswuParameters(comptime F: type) type {
    return struct { a: F, b: F, z: F, minus_b_over_a: F, b_over_za: F };
}

/// Simplified SWU (RFC 9380 section 6.6.2) onto y^2 = x^3 + A x + B.
fn map_to_curve_sswu(comptime F: type, comptime params: SswuParameters(F), u: F) [2]F {
    const z_u2 = params.z.mul(u.square());
    return sswu_finish(F, params, u, z_u2, sswu_denominator(F, z_u2).inverse());
}

/// The SSWU denominator Z^2 u^4 + Z u^2, whose inverse `sswu_finish` takes.
fn sswu_denominator(comptime F: type, z_u2: F) F {
    return z_u2.square().add(z_u2);
}

/// SSWU from `tv1`, the inverse of `sswu_denominator(z_u2)` (zero when it is zero).
fn sswu_finish(comptime F: type, comptime params: SswuParameters(F), u: F, z_u2: F, tv1: F) [2]F {
    const x1 = if (tv1.is_zero()) params.b_over_za else params.minus_b_over_a.mul(F.one.add(tv1));
    var x = x1;
    var y = if (F == Fp) sswu_y_fp(params, u, z_u2, &x) else sswu_y_generic(F, params, z_u2, &x);
    if (sgn0(F, u) != sgn0(F, y)) y = y.neg();
    assert(y.square().eql(curve_rhs(F, params, x)));
    return .{ x, y };
}

fn sswu_y_generic(comptime F: type, comptime params: SswuParameters(F), z_u2: F, x: *F) F {
    if (curve_rhs(F, params, x.*).sqrt()) |y| return y;
    // gx1 non-square implies gx2 = Z^3 u^6 gx1 is a square.
    x.* = z_u2.mul(x.*);
    const y = curve_rhs(F, params, x.*).sqrt().?;
    assert(y.square().eql(curve_rhs(F, params, x.*)));
    return y;
}

/// Fp only (p = 3 mod 4): one exponentiation. y' = gx1^((p+1)/4) squares to gx1 or, when
/// gx1 is not a square, to -gx1; then gx2 = (Z u^3)^2 Z gx1 has the root
/// Z u^3 sqrt(-Z) y' because Z gx1 = (-Z)(-gx1). Updates `x` to x2 in that case.
fn sswu_y_fp(comptime params: SswuParameters(Fp), u: Fp, z_u2: Fp, x: *Fp) Fp {
    const sqrt_minus_z = comptime sqrt_neg(params.z);
    const gx1 = curve_rhs(Fp, params, x.*);
    const candidate = gx1.pow((fields.p + 1) / 4);
    if (candidate.square().eql(gx1)) return candidate;
    assert(candidate.square().eql(gx1.neg()));
    x.* = z_u2.mul(x.*);
    return params.z.mul(u.square().mul(u)).mul(sqrt_minus_z).mul(candidate);
}

/// sqrt(-z) for a compile-time z whose negation is a square.
fn sqrt_neg(comptime z: Fp) Fp {
    @setEvalBranchQuota(10_000_000);
    return z.neg().sqrt().?;
}

fn curve_rhs(comptime F: type, comptime params: SswuParameters(F), x: F) F {
    return x.square().add(params.a).mul(x).add(params.b);
}

/// Evaluates sum coefficients[j] x^j (Horner).
fn polynomial(comptime F: type, coefficients: []const F, x: F) F {
    assert(coefficients.len > 0);
    var index = coefficients.len - 1;
    var accumulator = coefficients[index];
    while (index > 0) {
        index -= 1;
        accumulator = accumulator.mul(x).add(coefficients[index]);
    }
    return accumulator;
}

/// Evaluates x^n + sum coefficients[j] x^j with n = coefficients.len.
fn polynomial_monic(comptime F: type, coefficients: []const F, x: F) F {
    assert(coefficients.len > 0);
    var accumulator = F.one;
    var index = coefficients.len;
    while (index > 0) {
        index -= 1;
        accumulator = accumulator.mul(x).add(coefficients[index]);
    }
    return accumulator;
}

fn IsogenyMap(comptime F: type) type {
    return struct {
        x_numerator: []const F,
        x_denominator: []const F,
        y_numerator: []const F,
        y_denominator: []const F,
    };
}

/// Applies an isogeny map to (x', y') as a Jacobian `Point` (g1.G1 or g2.G2) without an
/// inversion; a zero denominator gives the identity.
fn isogeny(
    comptime Point: type,
    comptime map: IsogenyMap(Field(Point)),
    point: [2]Field(Point),
) Point {
    const F = Field(Point);
    const x = point[0];
    const jacobian = isogeny_jacobian(
        F,
        polynomial(F, map.x_numerator, x),
        polynomial_monic(F, map.x_denominator, x),
        point[1].mul(polynomial(F, map.y_numerator, x)),
        polynomial_monic(F, map.y_denominator, x),
    );
    if (jacobian[2].is_zero()) return Point.identity;
    const result: Point = .{ .x = jacobian[0], .y = jacobian[1], .z = jacobian[2] };
    if (std.debug.runtime_safety) assert(result.is_on_curve());
    return result;
}

fn Field(comptime Point: type) type {
    return @FieldType(Point, "x");
}

/// 1 / a and 1 / b from one inversion (Montgomery's trick); inverse(0) = 0 as `inverse`.
fn inverse_pair(comptime F: type, values: [2]F) [2]F {
    const product = values[0].mul(values[1]);
    if (product.is_zero()) return .{ values[0].inverse(), values[1].inverse() };
    const inverse = product.inverse();
    const result: [2]F = .{ inverse.mul(values[1]), inverse.mul(values[0]) };
    assert(result[0].mul(values[0]).eql(F.one) and result[1].mul(values[1]).eql(F.one));
    return result;
}

/// SSWU then the isogeny for both of hash_to_curve's field elements, sharing SSWU's
/// inversion between them: the sum of the points `isogeny(map_to_curve_sswu(u[i]))` gives.
fn map_pair(
    comptime Point: type,
    comptime params: SswuParameters(Field(Point)),
    comptime map: IsogenyMap(Field(Point)),
    u: [2]Field(Point),
) Point {
    const F = Field(Point);
    var z_u2: [2]F = undefined;
    var denominators: [2]F = undefined;
    for (&z_u2, &denominators, u) |*z, *denominator, value| {
        z.* = params.z.mul(value.square());
        denominator.* = sswu_denominator(F, z.*);
    }
    const tv1 = inverse_pair(F, denominators);
    var sum = Point.identity;
    for (u, z_u2, tv1) |value, z, inverse| {
        sum = sum.add(isogeny(Point, map, sswu_finish(F, params, value, z, inverse)));
    }
    return sum;
}

const g1_sswu: SswuParameters(Fp) = .{
    .a = Fp.from_int_comptime(0x00144698a3b8e9433d693a02c96d4982b0ea985383ee66a8 << 192 |
        0xd8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d),
    .b = Fp.from_int_comptime(0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070 << 192 |
        0xa0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0),
    .z = Fp.from_int_comptime(11),
    .minus_b_over_a = Fp.from_int_comptime(0x0793154fd85631d966ef2470460c78f6a928ad9f5bdbfac2 <<
        192 | 0x1df39753aa278ba751bdfcf95a84188e29d670675e4c9c7c),
    .b_over_za = Fp.from_int_comptime(0x123939a31626a32de772bc7a591ea140683bca0c62efb105 << 192 |
        0x310d5ce1d27d1aadf79a5d5cbe8e2c4ff7d4816af76d2814),
};

const g2_sswu: SswuParameters(Fp2) = .{
    .a = Fp2.from_ints_comptime(0, 240),
    .b = Fp2.from_ints_comptime(1012, 1012),
    .z = Fp2.from_ints_comptime(-2, -1),
    .minus_b_over_a = Fp2.from_ints_comptime(
        0x083c12791abdd5d2fe2f284f0cc6e5aa9b8c2d3f6f3f7923 << 192 |
            0x02cf75e62bfc4df1d6834443da498888725d8cccccccb1c3,
        0x11c4ff711ec210c74cec7f673684c72cc8eb1e458445999c << 192 |
            0x64615cbacab4a8324828bbbad70a777747a173333332f8e8,
    ),
    .b_over_za = Fp2.from_ints_comptime(
        0x01a59d4b6bbf912a32d63b43028e2deeebe8d5d97ca64b6d << 192 |
            0x66f64ac7a265a9305e1a40da5edb81b4e3ac4f5c28f5bd27,
        0x15103a07f641331bb298f5ed3ba1230aa0bcc9f87d923077 << 192 |
            0x324df24a0f7ffa93045d3d6f94c17ae10efa11eb851e7336,
    ),
};

/// map_to_curve for G1: a point on E (not yet in G1).
pub fn map_to_curve_g1(u: Fp) g1.G1 {
    const point = isogeny(g1.G1, g1_isogeny, map_to_curve_sswu(Fp, g1_sswu, u));
    assert(point.is_on_curve());
    return point;
}

/// map_to_curve for G2: a point on E' (not yet in G2).
pub fn map_to_curve_g2(u: Fp2) g2.G2 {
    const point = isogeny(g2.G2, g2_isogeny, map_to_curve_sswu(Fp2, g2_sswu, u));
    assert(point.is_on_curve());
    return point;
}

/// EIP-2537 MAP_FP_TO_G1: map_to_curve then clear_cofactor.
pub fn map_fp_to_g1(u: Fp) g1.Affine {
    const result = g1.clear_cofactor(map_to_curve_g1(u)).to_affine();
    assert(result.is_on_curve());
    return result;
}

/// EIP-2537 MAP_FP2_TO_G2: map_to_curve then clear_cofactor.
pub fn map_fp2_to_g2(u: Fp2) g2.Affine {
    const result = g2.clear_cofactor(map_to_curve_g2(u)).to_affine();
    assert(result.is_on_curve());
    return result;
}

/// hash_to_curve for BLS12381G1_XMD:SHA-256_SSWU_RO_ with a caller-chosen DST.
pub fn hash_to_g1(message: []const u8, dst: []const u8) ExpandError!g1.Affine {
    return hash_to_g1_parts(&.{message}, dst);
}

/// hash_to_g1 of the concatenation of `parts`.
pub fn hash_to_g1_parts(parts: []const []const u8, dst: []const u8) ExpandError!g1.Affine {
    return (try hash_to_g1_jacobian_parts(parts, dst)).to_affine();
}

/// hash_to_g1_parts in Jacobian coordinates, for callers that keep points projective.
pub fn hash_to_g1_jacobian_parts(parts: []const []const u8, dst: []const u8) ExpandError!g1.G1 {
    const result = g1.clear_cofactor(try map_to_g1_jacobian_parts(parts, dst));
    // A subgroup check is a third of the hash. ReleaseFast never checks an assert, yet LLVM
    // keeps this one's work, so it runs only in builds that check asserts.
    if (std.debug.runtime_safety) assert(g1.is_in_subgroup(result.to_affine()));
    return result;
}

/// The point `hash_to_g1_jacobian_parts` clears, on the curve but not yet in G1: the sum of
/// both field elements' mapped points. Clearing multiplies by the fixed h_eff, so a caller
/// summing many hashes may sum these and clear the sum once.
pub fn map_to_g1_jacobian_parts(parts: []const []const u8, dst: []const u8) ExpandError!g1.G1 {
    // One message fills two of a batch's lanes, which still beats the scalar map.
    var batch: G1Batch = .{};
    try batch.push(parts, dst);
    var point: [1]g1.G1 = undefined;
    batch.map_into(&point);
    return point[0];
}

/// The point `hash_to_g2_jacobian_parts` clears, as `map_to_g1_jacobian_parts` for G2.
pub fn map_to_g2_jacobian_parts(parts: []const []const u8, dst: []const u8) ExpandError!g2.G2 {
    const u = try hash_to_field_fp2_parts(parts, dst);
    if (fp8.ifma_available) {
        if (map_g2_lanes(fp8.Lanes(.ifma), u)) |point| return point;
    }
    return map_pair(g2.G2, g2_sswu, g2_isogeny, u);
}

/// `map_pair` for G2 with its Fp square roots on `L` (an `fp8.Lanes`): one lane exponentiation
/// for both elements' norm roots and one for both coordinates' roots, where the scalar path
/// spends two to three per element. Null when a gx has a zero imaginary part, which
/// `map_pair` handles. Variable time, for the public messages a hash maps.
fn map_g2_lanes(comptime L: type, u: [2]Fp2) ?g2.G2 {
    const params = g2_sswu;
    var z_u2: [2]Fp2 = undefined;
    var denominators: [2]Fp2 = undefined;
    for (&z_u2, &denominators, u) |*z, *denominator, value| {
        z.* = params.z.mul(value.square());
        denominator.* = sswu_denominator(Fp2, z.*);
    }
    const tv1 = inverse_pair(Fp2, denominators);
    var x: [2]Fp2 = undefined;
    var gx: [2]Fp2 = undefined;
    var norms: [fp8.lanes]Fp = undefined;
    for (&x, &gx, norms[0..2], tv1) |*x1, *gx1, *norm, inverse| {
        x1.* = if (inverse.is_zero())
            params.b_over_za
        else
            params.minus_b_over_a.mul(Fp2.one.add(inverse));
        gx1.* = curve_rhs(Fp2, params, x1.*);
        if (gx1.c1.is_zero()) return null;
        norm.* = gx1.norm();
    }
    // Unused lanes repeat lane 0; their results are dropped.
    for (norms[2..]) |*norm| norm.* = norms[0];
    // As `sswu_y_fp` on each norm: N^((p + 1) / 4) is sqrt(N), or sqrt(-N) when N, and so
    // gx1, is not a square.
    const norm_roots = L.from_fp(&norms).pow((fields.p + 1) / 4).to_fp();
    var t: [fp8.lanes]Fp = undefined;
    for (&x, &gx, t[0..2], z_u2, u, norms[0..2], norm_roots[0..2]) |*xi, *g, *ti, z, v, n, root| {
        var s = root;
        if (!root.square().eql(n)) {
            assert(root.square().eql(n.neg()));
            // gx2 = (Z u^2)^3 gx1 is a square, and with N(Z) = 5, sqrt(N(gx2)) is
            // N(Z u^2) N(u) sqrt(-5) sqrt(-N(gx1)).
            xi.* = z.mul(xi.*);
            g.* = curve_rhs(Fp2, params, xi.*);
            if (g.c1.is_zero()) return null;
            s = z.norm().mul(v.norm()).mul(comptime sqrt_neg(Fp.from_int_comptime(5))).mul(root);
        }
        if (std.debug.runtime_safety) assert(s.square().eql(g.norm()));
        ti.* = g.c0.add(s).mul(comptime Fp.from_int_comptime((fields.p + 1) / 2));
        // t = 0 would give c1^2 = s^2 - c0^2 = 0.
        assert(!ti.is_zero());
    }
    for (t[2..]) |*ti| ti.* = t[0];
    const roots = L.from_fp(&t).pow((fields.p + 1) / 4).to_fp();
    return g2_lanes_finish(t[0..2].*, roots[0..2].*, u, x, gx);
}

/// Each element's root of gx from y = t^((p + 1) / 4), as `Fp2.sqrt_general`: y^2 is t or -t
/// and c1 / (2y) is the other coordinate. Signs the roots as SSWU does and sums the images.
fn g2_lanes_finish(t: [2]Fp, y: [2]Fp, u: [2]Fp2, x: [2]Fp2, gx: [2]Fp2) g2.G2 {
    const inverses = inverse_pair(Fp, .{ y[0].double(), y[1].double() });
    var sum = g2.G2.identity;
    for (t, y, inverses, u, x, gx) |ti, yi, inverse, v, xi, g| {
        assert(!inverse.is_zero());
        const other = g.c1.mul(inverse);
        var root: Fp2 = if (yi.square().eql(ti))
            .{ .c0 = yi, .c1 = other }
        else
            .{ .c0 = other, .c1 = yi };
        assert(root.square().eql(g));
        if (sgn0(Fp2, v) != sgn0(Fp2, root)) root = root.neg();
        sum = sum.add(isogeny(g2.G2, g2_isogeny, .{ xi, root }));
    }
    return sum;
}

/// Maps hashed messages to G1 in batches, each message's point the one
/// `map_to_g1_jacobian_parts` gives. On a target with AVX-512 IFMA a batch maps on fp8's
/// lanes, two field elements per message; elsewhere it maps message by message. Variable
/// time, like every map here: for public messages only, never for signing.
pub const G1Batch = G1BatchOn(if (fp8.ifma_available) .ifma else null);

/// `G1Batch` on fp8 lanes of `backend`, or the scalar map when null.
pub fn G1BatchOn(comptime backend: ?fp8.Backend) type {
    return struct {
        const Self = @This();

        /// Messages a batch holds.
        pub const capacity = fp8.lanes / 2;

        u: [fp8.lanes]Fp = undefined,
        count: usize = 0,

        pub fn is_full(batch: *const Self) bool {
            assert(batch.count <= capacity);
            return batch.count == capacity;
        }

        /// Hashes a message (the concatenation of `parts`) to its two field elements.
        pub fn push(batch: *Self, parts: []const []const u8, dst: []const u8) ExpandError!void {
            assert(batch.count < capacity);
            const u = try hash_to_field_fp_parts(parts, dst);
            batch.u[2 * batch.count] = u[0];
            batch.u[2 * batch.count + 1] = u[1];
            batch.count += 1;
        }

        /// Maps the pending messages into `out`, one point per message in push order, and
        /// empties the batch.
        pub fn map_into(batch: *Self, out: []g1.G1) void {
            assert(out.len == batch.count);
            defer batch.count = 0;
            if (batch.count == 0) return;
            if (backend == null) {
                for (out, 0..) |*point, index| {
                    const u = batch.u[2 * index ..][0..2].*;
                    point.* = map_pair(g1.G1, g1_sswu, g1_isogeny, u);
                }
                return;
            }
            // Unused lanes repeat the first element; their points are dropped.
            for (batch.u[2 * batch.count ..]) |*u| u.* = batch.u[0];
            const mapped = map_g1_lanes(fp8.Lanes(backend.?), &batch.u);
            for (out, 0..) |*point, index| {
                point.* = mapped[2 * index].add(mapped[2 * index + 1]);
            }
        }

        /// Maps the pending messages and returns the sum of their points; empties the batch.
        pub fn sum_into(batch: *Self, sum: g1.G1) g1.G1 {
            var points: [capacity]g1.G1 = undefined;
            const count = batch.count;
            batch.map_into(points[0..count]);
            var result = sum;
            for (points[0..count]) |point| result = result.add(point);
            return result;
        }
    };
}

/// SSWU then the 11-isogeny for every lane of `u` on `L` (an `fp8.Lanes`): lane i is the
/// point `isogeny(map_to_curve_sswu(u[i]))` gives, in Jacobian coordinates.
fn map_g1_lanes(comptime L: type, u: *const [fp8.lanes]Fp) [fp8.lanes]g1.G1 {
    const params = g1_sswu;
    const lane_u = L.from_fp(u);
    const z = L.constant(params.z);
    const u_squared = lane_u.square();
    const z_u2 = z.mul(u_squared);
    const denominator = z_u2.square().add(z_u2);
    // A zero denominator inverts to zero, and that lane takes x1 = B / (Z A).
    const tv1 = inverse_lanes(L, denominator);
    const x1 = L.select(
        denominator.is_zero(),
        L.constant(params.b_over_za),
        L.constant(params.minus_b_over_a).mul(L.one.add(tv1)),
    );
    const gx1 = x1.square().add(L.constant(params.a)).mul(x1).add(L.constant(params.b));
    // As `sswu_y_fp`: gx1^((p+1)/4) is sqrt(gx1), or sqrt(-gx1) when gx1 is not a square.
    const candidate = gx1.pow((fields.p + 1) / 4);
    const square = candidate.square().eql(gx1);
    const x = L.select(square, x1, z_u2.mul(x1));
    const root_minus_z = L.constant(comptime sqrt_neg(params.z));
    const other = z.mul(u_squared.mul(lane_u)).mul(root_minus_z).mul(candidate);
    const root = L.select(square, candidate, other);
    const y = L.select(lane_u.sgn0() != root.sgn0(), root.neg(), root);
    if (std.debug.runtime_safety) assert(@reduce(.And, y.square().eql(curve_rhs_lanes(L, x))));
    return isogeny_g1_lanes(L, x, y);
}

/// Every lane's inverse (zero for zero) from one scalar safegcd inversion, by Montgomery's
/// trick: a Fermat power on the lanes costs some 450 lane products, this about 30 Fp ones.
fn inverse_lanes(comptime L: type, x: L) L {
    const values = x.to_fp();
    var prefix: [fp8.lanes]Fp = undefined;
    var product = Fp.one;
    for (values, &prefix) |value, *before| {
        before.* = product;
        if (!value.is_zero()) product = product.mul(value);
    }
    var inverse = product.inverse();
    var out: [fp8.lanes]Fp = undefined;
    var lane: usize = fp8.lanes;
    while (lane > 0) {
        lane -= 1;
        if (values[lane].is_zero()) {
            out[lane] = Fp.zero;
            continue;
        }
        out[lane] = inverse.mul(prefix[lane]);
        inverse = inverse.mul(values[lane]);
    }
    assert(inverse.mul(product).is_zero() == product.is_zero());
    return L.from_fp(&out);
}

fn curve_rhs_lanes(comptime L: type, x: L) L {
    return x.square().add(L.constant(g1_sswu.a)).mul(x).add(L.constant(g1_sswu.b));
}

/// The G1 isogeny map lane-wise, in Jacobian coordinates without an inversion; a zero
/// denominator gives the identity.
fn isogeny_g1_lanes(comptime L: type, x: L, y: L) [fp8.lanes]g1.G1 {
    const x_num = polynomial_lanes(L, g1_isogeny.x_numerator, false, x);
    const x_den = polynomial_lanes(L, g1_isogeny.x_denominator, true, x);
    const y_num = polynomial_lanes(L, g1_isogeny.y_numerator, false, x);
    const y_den = polynomial_lanes(L, g1_isogeny.y_denominator, true, x);
    const jacobian = isogeny_jacobian(L, x_num, x_den, y.mul(y_num), y_den);
    const z = jacobian[2].to_fp();
    var out: [fp8.lanes]g1.G1 = undefined;
    for (&out, jacobian[0].to_fp(), jacobian[1].to_fp(), z) |*point, px, py, pz| {
        point.* = if (pz.is_zero()) g1.G1.identity else .{ .x = px, .y = py, .z = pz };
    }
    return out;
}

/// (x_num / x_den, y_num / y_den) as Jacobian (X, Y, Z) with Z = x_den y_den: X = x_num
/// x_den y_den^2 and Y = y_num y_den^2 x_den^3. Z is zero exactly when a denominator is.
fn isogeny_jacobian(comptime F: type, x_num: F, x_den: F, y_num: F, y_den: F) [3]F {
    const y_den2 = y_den.square();
    const x_den_y_den2 = x_den.mul(y_den2);
    return .{
        x_num.mul(x_den_y_den2),
        y_num.mul(x_den_y_den2).mul(x_den.square()),
        x_den.mul(y_den),
    };
}

/// `polynomial`, or `polynomial_monic` when `monic`, lane-wise with compile-time coefficients.
fn polynomial_lanes(
    comptime L: type,
    comptime coefficients: []const Fp,
    comptime monic: bool,
    x: L,
) L {
    comptime assert(coefficients.len > 0);
    const top = if (monic) coefficients.len else coefficients.len - 1;
    var accumulator = if (monic) L.one else L.constant(coefficients[top]);
    comptime var index = top;
    inline while (index > 0) {
        index -= 1;
        accumulator = accumulator.mul(x).add(L.constant(coefficients[index]));
    }
    return accumulator;
}

/// hash_to_curve for BLS12381G2_XMD:SHA-256_SSWU_RO_ with a caller-chosen DST.
pub fn hash_to_g2(message: []const u8, dst: []const u8) ExpandError!g2.Affine {
    return hash_to_g2_parts(&.{message}, dst);
}

/// hash_to_g2 of the concatenation of `parts`.
pub fn hash_to_g2_parts(parts: []const []const u8, dst: []const u8) ExpandError!g2.Affine {
    return (try hash_to_g2_jacobian_parts(parts, dst)).to_affine();
}

/// hash_to_g2_parts in Jacobian coordinates, for callers that keep points projective.
pub fn hash_to_g2_jacobian_parts(parts: []const []const u8, dst: []const u8) ExpandError!g2.G2 {
    const result = g2.clear_cofactor(try map_to_g2_jacobian_parts(parts, dst));
    // A subgroup check is a third of the hash. ReleaseFast never checks an assert, yet LLVM
    // keeps this one's work, so it runs only in builds that check asserts.
    if (std.debug.runtime_safety) assert(g2.is_in_subgroup(result.to_affine()));
    return result;
}

const g1_isogeny: IsogenyMap(Fp) = .{
    .x_numerator = &g1_x_numerator,
    .x_denominator = &g1_x_denominator,
    .y_numerator = &g1_y_numerator,
    .y_denominator = &g1_y_denominator,
};

const g2_isogeny: IsogenyMap(Fp2) = .{
    .x_numerator = &g2_x_numerator,
    .x_denominator = &g2_x_denominator,
    .y_numerator = &g2_y_numerator,
    .y_denominator = &g2_y_denominator,
};

// Generated from RFC 9380 appendix E.2; index j holds k_(i, j).
const g1_x_numerator = [_]Fp{
    Fp.from_int_comptime(0x11a05f2b1e833340b809101dd99815856b303e88a2d7005f << 192 |
        0xf2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7),
    Fp.from_int_comptime(0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417 << 192 |
        0xf565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb),
    Fp.from_int_comptime(0xd54005db97678ec1d1048c5d10a9a1bce032473295983e5 << 192 |
        0x6878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0),
    Fp.from_int_comptime(0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25 << 192 |
        0xf1b33289f1b330835336e25ce3107193c5b388641d9b6861),
    Fp.from_int_comptime(0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f << 192 |
        0x086eeb65982fac18985a286f301e77c451154ce9ac8895d9),
    Fp.from_int_comptime(0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b << 192 |
        0x9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983),
    Fp.from_int_comptime(0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce1 << 192 |
        0x9008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84),
    Fp.from_int_comptime(0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1 << 192 |
        0xa682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e),
    Fp.from_int_comptime(0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574 << 192 |
        0xa2c596c928c5d1de4fa295f296b74e956d71986a8497e317),
    Fp.from_int_comptime(0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99 << 192 |
        0x676314baf4bb1b7fa3190b2edc0327797f241067be390c9e),
    Fp.from_int_comptime(0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96 << 192 |
        0xd50af36003b14866f69b771f8c285decca67df3f1605fb7b),
    Fp.from_int_comptime(0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc << 192 |
        0x23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229),
};
const g1_x_denominator = [_]Fp{
    Fp.from_int_comptime(0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba << 192 |
        0x9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c),
    Fp.from_int_comptime(0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c << 192 |
        0x0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff),
    Fp.from_int_comptime(0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1 << 192 |
        0xfca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19),
    Fp.from_int_comptime(0x3425581a58ae2fec83aafef7c40eb545b08243f16b16551 << 192 |
        0x54cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8),
    Fp.from_int_comptime(0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb << 192 |
        0x8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e),
    Fp.from_int_comptime(0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d << 192 |
        0x0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5),
    Fp.from_int_comptime(0x772caacf16936190f3e0c63e0596721570f5799af53a189 << 192 |
        0x4e2e073062aede9cea73b3538f0de06cec2574496ee84a3a),
    Fp.from_int_comptime(0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a8 << 192 |
        0x1996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e),
    Fp.from_int_comptime(0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b << 192 |
        0x74100da67f39883503826692abba43704776ec3a79a1d641),
    Fp.from_int_comptime(0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d037 << 192 |
        0x76df533978f31c1593174e4b4b7865002d6384d168ecdd0a),
};
const g1_y_numerator = [_]Fp{
    Fp.from_int_comptime(0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a86952 << 192 |
        0x2b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33),
    Fp.from_int_comptime(0x134996a104ee5811d51036d776fb46831223e96c254f383d << 192 |
        0x0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696),
    Fp.from_int_comptime(0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2 << 192 |
        0xc344be4b91400da7d26d521628b00523b8dfe240c72de1f6),
    Fp.from_int_comptime(0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c << 192 |
        0x09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb),
    Fp.from_int_comptime(0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b8 << 192 |
        0x79833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb),
    Fp.from_int_comptime(0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd << 192 |
        0x76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0),
    Fp.from_int_comptime(0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb << 192 |
        0x5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2),
    Fp.from_int_comptime(0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81f << 192 |
        0xfd038da6c26c842642f64550fedfe935a15e4ca31870fb29),
    Fp.from_int_comptime(0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c << 192 |
        0x1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587),
    Fp.from_int_comptime(0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe << 192 |
        0x06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30),
    Fp.from_int_comptime(0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493f << 192 |
        0xd1183e416389e61031bf3a5cce3fbafce813711ad011c132),
    Fp.from_int_comptime(0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c246 << 192 |
        0x2e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e),
    Fp.from_int_comptime(0xb182cac101b9399d155096004f53f447aa7b12a3426b08e << 192 |
        0xc02710e807b4633f06c851c1919211f20d4c04f00b971ef8),
    Fp.from_int_comptime(0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c1580 << 192 |
        0x13e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133),
    Fp.from_int_comptime(0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568 << 192 |
        0xd9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b),
    Fp.from_int_comptime(0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a39 << 192 |
        0x57add4fa95af01b2b665027efec01c7704b456be69c8b604),
};
const g1_y_denominator = [_]Fp{
    Fp.from_int_comptime(0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6 << 192 |
        0xeec3232b5be72e7a07f3688ef60c206d01479253b03663c1),
    Fp.from_int_comptime(0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59c << 192 |
        0xa4a10356f453e01f78a4260763529e3532f6102c2e49a03d),
    Fp.from_int_comptime(0x58df3306640da276faaae7d6e8eb15778c4855551ae7f31 << 192 |
        0x0c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2),
    Fp.from_int_comptime(0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e << 192 |
        0x123da489e726af41727364f2c28297ada8d26d98445f5416),
    Fp.from_int_comptime(0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0 << 192 |
        0x542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d),
    Fp.from_int_comptime(0x8d9e5297186db2d9fb266eaac783182b70152c65550d881 << 192 |
        0xc5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac),
    Fp.from_int_comptime(0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef << 192 |
        0x5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c),
    Fp.from_int_comptime(0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7 << 192 |
        0xfeb34fd206357132b920f5b00801dee460ee415a15812ed9),
    Fp.from_int_comptime(0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920 << 192 |
        0xabc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a),
    Fp.from_int_comptime(0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb << 192 |
        0x5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55),
    Fp.from_int_comptime(0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a629 << 192 |
        0x0e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8),
    Fp.from_int_comptime(0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d2 << 192 |
        0x8c0f9a88cea7913516f968986f7ebbea9684b529e2561092),
    Fp.from_int_comptime(0xad6b9514c767fe3c3613144b45f1496543346d98adf0226 << 192 |
        0x7d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc),
    Fp.from_int_comptime(0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1 << 192 |
        0xcb748df27942480e420517bd8714cc80d1fadc1326ed06f7),
    Fp.from_int_comptime(0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853 << 192 |
        0x324efcd6356caa205ca2f570f13497804415473a1d634b8f),
};

// Generated from RFC 9380 appendix E.3; index j holds k_(i, j).
const g2_x_numerator = [_]Fp2{
    Fp2.from_ints_comptime(
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a << 192 |
            0x88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a << 192 |
            0x88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6,
    ),
    Fp2.from_ints_comptime(
        0x0,
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f << 192 |
            0x9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a,
    ),
    Fp2.from_ints_comptime(
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f << 192 |
            0x9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063f << 192 |
            0xcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d,
    ),
    Fp2.from_ints_comptime(
        0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa << 192 |
            0x22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1,
        0x0,
    ),
};
const g2_x_denominator = [_]Fp2{
    Fp2.from_ints_comptime(
        0x0,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192 |
            0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63,
    ),
    Fp2.from_ints_comptime(
        0xc,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192 |
            0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f,
    ),
};
const g2_y_numerator = [_]Fp2{
    Fp2.from_ints_comptime(
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649b << 192 |
            0xf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706,
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649b << 192 |
            0xf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706,
    ),
    Fp2.from_ints_comptime(
        0x0,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a << 192 |
            0x88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be,
    ),
    Fp2.from_ints_comptime(
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f << 192 |
            0x9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063f << 192 |
            0xcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f,
    ),
    Fp2.from_ints_comptime(
        0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286 << 192 |
            0xb0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10,
        0x0,
    ),
};
const g2_y_denominator = [_]Fp2{
    Fp2.from_ints_comptime(
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192 |
            0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192 |
            0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb,
    ),
    Fp2.from_ints_comptime(
        0x0,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192 |
            0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3,
    ),
    Fp2.from_ints_comptime(
        0x12,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192 |
            0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99,
    ),
};

const testing = std.testing;

fn parse_fp(hex: []const u8) !Fp {
    if (hex.len != 96) return error.TestUnexpectedResult;
    var bytes: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex);
    return Fp.from_bytes_be(&bytes) orelse error.TestUnexpectedResult;
}

fn parse_fp2(hex: []const u8) !Fp2 {
    if (hex.len != 192) return error.TestUnexpectedResult;
    return .{ .c0 = try parse_fp(hex[0..96]), .c1 = try parse_fp(hex[96..192]) };
}

const VectorFields = struct { message: []const u8, columns: [6][]const u8 };

fn split_vector(line: []const u8, message_buffer: []u8) !VectorFields {
    var columns = std.mem.splitScalar(u8, line, ',');
    const message_hex = columns.next() orelse return error.TestUnexpectedResult;
    const message = try std.fmt.hexToBytes(message_buffer, message_hex);
    var out: VectorFields = .{ .message = message, .columns = undefined };
    for (&out.columns) |*column| column.* = columns.next() orelse return error.TestUnexpectedResult;
    return out;
}

test "map: expand_message_xmd RFC 9380 K.1 vectors" {
    const dst = "QUUX-V01-CS02-with-expander-SHA256-128";
    var out32: [32]u8 = undefined;
    try expand_message_xmd("", dst, &out32);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "68a985b87eb6b46952128911f2a4412b" ++
        "bc302a9d759667f87f7a21d803f07235");
    try testing.expectEqualSlices(u8, &expected, &out32);
    try expand_message_xmd("abc", dst, &out32);
    _ = try std.fmt.hexToBytes(&expected, "d8ccab23b5985ccea865c6c97b6e5b83" ++
        "50e794e603b4b97902f53a8a0d605615");
    try testing.expectEqualSlices(u8, &expected, &out32);
    var too_long: [expand_length_max + 1]u8 = undefined;
    try testing.expectError(error.OutputTooLong, expand_message_xmd("", dst, &too_long));
}

test "map: hash_to_curve G1 RFC 9380 J.9.1 vectors" {
    const dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    var lines = std.mem.tokenizeScalar(u8, @embedFile("vectors/rfc9380_g1.txt"), '\n');
    var count: u32 = 0;
    while (lines.next()) |line| : (count += 1) {
        var message_buffer: [1024]u8 = undefined;
        const vector = try split_vector(line, &message_buffer);
        const u = try hash_to_field_fp(vector.message, dst);
        try testing.expect(u[0].eql(try parse_fp(vector.columns[2])));
        try testing.expect(u[1].eql(try parse_fp(vector.columns[3])));
        const q0 = map_to_curve_g1(u[0]).to_affine();
        try testing.expect(q0.x.eql(try parse_fp(vector.columns[4])));
        try testing.expect(q0.y.eql(try parse_fp(vector.columns[5])));
        const point = try hash_to_g1(vector.message, dst);
        try testing.expect(point.x.eql(try parse_fp(vector.columns[0])));
        try testing.expect(point.y.eql(try parse_fp(vector.columns[1])));
    }
    try testing.expectEqual(@as(u32, 5), count);
}

test "map: hash_to_curve G2 RFC 9380 J.10.1 vectors" {
    const dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
    var lines = std.mem.tokenizeScalar(u8, @embedFile("vectors/rfc9380_g2.txt"), '\n');
    var count: u32 = 0;
    while (lines.next()) |line| : (count += 1) {
        var message_buffer: [1024]u8 = undefined;
        const vector = try split_vector(line, &message_buffer);
        const u = try hash_to_field_fp2(vector.message, dst);
        try testing.expect(u[0].eql(try parse_fp2(vector.columns[2])));
        try testing.expect(u[1].eql(try parse_fp2(vector.columns[3])));
        const q0 = map_to_curve_g2(u[0]).to_affine();
        try testing.expect(q0.x.eql(try parse_fp2(vector.columns[4])));
        try testing.expect(q0.y.eql(try parse_fp2(vector.columns[5])));
        const point = try hash_to_g2(vector.message, dst);
        try testing.expect(point.x.eql(try parse_fp2(vector.columns[0])));
        try testing.expect(point.y.eql(try parse_fp2(vector.columns[1])));
    }
    try testing.expectEqual(@as(u32, 5), count);
}

test "map: SSWU constants and exceptional inputs" {
    try testing.expect(g1_sswu.minus_b_over_a.mul(g1_sswu.a).eql(g1_sswu.b.neg()));
    try testing.expect(g1_sswu.b_over_za.mul(g1_sswu.z).mul(g1_sswu.a).eql(g1_sswu.b));
    try testing.expect(g2_sswu.minus_b_over_a.mul(g2_sswu.a).eql(g2_sswu.b.neg()));
    try testing.expect(g2_sswu.b_over_za.mul(g2_sswu.z).mul(g2_sswu.a).eql(g2_sswu.b));
    // u = 0 takes the tv1 = 0 branch.
    try testing.expect(g1.is_in_subgroup(map_fp_to_g1(Fp.zero)));
    try testing.expect(g2.is_in_subgroup(map_fp2_to_g2(Fp2.zero)));
}

const batch_backends = .{ G1BatchOn(null), G1BatchOn(.portable), G1Batch };

test "map: G1 batches give the RFC 9380 J.9.1 hashes on every backend" {
    const dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    inline for (batch_backends) |Batch| {
        // Five vectors fill one batch and leave one message for a partial batch.
        var lines = std.mem.tokenizeScalar(u8, @embedFile("vectors/rfc9380_g1.txt"), '\n');
        var buffers: [5][1024]u8 = undefined;
        var vectors: [5]VectorFields = undefined;
        var batch: Batch = .{};
        var points: [5]g1.G1 = undefined;
        var mapped: usize = 0;
        for (&vectors, &buffers) |*vector, *buffer| {
            vector.* = try split_vector(lines.next().?, buffer);
            try batch.push(&.{vector.message}, dst);
            if (batch.is_full()) {
                batch.map_into(points[mapped..][0..Batch.capacity]);
                mapped += Batch.capacity;
            }
        }
        batch.map_into(points[mapped..]);
        try testing.expect(lines.next() == null);
        for (vectors, points) |vector, point| {
            const hashed = g1.clear_cofactor(point).to_affine();
            try testing.expect(hashed.x.eql(try parse_fp(vector.columns[0])));
            try testing.expect(hashed.y.eql(try parse_fp(vector.columns[1])));
        }
    }
}

test "map: G1 lanes match the scalar map on edge and random inputs" {
    var prng = @import("prng.zig").Prng.init(0x6d6170);
    inline for (.{ fp8.Lanes(.portable), fp8.Fp8 }) |L| {
        for (0..6) |round| {
            var u: [fp8.lanes]Fp = undefined;
            for (&u) |*value| value.* = Fp.from_int(prng.int(Fp.Int) % fields.p);
            // u = 0 takes the zero-denominator branch; 1 and -1 differ only in sign.
            if (round == 0) {
                u[0] = Fp.zero;
                u[1] = Fp.one;
                u[2] = Fp.one.neg();
            }
            for (map_g1_lanes(L, &u), u) |lane, value| {
                const want = map_to_curve_g1(value);
                try testing.expect(!want.is_identity() and lane.is_on_curve());
                try testing.expect(want.eql(lane));
            }
        }
    }
}

test "map: G2 lanes match the scalar map on edge and random inputs" {
    var prng = @import("prng.zig").Prng.init(0x6d6132);
    inline for (.{ fp8.Lanes(.portable), fp8.Fp8 }) |L| {
        var lane_maps: usize = 0;
        for (0..24) |round| {
            var u: [2]Fp2 = undefined;
            for (&u) |*value| value.* = .{
                .c0 = Fp.from_int(prng.int(Fp.Int) % fields.p),
                .c1 = Fp.from_int(prng.int(Fp.Int) % fields.p),
            };
            // u = 0 takes the zero-denominator branch; 1 and -1 differ only in sign.
            if (round == 0) u = .{ Fp2.zero, Fp2.one };
            if (round == 1) u = .{ Fp2.one.neg(), .{ .c0 = Fp.zero, .c1 = Fp.one } };
            const want = map_pair(g2.G2, g2_sswu, g2_isogeny, u);
            const lanes = map_g2_lanes(L, u) orelse continue;
            lane_maps += 1;
            try testing.expect(lanes.is_on_curve() and lanes.eql(want));
        }
        try testing.expect(lane_maps >= 22);
    }
}

test "map: G1 batch sums equal the sum of the messages' maps" {
    const dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    inline for (batch_backends) |Batch| {
        var batch: Batch = .{};
        var want = g1.G1.identity;
        var sum = g1.G1.identity;
        const messages = [_][]const u8{ "a", "bc", "def" };
        for (messages) |message| {
            want = want.add(try map_to_g1_jacobian_parts(&.{message}, dst));
            try batch.push(&.{message}, dst);
        }
        sum = batch.sum_into(sum);
        try testing.expect(batch.count == 0);
        try testing.expect(sum.eql(want));
    }
}

test "map: fp8's variable-time lanes stay behind public inputs" {
    // The lanes branch on their values (square roots, inversions), so only the map of hashed
    // messages and the pairing, both on public data, use them: no other
    // arithmetic file names fp8, and secret scalars (signing, keys, shares) never reach them.
    const siblings = .{
        "curve.zig", "fields.zig", "g1.zig",      "g2.zig",     "montgomery.zig",
        "msm.zig",   "prng.zig",   "safegcd.zig", "sha256.zig", "root.zig",
    };
    inline for (siblings) |name| {
        try testing.expect(std.mem.indexOf(u8, @embedFile(name), "fp8") == null);
        try testing.expect(std.mem.indexOf(u8, @embedFile(name), "fp12_lanes") == null);
    }
    // Here they run once, on the field elements `G1BatchOn.push` hashes from messages.
    const source = @embedFile("map.zig");
    const code = source[0..std.mem.indexOf(u8, source, "\nconst testing = std.testing;").?];
    try testing.expectEqual(1, std.mem.count(u8, code, "map_g1_lanes(fp8.Lanes("));
    try testing.expectEqual(1, std.mem.count(u8, code, "batch.u[2 * batch.count] = "));
    // And on the two field elements `map_to_g2_jacobian_parts` hashes from a message.
    try testing.expectEqual(1, std.mem.count(u8, code, "map_g2_lanes(fp8.Lanes("));
    // pairing.zig runs them in the Miller loop's accumulator and the final exponentiation,
    // whose inputs are public points: one comptime choice of each.
    const pairing = @embedFile("pairing.zig");
    const pairing_tests = std.mem.indexOf(u8, pairing, "\nconst testing = std.testing;").?;
    const pairing_code = pairing[0..pairing_tests];
    try testing.expectEqual(1, std.mem.count(u8, pairing_code, "final_exponentiation_lanes(fp8."));
    try testing.expectEqual(1, std.mem.count(u8, pairing_code, "LaneAccumulator(fp8."));
}

test {
    _ = fp8;
}
