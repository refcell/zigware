//! Variable-time ECDSA P-256 verification, structured as aws-lc's (which commonware's
//! secp256r1 verifies with) rather than std's `mulDoubleBasePublic`:
//!
//! - `a G + b Q` runs one shared chain of 256 doublings in Jacobian coordinates, with the
//!   a = -3 doubling (3M + 5S) where std doubles with complete projective formulas.
//! - `G` is added from a comptime table of 64 affine odd multiples (width-8 wNAF, about 28
//!   mixed additions); `Q` from 8 Jacobian odd multiples built per call (width-5 wNAF, about 43
//!   additions). std adds about 128 times, every time with complete formulas.
//! - The result is never made affine: `x(R) = r mod n` is checked as `X = r Z^2` (and
//!   `(r + n) Z^2` when `r + n < p`), which saves a field inversion.
//! - `s^-1 mod n` is a binary extended GCD instead of std's constant-time divsteps.
//! - On x86_64, field multiplication is aws-lc's `mulx`/`adcx`/`adox` form (field.zig).
//!
//! Every input is public, so branching on it leaks nothing. The answer is the same as std's.

const std = @import("std");
const assert = std.debug.assert;
const P256 = std.crypto.ecc.P256;
const Fe = P256.Fe;
const Scalar = P256.scalar.Scalar;
const field = @import("field.zig");

/// A point `(x, y)` on the curve, never the identity.
pub const Affine = struct { x: Fe, y: Fe };

/// `(X : Y : Z)` with `x = X / Z^2` and `y = Y / Z^3`; `Z = 0` is the identity.
const Jacobian = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const identity: Jacobian = .{ .x = Fe.one, .y = Fe.one, .z = Fe.zero };

    fn from_affine(p: Affine) Jacobian {
        return .{ .x = p.x, .y = p.y, .z = Fe.one };
    }

    fn is_identity(p: Jacobian) bool {
        return p.z.isZero();
    }

    /// `2 p` (dbl-2001-b, for a = -3). The identity doubles to the identity.
    fn double(p: Jacobian) Jacobian {
        const delta = field.sq(p.z);
        const gamma = field.sq(p.y);
        const beta = field.mul(p.x, gamma);
        const alpha = field.mul(p.x.sub(delta), p.x.add(delta));
        const alpha3 = alpha.dbl().add(alpha);
        const beta4 = beta.dbl().dbl();
        const x = field.sq(alpha3).sub(beta4.dbl());
        const z = field.sq(p.y.add(p.z)).sub(gamma).sub(delta);
        const gamma_sq8 = field.sq(gamma).dbl().dbl().dbl();
        const y = field.mul(alpha3, beta4.sub(x)).sub(gamma_sq8);
        return .{ .x = x, .y = y, .z = z };
    }

    /// `p + q` for an affine `q` (madd-2007-bl), or `p - q` when `negate`.
    fn add_affine(p: Jacobian, q: *const Affine, negate: bool) Jacobian {
        const qy = if (negate) q.y.neg() else q.y;
        if (p.is_identity()) return .{ .x = q.x, .y = qy, .z = Fe.one };
        const z1z1 = field.sq(p.z);
        const x2z = field.mul(q.x, z1z1);
        const s2 = field.mul(field.mul(qy, p.z), z1z1);
        const h = x2z.sub(p.x);
        const r = s2.sub(p.y).dbl();
        if (h.isZero()) return if (r.isZero()) p.double() else identity;
        const hh = field.sq(h);
        const i = hh.dbl().dbl();
        const j = field.mul(h, i);
        const v = field.mul(p.x, i);
        const x = field.sq(r).sub(j).sub(v.dbl());
        const y = field.mul(r, v.sub(x)).sub(field.mul(p.y, j).dbl());
        const z = field.sq(p.z.add(h)).sub(z1z1).sub(hh);
        return .{ .x = x, .y = y, .z = z };
    }

    /// `p + q` (add-2007-bl), or `p - q` when `negate`.
    fn add(p: Jacobian, q: *const Jacobian, negate: bool) Jacobian {
        if (q.is_identity()) return p;
        const qy = if (negate) q.y.neg() else q.y;
        if (p.is_identity()) return .{ .x = q.x, .y = qy, .z = q.z };
        const z1z1 = field.sq(p.z);
        const z2z2 = field.sq(q.z);
        const x1z = field.mul(p.x, z2z2);
        const x2z = field.mul(q.x, z1z1);
        const s1 = field.mul(field.mul(p.y, q.z), z2z2);
        const s2 = field.mul(field.mul(qy, p.z), z1z1);
        const h = x2z.sub(x1z);
        const r = s2.sub(s1).dbl();
        if (h.isZero()) return if (r.isZero()) p.double() else identity;
        const i = field.sq(h.dbl());
        const j = field.mul(h, i);
        const v = field.mul(x1z, i);
        const x = field.sq(r).sub(j).sub(v.dbl());
        const y = field.mul(r, v.sub(x)).sub(field.mul(s1, j).dbl());
        const z = field.mul(field.sq(p.z.add(q.z)).sub(z1z1).sub(z2z2), h);
        return .{ .x = x, .y = y, .z = z };
    }
};

/// Width of the wNAF digits of the `Q` scalar (per-call table) and the `G` scalar (static table).
const q_width = 5;
const g_width = 8;
/// Digits of a scalar below 2^256 in width-w NAF (one more than its bits, for the carry).
const digits_len = 257;

/// `G, 3 G, ..., 127 G`: a NAF digit `d` selects entry `|d| / 2`.
const g_table: [1 << (g_width - 2)]Affine = table: {
    @setEvalBranchQuota(100_000_000);
    var result: [1 << (g_width - 2)]Affine = undefined;
    const g = plain_base_point();
    const g2 = g.dbl();
    var multiple = g;
    for (&result) |*entry| {
        const affine = multiple.affineCoordinates();
        entry.* = .{ .x = affine.x, .y = affine.y };
        multiple = multiple.add(g2);
    }
    break :table result;
};

/// `G` without std's `is_base` flag (std then takes its generic paths at comptime).
fn plain_base_point() P256 {
    const g = P256.basePoint;
    return .{ .x = g.x, .y = g.y, .z = g.z };
}

/// The width-`width` NAF of the big-endian `scalar`, least significant digit first: every
/// nonzero digit is odd with magnitude below `2^(width - 1)`.
fn naf(comptime width: u4, scalar: [32]u8) [digits_len]i16 {
    var value: u264 = std.mem.readInt(u256, &scalar, .big);
    var digits: [digits_len]i16 = @splat(0);
    var i: usize = 0;
    const modulus = 1 << width;
    while (value != 0) : (i += 1) {
        assert(i < digits_len);
        if (value & 1 == 1) {
            var digit: i32 = @intCast(value & (modulus - 1));
            if (digit >= modulus / 2) digit -= modulus;
            digits[i] = @intCast(digit);
            if (digit > 0) value -= @intCast(digit) else value += @intCast(-digit);
        }
        value >>= 1;
    }
    return digits;
}

/// `scalar_g G + scalar_q q` for big-endian scalars, sharing one doubling chain (Straus).
fn double_base(scalar_g: [32]u8, scalar_q: [32]u8, q: Affine) Jacobian {
    const g_digits = naf(g_width, scalar_g);
    const q_digits = naf(q_width, scalar_q);
    var q_table: [1 << (q_width - 2)]Jacobian = undefined;
    q_table[0] = .from_affine(q);
    const q2 = q_table[0].double();
    for (q_table[1..], 0..) |*entry, i| entry.* = q2.add(&q_table[i], false);
    var top: usize = digits_len;
    while (top > 0 and g_digits[top - 1] == 0 and q_digits[top - 1] == 0) top -= 1;
    var sum = Jacobian.identity;
    var i = top;
    while (i > 0) {
        i -= 1;
        sum = sum.double();
        const g_digit = g_digits[i];
        if (g_digit != 0) sum = sum.add_affine(&g_table[@abs(g_digit) / 2], g_digit < 0);
        const q_digit = q_digits[i];
        if (q_digit != 0) sum = sum.add(&q_table[@abs(q_digit) / 2], q_digit < 0);
    }
    return sum;
}

/// `s^-1 mod n` for a nonzero `s`, by the binary extended Euclidean algorithm, which keeps
/// `x1 s = u` and `x2 s = v (mod n)` while `gcd(u, v) = 1` shrinks to `u = 1` or `v = 1`.
pub fn invert_scalar(s: Scalar) Scalar {
    assert(!s.isZero());
    const n = P256.scalar.field_order;
    var u: u256 = std.mem.readInt(u256, &s.toBytes(.big), .big);
    var v: u256 = n;
    var x1: u256 = 1;
    var x2: u256 = 0;
    // Each pass halves u or v at least once; both start below 2^256.
    var passes: u32 = 0;
    while (u != 1 and v != 1) : (passes += 1) {
        assert(passes < 2 * 256 and u != 0 and v != 0);
        const u_shift: u8 = @intCast(@ctz(u));
        for (0..u_shift) |_| x1 = half_mod_n(x1);
        u >>= u_shift;
        const v_shift: u8 = @intCast(@ctz(v));
        for (0..v_shift) |_| x2 = half_mod_n(x2);
        v >>= v_shift;
        if (u >= v) {
            u -= v;
            x1 = if (x1 >= x2) x1 - x2 else x1 + (n - x2);
        } else {
            v -= u;
            x2 = if (x2 >= x1) x2 - x1 else x2 + (n - x1);
        }
    }
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, if (u == 1) x1 else x2, .big);
    // Proof: x1 and x2 stay below n.
    return Scalar.fromBytes(bytes, .big) catch unreachable;
}

/// `x / 2 mod n` for `x < n`.
fn half_mod_n(x: u256) u256 {
    assert(x < P256.scalar.field_order);
    if (x & 1 == 0) return x >> 1;
    return @intCast((@as(u257, x) + P256.scalar.field_order) >> 1);
}

/// The field element of a value below 2^256 that is known to be below p.
fn field_from(value: u256) Fe {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    // Proof: callers pass r < n < p, or r + n only when it is below p.
    return Fe.fromBytes(bytes, .big) catch unreachable;
}

/// Whether `(r, s)` (each in [1, n)) is a valid ECDSA signature of the reduced hash `z` by
/// `q`.
pub fn verify(q: Affine, z: Scalar, r: Scalar, s: Scalar) bool {
    assert(!r.isZero() and !s.isZero());
    const w = invert_scalar(s);
    const point = double_base(z.mul(w).toBytes(.big), r.mul(w).toBytes(.big), q);
    if (point.is_identity()) return false;
    const zz = field.sq(point.z);
    const r_int = std.mem.readInt(u256, &r.toBytes(.big), .big);
    if (field.mul(field_from(r_int), zz).equivalent(point.x)) return true;
    // x(R) in [n, p) reduces to r = x - n.
    const p_minus_n = Fe.field_order - P256.scalar.field_order;
    if (r_int >= p_minus_n) return false;
    return field.mul(field_from(r_int + P256.scalar.field_order), zz).equivalent(point.x);
}

const testing = std.testing;
const fuzz = @import("../fuzz.zig");

/// std's answer for the same inputs.
fn verify_std(q: Affine, z: Scalar, r: Scalar, s: Scalar) bool {
    const w = s.invert();
    const point_q = P256.fromAffineCoordinates(.{ .x = q.x, .y = q.y }) catch return false;
    const sum = P256.mulDoubleBasePublic(
        P256.basePoint,
        z.mul(w).toBytes(.big),
        point_q,
        r.mul(w).toBytes(.big),
        .big,
    ) catch return false;
    return reduce(sum.affineCoordinates().x.toBytes(.big)).equivalent(r);
}

/// A 32-byte big-endian value reduced mod n.
fn reduce(bytes: [32]u8) Scalar {
    return Scalar.fromBytes48(@as([16]u8, @splat(0)) ++ bytes, .big);
}

fn scalar_from(bytes: [32]u8) ?Scalar {
    const s = Scalar.fromBytes(bytes, .big) catch return null;
    return if (s.isZero()) null else s;
}

fn affine_of(point: P256) Affine {
    const a = point.affineCoordinates();
    return .{ .x = a.x, .y = a.y };
}

/// Signs `z` with secret `d` and nonce `k` (plain ECDSA), then checks `verify` accepts it and
/// rejects a flipped `z`, and agrees with std on random `(r, s)`.
fn check(bytes: []const u8) !void {
    var input = fuzz.Input.init(bytes);
    var raw: [4][32]u8 = undefined;
    for (&raw) |*r| input.fill(r);
    const d = scalar_from(raw[0]) orelse return;
    const k = scalar_from(raw[1]) orelse return;
    const z = reduce(raw[2]);
    const q = affine_of(P256.basePoint.mul(d.toBytes(.big), .big) catch return);
    const kg = P256.basePoint.mul(k.toBytes(.big), .big) catch return;
    const r = reduce(kg.affineCoordinates().x.toBytes(.big));
    if (r.isZero()) return;
    const s = k.invert().mul(z.add(r.mul(d)));
    if (s.isZero()) return;
    try testing.expect(verify(q, z, r, s));
    try testing.expect(verify(q, z, r, s.neg()));
    try testing.expect(!verify(q, z.add(Scalar.one), r, s));
    const other = scalar_from(raw[3]) orelse return;
    try testing.expectEqual(verify_std(q, z, other, s), verify(q, z, other, s));
    try testing.expectEqual(verify_std(q, z, r, other), verify(q, z, r, other));
}

test "secp256r1 verify: invert_scalar matches std" {
    var random = fuzz.prng(0x256);
    for (0..fuzz.iterations(32)) |_| {
        var bytes: [32]u8 = undefined;
        random.random().bytes(&bytes);
        const s = scalar_from(bytes) orelse continue;
        try testing.expect(invert_scalar(s).equivalent(s.invert()));
    }
    try testing.expect(invert_scalar(Scalar.one).equivalent(Scalar.one));
}

test "secp256r1 verify: naf recodes the scalar" {
    var random = fuzz.prng(0x9af);
    for (0..fuzz.iterations(64)) |_| {
        var bytes: [32]u8 = undefined;
        random.random().bytes(&bytes);
        inline for (.{ q_width, g_width }) |width| {
            const digits = naf(width, bytes);
            var value: i300 = 0;
            var i: usize = digits_len;
            while (i > 0) {
                i -= 1;
                value = value * 2 + digits[i];
                const digit = digits[i];
                const odd = @mod(digit, 2) == 1 and @abs(digit) < 1 << (width - 1);
                try testing.expect(digit == 0 or odd);
            }
            try testing.expectEqual(@as(i300, std.mem.readInt(u256, &bytes, .big)), value);
        }
    }
}

test "secp256r1 verify fuzz: accepts signatures and matches std" {
    var random = fuzz.prng(0xec);
    var bytes: [128]u8 = undefined;
    for (0..fuzz.iterations(48)) |_| {
        random.random().bytes(&bytes);
        try check(&bytes);
    }
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var input: [128]u8 = undefined;
            smith.bytes(&input);
            try check(&input);
        }
    }.run, .{});
}
