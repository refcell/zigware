//! Fp12 on fp8's lanes, for the pairing's final exponentiation. An element of Fp12 is
//! sum f_i w^i over Fp2 with w^6 = xi = 1 + u (w^2 = v, so c0 = f0 + f2 v + f4 v^2 and c1 =
//! f1 + f3 v + f5 v^2), and slot i of `re` and `im` holds f_i's two Fp coordinates; slots 6
//! and 7 stay zero. Every Fp2 product of a multiplication or a cyclotomic squaring then runs
//! as one lane-wise Fp product over all slots at once, with lane shuffles to line the
//! operands up.
//!
//! Variable time, like fp8: for public values only (pairing inputs are public points).

const std = @import("std");
const assert = std.debug.assert;
const fields = @import("fields.zig");
const fp8 = @import("fp8.zig");

const Fp = fields.Fp;
const Fp2 = fields.Fp2;
const Fp6 = fields.Fp6;
const Fp12 = fields.Fp12;

const slots = 6;
/// A shuffle mask entry for a lane that becomes zero (taken from the zero operand).
const z = -1;

pub fn Fp12Lanes(comptime L: type) type {
    return struct {
        const Self = @This();

        re: L,
        im: L,

        pub const one: Self = blk: {
            // L.one in lane 0 only.
            const lane_0: fp8.V = .{ std.math.maxInt(u64), 0, 0, 0, 0, 0, 0, 0 };
            var re = L.one;
            for (&re.rows) |*row| row.* &= lane_0;
            break :blk .{ .re = re, .im = L.zero };
        };

        /// Lane-wise `a` and `b` shuffled: entry k >= 0 takes lane k of `a`, entry ~k lane k
        /// of `b`.
        fn shuffle(a: L, b: L, comptime mask: [fp8.lanes]i32) L {
            var out: L = undefined;
            inline for (&out.rows, a.rows, b.rows) |*row, x, y| {
                row.* = @shuffle(u64, x, y, mask);
            }
            return out;
        }

        fn shuffle2(a: Self, b: Self, comptime mask: [fp8.lanes]i32) Self {
            return .{ .re = shuffle(a.re, b.re, mask), .im = shuffle(a.im, b.im, mask) };
        }

        /// Lanes of `a` in `mask` order, zero where the entry is `z`.
        fn pick(a: Self, comptime mask: [fp8.lanes]i32) Self {
            // A `z` entry takes lane 7 of the zero operand.
            const full = comptime blk: {
                var out: [fp8.lanes]i32 = undefined;
                for (mask, &out) |entry, *slot| slot.* = if (entry == z) ~@as(i32, 7) else entry;
                break :blk out;
            };
            return shuffle2(a, zero_lanes, full);
        }

        const zero_lanes: Self = .{ .re = L.zero, .im = L.zero };

        fn add(a: Self, b: Self) Self {
            return .{ .re = a.re.add(b.re), .im = a.im.add(b.im) };
        }

        fn sub(a: Self, b: Self) Self {
            return .{ .re = a.re.sub(b.re), .im = a.im.sub(b.im) };
        }

        fn double(a: Self) Self {
            return .{ .re = a.re.double(), .im = a.im.double() };
        }

        /// Slot-wise Fp2 products (Karatsuba: three lane products).
        fn mul_slots(a: Self, b: Self) Self {
            const v0 = a.re.mul(b.re);
            const v1 = a.im.mul(b.im);
            const cross = a.re.add(a.im).mul(b.re.add(b.im));
            return .{ .re = v0.sub(v1), .im = cross.sub(v0).sub(v1) };
        }

        /// Slot-wise times xi = 1 + u.
        fn mul_by_nonresidue(a: Self) Self {
            return .{ .re = a.re.sub(a.im), .im = a.re.add(a.im) };
        }

        pub fn from_fp12(f: Fp12) Self {
            const coefficients = w_coefficients(f);
            var re: [fp8.lanes]Fp = @splat(Fp.zero);
            var im: [fp8.lanes]Fp = @splat(Fp.zero);
            for (coefficients, 0..) |c, index| {
                re[index] = c.c0;
                im[index] = c.c1;
            }
            return .{ .re = L.from_fp(&re), .im = L.from_fp(&im) };
        }

        pub fn to_fp12(self: Self) Fp12 {
            const re = self.re.to_fp();
            const im = self.im.to_fp();
            var coefficients: [slots]Fp2 = undefined;
            for (&coefficients, 0..) |*c, index| c.* = .{ .c0 = re[index], .c1 = im[index] };
            assert(re[6].is_zero() and re[7].is_zero() and im[6].is_zero() and im[7].is_zero());
            return from_w_coefficients(coefficients);
        }

        /// c0 - c1 w: the odd powers of w negated.
        pub fn conjugate(self: Self) Self {
            const odd: fp8.Mask = .{ false, true, false, true, false, true, false, true };
            return .{
                .re = L.select(odd, self.re.neg(), self.re),
                .im = L.select(odd, self.im.neg(), self.im),
            };
        }

        /// The product, schoolbook over the w powers: round j multiplies every slot of `a` by
        /// slot j of `b` and adds slot i's product at power i + j; powers 6 to 10 fold back
        /// times xi.
        pub fn mul(a: Self, b: Self) Self {
            var low = zero_lanes; // powers 0 to 7
            var high = zero_lanes; // powers 8 to 10, in slots 0 to 2
            inline for (0..slots) |j| {
                const product = a.mul_slots(shuffle2(b, b, @splat(@as(i32, j))));
                low = low.add(shift_low(product, j));
                if (j >= 3) high = high.add(shift_high(product, j));
            }
            // Powers 6 and 7 from `low`, 8 to 10 from `high`, each times xi onto power - 6.
            const folded = shuffle2(low, high, .{
                6, 7, ~@as(i32, 0), ~@as(i32, 1), ~@as(i32, 2), 7, 7, 7,
            });
            const wrapped = pick(folded, .{ 0, 1, 2, 3, 4, z, z, z });
            return pick(low, .{ 0, 1, 2, 3, 4, 5, z, z }).add(wrapped.mul_by_nonresidue());
        }

        /// `product` (slots 0 to 5) moved up `j` slots, the part that stays below slot 8.
        fn shift_low(product: Self, comptime j: usize) Self {
            comptime var mask: [fp8.lanes]i32 = @splat(z);
            inline for (0..fp8.lanes) |slot| {
                if (slot >= j and slot - j < slots) mask[slot] = @intCast(slot - j);
            }
            return pick(product, mask);
        }

        /// The part of `product` moved up `j` slots that reaches slot 8 and above, from slot 0.
        fn shift_high(product: Self, comptime j: usize) Self {
            comptime var mask: [fp8.lanes]i32 = @splat(z);
            inline for (0..3) |slot| {
                const source = slot + 8 - j;
                if (source < slots) mask[slot] = @intCast(source);
            }
            return pick(product, mask);
        }

        /// Granger-Scott squaring in the cyclotomic subgroup (as `Fp12.cyclotomic_square`):
        /// three Fp4 squarings of (a_i, b_i) = (f_i, f_(i+3)), from a_i^2, b_i^2, and a_i b_i.
        /// Those are 24 Fp products (each square's (re + im)(re - im) and 2 re im, each
        /// product's four), exactly three lane products.
        pub fn cyclotomic_square(f: Self) Self {
            const plus = f.re.add(f.im);
            const minus = f.re.sub(f.im);
            const twice_re = f.re.double();
            // Lanes 0..5: the six squares; lanes 6, 7 and the third product: a_i b_i.
            // Entry ~k takes lane k of the second operand.
            const b0: i32 = ~@as(i32, 0);
            const b1: i32 = ~@as(i32, 1);
            const b2: i32 = ~@as(i32, 2);
            const b3: i32 = ~@as(i32, 3);
            const b4: i32 = ~@as(i32, 4);
            const b5: i32 = ~@as(i32, 5);
            const left_a = shuffle(plus, f.re, .{ 0, 1, 2, 3, 4, 5, b0, b1 });
            const right_a = shuffle(minus, f.re, .{ 0, 1, 2, 3, 4, 5, b3, b4 });
            const left_b = shuffle(twice_re, f.im, .{ 0, 1, 2, 3, 4, 5, b0, b1 });
            const right_b = shuffle(f.im, f.im, .{ 0, 1, 2, 3, 4, 5, 3, 4 });
            const left_c = shuffle(f.re, f.im, .{ 0, 1, 2, b0, b1, b2, 2, b2 });
            const right_c = shuffle(f.im, f.re, .{ 3, 4, 5, b3, b4, b5, b5, 5 });
            // Squares' re, then a0.re b0.re and a1.re b1.re.
            const product_a = left_a.mul(right_a);
            // Squares' im, then a0.im b0.im and a1.im b1.im.
            const product_b = left_b.mul(right_b);
            // a_i.re b_i.im, a_i.im b_i.re, then a2.re b2.re and a2.im b2.im.
            const product_c = left_c.mul(right_c);
            const squares: Self = .{ .re = product_a, .im = product_b };
            const re_re = shuffle(product_a, product_c, .{ 6, 7, ~@as(i32, 6), 7, 7, 7, 7, 7 });
            const im_im = shuffle(product_b, product_c, .{ 6, 7, ~@as(i32, 7), 7, 7, 7, 7, 7 });
            const cross = shuffle(product_c, product_c, .{ 3, 4, 5, 7, 7, 7, 7, 7 });
            // a_i b_i in slots 0..2 (other lanes hold junk, dropped below).
            const ab: Self = .{ .re = re_re.sub(im_im), .im = product_c.add(cross) };
            const t0 = squares;
            const t1 = pick(squares, .{ 3, 4, 5, z, z, z, z, z });
            const c0 = t1.mul_by_nonresidue().add(t0); // slots 0..2
            const c1 = ab.double(); // slots 0..2
            // Slot order of the result: c0_0, xi c1_2, c0_1, c1_0, c0_2, c1_1.
            const mixed = shuffle2(c0, c1, .{ 0, 7, 1, ~@as(i32, 0), 2, ~@as(i32, 1), 7, 7 });
            const xi_c1 = c1.mul_by_nonresidue();
            const h = shuffle2(mixed, xi_c1, .{ 0, ~@as(i32, 2), 2, 3, 4, 5, 6, 7 });
            const tripled = pick(h.double().add(h), .{ 0, 1, 2, 3, 4, 5, z, z });
            const twice = f.double();
            const odd: fp8.Mask = .{ false, true, false, true, false, true, false, true };
            const result_plus = tripled.add(twice);
            const result_minus = tripled.sub(twice);
            return .{
                .re = L.select(odd, result_plus.re, result_minus.re),
                .im = L.select(odd, result_plus.im, result_minus.im),
            };
        }
    };
}

/// f's coefficients of w^0 to w^5.
fn w_coefficients(f: Fp12) [slots]Fp2 {
    return .{ f.c0.c0, f.c1.c0, f.c0.c1, f.c1.c1, f.c0.c2, f.c1.c2 };
}

fn from_w_coefficients(c: [slots]Fp2) Fp12 {
    return .{
        .c0 = .{ .c0 = c[0], .c1 = c[2], .c2 = c[4] },
        .c1 = .{ .c0 = c[1], .c1 = c[3], .c2 = c[5] },
    };
}

const testing = std.testing;
const Prng = @import("prng.zig").Prng;

/// An element of the cyclotomic subgroup: f^((p^6 - 1)(p^2 + 1)) for a random f.
fn random_cyclotomic(prng: *Prng) Fp12 {
    const f = fields.random_fp12(prng);
    const t = f.conjugate().mul(f.inverse());
    return t.frobenius().frobenius().mul(t);
}

fn check_lanes(comptime L: type, seed: u64) !void {
    const F = Fp12Lanes(L);
    var prng = Prng.init(seed);
    for (0..20) |_| {
        const a = fields.random_fp12(&prng);
        const b = fields.random_fp12(&prng);
        const x = F.from_fp12(a);
        try testing.expect(x.to_fp12().eql(a));
        try testing.expect(x.mul(F.from_fp12(b)).to_fp12().eql(a.mul(b)));
        try testing.expect(x.conjugate().to_fp12().eql(a.conjugate()));
        const c = random_cyclotomic(&prng);
        const y = F.from_fp12(c);
        try testing.expect(y.cyclotomic_square().to_fp12().eql(c.cyclotomic_square()));
        try testing.expect(y.cyclotomic_square().to_fp12().eql(c.square()));
    }
    try testing.expect(F.one.to_fp12().eql(Fp12.one));
}

test "fp12 lanes: the portable lanes match Fp12" {
    try check_lanes(fp8.Lanes(.portable), 0x66313270);
}

test "fp12 lanes: the IFMA lanes match Fp12" {
    if (!fp8.ifma_available) return error.SkipZigTest;
    try check_lanes(fp8.Lanes(.ifma), 0x66313271);
}
