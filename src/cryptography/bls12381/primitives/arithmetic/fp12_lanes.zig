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

        /// The product.
        pub fn mul(a: Self, b: Self) Self {
            return sum_of_products(a, b, comptime all_terms(.full));
        }

        /// The square: the 21 products f_i f_j with i <= j, those with i < j twice.
        pub fn square(a: Self) Self {
            return sum_of_products(a, a, comptime all_terms(.square));
        }

        /// The product with a line b0 + b1 v + b4 v w (`Fp12.mul_by_014`), which has the w
        /// powers 0, 2, and 3 only.
        pub fn mul_by_014(a: Self, line: Self) Self {
            return sum_of_products(a, line, comptime all_terms(.line));
        }

        /// The line b0 + b1 v + b4 v w on lanes.
        pub fn from_line(b0: Fp2, b1: Fp2, b4: Fp2) Self {
            var re: [fp8.lanes]Fp = @splat(Fp.zero);
            var im: [fp8.lanes]Fp = @splat(Fp.zero);
            for ([_]usize{ 0, 2, 3 }, [_]Fp2{ b0, b1, b4 }) |slot, value| {
                re[slot] = value.c0;
                im[slot] = value.c1;
            }
            return .{ .re = L.from_fp(&re), .im = L.from_fp(&im) };
        }

        /// Sum over `terms` of a_i b_j at power i + j (twice when `twice`), with powers 6
        /// to 10 folded back times xi. Terms run eight at a time, one lane product round
        /// (three lane products) each; each round's products add into the powers through as
        /// many shuffles as the most products one power receives in that round.
        fn sum_of_products(a: Self, b: Self, comptime terms: []const Term) Self {
            var low = zero_lanes; // powers 0 to 7
            var high = zero_lanes; // powers 8 to 10, in slots 0 to 2
            comptime var start = 0;
            inline while (start < terms.len) : (start += fp8.lanes) {
                const batch = comptime terms[start..@min(start + fp8.lanes, terms.len)];
                const plan = comptime batch_plan(batch);
                var product = pick(a, plan.left).mul_slots(pick(b, plan.right));
                if (plan.any_twice) {
                    const twice = product.double();
                    product = .{
                        .re = L.select(plan.twice, twice.re, product.re),
                        .im = L.select(plan.twice, twice.im, product.im),
                    };
                }
                inline for (plan.low[0..plan.layers]) |mask| low = low.add(pick(product, mask));
                inline for (plan.high[0..plan.layers]) |mask| {
                    if (comptime !all_zero(mask)) high = high.add(pick(product, mask));
                }
            }
            // Powers 6 and 7 from `low`, 8 to 10 from `high`, each times xi onto power - 6.
            const folded = shuffle2(low, high, .{
                6, 7, ~@as(i32, 0), ~@as(i32, 1), ~@as(i32, 2), 7, 7, 7,
            });
            const wrapped = pick(folded, .{ 0, 1, 2, 3, 4, z, z, z });
            return pick(low, .{ 0, 1, 2, 3, 4, 5, z, z }).add(wrapped.mul_by_nonresidue());
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

/// One product a_i b_j of `sum_of_products`, added at power i + j (twice when `twice`).
const Term = struct { i: u8, j: u8, twice: bool = false };

/// The terms of a full product, a square, or a product with a line (powers 0, 2, and 3).
fn all_terms(comptime kind: enum { full, square, line }) []const Term {
    var terms: [slots * slots]Term = undefined;
    var count = 0;
    for (0..slots) |i| for (0..slots) |j| {
        const keep = switch (kind) {
            .full => true,
            .square => i <= j,
            .line => j == 0 or j == 2 or j == 3,
        };
        if (!keep) continue;
        terms[count] = .{ .i = i, .j = j, .twice = kind == .square and i < j };
        count += 1;
    };
    const final = terms[0..count].*;
    return &final;
}

fn all_zero(comptime mask: [fp8.lanes]i32) bool {
    for (mask) |entry| if (entry != z) return false;
    return true;
}

/// Lane masks for one round of up to eight terms: the operand lanes, the lanes to double,
/// and per layer the shuffles that move each product to its power (`low` for 0 to 7,
/// `high` for 8 to 10), at most one product per power per layer.
const BatchPlan = struct {
    left: [fp8.lanes]i32,
    right: [fp8.lanes]i32,
    twice: fp8.Mask,
    any_twice: bool,
    layers: usize,
    low: [fp8.lanes][fp8.lanes]i32,
    high: [fp8.lanes][fp8.lanes]i32,
};

fn batch_plan(comptime batch: []const Term) BatchPlan {
    assert(batch.len > 0 and batch.len <= fp8.lanes);
    var plan: BatchPlan = .{
        .left = @splat(z),
        .right = @splat(z),
        .twice = @splat(false),
        .any_twice = false,
        .layers = 0,
        .low = @splat(@splat(z)),
        .high = @splat(@splat(z)),
    };
    var used: [2 * slots - 1]usize = @splat(0);
    for (batch, 0..) |term, lane| {
        plan.left[lane] = term.i;
        plan.right[lane] = term.j;
        plan.twice[lane] = term.twice;
        plan.any_twice = plan.any_twice or term.twice;
        const power = term.i + term.j;
        const layer = used[power];
        used[power] += 1;
        plan.layers = @max(plan.layers, layer + 1);
        if (power < fp8.lanes) {
            plan.low[layer][power] = lane;
        } else {
            plan.high[layer][power - fp8.lanes] = lane;
        }
    }
    return plan;
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
        try testing.expect(x.square().to_fp12().eql(a.square()));
        const b0 = b.c0.c0;
        const b1 = b.c0.c1;
        const b4 = b.c1.c1;
        const line = F.from_line(b0, b1, b4);
        try testing.expect(x.mul_by_014(line).to_fp12().eql(a.mul_by_014(b0, b1, b4)));
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
