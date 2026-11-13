//! Polynomials and interpolation (commonware `math::poly`).
//!
//! `Poly(K)` holds at least one and at most 2^32 - 1 coefficients in `K` (constant first). `K`
//! can be a field or any `Space` over a scalar type, such as a group, which makes commitments
//! (`commit`) and evaluation "in the exponent" the same code as scalar evaluation.
//!
//! Wire format (commonware `NonEmptyVec<K>`): a varint coefficient count, then each
//! coefficient's encoding.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const algebra = @import("algebra.zig");
const wire = @import("wire.zig");
const fuzz = @import("fuzz.zig");
const Unstructured = fuzz.Unstructured;

/// Below this many polynomials, `Poly.msm` uses the naive algorithm.
const msm_points_min = 2;

pub fn Poly(comptime K: type) type {
    algebra.assert_additive(K);
    return struct {
        const Self = @This();

        /// Invariant: 1 <= coeffs.len <= maxInt(u32). Owned by the polynomial.
        coeffs: []K,

        /// Take ownership of `coeffs` (allocated with the allocator later passed to `deinit`).
        pub fn from_owned(coeffs: []K) Self {
            assert(coeffs.len >= 1);
            assert(coeffs.len <= std.math.maxInt(u32));
            return .{ .coeffs = coeffs };
        }

        pub fn from_slice(allocator: Allocator, coeffs: []const K) Allocator.Error!Self {
            assert(coeffs.len >= 1);
            return from_owned(try allocator.dupe(K, coeffs));
        }

        /// The zero polynomial, a single zero coefficient.
        pub fn zero(allocator: Allocator) Allocator.Error!Self {
            return from_slice(allocator, &.{K.zero});
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.coeffs);
            self.* = undefined;
        }

        pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
            return from_slice(allocator, self.coeffs);
        }

        /// An upper bound on the degree (coefficients are not inspected).
        pub fn degree(self: Self) u32 {
            assert(self.coeffs.len >= 1);
            return @intCast(self.coeffs.len - 1);
        }

        /// The number of evaluations needed to recover this polynomial: degree + 1.
        pub fn required(self: Self) u32 {
            assert(self.coeffs.len >= 1);
            return @intCast(self.coeffs.len);
        }

        pub fn constant(self: Self) K {
            return self.coeffs[0];
        }

        /// The degree ignoring high zero coefficients (0 for the zero polynomial).
        pub fn degree_exact(self: Self) u32 {
            var top: usize = self.coeffs.len - 1;
            while (top > 0 and self.coeffs[top].eql(K.zero)) top -= 1;
            assert(top < self.coeffs.len);
            return @intCast(top);
        }

        /// Equality treating missing high coefficients as zero.
        pub fn eql(a: Self, b: Self) bool {
            const count = @max(a.coeffs.len, b.coeffs.len);
            for (0..count) |index| {
                const left = if (index < a.coeffs.len) a.coeffs[index] else K.zero;
                const right = if (index < b.coeffs.len) b.coeffs[index] else K.zero;
                if (!left.eql(right)) return false;
            }
            return true;
        }

        /// Evaluate with Horner's method at `r`, where `K` is a `Space` over `R`.
        pub fn eval(self: Self, comptime R: type, r: R) K {
            assert(self.coeffs.len >= 1);
            var index = self.coeffs.len - 1;
            var accumulator = self.coeffs[index];
            while (index > 0) {
                index -= 1;
                accumulator = accumulator.mul(r).add(self.coeffs[index]);
            }
            return accumulator;
        }

        /// Like `eval`, but as one multi-scalar multiplication against `1, r, r^2, ...`.
        pub fn eval_msm(self: Self, allocator: Allocator, comptime R: type, r: R) !K {
            const weights = try allocator.alloc(R, self.coeffs.len);
            defer allocator.free(weights);
            var iterator = algebra.powers(R, R.one, r);
            for (weights) |*weight| weight.* = iterator.next();
            return algebra.msm(K, R, self.coeffs, weights);
        }

        /// `sum_i a_i * self(b_i)` for `pairs[i] = .{ a_i, b_i }`; zero for no pairs.
        pub fn lin_comb_eval(
            self: Self,
            allocator: Allocator,
            comptime R: type,
            pairs: []const [2]R,
        ) !K {
            if (pairs.len == 0) return K.zero;
            const weights = try allocator.alloc(R, self.coeffs.len);
            defer allocator.free(weights);
            @memset(weights, R.zero);
            for (pairs) |pair| {
                var iterator = algebra.powers(R, pair[0], pair[1]);
                for (weights) |*weight| weight.* = weight.add(iterator.next());
            }
            return algebra.msm(K, R, self.coeffs, weights);
        }

        fn merge_with(
            self: *Self,
            allocator: Allocator,
            rhs: Self,
            comptime subtract: bool,
        ) Allocator.Error!void {
            if (rhs.coeffs.len > self.coeffs.len) {
                const old_len = self.coeffs.len;
                self.coeffs = try allocator.realloc(self.coeffs, rhs.coeffs.len);
                @memset(self.coeffs[old_len..], K.zero);
            }
            assert(self.coeffs.len >= rhs.coeffs.len);
            for (self.coeffs[0..rhs.coeffs.len], rhs.coeffs) |*a, b| {
                a.* = if (subtract) a.sub(b) else a.add(b);
            }
        }

        pub fn add_assign(self: *Self, allocator: Allocator, rhs: Self) Allocator.Error!void {
            try self.merge_with(allocator, rhs, false);
        }

        pub fn sub_assign(self: *Self, allocator: Allocator, rhs: Self) Allocator.Error!void {
            try self.merge_with(allocator, rhs, true);
        }

        pub fn neg_assign(self: *Self) void {
            for (self.coeffs) |*coeff| coeff.* = coeff.neg();
        }

        /// Multiply every coefficient by `r` (`Space` scaling).
        pub fn mul_assign(self: *Self, comptime R: type, r: R) void {
            for (self.coeffs) |*coeff| coeff.* = coeff.mul(r);
        }

        /// A new polynomial with `map` applied to every coefficient.
        pub fn translate(
            self: Self,
            allocator: Allocator,
            comptime L: type,
            context: anytype,
            comptime map: fn (@TypeOf(context), K) L,
        ) Allocator.Error!Poly(L) {
            const out = try allocator.alloc(L, self.coeffs.len);
            for (out, self.coeffs) |*o, c| o.* = map(context, c);
            return Poly(L).from_owned(out);
        }

        /// `sum_i polys[i] * scalars[i]`, coefficient by coefficient.
        pub fn msm(
            allocator: Allocator,
            comptime R: type,
            polys: []const Self,
            scalars: []const R,
        ) !Self {
            const columns = @min(polys.len, scalars.len);
            var rows: usize = 1;
            for (polys[0..columns]) |p| rows = @max(rows, p.coeffs.len);
            const out = try allocator.alloc(K, rows);
            errdefer allocator.free(out);
            if (columns < msm_points_min) {
                @memset(out, K.zero);
                for (polys[0..columns], scalars[0..columns]) |p, s| {
                    for (out[0..p.coeffs.len], p.coeffs) |*o, c| o.* = o.add(c.mul(s));
                }
                return from_owned(out);
            }
            const row = try allocator.alloc(K, columns);
            defer allocator.free(row);
            for (out, 0..) |*o, index| {
                for (row, polys[0..columns]) |*cell, p| {
                    cell.* = if (index < p.coeffs.len) p.coeffs[index] else K.zero;
                }
                o.* = algebra.msm(K, R, row, scalars[0..columns]);
            }
            return from_owned(out);
        }

        /// Random coefficients (commonware `Poly::new`).
        pub fn random(allocator: Allocator, rng: std.Random, degree_value: u32) !Self {
            const out = try allocator.alloc(K, @as(usize, degree_value) + 1);
            for (out) |*c| c.* = K.random(rng);
            return from_owned(out);
        }

        /// Random coefficients with a fixed constant (commonware `Poly::new_with_constant`).
        pub fn random_with_constant(
            allocator: Allocator,
            rng: std.Random,
            degree_value: u32,
            constant_value: K,
        ) !Self {
            const out = try allocator.alloc(K, @as(usize, degree_value) + 1);
            out[0] = constant_value;
            for (out[1..]) |*c| c.* = K.random(rng);
            return from_owned(out);
        }

        pub fn encode_size(self: Self) usize {
            return wire.varint_size(self.required()) + self.coeffs.len * K.encode_size;
        }

        /// Upper bound on the encoded size with at most `coefficients` coefficients.
        pub fn max_encode_size(coefficients: u32) usize {
            return wire.varint_size(coefficients) + @as(usize, coefficients) * K.encode_size;
        }

        pub fn write(self: Self, w: *wire.Writer) void {
            const start = w.position;
            w.put_varint(self.required());
            for (self.coeffs) |c| w.put(&c.encode());
            assert(w.position - start == self.encode_size());
        }

        /// Read a polynomial with a coefficient count in `[1, count_max]` and at least
        /// `count_min` (commonware `RangeCfg<NonZeroU32>`).
        pub fn read(
            allocator: Allocator,
            r: *wire.Reader,
            count_min: u32,
            count_max: u32,
        ) !Self {
            assert(count_min >= 1 and count_min <= count_max);
            const count = try r.read_length(count_min, count_max);
            if (@as(usize, count) * K.encode_size > r.remaining()) return error.EndOfBuffer;
            const out = try allocator.alloc(K, count);
            errdefer allocator.free(out);
            for (out) |*c| c.* = try K.decode(try r.take_array(K.encode_size));
            return from_owned(out);
        }

        pub fn arbitrary(allocator: Allocator, u: *Unstructured, count_max: u32) !Self {
            assert(count_max >= 1);
            const count = 1 + u.length(count_max - 1);
            const out = try allocator.alloc(K, count);
            for (out) |*c| c.* = K.arbitrary(u);
            return from_owned(out);
        }
    };
}

/// Commit to a scalar polynomial: each coefficient times the group generator.
pub fn commit(
    allocator: Allocator,
    comptime G: type,
    p: Poly(G.Scalar),
) Allocator.Error!Poly(G) {
    algebra.assert_crypto_group(G);
    return p.translate(allocator, G, {}, struct {
        fn map(_: void, c: G.Scalar) G {
            return G.generator.mul(c);
        }
    }.map);
}

/// Orders interpolation indices: integers, byte arrays, or types with `order(a, b)`.
pub fn index_order(comptime I: type, a: I, b: I) std.math.Order {
    if (@typeInfo(I) == .int) return std.math.order(a, b);
    if (@typeInfo(I) == .array) return std.mem.order(std.meta.Child(I), &a, &b);
    return I.order(a, b);
}

/// Recovers a polynomial's constant from evaluations at known points (Lagrange weights at 0).
///
/// Keys are kept sorted and unique; `interpolate` takes evaluations for exactly these keys,
/// in this order.
pub fn Interpolator(comptime I: type, comptime F: type) type {
    algebra.assert_field(F);
    return struct {
        const Self = @This();

        keys: []I,
        weights: []F,

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.keys);
            allocator.free(self.weights);
            self.* = undefined;
        }

        const Entry = struct { key: I, point: F };

        fn entry_less(_: void, a: Entry, b: Entry) bool {
            return index_order(I, a.key, b.key) == .lt;
        }

        /// Build from `(index, point)` pairs. Duplicate indices keep the first point.
        pub fn init(allocator: Allocator, keys: []const I, points: []const F) !Self {
            assert(keys.len == points.len);
            const entries = try allocator.alloc(Entry, keys.len);
            defer allocator.free(entries);
            for (entries, keys, points) |*e, k, p| e.* = .{ .key = k, .point = p };
            std.mem.sort(Entry, entries, {}, entry_less); // Stable: first duplicate wins.
            var count: usize = 0;
            for (entries) |e| {
                if (count > 0 and index_order(I, entries[count - 1].key, e.key) == .eq) continue;
                entries[count] = e;
                count += 1;
            }
            const keys_out = try allocator.alloc(I, count);
            errdefer allocator.free(keys_out);
            const weights_out = try allocator.alloc(F, count);
            errdefer allocator.free(weights_out);
            const self: Self = .{ .keys = keys_out, .weights = weights_out };
            for (self.keys, self.weights, entries[0..count]) |*k, *w, e| {
                k.* = e.key;
                w.* = e.point;
            }
            try compute_weights(allocator, self.weights);
            return self;
        }

        /// Replace evaluation points with their Lagrange basis values at zero.
        fn compute_weights(allocator: Allocator, values: []F) !void {
            const n = values.len;
            if (n == 0) return;
            for (values, 0..) |w_i, i| {
                if (!w_i.eql(F.zero)) continue;
                // L_i(0) = 1 for the point at zero, and 0 for the others.
                for (values, 0..) |*w, j| w.* = if (j == i) F.one else F.zero;
                return;
            }
            // c_i = w_i * prod_{j != i} (w_j - w_i); weight_i = W / c_i with W = prod w_i.
            const c = try allocator.alloc(F, n);
            defer allocator.free(c);
            const prefix = try allocator.alloc(F, n + 1);
            defer allocator.free(prefix);
            var total_product = F.one;
            for (values, c, 0..) |w_i, *c_i, i| {
                total_product = total_product.mul(w_i);
                c_i.* = w_i;
                for (values, 0..) |w_j, j| {
                    if (j != i) c_i.* = c_i.mul(w_j.sub(w_i));
                }
            }
            // Batch inversion with Montgomery's trick.
            prefix[0] = F.one;
            for (c, 0..) |c_i, i| prefix[i + 1] = prefix[i].mul(c_i);
            var inverse_accumulator = total_product.mul(prefix[n].inv());
            var i = n;
            while (i > 0) {
                i -= 1;
                values[i] = inverse_accumulator.mul(prefix[i]);
                inverse_accumulator = inverse_accumulator.mul(c[i]);
            }
        }

        /// The constant term, or null when `keys` differ from the interpolator's keys.
        pub fn interpolate(
            self: Self,
            comptime K: type,
            keys: []const I,
            evals: []const K,
        ) ?K {
            assert(keys.len == evals.len);
            if (keys.len != self.keys.len) return null;
            for (keys, self.keys) |a, b| {
                if (index_order(I, a, b) != .eq) return null;
            }
            return algebra.msm(K, F, evals, self.weights);
        }
    };
}

const testing_types = @import("testing.zig");
const TF = testing_types.F;
const TG = testing_types.G;

const PlanKind = enum {
    codec,
    eval_add,
    eval_scale,
    eval_zero,
    eval_msm,
    lin_comb_eval,
    interpolate,
    interpolate_with_zero_point,
    interpolate_with_zero_point_middle,
    translate_scale,
    commit_eval,
    fuzz_additive,
    fuzz_space_ring,
};

/// The polynomial fuzz plan (commonware `poly::fuzz::Plan`), run with `testing.allocator`.
pub fn fuzz_plan(_: void, u: *Unstructured) !void {
    const allocator = std.testing.allocator;
    const kind = u.choose(PlanKind);
    var f = try Poly(TF).arbitrary(allocator, u, 24);
    defer f.deinit(allocator);
    switch (kind) {
        .codec => try check_codec(allocator, f),
        .eval_add => {
            var g = try Poly(TF).arbitrary(allocator, u, 24);
            defer g.deinit(allocator);
            const x = TF.arbitrary(u);
            const expected = f.eval(TF, x).add(g.eval(TF, x));
            try f.add_assign(allocator, g);
            try expect(f.eval(TF, x).eql(expected));
        },
        .eval_scale => {
            const x = TF.arbitrary(u);
            const w = TF.arbitrary(u);
            const expected = f.eval(TF, x).mul(w);
            f.mul_assign(TF, w);
            try expect(f.eval(TF, x).eql(expected));
        },
        .eval_zero => try expect(f.eval(TF, TF.zero).eql(f.constant())),
        .eval_msm => {
            const x = TF.arbitrary(u);
            try expect(f.eval(TF, x).eql(try f.eval_msm(allocator, TF, x)));
        },
        .lin_comb_eval => try check_lin_comb_eval(allocator, f, u),
        .interpolate => try check_interpolate(allocator, f, .shifted),
        .interpolate_with_zero_point => try check_interpolate(allocator, f, .from_zero),
        .interpolate_with_zero_point_middle => try check_interpolate(allocator, f, .zero_last),
        .translate_scale => try check_translate_scale(allocator, f, TF.arbitrary(u)),
        .commit_eval => {
            const x = TF.arbitrary(u);
            var committed = try commit(allocator, TG, f);
            defer committed.deinit(allocator);
            try expect(TG.generator.mul(f.eval(TF, x)).eql(committed.eval(TF, x)));
        },
        .fuzz_additive => try fuzz_additive(allocator, f, u),
        .fuzz_space_ring => try fuzz_space_ring(allocator, f, u),
    }
}

fn expect(ok: bool) !void {
    if (!ok) return error.LawViolated;
}

fn check_codec(allocator: Allocator, f: Poly(TF)) !void {
    const buffer = try allocator.alloc(u8, f.encode_size());
    defer allocator.free(buffer);
    var w = wire.Writer.init(buffer);
    f.write(&w);
    var r = wire.Reader.init(w.written());
    var decoded = try Poly(TF).read(allocator, &r, f.required(), f.required());
    defer decoded.deinit(allocator);
    try r.finish();
    try expect(decoded.eql(f));
    // A count outside the configured range is rejected.
    r = wire.Reader.init(w.written());
    if (f.required() > 1) {
        const too_small = Poly(TF).read(allocator, &r, 1, f.required() - 1);
        if (too_small) |_| return error.AcceptedOutOfRange else |_| {}
    }
}

fn check_lin_comb_eval(allocator: Allocator, f: Poly(TF), u: *Unstructured) !void {
    var pairs: [16][2]TF = undefined;
    const count = u.length(pairs.len);
    var naive = TF.zero;
    for (pairs[0..count]) |*pair| {
        pair.* = .{ TF.arbitrary(u), TF.arbitrary(u) };
        naive = naive.add(pair[0].mul(f.eval(TF, pair[1])));
    }
    try expect(naive.eql(try f.lin_comb_eval(allocator, TF, pairs[0..count])));
}

const InterpolationPoints = enum { shifted, from_zero, zero_last };

fn check_interpolate(allocator: Allocator, f: Poly(TF), points_kind: InterpolationPoints) !void {
    var zero = try Poly(TF).zero(allocator);
    defer zero.deinit(allocator);
    if (f.eql(zero)) return;
    const n = f.required();
    if (points_kind == .zero_last and n < 2) return;
    const keys = try allocator.alloc(u32, n);
    defer allocator.free(keys);
    const points = try allocator.alloc(TF, n);
    defer allocator.free(points);
    const evals = try allocator.alloc(TF, n);
    defer allocator.free(evals);
    for (keys, points, evals, 0..) |*k, *p, *e, i| {
        k.* = @intCast(i);
        p.* = switch (points_kind) {
            .shifted => TF.from_u64(i + 1),
            .from_zero => TF.from_u64(i),
            .zero_last => if (i + 1 == n) TF.zero else TF.from_u64(i + 1),
        };
        e.* = f.eval(TF, p.*);
    }
    var interpolator = try Interpolator(u32, TF).init(allocator, keys, points);
    defer interpolator.deinit(allocator);
    const recovered = interpolator.interpolate(TF, keys, evals) orelse return error.NoResult;
    try expect(recovered.eql(f.constant()));
    // One evaluation short: the key sets differ, so interpolation refuses.
    try expect(interpolator.interpolate(TF, keys[0 .. n - 1], evals[0 .. n - 1]) == null);
}

fn check_translate_scale(allocator: Allocator, f: Poly(TF), x: TF) !void {
    var translated = try f.translate(allocator, TF, x, struct {
        fn map(scalar: TF, c: TF) TF {
            return scalar.mul(c);
        }
    }.map);
    defer translated.deinit(allocator);
    var scaled = try f.clone(allocator);
    defer scaled.deinit(allocator);
    scaled.mul_assign(TF, x);
    try expect(translated.eql(scaled));
}

fn fuzz_additive(allocator: Allocator, a: Poly(TF), u: *Unstructured) !void {
    var b = try Poly(TF).arbitrary(allocator, u, 24);
    defer b.deinit(allocator);
    var ab = try a.clone(allocator);
    defer ab.deinit(allocator);
    try ab.add_assign(allocator, b);
    var ba = try b.clone(allocator);
    defer ba.deinit(allocator);
    try ba.add_assign(allocator, a);
    try expect(ab.eql(ba));
    // a - a == 0, even though it keeps the high zero coefficients.
    var difference = try a.clone(allocator);
    defer difference.deinit(allocator);
    try difference.sub_assign(allocator, a);
    try expect(difference.degree_exact() == 0 and difference.constant().eql(TF.zero));
    // a - b == a + (-b)
    var negated = try b.clone(allocator);
    defer negated.deinit(allocator);
    negated.neg_assign();
    var left = try a.clone(allocator);
    defer left.deinit(allocator);
    try left.sub_assign(allocator, b);
    var right = try a.clone(allocator);
    defer right.deinit(allocator);
    try right.add_assign(allocator, negated);
    try expect(left.eql(right));
}

fn fuzz_space_ring(allocator: Allocator, a: Poly(TF), u: *Unstructured) !void {
    var polys: [6]Poly(TF) = undefined;
    var scalars: [6]TF = undefined;
    const count = u.length(polys.len);
    var built: usize = 0;
    defer for (polys[0..built]) |*p| p.deinit(allocator);
    while (built < count) : (built += 1) {
        polys[built] = try Poly(TF).arbitrary(allocator, u, 8);
        scalars[built] = TF.arbitrary(u);
    }
    var fast = try Poly(TF).msm(allocator, TF, polys[0..count], scalars[0..count]);
    defer fast.deinit(allocator);
    var naive = try Poly(TF).zero(allocator);
    defer naive.deinit(allocator);
    for (polys[0..count], scalars[0..count]) |p, s| {
        var term = try p.clone(allocator);
        defer term.deinit(allocator);
        term.mul_assign(TF, s);
        try naive.add_assign(allocator, term);
    }
    try expect(fast.eql(naive));
    // (a * 1) == a and (a * 0) == 0.
    var scaled = try a.clone(allocator);
    defer scaled.deinit(allocator);
    scaled.mul_assign(TF, TF.one);
    try expect(scaled.eql(a));
    scaled.mul_assign(TF, TF.zero);
    try expect(scaled.degree_exact() == 0 and scaled.constant().eql(TF.zero));
}

const testing = std.testing;

test "poly fuzz plan (seeded)" {
    try fuzz.run_seeded(0x9017, 1000, {}, fuzz_plan);
}

test "poly fuzz plan (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            try fuzz.run_smith({}, smith, fuzz_plan);
        }
    }.one, .{});
}

fn poly_of(allocator: Allocator, values: []const u8) !Poly(TF) {
    const out = try allocator.alloc(TF, values.len);
    for (out, values) |*o, v| o.* = TF.from_u64(v);
    return Poly(TF).from_owned(out);
}

test "poly equality pads with zeros" {
    const allocator = testing.allocator;
    const cases = [_]struct { a: []const u8, b: []const u8, equal: bool }{
        .{ .a = &.{ 1, 2 }, .b = &.{ 1, 2 }, .equal = true },
        .{ .a = &.{ 1, 2 }, .b = &.{ 2, 3 }, .equal = false },
        .{ .a = &.{ 1, 2 }, .b = &.{ 1, 2, 3 }, .equal = false },
        .{ .a = &.{ 1, 2, 3 }, .b = &.{ 1, 2 }, .equal = false },
        .{ .a = &.{ 1, 2 }, .b = &.{ 1, 2, 0, 0 }, .equal = true },
        .{ .a = &.{ 1, 2, 0, 0 }, .b = &.{ 1, 2 }, .equal = true },
        .{ .a = &.{ 1, 2, 0 }, .b = &.{ 2, 3 }, .equal = false },
        .{ .a = &.{ 2, 3 }, .b = &.{ 1, 2, 0 }, .equal = false },
    };
    for (cases) |case| {
        var a = try poly_of(allocator, case.a);
        defer a.deinit(allocator);
        var b = try poly_of(allocator, case.b);
        defer b.deinit(allocator);
        try testing.expectEqual(case.equal, a.eql(b));
    }
}

test "lin_comb_eval edge cases" {
    const allocator = testing.allocator;
    const cases = [_]struct { poly: []const u8, pairs: []const [2]u8 }{
        .{ .poly = &.{ 3, 5, 7 }, .pairs = &.{} },
        .{ .poly = &.{11}, .pairs = &.{ .{ 2, 0 }, .{ 3, 1 }, .{ 5, 8 } } },
        .{ .poly = &.{ 4, 6, 8 }, .pairs = &.{ .{ 2, 5 }, .{ 7, 5 }, .{ 3, 5 } } },
        .{ .poly = &.{ 9, 2, 3, 4 }, .pairs = &.{ .{ 6, 0 }, .{ 1, 0 }, .{ 5, 7 } } },
        .{ .poly = &.{ 1, 2, 4, 8 }, .pairs = &.{ .{ 3, 1 }, .{ 7, 1 }, .{ 2, 6 } } },
    };
    for (cases) |case| {
        var f = try poly_of(allocator, case.poly);
        defer f.deinit(allocator);
        var pairs: [3][2]TF = undefined;
        var naive = TF.zero;
        for (case.pairs, 0..) |pair, i| {
            pairs[i] = .{ TF.from_u64(pair[0]), TF.from_u64(pair[1]) };
            naive = naive.add(pairs[i][0].mul(f.eval(TF, pairs[i][1])));
        }
        const result = try f.lin_comb_eval(allocator, TF, pairs[0..case.pairs.len]);
        try testing.expect(naive.eql(result));
    }
}

test "interpolation plans cover the test field" {
    const allocator = testing.allocator;
    var f = try poly_of(allocator, &.{ 3, 5, 7, 11 });
    defer f.deinit(allocator);
    try check_interpolate(allocator, f, .shifted);
    try check_interpolate(allocator, f, .from_zero);
    try check_interpolate(allocator, f, .zero_last);
}

test "interpolator keeps the first duplicate and sorts keys" {
    const allocator = testing.allocator;
    var f = try poly_of(allocator, &.{ 9, 4 });
    defer f.deinit(allocator);
    const keys = [_]u32{ 7, 2, 7 };
    const points = [_]TF{ TF.from_u64(3), TF.from_u64(5), TF.from_u64(99) };
    var interpolator = try Interpolator(u32, TF).init(allocator, &keys, &points);
    defer interpolator.deinit(allocator);
    try testing.expectEqualSlices(u32, &.{ 2, 7 }, interpolator.keys);
    const evals = [_]TF{ f.eval(TF, points[1]), f.eval(TF, points[0]) };
    const recovered = interpolator.interpolate(TF, &.{ 2, 7 }, &evals).?;
    try testing.expect(recovered.eql(TF.from_u64(9)));
}
