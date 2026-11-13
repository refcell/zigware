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
const codec = @import("codec");
const minifuzz = @import("invariants").minifuzz;
const ntt = @import("ntt.zig");
const Unstructured = minifuzz.Unstructured;

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
        pub fn random(allocator: Allocator, rng: anytype, degree_value: u32) !Self {
            const out = try allocator.alloc(K, @as(usize, degree_value) + 1);
            for (out) |*c| c.* = K.random(rng);
            return from_owned(out);
        }

        /// Random coefficients with a fixed constant (commonware `Poly::new_with_constant`).
        pub fn random_with_constant(
            allocator: Allocator,
            rng: anytype,
            degree_value: u32,
            constant_value: K,
        ) !Self {
            const out = try allocator.alloc(K, @as(usize, degree_value) + 1);
            out[0] = constant_value;
            for (out[1..]) |*c| c.* = K.random(rng);
            return from_owned(out);
        }

        /// The permitted coefficient count (zero is always rejected, as commonware's
        /// `RangeCfg<NonZeroU32>`) and the coefficient config.
        pub const Cfg = codec.SliceCfg(codec.Cfg(K));

        /// Accept exactly `count` coefficients.
        pub fn cfg_exact(count: u32) Cfg {
            return .{ .range = .exact(count), .item = codec.unit_cfg(codec.Cfg(K)) };
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size([]const K, self.coeffs);
        }

        /// Upper bound on the encoded size with at most `coefficients` coefficients
        /// (commonware `Poly::max_encode_size`).
        pub fn max_encode_size_with(coefficients: u32) usize {
            return codec.util.max_items_size(coefficients, codec.max_encode_size(K).?);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            assert(self.coeffs.len >= 1);
            codec.write([]const K, self.coeffs, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const count = try codec.read_usize(reader, cfg.range);
            if (count == 0 or count > std.math.maxInt(u32)) {
                return reader.fail(error.InvalidLength, count);
            }
            const coeffs = try codec.read_items(K, gpa, reader, count, cfg.item);
            return from_owned(@constCast(coeffs));
        }

        /// commonware's `Arbitrary`: the constant coefficient, then arbitrary's `Vec<K>`
        /// (a continue flag before each further coefficient).
        pub fn arbitrary(allocator: Allocator, u: *Unstructured) !Self {
            var coefficients: std.ArrayList(K) = .empty;
            errdefer coefficients.deinit(allocator);
            try coefficients.append(allocator, try u.arbitrary(K));
            // Each flag consumes a byte until the input runs out, which ends the list.
            const flags_max = u.len() + 1;
            var flags: usize = 0;
            while (flags < flags_max and try u.arbitrary(bool)) : (flags += 1) {
                try coefficients.append(allocator, try u.arbitrary(K));
            }
            return from_owned(try coefficients.toOwnedSlice(allocator));
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

        /// An interpolator for evaluation points `w^exponents[i]`, where `w` has order
        /// `next_power_of_two(total)`, using the O(n log n) `ntt.lagrange_coefficients`.
        /// `keys` and `exponents` must each be unique (a bijection); exponents >= total are
        /// ignored.
        pub fn init_roots_of_unity(
            allocator: Allocator,
            total: u32,
            keys: []const I,
            exponents: []const u32,
        ) !Self {
            comptime algebra.assert_field_ntt(F);
            assert(keys.len == exponents.len);
            const coefficients = try ntt.lagrange_coefficients(F, allocator, total, exponents);
            defer allocator.free(coefficients);
            const entries = try allocator.alloc(Entry, coefficients.len);
            defer allocator.free(entries);
            for (entries, coefficients) |*e, c| {
                const position = std.mem.indexOfScalar(u32, exponents, c.index).?;
                e.* = .{ .key = keys[position], .point = c.coefficient };
            }
            std.mem.sort(Entry, entries, {}, entry_less);
            const keys_out = try allocator.alloc(I, entries.len);
            errdefer allocator.free(keys_out);
            const weights_out = try allocator.alloc(F, entries.len);
            for (keys_out, weights_out, entries) |*k, *w, e| {
                k.* = e.key;
                w.* = e.point;
            }
            return .{ .keys = keys_out, .weights = weights_out };
        }

        /// `init_roots_of_unity` by the naive O(n^2) algorithm (testing aid).
        fn init_roots_of_unity_naive(
            allocator: Allocator,
            total: u32,
            keys: []const I,
            exponents: []const u32,
        ) !Self {
            const size = std.math.ceilPowerOfTwoAssert(u64, total);
            const w = F.root_of_unity(@intCast(std.math.log2_int(u64, size))).?;
            var kept_keys: std.ArrayList(I) = .empty;
            defer kept_keys.deinit(allocator);
            var points: std.ArrayList(F) = .empty;
            defer points.deinit(allocator);
            for (keys, exponents) |k, e| {
                if (e >= total) continue;
                try kept_keys.append(allocator, k);
                try points.append(allocator, algebra.exp(F, w, &.{e}));
            }
            return init(allocator, kept_keys.items, points.items);
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
const build_options = @import("build_options");
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
    roots_of_unity_eq_naive,
    fuzz_additive,
    fuzz_space_ring,
};

/// The polynomial fuzz plan (commonware `poly::fuzz::Plan`): a derived enum tag, then the
/// variant's fields in order. Runs with `testing.allocator`.
pub fn fuzz_plan(_: void, u: *Unstructured) !void {
    const allocator = std.testing.allocator;
    const kind = try u.arbitrary(PlanKind);
    switch (kind) {
        .fuzz_additive => return fuzz_additive(allocator, u),
        .fuzz_space_ring => return fuzz_space_ring(allocator, u),
        .roots_of_unity_eq_naive => return check_roots_of_unity(allocator, try u.arbitrary(u16)),
        else => {},
    }
    var f = try Poly(TF).arbitrary(allocator, u);
    defer f.deinit(allocator);
    switch (kind) {
        .codec => try check_codec(allocator, f),
        .eval_add => {
            var g = try Poly(TF).arbitrary(allocator, u);
            defer g.deinit(allocator);
            const x = try u.arbitrary(TF);
            const expected = f.eval(TF, x).add(g.eval(TF, x));
            try f.add_assign(allocator, g);
            try expect(f.eval(TF, x).eql(expected));
        },
        .eval_scale => {
            const x = try u.arbitrary(TF);
            const w = try u.arbitrary(TF);
            const expected = f.eval(TF, x).mul(w);
            f.mul_assign(TF, w);
            try expect(f.eval(TF, x).eql(expected));
        },
        .eval_zero => try expect(f.eval(TF, TF.zero).eql(f.constant())),
        .eval_msm => {
            const x = try u.arbitrary(TF);
            try expect(f.eval(TF, x).eql(try f.eval_msm(allocator, TF, x)));
        },
        .lin_comb_eval => try check_lin_comb_eval(allocator, f, u),
        .interpolate => try check_interpolate(allocator, f, .shifted),
        .interpolate_with_zero_point => try check_interpolate(allocator, f, .from_zero),
        .interpolate_with_zero_point_middle => try check_interpolate(allocator, f, .zero_last),
        .translate_scale => try check_translate_scale(allocator, f, try u.arbitrary(TF)),
        .commit_eval => {
            const x = try u.arbitrary(TF);
            var committed = try commit(allocator, TG, f);
            defer committed.deinit(allocator);
            try expect(TG.generator.mul(f.eval(TF, x)).eql(committed.eval(TF, x)));
        },
        .roots_of_unity_eq_naive, .fuzz_additive, .fuzz_space_ring => unreachable,
    }
}

fn expect(ok: bool) !void {
    if (!ok) return error.LawViolated;
}

fn check_codec(allocator: Allocator, f: Poly(TF)) !void {
    const bytes = try codec.encode(Poly(TF), allocator, f);
    defer allocator.free(bytes);
    const cfg = Poly(TF).cfg_exact(f.required());
    var decoded = try codec.decode_cfg(Poly(TF), allocator, bytes, cfg);
    defer decoded.deinit(allocator);
    try expect(decoded.eql(f));
    // A count outside the configured range is rejected.
    const too_small: Poly(TF).Cfg = .{ .range = .to(f.required()) };
    const rejected = codec.decode_cfg(Poly(TF), allocator, bytes, too_small);
    if (rejected) |_| return error.AcceptedOutOfRange else |err| {
        if (err != error.InvalidLength) return err;
    }
}

fn check_lin_comb_eval(allocator: Allocator, f: Poly(TF), u: *Unstructured) !void {
    // arbitrary's Vec<(F, F)>: a continue flag before each pair.
    var pairs: std.ArrayList([2]TF) = .empty;
    defer pairs.deinit(allocator);
    var naive = TF.zero;
    const flags_max = u.len() + 1;
    while (pairs.items.len < flags_max and try u.arbitrary(bool)) {
        const pair = [2]TF{ try u.arbitrary(TF), try u.arbitrary(TF) };
        naive = naive.add(pair[0].mul(f.eval(TF, pair[1])));
        try pairs.append(allocator, pair);
    }
    try expect(naive.eql(try f.lin_comb_eval(allocator, TF, pairs.items)));
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

fn check_roots_of_unity(allocator: Allocator, seed: u16) !void {
    const GF = @import("fields/goldilocks.zig").F;
    const n: u32 = @as(u32, seed % 256) + 1;
    const keys = try allocator.alloc(u32, n);
    defer allocator.free(keys);
    for (keys, 0..) |*k, i| k.* = @intCast(i);
    var fast = try Interpolator(u32, GF).init_roots_of_unity(allocator, n, keys, keys);
    defer fast.deinit(allocator);
    var naive = try Interpolator(u32, GF).init_roots_of_unity_naive(allocator, n, keys, keys);
    defer naive.deinit(allocator);
    try expect(std.mem.eql(u32, fast.keys, naive.keys));
    for (fast.weights, naive.weights) |a, b| try expect(a.eql(b));
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

/// `test_suites::fuzz_additive::<Poly<F>>` with allocating polynomials.
fn fuzz_additive(allocator: Allocator, u: *Unstructured) !void {
    var a = try Poly(TF).arbitrary(allocator, u);
    defer a.deinit(allocator);
    var b = try Poly(TF).arbitrary(allocator, u);
    defer b.deinit(allocator);
    var c = try Poly(TF).arbitrary(allocator, u);
    defer c.deinit(allocator);
    var ab = try sum(allocator, a, b);
    defer ab.deinit(allocator);
    var ba = try sum(allocator, b, a);
    defer ba.deinit(allocator);
    try expect(ab.eql(ba));
    var ab_c = try sum(allocator, ab, c);
    defer ab_c.deinit(allocator);
    var bc = try sum(allocator, b, c);
    defer bc.deinit(allocator);
    var a_bc = try sum(allocator, a, bc);
    defer a_bc.deinit(allocator);
    try expect(ab_c.eql(a_bc));
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
    var right = try sum(allocator, a, negated);
    defer right.deinit(allocator);
    try expect(left.eql(right));
}

fn sum(allocator: Allocator, a: Poly(TF), b: Poly(TF)) !Poly(TF) {
    var out = try a.clone(allocator);
    errdefer out.deinit(allocator);
    try out.add_assign(allocator, b);
    return out;
}

fn scale_of(allocator: Allocator, a: Poly(TF), x: TF) !Poly(TF) {
    var out = try a.clone(allocator);
    out.mul_assign(TF, x);
    return out;
}

/// `test_suites::fuzz_space_ring::<F, Poly<F>>` with allocating polynomials, drawing in
/// the same order.
fn fuzz_space_ring(allocator: Allocator, u: *Unstructured) !void {
    {
        var a = try Poly(TF).arbitrary(allocator, u);
        defer a.deinit(allocator);
        var b = try Poly(TF).arbitrary(allocator, u);
        defer b.deinit(allocator);
        const x = try u.arbitrary(TF);
        var ab = try sum(allocator, a, b);
        defer ab.deinit(allocator);
        var left = try scale_of(allocator, ab, x);
        defer left.deinit(allocator);
        var ax = try scale_of(allocator, a, x);
        defer ax.deinit(allocator);
        var bx = try scale_of(allocator, b, x);
        defer bx.deinit(allocator);
        var right = try sum(allocator, ax, bx);
        defer right.deinit(allocator);
        try expect(left.eql(right));
        _ = try u.arbitrary(TF); // `a *= c` against `a * c`: the same call here.
    }
    try check_poly_msm(allocator, u);
    {
        var a = try Poly(TF).arbitrary(allocator, u);
        defer a.deinit(allocator);
        const b = try u.arbitrary(TF);
        const c = try u.arbitrary(TF);
        var ab = try scale_of(allocator, a, b);
        defer ab.deinit(allocator);
        var ab_c = try scale_of(allocator, ab, c);
        defer ab_c.deinit(allocator);
        var a_bc = try scale_of(allocator, a, b.mul(c));
        defer a_bc.deinit(allocator);
        try expect(ab_c.eql(a_bc));
    }
    var a = try Poly(TF).arbitrary(allocator, u);
    defer a.deinit(allocator);
    var one = try scale_of(allocator, a, TF.one);
    defer one.deinit(allocator);
    try expect(one.eql(a));
    var zero = try scale_of(allocator, a, TF.zero);
    defer zero.deinit(allocator);
    try expect(zero.degree_exact() == 0 and zero.constant().eql(TF.zero));
}

fn check_poly_msm(allocator: Allocator, u: *Unstructured) !void {
    const count = u.int_in_range(usize, 0, 16);
    var polys: [16]Poly(TF) = undefined;
    var built: usize = 0;
    defer for (polys[0..built]) |*p| p.deinit(allocator);
    while (built < count) : (built += 1) polys[built] = try Poly(TF).arbitrary(allocator, u);
    var scalars: [16]TF = undefined;
    for (scalars[0..count]) |*scalar| scalar.* = try u.arbitrary(TF);
    var fast = try Poly(TF).msm(allocator, TF, polys[0..count], scalars[0..count]);
    defer fast.deinit(allocator);
    var naive = try Poly(TF).zero(allocator);
    defer naive.deinit(allocator);
    for (polys[0..count], scalars[0..count]) |p, x| {
        var term = try scale_of(allocator, p, x);
        defer term.deinit(allocator);
        try naive.add_assign(allocator, term);
    }
    try expect(fast.eql(naive));
}

const testing = std.testing;

test "poly fuzz plan" {
    try (minifuzz.Builder{}).with_search_limit(2000 * build_options.fuzz_soak)
        .run(testing.allocator, {}, fuzz_plan);
}

test "poly fuzz plan (coverage-guided)" {
    try testing.fuzz({}, testing_types.smith_body(void, fuzz_plan), .{});
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

test "roots of unity interpolator maps exponents back to keys" {
    const allocator = testing.allocator;
    const GF = @import("fields/goldilocks.zig").F;
    const keys = [_]u32{ 30, 10, 20 };
    const exponents = [_]u32{ 2, 0, 7 };
    var fast = try Interpolator(u32, GF).init_roots_of_unity(allocator, 5, &keys, &exponents);
    defer fast.deinit(allocator);
    const Naive = Interpolator(u32, GF);
    var naive = try Naive.init_roots_of_unity_naive(allocator, 5, &keys, &exponents);
    defer naive.deinit(allocator);
    try testing.expectEqualSlices(u32, &.{ 10, 30 }, fast.keys);
    try testing.expectEqualSlices(u32, naive.keys, fast.keys);
    for (fast.weights, naive.weights) |a, b| try testing.expect(a.eql(b));
}
