//! Number theoretic transforms over NTT-friendly fields (commonware `math::ntt`).
//!
//! Polynomials are stored with coefficients in reverse bit order, so the radix-2 butterflies
//! run in place. On top of the transform this module provides evaluation and interpolation of
//! many polynomials at once (`PolynomialVector`, `EvaluationVector`), erasure recovery from a
//! subset of evaluations (`EvaluationVector.recover`), fast vanishing polynomials, and Lagrange
//! coefficients at zero for evaluations at roots of unity (`lagrange_coefficients`).
//!
//! `Matrix` wire format (commonware): varint rows, varint cols, then a varint element count
//! followed by the elements in row-major order.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const algebra = @import("algebra.zig");
const codec = @import("codec");
const minifuzz = @import("invariants").minifuzz;
const Unstructured = minifuzz.Unstructured;

/// Size of the polynomials computed naively in `vanishing` (benchmarked by commonware).
const lg_vanishing_base: u32 = 8;

/// Reverse the low `bit_width` bits of `i`; higher bits are erased.
pub fn reverse_bits(bit_width: u32, i: u64) u64 {
    assert(bit_width <= 64);
    if (bit_width == 0) return 0;
    return @bitReverse(i << @intCast(64 - bit_width));
}

/// Permute `out` (length 2^bit_width) into reverse bit order, in place.
fn reverse_slice(comptime T: type, bit_width: u32, out: []T) void {
    assert(out.len == @as(usize, 1) << @intCast(bit_width));
    for (0..out.len) |i| {
        const j: usize = @intCast(reverse_bits(bit_width, i));
        if (i < j) std.mem.swap(T, &out[i], &out[j]);
    }
}

/// A row-major matrix view: element (i, j) is `data[cols * i + j]`.
fn MatrixView(comptime F: type) type {
    return struct {
        data: []F,
        cols: usize,

        fn at(self: @This(), i: usize, j: usize) *F {
            return &self.data[self.cols * i + j];
        }
    };
}

/// A view of separate column slices: element (i, j) is `columns[j][i]`.
fn ColumnsView(comptime F: type, comptime count: usize) type {
    return struct {
        columns: [count][]F,

        fn at(self: @This(), i: usize, j: usize) *F {
            return &self.columns[j][i];
        }
    };
}

fn lg_of(rows: usize) u32 {
    assert(rows > 0 and std.math.isPowerOfTwo(rows));
    return std.math.log2_int(usize, rows);
}

/// The NTT (or its inverse when `forward` is false) of each column, in place. Inputs are
/// coefficients in reverse bit order; outputs are evaluations at w^0, w^1, ... in order.
fn ntt(comptime F: type, comptime forward: bool, rows: usize, cols: usize, view: anytype) void {
    algebra.assert_field_ntt(F);
    const lg_rows = lg_of(rows);
    const root = F.root_of_unity(@intCast(lg_rows)) orelse @panic("too many rows to perform NTT");
    // Undoing the transform uses w^-1 = w^(2^lg_rows - 1).
    const order_minus_one = (@as(u64, 1) << @intCast(lg_rows)) - 1;
    const w = if (forward) root else algebra.exp(F, root, &.{order_minus_one});
    // stage_roots[s] is the root for stage s: w at the last stage, w^2 before it, and so on.
    var stage_roots: [64]F = undefined;
    var w_power = w;
    var stage: usize = lg_rows;
    while (stage > 0) {
        stage -= 1;
        stage_roots[stage] = w_power;
        w_power = w_power.mul(w_power);
    }
    for (0..lg_rows) |step| {
        // The inverse undoes the forward stages, last stage first.
        const s = if (forward) step else lg_rows - 1 - step;
        ntt_stage(F, forward, rows, cols, view, s, stage_roots[s]);
    }
}

fn ntt_stage(
    comptime F: type,
    comptime forward: bool,
    rows: usize,
    cols: usize,
    view: anytype,
    stage: usize,
    w: F,
) void {
    const skip = @as(usize, 1) << @intCast(stage);
    assert(2 * skip <= rows);
    var i: usize = 0;
    while (i < rows) : (i += 2 * skip) {
        var w_j = F.one;
        for (0..skip) |j| {
            const index_a = i + j;
            const index_b = index_a + skip;
            for (0..cols) |k| {
                const a = view.at(index_a, k).*;
                const b = view.at(index_b, k).*;
                if (forward) {
                    const w_j_b = w_j.mul(b);
                    view.at(index_a, k).* = a.add(w_j_b);
                    view.at(index_b, k).* = a.sub(w_j_b);
                } else {
                    // (a + w b) + (a - w b) = 2a and (a + w b) - (a - w b) = 2 w b, where
                    // this w_j is the inverse of the forward one.
                    view.at(index_a, k).* = algebra.div_2(F, a.add(b));
                    view.at(index_b, k).* = algebra.div_2(F, a.sub(b).mul(w_j));
                }
            }
            w_j = w_j.mul(w);
        }
    }
}

fn ntt_column(comptime F: type, comptime forward: bool, column: []F) void {
    ntt(F, forward, column.len, 1, ColumnsView(F, 1){ .columns = .{column} });
}

/// Divide the roots of a reverse-bit-order polynomial by `factor`: f(x) = 0 becomes
/// f(x / factor) = 0.
fn column_divide_roots(comptime F: type, coefficients: []F, factor: F) void {
    const lg_rows = lg_of(coefficients.len);
    var factor_i = F.one;
    for (0..coefficients.len) |i| {
        const index: usize = @intCast(reverse_bits(lg_rows, i));
        coefficients[index] = coefficients[index].mul(factor_i);
        factor_i = factor_i.mul(factor);
    }
}

/// Evaluate a reverse-bit-order polynomial at one point (testing aid).
fn column_evaluate_one(comptime F: type, coefficients: []const F, point: F) F {
    const lg_rows = lg_of(coefficients.len);
    var out = F.zero;
    var i = coefficients.len;
    while (i > 0) {
        i -= 1;
        out = out.mul(point).add(coefficients[@intCast(reverse_bits(lg_rows, i))]);
    }
    return out;
}

/// Degree of a reverse-bit-order polynomial (0 for the zero polynomial).
fn column_degree(comptime F: type, coefficients: []const F) usize {
    const lg_rows = lg_of(coefficients.len);
    var i = coefficients.len;
    while (i > 0) {
        i -= 1;
        if (!coefficients[@intCast(reverse_bits(lg_rows, i))].eql(F.zero)) return i;
    }
    return 0;
}

/// The points of a power-of-two domain where a polynomial must vanish, stored in reverse bit
/// order. A set bit means "does not vanish".
pub const VanishingPoints = struct {
    lg_size: u32,
    bits: std.DynamicBitSetUnmanaged,

    /// Size 2^lg_size, vanishing everywhere.
    pub fn init(allocator: Allocator, lg_size: u32) Allocator.Error!VanishingPoints {
        assert(lg_size < 64);
        const size = @as(usize, 1) << @intCast(lg_size);
        return .{ .lg_size = lg_size, .bits = try .initEmpty(allocator, size) };
    }

    /// Size 2^lg_size, vanishing nowhere.
    pub fn init_all_non_vanishing(
        allocator: Allocator,
        lg_size: u32,
    ) Allocator.Error!VanishingPoints {
        assert(lg_size < 64);
        const size = @as(usize, 1) << @intCast(lg_size);
        return .{ .lg_size = lg_size, .bits = try .initFull(allocator, size) };
    }

    pub fn deinit(self: *VanishingPoints, allocator: Allocator) void {
        self.bits.deinit(allocator);
        self.* = undefined;
    }

    /// Mark root w^index as vanishing (`value = false`) or not (`value = true`).
    pub fn set(self: *VanishingPoints, index: u64, value: bool) void {
        assert(index < self.bits.bit_length);
        self.bits.setValue(@intCast(reverse_bits(self.lg_size, index)), value);
    }

    pub fn set_non_vanishing(self: *VanishingPoints, index: u64) void {
        self.set(index, true);
    }

    pub fn get(self: VanishingPoints, index: u64) bool {
        assert(index < self.bits.bit_length);
        return self.bits.isSet(@intCast(reverse_bits(self.lg_size, index)));
    }

    pub fn count_non_vanishing(self: VanishingPoints) u64 {
        return self.bits.count();
    }

    pub fn eql(a: VanishingPoints, b: VanishingPoints) bool {
        return a.lg_size == b.lg_size and a.bits.eql(b.bits);
    }

    /// Whether chunk `index` of size 2^lg_chunk_size (in reverse bit order) is all vanishing.
    fn chunk_vanishes_everywhere(self: VanishingPoints, lg_chunk_size: u32, index: u64) bool {
        assert(lg_chunk_size <= self.lg_size);
        const start: usize = @intCast(index << @intCast(lg_chunk_size));
        const end = start + (@as(usize, 1) << @intCast(lg_chunk_size));
        assert(end <= self.bits.bit_length);
        for (start..end) |i| {
            if (self.bits.isSet(i)) return false;
        }
        return true;
    }

    /// Bit `j` of chunk `index`, in reverse bit order (the chunking of
    /// `chunk_vanishes_everywhere`).
    fn chunk_bit(self: VanishingPoints, lg_chunk_size: u32, index: u64, j: usize) bool {
        return self.bits.isSet(@as(usize, @intCast(index << @intCast(lg_chunk_size))) + j);
    }
};

/// Tracks polynomials that vanish nowhere (f = 1), somewhere, or everywhere (X^N - 1), so
/// merges with the trivial cases skip the multiplication.
const Where = enum { nowhere, somewhere, everywhere };

pub fn Vanishing(comptime F: type) type {
    return struct {
        /// The polynomial at 0.
        at_zero: F,
        /// The polynomial's evaluations over the domain (owned).
        evaluations: []F,
    };
}

/// The negated chunk roots -w^0, -w^1, ... (w of order 2^lg_chunk_size), in reverse bit order.
fn chunk_minus_roots(comptime F: type, lg_chunk_size: u32, out: []F) void {
    assert(out.len == @as(usize, 1) << @intCast(lg_chunk_size));
    const w = F.root_of_unity(@intCast(lg_chunk_size)) orelse @panic("sub-root of unity");
    var state = F.one;
    for (out) |*o| {
        o.* = state.neg();
        state = state.mul(w);
    }
    reverse_slice(F, lg_chunk_size, out);
}

/// Build the vanishing polynomial for one chunk naively, in reverse bit order.
fn vanishing_chunk(
    comptime F: type,
    points: VanishingPoints,
    lg_chunk_size: u32,
    index: u64,
    minus_roots: []const F,
    poly: []F,
) Where {
    assert(poly.len == minus_roots.len);
    if (points.chunk_vanishes_everywhere(lg_chunk_size, index)) {
        // X^N - 1, with the implicit leading 1 handled when merging.
        poly[0] = F.one.neg();
        return .everywhere;
    }
    poly[0] = F.one;
    var coeffs: usize = 1;
    for (minus_roots, 0..) |minus_root, j| {
        if (points.chunk_bit(lg_chunk_size, index, j)) continue;
        // Multiply by (X - w^j).
        poly[coeffs] = F.one;
        var k = coeffs - 1;
        while (k >= 1) : (k -= 1) poly[k] = poly[k].mul(minus_root).add(poly[k - 1]);
        poly[0] = poly[0].mul(minus_root);
        coeffs += 1;
    }
    assert(coeffs <= poly.len);
    if (coeffs == 1) return .nowhere;
    reverse_slice(F, lg_chunk_size, poly);
    return .somewhere;
}

/// Evaluate the polynomial vanishing exactly at the vanishing points of `points` over the
/// whole domain, and at zero. Assumes at least one non-vanishing point (otherwise the
/// result is still computed but meaningless).
pub fn vanishing(
    comptime F: type,
    allocator: Allocator,
    points: VanishingPoints,
) Allocator.Error!Vanishing(F) {
    const lg_len = points.lg_size;
    const len = @as(usize, 1) << @intCast(lg_len);
    const lg_chunk_size = @min(lg_vanishing_base, lg_len);
    const chunk_size = @as(usize, 1) << @intCast(lg_chunk_size);
    const out = try allocator.alloc(F, len);
    errdefer allocator.free(out);
    @memset(out, F.zero);
    const vanishes = try allocator.alloc(Where, len / chunk_size);
    defer allocator.free(vanishes);
    const minus_roots = try allocator.alloc(F, chunk_size);
    defer allocator.free(minus_roots);
    chunk_minus_roots(F, lg_chunk_size, minus_roots);

    var at_zero = F.one;
    var negate_at_zero = false;
    for (vanishes, 0..) |*v, i| {
        const poly = out[i * chunk_size ..][0..chunk_size];
        v.* = vanishing_chunk(F, points, lg_chunk_size, i, minus_roots, poly);
        switch (v.*) {
            .everywhere => negate_at_zero = !negate_at_zero,
            .somewhere => at_zero = at_zero.mul(poly[0]),
            .nowhere => {},
        }
    }
    if (negate_at_zero) at_zero = at_zero.neg();
    if (lg_chunk_size >= lg_len) {
        ntt_column(F, true, out);
        return .{ .at_zero = at_zero, .evaluations = out };
    }
    try vanishing_merge(F, allocator, lg_len, lg_chunk_size, out, vanishes, &at_zero);
    return .{ .at_zero = at_zero, .evaluations = out };
}

/// Merge chunk polynomials pairwise, doubling the chunk size each round, until one
/// polynomial (left as evaluations) covers the domain.
fn vanishing_merge(
    comptime F: type,
    allocator: Allocator,
    lg_len: u32,
    lg_chunk_start: u32,
    out: []F,
    vanishes: []Where,
    at_zero: *F,
) Allocator.Error!void {
    assert(lg_chunk_start < lg_len);
    const scratch = try allocator.alloc(F, out.len);
    defer allocator.free(scratch);
    const coeff_shifts = try allocator.alloc(F, out.len / 2);
    defer allocator.free(coeff_shifts);
    const root = F.root_of_unity(@intCast(lg_len)) orelse @panic("domain too large");
    // w_inv for the domain, then squared per round: the first round uses the largest power.
    var w_invs: [64]F = undefined;
    var w_inv = algebra.exp(F, root, &.{(@as(u64, 1) << @intCast(lg_len)) - 1});
    var round = lg_len - lg_chunk_start;
    while (round > 0) {
        round -= 1;
        w_invs[round] = w_inv;
        w_inv = w_inv.mul(w_inv);
    }
    var lg_chunk_size = lg_chunk_start;
    for (w_invs[0 .. lg_len - lg_chunk_start]) |w_round| {
        const chunk_size = @as(usize, 1) << @intCast(lg_chunk_size);
        var power = F.one;
        for (coeff_shifts[0..chunk_size]) |*shift| {
            shift.* = power;
            power = power.mul(w_round);
        }
        const merge: Merge(F) = .{
            .lg_chunk_size = lg_chunk_size,
            .coeff_shifts = coeff_shifts[0..chunk_size],
            .scratch = scratch[0 .. 2 * chunk_size],
            .evaluate = 2 * chunk_size >= out.len,
        };
        var i: usize = 0;
        while (i < out.len / (2 * chunk_size)) : (i += 1) {
            const chunk = out[2 * chunk_size * i ..][0 .. 2 * chunk_size];
            vanishes[i] = merge.pair(chunk, vanishes[2 * i], vanishes[2 * i + 1], at_zero);
        }
        lg_chunk_size += 1;
    }
    assert(lg_chunk_size == lg_len);
}

fn Merge(comptime F: type) type {
    return struct {
        const Self = @This();

        lg_chunk_size: u32,
        coeff_shifts: []const F,
        scratch: []F,
        /// Whether the merged polynomial must be left as evaluations (the last round).
        evaluate: bool,

        /// Multiply the roots of a chunk polynomial by the current power of w.
        fn shift(self: Self, coeffs: []F) void {
            for (coeffs, 0..) |*c, i| {
                c.* = c.mul(self.coeff_shifts[@intCast(reverse_bits(self.lg_chunk_size, i))]);
            }
        }

        fn pair(self: Self, chunk: []F, left: Where, right: Where, at_zero: *F) Where {
            const half = chunk.len / 2;
            assert(half == self.coeff_shifts.len and half >= 2);
            var evaluated = false;
            const result: Where = switch (left) {
                .nowhere => self.pair_nowhere(chunk, right),
                .somewhere => switch (right) {
                    .nowhere => blk: {
                        chunk[half] = F.zero;
                        var i = half - 1;
                        while (i >= 1) : (i -= 1) std.mem.swap(F, &chunk[i], &chunk[2 * i]);
                        break :blk .somewhere;
                    },
                    .everywhere => blk: {
                        // Spread the left side, multiplying by -(X^half + 1).
                        var i = half;
                        while (i > 0) {
                            i -= 1;
                            std.mem.swap(F, &chunk[i], &chunk[2 * i + 1]);
                            chunk[2 * i + 1] = chunk[2 * i + 1].neg();
                            chunk[2 * i] = chunk[2 * i + 1];
                        }
                        break :blk .somewhere;
                    },
                    .somewhere => blk: {
                        self.multiply(chunk);
                        evaluated = true;
                        break :blk .somewhere;
                    },
                },
                .everywhere => self.pair_everywhere(chunk, right, at_zero),
            };
            if (self.evaluate != evaluated) {
                if (evaluated) ntt_column(F, false, chunk) else ntt_column(F, true, chunk);
            }
            return result;
        }

        fn pair_nowhere(self: Self, chunk: []F, right: Where) Where {
            const half = chunk.len / 2;
            switch (right) {
                .nowhere => {
                    // 1 0 0 ... with more zeros: clear the right side's 1.
                    chunk[half] = F.zero;
                    return .nowhere;
                },
                .somewhere => {
                    chunk[0] = F.zero;
                    self.shift(chunk[half..]);
                    for (0..half) |i| std.mem.swap(F, &chunk[half + i], &chunk[2 * i]);
                    return .somewhere;
                },
                .everywhere => {
                    // X^half - 1 on the right, roots shifted by w_N: -X^half - 1, which in
                    // reverse bit order is -1 -1 at the front.
                    chunk[0] = F.one.neg();
                    chunk[1] = F.one.neg();
                    chunk[half] = F.zero;
                    return .somewhere;
                },
            }
        }

        fn pair_everywhere(self: Self, chunk: []F, right: Where, at_zero: *F) Where {
            const half = chunk.len / 2;
            switch (right) {
                .nowhere => {
                    chunk[0] = F.one.neg();
                    chunk[1] = F.one;
                    chunk[half] = F.zero;
                    return .somewhere;
                },
                .somewhere => {
                    // Move the right side over, multiplying by (X^half - 1).
                    self.shift(chunk[half..]);
                    for (0..half) |i| {
                        std.mem.swap(F, &chunk[half + i], &chunk[2 * i + 1]);
                        chunk[2 * i] = chunk[2 * i + 1].neg();
                    }
                    return .somewhere;
                },
                .everywhere => {
                    // Dropping the right side's -1 negates the product; fix at zero.
                    chunk[half] = F.zero;
                    at_zero.* = at_zero.neg();
                    return .everywhere;
                },
            }
        }

        /// The general case: multiply both halves as evaluations; leaves `chunk` evaluated.
        fn multiply(self: Self, chunk: []F) void {
            const half = chunk.len / 2;
            self.shift(chunk[half..]);
            @memset(self.scratch, F.zero);
            for (0..half) |i| std.mem.swap(F, &chunk[half + i], &self.scratch[2 * i]);
            var i = half - 1;
            while (i >= 1) : (i -= 1) std.mem.swap(F, &chunk[i], &chunk[2 * i]);
            const view = ColumnsView(F, 2){ .columns = .{ chunk, self.scratch } };
            ntt(F, true, chunk.len, 2, view);
            for (chunk, self.scratch) |*l, r| l.* = l.mul(r);
        }
    };
}

/// A matrix of field elements in row-major order.
pub fn Matrix(comptime F: type) type {
    algebra.assert_additive(F);
    return struct {
        const Self = @This();

        rows: usize,
        cols: usize,
        /// Owned, `rows * cols` elements.
        data: []F,

        pub fn init_zero(allocator: Allocator, rows: usize, cols: usize) Allocator.Error!Self {
            const data = try allocator.alloc(F, rows * cols);
            @memset(data, F.zero);
            return .{ .rows = rows, .cols = cols, .data = data };
        }

        /// Fill row by row from `values`; missing values are zero, extra values ignored.
        pub fn init(
            allocator: Allocator,
            rows: usize,
            cols: usize,
            values: []const F,
        ) Allocator.Error!Self {
            const out = try init_zero(allocator, rows, cols);
            const count = @min(values.len, out.data.len);
            @memcpy(out.data[0..count], values[0..count]);
            return out;
        }

        pub fn random(allocator: Allocator, rng: anytype, rows: usize, cols: usize) !Self {
            const out = try init_zero(allocator, rows, cols);
            for (out.data) |*x| x.* = F.random(rng);
            return out;
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.data);
            self.* = undefined;
        }

        pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
            const data = try allocator.dupe(F, self.data);
            return .{ .rows = self.rows, .cols = self.cols, .data = data };
        }

        pub fn row(self: Self, i: usize) []F {
            assert(i < self.rows);
            return self.data[self.cols * i ..][0..self.cols];
        }

        pub fn at(self: Self, i: usize, j: usize) *F {
            assert(i < self.rows and j < self.cols);
            return &self.data[self.cols * i + j];
        }

        pub fn eql(a: Self, b: Self) bool {
            if (a.rows != b.rows or a.cols != b.cols) return false;
            for (a.data, b.data) |x, y| {
                if (!x.eql(y)) return false;
            }
            return true;
        }

        /// `self * other`; `self.cols` must equal `other.rows`.
        pub fn mul(self: Self, allocator: Allocator, other: Self) Allocator.Error!Self {
            assert(self.cols == other.rows);
            const out = try init_zero(allocator, self.rows, other.cols);
            for (0..self.rows) |i| {
                for (0..self.cols) |j| {
                    const c = self.at(i, j).*;
                    for (out.row(i), other.row(j)) |*o, x| o.* = o.add(c.mul(x));
                }
            }
            return out;
        }

        fn view(self: Self) MatrixView(F) {
            return .{ .data = self.data, .cols = self.cols };
        }

        /// Interpret the columns as polynomials with at least `min_coefficients` coefficients
        /// (padded to a power of two); null if that would discard rows.
        pub fn as_polynomials(
            self: Self,
            allocator: Allocator,
            min_coefficients: usize,
        ) Allocator.Error!?PolynomialVector(F) {
            if (min_coefficients < self.rows) return null;
            return try PolynomialVector(F).init(allocator, min_coefficients, self.cols, self.data);
        }

        /// The most elements (and the largest dimension) to accept, and the element config.
        pub const Cfg = struct { usize, codec.Cfg(F) };

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(usize, self.rows) + codec.encode_size(usize, self.cols) +
                codec.encode_size([]const F, self.data);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(usize, self.rows, writer);
            codec.write(usize, self.cols, writer);
            codec.write([]const F, self.data, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const range = codec.RangeCfg(usize).to_inclusive(cfg[0]);
            const rows = try codec.read_usize(reader, range);
            const cols = try codec.read_usize(reader, range);
            const count = try codec.read_usize(reader, range);
            const data = try codec.read_items(F, gpa, reader, count, cfg[1]);
            errdefer gpa.free(data);
            const expected = std.math.mul(usize, rows, cols) catch
                return reader.invalid("Matrix", "matrix dimensions overflow");
            if (count != expected) {
                return reader.invalid("Matrix", "matrix element count does not match dimensions");
            }
            return .{ .rows = rows, .cols = cols, .data = @constCast(data) };
        }
    };
}

/// Polynomials stored column-wise, coefficients in reverse bit order (a0 a2 a1 a3 ...).
pub fn PolynomialVector(comptime F: type) type {
    algebra.assert_field_ntt(F);
    return struct {
        const Self = @This();

        data: Matrix(F),

        /// `cols` polynomials with at least `rows` coefficients (rounded up to a power of
        /// two). `coefficients` lists a0 b0 c0 a1 b1 c1 ...; missing ones are zero.
        pub fn init(
            allocator: Allocator,
            rows: usize,
            cols: usize,
            coefficients: []const F,
        ) Allocator.Error!Self {
            assert(rows > 0);
            const padded = std.math.ceilPowerOfTwoAssert(usize, rows);
            const lg_rows = lg_of(padded);
            const data = try Matrix(F).init_zero(allocator, padded, cols);
            for (0..padded) |i| {
                const start = i * cols;
                if (start >= coefficients.len) break;
                const count = @min(cols, coefficients.len - start);
                const target = data.row(@intCast(reverse_bits(lg_rows, i)));
                @memcpy(target[0..count], coefficients[start..][0..count]);
            }
            return .{ .data = data };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.data.deinit(allocator);
            self.* = undefined;
        }

        pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
            return .{ .data = try self.data.clone(allocator) };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.data.eql(b.data);
        }

        /// Coefficient row `i` (a_i b_i c_i ...), for `i` below the padded row count.
        pub fn coefficient_row(self: Self, i: usize) []const F {
            return self.data.row(@intCast(reverse_bits(lg_of(self.data.rows), i)));
        }

        /// Evaluate every polynomial over the domain; consumes `self`.
        pub fn evaluate(self: *Self, allocator: Allocator) Allocator.Error!EvaluationVector(F) {
            const active = try VanishingPoints.init_all_non_vanishing(
                allocator,
                lg_of(self.data.rows),
            );
            ntt(F, true, self.data.rows, self.data.cols, self.data.view());
            const out: EvaluationVector(F) = .{ .data = self.data, .active_rows = active };
            self.* = undefined;
            return out;
        }

        /// `evaluate` through an explicit Vandermonde matrix (testing aid).
        fn evaluate_naive(self: Self, allocator: Allocator) !EvaluationVector(F) {
            const rows = self.data.rows;
            const lg_rows = lg_of(rows);
            const w = F.root_of_unity(@intCast(lg_rows)) orelse @panic("too much data");
            var vandermonde = try Matrix(F).init_zero(allocator, rows, rows);
            defer vandermonde.deinit(allocator);
            var w_i = F.one;
            for (0..rows) |i| {
                var w_ij = F.one;
                for (0..rows) |j| {
                    vandermonde.at(i, @intCast(reverse_bits(lg_rows, j))).* = w_ij;
                    w_ij = w_ij.mul(w_i);
                }
                w_i = w_i.mul(w);
            }
            var data = try vandermonde.mul(allocator, self.data);
            errdefer data.deinit(allocator);
            const active = try VanishingPoints.init_all_non_vanishing(allocator, lg_rows);
            return .{ .data = data, .active_rows = active };
        }

        fn divide_roots(self: *Self, factor: F) void {
            const lg_rows = lg_of(self.data.rows);
            var factor_i = F.one;
            for (0..self.data.rows) |i| {
                for (self.data.row(@intCast(reverse_bits(lg_rows, i)))) |*p| p.* = p.mul(factor_i);
                factor_i = factor_i.mul(factor);
            }
        }

        /// Replace each polynomial P with P / q, for a reverse-bit-order `q` of the same
        /// size with no zeros on the coset `coset_shift * w^i` (consumes `q`'s contents).
        /// `scratch` holds `q.len` elements.
        fn divide(self: *Self, q: []F, scratch: []F) void {
            assert(q.len == self.data.rows);
            // Move the roots off the domain so the pointwise division is defined.
            const skew = F.coset_shift();
            self.divide_roots(skew);
            column_divide_roots(F, q, skew);
            ntt(F, true, self.data.rows, self.data.cols, self.data.view());
            ntt_column(F, true, q);
            batch_invert_nonzero(F, q, scratch);
            for (q, 0..) |q_inv, i| {
                for (self.data.row(i)) |*d| d.* = d.mul(q_inv);
            }
            ntt(F, false, self.data.rows, self.data.cols, self.data.view());
            self.divide_roots(algebra.coset_shift_inv(F));
        }
    };
}

/// Invert every nonzero entry with one field inversion; zeros stay zero.
fn batch_invert_nonzero(comptime F: type, values: []F, prefix: []F) void {
    assert(prefix.len == values.len);
    var product = F.one;
    for (values, prefix) |v, *p| {
        p.* = product;
        if (!v.eql(F.zero)) product = product.mul(v);
    }
    var inverse = product.inv();
    var i = values.len;
    while (i > 0) {
        i -= 1;
        if (values[i].eql(F.zero)) continue;
        const next = inverse.mul(values[i]);
        values[i] = inverse.mul(prefix[i]);
        inverse = next;
    }
}

/// Evaluations of polynomials over a domain, remembering which rows are present.
pub fn EvaluationVector(comptime F: type) type {
    algebra.assert_field_ntt(F);
    return struct {
        const Self = @This();

        data: Matrix(F),
        active_rows: VanishingPoints,

        /// No rows filled.
        pub fn empty(allocator: Allocator, lg_rows: u32, cols: usize) Allocator.Error!Self {
            assert(lg_rows < 64);
            var data = try Matrix(F).init_zero(allocator, @as(usize, 1) << @intCast(lg_rows), cols);
            errdefer data.deinit(allocator);
            return .{ .data = data, .active_rows = try VanishingPoints.init(allocator, lg_rows) };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.data.deinit(allocator);
            self.active_rows.deinit(allocator);
            self.* = undefined;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.data.eql(b.data) and a.active_rows.eql(b.active_rows);
        }

        pub fn fill_row(self: *Self, row_index: usize, values: []const F) void {
            assert(values.len <= self.data.cols);
            @memcpy(self.data.row(row_index)[0..values.len], values);
            self.active_rows.set(row_index, true);
        }

        /// Erase a row (testing aid for recovery).
        pub fn remove_row(self: *Self, row_index: usize) void {
            @memset(self.data.row(row_index), F.zero);
            self.active_rows.set(row_index, false);
        }

        pub fn filled_rows(self: Self) usize {
            return @intCast(self.active_rows.count_non_vanishing());
        }

        /// The polynomials with these evaluations (inverse of `evaluate`); consumes `self`.
        pub fn interpolate(self: *Self, allocator: Allocator) PolynomialVector(F) {
            ntt(F, false, self.data.rows, self.data.cols, self.data.view());
            self.active_rows.deinit(allocator);
            const out: PolynomialVector(F) = .{ .data = self.data };
            self.* = undefined;
            return out;
        }

        /// Recover the polynomials from the filled rows; consumes `self` on success. Succeeds
        /// when each polynomial has fewer coefficients than there are filled rows.
        pub fn recover(self: *Self, allocator: Allocator) !PolynomialVector(F) {
            const present = self.active_rows.count_non_vanishing();
            if (present == 0 or present == self.data.rows) return self.interpolate(allocator);
            // Interpolating D * V, with V vanishing on the missing rows, then dividing by V
            // recovers D when its degree is low enough.
            // Allocate everything first so `self` is consumed only on success.
            const v = try vanishing(F, allocator, self.active_rows);
            defer allocator.free(v.evaluations);
            const scratch = try allocator.alloc(F, v.evaluations.len);
            defer allocator.free(scratch);
            for (v.evaluations, 0..) |e, i| {
                for (self.data.row(i)) |*d| d.* = d.mul(e);
            }
            var out = self.interpolate(allocator);
            ntt_column(F, false, v.evaluations);
            out.divide(v.evaluations, scratch);
            return out;
        }
    };
}

pub fn LagrangeCoefficient(comptime F: type) type {
    return struct { index: u32, coefficient: F };
}

/// Lagrange coefficients at 0 for evaluations at w^j, j in `indices`, where w generates the
/// domain of size `next_power_of_two(total)`. Duplicates and indices >= total are ignored;
/// the result is sorted by index. Uses L_j(0) = P(w^j) / (N * P(0)), with P vanishing on the
/// missing points, which is cheap when few points are missing.
pub fn lagrange_coefficients(
    comptime F: type,
    allocator: Allocator,
    total: u32,
    indices: []const u32,
) ![]LagrangeCoefficient(F) {
    assert(total > 0);
    const size = std.math.ceilPowerOfTwoAssert(u64, total);
    const lg_size: u32 = @intCast(std.math.log2_int(u64, size));
    var present = try VanishingPoints.init(allocator, lg_size);
    defer present.deinit(allocator);
    for (indices) |i| {
        if (i < total) present.set_non_vanishing(i);
    }
    const count = present.count_non_vanishing();
    const out = try allocator.alloc(LagrangeCoefficient(F), @intCast(count));
    errdefer allocator.free(out);
    if (count == 0) return out;
    const n = algebra.scale(F, F.one, &.{size});
    if (count == size) {
        const n_inv = n.inv();
        for (out, 0..) |*o, i| o.* = .{ .index = @intCast(i), .coefficient = n_inv };
        return out;
    }
    const v = try vanishing(F, allocator, present);
    defer allocator.free(v.evaluations);
    const factor = n.mul(v.at_zero).inv();
    var written: usize = 0;
    for (0..size) |j| {
        if (!present.get(j)) continue;
        out[written] = .{ .index = @intCast(j), .coefficient = factor.mul(v.evaluations[j]) };
        written += 1;
    }
    assert(written == out.len);
    return out;
}

const goldilocks = @import("fields/goldilocks.zig");
const testing_types = @import("testing.zig");
const build_options = @import("build_options");
const GF = goldilocks.F;

fn arbitrary_polynomial_vector(
    allocator: Allocator,
    u: *Unstructured,
    lg_rows_max: u32,
    cols_max: usize,
) !PolynomialVector(GF) {
    const lg_rows = u.int_in_range(u32, 0, lg_rows_max);
    const cols = u.int_in_range(usize, 1, cols_max);
    const rows = @as(usize, 1) << @intCast(lg_rows);
    const coefficients = try allocator.alloc(GF, rows * cols);
    defer allocator.free(coefficients);
    for (coefficients) |*c| c.* = try u.arbitrary(GF);
    return PolynomialVector(GF).init(allocator, rows, cols, coefficients);
}

fn arbitrary_points_not_all_vanishing(
    allocator: Allocator,
    u: *Unstructured,
    lg_rows_max: u32,
) !VanishingPoints {
    const lg_rows = u.int_in_range(u32, 0, lg_rows_max);
    const rows = @as(usize, 1) << @intCast(lg_rows);
    const set_row = u.int_in_range(usize, 0, rows - 1);
    var out = try VanishingPoints.init(allocator, lg_rows);
    errdefer out.deinit(allocator);
    for (0..rows) |i| out.set(i, (try u.arbitrary(bool)) or i == set_row);
    return out;
}

/// A recovery case: `n` data rows plus `k` parity rows; `present` lists surviving rows.
pub const RecoverySetup = struct {
    n: usize,
    k: usize,
    cols: usize,
    data: []GF,
    present: VanishingPoints,

    pub fn deinit(self: *RecoverySetup, allocator: Allocator) void {
        allocator.free(self.data);
        self.present.deinit(allocator);
        self.* = undefined;
    }

    pub fn arbitrary(allocator: Allocator, u: *Unstructured) !RecoverySetup {
        const n = u.int_in_range(usize, 1, 128);
        const k = u.int_in_range(usize, 0, 128);
        const cols = u.int_in_range(usize, 1, 4);
        const data = try allocator.alloc(GF, n * cols);
        errdefer allocator.free(data);
        for (data) |*x| x.* = try u.arbitrary(GF);
        const padded = std.math.ceilPowerOfTwoAssert(usize, n + k);
        const present_count = u.int_in_range(usize, n, padded);
        const indices = try allocator.alloc(usize, padded);
        defer allocator.free(indices);
        for (indices, 0..) |*x, i| x.* = i;
        for (0..present_count) |i| {
            const j = u.int_in_range(usize, i, padded - 1);
            std.mem.swap(usize, &indices[i], &indices[j]);
        }
        var present = try VanishingPoints.init(allocator, lg_of(padded));
        for (indices[0..present_count]) |i| present.set(i, true);
        return .{ .n = n, .k = k, .cols = cols, .data = data, .present = present };
    }

    pub fn run(self: RecoverySetup, allocator: Allocator) !void {
        var data = try PolynomialVector(GF).init(allocator, self.n + self.k, self.cols, self.data);
        defer data.deinit(allocator);
        var copy = try data.clone(allocator);
        var encoded = try copy.evaluate(allocator);
        for (0..encoded.data.rows) |i| {
            if (!self.present.get(i)) encoded.remove_row(i);
        }
        var recovered = encoded.recover(allocator) catch |err| {
            encoded.deinit(allocator);
            return err;
        };
        defer recovered.deinit(allocator);
        if (!data.eql(recovered)) return error.RecoveryMismatch;
    }
};

fn check_vanishing(allocator: Allocator, points: VanishingPoints) !void {
    const v = try vanishing(GF, allocator, points);
    defer allocator.free(v.evaluations);
    if (points.count_non_vanishing() == 0) return;
    ntt_column(GF, false, v.evaluations);
    const coefficients = v.evaluations;
    const total = @as(u64, 1) << @intCast(points.lg_size);
    const expected_degree = total - points.count_non_vanishing();
    if (column_degree(GF, coefficients) != expected_degree) return error.WrongDegree;
    if (!v.at_zero.eql(coefficients[0])) return error.WrongAtZero;
    const w = GF.root_of_unity(@intCast(points.lg_size)).?;
    var w_i = GF.one;
    for (0..total) |i| {
        const value = column_evaluate_one(GF, coefficients, w_i);
        if (points.get(i) == value.eql(GF.zero)) return error.WrongRoots;
        w_i = w_i.mul(w);
    }
}

/// The NTT fuzz plan (commonware `ntt::fuzz::Plan`), run with `testing.allocator`.
pub fn fuzz_plan(_: void, u: *Unstructured) !void {
    const allocator = std.testing.allocator;
    switch (u.int_in_range(u8, 0, 3)) {
        0 => {
            var p = try arbitrary_polynomial_vector(allocator, u, 6, 4);
            var naive = try p.evaluate_naive(allocator);
            defer naive.deinit(allocator);
            var fast = try p.evaluate(allocator);
            defer fast.deinit(allocator);
            if (!fast.eql(naive)) return error.NttMismatch;
        },
        1 => {
            var p = try arbitrary_polynomial_vector(allocator, u, 6, 4);
            defer p.deinit(allocator);
            var copy = try p.clone(allocator);
            var evaluated = try copy.evaluate(allocator);
            var back = evaluated.interpolate(allocator);
            defer back.deinit(allocator);
            if (!p.eql(back)) return error.RoundTripMismatch;
        },
        2 => {
            var points = try arbitrary_points_not_all_vanishing(allocator, u, 8);
            defer points.deinit(allocator);
            try check_vanishing(allocator, points);
        },
        else => {
            var setup = try RecoverySetup.arbitrary(allocator, u);
            defer setup.deinit(allocator);
            try setup.run(allocator);
        },
    }
}

const testing = std.testing;

test "ntt fuzz plan" {
    try (minifuzz.Builder{}).with_search_limit(300 * build_options.fuzz_soak)
        .run(testing.allocator, {}, fuzz_plan);
}

test "ntt fuzz plan (coverage-guided)" {
    try testing.fuzz({}, testing_types.smith_body(void, fuzz_plan), .{});
}

test "reverse bits" {
    try testing.expectEqual(@as(u64, 0b0001), reverse_bits(4, 0b1000));
    try testing.expectEqual(@as(u64, 0b0010), reverse_bits(4, 0b0100));
    try testing.expectEqual(@as(u64, 0b0100), reverse_bits(4, 0b0010));
    try testing.expectEqual(@as(u64, 0b1000), reverse_bits(4, 0b0001));
}

test "matrix read rejects length mismatch" {
    var buffer: [64]u8 = undefined;
    var w = codec.Writer.init(&buffer);
    codec.write(usize, 2, &w);
    codec.write(usize, 2, &w);
    codec.write([]const GF, &.{ GF.one, GF.one, GF.one }, &w);
    const result = codec.decode_cfg(Matrix(GF), testing.allocator, w.written(), .{ 8, {} });
    try testing.expectError(error.Invalid, result);
}

test "matrix codec round trip" {
    const allocator = testing.allocator;
    var rng = @import("utils").rng.test_rng();
    var m = try Matrix(GF).random(allocator, &rng, 3, 5);
    defer m.deinit(allocator);
    const bytes = try codec.encode(Matrix(GF), allocator, m);
    defer allocator.free(bytes);
    var decoded = try codec.decode_cfg(Matrix(GF), allocator, bytes, .{ 15, {} });
    defer decoded.deinit(allocator);
    try testing.expect(m.eql(decoded));
    try testing.expectError(
        error.InvalidLength,
        codec.decode_cfg(Matrix(GF), allocator, bytes, .{ 14, {} }),
    );
}

test "divide matches pointwise inversion" {
    const allocator = testing.allocator;
    var rng = @import("utils").rng.test_rng();
    for ([_]u32{ 0, 1, 2, 3, 5, 8 }) |lg_rows| {
        const rows = @as(usize, 1) << @intCast(lg_rows);
        for ([_]usize{ 1, 3 }) |cols| {
            for (0..6) |zeros| try check_divide(allocator, &rng, lg_rows, rows, cols, zeros);
        }
    }
}

fn check_divide(
    allocator: Allocator,
    rng: anytype,
    lg_rows: u32,
    rows: usize,
    cols: usize,
    zeros: usize,
) !void {
    var data = try Matrix(GF).random(allocator, rng, rows, cols);
    var expected = try data.clone(allocator);
    defer expected.deinit(allocator);
    const q = try allocator.alloc(GF, rows);
    defer allocator.free(q);
    for (q, 0..) |*d, i| {
        const is_zero = switch (zeros) {
            0 => false,
            1 => true,
            2 => i == 0,
            3 => i == rows - 1,
            4 => i % 2 == 0,
            else => i != rows / 2,
        };
        d.* = if (is_zero) GF.zero else GF.random(rng);
        for (expected.row(i)) |*x| x.* = x.mul(d.inv());
    }
    var evaluations: EvaluationVector(GF) = .{
        .data = data,
        .active_rows = try VanishingPoints.init_all_non_vanishing(allocator, lg_rows),
    };
    var p = evaluations.interpolate(allocator);
    ntt_column(GF, false, q);
    // Cancel divide's coset shift so it sees the denominators chosen above.
    p.divide_roots(GF.coset_shift_inv());
    column_divide_roots(GF, q, GF.coset_shift_inv());
    const scratch = try allocator.alloc(GF, rows);
    defer allocator.free(scratch);
    p.divide(q, scratch);
    p.divide_roots(GF.coset_shift());
    var result = try p.evaluate(allocator);
    defer result.deinit(allocator);
    try testing.expect(result.data.eql(expected));
}

test "recovery 000" {
    const allocator = testing.allocator;
    var present = try VanishingPoints.init(allocator, 1);
    present.set_non_vanishing(1);
    var setup: RecoverySetup = .{
        .n = 1,
        .k = 1,
        .cols = 1,
        .data = try allocator.dupe(GF, &.{GF.one}),
        .present = present,
    };
    defer setup.deinit(allocator);
    try setup.run(allocator);
}

test "recovery of an empty vector" {
    const allocator = testing.allocator;
    var empty = try EvaluationVector(GF).empty(allocator, 4, 3);
    var recovered = try empty.recover(allocator);
    defer recovered.deinit(allocator);
    var other = try EvaluationVector(GF).empty(allocator, 4, 3);
    var expected = other.interpolate(allocator);
    defer expected.deinit(allocator);
    try testing.expect(recovered.eql(expected));
}

test "vanishing polynomial for all two-chunk combinations" {
    const allocator = testing.allocator;
    const lg_size = lg_vanishing_base + 1;
    const chunk_size = @as(usize, 1) << lg_vanishing_base;
    // (0,0) vanishes everywhere, (0,1) somewhere, (1,1) nowhere.
    const states = [_][2]bool{ .{ false, false }, .{ false, true }, .{ true, true } };
    for (states) |left| {
        for (states) |right| {
            var points = try VanishingPoints.init(allocator, lg_size);
            defer points.deinit(allocator);
            // Writing raw (bit-reversed) halves aligns them with the implementation's chunks.
            for ([2][2]bool{ left, right }, 0..) |values, half| {
                for (0..chunk_size) |i| {
                    const raw = half * chunk_size + i;
                    points.set(reverse_bits(lg_size, raw), values[i % 2]);
                }
            }
            try check_vanishing(allocator, points);
        }
    }
}

test "lagrange coefficients interpolate at zero" {
    const allocator = testing.allocator;
    // f(X) = 5 + 3X + 7X^2 needs 3 evaluations; use indices {0, 2, 4} of a domain of 5 (8).
    const coefficients = [_]GF{ GF.from_u64(5), GF.from_u64(3), GF.from_u64(7) };
    const w = GF.root_of_unity(3).?;
    const result = try lagrange_coefficients(GF, allocator, 5, &.{ 4, 0, 2, 2, 9 });
    defer allocator.free(result);
    try testing.expectEqual(@as(usize, 3), result.len);
    var sum = GF.zero;
    for (result) |entry| {
        const x = algebra.exp(GF, w, &.{entry.index});
        const y = coefficients[0].add(coefficients[1].mul(x)).add(coefficients[2].mul(x.mul(x)));
        sum = sum.add(entry.coefficient.mul(y));
    }
    try testing.expect(sum.eql(coefficients[0]));
}
