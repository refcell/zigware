//! The bucket (Pippenger) multi-scalar multiplication behind ed25519 batch verification, as in
//! commonware's curve25519 crate (`signing/core/msm.rs`): signed `width`-bit digits, one bucket
//! per digit magnitude, and mixed additions of affine points. `core.verify_shard` and the
//! curve25519 lane's `batch.verify_batch` both sum their chunks with `Terms`.

const std = @import("std");
const assert = std.debug.assert;

const core = @import("core.zig");
const verify_avx2 = @import("verify_avx2.zig");
const verify_ifma = @import("verify_ifma.zig");
const Point = core.Point;
const Fe = Point.Fe;
const scalar = Point.scalar;

/// The most signatures one bucket MSM sums.
pub const chunk_signatures = 128;
/// One `R` and one `A` per signature, and the basepoint.
pub const chunk_terms = 2 * chunk_signatures + 1;
/// The crate's `MIN_WIDTH`, which its `width_for` picks for every batch below 2^10 terms.
pub const width = 6;
/// Signed windows covering a 256-bit scalar; the top one absorbs the final carry (`s < 2^253`).
pub const windows = (256 + width - 1) / width;
/// One bucket per nonzero digit magnitude, `1 ..= 2^(width - 1)`.
const bucket_count = 1 << (width - 1);
/// Fewer signatures than this go through Straus: the bucket fold's fixed cost (`windows`
/// passes over `bucket_count` buckets) outweighs its saving below about 88 terms (the crate's
/// portable `STRAUS_TERM_CUTOFF`).
pub const straus_signatures = 44;

comptime {
    assert(chunk_terms < 1 << 10);
    assert(windows * width >= 256);
    assert(straus_signatures <= chunk_signatures / 2);
    assert(chunk_signatures <= std.math.maxInt(u8) + 1);
}

/// Recodes `s < 2^253` into `windows` signed digits in `[-2^(width-1), 2^(width-1)]`, so that
/// `s = sum digit_w 2^(width w)`.
pub fn signed_digits(s: *const [32]u8) [windows]i8 {
    const value = std.mem.readInt(u256, s, .little);
    assert(value < @as(u256, 1) << 253);
    var digits: [windows]i8 = undefined;
    var carry: i16 = 0;
    for (&digits, 0..) |*digit, window| {
        const shift: u8 = @intCast(window * width);
        var d: i16 = @as(i16, @intCast((value >> shift) & (2 * bucket_count - 1))) + carry;
        carry = 0;
        if (d > bucket_count) {
            d -= 2 * bucket_count;
            carry = 1;
        }
        assert(d >= -bucket_count and d <= bucket_count);
        digit.* = @intCast(d);
    }
    assert(carry == 0);
    return digits;
}

/// An affine point (`Z = 1`) prepared for mixed addition: `(y - x, y + x, 2 d x y)`.
const Cached = struct {
    y_minus_x: Fe,
    y_plus_x: Fe,
    t2d: Fe,

    fn init(point: Point) Cached {
        // Decompressed points, their negations, and the basepoint all carry Z = 1.
        assert(point.z.equivalent(Fe.one));
        return .{
            .y_minus_x = point.y.sub(point.x),
            .y_plus_x = point.y.add(point.x),
            .t2d = point.t.mul(Fe.edwards25519d2),
        };
    }
};

/// `p + q` (or `p - q` when `negate`) for an affine `q`: std's unified addition with `Z_q = 1`.
fn add_mixed(p: Point, q: *const Cached, negate: bool) Point {
    const q_minus = if (negate) q.y_plus_x else q.y_minus_x;
    const q_plus = if (negate) q.y_minus_x else q.y_plus_x;
    const a = p.y.sub(p.x).mul(q_minus);
    const b = p.x.add(p.y).mul(q_plus);
    const c = if (negate) p.t.mul(q.t2d).neg() else p.t.mul(q.t2d);
    const d = p.z.add(p.z);
    const x = b.sub(a);
    const y = b.add(a);
    const z = d.add(c);
    const t = d.sub(c);
    return .{ .x = x.mul(t), .y = y.mul(z), .z = z.mul(t), .t = x.mul(y) };
}

/// The std `Point` code behind the packed-point interface (`verify_avx2.zig`), for CPUs without
/// a packed backend. Its terms must be affine (`Z = 1`), which `add_signers` ensures.
pub const scalar_backend = struct {
    pub const available = true;

    pub const PackedCached = struct {
        cached: Cached,

        pub fn from_point(point: Point) PackedCached {
            return .{ .cached = .init(point) };
        }
    };

    pub const PackedPoint = struct {
        point: Point,

        pub const identity_element: PackedPoint = .{ .point = Point.identityElement };

        pub fn from_point(point: Point) PackedPoint {
            return .{ .point = point };
        }

        pub fn to_point(self: PackedPoint) Point {
            return self.point;
        }

        pub fn add_cached(self: PackedPoint, q: *const PackedCached, negate: bool) PackedPoint {
            return .{ .point = add_mixed(self.point, &q.cached, negate) };
        }

        pub fn add_point(self: PackedPoint, other: PackedPoint) PackedPoint {
            return .{ .point = self.point.add(other.point) };
        }

        pub fn dbl(self: PackedPoint) PackedPoint {
            return .{ .point = self.point.dbl() };
        }
    };
};

/// Every backend the bucket MSM can run on here, fastest first; tests compare them all. AVX2
/// and scalar are portable code; IFMA compiles only for targets that have it.
pub const backends = if (verify_ifma.available)
    .{ verify_ifma, verify_avx2, scalar_backend }
else
    .{ verify_avx2, scalar_backend };

/// The backend `Terms` uses: the first one this target supports.
pub const Backend = if (verify_ifma.available)
    verify_ifma
else if (verify_avx2.available)
    verify_avx2
else
    scalar_backend;

pub const Terms = TermsWith(Backend);

/// Up to `chunk_terms` MSM terms on `B`: points prepared for addition and their scalars'
/// signed digits, stored window-major so each bucket pass reads one row.
pub fn TermsWith(comptime B: type) type {
    comptime assert(@hasDecl(B, "PackedPoint") and @hasDecl(B, "PackedCached"));
    return struct {
        const Self = @This();
        points: [chunk_terms]B.PackedCached,
        digits: [windows][chunk_terms]i8,
        count: usize,

        pub fn init() Self {
            return .{ .points = undefined, .digits = undefined, .count = 0 };
        }

        pub fn add(terms: *Self, point: Point, s: *const [32]u8) void {
            assert(terms.count < chunk_terms);
            terms.points[terms.count] = .from_point(point);
            const digits = signed_digits(s);
            for (&terms.digits, digits) |*row, digit| row[terms.count] = digit;
            terms.count += 1;
        }

        /// `sum s_i P_i` by the bucket method: per window from the top, `width` doublings, then
        /// every term added to (or subtracted from) the bucket of its digit's magnitude, and
        /// the buckets folded with two running sums into `sum j bucket_j`.
        pub fn sum(terms: *const Self) Point {
            assert(terms.count <= chunk_terms);
            const P = B.PackedPoint;
            var result = P.identity_element;
            var buckets: [bucket_count]P = undefined;
            var window: usize = windows;
            while (window > 0) {
                window -= 1;
                for (0..width) |_| result = result.dbl();
                @memset(&buckets, P.identity_element);
                var used: usize = 0;
                const row = terms.digits[window][0..terms.count];
                for (row, terms.points[0..terms.count]) |digit, *point| {
                    if (digit == 0) continue;
                    const magnitude = @abs(digit);
                    const bucket = &buckets[magnitude - 1];
                    bucket.* = bucket.add_cached(point, digit < 0);
                    used = @max(used, magnitude);
                }
                result = result.add_point(fold(P, buckets[0..used]));
            }
            return result.to_point();
        }
    };
}

/// `sum (j + 1) buckets[j]`, from the top bucket down.
fn fold(comptime P: type, buckets: []const P) P {
    assert(buckets.len <= bucket_count);
    var running = P.identity_element;
    var total = P.identity_element;
    var index = buckets.len;
    while (index > 0) {
        index -= 1;
        running = running.add_point(buckets[index]);
        total = total.add_point(running);
    }
    return total;
}

/// The end of the run of signers equal to `order[start]` in `order`, sorted by key encoding.
pub fn group_end(keys: []const [32]u8, order: []const u8, start: usize) usize {
    assert(start < order.len);
    var end = start + 1;
    while (end < order.len and std.mem.eql(u8, &keys[order[end]], &keys[order[start]])) end += 1;
    assert(end <= order.len);
    return end;
}

/// Sets every point's Z to 1 with one inversion (Montgomery's trick).
pub fn normalize(points: []Point) void {
    assert(points.len > 0 and points.len <= chunk_signatures);
    var prefix: [chunk_signatures]Fe = undefined;
    var product = Fe.one;
    for (points, 0..) |point, index| {
        product = product.mul(point.z);
        prefix[index] = product;
    }
    var inverse = product.invert();
    var index = points.len;
    while (index > 0) {
        index -= 1;
        const point = &points[index];
        const z_inverse = if (index == 0) inverse else inverse.mul(prefix[index - 1]);
        inverse = inverse.mul(point.z);
        const x = point.x.mul(z_inverse);
        const y = point.y.mul(z_inverse);
        point.* = .{ .x = x, .y = y, .z = Fe.one, .t = x.mul(y) };
    }
    assert(points[0].z.equivalent(Fe.one));
}

/// Sorts the chunk's signers by key encoding and adds one `A` term per distinct signer, its
/// coefficient the sum of its signatures' `z h`.
pub fn add_signers(
    terms: *Terms,
    keys: []const [32]u8,
    minus_a: []const *const Point,
    zh: []const [32]u8,
    order: []u8,
) void {
    assert(keys.len == order.len and zh.len == order.len and minus_a.len == order.len);
    const Less = struct {
        fn less(context: []const [32]u8, left: u8, right: u8) bool {
            return std.mem.order(u8, &context[left], &context[right]) == .lt;
        }
    };
    std.sort.pdq(u8, order, keys, Less.less);
    var points: [chunk_signatures]Point = undefined;
    var coefficients: [chunk_signatures][32]u8 = undefined;
    var signers: usize = 0;
    var start: usize = 0;
    while (start < order.len) : (signers += 1) {
        const end = group_end(keys, order, start);
        var coefficient = zh[order[start]];
        for (order[start + 1 .. end]) |local| coefficient = scalar.add(coefficient, zh[local]);
        // minus_a carries -A, so the coalesced coefficient is negated to add (sum z h) A.
        points[signers] = minus_a[order[start]].*;
        coefficients[signers] = scalar.neg(coefficient);
        start = end;
    }
    // Keys derived by a signing key carry Z != 1; mixed addition needs Z = 1.
    normalize(points[0..signers]);
    for (points[0..signers], coefficients[0..signers]) |point, *coefficient| {
        terms.add(point, coefficient);
    }
    assert(signers <= order.len);
}
