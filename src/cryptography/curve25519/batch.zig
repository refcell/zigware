//! Ed25519 batch verification the way commonware's curve25519 crate does it
//! (`cryptography/curve25519/src/signing/core.rs` and `signing/core/msm.rs`): SHA-512
//! counter-mode coefficients, one multi-scalar term per distinct signer, and Pippenger's bucket
//! method over signed digits.
//!
//! The batch equation is `[8](sum z_i R_i + sum (sum z_i h_i) A - (sum z_i s_i) B) == 0`, with
//! `z_i` the 128-bit coefficient of signature `i` (see `batch_coefficients`). Every coefficient
//! depends only on the seed and its signature's index, so the verdict is a function of
//! `(items, seed)` at every thread count.
//!
//! The crate sizes one MSM for the whole batch on the heap. Here a strategy batch is cut into
//! chunks of at most `chunk_signatures`, each summed by its own bucket MSM in stack memory, and
//! the chunk sums are added before the one cofactored identity check: the sum of the chunks'
//! MSMs is the batch's MSM, and nothing allocates. A chunk has at most `chunk_terms` terms, for
//! which the crate's `width_for` picks its narrowest window, `width`. Batches too small for the
//! buckets' fixed fold cost use Straus (`core.MultiScalar`), as the crate does below its cutoff.

const std = @import("std");
const assert = std.debug.assert;
const cryptography = @import("cryptography");
const parallel = @import("parallel");

const core = cryptography.ed25519.core;
const Point = core.Point;
const Fe = Point.Fe;
const scalar = Point.scalar;
const Sha512 = std.crypto.hash.sha2.Sha512;
const serial_strategy = parallel.sequential;

/// The most signatures one bucket MSM sums.
pub const chunk_signatures = 128;
/// One `R` and one `A` per signature, and the basepoint.
const chunk_terms = 2 * chunk_signatures + 1;
/// The crate's `MIN_WIDTH`, which its `width_for` picks for every batch below 2^10 terms.
pub const width = 6;
/// Signed windows covering a 256-bit scalar; the top one absorbs the final carry (`s < 2^253`).
pub const windows = (256 + width - 1) / width;
/// One bucket per nonzero digit magnitude, `1 ..= 2^(width - 1)`.
const bucket_count = 1 << (width - 1);
/// Fewer signatures than this go through Straus: the bucket fold's fixed cost (`windows`
/// passes over `bucket_count` buckets) outweighs its saving below about 88 terms (the crate's
/// portable `STRAUS_TERM_CUTOFF`).
const straus_signatures = 44;

comptime {
    assert(chunk_terms < 1 << 10);
    assert(windows * width >= 256);
    assert(straus_signatures <= chunk_signatures / 2);
    assert(chunk_signatures <= std.math.maxInt(u8) + 1);
}

/// The four 128-bit coefficients `z_{4 block} .. z_{4 block + 3}`, as canonical scalars: one
/// SHA-512 of `seed || u64_le(block)`, cut into four little-endian 16-byte values.
pub fn batch_coefficients(seed: *const [32]u8, block: u64) [4][32]u8 {
    var hasher = Sha512.init(.{});
    hasher.update(seed);
    var counter: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter, block, .little);
    hasher.update(&counter);
    var digest: [Sha512.digest_length]u8 = undefined;
    hasher.final(&digest);
    var coefficients: [4][32]u8 = @splat(@splat(0));
    for (&coefficients, 0..) |*coefficient, lane| {
        coefficient[0..16].* = digest[lane * 16 ..][0..16].*;
    }
    assert(coefficients[3][16] == 0 and coefficients[0][31] == 0);
    return coefficients;
}

/// Reads coefficients by signature index, hashing each block of four once.
const Coefficients = struct {
    seed: [32]u8,
    block: u64 = std.math.maxInt(u64),
    values: [4][32]u8 = undefined,

    fn at(coefficients: *Coefficients, index: usize) [32]u8 {
        const block: u64 = index / 4;
        assert(block != std.math.maxInt(u64));
        if (block != coefficients.block) {
            coefficients.values = batch_coefficients(&coefficients.seed, block);
            coefficients.block = block;
        }
        return coefficients.values[index % 4];
    }
};

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

/// Up to `chunk_terms` MSM terms: points prepared for mixed addition and their scalars'
/// signed digits, stored window-major so each bucket pass reads one row.
pub const Terms = struct {
    points: [chunk_terms]Cached,
    digits: [windows][chunk_terms]i8,
    count: usize,

    pub fn init() Terms {
        return .{ .points = undefined, .digits = undefined, .count = 0 };
    }

    pub fn add(terms: *Terms, point: Point, s: *const [32]u8) void {
        assert(terms.count < chunk_terms);
        terms.points[terms.count] = .init(point);
        const digits = signed_digits(s);
        for (&terms.digits, digits) |*row, digit| row[terms.count] = digit;
        terms.count += 1;
    }

    /// `sum s_i P_i` by the bucket method: per window from the top, `width` doublings, then
    /// every term added to (or subtracted from) the bucket of its digit's magnitude, and the
    /// buckets folded with two running sums into `sum j bucket_j`.
    pub fn sum(terms: *const Terms) Point {
        assert(terms.count <= chunk_terms);
        var result = Point.identityElement;
        var buckets: [bucket_count]Point = undefined;
        var window: usize = windows;
        while (window > 0) {
            window -= 1;
            for (0..width) |_| result = result.dbl();
            @memset(&buckets, Point.identityElement);
            var used: usize = 0;
            const row = terms.digits[window][0..terms.count];
            for (row, terms.points[0..terms.count]) |digit, *point| {
                if (digit == 0) continue;
                const magnitude = @abs(digit);
                buckets[magnitude - 1] = add_mixed(buckets[magnitude - 1], point, digit < 0);
                used = @max(used, magnitude);
            }
            result = result.add(fold(buckets[0..used]));
        }
        return result;
    }
};

/// `sum (j + 1) buckets[j]`, from the top bucket down.
fn fold(buckets: []const Point) Point {
    assert(buckets.len <= bucket_count);
    var running = Point.identityElement;
    var total = Point.identityElement;
    var index = buckets.len;
    while (index > 0) {
        index -= 1;
        running = running.add(buckets[index]);
        total = total.add(running);
    }
    return total;
}

/// One signature's share of the equation: its decoded `R`, `z`, `z h`, and `z s`.
const Share = struct {
    r: Point,
    z: [32]u8,
    zh: [32]u8,
    zs: [32]u8,
};

/// Checks `s` is canonical and `R` decodes, then computes the signature's scalars.
fn share_of(item: core.BatchItem, z: [32]u8) ?Share {
    const s = item.signature[32..64].*;
    scalar.rejectNonCanonical(s) catch return null;
    const r = core.decompress(item.signature[0..32].*) orelse return null;
    const h = core.challenge(item.signature[0..32], &item.key.bytes, item.namespace, item.message);
    const share: Share = .{ .r = r, .z = z, .zh = scalar.mul(z, h), .zs = scalar.mul(z, s) };
    assert(share.z[16] == 0);
    return share;
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
fn add_signers(
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

/// The bucket MSM of one chunk of at most `chunk_signatures` items from `range.start`, without
/// the basepoint: `z R` per signature and `(sum z h) A` per distinct signer. Adds the chunk's
/// `sum z s` to `zs_sum`. Null when an `s` is non-canonical or an `R` does not decode.
fn chunk_sum(
    items: anytype,
    range: parallel.Range,
    coefficients: *Coefficients,
    zs_sum: *[32]u8,
) ?Point {
    const count = range.end - range.start;
    assert(count > 0 and count <= chunk_signatures);
    var terms: Terms = .init();
    var keys: [chunk_signatures][32]u8 = undefined;
    var minus_a: [chunk_signatures]*const Point = undefined;
    var zh: [chunk_signatures][32]u8 = undefined;
    var order: [chunk_signatures]u8 = undefined;
    for (0..count) |local| {
        const item: core.BatchItem = items.item(range.start + local);
        const share = share_of(item, coefficients.at(range.start + local)) orelse return null;
        terms.add(share.r, &share.z);
        zs_sum.* = scalar.add(zs_sum.*, share.zs);
        keys[local] = item.key.bytes;
        minus_a[local] = &item.key.minus_a;
        zh[local] = share.zh;
        order[local] = @intCast(local);
    }
    add_signers(&terms, keys[0..count], minus_a[0..count], zh[0..count], order[0..count]);
    assert(terms.count <= 2 * count);
    return terms.sum();
}

/// The equation's sum over `range`, basepoint term included, before the cofactor; null on a
/// structurally invalid signature. Ranges of `straus_signatures` or more are cut into chunks
/// whose lengths differ by at most one.
fn range_sum(items: anytype, range: parallel.Range, seed: [32]u8) ?Point {
    assert(range.start < range.end);
    var coefficients: Coefficients = .{ .seed = seed };
    var zs_sum = scalar.zero;
    const count = range.end - range.start;
    var total = Point.identityElement;
    if (count < straus_signatures) {
        var sum = core.MultiScalar.init();
        for (range.start..range.end) |index| {
            const item: core.BatchItem = items.item(index);
            const share = share_of(item, coefficients.at(index)) orelse return null;
            zs_sum = scalar.add(zs_sum, share.zs);
            sum.add(share.r, share.z);
            sum.add(item.key.minus_a, scalar.neg(share.zh));
        }
        sum.add(Point.basePoint, scalar.neg(zs_sum));
        return sum.finish();
    }
    const chunks = std.math.divCeil(usize, count, chunk_signatures) catch unreachable;
    for (0..chunks) |chunk| {
        const local = parallel.ops.balanced(count, chunks, chunk);
        const slice: parallel.Range = .init(range.start + local.start, range.start + local.end);
        total = total.add(chunk_sum(items, slice, &coefficients, &zs_sum) orelse return null);
    }
    // The basepoint term `-(sum z s) B`, once per range, from std's precomputed basepoint
    // table. Its only error is a product that is the identity, which it then is.
    const base = Point.basePoint.mulPublic(scalar.neg(zs_sum)) catch Point.identityElement;
    return total.add(base);
}

/// Verifies `count` signatures at once under a fresh 32-byte seed from `rng` (commonware
/// `verify_batch_inner`). `strategy` splits the items into batches, whose sums add into one
/// equation. `items` has `item(index) core.BatchItem`. An empty batch is rejected.
///
/// As in commonware, an outer `try_run` picks between the whole pipeline on the calling thread
/// and on `strategy`. A structurally invalid batch (a non-canonical `s` or an undecodable `R`)
/// stops before the batch equation and fails that `try_run`, so only batches that reach the
/// equation give an adaptive strategy a complete-work sample.
pub fn verify_batch(rng: anytype, count: usize, items: anytype, strategy: anytype) bool {
    const resolved = cryptography.hasher.resolve_strategy(strategy);
    if (count == 0) return false;
    var seed: [32]u8 = undefined;
    rng.fill_bytes(&seed);
    const Batch = struct {
        items: @TypeOf(items),
        seed: [32]u8,
        count: usize,

        pub fn run(batch: @This(), batches: anytype) error{Structural}!bool {
            var sums: [parallel.max_chunks]?Point = undefined;
            const shards = sums[0..batches.count()];
            if (batches.is_whole()) {
                shards[0] = batch.map(0, .init(0, batch.count));
            } else {
                batches.map_collect(shards, batch);
            }
            var total = Point.identityElement;
            for (shards) |shard| total = total.add(shard orelse return error.Structural);
            return core.is_identity(total.clearCofactor());
        }

        pub fn map(batch: @This(), _: usize, range: parallel.Range) ?Point {
            return range_sum(batch.items, range, batch.seed);
        }
    };
    const Pipeline = struct {
        batch: Batch,
        strategy: @TypeOf(resolved),

        pub fn serial(pipeline: @This()) error{Structural}!bool {
            const b = pipeline.batch;
            return serial_strategy.try_run_batches(b.count, 1, 1, b);
        }

        pub fn parallel(pipeline: @This()) error{Structural}!bool {
            const b = pipeline.batch;
            return pipeline.strategy.try_run_batches(b.count, 1, 1, b);
        }
    };
    const batch: Batch = .{ .items = items, .seed = seed, .count = count };
    const pipeline: Pipeline = .{ .batch = batch, .strategy = resolved };
    return resolved.try_run(count, pipeline) catch |err| switch (err) {
        error.Structural => false,
    };
}
