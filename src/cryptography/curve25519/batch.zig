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
const scalar = Point.scalar;
const Sha512 = std.crypto.hash.sha2.Sha512;
const serial_strategy = parallel.sequential;
const msm = cryptography.ed25519.msm;

pub const chunk_signatures = msm.chunk_signatures;
pub const width = msm.width;
pub const windows = msm.windows;
pub const Terms = msm.Terms;
pub const signed_digits = msm.signed_digits;
pub const group_end = msm.group_end;
pub const normalize = msm.normalize;
const straus_signatures = msm.straus_signatures;
const add_signers = msm.add_signers;

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
