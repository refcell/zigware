//! The bucket MSM's backends on the same inputs: each packed-point operation against std's
//! Edwards25519 arithmetic, and each backend's `TermsWith(...).sum` against `MultiScalar`
//! (Straus, an independent implementation). Points have mixed order (a torsion component), as
//! ZIP-215's lenient decoding allows. Every backend runs whether or not the target has its
//! instructions: the packed ones are portable vector code.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const core = @import("core.zig");
const msm = @import("msm.zig");

const Point = core.Point;
const scalar = Point.scalar;

/// An order-8 point (a ZIP-215 small-order vector).
const torsion_hex = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05";

fn random_scalar(rng: *utils.rng.TestRng) [32]u8 {
    var bytes: [32]u8 = undefined;
    rng.fill_bytes(&bytes);
    return scalar.reduce(bytes);
}

/// `[s] B + [k] T` for random `s` and `k < 8`, with Z = 1.
fn random_point(rng: *utils.rng.TestRng) Point {
    var torsion_bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&torsion_bytes, torsion_hex) catch unreachable; // A fixed valid hex.
    const torsion = core.decompress(torsion_bytes).?;
    const s = random_scalar(rng);
    var point = Point.basePoint.mulPublic(s) catch Point.identityElement;
    for (0..rng.next_u32() % 8) |_| point = point.add(torsion);
    var points = [1]Point{point};
    msm.normalize(&points);
    return points[0];
}

fn expect_same(expected: Point, actual: Point) !void {
    try testing.expect(core.is_identity(expected.sub(actual)));
}

test "packed point operations match std on every backend" {
    inline for (msm.backends) |B| {
        var rng = utils.rng.test_rng();
        for (0..48) |round| {
            const p = if (round == 0) Point.identityElement else random_point(&rng);
            const q = random_point(&rng);
            const packed_p = B.PackedPoint.from_point(p);
            const cached_q = B.PackedCached.from_point(q);
            try expect_same(p, packed_p.to_point());
            try expect_same(p.add(q), packed_p.add_cached(&cached_q, false).to_point());
            try expect_same(p.sub(q), packed_p.add_cached(&cached_q, true).to_point());
            try expect_same(p.dbl(), packed_p.dbl().to_point());
            const packed_q = B.PackedPoint.from_point(q);
            try expect_same(p.add(q), packed_p.add_point(packed_q).to_point());
            try expect_same(q, B.PackedPoint.identity_element.add_cached(&cached_q, false)
                .to_point());
            // A chain, so each operation's output feeds the next as the MSM's do.
            var chain = packed_p;
            var expected = p;
            for (0..6) |_| {
                chain = chain.dbl().add_cached(&cached_q, true).add_point(packed_q);
                expected = expected.dbl().sub(q).add(q);
            }
            try expect_same(expected, chain.to_point());
        }
    }
}

test "bucket MSM agrees with MultiScalar on every backend" {
    const sizes = [_]usize{ 1, 2, 45, msm.chunk_terms };
    var one: [32]u8 = @splat(0);
    one[0] = 1;
    var rng = utils.rng.test_rng();
    var points: [msm.chunk_terms]Point = undefined;
    var scalars: [msm.chunk_terms][32]u8 = undefined;
    for (&points, &scalars, 0..) |*point, *s, index| {
        point.* = random_point(&rng);
        s.* = switch (index % 7) {
            0 => scalar.neg(one), // l - 1, the largest canonical scalar.
            1 => scalar.zero,
            2 => one,
            else => random_scalar(&rng),
        };
    }
    for (sizes) |size| {
        var straus = core.MultiScalar.init();
        for (points[0..size], scalars[0..size]) |point, s| straus.add(point, s);
        const expected = straus.finish();
        inline for (msm.backends) |B| {
            var terms: msm.TermsWith(B) = .init();
            for (points[0..size], scalars[0..size]) |point, *s| terms.add(point, s);
            try expect_same(expected, terms.sum());
        }
    }
}
