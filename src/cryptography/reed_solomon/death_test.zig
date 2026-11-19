//! commonware `reed_solomon/engine.rs` and `engine/shards.rs` `#[should_panic]` and
//! `catch_unwind` tests, as death tests (`utils.death.expect_panic`). commonware's
//! `invalid_transform` checks every engine in both directions; each engine, direction, and
//! case is one test here, since a death test checks one panic.

const std = @import("std");
const death = @import("utils").death;
const engine = @import("engine.zig");

const GF_ORDER = engine.GF_ORDER;
const ShardsRefMut = engine.ShardsRefMut;
const max = std.math.maxInt(usize);
const unreachable_code = "reached unreachable code";

/// A transform of `shard_count` empty shards with invalid arguments.
const Transform = struct { usize, usize, usize, usize, usize };

/// Expects the calling test (`src`) to panic on `E`'s `fft` (or `ifft`) of `t`.
fn dies(
    comptime src: std.builtin.SourceLocation,
    comptime E: type,
    comptime inverse: bool,
    comptime t: Transform,
) !void {
    try death.expect_panic(src, unreachable_code, transform(E, inverse, t));
}

fn transform(comptime E: type, comptime inverse: bool, comptime t: Transform) fn () anyerror!void {
    return struct {
        fn body() !void {
            const eng: E = .init();
            const shards: ShardsRefMut = .init(t[0], 0, &.{});
            if (inverse) eng.ifft(shards, t[1], t[2], t[3], t[4]) else {
                eng.fft(shards, t[1], t[2], t[3], t[4]);
            }
        }
    }.body;
}

// commonware `transform_zero_size`.
test "reed solomon naive fft rejects zero size" {
    try dies(@src(), engine.Naive, false, .{ 4, 0, 0, 0, 0 });
}
test "reed solomon naive ifft rejects zero size" {
    try dies(@src(), engine.Naive, true, .{ 4, 0, 0, 0, 0 });
}
test "reed solomon scalar fft rejects zero size" {
    try dies(@src(), engine.Scalar, false, .{ 4, 0, 0, 0, 0 });
}
test "reed solomon scalar ifft rejects zero size" {
    try dies(@src(), engine.Scalar, true, .{ 4, 0, 0, 0, 0 });
}
test "reed solomon simd fft rejects zero size" {
    try dies(@src(), engine.Simd, false, .{ 4, 0, 0, 0, 0 });
}
test "reed solomon avx512 fft rejects zero size" {
    try dies(@src(), engine.Avx512, false, .{ 4, 0, 0, 0, 0 });
}
test "reed solomon simd ifft rejects zero size" {
    try dies(@src(), engine.Simd, true, .{ 4, 0, 0, 0, 0 });
}
test "reed solomon avx512 ifft rejects zero size" {
    try dies(@src(), engine.Avx512, true, .{ 4, 0, 0, 0, 0 });
}

// commonware `transform_non_power_of_two_size`.
test "reed solomon naive fft rejects non power of two size" {
    try dies(@src(), engine.Naive, false, .{ 4, 0, 3, 0, 0 });
}
test "reed solomon naive ifft rejects non power of two size" {
    try dies(@src(), engine.Naive, true, .{ 4, 0, 3, 0, 0 });
}
test "reed solomon scalar fft rejects non power of two size" {
    try dies(@src(), engine.Scalar, false, .{ 4, 0, 3, 0, 0 });
}
test "reed solomon scalar ifft rejects non power of two size" {
    try dies(@src(), engine.Scalar, true, .{ 4, 0, 3, 0, 0 });
}
test "reed solomon simd fft rejects non power of two size" {
    try dies(@src(), engine.Simd, false, .{ 4, 0, 3, 0, 0 });
}
test "reed solomon avx512 fft rejects non power of two size" {
    try dies(@src(), engine.Avx512, false, .{ 4, 0, 3, 0, 0 });
}
test "reed solomon simd ifft rejects non power of two size" {
    try dies(@src(), engine.Simd, true, .{ 4, 0, 3, 0, 0 });
}
test "reed solomon avx512 ifft rejects non power of two size" {
    try dies(@src(), engine.Avx512, true, .{ 4, 0, 3, 0, 0 });
}

// commonware `transform_size_exceeds_field`.
test "reed solomon naive fft rejects size beyond the field" {
    try dies(@src(), engine.Naive, false, .{ 2 * GF_ORDER, 0, 2 * GF_ORDER, 0, 0 });
}
test "reed solomon naive ifft rejects size beyond the field" {
    try dies(@src(), engine.Naive, true, .{ 2 * GF_ORDER, 0, 2 * GF_ORDER, 0, 0 });
}
test "reed solomon scalar fft rejects size beyond the field" {
    try dies(@src(), engine.Scalar, false, .{ 2 * GF_ORDER, 0, 2 * GF_ORDER, 0, 0 });
}
test "reed solomon scalar ifft rejects size beyond the field" {
    try dies(@src(), engine.Scalar, true, .{ 2 * GF_ORDER, 0, 2 * GF_ORDER, 0, 0 });
}
test "reed solomon simd fft rejects size beyond the field" {
    try dies(@src(), engine.Simd, false, .{ 2 * GF_ORDER, 0, 2 * GF_ORDER, 0, 0 });
}
test "reed solomon avx512 fft rejects size beyond the field" {
    try dies(@src(), engine.Avx512, false, .{ 2 * GF_ORDER, 0, 2 * GF_ORDER, 0, 0 });
}
test "reed solomon simd ifft rejects size beyond the field" {
    try dies(@src(), engine.Simd, true, .{ 2 * GF_ORDER, 0, 2 * GF_ORDER, 0, 0 });
}
test "reed solomon avx512 ifft rejects size beyond the field" {
    try dies(@src(), engine.Avx512, true, .{ 2 * GF_ORDER, 0, 2 * GF_ORDER, 0, 0 });
}

// commonware `transform_range_out_of_bounds`.
test "reed solomon naive fft rejects range out of bounds at 3" {
    try dies(@src(), engine.Naive, false, .{ 4, 3, 2, 0, 0 });
}
test "reed solomon naive fft rejects range out of bounds at 4" {
    try dies(@src(), engine.Naive, false, .{ 4, 4, 2, 0, 0 });
}
test "reed solomon naive fft rejects range out of bounds at max" {
    try dies(@src(), engine.Naive, false, .{ 4, max, 2, 0, 0 });
}
test "reed solomon naive ifft rejects range out of bounds at 3" {
    try dies(@src(), engine.Naive, true, .{ 4, 3, 2, 0, 0 });
}
test "reed solomon naive ifft rejects range out of bounds at 4" {
    try dies(@src(), engine.Naive, true, .{ 4, 4, 2, 0, 0 });
}
test "reed solomon naive ifft rejects range out of bounds at max" {
    try dies(@src(), engine.Naive, true, .{ 4, max, 2, 0, 0 });
}
test "reed solomon scalar fft rejects range out of bounds at 3" {
    try dies(@src(), engine.Scalar, false, .{ 4, 3, 2, 0, 0 });
}
test "reed solomon scalar fft rejects range out of bounds at 4" {
    try dies(@src(), engine.Scalar, false, .{ 4, 4, 2, 0, 0 });
}
test "reed solomon scalar fft rejects range out of bounds at max" {
    try dies(@src(), engine.Scalar, false, .{ 4, max, 2, 0, 0 });
}
test "reed solomon scalar ifft rejects range out of bounds at 3" {
    try dies(@src(), engine.Scalar, true, .{ 4, 3, 2, 0, 0 });
}
test "reed solomon scalar ifft rejects range out of bounds at 4" {
    try dies(@src(), engine.Scalar, true, .{ 4, 4, 2, 0, 0 });
}
test "reed solomon scalar ifft rejects range out of bounds at max" {
    try dies(@src(), engine.Scalar, true, .{ 4, max, 2, 0, 0 });
}
test "reed solomon simd fft rejects range out of bounds at 3" {
    try dies(@src(), engine.Simd, false, .{ 4, 3, 2, 0, 0 });
}
test "reed solomon avx512 fft rejects range out of bounds at 3" {
    try dies(@src(), engine.Avx512, false, .{ 4, 3, 2, 0, 0 });
}
test "reed solomon simd fft rejects range out of bounds at 4" {
    try dies(@src(), engine.Simd, false, .{ 4, 4, 2, 0, 0 });
}
test "reed solomon avx512 fft rejects range out of bounds at 4" {
    try dies(@src(), engine.Avx512, false, .{ 4, 4, 2, 0, 0 });
}
test "reed solomon simd fft rejects range out of bounds at max" {
    try dies(@src(), engine.Simd, false, .{ 4, max, 2, 0, 0 });
}
test "reed solomon avx512 fft rejects range out of bounds at max" {
    try dies(@src(), engine.Avx512, false, .{ 4, max, 2, 0, 0 });
}
test "reed solomon simd ifft rejects range out of bounds at 3" {
    try dies(@src(), engine.Simd, true, .{ 4, 3, 2, 0, 0 });
}
test "reed solomon avx512 ifft rejects range out of bounds at 3" {
    try dies(@src(), engine.Avx512, true, .{ 4, 3, 2, 0, 0 });
}
test "reed solomon simd ifft rejects range out of bounds at 4" {
    try dies(@src(), engine.Simd, true, .{ 4, 4, 2, 0, 0 });
}
test "reed solomon avx512 ifft rejects range out of bounds at 4" {
    try dies(@src(), engine.Avx512, true, .{ 4, 4, 2, 0, 0 });
}
test "reed solomon simd ifft rejects range out of bounds at max" {
    try dies(@src(), engine.Simd, true, .{ 4, max, 2, 0, 0 });
}
test "reed solomon avx512 ifft rejects range out of bounds at max" {
    try dies(@src(), engine.Avx512, true, .{ 4, max, 2, 0, 0 });
}

// commonware `transform_truncation_out_of_bounds`.
test "reed solomon naive fft rejects truncation out of bounds" {
    try dies(@src(), engine.Naive, false, .{ 4, 0, 2, 3, 0 });
}
test "reed solomon naive ifft rejects truncation out of bounds" {
    try dies(@src(), engine.Naive, true, .{ 4, 0, 2, 3, 0 });
}
test "reed solomon scalar fft rejects truncation out of bounds" {
    try dies(@src(), engine.Scalar, false, .{ 4, 0, 2, 3, 0 });
}
test "reed solomon scalar ifft rejects truncation out of bounds" {
    try dies(@src(), engine.Scalar, true, .{ 4, 0, 2, 3, 0 });
}
test "reed solomon simd fft rejects truncation out of bounds" {
    try dies(@src(), engine.Simd, false, .{ 4, 0, 2, 3, 0 });
}
test "reed solomon avx512 fft rejects truncation out of bounds" {
    try dies(@src(), engine.Avx512, false, .{ 4, 0, 2, 3, 0 });
}
test "reed solomon simd ifft rejects truncation out of bounds" {
    try dies(@src(), engine.Simd, true, .{ 4, 0, 2, 3, 0 });
}
test "reed solomon avx512 ifft rejects truncation out of bounds" {
    try dies(@src(), engine.Avx512, true, .{ 4, 0, 2, 3, 0 });
}

// commonware `transform_skew_out_of_bounds`.
test "reed solomon naive fft rejects skew out of bounds by order - 1" {
    try dies(@src(), engine.Naive, false, .{ 4, 0, 2, 0, GF_ORDER - 1 });
}
test "reed solomon naive fft rejects skew out of bounds by max" {
    try dies(@src(), engine.Naive, false, .{ 4, 0, 2, 0, max });
}
test "reed solomon naive ifft rejects skew out of bounds by order - 1" {
    try dies(@src(), engine.Naive, true, .{ 4, 0, 2, 0, GF_ORDER - 1 });
}
test "reed solomon naive ifft rejects skew out of bounds by max" {
    try dies(@src(), engine.Naive, true, .{ 4, 0, 2, 0, max });
}
test "reed solomon scalar fft rejects skew out of bounds by order - 1" {
    try dies(@src(), engine.Scalar, false, .{ 4, 0, 2, 0, GF_ORDER - 1 });
}
test "reed solomon scalar fft rejects skew out of bounds by max" {
    try dies(@src(), engine.Scalar, false, .{ 4, 0, 2, 0, max });
}
test "reed solomon scalar ifft rejects skew out of bounds by order - 1" {
    try dies(@src(), engine.Scalar, true, .{ 4, 0, 2, 0, GF_ORDER - 1 });
}
test "reed solomon scalar ifft rejects skew out of bounds by max" {
    try dies(@src(), engine.Scalar, true, .{ 4, 0, 2, 0, max });
}
test "reed solomon simd fft rejects skew out of bounds by order - 1" {
    try dies(@src(), engine.Simd, false, .{ 4, 0, 2, 0, GF_ORDER - 1 });
}
test "reed solomon avx512 fft rejects skew out of bounds by order - 1" {
    try dies(@src(), engine.Avx512, false, .{ 4, 0, 2, 0, GF_ORDER - 1 });
}
test "reed solomon simd fft rejects skew out of bounds by max" {
    try dies(@src(), engine.Simd, false, .{ 4, 0, 2, 0, max });
}
test "reed solomon avx512 fft rejects skew out of bounds by max" {
    try dies(@src(), engine.Avx512, false, .{ 4, 0, 2, 0, max });
}
test "reed solomon simd ifft rejects skew out of bounds by order - 1" {
    try dies(@src(), engine.Simd, true, .{ 4, 0, 2, 0, GF_ORDER - 1 });
}
test "reed solomon avx512 ifft rejects skew out of bounds by order - 1" {
    try dies(@src(), engine.Avx512, true, .{ 4, 0, 2, 0, GF_ORDER - 1 });
}
test "reed solomon simd ifft rejects skew out of bounds by max" {
    try dies(@src(), engine.Simd, true, .{ 4, 0, 2, 0, max });
}
test "reed solomon avx512 ifft rejects skew out of bounds by max" {
    try dies(@src(), engine.Avx512, true, .{ 4, 0, 2, 0, max });
}

// commonware `engine.rs` `eval_poly_truncation_out_of_bounds`.
test "reed solomon eval poly rejects truncation beyond the field" {
    try death.expect_panic(@src(), unreachable_code, struct {
        fn body() !void {
            const erasures = try std.testing.allocator.create([GF_ORDER]engine.GfElement);
            defer std.testing.allocator.destroy(erasures);
            erasures.* = @splat(0);
            engine.utils.eval_poly(erasures, GF_ORDER + 1);
        }
    }.body);
}

/// Runs `call` on a view of `shard_count` empty shards.
fn on_empty(
    comptime shard_count: usize,
    comptime call: fn (ShardsRefMut) void,
) fn () anyerror!void {
    return struct {
        fn body() !void {
            call(.init(shard_count, 0, &.{}));
        }
    }.body;
}

// commonware `shards.rs` `dimensions_overflow`.
test "reed solomon shards reject overflowing dimensions" {
    try death.expect_panic(@src(), "shard dimensions overflow", struct {
        fn body() !void {
            std.mem.doNotOptimizeAway(ShardsRefMut.init(max / 2 + 1, 2, &.{}));
        }
    }.body);
}

// commonware `shards.rs` `empty_shard_index_out_of_bounds`.
test "reed solomon shards reject an index out of bounds" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            std.mem.doNotOptimizeAway(view.get(2));
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_mutable_index_out_of_bounds`.
test "reed solomon shards reject a mutable index out of bounds" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            view.get(2)[0..0].* = .{};
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_split_out_of_bounds`.
test "reed solomon shards reject a split out of bounds" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            std.mem.doNotOptimizeAway(view.split_at(3));
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_range_out_of_bounds`.
test "reed solomon shards reject a range out of bounds" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            view.zero(0, 3);
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_range_reversed`.
test "reed solomon shards reject a reversed range" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            view.zero(2, 1);
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_range_start_overflow`.
test "reed solomon shards reject a range starting past the end" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            view.zero(max, max);
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_range_end_overflow`.
test "reed solomon shards reject a range ending past the end" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            view.zero(0, max);
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_xor_out_of_bounds`.
test "reed solomon shards reject an xor out of bounds" {
    try death.expect_panic(@src(), unreachable_code, on_empty(4, struct {
        fn call(view: ShardsRefMut) void {
            engine.utils.xor_within(view, 0, 3, 2);
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_xor_overlapping`.
test "reed solomon shards reject an overlapping xor" {
    try death.expect_panic(@src(), unreachable_code, on_empty(4, struct {
        fn call(view: ShardsRefMut) void {
            engine.utils.xor_within(view, 0, 1, 2);
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_dist2_zero`.
test "reed solomon shards reject dist2 at distance zero" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            std.mem.doNotOptimizeAway(view.dist2(0, 0));
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_dist4_zero`.
test "reed solomon shards reject dist4 at distance zero" {
    try death.expect_panic(@src(), unreachable_code, on_empty(4, struct {
        fn call(view: ShardsRefMut) void {
            std.mem.doNotOptimizeAway(view.dist4(0, 0));
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_dist2_out_of_bounds`.
test "reed solomon shards reject dist2 out of bounds" {
    try death.expect_panic(@src(), unreachable_code, on_empty(2, struct {
        fn call(view: ShardsRefMut) void {
            std.mem.doNotOptimizeAway(view.dist2(1, 1));
        }
    }.call));
}

// commonware `shards.rs` `empty_shard_dist4_out_of_bounds`.
test "reed solomon shards reject dist4 out of bounds" {
    try death.expect_panic(@src(), unreachable_code, on_empty(4, struct {
        fn call(view: ShardsRefMut) void {
            std.mem.doNotOptimizeAway(view.dist4(1, 1));
        }
    }.call));
}
