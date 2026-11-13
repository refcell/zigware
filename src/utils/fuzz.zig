//! Fuzz driver for utils tests (commonware `utils/fuzz`).
//!
//! A fuzz body takes a `*FuzzRng` and draws its operations from it with the samplers in
//! `rng.zig`. `run` first feeds the body `iterations * fuzz_soak` seeded random inputs inside
//! the normal `zig build test` (the seed mixes in `build_options.fuzz_seed`), then hands it to
//! `std.testing.fuzz`, where the coverage-guided fuzzer supplies the input bytes. `FuzzRng`
//! maps nearby input bytes to nearby draws, so fuzzer mutations stay local.

const std = @import("std");
const build_options = @import("build_options");
const rng = @import("rng.zig");
const assert = std.debug.assert;

/// Largest input handed to one iteration.
pub const input_size_max = 1024;

pub fn run(
    context: anytype,
    comptime body: fn (@TypeOf(context), *rng.FuzzRng) anyerror!void,
    seed: u64,
    iterations: u32,
) !void {
    assert(iterations > 0);
    const total: u64 = @as(u64, iterations) * build_options.fuzz_soak;
    var seed_rng = rng.TestRng.init(seed ^ build_options.fuzz_seed);
    var input: [input_size_max]u8 = undefined;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        // Bias toward short inputs, which repeat their bytes and stress the edge cases.
        const len_max: usize = if (rng.boolean(&seed_rng)) 32 else input.len;
        const len = rng.range_at_most(&seed_rng, usize, 0, len_max);
        seed_rng.fill_bytes(input[0..len]);
        var generator = rng.FuzzRng.init(input[0..len]);
        body(context, &generator) catch |err| {
            std.debug.print("fuzz: seed {d} iteration {d} failed: {t}\n", .{
                seed ^ build_options.fuzz_seed, iteration, err,
            });
            return err;
        };
    }
    assert(iteration == total);
    try std.testing.fuzz(context, struct {
        fn one(ctx: @TypeOf(context), smith: *std.testing.Smith) anyerror!void {
            var buffer: [input_size_max]u8 = undefined;
            const len = smith.slice(&buffer);
            var generator = rng.FuzzRng.init(buffer[0..len]);
            try body(ctx, &generator);
        }
    }.one, .{});
}
