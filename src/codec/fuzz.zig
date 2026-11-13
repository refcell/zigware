//! Deterministic seeded fuzzing for codec tests.
//!
//! A fuzz test body takes a `*std.testing.Smith`, so the same body runs under coverage-guided
//! fuzzing (`std.testing.fuzz`, `zig build test --fuzz`) and here, where `zig build test`
//! feeds it pseudo-random inputs from a fixed seed. Iterations scale with
//! `build_options.fuzz_soak`; `build_options.fuzz_seed` is mixed into every seed.
//! (codec sits below `invariants` in the package graph, so it carries this small driver
//! itself; other packages use `invariants.minifuzz`.)

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const Smith = std.testing.Smith;

/// Largest input handed to one iteration.
pub const input_size_max = 4096;

/// Runs `body` on `iterations * fuzz_soak` seeded random inputs, then under
/// `std.testing.fuzz` for coverage-guided runs.
pub fn run(
    context: anytype,
    comptime body: fn (@TypeOf(context), *Smith) anyerror!void,
    seed: u64,
    iterations: u32,
) !void {
    assert(iterations > 0);
    var prng = std.Random.DefaultPrng.init(seed ^ build_options.fuzz_seed);
    const random = prng.random();
    var input: [input_size_max]u8 = undefined;
    const total: u64 = @as(u64, iterations) * build_options.fuzz_soak;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        // Bias toward short inputs, where most decoder edge cases live.
        const len_max: usize = if (random.boolean()) 64 else input.len;
        const len = random.uintAtMost(usize, len_max);
        random.bytes(input[0..len]);
        var smith: Smith = .{ .in = input[0..len] };
        body(context, &smith) catch |err| {
            std.debug.print("fuzz: seed {d} iteration {d} failed: {t}\n", .{
                seed ^ build_options.fuzz_seed, iteration, err,
            });
            return err;
        };
    }
    assert(iteration == total);
    try std.testing.fuzz(context, body, .{});
}
