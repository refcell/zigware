//! Deterministic seeded fuzzing for p2p tests, and p2p's decoder fuzz targets.
//!
//! A fuzz body takes a `*std.testing.Smith`, so the same body runs under coverage-guided
//! fuzzing (`zig build test --fuzz`) and here, where `zig build test` feeds it seeded random
//! inputs. Iterations scale with `build_options.fuzz_soak`; `build_options.fuzz_seed` is mixed
//! into every seed. (Same driver as codec's; switch to `invariants.minifuzz` once it lands.)
//! Bodies draw values with `codec.fuzz.Draws`, since Smith's typed draws, `eos`, and `slice`
//! are nearly inert on seeded random input.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const codec = @import("codec");
const Smith = std.testing.Smith;
const types = @import("types.zig");

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

/// Any successful decode re-encodes to exactly the input.
fn expect_canonical(comptime T: type, input: []const u8) !void {
    const value = codec.decode(T, std.testing.allocator, input) catch return;
    var buffer: [types.Address.max_encode_size]u8 = undefined;
    const encoded = codec.encode_to(T, value, &buffer);
    try std.testing.expectEqualSlices(u8, input, encoded);
    try std.testing.expect(encoded.len <= T.max_encode_size);
}

fn decode_canonical(_: void, smith: *Smith) anyerror!void {
    var data: [512]u8 = undefined;
    const input = codec.fuzz.Draws.init(smith).slice(&data);
    try expect_canonical(types.Ingress, input);
    try expect_canonical(types.Address, input);
}

test "fuzz p2p types decode canonical" {
    try run({}, decode_canonical, 0x7032707479706573, 4000);
}

test {
    _ = @import("fuzz/simulated.zig");
    _ = @import("fuzz/authenticated.zig");
    _ = @import("authenticated/wire_fuzz_test.zig");
}
