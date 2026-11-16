//! The crate's minifuzz tests (`test::fuzz` and the curve plan), a check of the reference
//! against the crate's vectors, and a coverage-guided target over every plan
//! (`fuzz/fuzz_targets/curve25519.rs`).

const std = @import("std");
const build_options = @import("build_options");
const minifuzz = @import("invariants").minifuzz;
const fuzz = @import("fuzz.zig");
const reference = @import("reference.zig");
const vectors = @import("vectors.zig");
const testing = std.testing;
const Unstructured = minifuzz.Unstructured;

const context: fuzz.Context = .{ .gpa = testing.allocator, .io = testing.io };

/// Runs `plan` over `cases` inputs (times `-Dfuzz-soak`) from commonware's seed 0.
fn minifuzz_plan(comptime plan: fuzz.Plan, cases: u64) !void {
    const Body = struct {
        fn run(ctx: fuzz.Context, u: *Unstructured) anyerror!void {
            try plan.run(ctx, u);
        }
    };
    try (minifuzz.Builder{}).with_seed(0).with_search_limit(cases * build_options.fuzz_soak)
        .run(testing.allocator, context, Body.run);
}

test "curve25519 fuzz: batch matches individual" {
    try minifuzz_plan(.batch_matches_individual, 32);
}

test "curve25519 fuzz: signing matches reference" {
    try minifuzz_plan(.signing_matches_reference, 100);
}

test "curve25519 fuzz: verification matches reference" {
    try minifuzz_plan(.verification_matches_reference, 100);
}

test "curve25519 fuzz: key exchange matches reference" {
    try minifuzz_plan(.key_exchange_matches_reference, 100);
}

test "curve25519 fuzz: curve matches reference" {
    try minifuzz_plan(.curve, 100);
}

fn bytes(comptime N: usize, hex: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Fixture hex is valid.
    return out;
}

test "curve25519 fuzz: the reference agrees with the crate's vectors" {
    var buffer: [1024]u8 = undefined;
    for (vectors.rfc8032_ed25519) |vector| {
        const seed = bytes(32, vector.secret_key);
        const message = try std.fmt.hexToBytes(&buffer, vector.message);
        const signature = bytes(64, vector.signature);
        const public_key = bytes(32, vector.public_key);
        try testing.expectEqualSlices(u8, &public_key, &reference.public_key(seed));
        try testing.expectEqualSlices(u8, &signature, &reference.sign(seed, message));
        try testing.expect(reference.verify(public_key, signature, message));
    }
    var signature_buffer: [128]u8 = undefined;
    for (vectors.wycheproof_ed25519) |vector| {
        const message = try std.fmt.hexToBytes(&buffer, vector.message);
        const raw = try std.fmt.hexToBytes(&signature_buffer, vector.signature);
        const key = bytes(32, vector.public_key);
        const valid = raw.len == 64 and reference.verify(key, raw[0..64].*, message);
        try testing.expectEqual(vector.valid_zip215, valid);
    }
    // Every ZIP-215 pair verifies with s = 0, for any message.
    for (vectors.zip215_points) |a_hex| {
        for (vectors.zip215_points) |r_hex| {
            const signature = bytes(32, r_hex) ++ @as([32]u8, @splat(0));
            try testing.expect(reference.verify(bytes(32, a_hex), signature, "Zcash"));
        }
    }
    for (vectors.wycheproof_x25519) |vector| {
        const scalar = bytes(32, vector.private_key);
        const shared = reference.x25519(scalar, bytes(32, vector.public_key));
        const expected: [32]u8 = if (vector.shared_secret) |hex| bytes(32, hex) else @splat(0);
        try testing.expectEqualSlices(u8, &expected, &shared);
    }
}

test "curve25519 fuzz: every plan (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var input: [4096]u8 = undefined;
            var u = Unstructured.init(input[0..smith.slice(&input)]);
            const plans = std.enums.values(fuzz.Plan);
            const plan = plans[u.choose_index(plans.len) catch return];
            var fuzzing = context;
            fuzzing.max_batch_size = 64;
            fuzzing.interesting_batch_sizes = 17;
            plan.run(fuzzing, &u) catch |err| switch (err) {
                error.NotEnoughData => {},
                else => return err,
            };
        }
    }.run, .{});
}
