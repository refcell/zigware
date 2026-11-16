//! Fuzz for utils' top-level functions (commonware `utils/fuzz/fuzz_targets/lib_functions.rs`):
//! hex round trips, quorum math, union, union_unique, modulo, and the non-zero wrappers.

const std = @import("std");
const formatting = @import("formatting");
const utils = @import("root.zig");
const fuzz = @import("fuzz.zig");
const rng = @import("rng.zig");
const time = @import("time.zig");
const testing = std.testing;
const gpa = testing.allocator;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;

/// Draws up to 64 random bytes into `buffer`.
fn draw_bytes(generator: *rng.FuzzRng, buffer: *[64]u8) []u8 {
    const len = rng.range_at_most(generator, usize, 0, buffer.len);
    generator.fill_bytes(buffer[0..len]);
    return buffer[0..len];
}

fn check_non_zero(comptime T: type, generator: *rng.FuzzRng) !void {
    const value: T = @truncate(generator.next_u64());
    const wrapped = utils.NonZero(T).init(value);
    try expectEqual(value == 0, wrapped == null);
    if (wrapped) |nonzero| try expectEqual(value, nonzero.get());
    if (value != 0) try expectEqual(value, utils.nz(T, value).get());
}

fn check_duration(generator: *rng.FuzzRng) !void {
    const duration = time.Duration.from_millis(generator.next_u64());
    const wrapped = time.NonZeroDuration.init(duration);
    try expectEqual(duration.is_zero(), wrapped == null);
    if (wrapped) |nonzero| {
        try expectEqual(duration, nonzero.get());
        try expectEqual(duration, time.NonZeroDuration.init_panic(duration).get());
    }
}

fn check_hex(generator: *rng.FuzzRng) !void {
    var buffer: [64]u8 = undefined;
    const data = draw_bytes(generator, &buffer);
    const encoded = try formatting.hex(gpa, data);
    defer gpa.free(encoded);
    const decoded = (try formatting.from_hex(gpa, encoded)).?;
    defer gpa.free(decoded);
    try expectEqualSlices(u8, data, decoded);
}

fn check_from_hex(generator: *rng.FuzzRng) !void {
    var buffer: [64]u8 = undefined;
    // Bias toward hex digits so decoding succeeds often.
    const alphabet = "0123456789abcdefABCDEF x";
    const text = draw_bytes(generator, &buffer);
    for (text) |*byte| byte.* = alphabet[byte.* % alphabet.len];
    if (try formatting.from_hex(gpa, text)) |decoded| {
        defer gpa.free(decoded);
        const encoded = try formatting.hex(gpa, decoded);
        defer gpa.free(encoded);
        const again = (try formatting.from_hex(gpa, encoded)).?;
        defer gpa.free(again);
        try expectEqualSlices(u8, decoded, again);
    }
    // A `0x` prefix must not crash, whatever follows.
    const prefixed = try std.mem.concat(gpa, u8, &.{ "0x", text });
    defer gpa.free(prefixed);
    if (try formatting.from_hex(gpa, prefixed)) |decoded| gpa.free(decoded);
}

fn check_faults(generator: *rng.FuzzRng) !void {
    const n = generator.next_u32();
    if (n == 0) return;
    const faults = utils.N3f1.max_faults(n);
    try expectEqual((n -| 1) / 3, faults);
    try expectEqual(n, utils.N3f1.quorum(n) + faults);
}

fn check_union(generator: *rng.FuzzRng) !void {
    var buffer_a: [64]u8 = undefined;
    var buffer_b: [64]u8 = undefined;
    const a = draw_bytes(generator, &buffer_a);
    const b = draw_bytes(generator, &buffer_b);
    const result = try utils.@"union"(gpa, a, b);
    defer gpa.free(result);
    try expectEqual(a.len + b.len, result.len);
    try expectEqualSlices(u8, a, result[0..a.len]);
    try expectEqualSlices(u8, b, result[a.len..]);

    const unique = try utils.union_unique(gpa, a, b);
    defer gpa.free(unique);
    try expect(unique.len > a.len + b.len);
    const again = try utils.union_unique(gpa, a, b);
    defer gpa.free(again);
    try expectEqualSlices(u8, unique, again);
    // The namespace length prefix separates (a, b) from (a ++ b[0..1], b[1..]).
    if (b.len > 0) {
        const shifted_namespace = result[0 .. a.len + 1];
        const shifted = try utils.union_unique(gpa, shifted_namespace, b[1..]);
        defer gpa.free(shifted);
        try expect(!std.mem.eql(u8, unique, shifted));
    }
}

fn check_modulo(generator: *rng.FuzzRng) !void {
    var buffer: [64]u8 = undefined;
    const bytes = draw_bytes(generator, &buffer);
    const n = generator.next_u64();
    if (n == 0) return;
    const result = utils.modulo(bytes, n);
    try expect(result < n);
    try expectEqual(0, utils.modulo(&.{}, n));
    try expectEqual(result, utils.modulo(bytes, n));
    if (n == 1) try expectEqual(0, result);
    const zeros: [64]u8 = @splat(0);
    try expectEqual(0, utils.modulo(zeros[0..bytes.len], n));
    // Independent check for inputs that fit in a u64.
    if (bytes.len <= 8) {
        var value: u64 = 0;
        for (bytes) |byte| value = (value << 8) | byte;
        try expectEqual(value % n, result);
    }
}

fn fuzz_lib(_: void, generator: *rng.FuzzRng) !void {
    switch (rng.range_less_than(generator, u8, 0, 11)) {
        0 => try check_hex(generator),
        1 => try check_from_hex(generator),
        2 => try check_faults(generator),
        3 => try check_union(generator),
        4 => try check_modulo(generator),
        5 => try check_non_zero(usize, generator),
        6 => try check_non_zero(u8, generator),
        7 => try check_non_zero(u16, generator),
        8 => try check_non_zero(u32, generator),
        9 => try check_non_zero(u64, generator),
        10 => try check_duration(generator),
        else => unreachable,
    }
}

test "fuzz lib functions" {
    try fuzz.run({}, fuzz_lib, 0x6c69_6266, 500);
}
