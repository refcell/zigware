//! The exact FSE encoder against libzstd 1.5.7's `fse_compress.c` compiled from zstd-sys
//! 2.0.16: for each generated sample and setting, the SHA-256 of the line the oracle prints
//! (`<log> <ncount hex>|<stream hex or "none">`). `flat` samples are near-uniform histograms,
//! which reach `FSE_normalizeM2`.

const std = @import("std");
const testing = std.testing;
const fse = @import("fse_exact.zig");

pub const Kind = enum { skewed, flat, sparse };

/// Sample `index` of `kind`, `len` bytes, deterministic.
pub fn sample(out: []u8, kind: Kind, index: u64) void {
    var prng = std.Random.DefaultPrng.init(0x66736500 + index);
    const random = prng.random();
    switch (kind) {
        .skewed => for (out) |*byte| {
            byte.* = @intCast(@min(52, @as(u32, @intFromFloat(random.floatExp(f64) * 3))));
        },
        .flat => {
            const symbols = random.intRangeLessThan(u16, 2, 256);
            for (out, 0..) |*byte, i| {
                byte.* = if (i < symbols)
                    @intCast(i)
                else
                    random.uintLessThan(u8, @intCast(symbols - 1)) + 1;
            }
            random.shuffle(u8, out);
        },
        .sparse => for (out) |*byte| {
            const rare = random.uintLessThan(u8, 100) >= 97;
            byte.* = if (rare) random.intRangeLessThan(u8, 1, 40) else 0;
        },
    }
}

pub const Setting = struct { max_log: u32, low_prob: bool, capacity: usize };

/// The oracle's line for `src`, written into `out`.
pub fn line(out: []u8, src: []const u8, setting: Setting) ![]const u8 {
    var counts: [256]u32 = undefined;
    var max_symbol: u32 = 255;
    const largest = fse.count_simple(&counts, &max_symbol, src);
    if (largest == src.len or largest == 1) return std.fmt.bufPrint(out, "skip", .{});
    const log = fse.optimal_table_log(setting.max_log, src.len, max_symbol);
    var norm: [256]i16 = undefined;
    fse.normalize(&norm, log, &counts, src.len, max_symbol, setting.low_prob) catch
        return std.fmt.bufPrint(out, "normerr", .{});
    var header: [512]u8 = undefined;
    const header_len = try fse.write_ncount(&header, &norm, max_symbol, log);
    const table = try testing.allocator.create(fse.CTable);
    defer testing.allocator.destroy(table);
    table.build(&norm, max_symbol, log);
    const stream = try testing.allocator.alloc(u8, setting.capacity);
    defer testing.allocator.free(stream);
    var writer: std.Io.Writer = .fixed(out);
    try writer.print("{d} {x}|", .{ log, header[0..header_len] });
    if (fse.compress(stream, src, table)) |len| {
        try writer.print("{x}", .{stream[0..len]});
    } else {
        try writer.print("none", .{});
    }
    return writer.buffered();
}

pub const Case = struct { kind: Kind, index: u64, len: usize, setting: Setting };

fn make_case(
    kind: Kind,
    index: u64,
    len: usize,
    max_log: u32,
    low_prob: bool,
    capacity: usize,
) Case {
    return .{
        .kind = kind,
        .index = index,
        .len = len,
        .setting = .{ .max_log = max_log, .low_prob = low_prob, .capacity = capacity },
    };
}

pub const cases = [_]Case{
    make_case(.skewed, 0, 50, 6, false, 4096),
    make_case(.skewed, 1, 20000, 9, true, 300000),
    make_case(.skewed, 2, 4096, 9, true, 40),
    make_case(.flat, 3, 1000, 8, true, 300000),
    make_case(.flat, 4, 3000, 12, false, 300000),
    make_case(.flat, 5, 700, 0, true, 300000),
    make_case(.sparse, 6, 131072, 9, true, 300000),
    make_case(.sparse, 7, 255, 6, false, 4096),
};

const expected = [cases.len][]const u8{
    "73e6551dd1caf2ae029867a893ca1c5dbd8837ca9185bb3ae359dde802ba93a6",
    "943ef0611fb8fc5eee7d69d51f0176b5b6f08a99a7115039c6c1734540973ed9",
    "a3a9d598aa51d480f94034ad9eb8c88548c2752fbd6b2d69db1d9286f1d74672",
    "33d61328d6e318f7fa98bcfe1be80d8ab291c68db707fdc185cc3a824cdc37c1",
    "e800c834d8453ac339ad8a4fd6474cccec268543587d50abcef6187229ffd580",
    "aba78625b64bb1b9b72b0dcdd905f445d021c8cc6249460c6c8c9fb34a99d38a",
    "f803c9f740d216a71d9f395cd3e7a0babacecc39970363a4abebf444d35caf51",
    "4c523a6ce970791997d6eafed0b9d5b7b2d2a8738383c225108dd2a2928e68f9",
};

// Normalization (primary and M2), the NCount header, table construction, two-state encoding,
// and the stream overflow rule (case 2's 40-byte capacity) all match libzstd.
test "exact fse matches libzstd 1.5.7" {
    const gpa = testing.allocator;
    const out = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(out);
    for (cases, expected) |case, hash_hex| {
        const data = try gpa.alloc(u8, case.len);
        defer gpa.free(data);
        sample(data, case.kind, case.index);
        const text = try line(out, data, case.setting);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(text, &hash, .{});
        var want: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, hash_hex);
        try testing.expectEqualSlices(u8, &want, &hash);
    }
}

// libzstd's bit stream refuses to write past `capacity - 8` (`BIT_initCStream`'s end pointer):
// the oracle on a 131072-byte sparse input returns a 43292-byte stream at capacity 43300 and
// nothing at 43299. The same edge holds here for any input.
test "exact fse stream needs eight bytes of slack" {
    const gpa = testing.allocator;
    const data = try gpa.alloc(u8, 20000);
    defer gpa.free(data);
    sample(data, .skewed, 1);
    var counts: [256]u32 = undefined;
    var max_symbol: u32 = 255;
    _ = fse.count_simple(&counts, &max_symbol, data);
    const log = fse.optimal_table_log(9, data.len, max_symbol);
    var norm: [256]i16 = undefined;
    try fse.normalize(&norm, log, &counts, data.len, max_symbol, true);
    const table = try gpa.create(fse.CTable);
    defer gpa.destroy(table);
    table.build(&norm, max_symbol, log);
    const wide = try gpa.alloc(u8, 2 * data.len);
    defer gpa.free(wide);
    const len = fse.compress(wide, data, table).?;
    try testing.expect(len > 8);
    try testing.expect(fse.compress(wide[0 .. len + 7], data, table) == null);
    const narrow = try gpa.alloc(u8, len + 8);
    defer gpa.free(narrow);
    try testing.expectEqual(len, fse.compress(narrow, data, table).?);
    try testing.expectEqualSlices(u8, wide[0..len], narrow[0..len]);
}
