//! The double-fast match finder against libzstd 1.5.7: for each sample, the SHA-256 of every
//! sequence (`literal_length`, `off_base`, `match_length` as little-endian u32s, then one
//! `last_literals, 0, 0` per block) that `ZSTD_generateSequences` reports at level 3.
//! Blocks are 128 KiB and repeat offsets carry across them, as in a frame.

const std = @import("std");
const testing = std.testing;
const corpus = @import("corpus.zig");
const params = @import("params.zig");
const dfast = @import("dfast.zig");

const Kind = enum { text, records, mixed, noisy, sparse };

/// `mixed` alternates 50 KB pieces of text and records; `noisy` alternates 700 random
/// bytes, which grow the search step to 3, with 200 bytes of text; `sparse` alternates 2000
/// random bytes, which grow it past 3 so a match skips the long insert at `ip1`, with 300.
fn sample(gpa: std.mem.Allocator, kind: Kind, len: usize) ![]u8 {
    const data = try gpa.alloc(u8, len);
    var prng = std.Random.DefaultPrng.init(0x6c33);
    switch (kind) {
        .text => corpus.text(prng.random(), data),
        .records => corpus.records(prng.random(), data),
        .mixed => {
            var at: usize = 0;
            var text = true;
            while (at < data.len) : (text = !text) {
                const piece = data[at..@min(data.len, at + 50_000)];
                const random = prng.random();
                if (text) corpus.text(random, piece) else corpus.records(random, piece);
                at += piece.len;
            }
        },
        .sparse => {
            var at: usize = 0;
            var text = true;
            while (at < data.len) : (text = !text) {
                const piece = data[at..@min(data.len, at + @as(usize, if (text) 300 else 2000))];
                if (text) corpus.text(prng.random(), piece) else prng.random().bytes(piece);
                at += piece.len;
            }
        },
        .noisy => {
            var at: usize = 0;
            var text = true;
            while (at < data.len) : (text = !text) {
                const piece = data[at..@min(data.len, at + @as(usize, if (text) 200 else 700))];
                if (text) corpus.text(prng.random(), piece) else prng.random().bytes(piece);
                at += piece.len;
            }
        },
    }
    return data;
}

fn digest(gpa: std.mem.Allocator, src: []const u8) !struct { count: usize, hash: [32]u8 } {
    var state = try dfast.State.init(gpa, params.level3(src.len));
    defer state.deinit(gpa);
    var sequences = try std.ArrayList(dfast.Sequence).initCapacity(gpa, 1 << 17);
    defer sequences.deinit(gpa);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var rep: [dfast.rep_num]u32 = .{ 1, 4, 8 };
    var total: usize = 0;
    var start: usize = 0;
    while (start < src.len) {
        const end = @min(src.len, start + (1 << 17));
        try testing.expect(end - start >= 7);
        state.enforce_max_dist(end);
        sequences.clearRetainingCapacity();
        const last = dfast.compress_block(&state, src, start, end, &sequences, &rep);
        for (sequences.items) |sequence| {
            update(&hasher, .{ sequence.literal_length, sequence.off_base, sequence.match_length });
        }
        update(&hasher, .{ last, 0, 0 });
        total += sequences.items.len + 1;
        start = end;
    }
    return .{ .count = total, .hash = hasher.finalResult() };
}

fn update(hasher: *std.crypto.hash.sha2.Sha256, values: [3]u32) void {
    var bytes: [12]u8 = undefined;
    for (values, 0..) |value, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], value, .little);
    hasher.update(&bytes);
}

// Text and records under one block, across blocks, mixed past the 2 MiB window (where
// `enforce_max_dist` moves the prefix), and noise that grows the search step.
test "double fast finds libzstd level 3's sequences" {
    const gpa = testing.allocator;
    const cases = [_]struct { kind: Kind, len: usize, count: usize, hash: []const u8 }{
        .{
            .kind = .text,
            .len = 1000,
            .count = 91,
            .hash = "d1853dfb0c7a9c2d5da12d6772aa4ceaff8f4de5c749352462b104ebe5de7b32",
        },
        .{
            .kind = .text,
            .len = 200_000,
            .count = 22537,
            .hash = "04a1a00093a10c38850efb7798ecad1f9610eb2503c4eec4d6ddaa807f13735f",
        },
        .{
            .kind = .records,
            .len = 300_000,
            .count = 12504,
            .hash = "962272dbb0e7499867a43425de493c225b1333efb6e5043d3b13e68ad2f7a5ea",
        },
        .{
            .kind = .mixed,
            .len = 2_300_000,
            .count = 165417,
            .hash = "245da5de00adc7bfd165077d010db3cdba5d440208d4fa30885eabaa11c9fc8c",
        },
        .{
            .kind = .noisy,
            .len = 400_000,
            .count = 9401,
            .hash = "a3b358dfe6fb2c2a9feb9c91e6a84a840f7fc6a3c145eff38b3f60814e535380",
        },
        .{
            .kind = .sparse,
            .len = 400_000,
            .count = 5467,
            .hash = "8acae4714c8cca3d352363cde8ca70be140a1f1bc86df1ddef8ec8bf932acc99",
        },
    };
    for (cases) |case| {
        const src = try sample(gpa, case.kind, case.len);
        defer gpa.free(src);
        const result = try digest(gpa, src);
        try testing.expectEqual(case.count, result.count);
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, case.hash);
        try testing.expectEqualSlices(u8, &expected, &result.hash);
    }
}

// `count` agrees with a byte count for every equal length up to past eight vector steps and
// every limit up to one past the difference, flipping each bit in turn, so the vector, word,
// and byte loops each stop at the right byte.
test "count matches a byte count" {
    var src: [700]u8 = undefined;
    @memset(&src, 7);
    const b = 10;
    const a = 300;
    for (0..290) |equal| {
        src[a + equal] = 7 ^ (@as(u8, 1) << @intCast(equal % 8)); // Each bit in turn.
        var limit: usize = if (equal < 80) a else a + equal - 40;
        while (limit <= a + equal + 1) : (limit += 1) {
            try testing.expectEqual(@min(equal, limit - a), dfast.count(&src, a, b, limit));
        }
        try testing.expectEqual(equal, dfast.count(&src, a, b, src.len));
        src[a + equal] = 7;
    }
}
