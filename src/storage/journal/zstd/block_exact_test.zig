//! Whole frames against libzstd 1.5.7: for each sample, the length and SHA-256 of the frame
//! `zstd::bulk::compress(.., 3)` (zstd-sys 2.0.16, identical to `zstd -3 --no-check`) writes.
//! `mixed` puts noise between text and records, so blocks are stored raw, the pre-splitter
//! cuts blocks once savings allow it, and Huffman tables are reused and replaced.

const std = @import("std");
const testing = std.testing;
const corpus = @import("corpus.zig");
const zstd = @import("../zstd.zig");

pub const Kind = enum { text, records, mixed, run, noise, sandwich };

/// Sample `kind` of `out.len` bytes, deterministic.
pub fn sample(out: []u8, kind: Kind) void {
    var prng = std.Random.DefaultPrng.init(0x6578616374);
    const random = prng.random();
    switch (kind) {
        .text => corpus.text(random, out),
        .records => corpus.records(random, out),
        .run => @memset(out, 0x5a),
        .noise => random.bytes(out),
        .sandwich => sample_sandwich(out, random),
        .mixed => {
            const third = out.len / 3;
            corpus.text(random, out[0..third]);
            random.bytes(out[third..][0..third]);
            corpus.records(random, out[2 * third ..]);
        },
    }
}

/// Per 128 KiB block: random 4 KiB edges around skewed literals with a short copy every 13
/// bytes, so literals run 10 to 20 per sequence and only the edges look incompressible.
fn sample_sandwich(out: []u8, random: std.Random) void {
    for (out, 0..) |*byte, i| {
        const at = i % (128 * 1024);
        if (at < 4096 or at >= 128 * 1024 - 4096) {
            byte.* = random.int(u8);
        } else if (at % 21 >= 13 and i >= 1000) {
            byte.* = out[i - 1000];
        } else {
            byte.* = @intCast(@min(255, @as(u32, @intFromFloat(random.floatExp(f64) * 20))));
        }
    }
}

pub const Case = struct { kind: Kind, len: usize, frame_len: usize, hash: []const u8 };

pub const cases = [_]Case{
    .{ .kind = .text, .len = 0, .frame_len = 9, .hash = hashes[0] },
    .{ .kind = .text, .len = 6, .frame_len = 15, .hash = hashes[1] },
    .{ .kind = .text, .len = 100, .frame_len = 92, .hash = hashes[2] },
    .{ .kind = .records, .len = 1000, .frame_len = 538, .hash = hashes[3] },
    .{ .kind = .text, .len = 64_000, .frame_len = 19070, .hash = hashes[4] },
    .{ .kind = .records, .len = 300_000, .frame_len = 41260, .hash = hashes[5] },
    .{ .kind = .run, .len = 300_000, .frame_len = 30, .hash = hashes[6] },
    .{ .kind = .mixed, .len = 1_200_000, .frame_len = 569176, .hash = hashes[7] },
    // Found by searching for inputs that catch planted bugs: `minGain` at a 102-byte block,
    // the pre-splitter's savings gate on a raw first block, and the suspect-literals ratio.
    .{ .kind = .mixed, .len = 102, .frame_len = 111, .hash = hashes[8] },
    .{ .kind = .noise, .len = 300_000, .frame_len = 300018, .hash = hashes[9] },
    .{ .kind = .sandwich, .len = 262_144, .frame_len = 141340, .hash = hashes[10] },
};

const hashes = [_][]const u8{
    "6fb8543883dafcc2ed0934866b8b3f775231f5b0933add08bf502e9e84944cbd",
    "02e90bc41ddacd5d0ce9565eb9e00b5875ca08fc3b920325b5b05c44a66a4c96",
    "33afcdda3047375b3dccb3eb458b785b67f264e733534f6737738a2a3b089749",
    "f7256cb15a6465fb083b6f4aae3c657f1d683c35ae43c7441936f73655856bfc",
    "83efb456395306d72028346c7615bb1a55dbbc779427c020628dcbc02d94da1b",
    "a8ffea39bbfd59bf4c3459f222b267e9ee3a3c859effaa78b52057ad91b75506",
    "1b3ccf58ec8979770fd61a43dfbec8f810aa3f5a95ceecfdd3178cf7459c5b10",
    "aac73697b7ebe8d479dd02f7c66656b87a26e50a9191caffe2ded4e34ee62f00",
    "c2a6beae4674f3fc24b27c1c6f391e05968f65cca7cc90e6496e67416617f155",
    "8764bf020379ab418a09c2cc39dc73967eb74dd7ea896003e0c16d3dedecd8b4",
    "a17829438ae9f7eb891885b6cabb5a9e80d011cb846f11c3c3c72156884240c9",
};

pub fn frame(gpa: std.mem.Allocator, case: Case, out: *std.ArrayList(u8)) ![]const u8 {
    const data = try gpa.alloc(u8, case.len);
    defer gpa.free(data);
    sample(data, case.kind);
    const written = try zstd.compress_into(gpa, data, out);
    const decoded = try zstd.decompress(gpa, written);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, data, decoded);
    return written;
}

// Every piece together: header, block split and type choices, literals, sequences, and the
// repeat offsets and tables carried from block to block.
test "exact frames match libzstd 1.5.7 level 3" {
    const gpa = testing.allocator;
    for (cases) |case| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        const written = try frame(gpa, case, &out);
        try testing.expectEqual(case.frame_len, written.len);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(written, &hash, .{});
        var want: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, case.hash);
        try testing.expectEqualSlices(u8, &want, &hash);
    }
}
