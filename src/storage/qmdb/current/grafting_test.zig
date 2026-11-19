//! Tests for current's grafting (commonware's `qmdb/current/grafting.rs` tests that need no
//! grafted storage view).

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const grafting = @import("grafting.zig");
const death = @import("utils").death;

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;

/// Oracle: the complete chunks of `ops_leaves` covered by exactly one peak at height `G`.
fn count_single_peak_chunks(comptime F: type, ops_leaves: u64, grafting_height: u32) u64 {
    const chunk_size = @as(u64, 1) << @intCast(grafting_height);
    const complete = ops_leaves / chunk_size;
    if (complete == 0) return 0;
    const size = F.location_to_position(ops_leaves);
    var count: u64 = 0;
    for (0..complete) |chunk_index| {
        if (F == Mmr) {
            // An MMR chunk always has a single covering peak.
            _ = F.chunk_peaks(size, chunk_index, grafting_height);
            count += 1;
            continue;
        }
        var peaks = F.chunk_peaks(size, chunk_index, grafting_height);
        _ = peaks.next();
        if (peaks.next() == null) count += 1;
    }
    return count;
}

fn check_graftable_chunks(comptime F: type) !void {
    for (1..9) |grafting_height_usize| {
        const grafting_height: u32 = @intCast(grafting_height_usize);
        const chunk_size = @as(u64, 1) << @intCast(grafting_height);
        const leaves_max = @min(chunk_size * 80, 2000);
        for (0..leaves_max + 1) |ops_leaves| {
            const graftable = grafting.graftable_chunks(F, ops_leaves, grafting_height);
            const oracle = count_single_peak_chunks(F, ops_leaves, grafting_height);
            try testing.expectEqual(oracle, graftable);
            const complete = ops_leaves / chunk_size;
            try testing.expect(graftable <= complete);
            // MMR has no pending chunk; MMB has at most one.
            if (F == Mmr) try testing.expectEqual(complete, graftable);
            try testing.expect(complete - graftable <= 1);
        }
    }
}

test "graftable chunks match chunk peaks (mmr)" {
    try check_graftable_chunks(Mmr);
}

test "graftable chunks match chunk peaks (mmb)" {
    try check_graftable_chunks(Mmb);
}

// commonware `test_graftable_chunks_rejects_height_zero` (`#[should_panic]`).
test "graftable chunks rejects height zero" {
    try death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            _ = grafting.graftable_chunks(Mmr, 100, 0);
        }
    }.body);
}

test "grafting height" {
    try testing.expectEqual(@as(u32, 3), grafting.height(1));
    try testing.expectEqual(@as(u32, 8), grafting.height(32));
    try testing.expectEqual(@as(u32, 9), grafting.height(64));
}

test "verifier with no graftable chunks skips the chunk" {
    const grafting_height = 1;
    const chunk = [_]u8{0xAB};
    const chunks = [_][]const u8{&chunk};
    const left = D.fill(0x01);
    const right = D.fill(0x02);
    const position = Mmr.subtree_root_position(0, grafting_height);
    const standard = qmdb.hasher(Sha256);
    const plain = standard.node_digest(position, &left, &right);
    const pending = grafting.Verifier(Mmr, Sha256).init(grafting_height, 0, &chunks, 0);
    try testing.expect(plain.eql(pending.node_digest(position, &left, &right)));
    // With the chunk graftable it is combined, so the digest differs.
    const graftable = grafting.Verifier(Mmr, Sha256).init(grafting_height, 0, &chunks, 1);
    const grafted = graftable.node_digest(position, &left, &right);
    try testing.expect(!grafted.eql(plain));
    try testing.expect(grafted.eql(Sha256.hash(&.{ &chunk, plain.as_slice() })));
    // An all-zero chunk grafts to the subtree root itself.
    const zero = [_]u8{0};
    const zeros = [_][]const u8{&zero};
    const identity = grafting.Verifier(Mmr, Sha256).init(grafting_height, 0, &zeros, 1);
    try testing.expect(plain.eql(identity.node_digest(position, &left, &right)));
}

test "grafted hasher node digest pair matches node digest" {
    const Hasher = grafting.GraftedHasher(Mmr, Sha256);
    const hasher = Hasher.init(2);
    const a = D.fill(0x01);
    const b = D.fill(0x02);
    const c = D.fill(0x03);
    const d = D.fill(0x04);
    const left_pos = Mmr.subtree_root_position(0, 1);
    const right_pos = Mmr.subtree_root_position(2, 1);
    const paired = hasher.node_digest_pair(.{
        .{ .position = left_pos, .left = &a, .right = &b },
        .{ .position = right_pos, .left = &c, .right = &d },
    });
    try testing.expect(paired[0].eql(hasher.node_digest(left_pos, &a, &b)));
    try testing.expect(paired[1].eql(hasher.node_digest(right_pos, &c, &d)));
    // Grafted position 2 (height 1 over chunks 0 and 1) hashes at ops position 14.
    const standard = qmdb.hasher(Sha256);
    const parent = hasher.node_digest(2, &a, &b);
    try testing.expect(parent.eql(standard.node_digest(14, &a, &b)));
}

fn chunk_to_ops_pos(chunk_index: u64, grafting_height: u32) u64 {
    return Mmr.subtree_root_position(chunk_index << @intCast(grafting_height), grafting_height);
}

fn ops_pos_to_chunk(ops_pos: u64, grafting_height: u32) u64 {
    return Mmr.leftmost_leaf(ops_pos, grafting_height) >> @intCast(grafting_height);
}

test "chunk index to ops position roundtrip" {
    for (1..10) |height_usize| {
        const grafting_height: u32 = @intCast(height_usize);
        for (0..1000) |chunk_index| {
            const ops_pos = chunk_to_ops_pos(chunk_index, grafting_height);
            try testing.expectEqual(grafting_height, Mmr.pos_to_height(ops_pos));
            try testing.expectEqual(chunk_index, ops_pos_to_chunk(ops_pos, grafting_height));
        }
    }
    try testing.expectEqual(@as(u64, 2), chunk_to_ops_pos(0, 1));
    try testing.expectEqual(@as(u64, 5), chunk_to_ops_pos(1, 1));
    try testing.expectEqual(@as(u64, 9), chunk_to_ops_pos(2, 1));
    try testing.expectEqual(@as(u64, 12), chunk_to_ops_pos(3, 1));
    try testing.expectEqual(@as(u64, 17), chunk_to_ops_pos(4, 1));
    try testing.expectEqual(@as(u64, 6), chunk_to_ops_pos(0, 2));
    try testing.expectEqual(@as(u64, 13), chunk_to_ops_pos(1, 2));
    try testing.expectEqual(@as(u64, 14), chunk_to_ops_pos(0, 3));
}

test "ops to grafted position of leaves" {
    for (1..8) |height_usize| {
        const grafting_height: u32 = @intCast(height_usize);
        for (0..200) |chunk_index| {
            const ops_pos = chunk_to_ops_pos(chunk_index, grafting_height);
            const grafted = grafting.ops_to_grafted_pos(Mmr, ops_pos, grafting_height);
            try testing.expectEqual(Mmr.location_to_position(chunk_index), grafted);
        }
    }
}

test "ops grafted roundtrip" {
    for (1..6) |height_usize| {
        const grafting_height: u32 = @intCast(height_usize);
        for (0..100) |chunk_index| {
            const ops_pos = chunk_to_ops_pos(chunk_index, grafting_height);
            const grafted = grafting.ops_to_grafted_pos(Mmr, ops_pos, grafting_height);
            const back = grafting.grafted_to_ops_pos(Mmr, grafted, grafting_height);
            try testing.expectEqual(ops_pos, back);
        }
        // Internal nodes: the parent of adjacent leaves.
        var chunk_index: u64 = 0;
        while (chunk_index < 100) : (chunk_index += 2) {
            const left = chunk_to_ops_pos(chunk_index, grafting_height);
            const parent = left + (@as(u64, 1) << @intCast(grafting_height + 1));
            if (Mmr.pos_to_height(parent) < grafting_height) continue;
            const grafted = grafting.ops_to_grafted_pos(Mmr, parent, grafting_height);
            const back = grafting.grafted_to_ops_pos(Mmr, grafted, grafting_height);
            try testing.expectEqual(parent, back);
        }
    }
}

test "ops to grafted position known values" {
    const cases = [_][2]u64{
        .{ 2, 0 },  .{ 5, 1 },  .{ 6, 2 },  .{ 9, 3 },
        .{ 12, 4 }, .{ 13, 5 }, .{ 14, 6 },
    };
    for (cases) |case| {
        try testing.expectEqual(case[1], grafting.ops_to_grafted_pos(Mmr, case[0], 1));
    }
}

fn aligned(leaves: u64, floor: u64, grafting_height: u32) !usize {
    return grafting.chunk_aligned_inactive_peaks(Mmr, leaves, floor, grafting_height);
}

test "chunk aligned inactive peaks" {
    // 11 MMR leaves have peaks of 8, 2, and 1 leaves.
    try testing.expectEqual(@as(usize, 0), try aligned(11, 7, 2));
    try testing.expectEqual(@as(usize, 1), try aligned(11, 8, 2));
    // Ending at 10 is not a whole chunk of 4, so the boundary stays after the first peak.
    try testing.expectEqual(@as(usize, 1), try aligned(11, 10, 2));
    try testing.expectEqual(@as(usize, 2), try aligned(11, 10, 1));
    try testing.expectEqual(@as(usize, 3), try aligned(11, 11, 0));
}
