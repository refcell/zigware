//! Tests for the historical bitmap (commonware `utils/src/bitmap/historical/tests.rs` and the
//! `utils/fuzz` historical_bitmap target). Tests that only check a panic message are covered by
//! the panics themselves and are not ported (Zig tests cannot catch a panic).

const std = @import("std");
const historical = @import("historical.zig");
const Prunable = @import("prunable.zig").Prunable;
const rng = @import("../rng.zig");
const fuzz = @import("../fuzz.zig");

const testing = std.testing;
const gpa = testing.allocator;
const H = historical.BitMap(4);
const Dirty = H.Dirty;

fn commit_bits(bitmap: *H, number: u64, bits: []const bool) !void {
    var dirty = bitmap.into_dirty();
    errdefer bitmap.* = dirty.abort(gpa);
    for (bits) |bit| try dirty.push(gpa, bit);
    bitmap.* = try dirty.commit(gpa, number);
}

fn commit_chunks(bitmap: *H, number: u64, chunks: []const [4]u8) !void {
    var dirty = bitmap.into_dirty();
    errdefer bitmap.* = dirty.abort(gpa);
    for (chunks) |*chunk| try dirty.push_chunk(gpa, chunk);
    bitmap.* = try dirty.commit(gpa, number);
}

fn commit_prune(bitmap: *H, number: u64, bit: u64) !void {
    var dirty = bitmap.into_dirty();
    errdefer bitmap.* = dirty.abort(gpa);
    try dirty.prune_to_bit(gpa, bit);
    bitmap.* = try dirty.commit(gpa, number);
}

fn at(bitmap: *const H, number: u64) !Prunable(4) {
    return (try bitmap.get_at_commit(gpa, number)) orelse error.TestMissingCommit;
}

fn expect_bits(state: *const Prunable(4), start: u64, expected: []const bool) !void {
    for (expected, start..) |bit, index| try testing.expectEqual(bit, state.get_bit(index));
}

fn push_101(_: void, dirty: *Dirty) !void {
    for ([_]bool{ true, false, true }) |bit| try dirty.push(gpa, bit);
}

fn push_one(_: void, dirty: *Dirty) !void {
    try dirty.push(gpa, false);
}

test "historical: dirty lifecycle and operations" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try testing.expect(bitmap.is_empty());
    try testing.expectEqual(@as(usize, 0), bitmap.commit_count());

    try bitmap.apply_batch(gpa, 1, {}, push_101);
    try testing.expectEqual(@as(u64, 3), bitmap.len());
    try expect_bits(&bitmap.current, 0, &.{ true, false, true });
    try testing.expectEqual(@as(usize, 1), bitmap.commit_count());

    var dirty = bitmap.into_dirty();
    try dirty.push(gpa, true);
    try dirty.push(gpa, true);
    bitmap = dirty.abort(gpa);
    try testing.expectEqual(@as(u64, 3), bitmap.len());

    // Read-through semantics.
    dirty = bitmap.into_dirty();
    try testing.expect(dirty.get_bit(0));
    try dirty.set_bit(gpa, 1, true);
    try testing.expect(dirty.get_bit(1));
    try dirty.push(gpa, false);
    try testing.expect(!dirty.get_bit(3));
    bitmap = try dirty.commit(gpa, 2);
    try testing.expectEqual(@as(u64, 4), bitmap.len());
    try testing.expect(bitmap.get_bit(1) and !bitmap.get_bit(3));

    // An empty batch still records a commit.
    dirty = bitmap.into_dirty();
    bitmap = try dirty.commit(gpa, 3);
    try testing.expect(bitmap.commit_exists(3));

    dirty = bitmap.into_dirty();
    try dirty.set_bit(gpa, 0, false);
    try dirty.push_byte(gpa, 0xAA);
    bitmap = try dirty.commit(gpa, 4);
    try testing.expectEqual(@as(u64, 12), bitmap.len());
    try testing.expect(!bitmap.get_bit(0));
}

test "historical: dirty push, pop, prune, push_byte, push_chunk, get_chunk" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try commit_bits(&bitmap, 1, &.{ false, false, false });
    var dirty = bitmap.into_dirty();
    try dirty.set_bit(gpa, 0, true);
    try dirty.set_bit(gpa, 1, true);
    try dirty.push(gpa, true);
    try dirty.push(gpa, true);
    bitmap = try dirty.commit(gpa, 2);
    try testing.expectEqual(@as(u64, 5), bitmap.len());
    try expect_bits(&bitmap.current, 0, &.{ true, true, false });

    dirty = bitmap.into_dirty();
    try dirty.push(gpa, false);
    try testing.expect(!dirty.pop());
    try testing.expectEqual(@as(u64, 5), dirty.len());
    bitmap = try dirty.commit(gpa, 3);

    var chunks: H = .empty;
    defer chunks.deinit(gpa);
    try commit_chunks(&chunks, 1, &.{.{ 0, 0, 0, 0 }});
    dirty = chunks.into_dirty();
    try dirty.push_chunk(gpa, &.{ 0xAA, 0xBB, 0xCC, 0xDD });
    try dirty.push_byte(gpa, 0xFF);
    chunks = try dirty.commit(gpa, 2);
    try testing.expectEqual(@as(u64, 72), chunks.len());
    const second: [4]u8 = .{ 0xAA, 0xBB, 0xCC, 0xDD };
    try testing.expectEqual(second, chunks.get_chunk_containing(32).*);
    for (64..72) |bit| try testing.expect(chunks.get_bit(bit));

    dirty = chunks.into_dirty();
    try dirty.set_bit(gpa, 32, true);
    try dirty.set_bit(gpa, 39, true);
    const chunk = dirty.get_chunk(32);
    try testing.expectEqual(@as(u8, 0x81), chunk[0] & 0x81);
    chunks = try dirty.commit(gpa, 3);
    try commit_prune(&chunks, 4, 32);
    try testing.expectEqual(@as(u64, 72), chunks.len());
    try testing.expectEqual(@as(usize, 1), chunks.pruned_chunks());
}

test "historical: commit history management" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try commit_bits(&bitmap, 5, &.{true});
    var dirty = bitmap.into_dirty();
    try dirty.push(gpa, false);
    try testing.expectError(error.NonMonotonicCommit, dirty.commit(gpa, 5));
    try testing.expectError(error.NonMonotonicCommit, dirty.commit(gpa, 3));
    bitmap = dirty.abort(gpa);
    try testing.expectError(error.NonMonotonicCommit, bitmap.apply_batch(gpa, 5, {}, push_one));
    try testing.expectEqual(@as(u64, 1), bitmap.len());
    try bitmap.apply_batch(gpa, 10, {}, push_one);
    try testing.expectEqual(@as(u64, 2), bitmap.len());

    var queries: H = .empty;
    defer queries.deinit(gpa);
    try testing.expect(queries.earliest_commit() == null and queries.latest_commit() == null);
    for (1..6) |i| try commit_bits(&queries, i * 10, &.{true});
    try testing.expectEqual(@as(?u64, 10), queries.earliest_commit());
    try testing.expectEqual(@as(?u64, 50), queries.latest_commit());
    try testing.expect(queries.commit_exists(30) and !queries.commit_exists(25));
    var numbers = queries.commits();
    for ([_]u64{ 10, 20, 30, 40, 50 }) |expected| {
        try testing.expectEqual(@as(?u64, expected), numbers.next());
    }
    try testing.expectEqual(@as(?u64, null), numbers.next());
    try testing.expectEqual(@as(usize, 2), queries.prune_commits_before(gpa, 30));
    try testing.expectEqual(@as(usize, 3), queries.commit_count());
    queries.clear_history(gpa);
    try testing.expectEqual(@as(usize, 0), queries.commit_count());
    try testing.expect(queries.earliest_commit() == null and queries.latest_commit() == null);
    try testing.expectEqual(@as(u64, 5), queries.len());
}

test "historical: reconstruction with modifications" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try commit_bits(&bitmap, 1, &.{ true, false, true });
    var dirty = bitmap.into_dirty();
    try dirty.set_bit(gpa, 0, false);
    try dirty.push(gpa, false);
    bitmap = try dirty.commit(gpa, 2);
    var one = try at(&bitmap, 1);
    defer one.deinit(gpa);
    try testing.expectEqual(@as(u64, 3), one.len());
    try expect_bits(&one, 0, &.{ true, false });
    var two = try at(&bitmap, 2);
    defer two.deinit(gpa);
    try testing.expectEqual(@as(u64, 4), two.len());
    try testing.expect(!two.get_bit(0) and !two.get_bit(3));

    var successive: H = .empty;
    defer successive.deinit(gpa);
    try commit_chunks(&successive, 1, &.{.{ 0xFF, 0x00, 0xFF, 0x00 }});
    for ([_][2]u64{ .{ 0, 8 }, .{ 16, 24 } }, 2..) |bits, number| {
        dirty = successive.into_dirty();
        try dirty.set_bit(gpa, bits[0], false);
        try dirty.set_bit(gpa, bits[1], true);
        successive = try dirty.commit(gpa, number);
    }
    var s1 = try at(&successive, 1);
    defer s1.deinit(gpa);
    try testing.expect(s1.get_bit(0) and !s1.get_bit(8));
    var s2 = try at(&successive, 2);
    defer s2.deinit(gpa);
    try testing.expect(!s2.get_bit(0) and s2.get_bit(8) and s2.get_bit(16));
    var s3 = try at(&successive, 3);
    defer s3.deinit(gpa);
    try testing.expect(!s3.get_bit(16) and s3.get_bit(24));
}

test "historical: reconstruction with modifications and appends" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try commit_bits(&bitmap, 1, &.{ true, true, true, true });
    for ([_][2]u64{ .{ 0, 2 }, .{ 1, 3 } }, [_]bool{ false, true }, 2..) |bits, push, number| {
        var dirty = bitmap.into_dirty();
        errdefer bitmap = dirty.abort(gpa);
        try dirty.set_bit(gpa, bits[0], false);
        try dirty.set_bit(gpa, bits[1], false);
        try dirty.push(gpa, push);
        try dirty.push(gpa, push);
        bitmap = try dirty.commit(gpa, number);
    }
    var one = try at(&bitmap, 1);
    defer one.deinit(gpa);
    try testing.expectEqual(@as(u64, 4), one.len());
    try expect_bits(&one, 0, &.{ true, true, true, true });
    var two = try at(&bitmap, 2);
    defer two.deinit(gpa);
    try testing.expectEqual(@as(u64, 6), two.len());
    try testing.expect(!two.get_bit(0) and two.get_bit(1) and !two.get_bit(4));
    var three = try at(&bitmap, 3);
    defer three.deinit(gpa);
    try testing.expectEqual(@as(u64, 8), three.len());
    try testing.expect(!three.get_bit(1) and three.get_bit(6));
}

test "historical: reconstruction with length changes" {
    var appends: H = .empty;
    defer appends.deinit(gpa);
    try commit_bits(&appends, 1, &.{ true, false });
    try commit_bits(&appends, 2, &.{ true, true });
    try commit_bits(&appends, 3, &.{ false, false });
    for ([_]u64{ 2, 4, 6 }, 1..) |expected, number| {
        var state = try at(&appends, number);
        defer state.deinit(gpa);
        try testing.expectEqual(expected, state.len());
    }

    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try commit_bits(&bitmap, 1, &.{ true, false, true, false, true });
    var dirty = bitmap.into_dirty();
    _ = dirty.pop();
    _ = dirty.pop();
    bitmap = try dirty.commit(gpa, 2);
    try commit_bits(&bitmap, 3, &.{ true, true, true });
    var one = try at(&bitmap, 1);
    defer one.deinit(gpa);
    try testing.expectEqual(@as(u64, 5), one.len());
    try testing.expect(one.get_bit(0) and !one.get_bit(1) and one.get_bit(4));
    var two = try at(&bitmap, 2);
    defer two.deinit(gpa);
    try testing.expectEqual(@as(u64, 3), two.len());
    var three = try at(&bitmap, 3);
    defer three.deinit(gpa);
    try testing.expectEqual(@as(u64, 6), three.len());
    try testing.expect(three.get_bit(3) and three.get_bit(5));
}

test "historical: reconstruction with pruning" {
    const first: [4]u8 = .{ 0xAA, 0xBB, 0xCC, 0xDD };
    const second: [4]u8 = .{ 0x11, 0x22, 0x33, 0x44 };
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try commit_chunks(&bitmap, 1, &.{ first, second });
    try commit_prune(&bitmap, 2, 32);
    try testing.expectEqual(@as(usize, 1), bitmap.pruned_chunks());
    var one = try at(&bitmap, 1);
    defer one.deinit(gpa);
    try testing.expectEqual(@as(u64, 64), one.len());
    try testing.expectEqual(@as(usize, 0), one.pruned_chunks());
    try testing.expectEqual(first, one.get_chunk_containing(0).*);
    try testing.expectEqual(second, one.get_chunk_containing(32).*);
    var two = try at(&bitmap, 2);
    defer two.deinit(gpa);
    try testing.expectEqual(@as(u64, 64), two.len());
    try testing.expectEqual(@as(usize, 1), two.pruned_chunks());
    try testing.expectEqual(second, two.get_chunk_containing(32).*);
}

test "historical: reconstruction edge cases" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try commit_bits(&bitmap, 10, &.{true});
    try testing.expectEqual(@as(?Prunable(4), null), try bitmap.get_at_commit(gpa, 5));
    try testing.expectEqual(@as(?Prunable(4), null), try bitmap.get_at_commit(gpa, 15));
    var ten = try at(&bitmap, 10);
    ten.deinit(gpa);

    var pruned: H = .empty;
    defer pruned.deinit(gpa);
    const ones: [5]bool = @splat(true);
    for (1..6) |i| try commit_bits(&pruned, i, ones[0..i]);
    _ = pruned.prune_commits_before(gpa, 3);
    try testing.expectEqual(@as(?Prunable(4), null), try pruned.get_at_commit(gpa, 1));
    try testing.expectEqual(@as(?Prunable(4), null), try pruned.get_at_commit(gpa, 2));
    var three = try at(&pruned, 3);
    defer three.deinit(gpa);
    try testing.expectEqual(@as(u64, 6), three.len());
    var four = try at(&pruned, 4);
    four.deinit(gpa);
}

test "historical: modifications on appended bits and pops" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    var dirty = bitmap.into_dirty();
    try dirty.push(gpa, true);
    try dirty.set_bit(gpa, 0, false);
    bitmap = try dirty.commit(gpa, 1);
    try testing.expectEqual(@as(u64, 1), bitmap.len());
    try testing.expect(!bitmap.get_bit(0));
    dirty = bitmap.into_dirty();
    try dirty.push(gpa, true);
    try dirty.set_bit(gpa, 1, false);
    _ = dirty.pop();
    bitmap = try dirty.commit(gpa, 2);
    try testing.expectEqual(@as(u64, 1), bitmap.len());

    // pop returns the pending modification, not the committed value.
    var ten: H = .empty;
    defer ten.deinit(gpa);
    const ones: [10]bool = @splat(true);
    try commit_bits(&ten, 1, &ones);
    dirty = ten.into_dirty();
    try dirty.set_bit(gpa, 9, false);
    try testing.expect(!dirty.pop());
    ten = try dirty.commit(gpa, 2);
    try testing.expectEqual(@as(u64, 9), ten.len());
}

test "historical: get_chunk on appended chunks and popped tails" {
    var empty: H = .empty;
    defer empty.deinit(gpa);
    var dirty = empty.into_dirty();
    for (0..32) |i| try dirty.push(gpa, i % 2 == 0);
    try testing.expectEqual(@as(u8, 0x55), dirty.get_chunk(0)[0]);
    empty = dirty.abort(gpa);

    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    const ones: [33]bool = @splat(true);
    try commit_bits(&bitmap, 1, &ones);
    dirty = bitmap.into_dirty();
    _ = dirty.pop();
    _ = dirty.pop();
    // Bit 31 is past the projected length, so the chunk shows it cleared.
    try testing.expectEqual(@as(u8, 0x7F), dirty.get_chunk(0)[3]);
    bitmap = dirty.abort(gpa);
}

test "historical: prune a freshly appended chunk" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    const ones: [54]bool = @splat(true);
    try commit_bits(&bitmap, 1, ones[0..10]);
    try testing.expectEqual(@as(usize, 1), bitmap.current.chunks_len());
    var dirty = bitmap.into_dirty();
    for (ones) |bit| try dirty.push(gpa, bit);
    try testing.expectEqual(@as(u64, 64), dirty.len());
    try dirty.prune_to_bit(gpa, 64);
    bitmap = try dirty.commit(gpa, 2);
    try testing.expectEqual(@as(usize, 2), bitmap.pruned_chunks());
    var one = try at(&bitmap, 1);
    defer one.deinit(gpa);
    try testing.expectEqual(@as(u64, 10), one.len());
    try expect_bits(&one, 0, ones[0..10]);
}

test "historical: read appended bits after pops" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    const ones: [10]bool = @splat(true);
    try commit_bits(&bitmap, 1, &ones);
    var dirty = bitmap.into_dirty();
    for (0..3) |_| _ = dirty.pop();
    try dirty.push(gpa, false);
    try dirty.push(gpa, false);
    try testing.expect(!dirty.get_bit(7) and !dirty.get_bit(8));
    const chunk = dirty.get_chunk(0);
    try testing.expectEqual(@as(u8, 0), chunk[0] & 0x80);
    try testing.expectEqual(@as(u8, 0), chunk[1] & 0x01);
    try dirty.set_bit(gpa, 7, true);
    try testing.expect(dirty.get_bit(7));
    bitmap = try dirty.commit(gpa, 2);
    try testing.expectEqual(@as(u64, 9), bitmap.len());
    try testing.expect(bitmap.get_bit(7) and !bitmap.get_bit(8));
}

test "historical: reconstruct less pruned and fully pruned commits" {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    var bits: [64]bool = undefined;
    for (&bits, 0..) |*bit, i| bit.* = i < 32;
    try commit_bits(&bitmap, 1, &bits);
    try commit_prune(&bitmap, 2, 32);
    var one = try at(&bitmap, 1);
    defer one.deinit(gpa);
    try testing.expectEqual(@as(u64, 64), one.len());
    try testing.expectEqual(@as(usize, 0), one.pruned_chunks());
    try expect_bits(&one, 0, &bits);

    var full: H = .empty;
    defer full.deinit(gpa);
    for (&bits, 0..) |*bit, i| bit.* = i % 2 == 0;
    try commit_bits(&full, 1, bits[0..32]);
    try commit_prune(&full, 2, 32);
    try testing.expectEqual(@as(usize, 1), full.pruned_chunks());
    var two = try at(&full, 2);
    defer two.deinit(gpa);
    try testing.expectEqual(@as(u64, 32), two.len());
    try testing.expectEqual(@as(usize, 1), two.pruned_chunks());
    var before = try at(&full, 1);
    defer before.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), before.pruned_chunks());
    try expect_bits(&before, 0, bits[0..32]);
}

test "historical: commit number maxInt(u64) is reserved" {
    const max = std.math.maxInt(u64);
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    try testing.expectError(error.ReservedCommitNumber, bitmap.apply_batch(gpa, max, {}, push_one));
    try testing.expect(bitmap.is_empty());
    try bitmap.apply_batch(gpa, max - 1, {}, push_one);
    try testing.expectEqual(@as(u64, 1), bitmap.len());
    try testing.expectEqual(@as(?Prunable(4), null), try bitmap.get_at_commit(gpa, max));
    var last = try at(&bitmap, max - 1);
    last.deinit(gpa);
}

fn expect_commit(bitmap: *const H, number: u64, expected: *const Prunable(4)) !void {
    var state = try at(bitmap, number);
    defer state.deinit(gpa);
    try testing.expectEqual(expected.len(), state.len());
    try testing.expectEqual(expected.pruned_chunks(), state.pruned_chunks());
    for (state.pruned_bits()..expected.len()) |bit| {
        try testing.expectEqual(expected.get_bit(bit), state.get_bit(bit));
    }
}

/// commonware `test_randomized_helper`: random operations applied to a historical bitmap and
/// a `Prunable` ground truth; every commit must reconstruct to its ground-truth checkpoint.
fn check_random_history(generator: anytype, commits: u64, operations: usize) !void {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    var truth: Prunable(4) = .empty;
    defer truth.deinit(gpa);
    var checkpoints: std.ArrayList(Prunable(4)) = .empty;
    defer {
        for (checkpoints.items) |*checkpoint| checkpoint.deinit(gpa);
        checkpoints.deinit(gpa);
    }
    for (0..commits) |number| {
        var dirty = bitmap.into_dirty();
        errdefer bitmap = dirty.abort(gpa);
        for (0..operations) |_| try random_operation(&dirty, &truth, generator);
        bitmap = try dirty.commit(gpa, number);
        var checkpoint = try truth.clone(gpa);
        checkpoints.append(gpa, checkpoint) catch |err| {
            checkpoint.deinit(gpa);
            return err;
        };
    }
    for (checkpoints.items, 0..) |*checkpoint, number| {
        try expect_commit(&bitmap, number, checkpoint);
    }
}

fn random_operation(dirty: *Dirty, truth: *Prunable(4), generator: anytype) !void {
    const chunk_bits = Prunable(4).CHUNK_SIZE_BITS;
    const choice = rng.range_less_than(generator, u64, 0, 100);
    const len = truth.len();
    if (len == 0 or choice < 55) {
        const bit = rng.bernoulli(generator, 0.5);
        try dirty.push(gpa, bit);
        try truth.push(gpa, bit);
    } else if (choice < 75) {
        const bit = rng.range_less_than(generator, u64, 0, len);
        const value = rng.bernoulli(generator, 0.5);
        if (Prunable(4).to_chunk_index(bit) >= truth.pruned_chunks()) {
            try dirty.set_bit(gpa, bit, value);
            truth.set_bit(bit, value);
        }
    } else if (choice < 90) {
        if (len == truth.pruned_bits()) return;
        try testing.expectEqual(truth.pop(), dirty.pop());
    } else {
        const max_chunk: usize = @intCast((len / chunk_bits) -| 1);
        if (max_chunk <= truth.pruned_chunks()) return;
        const chunk = rng.range_at_most(generator, usize, truth.pruned_chunks() + 1, max_chunk);
        try dirty.prune_to_bit(gpa, chunk * chunk_bits);
        truth.prune_to_bit(chunk * chunk_bits);
    }
    try testing.expectEqual(truth.len(), dirty.len());
}

test "historical: randomized with multiple seeds" {
    for (0..101) |seed| {
        var generator = rng.TestRng.init(seed);
        try check_random_history(&generator, 20, 32);
    }
}

/// Fuzz (commonware utils/fuzz historical_bitmap.rs): commits of random push, pop, set, and
/// prune operations, each reconstructed and compared against a `Prunable` model.
fn fuzz_historical(_: void, generator: *rng.FuzzRng) !void {
    var bitmap: H = .empty;
    defer bitmap.deinit(gpa);
    var truth: Prunable(4) = .empty;
    defer truth.deinit(gpa);
    var checkpoints: std.ArrayList(Prunable(4)) = .empty;
    defer {
        for (checkpoints.items) |*checkpoint| checkpoint.deinit(gpa);
        checkpoints.deinit(gpa);
    }
    const commits = rng.range_at_most(generator, u64, 0, 16);
    for (0..commits) |number| {
        var dirty = bitmap.into_dirty();
        errdefer bitmap = dirty.abort(gpa);
        const operations = rng.range_at_most(generator, u32, 0, 48);
        for (0..operations) |_| try fuzz_operation(&dirty, &truth, generator);
        bitmap = try dirty.commit(gpa, number);
        var checkpoint = try truth.clone(gpa);
        checkpoints.append(gpa, checkpoint) catch |err| {
            checkpoint.deinit(gpa);
            return err;
        };
    }
    for (checkpoints.items, 0..) |*checkpoint, number| {
        try expect_commit(&bitmap, number, checkpoint);
    }
}

fn fuzz_operation(dirty: *Dirty, truth: *Prunable(4), generator: *rng.FuzzRng) !void {
    const chunk_bits = Prunable(4).CHUNK_SIZE_BITS;
    const len = truth.len();
    switch (rng.range_less_than(generator, u8, 0, 4)) {
        0 => {
            const bit = rng.boolean(generator);
            try dirty.push(gpa, bit);
            try truth.push(gpa, bit);
        },
        1 => if (len > truth.pruned_bits()) {
            try testing.expectEqual(truth.pop(), dirty.pop());
        },
        2 => {
            const bit = rng.range_at_most(generator, u64, 0, len * 2 + 1);
            const value = rng.boolean(generator);
            if (bit >= len or bit < truth.pruned_bits()) return;
            try dirty.set_bit(gpa, bit, value);
            truth.set_bit(bit, value);
        },
        else => {
            const chunk: usize = rng.range_at_most(generator, u8, 0, 255);
            const total: usize = @intCast(len / chunk_bits);
            if (chunk <= truth.pruned_chunks() or total == 0 or chunk >= total) return;
            try dirty.prune_to_bit(gpa, chunk * chunk_bits);
            truth.prune_to_bit(chunk * chunk_bits);
        },
    }
    try testing.expectEqual(truth.len(), dirty.len());
    try testing.expectEqual(truth.pruned_chunks(), dirty.pruned_chunks());
}

test "fuzz historical bitmap" {
    try fuzz.run({}, fuzz_historical, 0x6869_7374, 300);
}

const death = @import("../death.zig");

test "historical: reading a popped bit panics" {
    // commonware `bitmap/historical/tests.rs test_read_popped_bit_panics` (#[should_panic]).
    try death.expect_panic(@src(), "bit offset 8 out of bounds (len: 8)", struct {
        fn body() !void {
            var bitmap: H = .empty;
            defer bitmap.deinit(gpa);
            try commit_bits(&bitmap, 1, &@as([10]bool, @splat(true)));
            var dirty = bitmap.into_dirty();
            defer bitmap = dirty.abort(gpa);
            _ = dirty.pop();
            _ = dirty.pop();
            _ = dirty.get_bit(8);
        }
    }.body);
}

test "historical: pruning beyond the projected length panics" {
    // commonware `bitmap/historical/tests.rs test_prune_beyond_length_panics` (#[should_panic]).
    try death.expect_panic(@src(), "beyond projected length", struct {
        fn body() !void {
            var bitmap: H = .empty;
            defer bitmap.deinit(gpa);
            try commit_bits(&bitmap, 1, &@as([10]bool, @splat(true)));
            var dirty = bitmap.into_dirty();
            defer bitmap = dirty.abort(gpa);
            _ = dirty.pop();
            try dirty.prune_to_bit(gpa, 100);
        }
    }.body);
}

test "historical: popping into the pruned region panics" {
    // commonware `bitmap/historical/tests.rs test_pop_into_pruned_region_panics` (#[should_panic]).
    try death.expect_panic(@src(), "bit pruned: 31", struct {
        fn body() !void {
            var bitmap: H = .empty;
            defer bitmap.deinit(gpa);
            const full: [4]u8 = @splat(0xFF);
            try commit_chunks(&bitmap, 1, &.{ full, full });
            try commit_prune(&bitmap, 2, 32);
            var dirty = bitmap.into_dirty();
            defer bitmap = dirty.abort(gpa);
            for (0..33) |_| _ = dirty.pop();
        }
    }.body);
}
