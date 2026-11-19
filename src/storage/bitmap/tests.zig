//! Tests for the authenticated bitmap, ported from commonware's
//! `storage/src/bitmap/authenticated.rs`, plus the `bitmap_operations` fuzz target
//! (storage/fuzz). Commonware's `should_panic` tests (pushing a chunk or byte onto an
//! unaligned bitmap, reading out-of-bounds or pruned bits) are death tests in death_test.zig.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const merkle = @import("../merkle/mod.zig");
const authenticated = @import("authenticated.zig");
const memory = @import("runtime").storage.memory;
const fuzz_bytes = @import("../fuzz_bytes.zig");

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const H = merkle.hasher.Standard(Sha256);
const Storage = memory.Storage;
const gpa = testing.allocator;
const sha256_size = 32;

fn TestBitMap(comptime N: usize) type {
    return authenticated.BitMap(D, N);
}

const Map = TestBitMap(sha256_size);
const chunk_bits = Map.CHUNK_SIZE_BITS;

/// `sha256(s)` repeated to fill an `N`-byte chunk.
fn test_chunk(comptime N: usize, s: []const u8) [N]u8 {
    comptime std.debug.assert(N % 32 == 0);
    var chunk: [N]u8 = undefined;
    const digest = Sha256.hash(&.{s});
    for (0..N / 32) |i| chunk[i * 32 ..][0..32].* = digest.bytes;
    return chunk;
}

fn open(
    comptime N: usize,
    storage: *Storage,
    partition: []const u8,
    hasher: *const H,
) !TestBitMap(N) {
    return TestBitMap(N).init(gpa, storage.storage(), partition, hasher);
}

fn verify(
    comptime N: usize,
    hasher: *const H,
    proof: *const TestBitMap(N).Proof,
    bit: u64,
    chunk: *const [N]u8,
    root: *const D,
) bool {
    return TestBitMap(N).verify_bit_inclusion(hasher, proof, bit, chunk, root);
}

test "bitmap verify empty proof" {
    const hasher = H.init(.forward_fold);
    const proof: Map.Proof = .{ .leaves = 100 };
    const chunk: [sha256_size]u8 = @splat(0);
    const root: D = .{ .bytes = @splat(0) };
    try testing.expect(!verify(sha256_size, &hasher, &proof, 0, &chunk, &root));
}

test "bitmap verify rejects nonzero inactive peaks" {
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(sha256_size, &storage, "inactive_peaks_canonical", &hasher);
    defer bitmap.deinit();
    bitmap.into_dirty();
    for (0..chunk_bits * 4) |i| try bitmap.push(i % 3 == 0);
    try bitmap.merkleize(&hasher);
    const root = bitmap.root();
    const bit = chunk_bits + 5;
    var proof, const chunk = try bitmap.proof(&hasher, bit);
    defer proof.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), proof.inactive_peaks);
    try testing.expect(verify(sha256_size, &hasher, &proof, bit, &chunk, &root));
    proof.inactive_peaks = 1;
    try testing.expect(!verify(sha256_size, &hasher, &proof, bit, &chunk, &root));
}

fn check_relocated_partial_chunk(
    comptime N: usize,
    full_chunks: u64,
    bagging: merkle.Bagging,
    tail_bits: u64,
) !void {
    const bits = TestBitMap(N).CHUNK_SIZE_BITS;
    const hasher = H.init(bagging);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(N, &storage, "test", &hasher);
    defer bitmap.deinit();
    bitmap.into_dirty();
    const tail_start = full_chunks * bits;
    for (0..tail_start) |i| try bitmap.push(i % 2 != 0);
    for (0..tail_bits) |i| try bitmap.push(i % 2 == 0);
    try bitmap.merkleize(&hasher);
    const root = bitmap.root();
    for ([_]u64{ 0, tail_start }) |prune_to| {
        try bitmap.prune_to_bit(prune_to);
        bitmap.into_dirty();
        try bitmap.merkleize(&hasher);
        try testing.expect(root.eql(bitmap.root()));
        var proof, const chunk = try bitmap.proof(&hasher, tail_start);
        defer proof.deinit(gpa);
        try testing.expectEqual(tail_start + tail_bits, proof.leaves);
        var targets: merkle.BoundedList(u64, 16) = .{};
        for (0..full_chunks + 2) |target| targets.append(target);
        targets.append(full_chunks + 8);
        targets.append(@as(u64, std.math.maxInt(u32)) + 1);
        targets.append((merkle.mmr.Family.max_leaves - tail_bits) / bits);
        targets.append((std.math.maxInt(u64) - tail_bits) / bits);
        for (targets.slice()) |target_chunk| {
            var relocated = proof;
            relocated.leaves = target_chunk * bits + tail_bits;
            for (0..tail_bits + 1) |offset| {
                const bit = target_chunk * bits + offset;
                const valid = verify(N, &hasher, &relocated, bit, &chunk, &root);
                const expected = target_chunk == full_chunks and offset < tail_bits;
                try testing.expectEqual(expected, valid);
            }
        }
    }
}

test "bitmap verify rejects relocated partial chunk" {
    for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
        for ([_]u64{ 0, 1, 2, 3, 7 }) |full_chunks| {
            inline for (.{ 1, 32, 64 }) |n| {
                const bits = TestBitMap(n).CHUNK_SIZE_BITS;
                for ([_]u64{ 1, 2, bits - 1 }) |tail_bits| {
                    try check_relocated_partial_chunk(n, full_chunks, bagging, tail_bits);
                }
            }
        }
    }
}

test "bitmap verify rejects tampered length" {
    const bits = TestBitMap(1).CHUNK_SIZE_BITS;
    const max_bits = 8 * bits + 1;
    for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
        const hasher = H.init(bagging);
        var storage = Storage.init(gpa);
        defer storage.deinit();
        var bitmap = try open(1, &storage, "test", &hasher);
        defer bitmap.deinit();
        for (1..max_bits + 1) |bit_len| {
            bitmap.into_dirty();
            try bitmap.push(bit_len % 2 == 0);
            try bitmap.merkleize(&hasher);
            const root = bitmap.root();
            var bit: u64 = 0;
            while (bit < bit_len) : (bit += bits) {
                var proof, const chunk = try bitmap.proof(&hasher, bit);
                defer proof.deinit(gpa);
                var claims: merkle.BoundedList(u64, max_bits + 5) = .{};
                for (0..max_bits + 1) |claim| claims.append(claim);
                claims.append((@as(u64, std.math.maxInt(u32)) + 1) * bits);
                claims.append((@as(u64, std.math.maxInt(u32)) + 1) * bits + 1);
                claims.append(merkle.mmr.Family.max_leaves);
                claims.append(std.math.maxInt(u64));
                for (claims.slice()) |claimed_len| {
                    proof.leaves = claimed_len;
                    const valid = verify(1, &hasher, &proof, bit, &chunk, &root);
                    try testing.expectEqual(claimed_len == bit_len, valid);
                }
            }
        }
    }
}

test "bitmap empty then one" {
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(sha256_size, &storage, "test", &hasher);
    defer bitmap.deinit();
    try testing.expectEqual(@as(u64, 0), bitmap.len());
    try testing.expectEqual(@as(usize, 0), bitmap.pruned_chunks());
    try bitmap.prune_to_bit(0);
    try testing.expectEqual(@as(usize, 0), bitmap.pruned_chunks());
    const empty_root = bitmap.root();
    bitmap.into_dirty();
    try bitmap.push(true);
    try bitmap.merkleize(&hasher);
    const one_root = bitmap.root();
    try testing.expect(!empty_root.eql(one_root));
    try bitmap.prune_to_bit(1);
    try testing.expectEqual(@as(u64, 1), bitmap.len());
    const tail, const used = bitmap.last_chunk();
    try testing.expect(!std.mem.allEqual(u8, &tail, 0));
    try testing.expectEqual(@as(u64, 1), used);
    try testing.expectEqual(@as(usize, 0), bitmap.pruned_chunks());
    try testing.expect(one_root.eql(bitmap.root()));
    bitmap.into_dirty();
    for (0..chunk_bits - 1) |i| try bitmap.push(i % 2 != 0);
    try bitmap.merkleize(&hasher);
    try testing.expectEqual(@as(u64, 256), bitmap.len());
    const root = bitmap.root();
    try testing.expect(!one_root.eql(root));
    var proof, const chunk = try bitmap.proof(&hasher, 0);
    defer proof.deinit(gpa);
    try testing.expect(verify(sha256_size, &hasher, &proof, 255, &chunk, &root));
    try testing.expect(!verify(sha256_size, &hasher, &proof, 256, &chunk, &root));
    try bitmap.prune_to_bit(256);
    try testing.expectEqual(@as(u64, 256), bitmap.len());
    try testing.expectEqual(@as(usize, 1), bitmap.pruned_chunks());
    try testing.expectEqual(@as(u64, 256), bitmap.pruned_bits());
    try testing.expect(root.eql(bitmap.root()));
    try bitmap.prune_to_bit(10);
    try testing.expect(root.eql(bitmap.root()));
}

test "bitmap building" {
    const chunk = test_chunk(sha256_size, "test");
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var roots: [3]D = undefined;
    for (&roots, 0..) |*root, way| {
        var bitmap = try open(sha256_size, &storage, "test", &hasher);
        defer bitmap.deinit();
        bitmap.into_dirty();
        try bitmap.push_chunk(&chunk);
        switch (way) {
            0 => for (chunk) |byte| {
                for (0..8) |j| try bitmap.push(byte & (@as(u8, 1) << @intCast(j)) != 0);
            },
            1 => try bitmap.push_chunk(&chunk),
            else => for (chunk) |byte| try bitmap.push_byte(byte),
        }
        try testing.expectEqual(@as(u64, 512), bitmap.len());
        try bitmap.merkleize(&hasher);
        root.* = bitmap.root();
        try testing.expect(root.eql(try bitmap.mmr.root(&hasher, 0)));
    }
    try testing.expect(roots[0].eql(roots[1]) and roots[0].eql(roots[2]));
}

fn push_chunks(bitmap: *Map, names: []const []const u8) !void {
    for (names) |name| try bitmap.push_chunk(&test_chunk(sha256_size, name));
}

test "bitmap root boundaries" {
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(sha256_size, &storage, "test", &hasher);
    defer bitmap.deinit();
    bitmap.into_dirty();
    try push_chunks(&bitmap, &.{ "test", "test2" });
    try bitmap.merkleize(&hasher);
    const root = bitmap.root();
    bitmap.into_dirty();
    try bitmap.push(true);
    try bitmap.merkleize(&hasher);
    const new_root = bitmap.root();
    try testing.expect(!root.eql(new_root));
    try testing.expectEqual(@as(u64, 3), bitmap.size()); // Excludes the trailing bits.
    for (0..sha256_size * 8 - 1) |_| {
        bitmap.into_dirty();
        try bitmap.push(false);
        try bitmap.merkleize(&hasher);
        try testing.expect(!new_root.eql(bitmap.root()));
    }
    try testing.expectEqual(@as(u64, 4), bitmap.size()); // The filled chunk joined the MMR.
    bitmap.into_dirty();
    try bitmap.push(false);
    try testing.expectEqual(@as(u64, 256 * 3 + 1), bitmap.len());
    try bitmap.merkleize(&hasher);
    const newer_root = bitmap.root();
    try testing.expect(!new_root.eql(newer_root));
    try bitmap.prune_to_bit(bitmap.len());
    try testing.expectEqual(@as(usize, 3), bitmap.pruned_chunks());
    try testing.expectEqual(@as(u64, 256 * 3 + 1), bitmap.len());
    try testing.expect(newer_root.eql(bitmap.root()));
}

fn flip_each_bit(bitmap: *Map, hasher: *const H, root: D, start: u64) !void {
    var bit = bitmap.len();
    while (bit > start) {
        bit -= 1;
        const value = bitmap.get_bit(bit);
        bitmap.into_dirty();
        try bitmap.set_bit(bit, !value);
        try bitmap.merkleize(hasher);
        try testing.expect(!root.eql(bitmap.root()));
        bitmap.into_dirty();
        try bitmap.set_bit(bit, value);
        try bitmap.merkleize(hasher);
        try testing.expect(root.eql(bitmap.root()));
    }
}

test "bitmap get set bits" {
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(sha256_size, &storage, "test", &hasher);
    defer bitmap.deinit();
    bitmap.into_dirty();
    try push_chunks(&bitmap, &.{ "test", "test2", "test3", "test4" });
    try bitmap.push_byte(0xf1);
    try bitmap.push(true);
    try bitmap.push(false);
    try bitmap.push(true);
    try bitmap.merkleize(&hasher);
    const root = bitmap.root();
    try flip_each_bit(&bitmap, &hasher, root, 0);
    const start_bit = sha256_size * 8 * 2;
    try bitmap.prune_to_bit(start_bit);
    try flip_each_bit(&bitmap, &hasher, root, start_bit);
}

fn flip_bit(comptime N: usize, bit: u64, chunk: *const [N]u8) [N]u8 {
    const Bits = @import("utils").bitmap.Prunable(N);
    var flipped = chunk.*;
    flipped[Bits.chunk_byte_offset(bit)] ^= Bits.chunk_byte_bitmask(bit);
    return flipped;
}

fn check_mmr_proof_verification(comptime N: usize) !void {
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(N, &storage, "test", &hasher);
    defer bitmap.deinit();
    bitmap.into_dirty();
    for (0..10) |i| {
        var name_buffer: [8]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "test{d}", .{i});
        try bitmap.push_chunk(&test_chunk(N, name));
    }
    try bitmap.push_byte(0xa6);
    for ([_]bool{ true, false, true, true, false }) |bit| try bitmap.push(bit);
    try bitmap.merkleize(&hasher);
    const root = bitmap.root();
    var prune_to: u64 = 0;
    while (prune_to < bitmap.len()) : (prune_to += 251) {
        try testing.expect(root.eql(bitmap.root()));
        try bitmap.prune_to_bit(prune_to);
        for (prune_to..bitmap.len()) |bit| {
            var proof, const chunk = try bitmap.proof(&hasher, bit);
            defer proof.deinit(gpa);
            try testing.expect(verify(N, &hasher, &proof, bit, &chunk, &root));
            const corrupted = flip_bit(N, bit, &chunk);
            try testing.expect(!verify(N, &hasher, &proof, bit, &corrupted, &root));
        }
    }
}

test "bitmap mmr proof verification" {
    try check_mmr_proof_verification(32);
    try check_mmr_proof_verification(64);
}

fn push_test_chunks(bitmap: *Map, first: usize, end: usize) !void {
    for (first..end) |i| {
        var name_buffer: [8]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "test{d}", .{i});
        try bitmap.push_chunk(&test_chunk(sha256_size, name));
    }
}

fn push_tail(bitmap: *Map) !void {
    try bitmap.push_byte(0xa6);
    for ([_]bool{ true, false, true }) |bit| try bitmap.push(bit);
}

test "bitmap persistence" {
    const partition = "bitmap-test";
    const full_chunk_count = 100;
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(sha256_size, &storage, partition, &hasher);
    defer bitmap.deinit();
    try testing.expectEqual(@as(u64, 0), bitmap.len());
    bitmap.into_dirty();
    try push_test_chunks(&bitmap, 0, full_chunk_count);
    try bitmap.merkleize(&hasher);
    const chunk_aligned_root = bitmap.root();
    bitmap.into_dirty();
    try push_tail(&bitmap);
    try bitmap.merkleize(&hasher);
    const root = bitmap.root();
    var i: usize = 10;
    while (i <= full_chunk_count) : (i += 10) {
        try bitmap.prune_to_bit(i * chunk_bits);
        try bitmap.write_pruned();
        bitmap.deinit();
        bitmap = try open(sha256_size, &storage, partition, &hasher);
        bitmap.into_dirty();
        try push_test_chunks(&bitmap, i, full_chunk_count);
        try testing.expectEqual(i, bitmap.pruned_chunks());
        try testing.expectEqual(@as(u64, full_chunk_count * 256), bitmap.len());
        try bitmap.merkleize(&hasher);
        try testing.expect(chunk_aligned_root.eql(bitmap.root()));
        bitmap.into_dirty();
        try push_tail(&bitmap);
        try bitmap.merkleize(&hasher);
        try testing.expect(root.eql(bitmap.root()));
    }
}

test "bitmap destroy removes persisted state" {
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(sha256_size, &storage, "test", &hasher);
    bitmap.into_dirty();
    try push_test_chunks(&bitmap, 0, 4);
    try bitmap.merkleize(&hasher);
    try bitmap.prune_to_bit(2 * chunk_bits);
    try bitmap.write_pruned();
    try bitmap.destroy();
    var reopened = try open(sha256_size, &storage, "test", &hasher);
    defer reopened.deinit();
    try testing.expectEqual(@as(usize, 0), reopened.pruned_chunks());
}

test "bitmap proof out of bounds" {
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(sha256_size, &storage, "test", &hasher);
    defer bitmap.deinit();
    bitmap.into_dirty();
    try push_chunks(&bitmap, &.{"test"});
    try bitmap.merkleize(&hasher);
    try testing.expectError(error.BitOutOfBounds, bitmap.proof(&hasher, 256));
    try testing.expectError(error.BitOutOfBounds, bitmap.proof(&hasher, 1000));
    for ([_]u64{ 0, 255 }) |bit| {
        var proof, _ = try bitmap.proof(&hasher, bit);
        proof.deinit(gpa);
    }
}

test "bitmap init rejects a missing pinned node" {
    const hasher = H.init(.forward_fold);
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var bitmap = try open(sha256_size, &storage, "test", &hasher);
    bitmap.into_dirty();
    try push_test_chunks(&bitmap, 0, 3);
    try bitmap.merkleize(&hasher);
    try bitmap.prune_to_bit(2 * chunk_bits);
    try bitmap.write_pruned();
    // Dropping a pinned node makes the restore fail rather than produce a wrong root.
    const Key = @import("utils").sequence.PrefixedU64;
    if (bitmap.store.remove(Key.init(0, 0))) |value| gpa.free(value);
    try bitmap.store.sync();
    bitmap.deinit();
    try testing.expectError(error.MissingNode, open(sha256_size, &storage, "test", &hasher));
}

// Fuzz: the `bitmap_operations` target. Operations run against a reference list of bits;
// reads must match it, every proof must verify (and fail for a flipped bit), and after each
// merkleize the root must equal that of a bitmap rebuilt from scratch with the same bits.
// One-byte chunks (commonware's target uses 32) let short inputs fill, merkleize, and prune
// many chunks.

const fuzz_operations_max = 100;
const fuzz_partition = "fuzz-mmr-bitmap-test-partition";
const FuzzMap = TestBitMap(1);
const fuzz_chunk_bits = FuzzMap.CHUNK_SIZE_BITS;

const FuzzState = struct {
    storage: *Storage,
    hasher: H,
    bitmap: FuzzMap,
    bits: std.ArrayList(bool) = .empty,

    fn ensure_dirty(self: *FuzzState) void {
        if (self.bitmap.merkleized) self.bitmap.into_dirty();
    }

    fn ensure_merkleized(self: *FuzzState) !void {
        if (self.bitmap.merkleized) return;
        try self.bitmap.merkleize(&self.hasher);
        try self.check_root();
    }

    /// The root equals a from-scratch rebuild over the reference bits.
    fn check_root(self: *FuzzState) !void {
        var scratch_storage = Storage.init(gpa);
        defer scratch_storage.deinit();
        var scratch = try FuzzMap.init(gpa, scratch_storage.storage(), "scratch", &self.hasher);
        defer scratch.deinit();
        scratch.into_dirty();
        for (self.bits.items) |bit| try scratch.push(bit);
        try scratch.merkleize(&self.hasher);
        try testing.expect(scratch.root().eql(self.bitmap.root()));
    }

    fn bit_count(self: *const FuzzState) u64 {
        return self.bits.items.len;
    }
};

fn fuzz_set_bit(state: *FuzzState, reader: *fuzz_bytes.Reader) !void {
    const offset: u64 = reader.int(u16);
    const value = reader.boolean();
    state.ensure_dirty();
    const count = state.bit_count();
    if (count == 0) return;
    const bit = @max(offset % count, state.bitmap.pruned_bits());
    if (bit >= count) return;
    try state.bitmap.set_bit(bit, value);
    state.bits.items[@intCast(bit)] = value;
}

fn fuzz_read(state: *FuzzState, reader: *fuzz_bytes.Reader) !void {
    const offset: u64 = reader.int(u16);
    const pruned = state.bitmap.pruned_bits();
    const count = state.bit_count();
    try testing.expectEqual(count, state.bitmap.len());
    if (count <= pruned) return;
    const bit = pruned + offset % (count - pruned);
    try testing.expectEqual(state.bits.items[@intCast(bit)], state.bitmap.get_bit(bit));
    const chunk = state.bitmap.get_chunk_containing(bit);
    const first = bit - bit % fuzz_chunk_bits;
    const end = @min(first + fuzz_chunk_bits, count);
    for (first..end) |b| {
        try testing.expectEqual(state.bits.items[b], FuzzMap.get_bit_from_chunk(chunk, b));
    }
    _, const used = state.bitmap.last_chunk();
    try testing.expect(used <= fuzz_chunk_bits);
}

fn fuzz_prune(state: *FuzzState, reader: *fuzz_bytes.Reader) !void {
    const offset: u64 = reader.int(u16);
    try state.ensure_merkleized();
    const count = state.bit_count();
    if (count == 0) return;
    const bit = offset % (count + 1);
    if (bit < state.bitmap.pruned_bits()) return;
    const root = state.bitmap.root();
    try state.bitmap.prune_to_bit(bit);
    try testing.expect(state.bitmap.pruned_bits() <= bit);
    try testing.expect(root.eql(state.bitmap.root()));
}

fn fuzz_proof(state: *FuzzState, reader: *fuzz_bytes.Reader) !void {
    const offset: u64 = reader.int(u16);
    try state.ensure_merkleized();
    const pruned = state.bitmap.pruned_bits();
    const count = state.bit_count();
    if (count <= pruned) return;
    const bit = pruned + offset % (count - pruned);
    var proof, const chunk = try state.bitmap.proof(&state.hasher, bit);
    defer proof.deinit(gpa);
    const root = state.bitmap.root();
    try testing.expect(FuzzMap.verify_bit_inclusion(&state.hasher, &proof, bit, &chunk, &root));
    const flipped = flip_bit(1, bit, &chunk);
    const forged = FuzzMap.verify_bit_inclusion(&state.hasher, &proof, bit, &flipped, &root);
    try testing.expect(!forged);
}

fn fuzz_restore(state: *FuzzState) !void {
    state.bitmap.deinit();
    state.bitmap = try FuzzMap.init(gpa, state.storage.storage(), fuzz_partition, &state.hasher);
    // Only the pruning state persists, so the bitmap reopens with just its pruned bits.
    const count = state.bitmap.len();
    try testing.expectEqual(count, state.bitmap.pruned_bits());
    try testing.expect(count <= state.bit_count());
    state.bits.shrinkRetainingCapacity(@intCast(count));
    try state.check_root();
}

fn fuzz_step(state: *FuzzState, reader: *fuzz_bytes.Reader) !void {
    // Appends are weighted (4 of 12) so inputs fill, merkleize, and mutate whole chunks.
    switch (reader.int(u8) % 12) {
        0...3 => {
            const bit = reader.boolean();
            state.ensure_dirty();
            try state.bitmap.push(bit);
            try state.bits.append(gpa, bit);
        },
        4 => try fuzz_set_bit(state, reader),
        5 => try fuzz_read(state, reader),
        6 => try fuzz_prune(state, reader),
        7 => try state.ensure_merkleized(),
        8 => {
            const position: u64 = reader.int(u16);
            try state.ensure_merkleized();
            if (state.bitmap.size() > 0) _ = state.bitmap.get_node(position % state.bitmap.size());
        },
        9 => try fuzz_proof(state, reader),
        10 => try fuzz_restore(state),
        11 => {
            try state.ensure_merkleized();
            try state.bitmap.write_pruned();
        },
        else => unreachable,
    }
}

fn fuzz_run(bytes: []const u8) anyerror!void {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    const hasher = H.init(.forward_fold);
    var state: FuzzState = .{
        .storage = &storage,
        .hasher = hasher,
        .bitmap = try FuzzMap.init(gpa, storage.storage(), fuzz_partition, &hasher),
    };
    defer state.bits.deinit(gpa);
    defer state.bitmap.deinit();
    var reader = fuzz_bytes.Reader.init(bytes);
    var operations: u32 = 0;
    while (!reader.done() and operations < fuzz_operations_max) : (operations += 1) {
        try fuzz_step(&state, &reader);
    }
    try state.ensure_merkleized();
}

test "fuzz bitmap operations (seeded)" {
    try fuzz_bytes.seeded(1024, 0x6269746d6170, 128, fuzz_run);
}

test "fuzz bitmap operations" {
    try testing.fuzz({}, fuzz_bytes.smith(1024, fuzz_run), .{});
}
