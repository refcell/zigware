//! A persistent index that maps sparse indices to fixed-size values.
//!
//! Port of commonware's `storage/src/ordinal`. An `Ordinal` is a collection of blobs holding
//! ordered fixed-size records. Because records are fixed size, file position corresponds
//! directly to index, and unlike the contiguous fixed journal, an ordinal accepts writes in
//! any order.
//!
//! # Design
//!
//! - Each record is `[V][crc32(V)]` (CRC32C, big-endian).
//! - Index `N` lives in section `N / items_per_blob`, at offset
//!   `(N % items_per_blob) * record_size` of that section's blob.
//! - An `RMap` tracks which indices have been written.
//! - A record is written once: `put` ignores an index that already holds one.
//!
//! Blobs are named by the big-endian bytes of their section number.
//!
//! # Atomicity
//!
//! New data is written eagerly but only synced by `sync`, so a crash before `sync` may lose
//! some writes. For atomic sparse writes, pair the ordinal with a bitmap persisted in
//! `storage.metadata` that marks which records were committed.
//!
//! # Recovery
//!
//! Pass the committed bits to `init` to recover existing data. A bitmap marks the committed
//! records of its section and rebuilds the in-memory ranges without re-reading them (a damaged
//! marked record surfaces at `get`). A section listed with a null bitmap is validated record
//! by record and must hold exactly `items_per_blob` records. Stored sections omitted from the
//! bits, or whose bitmap marks nothing, are removed unopened. Stored records whose bits are
//! unset are cleared. Missing committed records, and CRC-invalid records of whole sections,
//! fail with `MissingRecord`. Null bits (or an empty list) remove every stored section.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");

const storage = @import("storage.zig");
pub const Ordinal = storage.Ordinal;
pub const Record = storage.Record;
pub const Error = storage.Error;
pub const section_name = storage.section_name;

/// The committed-record bitmap of one section (commonware's default `BitMap`).
pub const BitMap = utils.BitMap(utils.bitmap.DEFAULT_CHUNK_SIZE);

/// The committed records of one section: a bitmap of its records, or null for every record
/// (commonware's `BTreeMap<u64, &Option<BitMap>>` entry). Lists are sorted by section.
pub const SectionBits = struct {
    section: u64,
    bits: ?*const BitMap,
};

/// Configuration for an `Ordinal`. The ordinal borrows `partition`, which must outlive it.
pub const Config = struct {
    /// The partition holding the index blobs.
    partition: []const u8,
    /// The maximum number of items in each index blob.
    items_per_blob: u64,
    /// The write buffer size of each blob.
    write_buffer: usize,
    /// The read buffer size used on restart.
    replay_buffer: usize,

    pub fn validate(config: Config) void {
        assert(config.partition.len > 0);
        assert(config.items_per_blob > 0);
        assert(config.write_buffer > 0);
        assert(config.replay_buffer > 0);
    }
};

/// Bits marking every index in `indices`, one bitmap of `items_per_blob` bits per section
/// (commonware's `storage::utils::bits_for_indices`). Free with `free_bits`.
pub fn bits_for_indices(
    gpa: Allocator,
    items_per_blob: u64,
    indices: []const u64,
) Allocator.Error![]SectionBits {
    assert(items_per_blob > 0);
    var list: std.ArrayList(SectionBits) = .empty;
    errdefer list.deinit(gpa);
    errdefer destroy_bitmaps(gpa, list.items);
    for (indices) |index| {
        const section = index / items_per_blob;
        var position: usize = 0;
        while (position < list.items.len and list.items[position].section < section) {
            position += 1;
        }
        if (position == list.items.len or list.items[position].section != section) {
            const bitmap = try gpa.create(BitMap);
            errdefer gpa.destroy(bitmap);
            bitmap.* = try BitMap.zeroes(gpa, items_per_blob);
            errdefer bitmap.deinit(gpa);
            try list.insert(gpa, position, .{ .section = section, .bits = bitmap });
        }
        const bitmap: *BitMap = @constCast(list.items[position].bits.?);
        bitmap.set(index % items_per_blob, true);
    }
    return list.toOwnedSlice(gpa);
}

/// Free a list returned by `bits_for_indices`.
pub fn free_bits(gpa: Allocator, list: []const SectionBits) void {
    destroy_bitmaps(gpa, list);
    gpa.free(list);
}

fn destroy_bitmaps(gpa: Allocator, list: []const SectionBits) void {
    for (list) |entry| {
        const bitmap: *BitMap = @constCast(entry.bits orelse continue);
        bitmap.deinit(gpa);
        gpa.destroy(bitmap);
    }
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
    _ = @import("conformance_test.zig");
}

test "bits for indices" {
    // commonware's `utils.rs` `test_bits_for_indices`.
    const gpa = std.testing.allocator;
    const empty = try bits_for_indices(gpa, 10, &.{});
    defer free_bits(gpa, empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    // Out of order, so a list that only appends would misorder its sections.
    const bits = try bits_for_indices(gpa, 10, &.{ 25, 0, 10, 1, 9 });
    defer free_bits(gpa, bits);
    const expected = [_]struct { section: u64, set: []const u64 }{
        .{ .section = 0, .set = &.{ 0, 1, 9 } },
        .{ .section = 1, .set = &.{0} },
        .{ .section = 2, .set = &.{5} },
    };
    try std.testing.expectEqual(expected.len, bits.len);
    for (expected, bits) |want, got| {
        try std.testing.expectEqual(want.section, got.section);
        const bitmap = got.bits.?;
        try std.testing.expectEqual(@as(u64, 10), bitmap.len());
        try std.testing.expectEqual(@as(u64, want.set.len), bitmap.count_ones());
        for (want.set) |bit| try std.testing.expect(bitmap.get(bit));
    }
}
