//! Blob wrappers for reading and writing data with integrity guarantees, plus a page cache that
//! manages read caching over the data (commonware's `runtime/src/utils/buffer/paged`).
//!
//! # Page-oriented structure
//!
//! Blob data is stored in _pages_ having a _logical page size_ dictated by the managing page
//! cache: the payload bytes stored per page. A _physical page_ is what a page occupies on disk:
//! the logical page followed by a 12-byte _CRC record_:
//!
//! ```text
//! | len1 (2 bytes) | crc1 (4 bytes) | len2 (2 bytes) | crc2 (4 bytes) |
//! ```
//!
//! All integers are big-endian and the CRC is CRC-32C. An unqualified page size always denotes
//! the logical size; physical sizes carry a `physical_page_size` name.
//!
//! Two checksums are stored so that re-writing a partial page cannot destroy the valid checksum
//! for its last durable contents. Each rewrite covers the whole physical page: the new checksum
//! lands in the slot not protecting the durable contents, while the durable prefix and its
//! protected checksum are resubmitted byte-identically. A checksum covers the first `len` bytes
//! of the page; other bytes are ignored. A checksum with length 0 is never valid. If both are
//! valid, the one with the larger `len` is authoritative. Partial-page shrink first makes the
//! shorter checksum durable in the alternate slot, then invalidates the old longer checksum.
//!
//! A torn write can leave part of a checksum in the slot it targeted, beside the bytes that
//! checksum covered. Opening a blob for writing therefore zeroes that slot on a partial last
//! page when it is neither zero nor the checksum of a prefix of the page's valid bytes.
//!
//! A _full_ page's checksum stores a `len` equal to the logical page size. All pages in a blob
//! are full except possibly the last.

const std = @import("std");
const assert = std.debug.assert;
const Crc32 = @import("cryptography").crc32.Crc32;
const storage_mod = @import("../../storage.zig");
const Storage = storage_mod.Storage;

pub const cache = @import("cache.zig");
pub const tip = @import("tip.zig");
pub const sealed = @import("sealed.zig");
pub const view = @import("view.zig");
pub const writer = @import("writer.zig");
pub const CacheRef = cache.CacheRef;
pub const Sealed = sealed.Sealed;
pub const View = view.View;
pub const Writer = writer.Writer;
pub const Replay = writer.Replay;
pub const read_range = writer.read_range;
pub const read_tail = writer.read_tail;

/// Size in bytes of the checksum record appended to each logical page.
pub const checksum_size: u64 = 12;
const slot_len_size: usize = 2;
const slot_size: usize = 6;

/// Errors from paged blob access: storage errors plus a page failing its checksum.
pub const Error = storage_mod.Error || error{InvalidChecksum};

/// The logical page size whose physical page occupies exactly `physical_page_size` bytes.
///
/// Changing the page size of a store holding data is a destructive format migration: its
/// pages fail their integrity check and reopening for writing truncates them.
pub fn page_size(comptime physical_page_size: u32) u16 {
    comptime assert(std.math.isPowerOfTwo(physical_page_size));
    comptime assert(physical_page_size > checksum_size);
    comptime assert(physical_page_size - checksum_size <= std.math.maxInt(u16));
    return @intCast(physical_page_size - checksum_size);
}

/// One of a page footer's two CRC slots, laid out back to back after the page data.
pub const Slot = enum(u1) {
    first,
    second,

    /// Byte offset of this slot within the page's CRC footer.
    pub fn offset(self: Slot) usize {
        return @as(usize, @backingInt(self)) * slot_size;
    }

    pub fn other(self: Slot) Slot {
        return if (self == .first) .second else .first;
    }
};

/// The checksum covering a page's logical bytes and the footer slot that holds it.
pub const ActiveChecksum = struct {
    slot: Slot,
    len: u16,
    crc: u32,
};

/// A page's CRC record. The CRC with the larger length is authoritative.
pub const Checksum = struct {
    len1: u16,
    crc1: u32,
    len2: u16,
    crc2: u32,

    pub const size: usize = 12;

    comptime {
        assert(size == checksum_size);
        assert(size == 2 * slot_size);
    }

    /// A record with `len`/`crc` in the first slot and the second slot zeroed.
    pub fn init(len: u16, crc: u32) Checksum {
        return .{ .len1 = len, .crc1 = crc, .len2 = 0, .crc2 = 0 };
    }

    pub fn decode(bytes: *const [size]u8) Checksum {
        return .{
            .len1 = std.mem.readInt(u16, bytes[0..2], .big),
            .crc1 = std.mem.readInt(u32, bytes[2..6], .big),
            .len2 = std.mem.readInt(u16, bytes[6..8], .big),
            .crc2 = std.mem.readInt(u32, bytes[8..12], .big),
        };
    }

    pub fn to_bytes(self: Checksum) [size]u8 {
        var bytes: [size]u8 = undefined;
        std.mem.writeInt(u16, bytes[0..2], self.len1, .big);
        std.mem.writeInt(u32, bytes[2..6], self.crc1, .big);
        std.mem.writeInt(u16, bytes[6..8], self.len2, .big);
        std.mem.writeInt(u32, bytes[8..12], self.crc2, .big);
        assert(std.meta.eql(decode(&bytes), self));
        return bytes;
    }

    /// The slot holding the authoritative (longer) CRC; the first slot wins ties.
    pub fn authoritative(self: Checksum) Slot {
        return if (self.len1 >= self.len2) .first else .second;
    }

    pub fn get_slot(self: Checksum, slot: Slot) struct { u16, u32 } {
        return switch (slot) {
            .first => .{ self.len1, self.crc1 },
            .second => .{ self.len2, self.crc2 },
        };
    }

    /// The active checksum if `page` (exactly one physical page) is valid: the authoritative
    /// slot if it verifies, else the other slot (an interrupted write corrupts only the slot
    /// it was rewriting).
    pub fn validate_page(page: []const u8) ?ActiveChecksum {
        if (page.len < size) return null;
        const crc_start = page.len - size;
        const record = decode(page[crc_start..][0..size]);
        const preferred = record.authoritative();
        if (record.validate_slot(preferred, page, crc_start)) |active| return active;
        return record.validate_slot(preferred.other(), page, crc_start);
    }

    /// Validate one slot independently of the footer's authority ordering.
    pub fn validate_slot(
        self: Checksum,
        slot: Slot,
        page: []const u8,
        crc_start: usize,
    ) ?ActiveChecksum {
        const len, const crc = self.get_slot(slot);
        // A zero length marks an inactive slot (committed pages are never empty), which also
        // rejects zero-filled pages from unwritten storage.
        if (len == 0) return null;
        // The checksum covers only logical page bytes, not the footer itself.
        if (len > crc_start) return null;
        if (Crc32.checksum(page[0..len]) != crc) return null;
        return .{ .slot = slot, .len = len, .crc = crc };
    }

    /// Whether the slot of `page` not holding `active` is zeroed or holds the checksum of a
    /// prefix of the bytes `active` covers. Other content may be part of a checksum over later
    /// bytes, and a torn write to the slot could complete it.
    pub fn other_slot_is_inert(page: []const u8, active: ActiveChecksum) bool {
        const crc_start = page.len - size;
        const record = decode(page[crc_start..][0..size]);
        const slot = active.slot.other();
        const len, const crc = record.get_slot(slot);
        if (len == 0 and crc == 0) return true;
        const checksum = record.validate_slot(slot, page, crc_start) orelse return false;
        return checksum.len <= active.len;
    }

    /// One whole slot (`[len: u16][crc: u32]`) in its storage representation.
    pub fn slot_bytes(len: u16, crc: u32) [slot_size]u8 {
        var bytes: [slot_size]u8 = undefined;
        std.mem.writeInt(u16, bytes[0..2], len, .big);
        std.mem.writeInt(u32, bytes[2..6], crc, .big);
        return bytes;
    }

    /// Just a slot's leading `len` field. Rewriting only it commits a previously staged slot
    /// without disturbing its durable CRC.
    pub fn slot_len_bytes(len: u16) [slot_len_size]u8 {
        var bytes: [slot_len_size]u8 = undefined;
        std.mem.writeInt(u16, &bytes, len, .big);
        return bytes;
    }
};

/// A CRC record for a new checksum, and its active checksum. An old checksum stays in its
/// original slot while the new one goes in the other slot.
pub fn build_crc_record(
    new_len: u16,
    new_crc: u32,
    old: ?ActiveChecksum,
) struct { Checksum, ActiveChecksum } {
    const previous = old orelse return .{
        Checksum.init(new_len, new_crc),
        .{ .slot = .first, .len = new_len, .crc = new_crc },
    };
    const record: Checksum = switch (previous.slot) {
        .first => .{
            .len1 = previous.len,
            .crc1 = previous.crc,
            .len2 = new_len,
            .crc2 = new_crc,
        },
        .second => .{
            .len1 = new_len,
            .crc1 = new_crc,
            .len2 = previous.len,
            .crc2 = previous.crc,
        },
    };
    return .{ record, .{ .slot = previous.slot.other(), .len = new_len, .crc = new_crc } };
}

/// The CRC-validated logical length of a raw physical page, re-deriving the slot arbitration
/// independently of `Checksum.validate_page` so fuzz oracles do not trust the reader they
/// check. Null when neither slot verifies.
pub fn page_len(page: []const u8, logical_page_size: usize) ?usize {
    if (page.len != logical_page_size + checksum_size) return null;
    const footer = page[logical_page_size..];
    const lens = [2]usize{
        std.mem.readInt(u16, footer[0..2], .big),
        std.mem.readInt(u16, footer[6..8], .big),
    };
    const crcs = [2]u32{
        std.mem.readInt(u32, footer[2..6], .big),
        std.mem.readInt(u32, footer[8..12], .big),
    };
    const preferred: usize = @intFromBool(lens[1] > lens[0]);
    for ([2]usize{ preferred, preferred ^ 1 }) |slot| {
        const len = lens[slot];
        if (len > 0 and len <= logical_page_size and Crc32.checksum(page[0..len]) == crcs[slot]) {
            return len;
        }
    }
    return null;
}

/// The blob offset and length of physical page `page` for `logical_page_size`-byte pages.
pub fn physical_page(page: u64, logical_page_size: u64) Error!struct { u64, usize } {
    const physical_page_size = logical_page_size + checksum_size;
    const start = std.math.mul(u64, page, physical_page_size) catch return error.OffsetOverflow;
    return .{ start, @intCast(physical_page_size) };
}

/// Read physical page `page` into `scratch` (one physical page) and validate it, returning
/// its logical bytes (a prefix of `scratch`) and active checksum.
pub fn read_page_with_checksum(
    blob: anytype,
    page: u64,
    logical_page_size: u64,
    scratch: []u8,
    options: storage_mod.ReadOptions,
) Error!struct { []u8, ActiveChecksum } {
    const start, const len = try physical_page(page, logical_page_size);
    assert(scratch.len == len);
    try blob.read_at_options(start, scratch, options);
    const active = Checksum.validate_page(scratch) orelse return error.InvalidChecksum;
    return .{ scratch[0..active.len], active };
}

/// Flip one byte inside physical page `page` of the blob `name`, leaving every other page
/// valid: a torn interior page. The target must be followed by a complete physical page.
pub fn corrupt_page(
    storage: Storage,
    partition: []const u8,
    name: []const u8,
    page: u64,
    logical_page_size: u64,
) !void {
    // Every valid checksum slot covers byte zero, including a shorter fallback slot.
    const physical_page_size = logical_page_size + checksum_size;
    const offset = page * physical_page_size;
    const opened = try storage.open(partition, name);
    defer opened.blob.close();
    assert(offset + physical_page_size * 2 <= opened.len); // An interior page.
    var byte: [1]u8 = undefined;
    try opened.blob.read_at(offset, &byte);
    byte[0] ^= 0xFF;
    try opened.blob.write_at(offset, &byte, .{});
    try opened.blob.sync();
}

const testing = std.testing;

fn test_page(comptime logical: usize, data: []const u8, record: Checksum) [logical + 12]u8 {
    var page: [logical + 12]u8 = @splat(0);
    @memcpy(page[0..data.len], data);
    page[logical..].* = record.to_bytes();
    return page;
}

test "checksum record encoding is big-endian" {
    const record: Checksum = .{ .len1 = 0x0102, .crc1 = 0x03040506, .len2 = 7, .crc2 = 8 };
    const expected = [_]u8{ 1, 2, 3, 4, 5, 6, 0, 7, 0, 0, 0, 8 };
    try testing.expectEqualSlices(u8, &expected, &record.to_bytes());
    try testing.expectEqual(record, Checksum.decode(&expected));
    try testing.expectEqual(Slot.first, record.authoritative());
    try testing.expectEqual(Slot.first, Checksum.init(5, 1).authoritative());
    const second: Checksum = .{ .len1 = 1, .crc1 = 0, .len2 = 2, .crc2 = 0 };
    try testing.expectEqual(Slot.second, second.authoritative());
}

test "page size helper" {
    try testing.expectEqual(@as(u16, 4084), page_size(4096));
    try testing.expectEqual(@as(u16, 116), page_size(128));
}

test "validate page prefers the authoritative slot and falls back" {
    const data = "hello world";
    const crc_short = Crc32.checksum(data[0..5]);
    const crc_long = Crc32.checksum(data);
    // Both valid: the longer wins.
    const both_record: Checksum = .{ .len1 = 5, .crc1 = crc_short, .len2 = 11, .crc2 = crc_long };
    const both = test_page(16, data, both_record);
    const active = Checksum.validate_page(&both).?;
    try testing.expectEqual(ActiveChecksum{ .slot = .second, .len = 11, .crc = crc_long }, active);
    try testing.expectEqual(@as(?usize, 11), page_len(&both, 16));
    try testing.expect(Checksum.other_slot_is_inert(&both, active));

    // A torn authoritative slot falls back to the other.
    const torn = test_page(16, data, .{ .len1 = 5, .crc1 = crc_short, .len2 = 11, .crc2 = 1 });
    try testing.expectEqual(@as(u16, 5), Checksum.validate_page(&torn).?.len);
    try testing.expectEqual(@as(?usize, 5), page_len(&torn, 16));

    // A longer checksum in the other slot is not inert.
    const fallback = Checksum.validate_page(&torn).?;
    try testing.expect(!Checksum.other_slot_is_inert(&both, .{
        .slot = .first,
        .len = 5,
        .crc = crc_short,
    }));
    try testing.expect(!Checksum.other_slot_is_inert(&torn, fallback));

    // Zero lengths, lengths past the page, and zeroed pages never validate.
    const zero: [28]u8 = @splat(0);
    try testing.expect(Checksum.validate_page(&zero) == null);
    try testing.expect(page_len(&zero, 16) == null);
    const too_long = test_page(16, data, .{ .len1 = 17, .crc1 = crc_long, .len2 = 0, .crc2 = 0 });
    try testing.expect(Checksum.validate_page(&too_long) == null);
    try testing.expect(Checksum.validate_page(zero[0..11]) == null);
}

test "validate page rejects bad checksums and ties go to the first slot" {
    // mod.rs's equal-lengths, invalid-crc, corrupted-data, and no-fallback cases.
    const tie: Checksum = .{ .len1 = 100, .crc1 = 0xAAAAAAAA, .len2 = 100, .crc2 = 0xBBBBBBBB };
    try testing.expectEqual(Slot.first, tie.authoritative());
    const data = "hello world";
    const crc = Crc32.checksum(data);
    const wrong = test_page(64, data, Checksum.init(data.len, 0xBADBADBA));
    try testing.expect(Checksum.validate_page(&wrong) == null);
    var corrupted = test_page(64, data, Checksum.init(data.len, crc));
    try testing.expect(Checksum.validate_page(&corrupted) != null);
    corrupted[0] = 0xFF;
    try testing.expect(Checksum.validate_page(&corrupted) == null);
    const primary_only: Checksum = .{ .len1 = data.len, .crc1 = 0xBAD1DEA, .len2 = 0, .crc2 = 0 };
    const no_fallback = test_page(64, data, primary_only);
    try testing.expect(Checksum.validate_page(&no_fallback) == null);
}

test "build crc record preserves the old slot" {
    const fresh, const fresh_active = build_crc_record(3, 9, null);
    try testing.expectEqual(Checksum.init(3, 9), fresh);
    try testing.expectEqual(Slot.first, fresh_active.slot);

    const old: ActiveChecksum = .{ .slot = .first, .len = 2, .crc = 7 };
    const record, const active = build_crc_record(5, 11, old);
    try testing.expectEqual(Checksum{ .len1 = 2, .crc1 = 7, .len2 = 5, .crc2 = 11 }, record);
    try testing.expectEqual(ActiveChecksum{ .slot = .second, .len = 5, .crc = 11 }, active);
    const record2, const active2 = build_crc_record(6, 12, active);
    try testing.expectEqual(Checksum{ .len1 = 6, .crc1 = 12, .len2 = 5, .crc2 = 11 }, record2);
    try testing.expectEqual(Slot.first, active2.slot);
}

/// commonware's `CodecConformance<Checksum>`: an arbitrary record (four fields in order, as its
/// `Arbitrary` impl draws them) encoded to its 12 bytes.
const ChecksumConformance = struct {
    const codec = @import("codec");

    pub fn commit(gpa: std.mem.Allocator, seed: u64) ![]u8 {
        const record = try codec.arbitrary.generate(Checksum, arbitrary_checksum, gpa, seed);
        const bytes = record.to_bytes();
        assert(std.meta.eql(Checksum.decode(&bytes), record));
        return gpa.dupe(u8, &bytes);
    }

    fn arbitrary_checksum(
        _: std.mem.Allocator,
        u: *codec.arbitrary.Unstructured,
    ) !Checksum {
        const len1 = u.int(u16);
        const crc1 = u.int(u32);
        const len2 = u.int(u16);
        const crc2 = u.int(u32);
        return .{ .len1 = len1, .crc1 = crc1, .len2 = len2, .crc2 = crc2 };
    }
};

test "paged conformance: CodecConformance<Checksum>" {
    const conformance = @import("conformance");
    try conformance.verify(
        ChecksumConformance,
        testing.allocator,
        "commonware_runtime::utils::buffer::paged::tests::conformance::" ++
            "CodecConformance<Checksum>",
        conformance.default_cases,
        @embedFile("../../conformance.toml"),
    );
}

test {
    std.testing.refAllDecls(@This());
}
