//! Tests for the glob, ported from commonware's `segmented/glob.rs`.
//!
//! `test_glob_get_view` (two reads share one tip buffer) has no counterpart: decoded values
//! own their memory. Compressed entries are compared with this port's own compressor, which
//! differs from libzstd by design (see the lane file).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const Crc32 = @import("cryptography").crc32.Crc32;
const mocks = runtime.buffer.mocks;
const glob_mod = @import("glob.zig");
const manager_mod = @import("manager.zig");
const zstd = @import("../zstd.zig");

const Storage = mocks.Storage;
const gpa = testing.allocator;
const partition = "test-partition";
const Bytes = []const u8;
const bytes_cfg: codec.Cfg(Bytes) = .{ .range = .full(), .item = {} };

fn test_cfg(comptime V: type) glob_mod.Config(V) {
    return .{
        .partition = partition,
        .codec_config = if (V == Bytes) bytes_cfg else {},
        .write_buffer = 1024,
    };
}

fn init_glob(
    comptime V: type,
    storage: *Storage,
    cfg: glob_mod.Config(V),
) !glob_mod.Glob(V) {
    var recovery = try glob_mod.Recovery(V).init(gpa, storage.interface(), cfg);
    return recovery.finish();
}

/// Sync, close, and reopen with `section` shortened to `end` (commonware's
/// `test_reopen_section`).
fn reopen_section(
    comptime V: type,
    storage: *Storage,
    glob: *glob_mod.Glob(V),
    cfg: glob_mod.Config(V),
    section: u64,
    end: u64,
) !void {
    try glob.sync_all();
    glob.deinit();
    var recovery = try glob_mod.Recovery(V).init(gpa, storage.interface(), cfg);
    errdefer recovery.deinit();
    try recovery.truncate_sections(&.{.{ .section = section, .size = end }});
    glob.* = recovery.finish();
}

test "glob: append and get" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var glob = try init_glob(i32, &storage, test_cfg(i32));
    const entry = try glob.append(1, 42);
    try testing.expectEqual(0, entry.offset);
    try testing.expectEqual(42, try glob.get(1, entry.offset, entry.size));
    try glob.sync(&.{1});
    try testing.expectEqual(42, try glob.get(1, entry.offset, entry.size));
    try glob.destroy();
}

test "glob: multiple values" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var glob = try init_glob(i32, &storage, test_cfg(i32));
    const values = [_]i32{ 1, 2, 3, 4, 5 };
    var entries: [values.len]glob_mod.Entry = undefined;
    for (values, &entries) |value, *entry| entry.* = try glob.append(1, value);
    for (values, entries) |value, entry| {
        try testing.expectEqual(value, try glob.get(1, entry.offset, entry.size));
    }
    try glob.destroy();
}

test "glob: with compression" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var cfg = test_cfg([100]u8);
    cfg.compression = 3;
    var glob = try init_glob([100]u8, &storage, cfg);
    const value: [100]u8 = @splat(0); // Compressible data.
    const entry = try glob.append(1, value);
    // Size should be smaller due to compression.
    try testing.expect(entry.size < 100 + 4);
    try testing.expectEqual(value, try glob.get(1, entry.offset, entry.size));
    try glob.destroy();
}

/// Reference entry bytes: zstd frame of the encoding, then its big-endian CRC32.
fn expected_entry(value: Bytes) ![]u8 {
    const encoded = try codec.encode(Bytes, gpa, value);
    defer gpa.free(encoded);
    var expected: std.ArrayList(u8) = .empty;
    errdefer expected.deinit(gpa);
    _ = try zstd.compress_into(gpa, encoded, &expected);
    var trailer: [4]u8 = undefined;
    std.mem.writeInt(u32, &trailer, Crc32.checksum(expected.items), .big);
    try expected.appendSlice(gpa, &trailer);
    return expected.toOwnedSlice(gpa);
}

fn expect_stored(glob: *glob_mod.Glob(Bytes), entry: glob_mod.Entry, value: Bytes) !void {
    const expected = try expected_entry(value);
    defer gpa.free(expected);
    try testing.expectEqual(expected.len, entry.size);
    const writer = (try glob.manager.get(1)).?;
    const stored = try gpa.alloc(u8, entry.size);
    defer gpa.free(stored);
    try writer.read_at(entry.offset, stored);
    try testing.expectEqualSlices(u8, expected, stored);
    const got = try glob.get(1, entry.offset, entry.size);
    defer codec.free(Bytes, gpa, got);
    try testing.expectEqualSlices(u8, value, got);
}

test "glob: compressed entries match reference format" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var cfg = test_cfg(Bytes);
    cfg.compression = 19;
    var glob = try init_glob(Bytes, &storage, cfg);
    var values: [6][]u8 = undefined;
    for (values[0..5], [_]usize{ 0, 1, 127, 4096, 70_000 }) |*value, len| {
        value.* = try gpa.alloc(u8, len);
        for (value.*, 0..) |*byte, i| byte.* = @intCast(i % 7);
    }
    // Random bytes stay larger than the write buffer after compression, so that entry is
    // written through to the blob.
    values[5] = try gpa.alloc(u8, 4096);
    var rng = utils.rng.test_rng();
    rng.fill_bytes(values[5]);
    defer for (values) |value| gpa.free(value);
    var entries: [values.len]glob_mod.Entry = undefined;
    for (values, &entries) |value, *entry| {
        entry.* = try glob.append(1, value);
        try expect_stored(&glob, entry.*, value);
    }
    try testing.expect(entries[entries.len - 1].size > 1024);
    try glob.sync(&.{1});
    glob.deinit();
    // Persisted entries keep the same bytes and values.
    glob = try init_glob(Bytes, &storage, cfg);
    for (values, entries) |value, entry| try expect_stored(&glob, entry, value);
    try glob.destroy();
}

test "glob: prune" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var glob = try init_glob(i32, &storage, test_cfg(i32));
    for (1..6) |section| {
        _ = try glob.append(section, @intCast(section));
        try glob.sync(&.{section});
    }
    try testing.expect(try glob.prune(3));
    // The public accessor mirrors the guard.
    try testing.expect(glob.pruned(1));
    try testing.expect(glob.pruned(2));
    try testing.expect(!glob.pruned(3));
    // Sections 1 and 2 are gone.
    try testing.expectError(error.AlreadyPrunedToSection, glob.get(1, 0, 8));
    try testing.expectError(error.AlreadyPrunedToSection, glob.get(2, 0, 8));
    // Sections 3 to 5 still exist.
    var sections: std.ArrayList(u64) = .empty;
    defer sections.deinit(gpa);
    var iterator = glob.sections();
    while (iterator.next()) |section| try sections.append(gpa, section);
    try testing.expectEqualSlices(u64, &.{ 3, 4, 5 }, sections.items);
    try glob.destroy();
}

test "glob: checksum mismatch" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var glob = try init_glob(i32, &storage, test_cfg(i32));
    const entry = try glob.append(1, 42);
    try glob.sync(&.{1});
    // Corrupt the data by writing directly to the section.
    const writer = (try glob.manager.get(1)).?;
    try writer.write_at(entry.offset, &.{ 0xFF, 0xFF, 0xFF, 0xFF });
    try writer.sync();
    try testing.expectError(error.ChecksumMismatch, glob.get(1, entry.offset, entry.size));
    try glob.destroy();
}

test "glob: truncate" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    const cfg = test_cfg(i32);
    var glob = try init_glob(i32, &storage, cfg);
    const values = [_]i32{ 1, 2, 3, 4, 5 };
    var entries: [values.len]glob_mod.Entry = undefined;
    for (values, &entries) |value, *entry| entry.* = try glob.append(1, value);
    try glob.sync(&.{1});
    // Truncate to after the third value.
    const end = entries[2].offset + entries[2].size;
    try reopen_section(i32, &storage, &glob, cfg, 1, end);
    defer glob.destroy() catch {};
    // The first three values are still readable.
    for (values[0..3], entries[0..3]) |value, entry| {
        try testing.expectEqual(value, try glob.get(1, entry.offset, entry.size));
    }
    // The fourth reads past the end of the blob.
    const fourth = entries[3];
    try testing.expectError(error.BlobInsufficientLength, glob.get(1, fourth.offset, fourth.size));
}

/// Durable raw bytes of section 1 with `bytes` written at logical `offset`: the effect of a
/// crash that retains one unsynced write (commonware's prefix-retaining write faults).
fn retain_write(storage: *Storage, offset: u64, bytes: []const u8) ![]u8 {
    const name = manager_mod.section_name(1);
    const logical = (try storage.backend.logical_blob(gpa, partition, &name)).?;
    defer gpa.free(logical);
    const raw = (try storage.backend.raw_blob(gpa, partition, &name)).?;
    defer gpa.free(raw);
    const start = raw.len - logical.len + offset;
    const result = try gpa.alloc(u8, @max(raw.len, start + bytes.len));
    @memcpy(result[0..raw.len], raw);
    @memcpy(result[start..][0..bytes.len], bytes);
    return result;
}

// Reopen a section at a shorter size, append over the freed bytes without a sync, then crash
// with the append retained or lost. Recovery must not stitch the discarded frames behind the
// new value.
test "glob: truncate survives crash" {
    // A buffer smaller than one 8-byte entry writes every value straight to the blob.
    var cfg = test_cfg(i32);
    cfg.write_buffer = 4;
    for ([_]bool{ true, false }) |retained| {
        var storage = Storage.init(gpa);
        defer storage.deinit();
        // Seed durable history, reopen after its first entry, and leave a replacement unsynced.
        var glob = try init_glob(i32, &storage, cfg);
        var kept: u64 = 0;
        for (1..4) |value| {
            const entry = try glob.append(1, @intCast(value));
            if (value == 1) kept = entry.offset + entry.size;
        }
        try glob.sync(&.{1});
        try reopen_section(i32, &storage, &glob, cfg, 1, kept);
        try testing.expectEqual(kept, try glob.size(1));
        const entry = try glob.append(1, 4);
        try testing.expectEqual(kept, entry.offset);
        var replacement: [8]u8 = undefined;
        try (try glob.manager.get(1)).?.read_at(entry.offset, &replacement);
        const durable: ?[]u8 =
            if (retained) try retain_write(&storage, entry.offset, &replacement) else null;
        defer if (durable) |bytes| gpa.free(bytes);
        glob.deinit();
        storage.crash();
        if (durable) |bytes| {
            const name = manager_mod.section_name(1);
            try storage.backend.set_raw_blob(partition, &name, bytes);
        }
        // Recovery may retain or lose the replacement, but cannot restore the discarded suffix.
        glob = try init_glob(i32, &storage, cfg);
        const end = if (retained) entry.offset + entry.size else kept;
        try testing.expectEqual(end, try glob.size(1));
        try testing.expectEqual(1, try glob.get(1, 0, @intCast(kept)));
        if (retained) try testing.expectEqual(4, try glob.get(1, entry.offset, entry.size));
        try glob.destroy();
    }
}

test "glob: persistence" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var glob = try init_glob(i32, &storage, test_cfg(i32));
    const entry = try glob.append(1, 42);
    try glob.sync(&.{1});
    glob.deinit();
    glob = try init_glob(i32, &storage, test_cfg(i32));
    try testing.expectEqual(42, try glob.get(1, entry.offset, entry.size));
    try glob.destroy();
}

test "glob: get invalid size" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var glob = try init_glob(i32, &storage, test_cfg(i32));
    const entry = try glob.append(1, 42);
    try glob.sync(&.{1});
    // Sizes below the checksum fail with BlobInsufficientLength.
    for (0..4) |size| {
        const result = glob.get(1, entry.offset, @intCast(size));
        try testing.expectError(error.BlobInsufficientLength, result);
    }
    try glob.destroy();
}

test "glob: get wrong size" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var glob = try init_glob(i32, &storage, test_cfg(i32));
    const entry = try glob.append(1, 42);
    try glob.sync(&.{1});
    // A size too small (but at least the checksum) is a checksum mismatch.
    const result = glob.get(1, entry.offset, entry.size - 1);
    try testing.expectError(error.ChecksumMismatch, result);
    try glob.destroy();
}

test "glob: recovery verify" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var glob = try init_glob(i32, &storage, test_cfg(i32));
    const first = try glob.append(1, 7);
    const second = try glob.append(1, 8);
    try glob.sync(&.{1});
    glob.deinit();
    const name = manager_mod.section_name(1);
    try glob_mod.corrupt_frame(storage.interface(), partition, &name, 1, second.size);
    var recovery = try glob_mod.Recovery(i32).init(gpa, storage.interface(), test_cfg(i32));
    try testing.expect(try recovery.verify(1, first.offset, first.size));
    try testing.expect(!try recovery.verify(1, second.offset, second.size));
    try testing.expect(!try recovery.verify(1, first.offset, 3));
    try testing.expect(!try recovery.verify(2, 0, first.size));
    try testing.expect(!try recovery.verify(1, second.offset + 4, second.size));
    try testing.expect(!try recovery.verify(1, std.math.maxInt(u64) - 2, 8));
    glob = recovery.finish();
    try glob.destroy();
}
