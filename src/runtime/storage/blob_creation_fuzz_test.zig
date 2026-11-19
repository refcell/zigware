//! Blob recovery from arbitrary durable images (commonware
//! `runtime/fuzz/fuzz_targets/blob_creation.rs`): every image installed as a blob's crash
//! contents opens as the header spec requires. It is recreated as the canonical V1 region,
//! kept unchanged at its logical size, or rejected without being mutated.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");
const Crc32 = @import("cryptography").Crc32;
const iface = @import("../storage.zig");
const memory = @import("memory.zig");
const suite = @import("tests.zig");

const rng = utils.rng;
const FuzzRng = rng.FuzzRng;
const Storage = memory.Storage;
const BlobVersion = iface.BlobVersion;

const partition = "blob_creation";
const name = "blob";
const payload = "payload!";

/// Header spec constants (runtime/src/storage/header.rs): the prelude, the prelude plus its
/// V1 CRC, the V1 region size, and each layout's magic plus layout version bytes. The V1
/// values are checked against a real creation before every image is classified.
const prelude = 8;
const parse_len = 12;
const region = 4096;
const v0_prefix = "CWIC\x00\x00";
const v1_prefix = "CWIK\x00\x01";

/// Images past the region plus a small payload margin all behave alike.
const image_max = region + prelude;

/// The recovery an installed image requires; `kept` carries the logical size.
const Outcome = union(enum) { recreated, kept: u64, rejected };

fn crc_bytes(image: []const u8) [4]u8 {
    assert(image.len >= prelude);
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, Crc32.checksum(image[0..prelude]), .big);
    return out;
}

fn all_zero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

/// Classify the required outcome, per the header spec: a sub-prelude file is recreated, a
/// parseable header is honored before healing is considered (a version disagreement or
/// nonzero padding on an intact region never heals), and only failures a torn write can
/// produce reach the torn-creation classifier, which accepts a canonical V1 prefix (any
/// blob version, CRC bytes binding the written prelude) followed by zeros.
fn creation_outcome(image: []const u8, version: BlobVersion) Outcome {
    if (image.len < prelude) return .recreated;
    const stamped = std.mem.readInt(u16, image[6..8], .big);
    if (std.mem.eql(u8, image[0..6], v0_prefix)) {
        return if (stamped == version) .{ .kept = image.len - prelude } else .rejected;
    }
    if (std.mem.eql(u8, image[0..6], v1_prefix) and image.len >= region and
        std.mem.eql(u8, image[prelude..parse_len], &crc_bytes(image)))
    {
        if (!all_zero(image[parse_len..region])) return .rejected;
        return if (stamped == version) .{ .kept = image.len - region } else .rejected;
    }
    if (image.len > region) return .rejected;
    const head_len = @min(image.len, parse_len);
    if (!all_zero(image[head_len..])) return .rejected;
    const head = image[0..head_len];
    var written = head_len;
    while (written > 0 and head[written - 1] == 0) written -= 1;
    const canonical = if (written <= prelude)
        std.mem.eql(u8, head[0..@min(written, 6)], v1_prefix[0..@min(written, 6)])
    else
        std.mem.eql(u8, head[0..6], v1_prefix) and
            std.mem.eql(u8, head[prelude..written], crc_bytes(head)[0 .. written - prelude]);
    return if (canonical) .recreated else .rejected;
}

/// Draw an image near the shapes recovery distinguishes: random bytes, a torn or extended
/// canonical V1 creation, a V0 prelude, or zeros; then flip a few bytes, mostly in the head.
fn draw_image(r: *FuzzRng, canonical: []const u8, out: *[image_max]u8) []u8 {
    assert(canonical.len == region);
    // Lengths cluster at the torn head and around the region end, where outcomes change.
    const len = switch (rng.range_at_most(r, u8, 0, 2)) {
        0 => rng.range_at_most(r, usize, 0, parse_len + 2),
        1 => rng.range_at_most(r, usize, region - 2, image_max),
        2 => rng.range_at_most(r, usize, 0, image_max),
        else => unreachable,
    };
    const image = out[0..len];
    @memset(image, 0);
    switch (rng.range_at_most(r, u8, 0, 3)) {
        0 => r.fill_bytes(image),
        1 => {
            const copied = @min(len, region);
            @memcpy(image[0..copied], canonical[0..copied]);
            r.fill_bytes(image[copied..]);
        },
        2 => {
            var prelude_bytes: [prelude]u8 = undefined;
            @memcpy(prelude_bytes[0..6], v0_prefix);
            @memcpy(prelude_bytes[6..], canonical[6..8]);
            if (rng.boolean(r)) r.fill_bytes(prelude_bytes[6..]);
            const copied = @min(len, prelude);
            @memcpy(image[0..copied], prelude_bytes[0..copied]);
            r.fill_bytes(image[copied..]);
        },
        3 => {},
        else => unreachable,
    }
    const flips = rng.range_at_most(r, u8, 0, 3);
    for (0..flips) |_| {
        if (len == 0) break;
        const span = if (rng.boolean(r)) @min(len, parse_len) else len;
        image[rng.range_less_than(r, usize, 0, span)] ^= rng.range_at_most(r, u8, 1, 255);
    }
    assert(image.len <= image_max);
    return image;
}

fn expect_raw(storage: *Storage, expected: []const u8) !void {
    const raw = (try storage.raw_blob(testing.allocator, partition, name)).?;
    defer testing.allocator.free(raw);
    try testing.expectEqualSlices(u8, expected, raw);
}

/// A recoverable image heals into an empty blob whose durable header is `expected`, and a
/// synced write at logical offset zero reads back after a reopen.
fn expect_recovers(storage: *Storage, version: BlobVersion, expected: []const u8) !void {
    {
        const opened = try storage.open_versioned(partition, name, .only(version));
        defer opened.blob.close();
        try testing.expectEqual(@as(u64, 0), opened.len);
        try testing.expectEqual(version, opened.version);
        try expect_raw(storage, expected);
        try opened.blob.write_at(0, payload, .{ .sync = true });
    }
    const reopened = try storage.open_versioned(partition, name, .only(version));
    defer reopened.blob.close();
    try testing.expectEqual(@as(u64, payload.len), reopened.len);
    try testing.expectEqual(version, reopened.version);
    try suite.expect_read(reopened.blob, 0, payload);
}

fn expect_kept(storage: *Storage, version: BlobVersion, image: []const u8, size: u64) !void {
    assert(size > 0);
    const opened = try storage.open_versioned(partition, name, .only(version));
    defer opened.blob.close();
    try testing.expectEqual(size, opened.len);
    try testing.expectEqual(version, opened.version);
    try expect_raw(storage, image);
}

fn expect_rejects(storage: *Storage, version: BlobVersion, image: []const u8) !void {
    if (storage.open_versioned(partition, name, .only(version))) |opened| {
        opened.blob.close();
        return error.TestUnexpectedResult;
    } else |_| {}
    try expect_raw(storage, image);
}

fn fuzz_creation(_: void, r: *FuzzRng) !void {
    const gpa = testing.allocator;
    var storage: Storage = .init(gpa);
    defer storage.deinit();
    const version = rng.range_at_most(r, BlobVersion, 0, std.math.maxInt(BlobVersion));
    // The canonical V1 region, created through the production path, anchors the constants.
    const created = try storage.open_versioned(partition, name, .only(version));
    created.blob.close();
    try testing.expectEqual(@as(u64, 0), created.len);
    try testing.expectEqual(version, created.version);
    const canonical = (try storage.raw_blob(gpa, partition, name)).?;
    defer gpa.free(canonical);
    try testing.expectEqual(@as(usize, region), canonical.len);
    try testing.expectEqualSlices(u8, v1_prefix, canonical[0..6]);
    try testing.expectEqualSlices(u8, &crc_bytes(canonical), canonical[prelude..parse_len]);

    var buffer: [image_max]u8 = undefined;
    const image = draw_image(r, canonical, &buffer);
    try storage.set_raw_blob(partition, name, image);
    switch (creation_outcome(image, version)) {
        .recreated => try expect_recovers(&storage, version, canonical),
        .kept => |size| if (size == 0) {
            try expect_recovers(&storage, version, image);
        } else {
            try expect_kept(&storage, version, image, size);
        },
        .rejected => try expect_rejects(&storage, version, image),
    }
}

test "fuzz blob creation recovery" {
    const quiet = testing.log_level;
    testing.log_level = .err; // Healing logs a warning per torn image.
    defer testing.log_level = quiet;
    try utils.fuzz.run({}, fuzz_creation, 0x626c_6f62_6372_6561, 400);
}
