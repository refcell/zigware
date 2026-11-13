//! Blob header layouts shared by every storage backend: the on-disk prelude, the per-layout
//! geometry, and reopen-time resolution, including torn-creation recovery (commonware
//! `runtime/src/storage/header.rs`).
//!
//! On-disk layout, big-endian. The prelude is 8 bytes and a V1 header extends it:
//!
//! | bytes | field                        | owner       |
//! |-------|------------------------------|-------------|
//! | 0-3   | magic (per layout)           | runtime     |
//! | 4-5   | layout version (u16)         | runtime     |
//! | 6-7   | blob version (u16)           | application |
//! | 8-11  | CRC32 of bytes 0-7 (V1 only) | runtime     |
//! | 12..  | zero padding (V1 only)       | runtime     |
//!
//! The magic selects the layout: `CWIC` is V0 (data at offset 8) and `CWIK` is V1 (data at
//! offset 4096). The layout tag lives in the magic because V0 stamped the layout version as
//! zero, and zeros are what a torn write leaves behind: no magic turns into another by
//! zeroing bytes, so a torn header never reads as a complete header of another layout.

const std = @import("std");
const assert = std.debug.assert;
const Crc32 = @import("cryptography").Crc32;
const storage = @import("../storage.zig");
const BlobLayout = storage.BlobLayout;
const BlobVersion = storage.BlobVersion;
const LayoutRange = storage.LayoutRange;
const VersionRange = storage.VersionRange;

const log = std.log.scoped(.runtime_storage);

/// Size of the header prelude in bytes.
pub const prelude_size = 8;
/// Size of the V1 header extension in bytes (CRC32 over the prelude).
pub const extension_size = 4;
/// Leading bytes needed to parse any header: the prelude plus the V1 extension.
pub const parse_len = prelude_size + extension_size;
pub const magic_length = 4;
/// The largest header region of any layout.
pub const region_max = blob_layout_max.data_offset();

const blob_layout_max: BlobLayout = .v1;

comptime {
    assert(BlobLayout.v0.data_offset() == prelude_size);
    assert(region_max == storage.blob_page_size);
}

/// Reasons a header fails validation (commonware `HeaderError`, without the payloads).
pub const HeaderError = error{
    InvalidMagic,
    UnsupportedLayoutVersion,
    LayoutMismatch,
    VersionMismatch,
    InvalidChecksum,
    InvalidPadding,
    Truncated,
};

/// True if this parse failure could be the signature of a creation interrupted before the
/// header became durable. Layout and version mismatches and bad padding fire only once a V1
/// CRC validated over a complete region, so they are genuine disagreements or foreign bytes.
pub fn may_be_torn_creation(err: HeaderError) bool {
    return switch (err) {
        error.InvalidMagic,
        error.UnsupportedLayoutVersion,
        error.InvalidChecksum,
        error.Truncated,
        => true,
        error.LayoutMismatch, error.VersionMismatch, error.InvalidPadding => false,
    };
}

/// The storage error a header failure reports.
pub fn storage_error(err: HeaderError) storage.Error {
    return switch (err) {
        error.LayoutMismatch => error.BlobLayoutMismatch,
        error.VersionMismatch => error.BlobVersionMismatch,
        error.InvalidMagic,
        error.UnsupportedLayoutVersion,
        error.InvalidChecksum,
        error.InvalidPadding,
        error.Truncated,
        => error.BlobCorrupt,
    };
}

/// The layout version recorded in a header of this layout.
pub fn layout_version(layout: BlobLayout) u16 {
    return @backingInt(layout);
}

/// The magic of a layout: the brand `CWI` and a nonzero, distinct layout tag.
pub fn magic(layout: BlobLayout) [magic_length]u8 {
    return switch (layout) {
        .v0 => "CWIC".*,
        .v1 => "CWIK".*,
    };
}

/// The layout a magic identifies, if supported.
pub fn from_magic(bytes: [magic_length]u8) ?BlobLayout {
    if (std.mem.eql(u8, &bytes, "CWIC")) return .v0;
    if (std.mem.eql(u8, &bytes, "CWIK")) return .v1;
    return null;
}

/// The fixed-size prelude at the start of each blob.
pub const Header = struct {
    magic: [magic_length]u8,
    layout_version: u16,
    blob_version: BlobVersion,

    pub fn encode(header: Header) [prelude_size]u8 {
        var out: [prelude_size]u8 = undefined;
        out[0..magic_length].* = header.magic;
        std.mem.writeInt(u16, out[4..6], header.layout_version, .big);
        std.mem.writeInt(u16, out[6..8], header.blob_version, .big);
        return out;
    }

    pub fn decode(bytes: *const [prelude_size]u8) Header {
        return .{
            .magic = bytes[0..magic_length].*,
            .layout_version = std.mem.readInt(u16, bytes[4..6], .big),
            .blob_version = std.mem.readInt(u16, bytes[6..8], .big),
        };
    }

    /// Validates the magic and layout version, returning the layout the magic identifies.
    /// The version must agree with the magic, so a torn write that zeroes layout bytes
    /// fails instead of parsing as another layout.
    pub fn validate(header: Header) HeaderError!BlobLayout {
        const layout = from_magic(header.magic) orelse return error.InvalidMagic;
        if (header.layout_version != layout_version(layout)) {
            return error.UnsupportedLayoutVersion;
        }
        return layout;
    }
};

/// True if a blob of raw length `raw_len` is too short to hold any header (new or torn).
pub fn missing(raw_len: u64) bool {
    return raw_len < prelude_size;
}

/// Leading bytes `resolve` needs for a blob of raw length `raw_len`.
pub fn resolve_len(raw_len: u64) usize {
    return @intCast(@min(raw_len, region_max));
}

/// A header region created for a new blob.
pub const Created = struct {
    /// The header region; data begins at `region.len`.
    region: []const u8,
    blob_version: BlobVersion,
};

/// Writes the header region for a new blob into `out`, using the latest layout and blob
/// version allowed by the ranges. A caller writing this region over an existing blob must
/// truncate it to zero first, so a torn write cannot splice old bytes into a valid header.
pub fn create(layouts: LayoutRange, versions: VersionRange, out: *[region_max]u8) Created {
    assert(versions.min <= versions.max); // Blob versions must be non-empty.
    assert(@backingInt(layouts.min) <= @backingInt(layouts.max));
    const layout = layouts.max;
    const header: Header = .{
        .magic = magic(layout),
        .layout_version = layout_version(layout),
        .blob_version = versions.max,
    };
    const region = out[0..@intCast(layout.data_offset())];
    @memset(region, 0);
    region[0..prelude_size].* = header.encode();
    switch (layout) {
        .v0 => {},
        .v1 => std.mem.writeInt(u32, region[prelude_size..parse_len], checksum(region), .big),
    }
    return .{ .region = region, .blob_version = versions.max };
}

fn checksum(region: []const u8) u32 {
    assert(region.len >= prelude_size);
    return Crc32.checksum(region[0..prelude_size]);
}

/// A parsed header.
pub const Resolved = struct {
    /// Logical size of the blob: its raw length minus the data offset.
    len: u64,
    blob_version: BlobVersion,
    data_offset: u64,
};

/// Parses and validates a header. `raw` holds the blob's first `resolve_len(raw_len)` bytes,
/// and `raw_len >= prelude_size`.
pub fn parse(
    raw: []const u8,
    raw_len: u64,
    layouts: LayoutRange,
    versions: VersionRange,
) HeaderError!Resolved {
    assert(raw_len >= prelude_size);
    assert(raw.len >= prelude_size and raw.len <= raw_len);
    const header = Header.decode(raw[0..prelude_size]);
    const layout = try header.validate();
    try validate_region(layout, raw, raw_len);
    // Policy applies only after the region validates, so malformed headers stay corrupt
    // rather than masquerading as a mismatch; layout policy comes before version policy.
    if (!layouts.contains(layout)) return error.LayoutMismatch;
    if (!versions.contains(header.blob_version)) return error.VersionMismatch;
    const data_offset = layout.data_offset();
    return .{
        .len = raw_len - data_offset,
        .blob_version = header.blob_version,
        .data_offset = data_offset,
    };
}

/// Validates the header region past the prelude, which must be fully present: V0 is the
/// prelude alone; V1 extends to a CRC over the prelude and zero padding to the data offset.
fn validate_region(layout: BlobLayout, raw: []const u8, raw_len: u64) HeaderError!void {
    assert(raw.len >= prelude_size);
    assert(raw.len <= raw_len);
    switch (layout) {
        .v0 => {},
        .v1 => {
            if (raw.len < parse_len) return error.Truncated;
            const crc = std.mem.readInt(u32, raw[prelude_size..parse_len], .big);
            if (checksum(raw) != crc) return error.InvalidChecksum;
            const data_offset = layout.data_offset();
            if (raw_len < data_offset) return error.Truncated;
            assert(raw.len >= data_offset);
            for (raw[parse_len..@intCast(data_offset)]) |byte| {
                if (byte != 0) return error.InvalidPadding;
            }
        },
    }
}

/// True if a blob's raw contents are consistent with a creation of this layout interrupted
/// before its header became durable.
///
/// V0 has no integrity metadata, so it never qualifies. V1 creation writes the region with
/// set_len(0), write, sync; a file qualifies iff it fits within the region and equals a
/// canonical prefix followed by zeros. The magic and layout version are fixed, the blob
/// version bytes are the writer's choice, and CRC bytes must be a prefix of the CRC over
/// the preceding prelude. A file that is not a canonical prefix stays loudly corrupt.
pub fn interrupted_creation(layout: BlobLayout, raw: []const u8) bool {
    assert(@backingInt(layout) <= @backingInt(blob_layout_max));
    switch (layout) {
        .v0 => return false,
        .v1 => {
            if (raw.len > layout.data_offset()) return false;
            const head = raw[0..@min(raw.len, parse_len)];
            for (raw[head.len..]) |byte| {
                if (byte != 0) return false;
            }
            // The written prefix ends after the last nonzero byte: trailing zeros are
            // indistinguishable from unwritten bytes.
            var written: usize = head.len;
            while (written > 0 and head[written - 1] == 0) written -= 1;
            assert(written <= parse_len);
            var canonical: [parse_len]u8 = @splat(0);
            canonical[0..magic_length].* = magic(layout);
            std.mem.writeInt(u16, canonical[4..6], layout_version(layout), .big);
            if (written <= prelude_size) {
                // Torn at or before the CRC: the fixed bytes must match.
                const fixed = @min(written, 6);
                return std.mem.eql(u8, head[0..fixed], canonical[0..fixed]);
            }
            // CRC bytes persisted, so the full prelude did too: it must be canonical with
            // the writer's version, and the CRC bytes a prefix of the CRC over it.
            if (!std.mem.eql(u8, head[0..6], canonical[0..6])) return false;
            canonical[6..8].* = head[6..8].*;
            std.mem.writeInt(u32, canonical[8..12], checksum(&canonical), .big);
            return std.mem.eql(u8, head[8..written], canonical[8..written]);
        },
    }
}

/// Resolves a blob's header from its leading bytes. Returns null when the caller should
/// (re)create the blob: the file is too short to hold a header, or it holds a V1 creation
/// interrupted before its header became durable. Anything else fails as corrupt or
/// unacceptable. `raw` holds the blob's first `resolve_len(raw_len)` bytes.
pub fn resolve(
    raw: []const u8,
    raw_len: u64,
    layouts: LayoutRange,
    versions: VersionRange,
    partition: []const u8,
    name: []const u8,
) storage.Error!?Resolved {
    assert(raw.len >= resolve_len(raw_len));
    assert(versions.min <= versions.max);
    if (missing(raw_len)) return null;
    const err = if (parse(raw, raw_len, layouts, versions)) |resolved|
        return resolved
    else |err|
        err;
    // Heal a V1 creation interrupted before its header became durable: the failure must be
    // one a torn write can produce, and the contents a canonical creation prefix. Files
    // longer than the creation region hold data and never heal.
    if (raw_len <= BlobLayout.v1.data_offset() and may_be_torn_creation(err) and
        interrupted_creation(.v1, raw[0..@intCast(raw_len)]))
    {
        log.warn("recreating blob {s}/{x} left torn by an interrupted creation", .{
            partition, name,
        });
        return null;
    }
    return storage_error(err);
}

// Tests (commonware `storage::header::tests`).

const testing = std.testing;
const codec = @import("codec");
const conformance = @import("conformance");
const conformance_file = @embedFile("../conformance.toml");
const conformance_prefix = "commonware_runtime::storage::header::tests::conformance::";

fn v0_header(blob_version: u16) Header {
    return .{ .magic = magic(.v0), .layout_version = 0, .blob_version = blob_version };
}

/// Raw bytes of a blob of `layout` with `blob_version`, followed by `payload`.
pub fn blob_bytes(
    gpa: std.mem.Allocator,
    layout: BlobLayout,
    blob_version: u16,
    payload: []const u8,
) ![]u8 {
    var region: [region_max]u8 = undefined;
    const created = create(.only(layout), .only(blob_version), &region);
    assert(created.blob_version == blob_version);
    return std.mem.concat(gpa, u8, &.{ created.region, payload });
}

test "header create v1" {
    var out: [region_max]u8 = undefined;
    const created = create(.all, .{ .min = 0, .max = 7 }, &out);
    try testing.expectEqual(@as(u16, 7), created.blob_version);
    try testing.expectEqual(@as(usize, 4096), created.region.len);
    for (created.region[parse_len..]) |byte| try testing.expectEqual(@as(u8, 0), byte);
    const resolved = try parse(created.region, 4096, .all, .{ .min = 0, .max = 7 });
    try testing.expectEqual(Resolved{ .len = 0, .blob_version = 7, .data_offset = 4096 }, resolved);
}

test "header create v0" {
    var out: [region_max]u8 = undefined;
    const created = create(.only(.v0), .{ .min = 0, .max = 7 }, &out);
    try testing.expectEqual(@as(u16, 7), created.blob_version);
    try testing.expectEqualSlices(u8, "CWIC\x00\x00\x00\x07", created.region);
    const resolved = try parse(created.region, 8, .only(.v0), .{ .min = 0, .max = 7 });
    try testing.expectEqual(Resolved{ .len = 0, .blob_version = 7, .data_offset = 8 }, resolved);
}

test "header v1 fixture bytes" {
    var out: [region_max]u8 = undefined;
    const created = create(.only(.v1), .only(3), &out);
    const expected = "CWIK\x00\x01\x00\x03";
    try testing.expectEqualSlices(u8, expected, created.region[0..8]);
    const crc = std.mem.readInt(u32, created.region[8..12], .big);
    try testing.expectEqual(Crc32.checksum(expected), crc);
}

test "header extension rejects bad crc, truncation, and padding" {
    var out: [region_max]u8 = undefined;
    const region = @constCast(create(.only(.v1), .only(0), &out).region);
    try testing.expectError(error.Truncated, parse(region[0..4095], 4095, .all, .only(0)));
    region[parse_len] = 0x01;
    try testing.expectError(error.InvalidPadding, parse(region, 4096, .all, .only(0)));
    region[parse_len] = 0;
    region[parse_len - 1] ^= 0x01;
    try testing.expectError(error.InvalidChecksum, parse(region, 4096, .all, .only(0)));
}

test "header validate success" {
    const header = v0_header(5);
    try testing.expectEqual(BlobLayout.v0, try header.validate());
    _ = try parse(&header.encode(), 8, .all, .{ .min = 3, .max = 7 });
    _ = try parse(&header.encode(), 8, .all, .only(5));
}

test "header layout restriction" {
    const gpa = testing.allocator;
    const v0 = try blob_bytes(gpa, .v0, 0, "payload");
    defer gpa.free(v0);
    try testing.expectError(error.LayoutMismatch, parse(v0, v0.len, .only(.v1), .only(0)));
    const v1 = try blob_bytes(gpa, .v1, 0, "payload");
    defer gpa.free(v1);
    try testing.expectError(error.LayoutMismatch, parse(v1, v1.len, .only(.v0), .only(0)));
    // Outside both the layout and version ranges: the layout mismatch is reported.
    const outside = try blob_bytes(gpa, .v0, 5, "payload");
    defer gpa.free(outside);
    const result = parse(outside, outside.len, .only(.v1), .only(0));
    try testing.expectError(error.LayoutMismatch, result);
    // A malformed excluded layout stays corruption rather than a policy mismatch.
    v1[parse_len] = 1;
    try testing.expectError(error.InvalidPadding, parse(v1, v1.len, .only(.v0), .only(0)));
}

test "header validate magic and layout version mismatch" {
    var header = v0_header(5);
    header.magic = "XXXX".*;
    try testing.expectError(error.InvalidMagic, header.validate());
    header = v0_header(5);
    header.layout_version = 99;
    try testing.expectError(error.UnsupportedLayoutVersion, header.validate());
}

test "header errors map to storage errors" {
    const corrupt = [_]HeaderError{
        error.InvalidMagic,   error.UnsupportedLayoutVersion, error.InvalidChecksum,
        error.InvalidPadding, error.Truncated,
    };
    for (corrupt) |err| try testing.expectEqual(error.BlobCorrupt, storage_error(err));
    try testing.expectEqual(error.BlobVersionMismatch, storage_error(error.VersionMismatch));
    try testing.expectEqual(error.BlobLayoutMismatch, storage_error(error.LayoutMismatch));
}

test "header error torn creation candidates" {
    try testing.expect(may_be_torn_creation(error.InvalidMagic));
    try testing.expect(may_be_torn_creation(error.UnsupportedLayoutVersion));
    try testing.expect(may_be_torn_creation(error.InvalidChecksum));
    try testing.expect(may_be_torn_creation(error.Truncated));
    try testing.expect(!may_be_torn_creation(error.InvalidPadding));
    try testing.expect(!may_be_torn_creation(error.LayoutMismatch));
    try testing.expect(!may_be_torn_creation(error.VersionMismatch));
}

test "header magic zero subset is invalid" {
    for ([_]BlobLayout{ .v0, .v1 }) |layout| {
        for (0..magic_length) |i| {
            var bytes = magic(layout);
            bytes[i] = 0;
            try testing.expectEqual(@as(?BlobLayout, null), from_magic(bytes));
        }
    }
}

test "header torn v1 does not parse as v0" {
    const header: Header = .{ .magic = magic(.v1), .layout_version = 0, .blob_version = 5 };
    try testing.expectError(error.UnsupportedLayoutVersion, header.validate());
}

test "header v0 blob version out of range" {
    const header = v0_header(10);
    const result = parse(&header.encode(), 8, .all, .{ .min = 3, .max = 7 });
    try testing.expectError(error.VersionMismatch, result);
}

test "header v1 blob version checked after crc" {
    const gpa = testing.allocator;
    const raw = try blob_bytes(gpa, .v1, 10, "");
    defer gpa.free(raw);
    const range: VersionRange = .{ .min = 3, .max = 7 };
    try testing.expectError(error.VersionMismatch, parse(raw, raw.len, .all, range));
    raw[7] = 0;
    try testing.expectError(error.InvalidChecksum, parse(raw, raw.len, .all, range));
}

test "header interrupted v1 creation accepts torn states" {
    const gpa = testing.allocator;
    const region = try blob_bytes(gpa, .v1, 5, "");
    defer gpa.free(region);
    const zeros: [4096]u8 = @splat(0);
    const zeros_100: [100]u8 = @splat(0);
    var torn_crc: [4096]u8 = region[0..4096].*;
    @memset(torn_crc[8..12], 0);
    var persisted_length = zeros;
    persisted_length[0..10].* = region[0..10].*;
    // A V0 blob rotted into a canonical V1 prefix (version 0, zero payload, tag byte lost)
    // is byte-identical to a V1 creation torn inside the magic, and heals.
    const rotted = try blob_bytes(gpa, .v0, 0, &zeros_100);
    defer gpa.free(rotted);
    rotted[3] = 0;
    const cases = [_][]const u8{
        &zeros, zeros[0..3], region[0..2],      region[0..8], region[0..10],
        region, &torn_crc,   &persisted_length, rotted,
    };
    for (cases, 0..) |raw, i| {
        if (!interrupted_creation(.v1, raw)) {
            std.debug.print("case {d} should classify as an interrupted creation\n", .{i});
            return error.TestUnexpectedResult;
        }
    }
}

test "layout v0 interrupted creation rejects all" {
    var out: [region_max]u8 = undefined;
    const region = create(.only(.v1), .only(0), &out).region;
    try testing.expect(interrupted_creation(.v1, region[0..10]));
    try testing.expect(!interrupted_creation(.v0, region[0..10]));
    try testing.expect(!interrupted_creation(.v0, &.{}));
}

test "header interrupted v1 creation rejects foreign bytes" {
    const gpa = testing.allocator;
    const region = try blob_bytes(gpa, .v1, 5, "");
    defer gpa.free(region);
    const Mutation = struct { index: usize, value: u8 };
    const mutations = [_]Mutation{
        .{ .index = 0, .value = 'X' }, // Non-canonical magic byte.
        .{ .index = 4, .value = 0x02 }, // Non-canonical layout version.
        .{ .index = 3, .value = 0 }, // Magic byte lost with later bytes persisted.
        .{ .index = 5, .value = 0 }, // Layout version byte lost with later bytes persisted.
        .{ .index = 9, .value = @max(region[9] +% 1, 1) }, // CRC that mismatches its prelude.
        .{ .index = 100, .value = 0xff }, // Nonzero padding.
    };
    for (mutations) |mutation| {
        var raw: [4096]u8 = region[0..4096].*;
        raw[mutation.index] = mutation.value;
        try testing.expect(!interrupted_creation(.v1, &raw));
    }
    try expect_foreign_blobs(gpa, region);
}

fn expect_foreign_blobs(gpa: std.mem.Allocator, region: []const u8) !void {
    assert(region.len == 4096);
    // Data past the header region.
    const longer = try std.mem.concat(gpa, u8, &.{ region, "\x01" });
    defer gpa.free(longer);
    try testing.expect(!interrupted_creation(.v1, longer));
    // A rotted-magic V0 blob with its version stamp, or with a payload.
    const zeros_100: [100]u8 = @splat(0);
    var stamped = v0_header(5).encode() ++ zeros_100;
    stamped[3] = 0;
    try testing.expect(!interrupted_creation(.v1, &stamped));
    var payload = (v0_header(5).encode() ++ [_]u8{ 0xaa, 0xbb });
    payload[3] = 0;
    try testing.expect(!interrupted_creation(.v1, &payload));
    // All zeros, one byte longer than the creation region.
    const zeros_4097: [4097]u8 = @splat(0);
    try testing.expect(!interrupted_creation(.v1, &zeros_4097));
    // A synced V1 blob with a zero payload and its CRC rotted away.
    const synced = try blob_bytes(gpa, .v1, 5, &zeros_100);
    defer gpa.free(synced);
    @memset(synced[8..12], 0);
    try testing.expect(!interrupted_creation(.v1, synced));
}

test "header bytes round trip" {
    const header = v0_header(123);
    try testing.expectEqual(header, Header.decode(&header.encode()));
}

test "header resolve" {
    const gpa = testing.allocator;
    const log_level = testing.log_level;
    testing.log_level = .err; // Healing logs a warning.
    defer testing.log_level = log_level;
    // Too short: missing, recreate.
    try testing.expectEqual(@as(?Resolved, null), try resolve("CWI", 3, .all, .only(0), "p", "n"));
    // Torn V1 creation heals; a valid blob resolves; a corrupt one fails loudly.
    const blob = try blob_bytes(gpa, .v1, 0, "data");
    defer gpa.free(blob);
    const torn = blob[0..10];
    try testing.expectEqual(@as(?Resolved, null), try resolve(torn, 10, .all, .only(0), "p", "n"));
    const resolved = (try resolve(blob[0..4096], blob.len, .all, .only(0), "p", "n")).?;
    try testing.expectEqual(Resolved{ .len = 4, .blob_version = 0, .data_offset = 4096 }, resolved);
    blob[0] = 'X';
    const result = resolve(blob[0..4096], blob.len, .all, .only(0), "p", "n");
    try testing.expectError(error.BlobCorrupt, result);
    try testing.expectError(error.BlobVersionMismatch, resolve(
        &v0_header(9).encode(),
        8,
        .all,
        .only(0),
        "p",
        "n",
    ));
}

/// The image of a blob of `layout` with a seeded blob version and payload.
fn BlobConformance(comptime layout: BlobLayout) type {
    return struct {
        pub fn commit(gpa: std.mem.Allocator, seed: u64) ![]u8 {
            var payload: [8]u8 = undefined;
            std.mem.writeInt(u64, &payload, seed, .little);
            return blob_bytes(gpa, layout, @truncate(seed), &payload);
        }
    };
}

/// `CodecConformance<Header>`: the encoding of commonware's `Arbitrary` header (a layout
/// chosen from [V0, V1], then an arbitrary blob version).
const HeaderConformance = struct {
    pub fn commit(gpa: std.mem.Allocator, seed: u64) ![]u8 {
        const header = try codec.arbitrary.generate(Header, arbitrary_header, gpa, seed);
        return gpa.dupe(u8, &header.encode());
    }

    fn arbitrary_header(_: std.mem.Allocator, u: *codec.arbitrary.Unstructured) !Header {
        const layouts = [_]BlobLayout{ .v0, .v1 };
        const layout = layouts[@intCast(u.int_in_range(u64, 0, layouts.len - 1))];
        return .{
            .magic = magic(layout),
            .layout_version = layout_version(layout),
            .blob_version = u.int(u16),
        };
    }
};

fn verify_conformance(comptime C: type, comptime name: []const u8) !void {
    try conformance.verify(
        C,
        testing.allocator,
        conformance_prefix ++ name,
        conformance.default_cases,
        conformance_file,
    );
}

test "header conformance: V0Blob" {
    try verify_conformance(BlobConformance(.v0), "V0Blob");
}

test "header conformance: V1Blob" {
    try verify_conformance(BlobConformance(.v1), "V1Blob");
}

test "header conformance: CodecConformance<Header>" {
    try verify_conformance(HeaderConformance, "CodecConformance<Header>");
}

// Seeded fuzz: arbitrary and mutated header regions. `resolve` never panics; a resolved
// header is exactly the region `create` writes for its layout and version, and a heal is
// only ever a short torn V1 creation.

fn fuzz_resolve(_: void, smith: *std.testing.Smith) anyerror!void {
    var raw: [region_max + 16]u8 = undefined;
    var raw_len: usize = 0;
    if (smith.value(bool)) {
        const layout: BlobLayout = if (smith.value(bool)) .v1 else .v0;
        var region: [region_max]u8 = undefined;
        const created = create(.only(layout), .only(smith.value(u16)), &region);
        raw_len = smith.valueRangeAtMost(u32, 0, raw.len);
        @memset(&raw, 0);
        const copied = @min(raw_len, created.region.len);
        @memcpy(raw[0..copied], created.region[0..copied]);
        const flips = smith.valueRangeAtMost(u8, 0, 3);
        for (0..flips) |_| {
            if (raw_len == 0) break;
            raw[smith.index(raw_len)] ^= smith.value(u8);
        }
    } else {
        raw_len = smith.slice(raw[0..parse_len]);
    }
    try check_resolve(raw[0..raw_len], smith.value(bool));
}

fn check_resolve(raw: []const u8, restrict: bool) !void {
    const layouts: LayoutRange = if (restrict) .only(.v1) else .all;
    const resolved = resolve(raw[0..resolve_len(raw.len)], raw.len, layouts, .{
        .min = 0,
        .max = std.math.maxInt(u16),
    }, "fuzz", "blob") catch |err| {
        try testing.expect(err == error.BlobCorrupt or err == error.BlobLayoutMismatch);
        return;
    } orelse {
        try testing.expect(missing(raw.len) or interrupted_creation(.v1, raw));
        return;
    };
    const header = Header.decode(raw[0..prelude_size]);
    const layout = try header.validate();
    try testing.expect(layouts.contains(layout));
    try testing.expectEqual(layout.data_offset(), resolved.data_offset);
    try testing.expectEqual(raw.len - resolved.data_offset, resolved.len);
    var region: [region_max]u8 = undefined;
    const created = create(.only(layout), .only(resolved.blob_version), &region);
    try testing.expectEqualSlices(u8, created.region, raw[0..created.region.len]);
}

test "fuzz header resolve" {
    const build_options = @import("build_options");
    var prng = std.Random.DefaultPrng.init(0x6865_6164 ^ build_options.fuzz_seed);
    const random = prng.random();
    var input: [64]u8 = undefined;
    const total: u64 = @as(u64, 2000) * build_options.fuzz_soak;
    // Healing logs a warning per torn creation; keep the fuzz output readable.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        random.bytes(&input);
        var smith: std.testing.Smith = .{ .in = &input };
        fuzz_resolve({}, &smith) catch |err| {
            std.debug.print("fuzz: iteration {d} failed: {t}\n", .{ iteration, err });
            return err;
        };
    }
    try std.testing.fuzz({}, fuzz_resolve, .{});
}
