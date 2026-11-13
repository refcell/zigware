//! Fuzz targets for every codec decoder (codec/fuzz/fuzz_targets/codec_roundtrip.rs).
//!
//! `roundtrip`: builds a value from fuzz input, encodes it, checks `encode_size`, and decodes
//! it back (with too-short and too-long ranges failing for length-prefixed types).
//! `decode_canonical`: decodes raw fuzz bytes as each type; decoding must never panic, and a
//! successful decode must re-encode to exactly the input, since every encoding is canonical.

const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const codec = @import("codec.zig");
const varint = @import("varint.zig");
const Bytes = @import("types/bytes.zig").Bytes;
const fuzz = @import("fuzz.zig");
const RangeCfg = @import("config.zig").RangeCfg;
const map = @import("types/map.zig");

const gpa = testing.allocator;

fn expect_roundtrip(comptime T: type, value: T) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(T, value), encoded.len);
    // `usize` is the only scalar with a config: accept every length.
    const cfg = if (T == usize) RangeCfg(usize).full() else codec.unit_cfg(codec.Cfg(T));
    const decoded = try codec.decode_cfg(T, gpa, encoded, cfg);
    const reencoded = try codec.encode(T, gpa, decoded);
    defer gpa.free(reencoded);
    // Compare encodings, not values, so NaN floats round-trip too.
    try testing.expectEqualSlices(u8, encoded, reencoded);
}

fn expect_slice_roundtrip(comptime T: type, items: []const T) !void {
    const S = []const T;
    const encoded = try codec.encode(S, gpa, items);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(S, items), encoded.len);
    const len = items.len;
    const too_long = codec.decode_range(S, gpa, encoded, .range(0, len));
    try testing.expectError(error.InvalidLength, too_long);
    const too_short = codec.decode_range(S, gpa, encoded, .from(len + 1));
    try testing.expectError(error.InvalidLength, too_short);
    const decoded = try codec.decode_range(S, gpa, encoded, .inclusive(len, len));
    defer codec.free(S, gpa, decoded);
    try testing.expectEqualSlices(T, items, decoded);
}

fn expect_bytes_roundtrip(data: []const u8) !void {
    const encoded = try codec.encode(Bytes, gpa, .init(data));
    defer gpa.free(encoded);
    const len = data.len;
    const too_long = codec.decode_cfg(Bytes, gpa, encoded, .range(0, len));
    try testing.expectError(error.InvalidLength, too_long);
    const too_short = codec.decode_cfg(Bytes, gpa, encoded, .from(len + 1));
    try testing.expectError(error.InvalidLength, too_short);
    const decoded = try codec.decode_cfg(Bytes, gpa, encoded, .inclusive(len, len));
    try testing.expectEqualSlices(u8, data, decoded.data);
}

fn expect_varint_overflow_never_panics(smith: *Smith) !void {
    var input: [41]u8 = undefined;
    const continuation_bytes = smith.value(u8) % 41;
    @memset(input[0..continuation_bytes], 0xff);
    input[continuation_bytes] = smith.value(u8);
    const bytes = input[0 .. continuation_bytes + 1];
    inline for (.{ u16, u32, u64, u128, u256 }) |T| {
        _ = codec.decode(varint.UInt(T), gpa, bytes) catch {};
    }
    inline for (.{ i16, i32, i64, i128 }) |S| {
        _ = codec.decode(varint.SInt(S), gpa, bytes) catch {};
    }
}

/// Builds a map from fuzz input: sorted, with duplicate keys dropped.
fn roundtrip_map(comptime M: type, smith: *Smith) !void {
    const K = @FieldType(M.Entry, "key");
    const V = @FieldType(M.Entry, "value");
    var entries: [64]M.Entry = undefined;
    var len: usize = 0;
    while (len < entries.len and !smith.eos()) : (len += 1) {
        entries[len] = .{ .key = smith.value(K), .value = smith.value(V) };
    }
    M.sort(entries[0..len]);
    var unique: usize = 0;
    for (entries[0..len]) |entry| {
        if (unique > 0 and entries[unique - 1].key == entry.key) continue;
        entries[unique] = entry;
        unique += 1;
    }
    const value = M.init(entries[0..unique]);
    const encoded = try codec.encode(M, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(M, value), encoded.len);
    var decoded = try codec.decode_cfg(M, gpa, encoded, .{ .range = .exact(unique) });
    defer decoded.deinit(gpa);
    try testing.expectEqualSlices(M.Entry, value.entries, decoded.entries);
}

/// Builds a set from fuzz input: sorted, with duplicates dropped.
fn roundtrip_set(comptime S: type, smith: *Smith) !void {
    const K = @typeInfo(@FieldType(S, "items")).pointer.child;
    var items: [64]K = undefined;
    var len: usize = 0;
    while (len < items.len and !smith.eos()) : (len += 1) items[len] = smith.value(K);
    S.sort(items[0..len]);
    var unique: usize = 0;
    for (items[0..len]) |item| {
        if (unique > 0 and items[unique - 1] == item) continue;
        items[unique] = item;
        unique += 1;
    }
    const value = S.init(items[0..unique]);
    const encoded = try codec.encode(S, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(S, value), encoded.len);
    var decoded = try codec.decode_cfg(S, gpa, encoded, .{ .range = .exact(unique) });
    defer decoded.deinit(gpa);
    try testing.expectEqualSlices(K, value.items, decoded.items);
}

fn roundtrip_scalars(smith: *Smith, choice: u8) !void {
    switch (choice) {
        0 => try expect_roundtrip(bool, smith.value(bool)),
        1 => try expect_roundtrip(usize, smith.value(u32)),
        2 => try expect_roundtrip(u8, smith.value(u8)),
        3 => try expect_roundtrip(u16, smith.value(u16)),
        4 => try expect_roundtrip(u32, smith.value(u32)),
        5 => try expect_roundtrip(u64, smith.value(u64)),
        6 => try expect_roundtrip(u128, smith.value(u128)),
        7 => try expect_roundtrip(u256, smith.value(u256)),
        8 => try expect_roundtrip(i8, smith.value(i8)),
        9 => try expect_roundtrip(i16, smith.value(i16)),
        10 => try expect_roundtrip(i32, smith.value(i32)),
        11 => try expect_roundtrip(i64, smith.value(i64)),
        12 => try expect_roundtrip(i128, smith.value(i128)),
        13 => try expect_roundtrip(f32, @bitCast(smith.value(u32))),
        14 => try expect_roundtrip(f64, @bitCast(smith.value(u64))),
        15 => try expect_roundtrip(varint.UInt(u16), .{ .value = smith.value(u16) }),
        16 => try expect_roundtrip(varint.UInt(u32), .{ .value = smith.value(u32) }),
        17 => try expect_roundtrip(varint.UInt(u64), .{ .value = smith.value(u64) }),
        18 => try expect_roundtrip(varint.UInt(u128), .{ .value = smith.value(u128) }),
        19 => try expect_roundtrip(varint.UInt(u256), .{ .value = smith.value(u256) }),
        20 => try expect_roundtrip(varint.SInt(i16), .{ .value = smith.value(i16) }),
        21 => try expect_roundtrip(varint.SInt(i32), .{ .value = smith.value(i32) }),
        22 => try expect_roundtrip(varint.SInt(i64), .{ .value = smith.value(i64) }),
        23 => try expect_roundtrip(varint.SInt(i128), .{ .value = smith.value(i128) }),
        else => unreachable,
    }
}

fn roundtrip_composites(smith: *Smith, choice: u8) !void {
    var data: [256]u8 = undefined;
    switch (choice) {
        0 => try expect_bytes_roundtrip(data[0..smith.slice(&data)]),
        1 => try expect_slice_roundtrip(u8, data[0..smith.slice(&data)]),
        2 => try expect_roundtrip([4]u8, smith.value([4]u8)),
        3 => try expect_roundtrip([8]u8, smith.value([8]u8)),
        4 => try expect_roundtrip([16]u8, smith.value([16]u8)),
        5 => try expect_roundtrip([32]u8, smith.value([32]u8)),
        6 => try expect_roundtrip(?u32, smith.value(u32)),
        7 => try expect_roundtrip(?u32, null),
        8 => try expect_roundtrip(struct { u8, u16 }, .{ smith.value(u8), smith.value(u16) }),
        9 => try expect_roundtrip(
            struct { u32, u64, u128 },
            .{ smith.value(u32), smith.value(u64), smith.value(u128) },
        ),
        10 => try expect_varint_overflow_never_panics(smith),
        11 => try roundtrip_map(map.HashMap(u64, u64), smith),
        12 => try roundtrip_map(map.Map(u32, u32), smith),
        13 => try roundtrip_set(map.HashSet(u64), smith),
        14 => try roundtrip_set(map.Set(u32), smith),
        else => unreachable,
    }
}

const scalar_count = 24;
const composite_count = 15;

fn roundtrip(_: void, smith: *Smith) anyerror!void {
    const choice = smith.value(u8) % (scalar_count + composite_count);
    if (choice < scalar_count) return roundtrip_scalars(smith, choice);
    return roundtrip_composites(smith, choice - scalar_count);
}

fn expect_canonical(comptime T: type, input: []const u8, cfg: codec.Cfg(T)) !void {
    const value = codec.decode_cfg(T, gpa, input, cfg) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
    defer codec.free(T, gpa, value);
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, input, encoded);
}

fn decode_canonical(_: void, smith: *Smith) anyerror!void {
    var data: [512]u8 = undefined;
    const input = data[0..smith.slice(&data)];
    try expect_canonical(bool, input, {});
    try expect_canonical(u32, input, {});
    try expect_canonical(f64, input, {});
    try expect_canonical(usize, input, .full());
    try expect_canonical(?u16, input, {});
    try expect_canonical([3]u8, input, {});
    try expect_canonical(Bytes, input, .full());
    try expect_canonical([]const u8, input, .{ .range = .full() });
    try expect_canonical([]const u32, input, .{ .range = .full() });
    try expect_canonical([]const ?bool, input, .{ .range = .full() });
    const Nested = []const []const u8;
    try expect_canonical(Nested, input, .{ .range = .full(), .item = .{ .range = .full() } });
    try expect_canonical(struct { u8, ?u16, usize }, input, .{ {}, {}, .full() });
    try expect_canonical(map.Map(u8, u16), input, .{ .range = .full() });
    try expect_canonical(map.Set(u16), input, .{ .range = .full() });
    try expect_canonical(map.HashSet(Bytes), input, .{ .range = .full(), .item = .full() });
    inline for (.{ u0, u4, u8, u14, u16, u32, u36, u64, u128, u256 }) |T| {
        try expect_canonical(varint.UInt(T), input, {});
    }
    inline for (.{ i16, i32, i64, i128 }) |S| try expect_canonical(varint.SInt(S), input, {});
}

test "fuzz codec roundtrip" {
    try fuzz.run({}, roundtrip, 0x636f646563, 2000);
}

test "fuzz codec decode canonical" {
    try fuzz.run({}, decode_canonical, 0x63616e6f6e, 2000);
}
