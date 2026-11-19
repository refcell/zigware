//! Fuzz target for the sync wire decoders: `Target`, `Request`, and `Response` (both merkle
//! families).
//!
//! `decode_run` reads one message from the front of raw fuzz bytes: reading must never panic
//! or leak, and a message read must re-encode to exactly the bytes it consumed (every
//! encoding is canonical) with a matching `encode_size`. `fields_run` writes messages from
//! drawn fields near their bounds (equal, reversed, and out-of-domain locations; a zero
//! `max_ops`; too many operations) and checks that decoding succeeds exactly when the fields
//! are valid, an oracle independent of the decoders.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const merkle = @import("../../merkle/mod.zig");
const operation = @import("../operation.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const sync = @import("mod.zig");

const gpa = testing.allocator;
const D = cryptography.Sha256.Digest;
const Mmr = merkle.mmr.Family;
const families = .{ Mmr, merkle.mmb.Family };
const max_ops: usize = 4;

fn Response(comptime F: type) type {
    return sync.Response(F, u64, D);
}

fn response_cfg(comptime F: type) Response(F).Cfg {
    return .{ .max_ops = max_ops, .op = {} };
}

/// Reads one `T` from the front of `bytes` and checks it re-encodes to the bytes it consumed.
fn read_front(comptime T: type, bytes: []const u8, cfg: codec.Cfg(T)) !void {
    var reader = codec.Reader.init(bytes);
    var value = codec.read_cfg(T, gpa, &reader, cfg) catch return;
    defer if (@hasDecl(T, "deinit")) value.deinit(gpa);
    const consumed = bytes[0..reader.position];
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqual(value.encode_size(), encoded.len);
    try testing.expectEqualSlices(u8, consumed, encoded);
}

/// The first byte picks the family and the message; the rest is read as it.
fn decode_run(input: []const u8) anyerror!void {
    if (input.len == 0) return;
    const bytes = input[1..];
    inline for (families, 0..) |F, family| {
        if (input[0] % 2 == family) switch (input[0] / 2 % 3) {
            0 => try read_front(sync.Target(F, D), bytes, {}),
            1 => try read_front(sync.Request(F), bytes, {}),
            2 => try read_front(Response(F), bytes, response_cfg(F)),
            else => unreachable,
        };
    }
}

/// A location near `anchor`: below, equal, or above it, or near the family's domain bound.
fn draw_location(comptime F: type, reader: *fuzz_bytes.Reader, anchor: u64) u64 {
    const delta = reader.below(3);
    return switch (reader.below(4)) {
        0 => anchor -| delta,
        1 => anchor +| delta,
        2 => F.max_leaves - 1 + delta,
        else => reader.below(1 << 20),
    };
}

fn expect_target(comptime F: type, reader: *fuzz_bytes.Reader) !void {
    const start = draw_location(F, reader, reader.below(1 << 20));
    const end = draw_location(F, reader, start);
    var buffer: [64]u8 = undefined;
    var writer = codec.Writer.init(&buffer);
    codec.write(D, D.fill(reader.int(u8)), &writer);
    operation.write_location(start, &writer);
    operation.write_location(end, &writer);
    const valid = start < end and end <= F.max_leaves;
    const decoded = codec.decode(sync.Target(F, D), gpa, writer.written());
    if (!valid) return testing.expectError(error.Invalid, decoded);
    const target = try decoded;
    try testing.expectEqual(start, target.start);
    try testing.expectEqual(end, target.end);
}

fn expect_request(comptime F: type, reader: *fuzz_bytes.Reader) !void {
    const size = draw_location(F, reader, reader.below(1 << 20));
    const start = draw_location(F, reader, size);
    const boundary = reader.boolean();
    const ops = reader.below(3);
    var buffer: [64]u8 = undefined;
    var writer = codec.Writer.init(&buffer);
    writer.write_byte(@intFromBool(boundary));
    operation.write_location(size, &writer);
    operation.write_location(start, &writer);
    if (!boundary) writer.write_int(u64, ops);
    const valid = size <= F.max_leaves and start < size and (boundary or ops > 0);
    const decoded = codec.decode(sync.Request(F), gpa, writer.written());
    if (!valid) return testing.expectError(error.Invalid, decoded);
    const request = try decoded;
    try testing.expectEqual(size, request.size());
    try testing.expectEqual(start, request.start());
    try testing.expectEqual(if (boundary) 1 else ops, request.max_ops());
}

fn expect_response(reader: *fuzz_bytes.Reader) !void {
    var digests: [3]D = undefined;
    for (&digests) |*digest| digest.* = D.fill(reader.int(u8));
    var items: [max_ops + 1]u64 = undefined;
    for (&items) |*item| item.* = reader.int(u64);
    const R = Response(Mmr);
    const proof: R.Proof = .{
        .leaves = reader.below(1 << 40),
        .inactive_peaks = @intCast(reader.below(3)),
        .digests = digests[0..@intCast(reader.below(digests.len + 1))],
    };
    const count: usize = @intCast(reader.below(items.len + 1));
    const response: R = if (reader.boolean())
        .{ .operations = .{ .proof = proof, .operations = items[0..count] } }
    else
        .{ .boundary = .{ .proof = proof, .op = items[0], .pinned_nodes = digests[0..1] } };
    const encoded = try codec.encode(R, gpa, response);
    defer gpa.free(encoded);
    const decoded = codec.decode_cfg(R, gpa, encoded, response_cfg(Mmr));
    if (response == .operations and count > max_ops) {
        return testing.expectError(error.InvalidLength, decoded);
    }
    var value = try decoded;
    defer value.deinit(gpa);
    try testing.expect(value.proof().eql(&proof));
    // Every truncation must fail cleanly.
    for (0..encoded.len) |len| {
        const truncated = codec.decode_cfg(R, gpa, encoded[0..len], response_cfg(Mmr));
        try testing.expect(std.meta.isError(truncated));
    }
}

fn fields_run(input: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(input);
    inline for (families) |F| {
        try expect_target(F, &reader);
        try expect_request(F, &reader);
    }
    try expect_response(&reader);
}

test "fuzz qmdb_sync_codec (seeded)" {
    try fuzz_bytes.seeded(160, 0x73796e63, 512, decode_run);
    try fuzz_bytes.seeded(128, 0x73796e64, 256, fields_run);
}

test "fuzz qmdb_sync_codec" {
    try testing.fuzz({}, fuzz_bytes.smith(160, decode_run), .{});
}

test "fuzz qmdb_sync_codec_fields" {
    try testing.fuzz({}, fuzz_bytes.smith(128, fields_run), .{});
}
