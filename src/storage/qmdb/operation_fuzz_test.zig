//! Decoder fuzz for every QMDB operation type: any input that decodes must re-encode to the
//! same bytes (each operation has exactly one encoding), and decoding never over-reads or
//! leaks. The input picks a type and an `arbitrary` seed; the fuzz encodes that value, checks
//! it round-trips, then corrupts up to two bytes and checks the corrupted encoding is either
//! refused or canonical. Raw input bytes are decoded too, with a valid wire tag most of the
//! time.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const merkle = @import("../merkle/mod.zig");
const value = @import("value.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");
const keyless = @import("keyless/operation.zig");
const immutable = @import("immutable/operation.zig");
const any = @import("any/operation.zig");
const chain = @import("chain.zig");
const cryptography = @import("cryptography");

const U64 = utils.sequence.U64;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;
const Bytes = []const u8;
const Digest = cryptography.Sha256.Digest;
const bytes_cfg: codec.Cfg(Bytes) = .{ .range = .to_inclusive(64) };

const Target = struct { type, []const u8 };

const targets = [_]Target{
    .{ keyless.Operation(Mmr, value.Fixed(U64)), &.{ 0, 1 } },
    .{ keyless.Operation(Mmb, value.Variable(Bytes)), &.{ 0, 1 } },
    .{ immutable.Operation(Mmr, U64, value.Fixed(U64)), &.{ 0, 1 } },
    .{ immutable.Operation(Mmr, Bytes, value.Variable(U64)), &.{ 0, 1 } },
    .{ any.Ordered(Mmr, U64, value.Fixed(U64)), &.{ 0xD1, 0xD2, 0xD3 } },
    .{ any.Ordered(Mmb, U64, value.Variable(Bytes)), &.{ 0xD1, 0xD2, 0xD3 } },
    .{ any.Unordered(Mmr, U64, value.Fixed(U64)), &.{ 0xD1, 0xD2, 0xD3 } },
    .{ any.Unordered(Mmb, U64, value.Variable(Bytes)), &.{ 0xD1, 0xD2, 0xD3 } },
    .{ chain.Commitment(Mmr, Digest), &.{} },
};

fn cfg_of(comptime T: type) codec.Cfg(T) {
    const C = codec.Cfg(T);
    if (C == void) return {};
    // Variable encodings: a key config and a value config, or a value config alone.
    if (@typeInfo(C) == .@"struct" and @typeInfo(C).@"struct".is_tuple) {
        var cfg: C = undefined;
        inline for (@typeInfo(C).@"struct".field_types, 0..) |field_type, index| {
            cfg[index] = if (field_type == void) {} else bytes_cfg;
        }
        return cfg;
    }
    return bytes_cfg;
}

fn check(comptime T: type, input: []const u8) !void {
    const gpa = testing.allocator;
    var decoded = codec.decode_cfg(T, gpa, input, cfg_of(T)) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
    defer if (comptime codec.owns_memory(T)) decoded.deinit(gpa);
    try testing.expectEqual(input.len, codec.encode_size(T, decoded));
    const encoded = try codec.encode(T, gpa, decoded);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, input, encoded);
}

fn Generated(comptime T: type) type {
    return struct {
        fn generate(gpa: std.mem.Allocator, u: *codec.arbitrary.Unstructured) !T {
            return T.arbitrary(gpa, u);
        }
    };
}

/// Encodes `T::arbitrary` for `seed`, checks it decodes back to itself, then applies the
/// reader's corruptions and checks the result.
fn check_generated(comptime T: type, seed: u64, reader: *fuzz_bytes.Reader) !void {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const generate = Generated(T).generate;
    const generated = codec.arbitrary.generate(T, generate, arena.allocator(), seed) catch
        return; // Values too large for the generator's buffer are skipped.
    const encoded = try codec.encode(T, gpa, generated);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(T, gpa, encoded, cfg_of(T));
    defer if (comptime codec.owns_memory(T)) decoded.deinit(gpa);
    try testing.expect(decoded.eql(generated));
    for (0..2) |_| {
        const position = reader.below(encoded.len);
        encoded[position] ^= reader.int(u8);
    }
    try check(T, encoded);
}

fn run_one(input: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(input);
    const choice = reader.below(targets.len);
    const raw = reader.int(u8);
    const seed = reader.int(u16);
    inline for (targets, 0..) |target, index| {
        if (index == choice) {
            try check_generated(target[0], seed, &reader);
            var buffer: [256]u8 = undefined;
            const rest = input[reader.offset..];
            const len = @min(rest.len, buffer.len);
            @memcpy(buffer[0..len], rest[0..len]);
            const tags = target[1];
            // Keep the raw tag one time in eight to cover invalid tags.
            if (len > 0 and tags.len > 0 and raw & 7 != 0) buffer[0] = tags[buffer[0] % tags.len];
            try check(target[0], buffer[0..len]);
        }
    }
}

test "fuzz qmdb operation decoders (seeded)" {
    try fuzz_bytes.seeded(64, 0x716d6462, 4096, run_one);
}

test "fuzz qmdb operation decoders" {
    try testing.fuzz({}, fuzz_bytes.smith(256, run_one), .{});
}
