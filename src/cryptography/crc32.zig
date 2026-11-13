//! CRC-32C (Castagnoli, the iSCSI polynomial) implementation of the hasher interface
//! (commonware `cryptography/src/crc32`).
//!
//! Checksums only: CRC32 detects accidental corruption and offers no protection against
//! deliberate tampering. The digest encodes as the checksum's 4 big-endian bytes.
//!
//! Backed by `std.hash.crc.@"CRC-32/ISCSI"`, which uses the SSE4.2 instruction when the target
//! has it and a table otherwise. The two keep their running state differently (the hardware
//! wrapper stores the checksum so far, the table version the pre-xor register); both start
//! from the state of the empty checksum, so `state = checksum ^ init().crc` covers both.

const std = @import("std");
const codec = @import("codec");
const assert = std.debug.assert;
const hasher = @import("hasher.zig");
const digest = @import("digest.zig");

pub const Core = std.hash.crc.@"CRC-32/ISCSI";

const size = 4;

/// Digest of a CRC32 checksum: the checksum's big-endian bytes.
pub const Digest = digest.Digest(size, "crc32");

/// CRC-32C hasher.
pub const Crc32 = struct {
    const Self = @This();
    pub const Digest = digest.Digest(size, "crc32");

    core: Core,

    pub fn init() Self {
        return .{ .core = Core.init() };
    }

    /// The CRC-32C checksum of `data`.
    pub fn checksum(data: []const u8) u32 {
        var core = Core.init();
        core.update(data);
        return core.final();
    }

    /// A hasher that continues the stream whose checksum so far is `value`.
    pub fn resume_from(value: u32) Self {
        var self: Self = .{ .core = Core.init() };
        self.core.crc = value ^ Core.init().crc;
        assert(self.core.final() == value);
        return self;
    }

    pub fn update(self: *Self, bytes: []const u8) void {
        self.core.update(bytes);
    }

    /// Returns the checksum so far and resets the hasher to the empty stream.
    pub fn finalize(self: *Self) Self.Digest {
        const value = self.core.final();
        self.* = init();
        assert(self.core.final() == 0);
        return Self.Digest.from_u32(value);
    }

    pub fn hash(parts: []const []const u8) Self.Digest {
        var self = init();
        for (parts) |part| self.update(part);
        return self.finalize();
    }

    pub fn hash_across(parts: []const []const u8, strategy: anytype) Self.Digest {
        _ = strategy;
        return hash(parts);
    }

    pub fn hash_pair(
        left: []const []const u8,
        right: []const []const u8,
        strategy: anytype,
    ) [2]Self.Digest {
        _ = strategy;
        return .{ hash(left), hash(right) };
    }

    pub fn hash_many(messages: []const []const u8, digests: []Self.Digest, strategy: anytype) void {
        _ = strategy;
        hasher.hash_each(Self, messages, digests);
    }
};

comptime {
    assert(Crc32.Digest == Digest);
    hasher.assert_hasher(Crc32);
}

const testing = std.testing;
const fuzz = @import("fuzz.zig");

/// Bitwise reference CRC-32C, independent of the table and hardware paths.
fn reference(data: []const u8) u32 {
    var crc: u32 = 0xffffffff;
    for (data) |byte| {
        crc ^= byte;
        for (0..8) |_| crc = (crc >> 1) ^ (0x82f63b78 & (0 -% (crc & 1)));
    }
    return ~crc;
}

fn verify(data: []const u8, expected: u32) !void {
    try testing.expectEqual(expected, reference(data));
    try testing.expectEqual(expected, Crc32.checksum(data));
}

fn sequential(out: []u8) []u8 {
    for (out, 0..) |*byte, i| byte.* = @truncate(i);
    return out;
}

test "crc32 RFC 3720 vectors" {
    try verify(&@as([32]u8, @splat(0)), 0x8A9136AA);
    try verify(&@as([32]u8, @splat(0xff)), 0x62A8AB43);
    var ascending: [32]u8 = undefined;
    var descending: [32]u8 = undefined;
    for (0..32) |i| {
        ascending[i] = @intCast(i);
        descending[i] = @intCast(31 - i);
    }
    try verify(&ascending, 0x46DD794E);
    try verify(&descending, 0x113FDB5C);
    const iscsi_read_pdu = [48]u8{
        0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x18, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try verify(&iscsi_read_pdu, 0xD9963A56);
}

test "crc32 external vectors" {
    try verify("", 0x00000000);
    try verify("123456789", 0xE3069283);
    try verify("23456789", 0xBFE92A83);
    try verify("The quick brown fox jumps over the lazy dog", 0x22620404);
    var leveldb: [240]u8 = undefined;
    for (&leveldb, 0..) |*byte, i| byte.* = @intCast(i + 1);
    try verify(&leveldb, 0x24C5D375);
}

test "crc32 SIMD boundaries" {
    const expected = [_]struct { usize, u32 }{
        .{ 0, 0x00000000 },    .{ 1, 0x527D5351 },    .{ 2, 0x030AF4D1 },    .{ 3, 0x92FD4BFA },
        .{ 4, 0xD9331AA3 },    .{ 7, 0xA359ED4C },    .{ 8, 0x8A2CBC3B },    .{ 9, 0x7144C5A8 },
        .{ 15, 0x68EF03F6 },   .{ 16, 0xD9C908EB },   .{ 17, 0x38435E17 },   .{ 31, 0xE95CABCB },
        .{ 32, 0x46DD794E },   .{ 33, 0x9F85A26D },   .{ 63, 0x7A873004 },   .{ 64, 0xFB6D36EB },
        .{ 65, 0x694420FA },   .{ 127, 0x6C31BD0C },  .{ 128, 0x30D9C515 },  .{ 129, 0xF514629F },
        .{ 255, 0x8953C482 },  .{ 256, 0x9C44184B },  .{ 257, 0x8A13A1CE },  .{ 511, 0x35348950 },
        .{ 512, 0xAE10EE5A },  .{ 513, 0x6814B154 },  .{ 1023, 0x0C8F24D0 }, .{ 1024, 0x2CDF6E8F },
        .{ 1025, 0x8EB48B63 }, .{ 4095, 0xBCB5BD82 }, .{ 4096, 0x9C71FE32 }, .{ 4097, 0x83391BE9 },
    };
    var buffer: [4097]u8 = undefined;
    const data = sequential(&buffer);
    for (expected) |entry| try verify(data[0..entry[0]], entry[1]);
}

test "crc32 chunk size and alignment independence" {
    var buffer: [1024]u8 = undefined;
    const data = sequential(&buffer);
    const expected = reference(data);
    for (1..65) |chunk| {
        var h = Crc32.init();
        var offset: usize = 0;
        while (offset < data.len) : (offset += chunk) {
            h.update(data[offset..@min(offset + chunk, data.len)]);
        }
        try testing.expectEqual(expected, h.finalize().as_u32());
    }
    for (0..16) |offset| {
        const window = data[offset..][0..64];
        try testing.expectEqual(reference(window), Crc32.checksum(window));
    }
}

test "crc32 hasher interface" {
    var h = Crc32.init();
    h.update("hello world");
    const d = h.finalize();
    try testing.expectEqual(reference("hello world"), d.as_u32());
    h.update("hello world");
    try testing.expect(h.finalize().eql(d));
    try testing.expect(Crc32.hash(&.{"hello world"}).eql(d));
    try testing.expect(Crc32.hash(&.{ "hello", " world" }).eql(d));
    const encoded = codec.encode_fixed(Digest, d);
    try testing.expect((try codec.decode(Digest, testing.allocator, &encoded)).eql(d));
    const dead = Digest.from_u32(0xDEADBEEF);
    try testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, &dead.bytes);
}

test "crc32 resume continues the stream and finalize resets" {
    var h = Crc32.resume_from(Crc32.checksum("durable prefix"));
    h.update("new suffix");
    try testing.expect(h.finalize().eql(Crc32.hash(&.{ "durable prefix", "new suffix" })));
    h.update("new suffix");
    try testing.expectEqual(Crc32.checksum("new suffix"), h.finalize().as_u32());

    var buffer: [4097]u8 = undefined;
    const data = sequential(&buffer);
    const expected = reference(data);
    for (0..data.len + 1) |split| {
        var resumed = Crc32.resume_from(reference(data[0..split]));
        resumed.update(data[split..]);
        try testing.expectEqual(expected, resumed.finalize().as_u32());
    }
    for ([_]u32{ 0, 0xffffffff, 0xdeadbeef, Crc32.checksum("resume") }) |value| {
        var resumed = Crc32.resume_from(value);
        try testing.expectEqual(value, resumed.finalize().as_u32());
    }
}

test "crc32 fuzz hasher entrypoints" {
    try fuzz.fuzz_hasher(Crc32, 0xc4c32);
}
