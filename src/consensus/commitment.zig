//! Coding commitments (commonware `consensus::types::coding`): the certificate payload for
//! erasure-coded blocks.
//!
//! A `Commitment(BlockDigest, Root, Context)` is 100 bytes:
//!
//! ```text
//! 0                   32                  64                  96            100
//! +-------------------+-------------------+-------------------+---------------+
//! | block digest      | coding root       | context digest    | coding config |
//! +-------------------+-------------------+-------------------+---------------+
//! ```
//!
//! Each digest field is 32 bytes wide; a shorter digest is followed by zero padding. Decoding
//! parses every field as its declared type and rejects non-zero padding, so the accessors of a
//! decoded commitment never fail. `BlockDigest` is the block's digest, `Root` the coding
//! scheme's `Commitment`, and `Context` the context hasher's digest.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const coding = @import("coding");

const Config = coding.Config;

/// The fixed wire width of each digest field.
pub const commitment_digest_size: usize = 32;
/// The encoded size of a commitment.
pub const commitment_size: usize = 3 * commitment_digest_size + Config.fixed_size;

pub fn Commitment(comptime BlockDigest: type, comptime Root: type, comptime Context: type) type {
    comptime {
        assert(codec.fixed_size(BlockDigest).? <= commitment_digest_size);
        assert(codec.fixed_size(Root).? <= commitment_digest_size);
        assert(codec.fixed_size(Context).? <= commitment_digest_size);
        assert(Config.fixed_size == 4);
    }
    return struct {
        const Self = @This();
        const context_name = "Commitment";
        const block_offset = 0;
        const root_offset = block_offset + commitment_digest_size;
        const context_offset = root_offset + commitment_digest_size;
        const config_offset = context_offset + commitment_digest_size;

        bytes: [commitment_size]u8,

        pub const fixed_size: usize = commitment_size;
        /// The all-zero sentinel (commonware `Digest::EMPTY`). Its config bytes are not a valid
        /// `Config`, so the accessors must not be called on it.
        pub const empty: Self = .{ .bytes = @splat(0) };

        pub fn init(
            block_digest: BlockDigest,
            root_digest: Root,
            context_digest: Context,
            coding_config: Config,
        ) Self {
            var bytes: [commitment_size]u8 = @splat(0);
            put(BlockDigest, &bytes, block_offset, block_digest);
            put(Root, &bytes, root_offset, root_digest);
            put(Context, &bytes, context_offset, context_digest);
            put(Config, &bytes, config_offset, coding_config);
            return .{ .bytes = bytes };
        }

        fn put(comptime T: type, bytes: *[commitment_size]u8, offset: usize, value: T) void {
            const size = comptime codec.fixed_size(T).?;
            const written = codec.encode_to(T, value, bytes[offset..][0..size]);
            assert(written.len == size);
        }

        fn field(self: *const Self, comptime T: type, comptime offset: usize) T {
            const size = comptime codec.fixed_size(T).?;
            // Proof: `init` encodes each field as `T`, and `read` validates each one.
            return codec.decode_fixed(T, self.bytes[offset..][0..size]) catch unreachable;
        }

        pub fn block(self: *const Self) BlockDigest {
            return self.field(BlockDigest, block_offset);
        }

        pub fn root(self: *const Self) Root {
            return self.field(Root, root_offset);
        }

        pub fn context(self: *const Self) Context {
            return self.field(Context, context_offset);
        }

        pub fn config(self: *const Self) Config {
            return self.field(Config, config_offset);
        }

        pub fn as_slice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }

        pub fn order(a: Self, b: Self) std.math.Order {
            return std.mem.order(u8, &a.bytes, &b.bytes);
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{x}", .{&self.bytes});
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_bytes(&self.bytes);
        }

        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const bytes = try reader.take_array(commitment_size);
            try validate_field(BlockDigest, reader, bytes, block_offset, "invalid block digest");
            try validate_field(Root, reader, bytes, root_offset, "invalid coding root");
            try validate_field(
                Context,
                reader,
                bytes,
                context_offset,
                "invalid context digest",
            );
            const config_bytes = bytes[config_offset..][0..Config.fixed_size];
            _ = codec.decode_fixed(Config, config_bytes) catch
                return reader.invalid(context_name, "invalid embedded CodingConfig");
            return .{ .bytes = bytes.* };
        }

        /// Parses a digest field as `T` and checks its zero padding.
        fn validate_field(
            comptime T: type,
            reader: *codec.Reader,
            bytes: *const [commitment_size]u8,
            comptime offset: usize,
            comptime reason: []const u8,
        ) codec.Error!void {
            const size = comptime codec.fixed_size(T).?;
            _ = codec.decode_fixed(T, bytes[offset..][0..size]) catch
                return reader.invalid(context_name, reason);
            const padding = bytes[offset + size .. offset + commitment_digest_size];
            for (padding) |byte| {
                if (byte != 0) return reader.invalid(context_name, "non-zero digest padding");
            }
        }
    };
}

const testing = std.testing;
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const Sha256 = cryptography.Sha256;
const Crc32Digest = cryptography.crc32.Digest;

const one_one: Config = .{ .minimum_shards = 1, .extra_shards = 1 };

fn crc(value: u32) Crc32Digest {
    var digest: Crc32Digest = undefined;
    std.mem.writeInt(u32, &digest.bytes, value, .big);
    return digest;
}

/// A 32-byte digest whose decoding always fails.
const Unreadable = struct {
    bytes: [32]u8,
    pub const fixed_size: usize = 32;
    pub fn write(self: Unreadable, writer: *codec.Writer) void {
        writer.write_bytes(&self.bytes);
    }
    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Unreadable {
        return reader.invalid("Digest", "read not implemented");
    }
};

fn expect_rejected(comptime C: type, value: C) !void {
    const encoded = codec.encode_fixed(C, value);
    try testing.expectError(error.Invalid, codec.decode(C, testing.allocator, &encoded));
}

test "coding commitment rejects fallible digests" {
    const bad: Unreadable = .{ .bytes = @splat(7) };
    const ok = Sha256.Digest.empty;
    const ByBlock = Commitment(Unreadable, Unreadable, Unreadable);
    try expect_rejected(ByBlock, .init(bad, bad, bad, one_one));
    const ByRoot = Commitment(Sha256.Digest, Unreadable, Sha256.Digest);
    try expect_rejected(ByRoot, .init(ok, bad, ok, one_one));
    const ByContext = Commitment(Sha256.Digest, Sha256.Digest, Unreadable);
    try expect_rejected(ByContext, .init(ok, ok, bad, one_one));
    // A zero shard count is not a valid config.
    const Valid = Commitment(Sha256.Digest, Sha256.Digest, Sha256.Digest);
    try expect_rejected(Valid, .{ .bytes = @splat(0) });
}

test "coding commitment supports short digest types" {
    const C = Commitment(Crc32Digest, Crc32Digest, Crc32Digest);
    const commitment = C.init(crc(1), crc(2), crc(3), one_one);
    try testing.expectEqual(commitment_size, C.fixed_size);
    const encoded = codec.encode_fixed(C, commitment);
    try testing.expectEqual(100, encoded.len);
    const decoded = try codec.decode(C, testing.allocator, &encoded);
    try testing.expectEqual(1, decoded.block().as_u32());
    try testing.expectEqual(2, decoded.root().as_u32());
    try testing.expectEqual(3, decoded.context().as_u32());
    try testing.expect(decoded.config().eql(one_one));
    // The padding after each short digest is zero, and the config sits at offset 96.
    try testing.expectEqualSlices(u8, &@as([28]u8, @splat(0)), encoded[4..32]);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 0, 1 }, encoded[96..100]);
}

test "coding commitment rejects non-zero digest padding" {
    const C = Commitment(Crc32Digest, Crc32Digest, Crc32Digest);
    const encoded = codec.encode_fixed(C, C.init(crc(1), crc(2), crc(3), one_one));
    for ([_]usize{ 4, 32 + 4, 64 + 4, 31 }) |offset| {
        var malformed = encoded;
        malformed[offset] = 1;
        try testing.expectError(error.Invalid, codec.decode(C, testing.allocator, &malformed));
    }
}

/// commonware's SHA-256 digest `Arbitrary`: the hash of `int_in_range(0..=256)` drawn bytes.
fn gen_sha256(
    gpa: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!Sha256.Digest {
    const len = u.int_in_range(u64, 0, 256);
    const data = try gpa.alloc(u8, len);
    try u.bytes(data);
    return Sha256.hash(&.{data});
}

const TestCommitment = Commitment(Sha256.Digest, Sha256.Digest, Sha256.Digest);

fn gen_commitment(
    gpa: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!TestCommitment {
    const block_digest = try gen_sha256(gpa, u);
    const root_digest = try gen_sha256(gpa, u);
    const context_digest = try gen_sha256(gpa, u);
    const minimum = u.int_in_range(u16, 1, std.math.maxInt(u16));
    const extra = u.int_in_range(u16, 1, std.math.maxInt(u16));
    const coding_config: Config = .{ .minimum_shards = minimum, .extra_shards = extra };
    return .init(block_digest, root_digest, context_digest, coding_config);
}

const CommitmentConformance = struct {
    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const gpa_arena = arena.allocator();
        const value = try codec.arbitrary.generate(TestCommitment, gen_commitment, gpa_arena, seed);
        return codec.encode(TestCommitment, gpa, value);
    }
};

test "coding commitment conformance hash matches commonware" {
    try conformance.verify(
        CommitmentConformance,
        std.heap.smp_allocator,
        "commonware_consensus::types::tests::conformance::CodecConformance<TestCommitment>",
        conformance.default_cases,
        @embedFile("conformance.toml"),
    );
}
