//! Mock blocks for marshal tests (commonware `marshal/mocks/block.rs`).
//!
//! `EmptyBlock(H)` has no consensus context: its parent digest doubles as its certification
//! context. `Block(H, C)` stores the context it was proposed in and its precomputed digest.
//! `ready` wraps a block with its digest, as the application hands blocks to marshal.
//! commonware's `encode_block` (a `CodedBlock`) lives with the coding variant, and its
//! test-only `DigestCounter` with the tests that count digests.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const broadcast = @import("broadcast");
const codec = @import("codec");
const types = @import("../../types.zig");
const traits = @import("../../traits.zig");

const Height = types.Height;

/// `block` with its digest, owned (commonware `ready`).
pub fn ready(
    comptime B: type,
    gpa: Allocator,
    block: B,
) Allocator.Error!broadcast.Digested(B) {
    comptime traits.assert_block(B);
    return broadcast.Digested(B).precomputed(gpa, block, block.digest());
}

/// Counts `Block.digest` calls on tracked blocks and their decoded copies (commonware
/// `DigestCounter`), for tests that check a block's digest is read once per path. One
/// counter for the process: a test tracks at most `max_tracked` blocks and resets it.
pub const DigestCounter = struct {
    const max_tracked = 8;
    const max_digest_bytes = 64;
    var tracked: [max_tracked][max_digest_bytes]u8 = undefined;
    var tracked_sizes: [max_tracked]u8 = undefined;
    var tracked_len: std.atomic.Value(u32) = .init(0);
    var calls: std.atomic.Value(u64) = .init(0);

    /// Counts digest calls on blocks whose digest is `digest_bytes` from now on.
    pub fn track(digest_bytes: []const u8) void {
        const index = tracked_len.load(.acquire);
        assert(index < max_tracked);
        assert(digest_bytes.len <= max_digest_bytes);
        @memcpy(tracked[index][0..digest_bytes.len], digest_bytes);
        tracked_sizes[index] = @intCast(digest_bytes.len);
        tracked_len.store(index + 1, .release);
    }

    /// The digest calls counted since the last `reset`.
    pub fn count() u64 {
        return calls.load(.acquire);
    }

    /// Stops tracking every block and zeroes the count.
    pub fn reset() void {
        tracked_len.store(0, .release);
        calls.store(0, .release);
        assert(count() == 0);
    }

    fn observe(digest_bytes: []const u8) void {
        const len = tracked_len.load(.acquire);
        if (len == 0) return;
        for (tracked[0..len], tracked_sizes[0..len]) |*bytes, size| {
            if (std.mem.eql(u8, bytes[0..size], digest_bytes)) {
                _ = calls.fetchAdd(1, .acq_rel);
                return;
            }
        }
    }
};

/// A block with no explicit consensus context, hashed with `H`.
pub fn EmptyBlock(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const Digest = H.Digest;
        /// The parent's digest is the certification context.
        pub const Context = H.Digest;

        /// The parent block's digest.
        parent_value: Digest,
        height_value: Height,
        /// Milliseconds since the Unix epoch.
        timestamp: u64,

        pub const max_encode_size: usize = Digest.fixed_size + Height.max_encode_size +
            codec.varint.max_size(u64);

        pub fn init(parent_digest: Digest, at: Height, timestamp: u64) Self {
            return .{ .parent_value = parent_digest, .height_value = at, .timestamp = timestamp };
        }

        /// The hash of the parent, the big-endian height, and the big-endian timestamp.
        pub fn digest(self: Self) Digest {
            var height_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &height_bytes, self.height_value.get(), .big);
            var timestamp_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &timestamp_bytes, self.timestamp, .big);
            return H.hash(&.{ self.parent_value.as_slice(), &height_bytes, &timestamp_bytes });
        }

        pub fn height(self: Self) Height {
            return self.height_value;
        }

        pub fn parent(self: Self) Digest {
            return self.parent_value;
        }

        pub fn context(self: Self) Context {
            return self.parent_value;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.parent_value.eql(b.parent_value) and a.height_value == b.height_value and
                a.timestamp == b.timestamp;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.parent_value.write(writer);
            self.height_value.write(writer);
            codec.varint.write(u64, self.timestamp, writer);
        }

        pub fn encode_size(self: Self) usize {
            const size = Digest.fixed_size + self.height_value.encode_size() +
                codec.varint.size(u64, self.timestamp);
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const parent_digest = try Digest.read(gpa, reader, {});
            const at = try Height.read(gpa, reader, {});
            const timestamp = try codec.varint.read(u64, reader);
            return .{ .parent_value = parent_digest, .height_value = at, .timestamp = timestamp };
        }
    };
}

/// A block that stores the consensus context `C` it was proposed in, hashed with `H`.
pub fn Block(comptime H: type, comptime C: type) type {
    return struct {
        const Self = @This();
        pub const Digest = H.Digest;
        pub const Context = C;

        context_value: C,
        /// The parent block's digest.
        parent_value: Digest,
        height_value: Height,
        /// Milliseconds since the Unix epoch.
        timestamp: u64,
        /// Precomputed from the fields above; encoded with the block.
        digest_value: Digest,

        pub const max_encode_size: usize = codec.max_encode_size(C).? + Digest.fixed_size +
            Height.max_encode_size + codec.varint.max_size(u64) + Digest.fixed_size;

        pub fn init(
            gpa: Allocator,
            context_value: C,
            parent_digest: Digest,
            at: Height,
            timestamp: u64,
        ) Allocator.Error!Self {
            const encoded_context = try codec.encode(C, gpa, context_value);
            defer gpa.free(encoded_context);
            var height_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &height_bytes, at.get(), .big);
            var timestamp_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &timestamp_bytes, timestamp, .big);
            const digest_value = H.hash(&.{
                parent_digest.as_slice(),
                &height_bytes,
                encoded_context,
                &timestamp_bytes,
            });
            return .{
                .context_value = context_value,
                .parent_value = parent_digest,
                .height_value = at,
                .timestamp = timestamp,
                .digest_value = digest_value,
            };
        }

        pub fn digest(self: Self) Digest {
            DigestCounter.observe(self.digest_value.as_slice());
            return self.digest_value;
        }

        pub fn height(self: Self) Height {
            return self.height_value;
        }

        pub fn parent(self: Self) Digest {
            return self.parent_value;
        }

        pub fn context(self: Self) C {
            return self.context_value;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(C, self.context_value, writer);
            self.parent_value.write(writer);
            self.height_value.write(writer);
            codec.varint.write(u64, self.timestamp, writer);
            self.digest_value.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            const size = codec.encode_size(C, self.context_value) + Digest.fixed_size +
                self.height_value.encode_size() + codec.varint.size(u64, self.timestamp) +
                Digest.fixed_size;
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const context_value = try codec.read(C, gpa, reader);
            const parent_digest = try Digest.read(gpa, reader, {});
            const at = try Height.read(gpa, reader, {});
            const timestamp = try codec.varint.read(u64, reader);
            const digest_value = try Digest.read(gpa, reader, {});
            return .{
                .context_value = context_value,
                .parent_value = parent_digest,
                .height_value = at,
                .timestamp = timestamp,
                .digest_value = digest_value,
            };
        }
    };
}

const testing = std.testing;
const Sha256 = @import("cryptography").Sha256;

/// SHA-256 of `parts`, computed with the standard library (independent of the hasher).
fn sha256(parts: []const []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (parts) |part| hasher.update(part);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

test "empty block digest and codec" {
    const B = EmptyBlock(Sha256);
    comptime traits.assert_certifiable_block(B);
    const parent_digest = Sha256.Digest.fill(7);
    const block = B.init(parent_digest, .new(3), 1234);
    const expected = sha256(&.{
        &parent_digest.bytes,
        &.{ 0, 0, 0, 0, 0, 0, 0, 3 },
        &.{ 0, 0, 0, 0, 0, 0, 0x04, 0xd2 },
    });
    try testing.expectEqualSlices(u8, &expected, &block.digest().bytes);
    try testing.expect(block.context().eql(parent_digest));

    const encoded = try codec.encode(B, testing.allocator, block);
    defer testing.allocator.free(encoded);
    // Digest, varint height (1 byte), varint timestamp (2 bytes).
    try testing.expectEqual(32 + 1 + 2, encoded.len);
    const decoded = try codec.decode(B, testing.allocator, encoded);
    try testing.expect(decoded.eql(block));
    try testing.expectError(error.EndOfBuffer, codec.decode(B, testing.allocator, encoded[1..]));
}

test "context block digest covers the encoded context" {
    const B = Block(Sha256, types.Round);
    comptime traits.assert_certifiable_block(B);
    const gpa = testing.allocator;
    const round: types.Round = .new(.new(2), .new(300));
    const parent_digest = Sha256.Digest.fill(9);
    const block = try B.init(gpa, round, parent_digest, .new(5), 77);
    // The round encodes as varint epoch 2 and varint view 300 (0xac 0x02).
    const expected = sha256(&.{
        &parent_digest.bytes,
        &.{ 0, 0, 0, 0, 0, 0, 0, 5 },
        &.{ 2, 0xac, 0x02 },
        &.{ 0, 0, 0, 0, 0, 0, 0, 77 },
    });
    try testing.expectEqualSlices(u8, &expected, &block.digest().bytes);
    const other = try B.init(gpa, .new(.new(2), .new(301)), parent_digest, .new(5), 77);
    try testing.expect(!block.digest().eql(other.digest()));

    const encoded = try codec.encode(B, gpa, block);
    defer gpa.free(encoded);
    try testing.expectEqual(3 + 32 + 1 + 1 + 32, encoded.len);
    const decoded = try codec.decode(B, gpa, encoded);
    try testing.expect(decoded.digest().eql(block.digest()));
    try testing.expectEqual(block.height(), decoded.height());
    try testing.expect(std.meta.eql(decoded.context(), round));
}

test "ready keeps the block's digest" {
    const B = EmptyBlock(Sha256);
    const block = B.init(Sha256.Digest.fill(1), .new(1), 2);
    var digested = try ready(B, testing.allocator, block);
    defer digested.deinit();
    try testing.expect(digested.digest().eql(block.digest()));
}
