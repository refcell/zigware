//! Fuzzing utilities for hashers (commonware `cryptography/src/fuzz.rs`).
//!
//! For any hasher, the one-shot `hash`, `hash_across`, `hash_pair`, and `hash_many` entrypoints
//! must agree with streaming the same bytes through `update`. Inputs are biased toward the
//! shapes and lengths implementations specialize (merkle node shapes, block boundaries).
//!
//! `Input` is a small stand-in for Rust's `arbitrary::Unstructured`: it draws values from a
//! byte string and yields zeroes once the bytes run out, so every input decodes to some plan.

const std = @import("std");
const parallel = @import("parallel");
const assert = std.debug.assert;
const build_options = @import("build_options");

/// Largest message a plan generates, in bytes.
pub const message_length_max = 1024;
/// Most messages a batch plan generates.
pub const batch_count_max = 40;

/// Draws structured values from fuzzer bytes.
pub const Input = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) Input {
        return .{ .bytes = bytes };
    }

    /// Takes up to `count` bytes; fewer when the input runs out.
    pub fn take(self: *Input, count: usize) []const u8 {
        const n = @min(count, self.bytes.len);
        const out = self.bytes[0..n];
        self.bytes = self.bytes[n..];
        assert(out.len <= count);
        return out;
    }

    /// A value in `[min, max]`, drawn from as few bytes as the range needs.
    pub fn int_in_range(self: *Input, min: u64, max: u64) u64 {
        assert(min <= max);
        const range = max - min;
        if (range == 0) return min;
        const width: usize = @divFloor(64 - @clz(range) + 7, 8);
        var value: u64 = 0;
        for (self.take(width)) |byte| value = (value << 8) | byte;
        const result = min + if (range == std.math.maxInt(u64)) value else value % (range + 1);
        assert(result >= min and result <= max);
        return result;
    }

    pub fn boolean(self: *Input) bool {
        return self.int_in_range(0, 1) == 1;
    }

    /// Fills `out` from the input, padding with zeroes when the input runs out.
    pub fn fill(self: *Input, out: []u8) void {
        const got = self.take(out.len);
        @memcpy(out[0..got.len], got);
        @memset(out[got.len..], 0);
    }
};

/// Iterations of a seeded fuzz loop, scaled by `-Dfuzz-soak`.
pub fn iterations(base: u32) u32 {
    assert(base > 0);
    return base * @max(build_options.fuzz_soak, 1);
}

/// A seeded generator for deterministic fuzz loops, mixed with `-Dfuzz-seed`.
pub fn prng(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed ^ build_options.fuzz_seed);
}

/// A message length biased toward SHA-256's fast-path boundaries (64, 72, 119 bytes).
fn arbitrary_length(input: *Input) usize {
    return switch (input.int_in_range(0, 6)) {
        0 => 55,
        1 => 64,
        2 => 72,
        3 => 119,
        4 => 120,
        5 => 1024,
        else => @intCast(input.int_in_range(0, message_length_max)),
    };
}

/// A message as at most three parts in `storage`: a merkle shape or a split message.
pub const Message = struct {
    storage: [message_length_max]u8 = undefined,
    lengths: [3]usize = .{ 0, 0, 0 },
    count: usize = 0,

    pub fn arbitrary(input: *Input) Message {
        var message: Message = .{};
        const shape: [3]usize = switch (input.int_in_range(0, 4)) {
            0 => .{ 8, 32, 32 },
            1 => .{ 32, 32, 0 },
            2 => .{ 8, 32, 0 },
            3 => .{ 4, 32, 0 },
            else => split: {
                const length = arbitrary_length(input);
                const at: usize = @intCast(input.int_in_range(0, length));
                break :split .{ at, length - at, 0 };
            },
        };
        const count: usize = if (shape[2] > 0) 3 else 2;
        message.count = count;
        message.lengths = shape;
        const total = shape[0] + shape[1] + shape[2];
        assert(total <= message_length_max);
        input.fill(message.storage[0..total]);
        return message;
    }

    /// The message's parts, as slices into `storage` written to `parts`.
    pub fn parts(self: *const Message, out: *[3][]const u8) []const []const u8 {
        var offset: usize = 0;
        for (0..self.count) |index| {
            out[index] = self.storage[offset..][0..self.lengths[index]];
            offset += self.lengths[index];
        }
        return out[0..self.count];
    }
};

/// Checks that every one-shot entrypoint of `H` agrees with streaming `left` and `right`.
pub fn run_plan(comptime H: type, left: []const []const u8, right: []const []const u8) !void {
    const expected_left = reference(H, left);
    const expected_right = reference(H, right);

    // Stream each part separately, reusing the hasher finalize reset for the second message.
    var hasher = H.init();
    for (left) |part| hasher.update(part);
    const streamed_left = hasher.finalize();
    for (right) |part| hasher.update(part);
    const streamed_right = hasher.finalize();
    try expect_digest(H, expected_left, streamed_left);
    try expect_digest(H, expected_right, streamed_right);

    try expect_digest(H, expected_left, H.hash(left));
    try expect_digest(H, expected_right, H.hash(right));
    try expect_digest(H, expected_left, H.hash_across(left, parallel.sequential));
    try expect_digest(H, expected_right, H.hash_across(right, parallel.sequential));
    const pair = H.hash_pair(left, right, parallel.sequential);
    try expect_digest(H, expected_left, pair[0]);
    try expect_digest(H, expected_right, pair[1]);
}

/// Hashes the concatenation of `parts` with a single `update`.
fn reference(comptime H: type, parts: []const []const u8) H.Digest {
    var buffer: [4 * message_length_max]u8 = undefined;
    var length: usize = 0;
    for (parts) |part| {
        @memcpy(buffer[length..][0..part.len], part);
        length += part.len;
    }
    var hasher = H.init();
    hasher.update(buffer[0..length]);
    return hasher.finalize();
}

fn expect_digest(comptime H: type, expected: H.Digest, actual: H.Digest) !void {
    try std.testing.expectEqualSlices(u8, &expected.bytes, &actual.bytes);
}

/// Runs one arbitrary plan decoded from `bytes` against `H`.
pub fn run_arbitrary_plan(comptime H: type, bytes: []const u8) !void {
    var input = Input.init(bytes);
    const left = Message.arbitrary(&input);
    const right = Message.arbitrary(&input);
    var left_parts: [3][]const u8 = undefined;
    var right_parts: [3][]const u8 = undefined;
    try run_plan(H, left.parts(&left_parts), right.parts(&right_parts));
}

/// The hasher differential fuzz: the empty plan, seeded arbitrary plans, then the same plans
/// decoded from coverage-guided input.
pub fn fuzz_hasher(comptime H: type, seed: u64) !void {
    try run_plan(H, &.{}, &.{});
    var random = prng(seed);
    var bytes: [3 * message_length_max]u8 = undefined;
    for (0..iterations(512)) |_| {
        random.random().bytes(&bytes);
        const length = random.random().uintAtMost(usize, bytes.len);
        try run_arbitrary_plan(H, bytes[0..length]);
    }
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var input: [3 * message_length_max]u8 = undefined;
            const length = smith.slice(&input);
            try run_arbitrary_plan(H, input[0..length]);
        }
    }.run, .{});
}

/// Checks `H.hash_many` on `messages` (which may overlap or alias one buffer) against hashing
/// each alone, on the sequential strategy and on a thread pool.
pub fn check_hash_many(comptime H: type, messages: []const []const u8) !void {
    const gpa = std.testing.allocator;
    const pool = try parallel.ThreadPool.create(gpa, std.testing.io, .{ .threads = 3 });
    defer pool.destroy();
    const digests = try gpa.alloc(H.Digest, messages.len);
    defer gpa.free(digests);
    @memset(digests, H.Digest.empty);
    H.hash_many(messages, digests, parallel.sequential);
    for (messages, digests) |message, digest| try expect_digest(H, H.hash(&.{message}), digest);
    @memset(digests, H.Digest.empty);
    H.hash_many(messages, digests, parallel.Rayon.init(pool));
    for (messages, digests) |message, digest| try expect_digest(H, H.hash(&.{message}), digest);
}

/// Checks `H.hash_many` on `count` arbitrary messages against hashing each alone, on the
/// sequential strategy and on a thread pool.
pub fn fuzz_hash_many(comptime H: type, seed: u64) !void {
    const gpa = std.testing.allocator;
    const pool = try parallel.ThreadPool.create(gpa, std.testing.io, .{ .threads = 3 });
    defer pool.destroy();
    var random = prng(seed);
    var storage: [batch_count_max][256]u8 = undefined;
    var messages: [batch_count_max][]const u8 = undefined;
    var digests: [batch_count_max]H.Digest = undefined;
    for (0..iterations(256)) |_| {
        const count = random.random().uintAtMost(usize, batch_count_max);
        const equal = random.random().boolean();
        const common = random.random().uintAtMost(usize, 256);
        for (0..count) |lane| {
            const length = if (equal) common else random.random().uintAtMost(usize, 256);
            random.random().bytes(storage[lane][0..length]);
            if (length > 0) storage[lane][0] = @truncate(lane);
            messages[lane] = storage[lane][0..length];
        }
        H.hash_many(messages[0..count], digests[0..count], parallel.sequential);
        for (messages[0..count], digests[0..count]) |message, digest| {
            try expect_digest(H, H.hash(&.{message}), digest);
        }
        @memset(digests[0..count], H.Digest.empty);
        H.hash_many(messages[0..count], digests[0..count], parallel.Rayon.init(pool));
        for (messages[0..count], digests[0..count]) |message, digest| {
            try expect_digest(H, H.hash(&.{message}), digest);
        }
    }
}
