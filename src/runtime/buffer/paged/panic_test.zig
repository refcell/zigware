//! commonware's `#[should_panic]` tests of the paged buffer (`paged/mod.rs`, `writer.rs`,
//! `sealed.rs`, `tip.rs`), as death tests: each reruns in a child process that must panic.
//! A violated precondition is an `assert`, so the expected message is the assert's panic.
//!
//! Not ported: `test_validate_read_ranges_rejects_length_overflow`. commonware calls the
//! validator with a `u64::MAX` blob size; here ranges are validated against the writer's size
//! first, so a range past it returns `BlobInsufficientLength` instead of panicking.

const std = @import("std");
const codec = @import("codec");
const death = @import("utils").death;
const mocks = @import("../mocks.zig");
const paged = @import("mod.zig");
const Buffer = @import("tip.zig").Buffer;
const Range = paged.view.Range;

const gpa = std.testing.allocator;
const assert_panic = "reached unreachable code";
const page_size: u16 = 103;
const buffer_size: usize = page_size * 2;

/// A writer over a fresh blob holding `0..16` (commonware's `rmany` fixture). Leaks in the
/// child, which panics before it would clean up.
fn writer_with_16_bytes() !paged.Writer {
    const storage = try gpa.create(mocks.Storage);
    storage.* = mocks.Storage.init(gpa);
    const cache_ref = try gpa.create(paged.CacheRef);
    cache_ref.* = try paged.CacheRef.init(gpa, page_size, 2);
    const opened = try storage.open("test_partition", "rmany");
    var writer = try paged.Writer.init(gpa, opened.blob, opened.len, buffer_size, cache_ref);
    var data: [16]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index);
    _ = try writer.append(&data);
    return writer;
}

fn read_ranges(buf_len: usize, ranges: []const Range) !void {
    var writer = try writer_with_16_bytes();
    var buf: [16]u8 = undefined;
    _ = try writer.read_ranges_into(buf[0..buf_len], ranges);
}

fn read_many(buf_len: usize, offsets: []const u64) !void {
    var writer = try writer_with_16_bytes();
    var buf: [16]u8 = undefined;
    _ = try writer.read_many_into(buf[0..buf_len], offsets, 4);
}

test "paged corrupt_page rejects a short blob (test_corrupt_page_rejects_short_blob)" {
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            var storage = mocks.Storage.init(gpa);
            try paged.corrupt_page(storage.interface(), "short-blob", "blob", 0, 64);
        }
    }.body);
}

test "paged read_ranges_into rejects a buffer length mismatch" {
    // commonware `test_validate_read_ranges_rejects_buffer_len_mismatch`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            try read_ranges(7, &.{ .{ .offset = 0, .len = 4 }, .{ .offset = 4, .len = 4 } });
        }
    }.body);
}

test "paged read_ranges_into rejects overlapping ranges" {
    // commonware `test_validate_read_ranges_rejects_overlapping_ranges`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            try read_ranges(8, &.{ .{ .offset = 0, .len = 4 }, .{ .offset = 2, .len = 4 } });
        }
    }.body);
}

test "paged read_ranges_into rejects unsorted ranges" {
    // commonware `test_validate_read_ranges_rejects_unsorted_ranges`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            try read_ranges(8, &.{ .{ .offset = 8, .len = 4 }, .{ .offset = 4, .len = 4 } });
        }
    }.body);
}

test "paged read_many_into rejects an invalid buffer length" {
    // commonware `test_read_many_into_rejects_invalid_buffer_len`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            try read_many(7, &.{ 0, 4 });
        }
    }.body);
}

test "paged read_many_into rejects unsorted offsets" {
    // commonware `test_read_many_into_rejects_unsorted_offsets`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            try read_many(8, &.{ 8, 4 });
        }
    }.body);
}

test "paged read_many_into rejects overlapping offsets" {
    // commonware `test_read_many_into_rejects_overlapping_offsets`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            try read_many(8, &.{ 2, 4 });
        }
    }.body);
}

test "sealed read_many_into rejects unsorted offsets" {
    // commonware `test_sealed_read_many_into_rejects_unsorted_offsets`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            var writer = try writer_with_16_bytes();
            const sealing = try writer.seal();
            try sealing.completion.wait();
            var sealed = sealing.sealed;
            var out: [8]u8 = undefined;
            _ = try sealed.read_many_into(&out, &.{ 8, 4 }, 4);
        }
    }.body);
}

/// Declares 8 encoded bytes but writes `len` (commonware's `IncorrectSize`).
fn IncorrectSize(comptime len: usize) type {
    return struct {
        pub const fixed_size: usize = 8;

        pub fn write(_: @This(), writer: *codec.Writer) void {
            writer.write_byte_n(0, len);
        }

        pub fn read(_: std.mem.Allocator, _: *codec.Reader, _: void) codec.Error!@This() {
            unreachable; // Only encoded.
        }
    };
}

fn typed_append(comptime len: usize, seed: []const u8) !void {
    var buffer = try Buffer.init(gpa, 0, seed, 32, 16);
    _ = buffer.try_append_value(IncorrectSize(len), .{});
}

test "tip typed append rejects a short encoding, an empty seed" {
    // commonware `test_typed_append_rejects_short_encoding`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            try typed_append(7, &.{});
        }
    }.body);
}

test "tip typed append rejects a short encoding, a one-byte seed" {
    // commonware `test_typed_append_rejects_short_encoding`.
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            try typed_append(7, &.{0});
        }
    }.body);
}

test "tip typed append rejects a long encoding, an empty seed" {
    // commonware `test_typed_append_rejects_long_encoding`: any panic; the
    // writer's bounds check trips when the value overruns its slot.
    try death.expect_panic(@src(), "", struct {
        fn body() !void {
            try typed_append(9, &.{});
        }
    }.body);
}

test "tip typed append rejects a long encoding, a one-byte seed" {
    // commonware `test_typed_append_rejects_long_encoding`: any panic; the
    // writer's bounds check trips when the value overruns its slot.
    try death.expect_panic(@src(), "", struct {
        fn body() !void {
            try typed_append(9, &.{0});
        }
    }.body);
}

test "tip rejects a zero page size (test_zero_page_size_is_rejected)" {
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            _ = try Buffer.init(gpa, 0, &.{}, 0, 0);
        }
    }.body);
}

test "tip rejects a misaligned capacity (test_misaligned_capacity_is_rejected)" {
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            _ = try Buffer.init(gpa, 0, &.{}, 17, 8);
        }
    }.body);
}

test "tip rejects a full-page seed (test_full_page_seed_is_rejected)" {
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            _ = try Buffer.init(gpa, 0, &@as([8]u8, @splat(0)), 16, 8);
        }
    }.body);
}

test "tip rejects a full-page replacement (test_full_page_replacement_is_rejected)" {
    try death.expect_panic(@src(), assert_panic, struct {
        fn body() !void {
            var buffer = try Buffer.init(gpa, 0, &.{}, 16, 8);
            buffer.replace(0, &@as([8]u8, @splat(0)));
        }
    }.body);
}
