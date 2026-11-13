//! The `reed_solomon` fuzz target of commonware's `coding/fuzz`: encode arbitrary data under
//! an arbitrary config, shuffle the shards, check `to_use` of them, and decode the data back.
//!
//! Inputs come from `invariants.minifuzz.Unstructured` in the order of commonware's
//! `FuzzInput::arbitrary`; the data is `arbitrary_len(u8)` bytes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const minifuzz = @import("invariants").minifuzz;
const coding = @import("root.zig");

const Unstructured = minifuzz.Unstructured;
const max_count: u16 = 512;

/// Runs one input against scheme `S`.
pub fn run(comptime S: type, gpa: Allocator, u: *Unstructured) !void {
    comptime coding.assert_scheme(S);
    const min = u.int_in_range(u16, 1, max_count);
    const recovery = u.int_in_range(u16, 1, max_count);
    const total: usize = @as(usize, min) + recovery;
    const to_use = u.int_in_range(u16, min, min + recovery);
    const data = try u.bytes(u.arbitrary_len(u8));
    // `Shuffle`: swap position `i` with `i + choose_index(total - i)` for `i < total - 1`.
    var order: [2 * max_count]u16 = undefined;
    for (order[0..total], 0..) |*index, i| index.* = @intCast(i);
    for (0..total - 1) |i| {
        const j = i + try u.choose_index(total - i);
        std.mem.swap(u16, &order[i], &order[j]);
    }

    const config: coding.Config = .{ .minimum_shards = min, .extra_shards = recovery };
    var encoding = try S.encode(gpa, config, data, parallel.sequential);
    defer encoding.deinit(gpa);
    try testing.expectEqual(total, encoding.shards.len);
    const checked = try gpa.alloc(S.CheckedShard, to_use);
    defer gpa.free(checked);
    for (order[0..to_use], checked) |index, *piece| {
        const shard = &encoding.shards[index];
        piece.* = try S.check(config, &encoding.commitment, index, shard, parallel.sequential);
    }
    const decoded = try S.decode(gpa, config, &encoding.commitment, checked, parallel.sequential);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, data, decoded);
}

const RS = coding.ReedSolomon(cryptography.Sha256);

/// Runs `bytes` as one input, as the coverage-guided target does.
pub fn run_input(gpa: Allocator, bytes: []const u8) !void {
    var u = Unstructured.init(bytes);
    run(RS, gpa, &u) catch |err| switch (err) {
        error.NotEnoughData, error.IncorrectFormat => {},
        else => return err,
    };
}

fn body(_: void, u: *Unstructured) !void {
    return run(RS, testing.allocator, u);
}

test "fuzz reed_solomon scheme (minifuzz)" {
    // Up to 1024 shards per case: a few dozen cases keep Debug runs short.
    try (minifuzz.Builder{}).with_seed(0).with_search_limit(48).run(testing.allocator, {}, body);
}

test "fuzz reed_solomon scheme (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn fuzz(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [8192]u8 = undefined;
            const length = smith.slice(&bytes);
            try run_input(testing.allocator, bytes[0..length]);
        }
    }.fuzz, .{});
}
