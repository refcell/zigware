//! Port of commonware's `minifuzz` tests. `#[should_panic]` tests become checks that
//! `search` reports a failure, since a Zig body fails by returning an error.

const std = @import("std");
const testing = std.testing;
const minifuzz = @import("minifuzz.zig");
const Builder = minifuzz.Builder;
const Branch = minifuzz.Branch;
const Unstructured = minifuzz.Unstructured;

/// Rust's `Plan`: `depth` branch bits then a leaf byte. The leaf is reachable only when the
/// bits match the path true, false, true, ...; it must not be 77.
fn haystack(depth: usize, u: *Unstructured) !void {
    var on_path = true;
    for (0..depth) |level| {
        const bit = try u.arbitrary(bool);
        if (bit != (level % 2 == 0)) on_path = false;
    }
    const leaf = try u.arbitrary(u8);
    if (on_path) try testing.expect(leaf != 77);
}

fn not_42(_: void, u: *Unstructured) !void {
    try testing.expect(try u.arbitrary(u8) != 42);
}

fn expect_failure(outcome: minifuzz.Outcome) !minifuzz.Failure {
    return switch (outcome) {
        .passed => error.TestExpectedFailure,
        .failed => |failure| failure,
    };
}

test "search_haystack" {
    for ([_]usize{ 0, 1, 2, 4, 6, 8, 10 }) |depth| {
        const builder = (Builder{}).with_search_limit(1_000_000).with_seed(0);
        const failure = try expect_failure(try builder.search(testing.allocator, depth, haystack));
        try testing.expectEqual(error.TestUnexpectedResult, failure.err);
        try testing.expect(!failure.sampling);
    }
}

test "reproduce_failure" {
    const builder = (Builder{}).with_reproduce("0x0000000000000000000000a0");
    const failure = try expect_failure(try builder.search(testing.allocator, {}, not_42));
    var token: [26]u8 = undefined;
    const printed = try std.fmt.bufPrint(&token, "{f}", .{failure.branch});
    try testing.expectStringStartsWith(printed, "0x");
    // The replayed failure is found again on the same branch.
    const again = (Builder{}).with_reproduce(printed);
    const replayed = try expect_failure(try again.search(testing.allocator, {}, not_42));
    try testing.expectEqual(failure.branch, replayed.branch);
}

test "sampling errors fail the search (panic_non_displayable)" {
    const body = struct {
        fn body(_: void, u: *Unstructured) !void {
            _ = try u.choose_index(0);
        }
    }.body;
    const builder = (Builder{}).with_search_limit(1).with_seed(0);
    const failure = try expect_failure(try builder.search(testing.allocator, {}, body));
    try testing.expectEqual(error.EmptyChoose, failure.err);
    try testing.expect(failure.sampling);
}

test "search_limit_reduces_min_iterations" {
    const body = struct {
        fn body(calls: *u64, _: *Unstructured) !void {
            calls.* += 1;
        }
    }.body;
    var calls: u64 = 0;
    const builder = (Builder{}).with_min_iterations(1000).with_search_limit(1).with_seed(0);
    try builder.run(testing.allocator, &calls, body);
    // One search try, then one long-input case (as many as the search had tries).
    try testing.expectEqual(@as(u64, 1 + 1), calls);
}

test "incorrect_format_does_not_count_as_try" {
    const body = struct {
        fn body(calls: *u64, _: *Unstructured) !void {
            calls.* += 1;
            if (calls.* == 1) return error.IncorrectFormat;
        }
    }.body;
    var calls: u64 = 0;
    try (Builder{}).with_search_limit(1).with_seed(0).run(testing.allocator, &calls, body);
    // A rejected input and one counted try, then one long-input case.
    try testing.expectEqual(@as(u64, 2 + 1), calls);
}

test "min_iterations_overrides_search_time" {
    const builder = (Builder{}).with_search_time(testing.io, .zero)
        .with_min_iterations(1000).with_seed(0);
    _ = try expect_failure(try builder.search(testing.allocator, {}, not_42));
}

test "search time bounds a passing search" {
    const body = struct {
        fn body(_: void, u: *Unstructured) !void {
            _ = try u.arbitrary(u64);
        }
    }.body;
    const builder = (Builder{}).with_search_time(testing.io, .fromMilliseconds(20))
        .with_min_iterations(5).with_seed(7);
    const outcome = try builder.search(testing.allocator, {}, body);
    try testing.expect(outcome == .passed);
}

test "Branch tokens" {
    const branch = Branch.parse("0x0000002a0000002b00000003").?;
    try testing.expectEqual(Branch{ .seed = 42, .thread = 43, .size = 3 }, branch);
    try testing.expectEqual(@as(u64, 42 << 32 | 43), branch.rng_seed());
    const initial: Branch = .{ .seed = 42, .thread = 43, .size = 0 };
    try testing.expectEqual(initial, Branch.init(42 << 32 | 43));
    const last: Branch = .{ .seed = 1, .thread = 0xffffffff, .size = 0xffffffff };
    try testing.expectEqual(Branch{ .seed = 1, .thread = 0, .size = 0xffffffff }, last.next());
    var token: [26]u8 = undefined;
    try testing.expectEqualStrings(
        "0x0000002a0000002b00000003",
        try std.fmt.bufPrint(&token, "{f}", .{branch}),
    );
    try testing.expectEqual(@as(?Branch, null), Branch.parse("0x00"));
    try testing.expectEqual(@as(?Branch, null), Branch.parse("0xzz00002a0000002b00000003"));
}

test "long-input cases reach what short searches miss, and replay" {
    // Fails only on inputs of 128 bytes or more, which a 16-try search never builds, since
    // the body never asks for more data (like a generator that pads with zeros).
    const body = struct {
        fn body(_: void, u: *Unstructured) !void {
            if (u.len() >= 128) return error.TestUnexpectedResult;
            _ = u.take_rest();
        }
    }.body;
    const builder = (Builder{}).with_search_limit(16).with_seed(0);
    const failure = try expect_failure(try builder.search(testing.allocator, {}, body));
    try testing.expect(failure.branch.is_long());
    var token: [26]u8 = undefined;
    const text = try std.fmt.bufPrint(&token, "{f}", .{failure.branch});
    const replay = (Builder{}).with_reproduce(text);
    const replayed = try expect_failure(try replay.search(testing.allocator, {}, body));
    try testing.expectEqual(failure.branch, replayed.branch);
}
