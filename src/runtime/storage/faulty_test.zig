//! Tests of fault-injecting storage (commonware `storage::faulty::tests`). The tests that gate
//! the backing I/O mid-operation (commonware's `OperationGate`) are in `faulty_gate_test.zig`.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const iface = @import("../storage.zig");
const memory = @import("memory.zig");
const header = @import("header.zig");
const faulty = @import("faulty.zig");
const mocks = @import("mocks.zig");
const suite = @import("tests.zig");
const deterministic = @import("../deterministic.zig");

const Probability = utils.Probability;
const Config = faulty.Config;
const Mode = faulty.PartialWriteMode;
const gpa = testing.allocator;

const zero = Probability.zero;
const one = Probability.one;
const half = Probability.literal(0.5);
const modes = [_]Mode{ .prefix, .subset };

fn Harness(comptime Rng: type) type {
    return struct {
        const Self = @This();

        inner: memory.Storage,
        rng: Rng,
        storage: faulty.Storage(Rng),

        fn init(h: *Self, rng: Rng, config: Config) void {
            h.inner = .init(gpa);
            h.rng = rng;
            h.storage = .init(gpa, &h.inner, &h.rng, config);
        }

        fn deinit(h: *Self) void {
            h.storage.deinit();
            h.inner.deinit();
        }

        fn open(h: *Self, name: []const u8) !iface.Blob {
            return (try h.storage.open("partition", name)).blob;
        }

        /// The blob's durable logical contents, as the inner storage would reopen them.
        fn durable(h: *Self, partition: []const u8, name: []const u8) ![]u8 {
            return (try h.inner.logical_blob(gpa, partition, name)).?;
        }

        fn expect_durable(h: *Self, name: []const u8, expected: []const u8) !void {
            const bytes = try h.durable("partition", name);
            defer gpa.free(bytes);
            try testing.expectEqualSlices(u8, expected, bytes);
        }

        fn durable_len(h: *Self, name: []const u8) !u64 {
            const bytes = try h.durable("partition", name);
            defer gpa.free(bytes);
            return bytes.len;
        }

        fn pending(h: *const Self) usize {
            return h.storage.pending.items.len;
        }
    };
}

const Seeded = Harness(utils.rng.TestRng);
const Scripted = Harness(utils.rng.ScriptedRng);

fn write_rate(failure: Probability, retention: Probability, mode: Mode) faulty.WriteConfig {
    return .{ .failure_rate = failure, .retention_rate = retention, .mode = mode };
}

fn writes(failure: Probability, retention: Probability, mode: Mode) Config {
    return .{ .write_rate = write_rate(failure, retention, mode) };
}

/// Unsynced writes always survive a crash.
const retain_all = writes(zero, one, .prefix);

test "faulty storage with no faults passes the storage suite" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    var h: Seeded = undefined;
    h.init(.init(42), .{});
    defer h.deinit();
    try (try runner.start(suite.run_storage_tests, .{ runner.io(), gpa, h.storage.storage() }));
}

test "probability endpoints do not consume randomness" {
    var expected_rng: utils.rng.TestRng = .init(0);
    const expected = expected_rng.next_u64();
    var rng: utils.rng.TestRng = .init(0);
    for ([_]Probability{ zero, one }, [_]bool{ false, true }) |probability, outcome| {
        try testing.expectEqual(outcome, probability.sample(&rng));
        for (modes) |mode| {
            const policy: faulty.Policy = .{ .mode = mode, .rate = probability };
            const selected = try faulty.retained_bytes(gpa, &rng, 4, policy);
            defer gpa.free(selected);
            for (selected) |keep| try testing.expectEqual(outcome, keep);
        }
    }
    try testing.expectEqual(expected, rng.next_u64());
}

test "prefix retention rate selects inclusive prefix" {
    var observed: [5]bool = @splat(false);
    const policy: faulty.Policy = .{ .mode = .prefix, .rate = half };
    for (0..512) |seed| {
        var rng: utils.rng.TestRng = .init(seed);
        const selected = try faulty.retained_bytes(gpa, &rng, 4, policy);
        defer gpa.free(selected);
        const prefix_len = std.mem.indexOfScalar(bool, selected, false) orelse 4;
        for (selected[prefix_len..]) |keep| try testing.expect(!keep);
        observed[prefix_len] = true;
    }
    for (observed) |seen| try testing.expect(seen);
    var rng: utils.rng.TestRng = .init(42);
    const empty = try faulty.retained_bytes(gpa, &rng, 0, policy);
    defer gpa.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
}

test "rate_for" {
    const config: Config = .{
        .open_rate = Probability.literal(0.1),
        .write_rate = write_rate(Probability.literal(0.3), Probability.literal(0.4), .subset),
        .resize_rate = .{
            .failure_rate = Probability.literal(0.7),
            .partial_rate = Probability.literal(0.8),
        },
        .sync_rate = Probability.literal(0.9),
    };
    try testing.expect(config.rate_for(.open).eql(Probability.literal(0.1)));
    try testing.expect(config.rate_for(.write).eql(Probability.literal(0.3)));
    try testing.expect(config.rate_for(.resize).eql(Probability.literal(0.7)));
    try testing.expect(config.rate_for(.sync).eql(Probability.literal(0.9)));
    try testing.expect(config.rate_for(.scan).is_zero());
}

test "write rejects offset overflow before retention" {
    var h: Seeded = undefined;
    h.init(.init(42), writes(one, half, .subset));
    defer h.deinit();
    const blob = try h.open("blob");
    const max = std.math.maxInt(u64);
    try testing.expectError(error.OffsetOverflow, blob.write_at(max, "\x01\x02", .{}));
    try testing.expectEqual(@as(u64, 0), try h.durable_len("blob"));
}

test "failed write can retain every byte" {
    var h: Seeded = undefined;
    h.init(.init(42), writes(one, one, .prefix));
    defer h.deinit();
    const blob = try h.open("blob");
    try testing.expectError(error.Io, blob.write_at(0, "x", .{}));
    try h.expect_durable("blob", "x");
}

test "operations fail at their fault rate" {
    var h: Seeded = undefined;
    h.init(.init(42), .{});
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "data", .{});
    try blob.sync();
    h.storage.config.read_rate = one;
    var buffer: [4]u8 = undefined;
    try testing.expectError(error.Io, blob.read_at(0, &buffer));
    h.storage.config.sync_rate = one;
    try testing.expectError(error.Io, blob.sync());
    blob.close();
    const s = h.storage.storage();
    h.storage.config.remove_rate = one;
    try testing.expectError(error.Io, s.remove("partition", "test"));
    h.storage.config.scan_rate = one;
    try testing.expectError(error.Io, s.scan(gpa, "partition"));
    h.storage.config.open_rate = one;
    try testing.expectError(error.Io, s.open("partition", "test"));
}

test "write always fails" {
    for ([_]iface.WriteOptions{ .{}, .{ .sync = true } }) |options| {
        var h: Seeded = undefined;
        h.init(.init(42), writes(one, zero, .prefix));
        defer h.deinit();
        const blob = try h.open("test");
        try testing.expectError(error.Io, blob.write_at(0, "data", options));
    }
}

test "write_at sync failure is not durable" {
    var h: Seeded = undefined;
    h.init(.init(42), .{ .sync_rate = one });
    defer h.deinit();
    const blob = try h.open("test");
    try testing.expectError(error.Io, blob.write_at(0, "data", .{ .sync = true }));
    try testing.expectEqual(@as(u64, 0), try h.durable_len("test"));
}

test "empty write_at sync does not sync a prior write" {
    var h: Seeded = undefined;
    h.init(.init(42), .{ .sync_rate = one });
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "data", .{});
    try blob.write_at(4, "", .{ .sync = true });
    try testing.expectEqual(@as(u64, 0), try h.durable_len("test"));
}

test "empty unsynced write does not create crash debt" {
    var h: Seeded = undefined;
    h.init(.init(42), retain_all);
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "", .{});
    try testing.expectEqual(@as(usize, 0), h.pending());
}

test "start_sync fails when every sync fails (test_faulty_storage_start_sync_always_fails)" {
    var h: Seeded = undefined;
    h.init(.init(42), .{ .write_rate = write_rate(zero, one, .prefix), .sync_rate = one });
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "data", .{});
    // The fault reaches the caller through the completion, and the write stays crash debt.
    try testing.expectError(error.Io, (try blob.start_sync()).wait_release());
    try testing.expectEqual(@as(usize, 1), h.pending());
}

// commonware `test_dropped_completed_start_sync_clears_the_crash_epoch`: a completed
// start_sync retires the journal even when its completion is dropped unobserved, so a crash
// does not replay the stale write over the synced one.
test "a dropped completed start_sync clears the crash epoch" {
    var h: Seeded = undefined;
    h.init(.init(42), retain_all);
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "stale", .{});
    h.storage.config.write_rate = null;
    try blob.write_at(0, "fresh", .{});
    (try blob.start_sync()).release();
    h.storage.config.write_rate = write_rate(zero, one, .prefix);
    try blob.write_at(5, "later", .{});
    try h.storage.crash();
    try h.expect_durable("test", "freshlater");
}

test "dynamic config" {
    var h: Seeded = undefined;
    h.init(.init(42), .{});
    defer h.deinit();
    const blob = try h.open("test");
    try blob.sync();
    h.storage.config.sync_rate = one;
    try testing.expectError(error.Io, blob.sync());
    h.storage.config.sync_rate = zero;
    try blob.sync();
}

test "determinism" {
    const Run = struct {
        fn opens(seed: u64) ![20]bool {
            var h: Seeded = undefined;
            h.init(.init(seed), .{ .open_rate = half });
            defer h.deinit();
            var results: [20]bool = undefined;
            for (&results, 0..) |*result, index| {
                var name_buffer: [8]u8 = undefined;
                const name = try std.fmt.bufPrint(&name_buffer, "blob{d}", .{index});
                result.* = if (h.open(name)) |_| true else |_| false;
            }
            return results;
        }
    };
    const first = try Run.opens(42);
    try testing.expectEqual(first, try Run.opens(42));
    try testing.expect(!std.mem.eql(bool, &first, &try Run.opens(999)));
}

test "reopened sync clears prior handle crash writes" {
    var h: Seeded = undefined;
    h.init(.init(42), retain_all);
    defer h.deinit();
    var blob = try h.open("test");
    try blob.write_at(0, "stale", .{});
    blob.close();
    blob = try h.open("test");
    try blob.write_at(0, "fresh", .{});
    try blob.sync();
    blob.close();
    try h.storage.crash();
    try h.expect_durable("test", "fresh");
}

test "sync write does not barrier a disjoint pending write" {
    var h: Seeded = undefined;
    h.init(.init(42), retain_all);
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "........", .{ .sync = true });
    try blob.write_at(0, "A", .{});
    try blob.write_at(7, "Z", .{ .sync = true });
    try h.storage.crash();
    try h.expect_durable("test", "A......Z");
}

test "sync write retires only overlapping pending bytes" {
    var h: Seeded = undefined;
    h.init(.init(42), retain_all);
    defer h.deinit();
    const blob = try h.open("test");
    const other = try h.open("other");
    try blob.write_at(0, "........", .{ .sync = true });
    try other.write_at(0, "........", .{ .sync = true });
    try blob.write_at(0, "ABCDEFGH", .{});
    try other.write_at(0, "12345678", .{});
    try blob.write_at(3, "xy", .{ .sync = true });
    try h.storage.crash();
    try h.expect_durable("test", "ABCxyFGH");
    try h.expect_durable("other", "12345678");
}

test "range sync preserves prefix retention across pending fragments" {
    var exercised = false;
    for (0..64) |seed| {
        var h: Seeded = undefined;
        h.init(.init(seed), writes(zero, half, .prefix));
        defer h.deinit();
        const blob = try h.open("test");
        try blob.write_at(0, "........", .{ .sync = true });
        try blob.write_at(0, "ABCDEFGH", .{});
        try blob.write_at(3, "xy", .{ .sync = true });
        try h.storage.crash();
        const durable = try h.durable("partition", "test");
        defer gpa.free(durable);
        // A prefix that stops before the synced range cannot resume after it.
        if (std.mem.indexOfScalar(u8, durable[0..3], '.') != null) {
            exercised = true;
            try testing.expectEqualStrings("...", durable[5..]);
        }
    }
    try testing.expect(exercised);
}

test "crash replays writes and resizes in issue order" {
    // Each resize draws its failure (none) and whether it survives a crash (yes).
    const max = std.math.maxInt(u64);
    const samples = [_]u64{ max, 0, max, 0, max, 0 };
    var h: Scripted = undefined;
    var config = retain_all;
    config.resize_rate = .{ .failure_rate = half, .partial_rate = zero };
    h.init(.init(&samples), config);
    defer h.deinit();
    const first = try h.open("first");
    try first.write_at(0, "abcdef", .{});
    try first.resize(3);
    try first.resize(5);
    const second = try h.open("second");
    try second.write_at(0, "abcdef", .{ .sync = true });
    try second.resize(3);
    try second.write_at(5, "X", .{});
    try h.storage.crash();
    try h.expect_durable("first", "abc\x00\x00");
    try h.expect_durable("second", "abc\x00\x00X");
}

test "partial sync write replays after a retained resize" {
    // The resize survives a crash; the failed write retains W and Y of WXYZ.
    const max = std.math.maxInt(u64);
    const samples = [_]u64{ max, 0 } ++ [_]u64{ 0, max, 0, max };
    var h: Scripted = undefined;
    h.init(.init(&samples), .{ .resize_rate = .{ .failure_rate = half, .partial_rate = zero } });
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "abcdefghij", .{ .sync = true });
    try blob.resize(3);
    h.storage.config.write_rate = write_rate(one, half, .subset);
    try testing.expectError(error.Io, blob.write_at(6, "WXYZ", .{ .sync = true }));
    try h.expect_durable("test", "abcdefWhYj");
    try h.storage.crash();
    try h.expect_durable("test", "abc\x00\x00\x00W\x00Y");
}

test "pre-issued sync write survives a failed partial resize" {
    var h: Seeded = undefined;
    h.init(.init(42), .{ .resize_rate = .{ .failure_rate = one, .partial_rate = one } });
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "abcdefghij", .{ .sync = true });
    try testing.expectError(error.Io, blob.resize(0));
    try blob.write_at(10, "X", .{ .sync = true });
    const retained_len: usize = for (h.storage.pending.items) |mutation| {
        if (mutation.kind == .resize) break @intCast(mutation.kind.resize);
    } else unreachable; // The partial resize is journaled.
    try testing.expect(retained_len > 0 and retained_len < 10);
    try h.storage.crash();
    var expected: [11]u8 = @splat(0);
    @memcpy(expected[0..retained_len], "abcdefghij"[0..retained_len]);
    expected[10] = 'X';
    try h.expect_durable("test", &expected);
}

test "partial sync write retires each persisted range" {
    for (modes) |mode| {
        var h: Seeded = undefined;
        h.init(.init(42), retain_all);
        defer h.deinit();
        const blob = try h.open("test");
        try blob.write_at(0, "........", .{ .sync = true });
        try blob.write_at(0, "ABCDEFGH", .{});
        h.storage.config.write_rate = write_rate(one, half, mode);
        try testing.expectError(error.Io, blob.write_at(2, "wxyz", .{ .sync = true }));
        const before = try h.durable("partition", "test");
        defer gpa.free(before);
        try h.storage.crash();
        const after = try h.durable("partition", "test");
        defer gpa.free(after);
        for (before, after, 0..) |old, new, index| {
            const expected = if (old == '.') 'A' + @as(u8, @intCast(index)) else old;
            try testing.expectEqual(expected, new);
        }
    }
}

test "partition removal preserves unrelated crash writes" {
    var h: Seeded = undefined;
    h.init(.init(42), retain_all);
    defer h.deinit();
    const s = h.storage.storage();
    const a = (try s.open("removed", "a")).blob;
    const b = (try s.open("removed", "b")).blob;
    const kept = (try s.open("kept", "blob")).blob;
    try a.write_at(0, "one", .{});
    try kept.write_at(0, "old", .{});
    try b.write_at(0, "two", .{});
    try kept.write_at(3, "new", .{});
    a.close();
    b.close();
    kept.close();
    try s.remove("removed", null);
    try testing.expectEqual(@as(usize, 2), h.pending());
    try h.storage.crash();
    try testing.expectError(error.PartitionMissing, h.inner.scan(gpa, "removed"));
    const durable = try h.durable("kept", "blob");
    defer gpa.free(durable);
    try testing.expectEqualStrings("oldnew", durable);
}

test "write retention is snapshotted and replayed in order" {
    var h: Seeded = undefined;
    h.init(.init(42), retain_all);
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "........", .{ .sync = true });
    try blob.write_at(0, "AB", .{});
    h.storage.config.write_rate = null;
    try blob.write_at(2, "CD", .{});
    h.storage.config.write_rate = retain_all.write_rate;
    try blob.write_at(1, "XY", .{});
    h.storage.config.write_rate = null;
    try h.storage.crash();
    try h.expect_durable("test", "AXY.....");
    blob.close();
    const inner = (try h.inner.open("partition", "test")).blob;
    try inner.write_at(0, "Q", .{ .sync = true });
    inner.close();
    try h.storage.crash();
    try h.expect_durable("test", "QXY.....");
}

/// Overwrites `len` synced zeros with unsynced ones that survive a crash byte by byte.
fn random_crash(seed: u64, comptime len: usize) ![len]u8 {
    var h: Seeded = undefined;
    h.init(.init(seed), writes(zero, half, .subset));
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, &@as([len]u8, @splat(0)), .{ .sync = true });
    try blob.write_at(0, &@as([len]u8, @splat(1)), .{});
    // The retention policy belongs to the completed write, not to the config at the crash.
    h.storage.config.write_rate = null;
    try h.storage.crash();
    const durable = try h.durable("partition", "test");
    defer gpa.free(durable);
    try testing.expectEqual(len, durable.len);
    return durable[0..len].*;
}

test "random crash write is deterministic and inclusive" {
    const first = try random_crash(12345, 64);
    try testing.expectEqual(first, try random_crash(12345, 64));
    try testing.expect(!std.mem.eql(u8, &first, &try random_crash(54321, 64)));
    try testing.expect(std.mem.indexOfScalar(u8, &first, 0) != null);
    try testing.expect(std.mem.indexOfScalar(u8, &first, 1) != null);
    var saw: [2]bool = @splat(false);
    for (0..64) |seed| saw[(try random_crash(seed, 1))[0]] = true;
    try testing.expect(saw[0] and saw[1]);
}

test "failed partial write does not barrier prior crash writes" {
    for (modes) |mode| {
        var saw_old = false;
        var saw_new = false;
        for (0..64) |seed| {
            var h: Seeded = undefined;
            h.init(.init(seed), writes(zero, half, .subset));
            defer h.deinit();
            const blob = try h.open("test");
            try blob.write_at(0, "......", .{ .sync = true });
            try blob.write_at(0, "AAAA", .{});
            h.storage.config.write_rate = write_rate(one, half, mode);
            try testing.expectError(error.Io, blob.write_at(4, "XY", .{}));
            try h.storage.crash();
            const durable = try h.durable("partition", "test");
            defer gpa.free(durable);
            saw_old = saw_old or std.mem.indexOfScalar(u8, durable[0..4], '.') != null;
            saw_new = saw_new or std.mem.indexOfScalar(u8, durable[0..4], 'A') != null;
        }
        try testing.expect(saw_old and saw_new);
    }
}

test "failed partial resize does not barrier prior crash writes" {
    var saw_old = false;
    var saw_new = false;
    for (0..64) |seed| {
        var h: Seeded = undefined;
        h.init(.init(seed), writes(zero, half, .subset));
        defer h.deinit();
        const blob = try h.open("test");
        try blob.write_at(0, "......", .{ .sync = true });
        try blob.write_at(0, "AAAA", .{});
        h.storage.config.resize_rate = .{ .failure_rate = one, .partial_rate = one };
        try testing.expectError(error.Io, blob.resize(8));
        try h.storage.crash();
        const durable = try h.durable("partition", "test");
        defer gpa.free(durable);
        try testing.expectEqual(@as(usize, 7), durable.len);
        saw_old = saw_old or std.mem.indexOfScalar(u8, durable[0..4], '.') != null;
        saw_new = saw_new or std.mem.indexOfScalar(u8, durable[0..4], 'A') != null;
    }
    try testing.expect(saw_old and saw_new);
}

test "crash journal clears only after completed durability" {
    var h: Seeded = undefined;
    h.init(.init(42), retain_all);
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, "a", .{});
    try testing.expectEqual(@as(usize, 1), h.pending());
    h.storage.config.sync_rate = one;
    try testing.expectError(error.Io, blob.sync());
    try testing.expectEqual(@as(usize, 1), h.pending());
    h.storage.config.sync_rate = null;
    try blob.sync();
    try testing.expectEqual(@as(usize, 0), h.pending());

    const other = try h.open("other");
    try blob.write_at(0, "b", .{});
    try other.write_at(0, "x", .{});
    try testing.expectEqual(@as(usize, 2), h.pending());
    try blob.sync();
    try testing.expectEqual(@as(usize, 1), h.pending());
    try other.sync();
    try testing.expectEqual(@as(usize, 0), h.pending());

    try blob.write_at(0, "c", .{});
    try testing.expectEqual(@as(usize, 1), h.pending());
    try blob.write_at(0, "d", .{ .sync = true });
    try testing.expectEqual(@as(usize, 0), h.pending());
}

test "sync failure journals the successful inner write" {
    var h: Seeded = undefined;
    var config = retain_all;
    config.sync_rate = one;
    h.init(.init(42), config);
    defer h.deinit();
    const blob = try h.open("test");
    try testing.expectError(error.Io, blob.write_at(0, "data", .{ .sync = true }));
    try testing.expectEqual(@as(usize, 1), h.pending());
    try h.storage.crash();
    try h.expect_durable("test", "data");
}

test "zero write retention preserves nothing" {
    var h: Seeded = undefined;
    h.init(.init(42), writes(one, zero, .prefix));
    defer h.deinit();
    const blob = try h.open("test");
    try testing.expectError(error.Io, blob.write_at(0, "hello world", .{}));
    try testing.expectEqual(@as(u64, 0), try h.durable_len("test"));
}

/// Syncs `original`, then fails an overwrite with `replacement` that durably keeps a random
/// subset of its bytes; returns the durable contents.
fn subset_overwrite(seed: u64, comptime original: []const u8, replacement: []const u8) ![]u8 {
    std.debug.assert(original.len == replacement.len);
    var h: Seeded = undefined;
    h.init(.init(seed), writes(zero, half, .subset));
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, original, .{});
    try blob.sync();
    h.storage.config.write_rate = write_rate(one, half, .subset);
    try testing.expectError(error.Io, blob.write_at(0, replacement, .{}));
    const durable = try h.durable("partition", "test");
    try testing.expectEqual(original.len, durable.len);
    return durable;
}

test "partial write subset can be non-prefix" {
    const original = "abcdefghijklmnop";
    const replacement = "ABCDEFGHIJKLMNOP";
    const observed = try subset_overwrite(42, original, replacement);
    defer gpa.free(observed);
    var kept_any = false;
    var omitted_any = false;
    var non_prefix = false;
    for (observed, original, replacement) |actual, old, new| {
        try testing.expect(actual == old or actual == new);
        if (actual == new) {
            kept_any = true;
            non_prefix = non_prefix or omitted_any;
        } else {
            omitted_any = true;
        }
    }
    try testing.expect(kept_any and omitted_any and non_prefix);
}

test "partial write subset with the same seed is deterministic" {
    const original: [64]u8 = @splat(0x11);
    const replacement: [64]u8 = @splat(0xAA);
    const first = try subset_overwrite(12345, &original, &replacement);
    defer gpa.free(first);
    const second = try subset_overwrite(12345, &original, &replacement);
    defer gpa.free(second);
    try testing.expectEqualSlices(u8, first, second);
    try testing.expect(std.mem.indexOfScalar(u8, first, 0x11) != null);
    try testing.expect(std.mem.indexOfScalar(u8, first, 0xAA) != null);
}

/// The blob's raw durable contents are `prefix` followed by `payload`.
fn expect_raw(inner: *memory.Storage, prefix: []const u8, payload: []const u8) !void {
    const raw = (try inner.raw_blob(gpa, "partition", "blob")).?;
    defer gpa.free(raw);
    try testing.expectEqual(prefix.len + payload.len, raw.len);
    try testing.expectEqualSlices(u8, prefix, raw[0..prefix.len]);
    try testing.expectEqualSlices(u8, payload, raw[prefix.len..]);
}

// A subset kept by a failed write or by a crash addresses only payload bytes, under both
// layouts (commonware `memory::tests::test_subset_write_preserves_v0_and_v1_headers`).
test "subset write preserves v0 and v1 headers" {
    // Alternating case tells a retained subset from a contiguous prefix.
    const original = "abcdefghijklmnop";
    const replacement = "ABCDEFGHIJKLMNOP";
    const retained = "AbCdEfGhIjKlMnOp";
    var script: [replacement.len]u64 = undefined;
    for (&script, 0..) |*sample, index| {
        sample.* = if (index % 2 == 0) 0 else std.math.maxInt(u64);
    }
    for ([_]iface.BlobLayout{ .v0, .v1 }) |layout| {
        for ([_]bool{ true, false }) |failed_write| {
            const raw = try header.blob_bytes(gpa, layout, 0, original);
            defer gpa.free(raw);
            const prefix = raw[0 .. raw.len - original.len];
            var h: Scripted = undefined;
            h.init(.init(&script), writes(if (failed_write) one else zero, half, .subset));
            defer h.deinit();
            try h.inner.set_raw_blob("partition", "blob", raw);
            const opened = try h.storage.open_versioned("partition", "blob", .only(0));
            try testing.expectEqual(@as(u64, original.len), opened.len);
            try testing.expectEqual(@as(iface.BlobVersion, 0), opened.version);
            const result = opened.blob.write_at(0, replacement, .{});
            if (failed_write) try testing.expectError(error.Io, result) else try result;
            opened.blob.close();
            // A failed write keeps its subset at once; an unsynced one is still volatile.
            try expect_raw(&h.inner, prefix, if (failed_write) retained else original);
            try h.storage.crash();
            h.inner.crash();
            try expect_raw(&h.inner, prefix, retained);
            const recovered = try h.inner.open_versioned("partition", "blob", .only(0));
            defer recovered.blob.close();
            try testing.expectEqual(@as(u64, original.len), recovered.len);
            try suite.expect_read(recovered.blob, 0, retained);
            try testing.expectEqual(script.len, h.rng.position);
        }
    }
}

test "write retention rate endpoints" {
    for ([_]Probability{ zero, one }, [_][]const u8{ "old", "new" }) |retention, expected| {
        for (modes) |mode| {
            var failed: Seeded = undefined;
            failed.init(.init(42), writes(one, retention, mode));
            defer failed.deinit();
            const blob = try failed.open("failed");
            try testing.expectError(error.Io, blob.write_at(0, "new", .{ .sync = true }));
            try failed.expect_durable("failed", if (retention.is_one()) expected else "");

            var crashed: Seeded = undefined;
            crashed.init(.init(42), writes(zero, retention, mode));
            defer crashed.deinit();
            const other = try crashed.open("crashed");
            try other.write_at(0, "old", .{ .sync = true });
            try other.write_at(0, "new", .{});
            try crashed.storage.crash();
            try crashed.expect_durable("crashed", expected);
        }
    }
}

const partial_resize: Config = .{ .resize_rate = .{ .failure_rate = one, .partial_rate = one } };

test "partial resize grow" {
    var h: Seeded = undefined;
    h.init(.init(42), partial_resize);
    defer h.deinit();
    const blob = try h.open("test");
    try testing.expectError(error.Io, blob.resize(100));
    try h.storage.crash();
    const size = try h.durable_len("test");
    try testing.expect(size > 0 and size < 100);
}

test "partial resize shrink" {
    var h: Seeded = undefined;
    h.init(.init(42), .{});
    defer h.deinit();
    const blob = try h.open("test");
    try blob.resize(100);
    try blob.sync();
    h.storage.config = partial_resize;
    try testing.expectError(error.Io, blob.resize(10));
    try h.storage.crash();
    const size = try h.durable_len("test");
    try testing.expect(size > 10 and size < 100);
}

test "partial resize after a write extends" {
    var h: Seeded = undefined;
    h.init(.init(42), .{});
    defer h.deinit();
    const blob = try h.open("test");
    try blob.write_at(0, &@as([50]u8, @splat(0xAB)), .{});
    try blob.sync();
    try testing.expectEqual(@as(u64, 50), try h.durable_len("test"));
    h.storage.config = partial_resize;
    try testing.expectError(error.Io, blob.resize(10));
    try h.storage.crash();
    const size = try h.durable_len("test");
    try testing.expect(size > 10 and size < 50);
}

test "partial resize disabled, same size, or one byte away leaves the size" {
    const disabled: Config = .{ .resize_rate = .{ .failure_rate = one, .partial_rate = zero } };
    for ([_]Config{ disabled, partial_resize, partial_resize }, [_]u64{ 100, 0, 1 }) |config, len| {
        var h: Seeded = undefined;
        h.init(.init(42), config);
        defer h.deinit();
        const blob = try h.open("test");
        try testing.expectError(error.Io, blob.resize(len));
        try h.storage.crash();
        try testing.expectEqual(@as(u64, 0), try h.durable_len("test"));
    }
}

test "a fault-free faulty blob forwards read options" {
    // commonware `test_faulty_blob_forwards_read_options_without_faults`: both reads keep
    // DONT_CACHE. A recording blob under the handle shows what the wrapper forwarded.
    var h: Seeded = undefined;
    h.init(.init(42), .{});
    defer h.deinit();
    const blob = try h.open("blob");
    defer blob.close();
    try blob.write_at(0, "data", .{});
    const handle: *faulty.Storage(utils.rng.TestRng).Blob = @ptrCast(@alignCast(blob.ptr));
    var recording: mocks.RecordingBlob = .{ .inner = handle.inner };
    handle.inner = recording.blob();
    var buffer: [4]u8 = undefined;
    for (0..2) |_| {
        try blob.read_at_options(0, &buffer, .{ .dont_cache = true });
        try testing.expectEqualStrings("data", &buffer);
    }
    try testing.expectEqualSlices(
        iface.ReadOptions,
        &.{ .{ .dont_cache = true }, .{ .dont_cache = true } },
        recording.reads(),
    );
}
