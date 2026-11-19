//! Tests of audited storage (commonware `storage::audited::tests`).

const std = @import("std");
const testing = std.testing;
const iface = @import("../storage.zig");
const memory = @import("memory.zig");
const audited = @import("audited.zig");
const mocks = @import("mocks.zig");
const suite = @import("tests.zig");
const deterministic = @import("../deterministic.zig");

const Auditor = deterministic.Auditor;
const gpa = testing.allocator;

/// Memory storage audited by its own auditor.
const Harness = struct {
    inner: memory.Storage,
    auditor: Auditor,
    storage: audited.Storage,

    fn init(h: *Harness) void {
        h.inner = .init(gpa);
        h.auditor = .{};
        h.storage = .init(gpa, h.inner.storage(), &h.auditor);
    }

    fn deinit(h: *Harness) void {
        h.storage.deinit();
        h.inner.deinit();
    }
};

test "audited storage passes the storage suite" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    try (try runner.start(suite.run_storage_tests, .{ runner.io(), gpa, h.storage.storage() }));
    try testing.expect(!std.mem.eql(u8, "00000000", &h.auditor.state()));
}

test "audited storage separates partition and blob names" {
    var first: Harness = undefined;
    first.init();
    defer first.deinit();
    var second: Harness = undefined;
    second.init();
    defer second.deinit();
    _ = try first.storage.storage().open("a", "bc");
    _ = try second.storage.storage().open("ab", "c");
    try testing.expect(!std.mem.eql(u8, &first.auditor.state(), &second.auditor.state()));
}

test "write options change the audit event" {
    const all = [_]iface.WriteOptions{
        .{},
        .{ .sync = true },
        .{ .dont_cache = true },
        .{ .sync = true, .dont_cache = true },
    };
    var states: [all.len][8]u8 = undefined;
    for (all, &states) |options, *state| {
        var h: Harness = undefined;
        h.init();
        defer h.deinit();
        const blob = (try h.storage.storage().open("partition", "blob")).blob;
        try blob.write_at(0, "data", options);
        state.* = h.auditor.state();
    }
    for (states, 0..) |a, i| {
        for (states[i + 1 ..]) |b| try testing.expect(!std.mem.eql(u8, &a, &b));
    }
}

test "read options change the audit event" {
    var states: [2][8]u8 = undefined;
    for ([_]iface.ReadOptions{ .{}, .{ .dont_cache = true } }, &states) |options, *state| {
        var h: Harness = undefined;
        h.init();
        defer h.deinit();
        const blob = (try h.storage.storage().open("partition", "blob")).blob;
        try blob.write_at(0, "data", .{});
        var buffer: [4]u8 = undefined;
        try blob.read_at_options(0, &buffer, options);
        state.* = h.auditor.state();
    }
    try testing.expect(!std.mem.eql(u8, &states[0], &states[1]));
}

test "write audits ignore chunking but not contents" {
    var states: [3][8]u8 = undefined;
    const payloads = [_][]const []const u8{ &.{"abcd"}, &.{ "a", "bc", "d" }, &.{"abce"} };
    for (payloads, &states) |chunks, *state| {
        var h: Harness = undefined;
        h.init();
        defer h.deinit();
        const blob = (try h.storage.storage().open("partition", "blob")).blob;
        try blob.write_at_vectored(0, chunks, .{});
        state.* = h.auditor.state();
    }
    try testing.expectEqual(states[0], states[1]);
    try testing.expect(!std.mem.eql(u8, &states[0], &states[2]));
}

test "every operation is audited, failed or not" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    const s = h.storage.storage();
    var previous = h.auditor.state();
    const Step = struct {
        fn changed(auditor: *Auditor, last: *[8]u8) !void {
            const state = auditor.state();
            try testing.expect(!std.mem.eql(u8, last, &state));
            last.* = state;
        }
    };
    const blob = (try s.open("partition", "blob")).blob;
    try Step.changed(&h.auditor, &previous);
    try blob.write_at(0, "data", .{});
    try Step.changed(&h.auditor, &previous);
    var buffer: [8]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, blob.read_at(0, &buffer));
    try Step.changed(&h.auditor, &previous);
    try blob.resize(2);
    try Step.changed(&h.auditor, &previous);
    try blob.sync();
    try Step.changed(&h.auditor, &previous);
    blob.close();
    const names = try s.scan(gpa, "partition");
    names.deinit(gpa);
    try Step.changed(&h.auditor, &previous);
    try s.remove("partition", "blob");
    try Step.changed(&h.auditor, &previous);
    try testing.expectError(error.PartitionMissing, s.remove("missing", null));
    try Step.changed(&h.auditor, &previous);
}

/// An audited blob over memory whose inner handle records what the wrapper forwards.
const Recorded = struct {
    blob: iface.Blob,
    recording: mocks.RecordingBlob,

    fn init(r: *Recorded, h: *Harness) !void {
        r.blob = (try h.storage.storage().open("partition", "blob")).blob;
        const handle: *audited.Storage.Blob = @ptrCast(@alignCast(r.blob.ptr));
        r.recording = .{ .inner = handle.inner };
        handle.inner = r.recording.blob();
    }
};

test "audited blobs forward read options (test_audited_blob_forwards_read_options)" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var r: Recorded = undefined;
    try r.init(&h);
    defer r.blob.close();
    try r.blob.write_at(0, "data", .{});
    var buffer: [4]u8 = undefined;
    try r.blob.read_at_options(0, &buffer, .{ .dont_cache = true });
    try r.blob.read_at_options(0, &buffer, .{});
    try testing.expectEqualStrings("data", &buffer);
    try testing.expectEqualSlices(
        iface.ReadOptions,
        &.{ .{ .dont_cache = true }, .{} },
        r.recording.reads(),
    );
}

test "audited writes keep their chunking and options" {
    // commonware `test_audited_blob_writes_preserve_chunking_and_options`.
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var r: Recorded = undefined;
    try r.init(&h);
    defer r.blob.close();
    const chunked: []const []const u8 = &.{ "a", "b", "c", "d" };
    try r.blob.write_at_vectored(0, chunked, .{});
    try r.blob.write_at_vectored(0, chunked, .{ .sync = true });
    const both: iface.WriteOptions = .{ .sync = true, .dont_cache = true };
    try r.blob.write_at(0, "e", both);
    const Write = mocks.RecordingBlob.Write;
    try testing.expectEqualSlices(Write, &.{
        .{ .chunks = 4, .options = .{} },
        .{ .chunks = 4, .options = .{ .sync = true } },
        .{ .chunks = 1, .options = both },
    }, r.recording.writes());
    var buffer: [4]u8 = undefined;
    try r.blob.read_at(0, &buffer);
    try testing.expectEqualStrings("ebcd", &buffer);
}
