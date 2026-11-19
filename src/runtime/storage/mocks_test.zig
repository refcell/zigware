//! Tests of the storage test wrappers (commonware `mocks::tests`).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const iface = @import("../storage.zig");
const memory = @import("memory.zig");
const mocks = @import("mocks.zig");
const suite = @import("tests.zig");
const deterministic = @import("../deterministic.zig");

const gpa = testing.allocator;
const expect_read = suite.expect_read;

test "mutation faults fail after allowed operations" {
    var inner: memory.Storage = .init(gpa);
    defer inner.deinit();
    var faults: mocks.MutationFaults = .init(testing.io);
    var wrapper: mocks.MutationFault = .init(gpa, inner.storage(), &faults);
    const storage = wrapper.storage();
    const blob = (try storage.open("mutation", "blob")).blob;
    // Two mutations succeed, then every later one fails, whatever its kind.
    faults.allow(2);
    try blob.write_at(0, "data", .{});
    try blob.sync();
    try testing.expect(!faults.failed());
    try testing.expectError(error.Io, blob.resize(2));
    try testing.expect(faults.failed() and !faults.parked());
    try testing.expectError(error.Io, blob.write_at(0, "more", .{}));
    try testing.expectError(error.Io, blob.sync());
    try testing.expectError(error.Io, storage.remove("mutation", "blob"));
    try testing.expectError(error.Io, storage.open("mutation", "created"));
    // Reads still succeed, and no failed mutation reached storage.
    try expect_read(blob, 0, "data");
    const names = try storage.scan(gpa, "mutation");
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), names.items.len);
    try testing.expectEqualStrings("blob", names.items[0]);
    // Opening a stored blob is not a mutation.
    blob.close();
    const reopened = (try storage.open("mutation", "blob")).blob;
    defer reopened.close();
    // Disarming lets mutations through again.
    faults.disarm();
    try reopened.resize(2);
}

/// The parked-mutation case runs on the deterministic runner so the parked task can be
/// canceled (commonware drops the polled future).
const Parking = struct {
    fn resizing(ctx: deterministic.Context, blob: iface.Blob) anyerror!void {
        _ = ctx;
        try blob.resize(2);
    }

    fn body(ctx: deterministic.Context) !void {
        var inner: memory.Storage = .init(gpa);
        defer inner.deinit();
        var faults: mocks.MutationFaults = .init(ctx.io());
        var wrapper: mocks.MutationFault = .init(gpa, inner.storage(), &faults);
        const blob = (try wrapper.storage().open("mutation", "blob")).blob;
        defer blob.close();
        // One mutation succeeds, then the next never completes.
        faults.park_after(1);
        try blob.write_at(0, "data", .{});
        try testing.expect(!faults.parked());
        const handle = try ctx.child("resize").spawn(resizing, .{blob});
        try ctx.sleep(.fromMilliseconds(10));
        try testing.expect(faults.parked() and !faults.failed());
        try testing.expectError(error.Closed, handle.abort());
        // The parked mutation never reached storage.
        try expect_read(blob, 0, "data");
        // Disarming lets mutations through again.
        faults.disarm();
        try blob.resize(2);
        try expect_read(blob, 0, "da");
    }
};

test "mutation faults park after allowed operations" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(Parking.body, .{}));
}

test "recording storage preserves data and records options" {
    var inner: memory.Storage = .init(gpa);
    defer inner.deinit();
    var recordings: mocks.Recordings = .init(gpa);
    defer recordings.deinit();
    var wrapper: mocks.Recording = .init(gpa, inner.storage(), &recordings);
    const blob = (try wrapper.storage().open("recording", "blob")).blob;
    defer blob.close();
    try blob.write_at(0, "data", .{ .dont_cache = true });
    var buffer: [4]u8 = undefined;
    try blob.read_at_options(0, &buffer, .{ .dont_cache = true });
    try testing.expectEqualStrings("data", &buffer);
    try blob.read_at(0, &buffer);
    try testing.expectEqualSlices(
        iface.ReadOptions,
        &.{ .{ .dont_cache = true }, .{} },
        recordings.reads.items,
    );
    try testing.expectEqualSlices(
        iface.WriteOptions,
        &.{.{ .dont_cache = true }},
        recordings.writes.items,
    );
    recordings.clear();
    try testing.expectEqual(@as(usize, 0), recordings.reads.items.len);
    try testing.expectEqual(@as(usize, 0), recordings.writes.items.len);
}

/// A wrapper over recording storage forwards each read's options unchanged.
fn expect_read_options_forwarded(
    storage: iface.Storage,
    recordings: *mocks.Recordings,
    partition: []const u8,
) !void {
    const blob = (try storage.open(partition, "blob")).blob;
    defer blob.close();
    try blob.write_at(0, "data", .{});
    recordings.clear();
    var buffer: [4]u8 = undefined;
    try blob.read_at_options(0, &buffer, .{ .dont_cache = true });
    try testing.expectEqualStrings("data", &buffer);
    try testing.expectEqualSlices(
        iface.ReadOptions,
        &.{.{ .dont_cache = true }},
        recordings.reads.items,
    );
    try testing.expectEqual(@as(usize, 0), recordings.writes.items.len);
}

test "fault wrappers forward read options (write_fault_*, sync_fault_blob_forwards_*)" {
    var inner: memory.Storage = .init(gpa);
    defer inner.deinit();
    var recordings: mocks.Recordings = .init(gpa);
    defer recordings.deinit();
    var recording: mocks.Recording = .init(gpa, inner.storage(), &recordings);
    var write_faults: mocks.WriteFaults = .{};
    var write_fault: mocks.WriteFault = .init(gpa, recording.storage(), &write_faults);
    try expect_read_options_forwarded(write_fault.storage(), &recordings, "write_fault");
    var sync_faults: mocks.SyncFaults = .{ .partition = "sync_fault" };
    var sync_fault: mocks.SyncFault = .init(gpa, recording.storage(), &sync_faults);
    try expect_read_options_forwarded(sync_fault.storage(), &recordings, "sync_fault");
}

test "write faults fail writes while armed and count successful ones" {
    var inner: memory.Storage = .init(gpa);
    defer inner.deinit();
    var faults: mocks.WriteFaults = .{};
    var wrapper: mocks.WriteFault = .init(gpa, inner.storage(), &faults);
    const blob = (try wrapper.storage().open("partition", "blob")).blob;
    defer blob.close();
    try blob.write_at(0, "ab", .{});
    faults.arm();
    try testing.expectError(error.Io, blob.write_at(2, "cd", .{}));
    try blob.sync();
    faults.disarm();
    try blob.write_at(2, "ef", .{});
    try testing.expectEqual(@as(u64, 2), faults.successful_writes());
    try expect_read(blob, 0, "abef");
}

test "sync faults fail syncs of one partition only" {
    var inner: memory.Storage = .init(gpa);
    defer inner.deinit();
    var faults: mocks.SyncFaults = .{ .partition = "faulty" };
    var wrapper: mocks.SyncFault = .init(gpa, inner.storage(), &faults);
    const storage = wrapper.storage();
    const faulty = (try storage.open("faulty", "blob")).blob;
    defer faulty.close();
    const healthy = (try storage.open("healthy", "blob")).blob;
    defer healthy.close();
    try faulty.write_at(0, "data", .{});
    try testing.expectError(error.Io, faulty.sync());
    try healthy.write_at(0, "data", .{});
    try healthy.sync();
}

const Gate = struct {
    fn reading(ctx: deterministic.Context, blob: iface.Blob) anyerror!void {
        _ = ctx;
        var buffer: [4]u8 = undefined;
        try blob.read_at(0, &buffer);
    }

    fn body(ctx: deterministic.Context) !void {
        var inner: memory.Storage = .init(gpa);
        defer inner.deinit();
        var gate: mocks.ReadGate = .init(ctx.io(), "gated");
        var wrapper: mocks.ReadGated = .init(gpa, inner.storage(), &gate);
        const storage = wrapper.storage();
        const gated = (try storage.open("gated", "blob")).blob;
        defer gated.close();
        const other = (try storage.open("other", "blob")).blob;
        defer other.close();
        try gated.write_at(0, "data", .{});
        try other.write_at(0, "data", .{});
        // Disarmed, reads pass; armed, only reads of the gated partition park.
        try expect_read(gated, 0, "data");
        gate.arm();
        try expect_read(other, 0, "data");
        const handle = try ctx.child("read").spawn(reading, .{gated});
        try ctx.sleep(.fromMilliseconds(10));
        try testing.expectEqual(@as(u64, 1), gate.blocked());
        try testing.expectError(error.Closed, handle.abort());
        gate.disarm();
        try expect_read(gated, 0, "data");
        try testing.expectEqual(@as(u64, 1), gate.blocked());
    }
};

test "read gate parks reads of its partition while armed" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(Gate.body, .{}));
}

const SyncGateTest = struct {
    fn syncing(ctx: deterministic.Context, blob: iface.Blob) anyerror!void {
        _ = ctx;
        try blob.sync();
    }

    fn body(ctx: deterministic.Context) !void {
        var inner: memory.Storage = .init(gpa);
        defer inner.deinit();
        var gates: mocks.SyncGates = .init(ctx.io());
        var wrapper: mocks.SyncGated = .init(gpa, inner.storage(), &gates);
        const blob = (try wrapper.storage().open("partition", "blob")).blob;
        defer blob.close();
        // Unarmed, syncs pass.
        try blob.write_at(0, "data", .{ .sync = true });
        try blob.sync();
        gates.arm();
        const handle = try ctx.child("sync").spawn(syncing, .{blob});
        try ctx.sleep(.fromMilliseconds(10));
        try testing.expect(gates.blocked());
        try testing.expectEqual(@as(u64, 1), gates.calls());
        gates.release();
        try try handle.join();
        try testing.expect(!gates.blocked());
        // Only the first operation after `arm` parks; later ones are counted.
        try blob.write_at(0, "more", .{ .sync = true });
        try testing.expectEqual(@as(u64, 2), gates.calls());
        try expect_read(blob, 0, "more");
    }
};

test "sync gate parks the first durability operation after arm until released" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(SyncGateTest.body, .{}));
}
