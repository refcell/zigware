//! commonware `storage::faulty::tests` that gate the backing blob mid-operation
//! (`OperationGate`): faulty storage wraps a memory blob behind a gate that pauses one write
//! or sync until released, so a test can observe what faulty lets proceed meanwhile. Commonware
//! runs them on the tokio and io_uring runners, which only schedule the gate's tasks; here the
//! deterministic runtime does, and an operation commonware polls once runs as a task the test
//! checks after a scheduler pass.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const utils = @import("utils");
const iface = @import("../storage.zig");
const memory = @import("memory.zig");
const faulty = @import("faulty.zig");
const deterministic = @import("../deterministic.zig");

const Error = iface.Error;
const Completion = iface.Completion;
const Context = deterministic.Context;
const gpa = testing.allocator;
const retain_all: faulty.Config = .{
    .write_rate = .{ .failure_rate = .zero, .retention_rate = .one, .mode = .prefix },
};

/// Pauses the first write (after it lands) or sync (after it runs) until `release` is set
/// (commonware `OperationGate`); `start_sync` runs the gated sync on its own task.
const Gate = struct {
    inner: iface.Blob,
    io: Io,
    pause_after_write: bool,
    armed: bool = true,
    started: Io.Event = .unset,
    release: Io.Event = .unset,
    completed: Io.Event = .unset,
    syncing: ?Io.Future(void) = null,

    fn blob(self: *Gate) iface.Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: iface.Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .start_sync = start_sync,
        .close = close,
    };

    fn from(ptr: *anyopaque) *Gate {
        return @ptrCast(@alignCast(ptr));
    }

    fn pause(self: *Gate, after_write: bool) void {
        if (self.pause_after_write != after_write or !self.armed) return;
        self.armed = false;
        self.started.set(self.io);
        self.release.waitUncancelable(self.io);
    }

    fn read_at(ptr: *anyopaque, offset: u64, buffer: []u8, options: iface.ReadOptions) Error!void {
        return from(ptr).inner.read_at_options(offset, buffer, options);
    }

    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: iface.WriteOptions,
    ) Error!void {
        const self = from(ptr);
        try self.inner.write_at_vectored(offset, chunks, options);
        self.pause(true);
    }

    fn resize(ptr: *anyopaque, length: u64) Error!void {
        return from(ptr).inner.resize(length);
    }

    fn sync(ptr: *anyopaque) Error!void {
        const self = from(ptr);
        try self.inner.sync();
        self.pause(false);
    }

    fn start_sync(ptr: *anyopaque) Error!Completion {
        const self = from(ptr);
        std.debug.assert(self.syncing == null);
        const completion = try Completion.init_pending(gpa, self.io);
        self.syncing = self.io.concurrent(run_sync, .{ self, completion }) catch {
            completion.release();
            return error.Io;
        };
        return completion.retain();
    }

    /// Owns the producer's reference to `completion`.
    fn run_sync(self: *Gate, completion: Completion) void {
        completion.finish(sync(self));
        completion.release();
        self.completed.set(self.io);
    }

    fn close(ptr: *anyopaque) void {
        from(ptr).inner.close();
    }

    fn join(self: *Gate) void {
        if (self.syncing) |*future| future.await(self.io);
        self.syncing = null;
    }
};

/// Faulty storage over memory, and one blob of it behind a gate.
const Fixture = struct {
    inner: memory.Storage,
    rng: utils.rng.TestRng,
    storage: faulty.Storage(utils.rng.TestRng),
    gate: Gate,
    blob: iface.Blob,

    /// Writes `base` durably to `name`, then wraps it in faulty behind a gate.
    fn init(self: *Fixture, io: Io, name: []const u8, base: []const u8, after_write: bool) !void {
        self.inner = .init(gpa);
        errdefer self.inner.deinit();
        self.rng = .init(42);
        self.storage = .init(gpa, &self.inner, &self.rng, retain_all);
        errdefer self.storage.deinit();
        self.storage.io = io;
        const opened = try self.inner.open("partition", name);
        errdefer opened.blob.close();
        try opened.blob.write_at(0, base, .{ .sync = true });
        const backing: *memory.Blob = @ptrCast(@alignCast(opened.blob.ptr));
        self.gate = .{ .inner = opened.blob, .io = io, .pause_after_write = after_write };
        const generation = backing.generation;
        const size = base.len;
        self.blob = try self.storage.wrap(self.gate.blob(), generation, backing.data_offset, size);
    }

    fn deinit(self: *Fixture) void {
        self.gate.release.set(self.gate.io);
        self.gate.join();
        self.storage.deinit();
        self.inner.deinit();
    }

    /// Replays the journal onto the durable contents and checks them.
    fn expect_crash_durable(self: *Fixture, name: []const u8, expected: []const u8) !void {
        try self.storage.crash();
        const bytes = (try self.inner.logical_blob(gpa, "partition", name)).?;
        defer gpa.free(bytes);
        try testing.expectEqualSlices(u8, expected, bytes);
    }
};

/// On a failed check, releases the gate and joins `task` before the fixture is freed.
fn settle(f: *Fixture, task: anytype) void {
    f.gate.release.set(f.gate.io);
    if (task.join()) |outcome| outcome catch {} else |_| {}
}

fn run(comptime body: fn (Context) anyerror!void) !void {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(body, .{}));
}

/// Operations the tests run as tasks; each sets `done` when it returns.
const Op = struct {
    fn write(ctx: Context, blob: iface.Blob, bytes: []const u8, done: *bool) anyerror!void {
        _ = ctx;
        defer done.* = true;
        try blob.write_at(0, bytes, .{});
    }

    fn write_then_sync(ctx: Context, blob: iface.Blob, bytes: []const u8, done: *bool) !void {
        _ = ctx;
        defer done.* = true;
        try blob.write_at(0, bytes, .{});
        try blob.sync();
    }

    /// A started sync whose completion is dropped (`started`), or a full sync.
    fn barrier(ctx: Context, blob: iface.Blob, started: bool) anyerror!void {
        _ = ctx;
        if (started) (try blob.start_sync()).release() else try blob.sync();
    }

    fn start(ctx: Context, blob: iface.Blob, out: *?Completion, done: *bool) anyerror!void {
        _ = ctx;
        defer done.* = true;
        out.* = try blob.start_sync();
    }
};

fn returns_before_backing_completion(ctx: Context) !void {
    const io = ctx.io();
    var f: Fixture = undefined;
    try f.init(io, "start-sync", "data", false);
    defer f.deinit();
    var completion: ?Completion = null;
    var done = false;
    const starting = try ctx.child("start").spawn(Op.start, .{ f.blob, &completion, &done });
    errdefer settle(&f, starting);
    try ctx.sleep(.fromMilliseconds(10));
    // start_sync returned while the backing sync is still held.
    try testing.expect(done);
    try try starting.join();
    try f.gate.started.wait(io);
    try testing.expect(completion.?.poll() == null);
    f.gate.release.set(io);
    try completion.?.wait_release();
}

// commonware `test_start_sync_returns_before_backing_completion`.
test "start_sync returns before the backing sync completes" {
    try run(returns_before_backing_completion);
}

/// A started sync (`start`) or a full sync is held in the backing blob while a later write
/// to the same range arrives (commonware `run_overlapping_barrier`): the started sync lets
/// the write proceed, the full sync holds it, and either way the write stays crash debt the
/// sync does not cover.
fn overlapping_barrier(ctx: Context, start: bool) !void {
    const io = ctx.io();
    var f: Fixture = undefined;
    try f.init(io, "overlap", "base", false);
    defer f.deinit();
    const barrier = try ctx.child("barrier").spawn(Op.barrier, .{ f.blob, start });
    errdefer settle(&f, barrier);
    try f.gate.started.wait(io);
    var late_done = false;
    const late = try ctx.child("late").spawn(Op.write, .{ f.blob, "late", &late_done });
    errdefer settle(&f, late);
    try ctx.sleep(.fromMilliseconds(10));
    // A started sync does not block a later write; a full sync does.
    try testing.expectEqual(start, late_done);
    f.gate.release.set(io);
    try try barrier.join();
    try try late.join();
    // The backing sync finished, also after its completion was dropped.
    if (start) try f.gate.completed.wait(io);
    try f.expect_crash_durable("overlap", "late");
}

// commonware `test_full_sync_epoch_is_linearized_with_overlapping_write`.
test "a full sync's epoch is linearized with an overlapping write" {
    try run(struct {
        fn body(ctx: Context) !void {
            try overlapping_barrier(ctx, false);
        }
    }.body);
}

// commonware `test_dropped_start_sync_epoch_is_linearized_with_overlapping_write`.
test "a dropped start_sync's epoch is linearized with an overlapping write" {
    try run(struct {
        fn body(ctx: Context) !void {
            try overlapping_barrier(ctx, true);
        }
    }.body);
}

/// A write whose backing write landed but which has not journaled itself yet holds a later
/// full sync, so its journal entry cannot appear after the sync and replay stale bytes.
fn completed_write_cannot_record_after_full_sync(ctx: Context) !void {
    const io = ctx.io();
    var f: Fixture = undefined;
    try f.init(io, "late-record", "base!", true);
    defer f.deinit();
    var stale_done = false;
    const stale = try ctx.child("stale").spawn(Op.write, .{ f.blob, "stale", &stale_done });
    errdefer settle(&f, stale);
    try f.gate.started.wait(io);
    f.storage.config = .{};
    var fresh_done = false;
    const fresh_args = .{ f.blob, "fresh", &fresh_done };
    const fresh = try ctx.child("fresh").spawn(Op.write_then_sync, fresh_args);
    errdefer settle(&f, fresh);
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!fresh_done); // The fresh write waits for the stale one to journal.
    f.gate.release.set(io);
    try try stale.join();
    try try fresh.join();
    try f.expect_crash_durable("late-record", "fresh");
}

// commonware `test_completed_backing_write_cannot_record_after_later_full_sync`.
test "a completed backing write cannot journal after a later full sync" {
    try run(completed_write_cannot_record_after_full_sync);
}
