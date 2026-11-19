//! The prunable archive's pipelined `start_sync` tests (commonware `archive/prunable/mod.rs`),
//! run on `runtime.storage.mocks.DelayedSync`: a started sync parks until the test releases
//! it, and an operation that must wait runs as a spawned task on the deterministic runtime.
//! Each test names the archive code it exercises in `storage.zig`:
//!
//! - put while a sync is in flight: `put_internal` (no I/O, no wait).
//! - duplicate put: `requested` (the completion re-requests the in-flight section syncs).
//! - overlapping start_sync, sync, destroy: the segmented journals' started syncs, which a
//!   later sync request and `destroy` observe first.
//! - prune: `retain_at_least(&requested, min)` and the journals settling the started syncs of
//!   the sections they remove; a failed one surfaces at once.
//! - restarts: independent per-section syncs, of which only completed ones survive a crash.
//! - markers: oversized's in-flight marker generation (`Tracking.marker_pending`): a marker
//!   trails the data sync it publishes, starts beside the next request's data syncs, and a
//!   failed generation fails the next request.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const deterministic = runtime.deterministic;
const translator = @import("../../translator.zig");
const prunable = @import("mod.zig");
const tests = @import("tests.zig");

const Harness = tests.Harness;
const Key = [64]u8;
const Archive = prunable.Archive(translator.FourCap, Key, i32);
const Completion = runtime.storage.Completion;
const gpa = testing.allocator;

/// The harness storage behind the delayed-sync mock.
const Delayed = struct {
    syncs: runtime.storage.mocks.DelayedSync,
    wrapper: runtime.storage.mocks.DelayedSynced,

    /// Must not move after `wrap`.
    fn wrap(self: *Delayed, io: std.Io, harness: *Harness) void {
        self.syncs = .init(gpa, io);
        self.wrapper = .init(gpa, harness.storage.interface(), &self.syncs);
    }

    fn deinit(self: *Delayed) void {
        self.syncs.deinit();
        self.* = undefined;
    }

    fn open(self: *Delayed, harness: *Harness, cfg: anytype, name: []const u8) !Archive {
        const scope = metrics.Scope.init(&harness.registry).child(name);
        return Archive.init(gpa, self.wrapper.storage(), scope, cfg);
    }
};

fn expect_index(archive: *Archive, index: u64, expected: ?i32) !void {
    try testing.expectEqual(expected, try archive.get(.{ .index = index }));
}

const default_section: u64 = 65536;

/// Runs `body(ctx)` on the deterministic runtime.
fn run(comptime body: fn (deterministic.Context) anyerror!void) !void {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(body, .{}));
}

const Op = fn (*Archive) anyerror!void;

fn run_op(ctx: deterministic.Context, op: *const Op, archive: *Archive, done: *bool) anyerror!void {
    _ = ctx;
    try op(archive);
    done.* = true;
}

/// The blocked-operation check (step 1's buffer test pattern): `op` runs as a spawned task;
/// after a sleep it has not finished and the oldest parked sync has a waiter; releasing every
/// parked sync lets it finish.
fn expect_waits(
    ctx: deterministic.Context,
    delayed: *Delayed,
    comptime op: Op,
    archive: *Archive,
) !void {
    var done = false;
    const handle = try ctx.child("op").spawn(run_op, .{ &op, archive, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done);
    const oldest = delayed.syncs.next();
    try testing.expect(oldest.blocked());
    oldest.release({});
    delayed.syncs.release_all();
    try try handle.join();
    try testing.expect(done);
}

/// Releases only the newest of exactly three parked syncs, keeping the two older ones
/// parked in order.
fn release_newest_of_three(delayed: *Delayed) [2]runtime.storage.mocks.Deferred {
    std.debug.assert(delayed.syncs.parked() == 3);
    const older = [2]runtime.storage.mocks.Deferred{ delayed.syncs.next(), delayed.syncs.next() };
    delayed.syncs.next().release({});
    return older;
}

const PutAfterStart = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.config("test", default_section, translator.FourCap);
        {
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            var archive = try delayed.open(&harness, cfg, "storage");
            defer archive.deinit();
            const handle = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
            defer handle.release();
            const parked = delayed.syncs.parked();
            try testing.expect(parked > 0);
            // A put while the handle is pending issues no new storage sync.
            try archive.put(2, tests.test_key("bbb"), 20);
            try testing.expectEqual(parked, delayed.syncs.parked());
            try expect_index(&archive, 1, 10);
            delayed.syncs.release_all();
            try handle.wait();
            const follow_up = try archive.start_sync();
            defer follow_up.release();
            try testing.expect(delayed.syncs.parked() > 0);
            delayed.syncs.release_all();
            try follow_up.wait();
        }
        harness.storage.crash();
        var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
        defer archive.deinit();
        try expect_index(&archive, 1, 10);
        try expect_index(&archive, 2, 20);
    }
};

test "prunable put after start_sync is accepted before the handle completes" {
    try run(PutAfterStart.body);
}

const DuplicatePut = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        var delayed: Delayed = undefined;
        delayed.wrap(ctx.io(), &harness);
        defer delayed.deinit();
        const cfg = harness.config("test", default_section, translator.FourCap);
        var archive = try delayed.open(&harness, cfg, "storage");
        defer archive.deinit();
        const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
        defer first.release();
        try testing.expectEqual(@as(usize, 2), delayed.syncs.parked());
        // The duplicate stores nothing and issues no sync, yet observes the first sync.
        const second = try archive.put_start_sync(1, tests.test_key("duplicate"), 99);
        defer second.release();
        try testing.expectEqual(@as(usize, 2), delayed.syncs.parked());
        try testing.expect(second.poll() == null);
        delayed.syncs.release_all();
        try first.wait();
        try second.wait();
        try expect_index(&archive, 1, 10);
    }
};

test "prunable duplicate put_start_sync observes the in-flight sync" {
    try run(DuplicatePut.body);
}

/// One pending put_start_sync at index 1 (one item per section when `section` is 1).
fn start_first(delayed: *Delayed, archive: *Archive) !Completion {
    const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
    try testing.expect(delayed.syncs.parked() > 0);
    return first;
}

fn second_put_start_sync(archive: *Archive) !void {
    const second = try archive.put_start_sync(2, tests.test_key("bbb"), 20);
    second.release();
}

fn blocking_sync(archive: *Archive) !void {
    try archive.sync();
}

fn prune_two(archive: *Archive) !void {
    try archive.prune(2);
}

/// commonware's four "waits for the in-flight sync" tests share one shape: an operation after
/// a pending put_start_sync must not finish until that sync is released.
fn WaitsFor(comptime section: u64, comptime op: fn (*Archive) anyerror!void) type {
    return struct {
        fn body(ctx: deterministic.Context) !void {
            var harness = try Harness.init();
            defer harness.deinit();
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            const cfg = harness.config("test", section, translator.FourCap);
            var archive = try delayed.open(&harness, cfg, "storage");
            defer archive.deinit();
            const first = try start_first(&delayed, &archive);
            defer first.release();
            try expect_waits(ctx, &delayed, op, &archive);
            try first.wait();
            delayed.syncs.release_all();
        }
    };
}

test "prunable overlapping put_start_sync waits for the in-flight sync" {
    try run(WaitsFor(default_section, second_put_start_sync).body);
}

test "prunable sync after put_start_sync waits for the in-flight sync" {
    try run(WaitsFor(default_section, blocking_sync).body);
}

test "prunable prune after put_start_sync waits for in-flight syncs of pruned sections" {
    try run(WaitsFor(1, prune_two).body);
}

const DestroyWaits = struct {
    fn destroy(archive: *Archive) !void {
        try archive.destroy();
    }

    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        var delayed: Delayed = undefined;
        delayed.wrap(ctx.io(), &harness);
        defer delayed.deinit();
        const cfg = harness.config("test", default_section, translator.FourCap);
        var archive = try delayed.open(&harness, cfg, "storage");
        const first = try start_first(&delayed, &archive);
        defer first.release();
        // `destroy` frees the archive whether or not it succeeds.
        try expect_waits(ctx, &delayed, destroy, &archive);
        try first.wait();
    }
};

test "prunable destroy after put_start_sync waits for the in-flight sync" {
    try run(DestroyWaits.body);
}

/// A failed in-flight sync surfaces at the next `op`, and on the handle.
fn Surfaces(comptime section: u64, comptime op: fn (*Archive) anyerror!void) type {
    return struct {
        fn body(ctx: deterministic.Context) !void {
            var harness = try Harness.init();
            defer harness.deinit();
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            const cfg = harness.config("test", section, translator.FourCap);
            var archive = try delayed.open(&harness, cfg, "storage");
            defer archive.deinit();
            const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
            defer first.release();
            try testing.expectEqual(@as(usize, 2), delayed.syncs.parked());
            delayed.syncs.fail_all();
            try testing.expectError(error.Io, op(&archive));
            try testing.expectError(error.Io, first.wait());
        }
    };
}

fn put_then_start_sync(archive: *Archive) !void {
    // The write is accepted before the failed sync is observed.
    try archive.put(2, tests.test_key("bbb"), 20);
    const handle = try archive.start_sync();
    handle.release();
}

test "prunable prune surfaces a failed in-flight sync" {
    try run(Surfaces(1, prune_two).body);
}

test "prunable failed start_sync is returned by the next start_sync" {
    try run(Surfaces(default_section, put_then_start_sync).body);
}

const PruneDropsRequests = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        var delayed: Delayed = undefined;
        delayed.wrap(ctx.io(), &harness);
        defer delayed.deinit();
        const cfg = harness.config("test", 1, translator.FourCap);
        var archive = try delayed.open(&harness, cfg, "storage");
        defer archive.deinit();
        const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
        defer first.release();
        delayed.syncs.release_all();
        try first.wait();
        // Section 1 stays requested until a blocking sync; prune must drop it, or the next
        // request would sync a pruned section.
        try archive.prune(2);
        const second = try archive.put_start_sync(2, tests.test_key("bbb"), 20);
        defer second.release();
        delayed.syncs.release_all();
        try second.wait();
        delayed.syncs.unblock();
        try archive.sync();
        try expect_index(&archive, 1, null);
        try expect_index(&archive, 2, 20);
    }
};

test "prunable put_start_sync after prune drops pruned sync requests" {
    try run(PruneDropsRequests.body);
}

/// Two sections each with an in-flight sync; `released` of the four parked syncs complete,
/// in start order, before a crash.
fn Restarts(comptime released: u64) type {
    return struct {
        fn body(ctx: deterministic.Context) !void {
            var harness = try Harness.init();
            defer harness.deinit();
            const cfg = harness.config("test", 1, translator.FourCap);
            {
                var delayed: Delayed = undefined;
                delayed.wrap(ctx.io(), &harness);
                defer delayed.deinit();
                var archive = try delayed.open(&harness, cfg, "storage");
                defer archive.deinit();
                const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
                defer first.release();
                const second = try archive.put_start_sync(2, tests.test_key("bbb"), 20);
                defer second.release();
                // Different sections have independent in-flight syncs.
                try testing.expectEqual(@as(usize, 4), delayed.syncs.parked());
                delayed.syncs.release_next(released);
                try first.wait();
                if (released == 4) try second.wait();
                harness.storage.crash();
                // The syncs still parked never complete.
                delayed.syncs.fail_all();
            }
            var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
            defer archive.deinit();
            try expect_index(&archive, 1, 10);
            try expect_index(&archive, 2, if (released == 4) 20 else null);
        }
    };
}

test "prunable overlapping put_start_sync restarts after all handles complete" {
    try run(Restarts(4).body);
}

test "prunable overlapping put_start_sync restarts only completed handles" {
    try run(Restarts(2).body);
}
const StartupMarkerFailure = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.config("startup-marker-failure", 4, translator.FourCap);
        {
            // One durable value with no published marker, so reopen derives one.
            var archive = try harness.open(translator.FourCap, i32, cfg, "seed");
            defer archive.deinit();
            try archive.put(0, tests.test_key("zero"), 10);
            try archive.sync();
        }
        var delayed: Delayed = undefined;
        delayed.wrap(ctx.io(), &harness);
        defer delayed.deinit();
        try delayed.syncs.arm();
        var archive = try delayed.open(&harness, cfg, "reopen");
        defer archive.deinit();
        // The derived marker sync is the only durability operation startup issues.
        try testing.expectEqual(@as(usize, 1), delayed.syncs.parked());
        delayed.syncs.fail_all();
        // commonware: Error::Metadata; zigware's metadata error set is the journal's Io.
        try testing.expectError(error.Io, archive.sync());
    }
};

test "prunable startup marker failure fails the next sync" {
    try run(StartupMarkerFailure.body);
}

const StartSyncPublishes = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.config("marker-lag", 4, translator.FourCap);
        {
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            var archive = try delayed.open(&harness, cfg, "archive");
            defer archive.deinit();
            const first = try archive.put_start_sync(0, tests.test_key("zero"), 10);
            defer first.release();
            try testing.expectEqual(@as(usize, 2), delayed.syncs.parked());
            delayed.syncs.release_all();
            try first.wait();
            // Moving to section 4 publishes section 0's boundary beside section 4's data.
            try archive.put(4, tests.test_key("four"), 40);
            const second = try archive.start_sync();
            defer second.release();
            try testing.expectEqual(@as(usize, 3), delayed.syncs.parked());
            delayed.syncs.release_all();
            try second.wait();
        }
        for ([_][]const u8{ "first_reopen", "second_reopen" }) |name| {
            var archive = try harness.open(translator.FourCap, i32, cfg, name);
            defer archive.deinit();
            const ranges = archive.ranges();
            try testing.expectEqual(@as(usize, 2), ranges.len);
            try testing.expectEqual(@as(u64, 0), ranges[0].start);
            try testing.expectEqual(@as(u64, 4), ranges[1].start);
        }
    }
};

test "prunable start_sync publishes the closed section boundary" {
    try run(StartSyncPublishes.body);
}

const SyncPublishes = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.config("blocking-marker-lag", 4, translator.FourCap);
        {
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            var archive = try delayed.open(&harness, cfg, "archive");
            defer archive.deinit();
            const first = try archive.put_start_sync(0, tests.test_key("zero"), 10);
            defer first.release();
            delayed.syncs.release_all();
            try first.wait();
            try archive.put(4, tests.test_key("four"), 40);
            var done = false;
            const handle = try ctx.child("sync").spawn(run_op, .{ blocking_sync, &archive, &done });
            try ctx.sleep(.fromMilliseconds(10));
            // The closed section's marker starts beside the two data syncs, not after them;
            // releasing only the marker (parked last) does not finish the blocking sync.
            try testing.expectEqual(@as(usize, 3), delayed.syncs.parked());
            const data = release_newest_of_three(&delayed);
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expect(!done);
            for (data) |deferred| deferred.release({});
            try try handle.join();
        }
        var archive = try harness.open(translator.FourCap, i32, cfg, "first_reopen");
        defer archive.deinit();
        try expect_index(&archive, 0, 10);
        try expect_index(&archive, 4, 40);
    }
};

test "prunable sync publishes the closed section boundary beside its data" {
    try run(SyncPublishes.body);
}

const WithholdsMarker = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.config("marker-unproven-boundary", 4, translator.FourCap);
        {
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            var archive = try delayed.open(&harness, cfg, "archive");
            defer archive.deinit();
            const first = try archive.put_start_sync(0, tests.test_key("zero"), 10);
            defer first.release();
            delayed.syncs.release_all();
            try first.wait();
            try archive.put(4, tests.test_key("four"), 40);
            const second = try archive.start_sync();
            defer second.release();
            try testing.expectEqual(@as(usize, 3), delayed.syncs.parked());
            // Complete only the marker; section 4's data stays in flight, so nothing beyond
            // its floor is proven and the next request starts only section 8's data syncs.
            const data = release_newest_of_three(&delayed);
            try archive.put(8, tests.test_key("eight"), 80);
            const before = delayed.syncs.starts();
            const third = try archive.start_sync();
            defer third.release();
            try testing.expectEqual(@as(u64, 2), delayed.syncs.starts() - before);
            for (data) |deferred| deferred.release({});
            delayed.syncs.release_all();
            try second.wait();
            try third.wait();
            delayed.syncs.unblock();
            try archive.sync();
        }
        var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
        defer archive.deinit();
        const ranges = archive.ranges();
        try testing.expectEqual(@as(usize, 3), ranges.len);
        for (ranges, [_]u64{ 0, 4, 8 }) |range, start| {
            try testing.expectEqual(start, range.start);
            try testing.expectEqual(start, range.end);
        }
    }
};

test "prunable start_sync withholds the marker of an unproven boundary" {
    try run(WithholdsMarker.body);
}

const DefersMarkers = struct {
    fn start_eight(archive: *Archive) !void {
        try archive.put(8, tests.test_key("eight"), 80);
        const handle = try archive.start_sync();
        handle.release();
    }

    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.config("marker-in-flight", 4, translator.FourCap);
        var delayed: Delayed = undefined;
        delayed.wrap(ctx.io(), &harness);
        defer delayed.deinit();
        var archive = try delayed.open(&harness, cfg, "archive");
        defer archive.deinit();
        const first = try archive.put_start_sync(0, tests.test_key("zero"), 10);
        defer first.release();
        delayed.syncs.release_all();
        try first.wait();
        // Section 4's data and section 0's marker start; only the data completes.
        try archive.put(4, tests.test_key("four"), 40);
        const second = try archive.start_sync();
        defer second.release();
        const marker = release_newest_of_three_but_marker(&delayed);
        try second.wait();
        // Section 4 is proven and idle, but the parked marker generation defers it: the
        // request neither waits on the marker nor starts another one.
        const before = delayed.syncs.starts();
        var done = false;
        const handle = try ctx.child("start").spawn(run_op, .{ &start_eight, &archive, &done });
        try ctx.sleep(.fromMilliseconds(10));
        try testing.expect(done);
        try testing.expectEqual(@as(u64, 2), delayed.syncs.starts() - before);
        marker.release({});
        delayed.syncs.release_all();
        try try handle.join();
        try archive.sync();
        // The blocking sync leaves its marker generation in flight.
        delayed.syncs.release_all();
    }

    /// Releases the two data syncs of exactly three parked syncs, keeping the marker (newest).
    fn release_newest_of_three_but_marker(delayed: *Delayed) runtime.storage.mocks.Deferred {
        std.debug.assert(delayed.syncs.parked() == 3);
        delayed.syncs.next().release({});
        delayed.syncs.next().release({});
        return delayed.syncs.next();
    }
};

test "prunable start_sync defers markers while a marker generation is in flight" {
    try run(DefersMarkers.body);
}
