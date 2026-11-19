//! The completion of a started sync (commonware's shared `Handle<()>` returned by
//! `Blob::start_sync` and every `start_sync` above it).
//!
//! A `Completion` only observes: the sync it reports was fixed when it started, and releasing
//! a completion without waiting (commonware's drop) cancels nothing. Completions are
//! reference counted; every copy handed out is one reference, returned with `release`.
//!
//! - `Completion.ok` and `Completion.ready(result)` are already complete and cost no
//!   allocation (commonware `Handle::ready`). Backends that sync inline return these.
//! - `Completion.init_pending(gpa, io)` stays in flight until its producer calls `finish`.
//!   Waiting blocks on an `Io.Event` with the producer's `Io`, so the owners that wait (writers,
//!   journals, databases) need no `Io` of their own.
//! - `Completion.join(a, b)` completes when both do and reports the first failure it observes
//!   (commonware `try_join`). A joined completion holds only leaf completions, at most
//!   `max_parts`, so waiting on one is a bounded loop (no recursion); a join over more
//!   in-flight syncs first waits for the oldest.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Error = @import("../storage.zig").Error;

pub const Completion = struct {
    state: State,

    /// The most in-flight syncs one joined completion covers.
    pub const max_parts = 8;

    const State = union(enum) {
        /// Complete: the failure, or null on success.
        ready: ?Error,
        leaf: *Leaf,
        joined: *Joined,
    };

    /// A completed, successful sync.
    pub const ok: Completion = .{ .state = .{ .ready = null } };

    /// A completed sync with `result`.
    pub fn ready(result: Error!void) Completion {
        result catch |err| return .{ .state = .{ .ready = err } };
        return ok;
    }

    /// An in-flight sync that completes when `finish` runs. The returned reference belongs to
    /// the producer, which hands out `retain`ed copies and releases its own after `finish`.
    pub fn init_pending(gpa: Allocator, io: Io) Allocator.Error!Completion {
        const leaf = try gpa.create(Leaf);
        leaf.* = .{ .gpa = gpa, .io = io };
        assert(leaf.refs.load(.monotonic) == 1);
        return .{ .state = .{ .leaf = leaf } };
    }

    /// Complete an in-flight sync with `result`, waking its waiters. Runs once.
    pub fn finish(c: Completion, result: Error!void) void {
        const leaf = c.state.leaf;
        assert(!leaf.event.isSet());
        leaf.result = if (result) |_| null else |err| err;
        leaf.event.set(leaf.io);
        assert(leaf.event.isSet());
    }

    /// The sync's result, or null while it is in flight.
    pub fn poll(c: Completion) ?Error!void {
        switch (c.state) {
            .ready => |failure| return if (failure) |err| err else {},
            .leaf => |leaf| return leaf.poll(),
            .joined => |joined| {
                assert(joined.count >= 2 and joined.count <= max_parts);
                var complete = true;
                for (joined.leaves[0..joined.count]) |leaf| {
                    const result = leaf.poll() orelse {
                        complete = false;
                        continue;
                    };
                    result catch |err| return err;
                }
                return if (complete) {} else null;
            },
        }
    }

    /// Wait until the sync completes and return its result.
    pub fn wait(c: Completion) Error!void {
        switch (c.state) {
            .ready => |failure| if (failure) |err| return err,
            .leaf => |leaf| try leaf.wait(),
            .joined => |joined| {
                assert(joined.count >= 2 and joined.count <= max_parts);
                // Fail fast on a part that already failed, then wait on each in turn.
                if (c.poll()) |result| return result;
                for (joined.leaves[0..joined.count]) |leaf| try leaf.wait();
            },
        }
    }

    /// Whether the sync is still in flight.
    pub fn is_pending(c: Completion) bool {
        return c.poll() == null;
    }

    /// The number of waits begun on the in-flight syncs this completion covers (for mocks
    /// that report a sync's handle being awaited, commonware's `DeferredSync::blocked`).
    pub fn waiters(c: Completion) u32 {
        return switch (c.state) {
            .ready => 0,
            .leaf => |leaf| leaf.waits.load(.acquire),
            .joined => |joined| sum: {
                var total: u32 = 0;
                for (joined.leaves[0..joined.count]) |leaf| total += leaf.waits.load(.acquire);
                break :sum total;
            },
        };
    }

    /// Another reference to the same completion.
    pub fn retain(c: Completion) Completion {
        switch (c.state) {
            .ready => {},
            .leaf => |leaf| assert(leaf.refs.fetchAdd(1, .monotonic) > 0),
            .joined => |joined| assert(joined.refs.fetchAdd(1, .monotonic) > 0),
        }
        return c;
    }

    /// Return this reference. The sync itself continues (commonware's drop).
    pub fn release(c: Completion) void {
        switch (c.state) {
            .ready => {},
            .leaf => |leaf| leaf.unref(),
            .joined => |joined| {
                const refs = joined.refs.fetchSub(1, .acq_rel);
                assert(refs > 0);
                if (refs > 1) return;
                for (joined.leaves[0..joined.count]) |leaf| leaf.unref();
                joined.gpa.destroy(joined);
            },
        }
    }

    /// A completion of both `a` and `b`, which it consumes (commonware `try_join`). A part that
    /// already failed fails the join at once, and completed successes drop out. A join covers
    /// at most `max_parts` in-flight syncs: when more are in flight, it first waits for the
    /// oldest, so folding any number of syncs stays bounded.
    pub fn join(a: Completion, b: Completion) Allocator.Error!Completion {
        defer a.release();
        defer b.release();
        var parts: Parts = .{};
        for ([_]Completion{ a, b }) |part| switch (part.state) {
            .ready => |failure| if (failure) |err| return ready(err),
            .leaf => |leaf| parts.add(leaf) catch |err| return ready(err),
            .joined => |joined| for (joined.leaves[0..joined.count]) |leaf| {
                parts.add(leaf) catch |err| return ready(err);
            },
        };
        assert(parts.count <= max_parts);
        if (parts.count == 0) return ok;
        const first = parts.leaves[0];
        if (parts.count == 1) return (Completion{ .state = .{ .leaf = first } }).retain();
        const joined = try first.gpa.create(Joined);
        joined.* = .{ .gpa = first.gpa, .count = @intCast(parts.count) };
        for (parts.leaves[0..parts.count], 0..) |leaf, index| {
            assert(leaf.refs.fetchAdd(1, .monotonic) > 0);
            joined.leaves[index] = leaf;
        }
        return .{ .state = .{ .joined = joined } };
    }

    /// The in-flight leaves of a join being built (borrowed: the parts hold them).
    const Parts = struct {
        leaves: [max_parts]*Leaf = undefined,
        count: usize = 0,

        /// Add `leaf` unless it already completed; a completed failure is returned. When the
        /// join is full, wait for its oldest leaf first.
        fn add(parts: *Parts, leaf: *Leaf) Error!void {
            assert(parts.count <= max_parts);
            if (leaf.poll()) |result| return result;
            if (parts.count == max_parts) {
                try parts.leaves[0].wait();
                const rest = parts.leaves[1..parts.count];
                std.mem.copyForwards(*Leaf, parts.leaves[0..rest.len], rest);
                parts.count -= 1;
            }
            assert(parts.count < max_parts);
            parts.leaves[parts.count] = leaf;
            parts.count += 1;
        }
    };
};

/// One in-flight sync.
const Leaf = struct {
    gpa: Allocator,
    io: Io,
    refs: std.atomic.Value(u32) = .init(1),
    /// Waits begun on this sync.
    waits: std.atomic.Value(u32) = .init(0),
    event: Io.Event = .unset,
    /// Written before `event` is set.
    result: ?Error = null,

    fn poll(leaf: *Leaf) ?Error!void {
        assert(leaf.refs.load(.monotonic) > 0);
        if (!leaf.event.isSet()) return null;
        if (leaf.result) |err| return err;
    }

    fn wait(leaf: *Leaf) Error!void {
        assert(leaf.refs.load(.monotonic) > 0);
        _ = leaf.waits.fetchAdd(1, .acq_rel);
        leaf.event.wait(leaf.io) catch return error.Canceled;
        assert(leaf.event.isSet());
        if (leaf.result) |err| return err;
    }

    fn unref(leaf: *Leaf) void {
        const refs = leaf.refs.fetchSub(1, .acq_rel);
        assert(refs > 0);
        if (refs == 1) leaf.gpa.destroy(leaf);
    }
};

/// In-flight syncs that complete together.
const Joined = struct {
    gpa: Allocator,
    refs: std.atomic.Value(u32) = .init(1),
    leaves: [Completion.max_parts]*Leaf = undefined,
    count: u8,
};

const testing = std.testing;

test "ready completions report their result without allocating" {
    // `ok` and `ready` need no allocator, and retain/release are no-ops for them.
    try Completion.ok.wait();
    try testing.expect(!Completion.ok.is_pending());
    const failed = Completion.ready(error.Io);
    try testing.expectError(error.Io, failed.poll().?);
    try testing.expectError(error.Io, failed.retain().wait());
    failed.release();
    try testing.expectEqual(@as(u32, 0), failed.waiters());
}

test "a pending completion completes on finish and outlives its producer reference" {
    // Every reference observes the same result; the last release frees the leaf.
    const producer = try Completion.init_pending(testing.allocator, testing.io);
    const observer = producer.retain();
    try testing.expect(observer.is_pending());
    producer.finish(error.BlobSyncFailed);
    producer.release();
    try testing.expectError(error.BlobSyncFailed, observer.poll().?);
    try testing.expectError(error.BlobSyncFailed, observer.wait());
    try testing.expectEqual(@as(u32, 1), observer.waiters());
    observer.release();
}

test "join completes when both parts do and fails on the first failure" {
    // Ready successes drop out of a join; two in-flight parts allocate one joined node.
    const a = try Completion.init_pending(testing.allocator, testing.io);
    const b = try Completion.init_pending(testing.allocator, testing.io);
    const ab = try Completion.join(a.retain(), b.retain());
    const abc = try Completion.join(ab.retain(), Completion.ok);
    try testing.expect(abc.state == .joined and abc.is_pending());
    a.finish({});
    try testing.expect(abc.is_pending()); // `b` is still in flight.
    b.finish(error.Io);
    try testing.expectError(error.Io, abc.wait());
    try testing.expectError(error.Io, ab.poll().?);
    for ([_]Completion{ a, b, ab, abc }) |c| c.release();

    // A part that already failed fails the join at once, whatever the other part is doing.
    const slow = try Completion.init_pending(testing.allocator, testing.io);
    const failed = try Completion.join(slow.retain(), .ready(error.ReadFailed));
    try testing.expectError(error.ReadFailed, failed.poll().?);
    slow.finish({});
    slow.release();

    // Joining a single in-flight part returns that part.
    const single = try Completion.init_pending(testing.allocator, testing.io);
    const joined = try Completion.join(Completion.ok, single.retain());
    try testing.expect(joined.state == .leaf and joined.state.leaf == single.state.leaf);
    single.finish({});
    try joined.wait();
    joined.release();
    single.release();
}

const deterministic = @import("../deterministic.zig");

/// Finish the two oldest leaves after a delay, so a fold over them can wait.
fn finish_two(ctx: deterministic.Context, first: Completion, second: Completion) anyerror!void {
    try ctx.sleep(.fromMilliseconds(5));
    first.finish({});
    second.finish({});
    first.release();
    second.release();
}

fn fold_many(ctx: deterministic.Context) !void {
    var leaves: [Completion.max_parts + 2]Completion = undefined;
    for (&leaves) |*leaf| leaf.* = try Completion.init_pending(testing.allocator, ctx.io());
    defer for (leaves) |leaf| leaf.release();
    const handle = try ctx.child("finish").spawn(
        finish_two,
        .{ leaves[0].retain(), leaves[1].retain() },
    );
    // The last two adds wait for the oldest leaves instead of overflowing the join.
    var folded = Completion.ok;
    for (leaves) |leaf| folded = try Completion.join(folded, leaf.retain());
    defer folded.release();
    try try handle.join();
    try testing.expect(folded.state == .joined);
    try testing.expectEqual(@as(u8, Completion.max_parts), folded.state.joined.count);
    try testing.expect(folded.is_pending());
    for (leaves[2..]) |leaf| leaf.finish({});
    try folded.wait();
}

test "join over more in-flight syncs than max_parts waits for the oldest" {
    var runner = try deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start_context(fold_many, .{}));
}
