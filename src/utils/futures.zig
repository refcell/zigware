//! Task pools over `std.Io` (commonware `utils/src/futures.rs` and `futures/try_join_all.rs`).
//!
//! Rust pools hold futures; here a pool runs functions as `std.Io` tasks and hands their results
//! out in completion order. Pools are bounded: `init` allocates room for `capacity` pending
//! tasks, and `push` asserts there is room. A pool must not move after its first `push`.
//!
//! `AbortablePool` tasks return `Io.Cancelable!T`; aborting one cancels its task, which then
//! completes with `error.Aborted`. Rust aborts on dropping the `Aborter`; here `Aborter.abort`
//! is explicit, and an aborter that is never used leaves its task running.
//!
//! Not ported, as they exist for Rust ownership and polling: `OptionFuture` (`?Io.Future(T)`),
//! `rebind`/`rebind_entry` (Zig methods take `*Self`), and `Shared` (`acknowledgement` or a
//! `channel` covers one result for many waiters).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub fn Pool(comptime T: type) type {
    return struct {
        const Self = @This();

        io: Io,
        group: Io.Group = .init,
        queue: Io.Queue(T),
        buffer: []T,
        /// Tasks pushed whose results were not taken.
        pending: usize = 0,

        pub fn init(gpa: Allocator, io: Io, capacity: usize) Allocator.Error!Self {
            assert(capacity > 0);
            const buffer = try gpa.alloc(T, capacity);
            return .{ .io = io, .queue = .init(buffer), .buffer = buffer };
        }

        /// Cancels every pending task, then frees the pool.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.cancel_all();
            gpa.free(self.buffer);
            self.* = undefined;
        }

        pub fn len(self: *const Self) usize {
            assert(self.pending <= self.buffer.len);
            return self.pending;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.len() == 0;
        }

        /// Runs `function(args...)`, which returns `T`, as a task of the pool. Like Rust's
        /// `FuturesUnordered::push`, it never runs the task on the caller, so a task may wait
        /// on what the caller does next.
        pub fn push(
            self: *Self,
            function: anytype,
            args: std.meta.ArgsTuple(@TypeOf(function)),
        ) Io.ConcurrentError!void {
            assert(self.pending < self.buffer.len);
            const Task = struct {
                fn run(pool: *Self, task_args: @TypeOf(args)) void {
                    const result: T = @call(.auto, function, task_args);
                    // The queue holds a result for every pending task and is never closed.
                    pool.queue.putOneUncancelable(pool.io, result) catch unreachable;
                }
            };
            // `async` may run the task inline when no thread is free, blocking the caller.
            try self.group.concurrent(self.io, Task.run, .{ self, args });
            self.pending += 1;
        }

        /// Waits for the next task to complete and returns its result; the pool is not empty.
        pub fn next_completed(self: *Self) Io.Cancelable!T {
            assert(self.pending > 0);
            const result = self.queue.getOne(self.io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => unreachable, // The queue is never closed.
            };
            self.pending -= 1;
            return result;
        }

        /// Cancels every pending task and drops their results.
        pub fn cancel_all(self: *Self) void {
            self.group.cancel(self.io);
            // Every task has returned, so each pending result is in the queue.
            while (self.pending > 0) : (self.pending -= 1) {
                _ = self.queue.getOneUncancelable(self.io) catch unreachable;
            }
            assert(self.is_empty());
        }
    };
}

pub const Aborted = error{Aborted};

pub fn AbortablePool(comptime T: type) type {
    return struct {
        const Self = @This();

        const Completion = struct { slot: u32, result: Io.Cancelable!T };

        const Slot = struct {
            /// The running task; null once awaited, aborted, or free.
            future: ?Io.Future(void) = null,
            /// Bumped each time the slot is reused, so a stale aborter does nothing.
            generation: u32 = 0,
            live: bool = false,
            /// Aborted before its result was taken: `next_completed` reports `error.Aborted`.
            aborted: bool = false,
        };

        io: Io,
        mutex: Io.Mutex = .init,
        slots: []Slot,
        queue: Io.Queue(Completion),
        buffer: []Completion,
        pending: usize = 0,

        pub fn init(gpa: Allocator, io: Io, capacity: u32) Allocator.Error!Self {
            assert(capacity > 0);
            const slots = try gpa.alloc(Slot, capacity);
            errdefer gpa.free(slots);
            @memset(slots, .{});
            const buffer = try gpa.alloc(Completion, capacity);
            return .{ .io = io, .slots = slots, .queue = .init(buffer), .buffer = buffer };
        }

        /// Aborts every pending task, then frees the pool.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.slots, 0..) |slot, index| {
                if (!slot.live) continue;
                const aborter: Aborter = .{
                    .pool = self,
                    .slot = @intCast(index),
                    .generation = slot.generation,
                };
                aborter.abort();
            }
            // Every task was aborted or finished; their completions are queued.
            while (self.pending > 0) {
                const completion = self.queue.getOneUncancelable(self.io) catch unreachable;
                _ = self.finish(completion) catch {};
            }
            gpa.free(self.slots);
            gpa.free(self.buffer);
            self.* = undefined;
        }

        pub fn len(self: *const Self) usize {
            assert(self.pending <= self.slots.len);
            return self.pending;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.len() == 0;
        }

        /// Runs `function(args...)`, which returns `Io.Cancelable!T`, as a task; the aborter
        /// cancels it. Like `Pool.push`, it never runs the task on the caller.
        pub fn push(
            self: *Self,
            function: anytype,
            args: std.meta.ArgsTuple(@TypeOf(function)),
        ) Io.ConcurrentError!Aborter {
            assert(self.pending < self.slots.len);
            const index = for (self.slots, 0..) |slot, index| {
                if (!slot.live) break index;
            } else unreachable; // Fewer than `capacity` tasks are pending.
            const Task = struct {
                fn run(pool: *Self, slot: u32, task_args: @TypeOf(args)) void {
                    const result: Io.Cancelable!T = @call(.auto, function, task_args);
                    const completion: Completion = .{ .slot = slot, .result = result };
                    // The queue holds a completion for every pending task and is never closed.
                    pool.queue.putOneUncancelable(pool.io, completion) catch unreachable;
                }
            };
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const slot = &self.slots[index];
            // The task's completion is read under the mutex, so the slot is set before it is.
            const slot_index: u32 = @intCast(index);
            slot.future = try self.io.concurrent(Task.run, .{ self, slot_index, args });
            slot.live = true;
            slot.aborted = false;
            slot.generation +%= 1;
            self.pending += 1;
            return .{ .pool = self, .slot = @intCast(index), .generation = slot.generation };
        }

        /// Waits for the next task to complete and returns its result, or `error.Aborted` for an
        /// aborted task; the pool is not empty.
        pub fn next_completed(self: *Self) (Aborted || Io.Cancelable)!T {
            assert(self.pending > 0);
            const completion = self.queue.getOne(self.io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => unreachable, // The queue is never closed.
            };
            return self.finish(completion);
        }

        /// Frees the completed task's slot and returns its result.
        fn finish(self: *Self, completion: Completion) (Aborted || Io.Cancelable)!T {
            self.mutex.lockUncancelable(self.io);
            const slot = &self.slots[completion.slot];
            assert(slot.live);
            var future = slot.future;
            const aborted = slot.aborted;
            slot.* = .{ .generation = slot.generation };
            self.pending -= 1;
            self.mutex.unlock(self.io);
            // The task already posted its result; this releases its resources.
            if (future) |*task| task.await(self.io);
            if (aborted) return error.Aborted;
            return completion.result catch error.Aborted;
        }

        pub const Aborter = struct {
            pool: *Self,
            slot: u32,
            generation: u32,

            /// Cancels the task if it is still pending.
            pub fn abort(aborter: Aborter) void {
                const pool = aborter.pool;
                pool.mutex.lockUncancelable(pool.io);
                const slot = &pool.slots[aborter.slot];
                const current = slot.live and slot.generation == aborter.generation;
                var future = if (current) slot.future else null;
                if (current) {
                    slot.aborted = true;
                    slot.future = null;
                }
                pool.mutex.unlock(pool.io);
                if (future) |*task| task.cancel(pool.io);
            }
        };
    };
}

/// Runs `function(args)` for every `args` in `arguments` concurrently and returns the values in
/// input order, or the first error observed after canceling the remaining tasks. `function`
/// returns `E!T`; values already collected when an error occurs are dropped without cleanup, so
/// `T` should not own memory. The caller frees the returned slice.
///
/// Each task gets its own thread (`Group.concurrent`), never the caller's: `Group.async` runs a
/// task inline once `async_limit` tasks are busy, and a task that waits to be canceled then
/// blocks the join that would cancel it (the macOS `try_join_all` hang). Fails with
/// `ConcurrencyUnavailable` when the `Io` cannot start a task.
pub fn try_join_all(
    comptime T: type,
    comptime E: type,
    gpa: Allocator,
    io: Io,
    comptime function: anytype,
    arguments: []const std.meta.ArgsTuple(@TypeOf(function)),
) (E || Allocator.Error || Io.Cancelable || Io.ConcurrentError)![]T {
    const Args = std.meta.ArgsTuple(@TypeOf(function));
    const Completion = struct { index: usize, result: E!T };
    const Task = struct {
        fn run(queue: *Io.Queue(Completion), task_io: Io, index: usize, args: Args) void {
            const result: E!T = @call(.auto, function, args);
            // The queue has room for every completion and is never closed.
            queue.putOneUncancelable(task_io, .{ .index = index, .result = result }) catch
                unreachable;
        }
    };
    const values = try gpa.alloc(T, arguments.len);
    errdefer gpa.free(values);
    const buffer = try gpa.alloc(Completion, @max(arguments.len, 1));
    defer gpa.free(buffer);
    var queue: Io.Queue(Completion) = .init(buffer);
    var group: Io.Group = .init;
    // Runs before `buffer` is freed: every task has returned once `cancel` does.
    defer group.cancel(io);
    for (arguments, 0..) |args, index| {
        try group.concurrent(io, Task.run, .{ &queue, io, index, args });
    }
    for (0..arguments.len) |_| {
        const completion = queue.getOne(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => unreachable, // The queue is never closed.
        };
        values[completion.index] = try completion.result;
    }
    return values;
}

test {
    _ = @import("futures_test.zig");
}
