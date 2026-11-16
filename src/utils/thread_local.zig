//! A guard for thread-local caching of expensive-to-construct objects (commonware
//! `utils/src/thread_local.rs`).
//!
//! When an object is expensive to construct but cheap to reset and is used within a stateless
//! function, keeping one instance per thread avoids repeated allocation. Declare a slot per
//! thread with `threadlocal var slot: Slot(T) = .{};` (Rust's `thread_local_cache!`), then
//! `Cached(T).take(&slot, maker)` hands out the cached value (after `maker.reset(*T)`) or a new
//! one from `maker.create()`; the guard's `deinit` returns the value to the slot.
//!
//! The slot gives no synchronization across threads: each thread has its own. Within one thread
//! only one guard per slot may be held at a time; taking a second panics. A slot never frees
//! its value: use it for values whose lifetime is the thread's.

const std = @import("std");
const assert = std.debug.assert;

/// One thread's cache of a `T`.
pub fn Slot(comptime T: type) type {
    return struct {
        /// Whether a guard holds the value.
        held: bool = false,
        value: ?T = null,
    };
}

pub fn Cached(comptime T: type) type {
    return struct {
        const Self = @This();

        slot: *Slot(T),
        value: T,

        /// The cached value reset by `maker.reset(*T) !void`, or `maker.create() !T` when the
        /// slot is empty. A failed reset keeps the cached value, and any error leaves the slot
        /// free.
        pub fn take(slot: *Slot(T), maker: anytype) !Self {
            if (slot.held) @panic("cache already held on this thread");
            if (slot.value) |*cached| {
                try maker.reset(cached);
                slot.held = true;
                const value = cached.*;
                slot.value = null;
                return .{ .slot = slot, .value = value };
            }
            const value = try maker.create();
            slot.held = true;
            return .{ .slot = slot, .value = value };
        }

        /// Returns the value to the slot.
        pub fn deinit(self: *Self) void {
            const slot = self.slot;
            if (!slot.held) @panic("cache expected to be held");
            assert(slot.value == null);
            slot.held = false;
            slot.value = self.value;
            self.* = undefined;
        }
    };
}

const testing = std.testing;

const Counter = struct {
    creates: *u32,
    resets: *u32,

    pub fn create(counter: Counter) !u32 {
        counter.creates.* += 1;
        return 100 + counter.creates.*;
    }

    pub fn reset(counter: Counter, value: *u32) !void {
        counter.resets.* += 1;
        value.* += 1;
    }
};

threadlocal var reuse_slot: Slot(u32) = .{};

test "thread_local: reuses the cached value after reset" {
    var creates: u32 = 0;
    var resets: u32 = 0;
    const counter: Counter = .{ .creates = &creates, .resets = &resets };
    var first = try Cached(u32).take(&reuse_slot, counter);
    try testing.expectEqual(101, first.value);
    first.value = 7;
    first.deinit();
    try testing.expectEqual(@as(?u32, 7), reuse_slot.value);
    var second = try Cached(u32).take(&reuse_slot, counter);
    try testing.expectEqual(8, second.value);
    second.deinit();
    try testing.expectEqual(1, creates);
    try testing.expectEqual(1, resets);
}

const Failing = struct {
    create_error: bool = false,
    reset_error: bool = false,
    created: u32 = 0,

    pub fn create(maker: Failing) !u32 {
        if (maker.create_error) return error.CreateFailed;
        return maker.created;
    }

    pub fn reset(maker: Failing, _: *u32) !void {
        if (maker.reset_error) return error.ResetFailed;
    }
};

threadlocal var error_slot: Slot(u32) = .{};

test "thread_local: create and reset errors leave the slot free" {
    try testing.expectError(error.CreateFailed, Cached(u32).take(&error_slot, Failing{
        .create_error = true,
    }));
    var guard = try Cached(u32).take(&error_slot, Failing{ .created = 42 });
    try testing.expectEqual(42, guard.value);
    guard.deinit();
    // A failed reset keeps the cached value.
    try testing.expectError(error.ResetFailed, Cached(u32).take(&error_slot, Failing{
        .reset_error = true,
    }));
    try testing.expectEqual(@as(?u32, 42), error_slot.value);
    try testing.expect(!error_slot.held);
    var again = try Cached(u32).take(&error_slot, Failing{});
    try testing.expectEqual(42, again.value);
    again.deinit();
}

threadlocal var thread_slot: Slot(u64) = .{};

const ThreadMaker = struct {
    id: u64,

    pub fn create(maker: ThreadMaker) !u64 {
        return maker.id;
    }

    pub fn reset(_: ThreadMaker, _: *u64) !void {}
};

fn use_slot(id: u64, seen: *u64) void {
    // ThreadMaker never fails and the fresh thread holds no guard.
    var guard = Cached(u64).take(&thread_slot, ThreadMaker{ .id = id }) catch unreachable;
    seen.* = guard.value;
    guard.deinit();
}

test "thread_local: each thread has its own slot" {
    var guard = try Cached(u64).take(&thread_slot, ThreadMaker{ .id = 1 });
    var seen: u64 = 0;
    const thread = try std.Thread.spawn(.{}, use_slot, .{ 2, &seen });
    thread.join();
    try testing.expectEqual(2, seen);
    try testing.expectEqual(1, guard.value);
    guard.deinit();
}
