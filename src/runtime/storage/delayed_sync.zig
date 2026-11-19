//! A storage whose blobs hold started syncs in flight (commonware `runtime/src/mocks.rs`
//! `DelayedSyncContext`, `DelayedSyncBlob`, `PendingSyncs`, `DeferredSync`, and the
//! `next_pending_sync`/`release_*`/`fail_pending_syncs` helpers).
//!
//! Every `start_sync` parks in a deferred queue, in start order, until a test releases it
//! (`next`, `release_next`, `release_all`, `fail_all`) or `unblock` runs. `arm` also installs a
//! one-shot gate, pushed onto the same queue, that holds the next durability operation (a
//! blocking `sync`, a `write_at` with `sync` set, or a `start_sync`) and starts `calls`.
//!
//! Difference from commonware: its deferred sync runs the inner blob's sync inside the handle
//! future, so only a polled handle syncs. Here a release runs the inner sync on the releasing
//! task, so a released sync is durable whether or not anyone waits on its completion. A
//! parked sync keeps its blob, and the inner open, alive until it is released (as the mock's
//! `Arc` does).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const iface = @import("../storage.zig");
const Completion = iface.Completion;
const Error = iface.Error;

/// Spin lock for short critical sections; nothing blocks while holding it.
const Lock = struct {
    mutex: std.atomic.Mutex = .unlocked,

    fn lock(self: *Lock) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Lock) void {
        self.mutex.unlock();
    }
};

/// A parked sync (commonware `DeferredSync`): the gate, or a started sync of `blob`.
pub const Deferred = struct {
    pending: *DelayedSync,
    /// The producer's reference.
    completion: Completion,
    /// The blob whose inner sync a successful release runs; null for an unconsumed gate.
    blob: ?*Blob,

    /// Whether someone waits on this sync (commonware `DeferredSync::blocked` resolved).
    pub fn blocked(self: Deferred) bool {
        assert(self.completion.is_pending());
        return self.completion.waiters() > 0;
    }

    /// Complete the sync with `result`; a success first runs the inner blob's sync.
    pub fn release(self: Deferred, result: Error!void) void {
        assert(self.completion.is_pending());
        const pending = self.pending;
        const outcome = if (result) |_| inner: {
            const blob = self.blob orelse break :inner {};
            break :inner blob.inner.sync();
        } else |err| err;
        pending.lock.lock();
        pending.entered_released += 1;
        if (self.blob != null) {
            if (outcome) |_| pending.completed += 1 else |_| {}
        }
        pending.lock.unlock();
        self.completion.finish(outcome);
        self.completion.release();
        if (self.blob) |blob| blob.unref();
    }
};

/// The shared controls (commonware `PendingSyncs`). Must outlive every blob opened through it.
pub const DelayedSync = struct {
    pub const capacity = 16;

    gpa: Allocator,
    io: Io,
    lock: Lock = .{},
    /// Parked syncs in start order.
    queue: [capacity]Deferred = undefined,
    queued: usize = 0,
    /// The unconsumed one-shot gate (a queued entry's completion), see `arm`.
    gate: ?Completion = null,
    tracking: bool = false,
    gate_calls: u64 = 0,
    /// Sticky: started syncs no longer park.
    unblocked: bool = false,
    /// Sticky: unparked and `unblock`ed syncs fail.
    fail: bool = false,
    started: u64 = 0,
    /// Started syncs that ran without parking, plus released ones.
    entered_released: u64 = 0,
    completed: u64 = 0,

    pub fn init(gpa: Allocator, io: Io) DelayedSync {
        return .{ .gpa = gpa, .io = io };
    }

    /// Every parked sync must have been released.
    pub fn deinit(self: *DelayedSync) void {
        assert(self.queued == 0);
        assert(self.gate == null);
        self.* = undefined;
    }

    /// Begin counting durability operations and hold the next one behind a one-shot gate.
    pub fn arm(self: *DelayedSync) Allocator.Error!void {
        const gate = try Completion.init_pending(self.gpa, self.io);
        self.lock.lock();
        defer self.lock.unlock();
        assert(!self.tracking); // One gate per mock, as commonware asserts.
        assert(self.queued < capacity);
        self.tracking = true;
        self.gate_calls = 0;
        self.gate = gate.retain();
        self.queue[self.queued] = .{ .pending = self, .completion = gate, .blob = null };
        self.queued += 1;
    }

    /// Durability operations observed since `arm`.
    pub fn calls(self: *DelayedSync) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        assert(self.tracking);
        return self.gate_calls;
    }

    pub fn starts(self: *DelayedSync) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.started;
    }

    /// Started syncs that ran, were released, or are parked with a waiter.
    pub fn entered(self: *DelayedSync) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        var waiting: u64 = 0;
        for (self.queue[0..self.queued]) |deferred| {
            if (deferred.blob != null and deferred.completion.waiters() > 0) waiting += 1;
        }
        return self.entered_released + waiting;
    }

    /// Started syncs that completed durably.
    pub fn completions(self: *DelayedSync) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.completed;
    }

    /// Parked syncs, the gate included.
    pub fn parked(self: *DelayedSync) usize {
        self.lock.lock();
        defer self.lock.unlock();
        return self.queued;
    }

    /// Take the oldest parked sync (commonware `next_pending_sync`); panics if none.
    pub fn next(self: *DelayedSync) Deferred {
        self.lock.lock();
        defer self.lock.unlock();
        assert(self.queued > 0); // No pending sync was started.
        const first = self.queue[0];
        const rest = self.queue[1..self.queued];
        std.mem.copyForwards(Deferred, self.queue[0..rest.len], rest);
        self.queued -= 1;
        if (self.gate) |gate| {
            if (first.blob == null and gate.state.leaf == first.completion.state.leaf) {
                // A test that takes the gate releases it itself; it is no longer observable.
                self.gate = null;
                gate.release();
            }
        }
        return first;
    }

    /// Take the newest parked sync (commonware `pending.lock().pop()`); panics if none.
    pub fn last(self: *DelayedSync) Deferred {
        self.lock.lock();
        defer self.lock.unlock();
        assert(self.queued > 0); // No pending sync was started.
        self.queued -= 1;
        const newest = self.queue[self.queued];
        // The gate is always the oldest entry until consumed, so it is never the newest here.
        assert(newest.blob != null or self.gate == null);
        return newest;
    }

    /// Complete the oldest `count` parked syncs successfully.
    pub fn release_next(self: *DelayedSync, count: usize) void {
        assert(count <= self.parked());
        for (0..count) |_| self.next().release({});
    }

    /// Complete every parked sync successfully (commonware `release_pending_syncs`).
    pub fn release_all(self: *DelayedSync) void {
        self.drain(false);
    }

    /// Fail every parked sync with an injected error (commonware `fail_pending_syncs`).
    pub fn fail_all(self: *DelayedSync) void {
        self.drain(true);
    }

    /// Release every parked sync and stop parking new ones (sticky).
    pub fn unblock(self: *DelayedSync) void {
        self.lock.lock();
        self.unblocked = true;
        const fail = self.fail;
        self.lock.unlock();
        self.drain(fail);
        assert(self.unblocked);
    }

    /// Make unparked syncs, and those released by `unblock`, fail with an injected error.
    pub fn arm_fail(self: *DelayedSync) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.fail = true;
    }

    fn drain(self: *DelayedSync, fail: bool) void {
        var count = self.parked();
        while (count > 0) : (count -= 1) {
            self.next().release(if (fail) error.Io else {});
        }
        assert(self.parked() == 0 or !self.unblocked);
    }

    /// Count a durability operation if tracking, consuming the gate if still installed.
    fn observe(self: *DelayedSync) ?Completion {
        assert(self.queued <= capacity);
        if (!self.tracking) return null;
        self.gate_calls += 1;
        const gate = self.gate orelse return null;
        self.gate = null;
        return gate;
    }

    /// A blocking sync: wait behind the gate, if it applies, then sync the inner blob.
    fn sync(self: *DelayedSync, blob: *Blob) Error!void {
        self.lock.lock();
        const gate = self.observe();
        self.lock.unlock();
        if (gate) |waiter| {
            defer waiter.release();
            try waiter.wait();
        }
        return blob.inner.sync();
    }

    fn start_sync(self: *DelayedSync, blob: *Blob) Error!Completion {
        self.lock.lock();
        self.started += 1;
        if (self.observe()) |gate| {
            // The gate's queued entry becomes this sync: its release now syncs `blob`.
            defer self.lock.unlock();
            defer gate.release();
            for (self.queue[0..self.queued]) |*deferred| {
                if (deferred.blob == null and deferred.completion.state.leaf == gate.state.leaf) {
                    blob.refs += 1;
                    deferred.blob = blob;
                    return gate.retain();
                }
            }
            unreachable; // An installed gate stays queued until `next` takes it.
        }
        if (self.unblocked) {
            const fail = self.fail;
            self.entered_released += 1;
            self.lock.unlock();
            if (fail) return Completion.ready(error.Io);
            try blob.inner.sync();
            self.lock.lock();
            self.completed += 1;
            self.lock.unlock();
            return Completion.ok;
        }
        self.lock.unlock();
        return self.park(blob);
    }

    fn park(self: *DelayedSync, blob: *Blob) Error!Completion {
        const completion = try Completion.init_pending(self.gpa, self.io);
        self.lock.lock();
        defer self.lock.unlock();
        assert(self.queued < capacity);
        blob.refs += 1;
        self.queue[self.queued] = .{ .pending = self, .completion = completion, .blob = blob };
        self.queued += 1;
        return completion.retain();
    }
};

/// The `Storage` whose blobs defer `start_sync` (commonware `DelayedSyncContext`).
pub const DelayedSynced = struct {
    gpa: Allocator,
    inner: iface.Storage,
    pending: *DelayedSync,

    pub fn init(gpa: Allocator, inner: iface.Storage, pending: *DelayedSync) DelayedSynced {
        return .{ .gpa = gpa, .inner = inner, .pending = pending };
    }

    /// The `Storage` interface of this wrapper, which must not move while in use.
    pub fn storage(self: *DelayedSynced) iface.Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: iface.Storage.VTable = .{
        .open_versioned = open_versioned,
        .remove = remove,
        .scan = scan,
    };

    fn from(ptr: *anyopaque) *DelayedSynced {
        return @ptrCast(@alignCast(ptr));
    }

    fn open_versioned(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        const self = from(ptr);
        assert(versions.min <= versions.max);
        const blob = try self.gpa.create(Blob);
        errdefer self.gpa.destroy(blob);
        const opened = try self.inner.open_versioned(partition, name, versions);
        blob.* = .{ .owner = self, .inner = opened.blob };
        return .{ .blob = blob.blob(), .len = opened.len, .version = opened.version };
    }

    fn remove(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
        return from(ptr).inner.remove(partition, name);
    }

    fn scan(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!iface.Names {
        return from(ptr).inner.scan(gpa, partition);
    }
};

/// A blob of a `DelayedSynced` storage (commonware `DelayedSyncBlob`).
pub const Blob = struct {
    owner: *DelayedSynced,
    inner: iface.Blob,
    /// The handle plus each parked sync of it; guarded by the owner's `DelayedSync.lock`.
    refs: u32 = 1,

    fn blob(self: *Blob) iface.Blob {
        return .{ .ptr = self, .vtable = &blob_vtable };
    }

    const blob_vtable: iface.Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .close = close,
        .start_sync = start_sync,
    };

    fn of(ptr: *anyopaque) *Blob {
        return @ptrCast(@alignCast(ptr));
    }

    fn read_at(ptr: *anyopaque, offset: u64, buffer: []u8, options: iface.ReadOptions) Error!void {
        return of(ptr).inner.read_at_options(offset, buffer, options);
    }

    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: iface.WriteOptions,
    ) Error!void {
        const self = of(ptr);
        const pending = self.owner.pending;
        pending.lock.lock();
        const tracking = pending.tracking;
        pending.lock.unlock();
        if (!options.sync or !tracking) {
            return self.inner.write_at_vectored(offset, chunks, options);
        }
        var plain = options;
        plain.sync = false;
        try self.inner.write_at_vectored(offset, chunks, plain);
        return pending.sync(self);
    }

    fn resize(ptr: *anyopaque, length: u64) Error!void {
        return of(ptr).inner.resize(length);
    }

    fn sync(ptr: *anyopaque) Error!void {
        const self = of(ptr);
        return self.owner.pending.sync(self);
    }

    fn start_sync(ptr: *anyopaque) Error!Completion {
        const self = of(ptr);
        return self.owner.pending.start_sync(self);
    }

    fn close(ptr: *anyopaque) void {
        of(ptr).unref();
    }

    fn unref(self: *Blob) void {
        const pending = self.owner.pending;
        pending.lock.lock();
        assert(self.refs > 0);
        self.refs -= 1;
        const last = self.refs == 0;
        pending.lock.unlock();
        if (!last) return;
        self.inner.close();
        self.owner.gpa.destroy(self);
    }
};
