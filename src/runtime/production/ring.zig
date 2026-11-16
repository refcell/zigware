//! An io_uring driver for production storage and network (commonware `runtime::iouring`,
//! reduced to the I/O those need; tasks stay on `std.Io`).
//!
//! One ring thread owns the ring, as each commonware worker owns its ring
//! (`SINGLE_ISSUER | DEFER_TASKRUN`): it alone enters the kernel, submitting in batches and
//! running completion work, so blocked submitters are never interrupted. A task queues its
//! operation under the ring's mutex, wakes the ring thread through an eventfd if it sleeps
//! (a read of the eventfd is always pending on the ring), and waits on an `Io.Event`.
//! A waiter that is canceled or times out queues `IORING_OP_ASYNC_CANCEL` and waits for the
//! operation's completion before returning, so its buffers stay valid for as long as the
//! kernel uses them. Operations are bounded so that each has room for its cancellation, and
//! the completion queue (twice the submission queue) never overflows.
//!
//! io_uring exists only on Linux: elsewhere `Ring.init` fails with `error.Unsupported`.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Io = std.Io;
const linux = std.os.linux;
const posix = std.posix;

pub const supported = builtin.os.tag == .linux;

pub const Config = struct {
    /// Submission queue entries (a power of two, at least 4): one is the wake read, and
    /// the operations in flight (`entries / 2 - 1`) and their cancellations share the rest.
    entries: u16 = 256,
};

pub const InitError = error{ Unsupported, SystemResources };
pub const PerformError = Io.Cancelable || Io.Timeout.Error;

/// One I/O operation. Buffers must stay valid until `perform` returns.
pub const Operation = union(enum) {
    read: struct { fd: posix.fd_t, buffer: []u8, offset: u64 },
    write: struct { fd: posix.fd_t, bytes: []const u8, offset: u64 },
    fsync: struct { fd: posix.fd_t },
    recv: struct { fd: posix.fd_t, buffer: []u8 },
    sendmsg: struct { fd: posix.fd_t, msg: *const posix.msghdr_const },
};

/// `user_data` of the pending eventfd read that wakes the ring thread. Every other
/// `user_data` is a request's address, with the low bit set on its cancellation.
const user_data_wake: u64 = 1;
const cancel_tag: u64 = 1;
/// Completions the ring thread takes per batch.
const reap_batch = 64;

const Request = struct {
    done: Io.Event = .unset,
    result: i32 = 0,
    /// Completions still to reap: the operation's, and its cancellation's if submitted. The
    /// request holds its operation slot until both are reaped (ring mutex).
    pending: u8 = 1,

    comptime {
        assert(@alignOf(Request) > cancel_tag);
    }
};

pub const Ring = if (supported) LinuxRing else UnsupportedRing;

const LinuxRing = struct {
    io: Io,
    uring: linux.IoUring,
    /// Written to wake the ring thread from `enter`; a read of it is always pending.
    wake_fd: posix.fd_t,
    wake_value: u64 = 0,
    /// The ring was created disabled and the ring thread enables it, becoming its only issuer.
    enable: bool,
    mutex: Io.Mutex = .init,
    /// Signaled when an operation completes.
    slot_free: Io.Condition = .init,
    /// Operations whose completions have not all been reaped.
    operations: u32 = 0,
    operations_max: u32,
    /// Queued or submitted entries whose completion has not been reaped: operations, their
    /// cancellations, and the wake read. At most the submission queue size.
    in_flight: u32 = 0,
    in_flight_max: u32,
    /// The ring thread is in (or about to enter) `io_uring_enter` and needs a wake.
    sleeping: bool = false,
    stopping: bool = false,
    wake_armed: bool = false,
    thread: std.Thread,

    /// Initializes in place: the ring thread holds the ring's address.
    pub fn init(ring: *LinuxRing, io: Io, config: Config) InitError!void {
        assert(std.math.isPowerOfTwo(config.entries) and config.entries >= 4);
        const preferred = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN |
            linux.IORING_SETUP_R_DISABLED;
        var enable = true;
        const uring = linux.IoUring.init(config.entries, preferred) catch |err| switch (err) {
            // Kernels before 6.1 lack these flags; the ring thread is the only issuer anyway.
            error.ArgumentsInvalid => fallback: {
                enable = false;
                break :fallback linux.IoUring.init(config.entries, 0) catch |e| return map_init(e);
            },
            else => return map_init(err),
        };
        const wake_rc = linux.eventfd(0, linux.EFD.CLOEXEC);
        if (linux.errno(wake_rc) != .SUCCESS) {
            var owned = uring;
            owned.deinit();
            return error.SystemResources;
        }
        ring.* = .{
            .io = io,
            .uring = uring,
            .wake_fd = @intCast(wake_rc),
            .enable = enable,
            // Each operation and its cancellation, plus the wake read, fit the queue.
            .operations_max = config.entries / 2 - 1,
            .in_flight_max = config.entries,
            .thread = undefined,
        };
        ring.thread = std.Thread.spawn(.{}, run, .{ring}) catch {
            _ = linux.close(ring.wake_fd);
            ring.uring.deinit();
            return error.SystemResources;
        };
        assert(ring.operations == 0);
    }

    fn map_init(err: anyerror) InitError {
        return switch (err) {
            error.SystemResources,
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            => error.SystemResources,
            else => error.Unsupported,
        };
    }

    /// Every `perform` must have returned.
    pub fn deinit(ring: *LinuxRing) void {
        {
            ring.mutex.lockUncancelable(ring.io);
            defer ring.mutex.unlock(ring.io);
            assert(ring.operations == 0);
            ring.stopping = true;
        }
        ring.wake();
        ring.thread.join();
        assert(ring.in_flight == 0);
        _ = linux.close(ring.wake_fd);
        ring.uring.deinit();
        ring.* = undefined;
    }

    /// Runs `operation` and returns its result: a count, or a negated errno.
    pub fn perform(ring: *LinuxRing, operation: Operation, timeout: Io.Timeout) PerformError!i32 {
        var request: Request = .{};
        const user_data: u64 = @intFromPtr(&request);
        assert(user_data & cancel_tag == 0 and user_data > user_data_wake);
        const wake_queued = wake: {
            try ring.mutex.lock(ring.io);
            defer ring.mutex.unlock(ring.io);
            while (ring.operations == ring.operations_max) {
                try ring.slot_free.wait(ring.io, &ring.mutex);
            }
            ring.operations += 1;
            break :wake ring.queue_locked(user_data, .{ .operation = operation });
        };
        if (wake_queued) ring.wake();
        request.done.waitTimeout(ring.io, timeout) catch |err| {
            ring.cancel(&request);
            return err;
        };
        assert(request.done.isSet());
        return request.result;
    }

    /// Cancels a request whose waiter gave up, and waits until the kernel is done with it.
    fn cancel(ring: *LinuxRing, request: *Request) void {
        const user_data: u64 = @intFromPtr(request);
        var wake_queued = false;
        {
            ring.mutex.lockUncancelable(ring.io);
            defer ring.mutex.unlock(ring.io);
            // A request in flight holds one operation slot and at most two entries, so its
            // cancellation always fits.
            if (!request.done.isSet()) {
                assert(request.pending == 1);
                request.pending = 2;
                wake_queued = ring.queue_locked(user_data | cancel_tag, .{ .cancel = user_data });
            }
        }
        if (wake_queued) ring.wake();
        request.done.waitUncancelable(ring.io);
        assert(request.pending == 0);
    }

    const Entry = union(enum) { operation: Operation, cancel: u64, wake_read };

    /// Queues one entry for the ring thread to submit (mutex held, a slot free). Returns
    /// whether the caller must wake the ring thread, after releasing the mutex.
    fn queue_locked(ring: *LinuxRing, user_data: u64, entry: Entry) bool {
        assert(ring.in_flight < ring.in_flight_max);
        assert(ring.operations <= ring.operations_max);
        const uring = &ring.uring;
        // Queued entries count as in flight until reaped, so a free slot is a free entry.
        const sqe = uring.get_sqe() catch unreachable;
        switch (entry) {
            .wake_read => sqe.prep_read(ring.wake_fd, std.mem.asBytes(&ring.wake_value), 0),
            .cancel => |target| sqe.prep_cancel(target, 0),
            .operation => |operation| switch (operation) {
                .read => |o| sqe.prep_read(o.fd, o.buffer, o.offset),
                .write => |o| sqe.prep_write(o.fd, o.bytes, o.offset),
                .fsync => |o| sqe.prep_fsync(o.fd, 0),
                .recv => |o| sqe.prep_recv(o.fd, o.buffer, 0),
                .sendmsg => |o| sqe.prep_sendmsg(o.fd, o.msg, linux.MSG.NOSIGNAL),
            },
        }
        sqe.user_data = user_data;
        ring.in_flight += 1;
        _ = uring.flush_sq();
        assert(uring.sq.sqe_head == uring.sq.sqe_tail);
        const sleeping = ring.sleeping;
        ring.sleeping = false; // One wake is enough until the thread sleeps again.
        return sleeping;
    }

    /// Wakes the ring thread out of `io_uring_enter`.
    fn wake(ring: *LinuxRing) void {
        const one: u64 = 1;
        const rc = linux.write(ring.wake_fd, std.mem.asBytes(&one), @sizeOf(u64));
        // An eventfd write fails only if its counter would overflow, which a read prevents.
        assert(linux.errno(rc) == .SUCCESS);
    }

    /// The ring thread: the only one to enter the ring. Submits what was queued, waits for
    /// completions, and wakes their waiters, until `deinit` stops it.
    fn run(ring: *LinuxRing) void {
        if (ring.enable) {
            const rc = linux.io_uring_register(ring.uring.fd, .REGISTER_ENABLE_RINGS, null, 0);
            if (linux.errno(rc) != .SUCCESS) std.debug.panic("io_uring enable failed", .{});
        }
        {
            ring.mutex.lockUncancelable(ring.io);
            defer ring.mutex.unlock(ring.io);
            _ = ring.queue_locked(user_data_wake, .wake_read);
            ring.wake_armed = true;
        }
        while (true) {
            const to_submit = submit: {
                ring.mutex.lockUncancelable(ring.io);
                defer ring.mutex.unlock(ring.io);
                if (ring.stopping and !ring.wake_armed and ring.in_flight == 0) return;
                ring.sleeping = true;
                break :submit ring.uring.sq_ready();
            };
            ring.enter(to_submit);
            ring.reap();
        }
    }

    /// Submits `to_submit` entries and waits for at least one completion.
    fn enter(ring: *LinuxRing, to_submit: u32) void {
        var attempts: u32 = 0;
        while (true) : (attempts += 1) {
            assert(attempts < 1024); // Interrupts do not repeat without end.
            _ = ring.uring.enter(to_submit, 1, linux.IORING_ENTER_GETEVENTS) catch |err|
                switch (err) {
                    error.SignalInterrupt => continue,
                    // Waiters would never wake; there is no recovery.
                    else => std.debug.panic("io_uring enter failed: {t}", .{err}),
                };
            return;
        }
    }

    /// Takes every ready completion and wakes its waiter.
    fn reap(ring: *LinuxRing) void {
        var cqes: [reap_batch]linux.io_uring_cqe = undefined;
        ring.mutex.lockUncancelable(ring.io);
        defer ring.mutex.unlock(ring.io);
        ring.sleeping = false;
        var batches: u32 = 0;
        while (batches <= ring.in_flight_max) : (batches += 1) {
            const count = ring.uring.copy_cqes(&cqes, 0) catch |err|
                std.debug.panic("io_uring reap failed: {t}", .{err});
            if (count == 0) return;
            assert(ring.in_flight >= count);
            ring.in_flight -= count;
            for (cqes[0..count]) |cqe| {
                if (cqe.user_data == user_data_wake) {
                    ring.wake_armed = false;
                    if (!ring.stopping) {
                        _ = ring.queue_locked(user_data_wake, .wake_read);
                        ring.wake_armed = true;
                    }
                } else {
                    ring.complete(cqe);
                }
            }
        }
        unreachable; // At most `in_flight_max` completions are outstanding.
    }

    /// Records one completion of a request; the last one wakes its waiter (mutex held).
    fn complete(ring: *LinuxRing, cqe: linux.io_uring_cqe) void {
        const request: *Request = @ptrFromInt(cqe.user_data & ~cancel_tag);
        if (cqe.user_data & cancel_tag == 0) request.result = cqe.res;
        assert(request.pending > 0);
        request.pending -= 1;
        if (request.pending > 0) return;
        assert(ring.operations > 0);
        ring.operations -= 1;
        ring.slot_free.broadcast(ring.io); // A canceled slot waiter may swallow a signal.
        // The waiter may return as soon as this is set: nothing touches the request after it.
        request.done.set(ring.io);
    }
};

const UnsupportedRing = struct {
    pub fn init(_: *UnsupportedRing, _: Io, _: Config) InitError!void {
        return error.Unsupported;
    }

    pub fn deinit(_: *UnsupportedRing) void {
        unreachable; // `init` never succeeds.
    }

    pub fn perform(_: *UnsupportedRing, _: Operation, _: Io.Timeout) PerformError!i32 {
        unreachable; // `init` never succeeds.
    }
};

/// Maps a negative result to its errno.
pub fn errno(result: i32) linux.E {
    assert(result < 0);
    return @fromBackingInt(@intCast(-result));
}

test {
    _ = @import("ring_test.zig");
}
