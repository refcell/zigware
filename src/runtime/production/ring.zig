//! An io_uring driver for production storage and network (commonware `runtime::iouring`,
//! reduced to the I/O those need; tasks stay on `std.Io`).
//!
//! Any task submits an operation under the ring's mutex and waits on an `Io.Event`; one reaper
//! thread waits for completions and wakes the submitters. A waiter that is canceled or times
//! out submits `IORING_OP_ASYNC_CANCEL` and waits for the operation's completion before
//! returning, so its buffers stay valid for as long as the kernel uses them. At most half the
//! submission queue holds operations, so each one always has room for its cancellation, and
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
    /// Submission queue entries (a power of two, at least 2): half of them bound the
    /// operations in flight, the other half their cancellations.
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

/// `user_data` of the no-op that stops the reaper. Every other `user_data` is a request's
/// address, with the low bit set on its cancellation.
const user_data_shutdown: u64 = 1;
const cancel_tag: u64 = 1;
/// Completions the reaper takes per wakeup.
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
    mutex: Io.Mutex = .init,
    /// Signaled when an operation completes.
    slot_free: Io.Condition = .init,
    /// Submitted operations whose completion has not been reaped.
    operations: u32 = 0,
    operations_max: u32,
    /// Submitted entries whose completion has not been reaped: operations, cancellations, and
    /// the shutdown no-op. At most the submission queue size.
    in_flight: u32 = 0,
    in_flight_max: u32,
    reaper: std.Thread,

    /// Initializes in place: the reaper thread holds the ring's address.
    pub fn init(ring: *LinuxRing, io: Io, config: Config) InitError!void {
        assert(std.math.isPowerOfTwo(config.entries) and config.entries >= 2);
        const uring = linux.IoUring.init(config.entries, 0) catch |err| return switch (err) {
            error.SystemResources,
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            => error.SystemResources,
            else => error.Unsupported,
        };
        ring.* = .{
            .io = io,
            .uring = uring,
            .operations_max = config.entries / 2,
            .in_flight_max = config.entries,
            .reaper = undefined,
        };
        errdefer ring.uring.deinit();
        ring.reaper = std.Thread.spawn(.{}, reap, .{ring}) catch return error.SystemResources;
        assert(ring.in_flight == 0);
    }

    /// Every `perform` must have returned.
    pub fn deinit(ring: *LinuxRing) void {
        {
            ring.mutex.lockUncancelable(ring.io);
            defer ring.mutex.unlock(ring.io);
            assert(ring.in_flight == 0 and ring.operations == 0);
            ring.push_uncancelable(user_data_shutdown, .nop);
        }
        ring.reaper.join();
        ring.uring.deinit();
        ring.* = undefined;
    }

    /// Runs `operation` and returns its result: a count, or a negated errno.
    pub fn perform(ring: *LinuxRing, operation: Operation, timeout: Io.Timeout) PerformError!i32 {
        var request: Request = .{};
        const user_data: u64 = @intFromPtr(&request);
        assert(user_data & cancel_tag == 0 and user_data != 0);
        {
            try ring.mutex.lock(ring.io);
            defer ring.mutex.unlock(ring.io);
            while (ring.operations == ring.operations_max) {
                try ring.slot_free.wait(ring.io, &ring.mutex);
            }
            ring.operations += 1;
            ring.push_uncancelable(user_data, .{ .operation = operation });
        }
        request.done.waitTimeout(ring.io, timeout) catch |err| {
            ring.mutex.lockUncancelable(ring.io);
            // A request in flight holds one operation slot and at most two entries, so its
            // cancellation always fits.
            if (!request.done.isSet()) {
                assert(request.pending == 1);
                request.pending = 2;
                ring.push_uncancelable(user_data | cancel_tag, .{ .cancel = user_data });
            }
            ring.mutex.unlock(ring.io);
            request.done.waitUncancelable(ring.io);
            return err;
        };
        assert(request.done.isSet());
        return request.result;
    }

    const Entry = union(enum) { operation: Operation, cancel: u64, nop };

    /// Queues and submits one entry (mutex held, a slot free).
    fn push_uncancelable(ring: *LinuxRing, user_data: u64, entry: Entry) void {
        assert(ring.in_flight < ring.in_flight_max);
        assert(ring.operations <= ring.operations_max);
        const uring = &ring.uring;
        // A free slot means a free submission entry: every queued entry is submitted at once.
        const sqe = uring.get_sqe() catch unreachable;
        switch (entry) {
            .nop => sqe.prep_nop(),
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
        while (true) {
            _ = uring.submit() catch |err| switch (err) {
                error.SignalInterrupt => continue,
                // Without submission the waiter would never wake; there is no recovery.
                else => std.debug.panic("io_uring submit failed: {t}", .{err}),
            };
            break;
        }
        assert(uring.sq_ready() == 0);
    }

    fn reap(ring: *LinuxRing) void {
        var cqes: [reap_batch]linux.io_uring_cqe = undefined;
        var running = true;
        while (running) {
            const count = ring.uring.copy_cqes(&cqes, 1) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => std.debug.panic("io_uring wait failed: {t}", .{err}),
            };
            assert(count <= cqes.len);
            ring.mutex.lockUncancelable(ring.io);
            defer ring.mutex.unlock(ring.io);
            assert(ring.in_flight >= count);
            ring.in_flight -= count;
            for (cqes[0..count]) |cqe| {
                if (cqe.user_data == user_data_shutdown) {
                    running = false;
                } else {
                    ring.complete(cqe);
                }
            }
        }
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
