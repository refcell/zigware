//! io_uring workers for production storage and network (commonware `runtime::iouring`,
//! reduced to the I/O those need; tasks stay on `std.Io`).
//!
//! Each commonware worker thread owns a ring and submits its tasks' I/O to it. Tasks on
//! `std.Io.Threaded` are threads, so each thread that performs I/O owns a worker ring here:
//! created on its first operation and used by it alone (`SINGLE_ISSUER | DEFER_TASKRUN`), it
//! submits an operation and waits for its completion in one `io_uring_enter`, with no
//! hand-off between threads. A thread waits in slices (`slice_ns`) and checks for
//! cancellation between them, since `std.Io.Threaded` interrupts only its own system calls.
//! A canceled or timed-out operation is canceled with `IORING_OP_ASYNC_CANCEL`, and its
//! thread waits for both completions, so buffers stay valid for as long as the kernel uses
//! them.
//!
//! A ring has room for `workers_max` workers. A thread without one (the ring is full, or the
//! kernel refused it a ring) gets null from `worker` and does its I/O through `std.Io`.
//! io_uring exists only on Linux: elsewhere `Ring.init` fails with `error.Unsupported`.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Io = std.Io;
const linux = std.os.linux;
const posix = std.posix;

pub const supported = builtin.os.tag == .linux;

pub const Config = struct {
    /// Submission queue entries of each worker's ring (a power of two, at least 2): an
    /// operation and its cancellation.
    entries: u16 = 4,
};

/// Threads with their own ring, per `Ring`.
pub const workers_max = 256;
/// Longest wait in the kernel before a thread checks whether it was canceled.
pub const slice_ns: u64 = 20 * std.time.ns_per_ms;

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

const user_data_operation: u64 = 1;
const user_data_cancel: u64 = 2;

pub const Ring = if (supported) LinuxRing else UnsupportedRing;
pub const Worker = if (supported) LinuxWorker else UnsupportedWorker;

/// Distinguishes rings in the per-thread cache, so a thread never reuses a worker of a ring
/// that was deinitialized.
var ring_ids: std.atomic.Value(u64) = .init(1);

/// The workers this thread owns, by ring id (a thread can use a few rings at once).
const thread_cache_size = 4;
threadlocal var thread_cache: [thread_cache_size]CacheEntry = @splat(.{});
threadlocal var thread_cache_next: u8 = 0;

const CacheEntry = struct {
    ring_id: u64 = 0,
    /// Null when the thread got no worker from this ring.
    worker: ?*Worker = null,
};

const LinuxRing = struct {
    io: Io,
    config: Config,
    id: u64,
    workers: [workers_max]LinuxWorker,
    /// Worker slots handed out; slots never return, since a worker belongs to its thread.
    claimed: std.atomic.Value(u32) = .init(0),

    pub fn init(ring: *LinuxRing, io: Io, config: Config) InitError!void {
        assert(std.math.isPowerOfTwo(config.entries) and config.entries >= 2);
        ring.* = .{
            .io = io,
            .config = config,
            .id = ring_ids.fetchAdd(1, .monotonic),
            .workers = undefined,
        };
        // Probe once so that a kernel without io_uring fails here, not on every operation.
        var probe = try ring_create(config.entries);
        probe.deinit();
        assert(ring.claimed.load(.monotonic) == 0);
    }

    /// Every `perform` must have returned.
    pub fn deinit(ring: *LinuxRing) void {
        const claimed = @min(ring.claimed.load(.acquire), workers_max);
        for (ring.workers[0..claimed]) |*owned| {
            assert(!owned.busy);
            if (owned.ready) owned.uring.deinit();
        }
        ring.* = undefined;
    }

    /// The calling thread's worker, created on first use, or null when it cannot have one:
    /// use `std.Io` then.
    pub fn worker(ring: *LinuxRing) ?*LinuxWorker {
        for (&thread_cache) |*entry| {
            if (entry.ring_id == ring.id) return entry.worker;
        }
        const created = ring.claim();
        const slot = &thread_cache[thread_cache_next % thread_cache_size];
        thread_cache_next +%= 1;
        slot.* = .{ .ring_id = ring.id, .worker = created };
        assert(created == null or created.?.ready);
        return created;
    }

    /// A new worker for the calling thread, which becomes its only issuer.
    fn claim(ring: *LinuxRing) ?*LinuxWorker {
        const index = ring.claimed.fetchAdd(1, .acq_rel);
        if (index >= workers_max) {
            ring.claimed.store(workers_max, .release);
            return null;
        }
        const created = &ring.workers[index];
        created.* = .{ .io = ring.io, .uring = undefined, .ready = false };
        created.uring = ring_create(ring.config.entries) catch |err| {
            std.log.warn("io_uring worker unavailable ({t}); using std.Io", .{err});
            return null;
        };
        created.ready = true;
        created.register();
        return created;
    }
};

/// A ring for one thread: kernels before 6.1 lack `DEFER_TASKRUN`, and before 5.11 the
/// timed waits this needs (`IORING_FEAT_EXT_ARG`).
fn ring_create(entries: u16) InitError!linux.IoUring {
    const preferred = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN;
    var uring = linux.IoUring.init(entries, preferred) catch |err| switch (err) {
        error.ArgumentsInvalid => linux.IoUring.init(entries, 0) catch |e| return map_init(e),
        else => return map_init(err),
    };
    if (uring.features & linux.IORING_FEAT_EXT_ARG == 0) {
        uring.deinit();
        return error.Unsupported;
    }
    assert(uring.fd >= 0);
    return uring;
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

const LinuxWorker = struct {
    io: Io,
    uring: linux.IoUring,
    ready: bool,
    /// What `io_uring_enter` takes: the ring's registered index, or its descriptor.
    enter_fd: i32 = -1,
    enter_flags: u32 = 0,
    /// An operation is in flight (the owning thread performs one at a time).
    busy: bool = false,
    result: i32 = 0,
    operation_done: bool = false,
    cancel_done: bool = false,

    /// Registers the ring with its thread (kernel 5.18), so each enter skips the descriptor
    /// lookup. The registration holds the ring until the thread exits, as it is the thread's;
    /// a thread holds at most 16, and later rings enter by descriptor.
    fn register(worker: *LinuxWorker) void {
        assert(worker.ready and worker.enter_flags == 0);
        worker.enter_fd = worker.uring.fd;
        var update: linux.io_uring_rsrc_update = .{
            .offset = std.math.maxInt(u32), // Any free index.
            .resv = 0,
            .data = @intCast(worker.uring.fd),
        };
        const rc = linux.io_uring_register(worker.uring.fd, .REGISTER_RING_FDS, &update, 1);
        if (linux.errno(rc) != .SUCCESS) return;
        worker.enter_fd = @intCast(update.offset);
        worker.enter_flags = linux.IORING_ENTER_REGISTERED_RING;
        assert(worker.enter_fd >= 0);
    }

    /// Runs `operation` and returns its result: a count, or a negated errno.
    pub fn perform(
        worker: *LinuxWorker,
        operation: Operation,
        timeout: Io.Timeout,
    ) PerformError!i32 {
        assert(worker.ready);
        assert(!worker.busy);
        worker.busy = true;
        defer worker.busy = false;
        const deadline = timeout.toDeadline(worker.io);
        worker.operation_done = false;
        worker.queue(operation);
        while (true) {
            worker.io.checkCancel() catch |err| return worker.abort(err);
            var wait_ns = slice_ns;
            if (deadline == .deadline) {
                const left = deadline.deadline.durationFromNow(worker.io).raw.nanoseconds;
                if (left <= 0) return worker.abort(error.Timeout);
                wait_ns = @min(wait_ns, @as(u64, @intCast(left)));
            }
            worker.enter(wait_ns);
            worker.reap();
            if (worker.operation_done) return worker.result;
        }
    }

    fn queue(worker: *LinuxWorker, operation: Operation) void {
        // The owner has one operation and at most its cancellation in flight.
        const sqe = worker.uring.get_sqe() catch unreachable;
        switch (operation) {
            .read => |o| sqe.prep_read(o.fd, o.buffer, o.offset),
            .write => |o| sqe.prep_write(o.fd, o.bytes, o.offset),
            .fsync => |o| sqe.prep_fsync(o.fd, 0),
            .recv => |o| sqe.prep_recv(o.fd, o.buffer, 0),
            .sendmsg => |o| sqe.prep_sendmsg(o.fd, o.msg, linux.MSG.NOSIGNAL),
        }
        sqe.user_data = user_data_operation;
        assert(worker.uring.sq.sqe_tail -% worker.uring.sq.sqe_head == 1);
    }

    /// Cancels the operation in flight, waits until the kernel is done with it, and returns
    /// `err`.
    fn abort(worker: *LinuxWorker, err: PerformError) PerformError {
        assert(!worker.operation_done);
        const sqe = worker.uring.get_sqe() catch unreachable;
        sqe.prep_cancel(user_data_operation, 0);
        sqe.user_data = user_data_cancel;
        worker.cancel_done = false;
        while (!(worker.operation_done and worker.cancel_done)) {
            worker.enter(slice_ns);
            worker.reap();
        }
        return err;
    }

    /// Submits what is queued and waits up to `wait_ns` for a completion.
    fn enter(worker: *LinuxWorker, wait_ns: u64) void {
        assert(wait_ns > 0);
        const to_submit = worker.uring.flush_sq();
        var ts: linux.kernel_timespec = .{
            .sec = @intCast(wait_ns / std.time.ns_per_s),
            .nsec = @intCast(wait_ns % std.time.ns_per_s),
        };
        var arg: linux.io_uring_getevents_arg = .{
            .sigmask = 0,
            .sigmask_sz = 0,
            .pad = 0,
            .ts = @intFromPtr(&ts),
        };
        const flags = linux.IORING_ENTER_GETEVENTS | linux.IORING_ENTER_EXT_ARG |
            worker.enter_flags;
        const rc = linux.syscall6(
            .io_uring_enter,
            @as(u32, @bitCast(worker.enter_fd)),
            to_submit,
            1,
            flags,
            @intFromPtr(&arg),
            @sizeOf(linux.io_uring_getevents_arg),
        );
        switch (linux.errno(rc)) {
            // A timeout or interrupt ends the slice; unsubmitted entries go with the next.
            .SUCCESS, .TIME, .INTR, .AGAIN, .BUSY => {},
            // The waiter would never wake; there is no recovery.
            else => |e| std.debug.panic("io_uring enter failed: {t}", .{e}),
        }
    }

    /// Records every ready completion.
    fn reap(worker: *LinuxWorker) void {
        var cqes: [4]linux.io_uring_cqe = undefined;
        const count = worker.uring.copy_cqes(&cqes, 0) catch |err|
            std.debug.panic("io_uring reap failed: {t}", .{err});
        assert(count <= 2);
        for (cqes[0..count]) |cqe| switch (cqe.user_data) {
            user_data_operation => {
                assert(!worker.operation_done);
                worker.operation_done = true;
                worker.result = cqe.res;
            },
            user_data_cancel => worker.cancel_done = true,
            else => unreachable,
        };
    }
};

const UnsupportedRing = struct {
    pub fn init(_: *UnsupportedRing, _: Io, _: Config) InitError!void {
        return error.Unsupported;
    }

    pub fn deinit(_: *UnsupportedRing) void {
        unreachable; // `init` never succeeds.
    }

    pub fn worker(_: *UnsupportedRing) ?*UnsupportedWorker {
        unreachable; // `init` never succeeds.
    }
};

const UnsupportedWorker = struct {
    pub fn perform(_: *UnsupportedWorker, _: Operation, _: Io.Timeout) PerformError!i32 {
        unreachable; // No ring gives one.
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
