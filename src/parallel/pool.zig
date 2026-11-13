//! A small fork-join thread pool for the `Rayon` strategy.
//!
//! The pool owns `threads` workers started through `std.Io` (`Group.concurrent`), so the
//! deterministic runtime can replace them with its own tasks, and every wait goes through
//! `std.Io` futexes. A parallel operation hands the pool at most `max_jobs` jobs at once with
//! `run`: the calling thread queues jobs `1..count`, runs job 0 itself, then takes back the
//! jobs no worker has started yet, newest first, while workers take the oldest from the front
//! of the queue. A caller still waiting for a job a worker holds runs other queued jobs, so a
//! nested parallel operation inside a job never starves.
//!
//! Jobs live on the caller's stack and are linked into the queue intrusively, so queuing does
//! not allocate. A job leaves the queue under the pool's mutex, either taken by a worker or
//! taken back by its caller, so no job is ever run twice or left behind.
//!
//! A pool with zero threads runs every job on its caller, in order, which suits the
//! deterministic runtime (commonware's single-threaded `use_current_thread` pool).

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

/// The most jobs one `run` call hands the pool.
pub const max_jobs: usize = 64;

/// The most worker threads a pool may own.
pub const threads_max: u32 = 1024;

pub const Config = struct {
    /// Worker threads to start. Zero runs every job on the calling thread.
    threads: u32,
};

/// Counts the jobs of one `run` call that are not finished yet.
const Latch = struct {
    pending: std.atomic.Value(u32),
};

const Job = struct {
    node: std.DoublyLinkedList.Node = .{},
    context: *const anyopaque,
    call: *const fn (context: *const anyopaque, index: usize) void,
    index: usize,
    latch: *Latch,
    /// Whether the job is in the queue; guarded by the pool's mutex.
    queued: bool,

    /// Runs the job, then counts it finished. The latch's memory is the waiter's stack, so the
    /// decrement is the last access other than the wake, and waking an address whose waiter
    /// has already returned is only a spurious wake for whoever waits there next.
    fn execute(job: *Job, io: Io) void {
        assert(!job.queued);
        const latch = job.latch;
        job.call(job.context, job.index);
        const before = latch.pending.fetchSub(1, .acq_rel);
        assert(before > 0);
        if (before == 1) io.futexWake(u32, &latch.pending.raw, 1);
    }
};

pub const ThreadPool = struct {
    io: Io,
    allocator: std.mem.Allocator,
    threads: u32,
    mutex: Io.Mutex = .init,
    queue: std.DoublyLinkedList = .{},
    /// Bumped under `mutex` whenever jobs are queued or the pool shuts down; idle workers
    /// sleep on it.
    epoch: std.atomic.Value(u32) = .init(0),
    shutdown: bool = false,
    group: Io.Group = .init,

    pub const Error = std.mem.Allocator.Error || Io.ConcurrentError;

    /// Starts a pool of `config.threads` workers. `allocator` must be thread-safe if callers
    /// on several threads sort through the pool, which borrows it for merge buffers.
    pub fn create(allocator: std.mem.Allocator, io: Io, config: Config) Error!*ThreadPool {
        assert(config.threads <= threads_max);
        const pool = try allocator.create(ThreadPool);
        errdefer allocator.destroy(pool);
        pool.* = .{ .io = io, .allocator = allocator, .threads = config.threads };
        errdefer pool.stop();
        for (0..config.threads) |_| try pool.group.concurrent(io, worker_main, .{pool});
        assert(pool.queue.first == null);
        return pool;
    }

    /// Stops the workers and frees the pool. No `run` call may be in progress.
    pub fn destroy(pool: *ThreadPool) void {
        const allocator = pool.allocator;
        pool.stop();
        allocator.destroy(pool);
    }

    fn stop(pool: *ThreadPool) void {
        pool.mutex.lockUncancelable(pool.io);
        assert(pool.queue.first == null);
        pool.shutdown = true;
        _ = pool.epoch.fetchAdd(1, .release);
        pool.mutex.unlock(pool.io);
        pool.io.futexWake(u32, &pool.epoch.raw, std.math.maxInt(u32));
        pool.group.await(pool.io) catch pool.group.cancel(pool.io);
        assert(pool.group.token.raw == null);
    }

    fn worker_main(pool: *ThreadPool) void {
        while (true) {
            pool.mutex.lockUncancelable(pool.io);
            if (pool.pop_locked()) |job| {
                pool.mutex.unlock(pool.io);
                job.execute(pool.io);
                continue;
            }
            if (pool.shutdown) {
                pool.mutex.unlock(pool.io);
                return;
            }
            const seen = pool.epoch.load(.monotonic);
            pool.mutex.unlock(pool.io);
            pool.io.futexWaitUncancelable(u32, &pool.epoch.raw, seen);
        }
    }

    fn pop_locked(pool: *ThreadPool) ?*Job {
        const node = pool.queue.popFirst() orelse return null;
        const job: *Job = @fieldParentPtr("node", node);
        assert(job.queued);
        job.queued = false;
        return job;
    }

    fn push_all(pool: *ThreadPool, jobs: []Job) void {
        assert(jobs.len > 0);
        pool.mutex.lockUncancelable(pool.io);
        assert(!pool.shutdown);
        for (jobs) |*job| {
            assert(job.queued);
            pool.queue.append(&job.node);
        }
        _ = pool.epoch.fetchAdd(1, .release);
        pool.mutex.unlock(pool.io);
        const wake: u32 = @intCast(@min(jobs.len, pool.threads));
        pool.io.futexWake(u32, &pool.epoch.raw, wake);
    }

    /// Takes `job` back from the queue if no worker has taken it.
    fn reclaim(pool: *ThreadPool, job: *Job) bool {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        if (!job.queued) return false;
        pool.queue.remove(&job.node);
        job.queued = false;
        return true;
    }

    /// Waits until every job counted by `latch` finishes, running other queued jobs meanwhile.
    fn wait(pool: *ThreadPool, latch: *Latch) void {
        while (true) {
            const pending = latch.pending.load(.acquire);
            if (pending == 0) return;
            pool.mutex.lockUncancelable(pool.io);
            const job = pool.pop_locked();
            pool.mutex.unlock(pool.io);
            if (job) |queued| {
                queued.execute(pool.io);
            } else {
                pool.io.futexWaitUncancelable(u32, &latch.pending.raw, pending);
            }
        }
    }

    /// Calls `body(context, index)` for every `index` in `0..count`, possibly in parallel, and
    /// returns once all calls have returned. `context` must be a pointer.
    pub fn run(
        pool: *ThreadPool,
        count: usize,
        context: anytype,
        comptime body: fn (@TypeOf(context), usize) void,
    ) void {
        const Context = @TypeOf(context);
        comptime assert(@typeInfo(Context) == .pointer);
        assert(count >= 1);
        assert(count <= max_jobs);
        if (pool.threads == 0 or count == 1) {
            for (0..count) |index| body(context, index);
            return;
        }

        const Erased = struct {
            fn call(erased: *const anyopaque, index: usize) void {
                body(@ptrCast(@alignCast(erased)), index);
            }
        };
        var latch: Latch = .{ .pending = .init(@intCast(count - 1)) };
        var jobs: [max_jobs]Job = undefined;
        for (jobs[1..count], 1..) |*job, index| job.* = .{
            .context = @ptrCast(context),
            .call = Erased.call,
            .index = index,
            .latch = &latch,
            .queued = true,
        };
        pool.push_all(jobs[1..count]);
        body(context, 0);

        // Workers take the oldest jobs, so take back the newest ones first.
        var index = count;
        while (index > 1) {
            index -= 1;
            if (pool.reclaim(&jobs[index])) jobs[index].execute(pool.io);
        }
        pool.wait(&latch);
        assert(latch.pending.load(.acquire) == 0);
    }
};
