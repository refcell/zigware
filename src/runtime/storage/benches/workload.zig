//! Benchmark workload orchestration (commonware `runtime/src/storage/benches/workload.rs`).
//!
//! Each timed I/O stream runs as its own `io.concurrent` task (commonware spawns one task per
//! stream); a failed stream cancels the rest. Cache warm-up runs its streams one after another
//! on the caller, where commonware polls them together on one task: either way the pages end
//! up cached before the timed phase.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const iface = @import("runtime").storage;
const config_mod = @import("config.zig");
const filesystem = @import("filesystem.zig");
const runner = @import("runner.zig");
const report_mod = @import("report.zig");
const Config = config_mod.Config;
const Stats = report_mod.Stats;
const Report = report_mod.Report;

/// Storage partition used for all benchmark blobs.
pub const partition = "storage-bench";
/// Key for the single blob within the partition.
pub const blob_name = "blob";

/// What the benchmark runs against: the runtime's storage over the per-run root.
pub const Env = struct {
    gpa: Allocator,
    io: Io,
    storage: iface.Storage,
    /// The storage root, for the direct file calls (preallocation, page-cache eviction).
    root: Io.Dir,
};

/// State every stream of one run shares.
const Shared = struct {
    env: *const Env,
    cfg: *const Config,
    blob: iface.Blob,
    deadline_ns: u64,
    total_blocks: u64,
    payload: ?*const filesystem.Payload = null,
    /// The visible length the frontier writer publishes to readers.
    current_len: std.atomic.Value(u64) = .init(0),
};

/// Runs the configured workload and returns its report (commonware `run_benchmark`).
pub fn run_benchmark(env: *const Env, cfg: *const Config) !Report {
    assert(cfg.validate() == null);
    defer env.storage.remove(partition, null) catch {};
    return switch (cfg.workload) {
        .read_seq, .read_rand => run_read(env, cfg),
        .write_seq, .write_rand => run_overwrite(env, cfg),
        .write_append => run_write_append(env, cfg),
        .write_sync => run_write_sync(env, cfg),
        .read_write_append => run_read_write_append(env, cfg),
    };
}

fn worker_seed(seed: u64, worker: u32) u64 {
    return seed +% worker;
}

fn deadline(env: *const Env, cfg: *const Config) struct { u64, u64 } {
    const start = filesystem.now_ns(env.io, .awake);
    return .{ start, start + cfg.duration_ns };
}

fn elapsed(env: *const Env, start: u64) u64 {
    return filesystem.now_ns(env.io, .awake) -| start;
}

/// Runs a read-only workload (sequential or random).
fn run_read(env: *const Env, cfg: *const Config) !Report {
    const file_size = cfg.file_size_bytes();
    var rng: filesystem.Rng = .init(cfg.seed);
    const blob = try filesystem.prepare_filled_blob(
        env.gpa,
        &rng,
        env.io,
        env.storage,
        env.root,
        partition,
        blob_name,
        file_size,
    );
    defer blob.close();
    var shared: Shared = .{
        .env = env,
        .cfg = cfg,
        .blob = blob,
        .deadline_ns = 0,
        .total_blocks = file_size / cfg.io_size,
    };
    try prepare_cache(&shared);
    const start, shared.deadline_ns = deadline(env, cfg);
    var workers: [config_mod.inflight_max]Stats = undefined;
    try join_all(&shared, read_stream, workers[0..cfg.inflight]);
    return Report.init(env.gpa, elapsed(env, start), workers[0..cfg.inflight], null, file_size);
}

fn read_stream(shared: *Shared, worker: u32) anyerror!Stats {
    const cfg = shared.cfg;
    const env = shared.env;
    const buffer = try env.gpa.alloc(u8, cfg.io_size);
    defer env.gpa.free(buffer);
    if (cfg.workload == .read_seq) {
        var blocks: runner.SequentialBlocks =
            .init(worker % shared.total_blocks, cfg.inflight, shared.total_blocks);
        return read_loop(shared, buffer, &blocks);
    }
    var blocks: runner.RandomBlocks = .init(worker_seed(cfg.seed, worker), shared.total_blocks);
    return read_loop(shared, buffer, &blocks);
}

/// Runs a sequential or random overwrite workload on a fixed-size file.
fn run_overwrite(env: *const Env, cfg: *const Config) !Report {
    const file_size = cfg.file_size_bytes();
    // Preallocate the blob so the run measures steady-state write cost.
    const blob = try prepare_fixed(env, file_size);
    defer blob.close();
    var rng: filesystem.Rng = .init(cfg.seed);
    var payload = try filesystem.random_write_payload(env.gpa, &rng, cfg.io_size, cfg.write_shape);
    defer payload.deinit(env.gpa);
    var shared: Shared = .{
        .env = env,
        .cfg = cfg,
        .blob = blob,
        .deadline_ns = 0,
        .total_blocks = file_size / cfg.io_size,
        .payload = &payload,
    };
    const start, shared.deadline_ns = deadline(env, cfg);
    var workers: [config_mod.inflight_max]Stats = undefined;
    try join_all(&shared, overwrite_stream, workers[0..cfg.inflight]);
    // `every` flushes any partial tail in the loop; `end` needs one final sync.
    if (cfg.sync_mode == .end) try blob.sync();
    return Report.init(env.gpa, elapsed(env, start), null, workers[0..cfg.inflight], file_size);
}

fn overwrite_stream(shared: *Shared, worker: u32) anyerror!Stats {
    const cfg = shared.cfg;
    const env = shared.env;
    const payload = shared.payload.?;
    const none: runner.NoAfterWrite = .{};
    if (cfg.workload == .write_seq) {
        var blocks: runner.SequentialBlocks =
            .init(worker % shared.total_blocks, cfg.inflight, shared.total_blocks);
        return runner.run_write_loop(
            env.gpa,
            env.io,
            shared.blob,
            shared.deadline_ns,
            payload,
            cfg.sync_mode,
            &blocks,
            none,
        );
    }
    var blocks: runner.RandomBlocks = .init(worker_seed(cfg.seed, worker), shared.total_blocks);
    return runner.run_write_loop(
        env.gpa,
        env.io,
        shared.blob,
        shared.deadline_ns,
        payload,
        cfg.sync_mode,
        &blocks,
        none,
    );
}

/// Runs a single-writer append workload on a growing file.
fn run_write_append(env: *const Env, cfg: *const Config) !Report {
    const blob = try prepare_fixed(env, 0);
    defer blob.close();
    var rng: filesystem.Rng = .init(cfg.seed);
    var payload = try filesystem.random_write_payload(env.gpa, &rng, cfg.io_size, cfg.write_shape);
    defer payload.deinit(env.gpa);
    var shared: Shared = .{
        .env = env,
        .cfg = cfg,
        .blob = blob,
        .deadline_ns = 0,
        .total_blocks = std.math.maxInt(u64),
        .payload = &payload,
    };
    const start, shared.deadline_ns = deadline(env, cfg);
    var workers: [1]Stats = undefined;
    try join_all(&shared, append_stream, &workers);
    if (cfg.sync_mode == .end) try blob.sync();
    const final_file_size = workers[0].bytes;
    return Report.init(env.gpa, elapsed(env, start), null, &workers, final_file_size);
}

fn append_stream(shared: *Shared, worker: u32) anyerror!Stats {
    assert(worker == 0);
    const env = shared.env;
    var blocks: runner.SequentialBlocks = .init(0, 1, std.math.maxInt(u64));
    return runner.run_write_loop(
        env.gpa,
        env.io,
        shared.blob,
        shared.deadline_ns,
        shared.payload.?,
        shared.cfg.sync_mode,
        &blocks,
        runner.NoAfterWrite{},
    );
}

/// Runs sequential durable positioned writes on a fixed-size file.
fn run_write_sync(env: *const Env, cfg: *const Config) !Report {
    const file_size = cfg.file_size_bytes();
    const blob = try prepare_fixed(env, file_size);
    defer blob.close();
    var rng: filesystem.Rng = .init(cfg.seed);
    var payload = try filesystem.random_write_payload(env.gpa, &rng, cfg.io_size, cfg.write_shape);
    defer payload.deinit(env.gpa);
    var shared: Shared = .{
        .env = env,
        .cfg = cfg,
        .blob = blob,
        .deadline_ns = 0,
        .total_blocks = file_size / cfg.io_size,
        .payload = &payload,
    };
    const start, shared.deadline_ns = deadline(env, cfg);
    var workers: [config_mod.inflight_max]Stats = undefined;
    try join_all(&shared, sync_stream, workers[0..cfg.inflight]);
    return Report.init(env.gpa, elapsed(env, start), null, workers[0..cfg.inflight], file_size);
}

fn sync_stream(shared: *Shared, worker: u32) anyerror!Stats {
    const cfg = shared.cfg;
    const env = shared.env;
    var blocks: runner.SequentialBlocks =
        .init(worker % shared.total_blocks, cfg.inflight, shared.total_blocks);
    return runner.run_sync_write_loop(
        env.gpa,
        env.io,
        shared.blob,
        shared.deadline_ns,
        shared.payload.?,
        cfg.sync_method,
        &blocks,
    );
}

/// Runs one append writer plus `inflight` random readers of the visible prefix, which grows
/// as the writer appends. Stream 0 is the writer.
fn run_read_write_append(env: *const Env, cfg: *const Config) !Report {
    const initial_size = cfg.file_size_bytes();
    var rng: filesystem.Rng = .init(cfg.seed);
    const blob = try filesystem.prepare_filled_blob(
        env.gpa,
        &rng,
        env.io,
        env.storage,
        env.root,
        partition,
        blob_name,
        initial_size,
    );
    defer blob.close();
    var payload = try filesystem.random_write_payload(env.gpa, &rng, cfg.io_size, cfg.write_shape);
    defer payload.deinit(env.gpa);
    var shared: Shared = .{
        .env = env,
        .cfg = cfg,
        .blob = blob,
        .deadline_ns = 0,
        .total_blocks = initial_size / cfg.io_size,
        .payload = &payload,
        .current_len = .init(initial_size),
    };
    try prepare_cache(&shared);
    const start, shared.deadline_ns = deadline(env, cfg);
    var workers: [config_mod.inflight_max + 1]Stats = undefined;
    const streams = workers[0 .. cfg.inflight + 1];
    try join_all(&shared, frontier_stream, streams);
    const final_file_size = initial_size + streams[0].bytes;
    if (cfg.sync_mode == .end) try blob.sync();
    return Report.init(env.gpa, elapsed(env, start), streams[1..], streams[0..1], final_file_size);
}

/// Publishes the writer's end offset as the readers' visible length.
const PublishLen = struct {
    current_len: *std.atomic.Value(u64),

    pub fn call(self: PublishLen, end_offset: u64) void {
        self.current_len.store(end_offset, .monotonic);
    }
};

/// Random blocks of the currently visible prefix.
const FrontierBlocks = struct {
    rng: filesystem.Rng,
    current_len: *const std.atomic.Value(u64),
    io_size: u64,

    pub fn next(self: *FrontierBlocks) u64 {
        const total_blocks = self.current_len.load(.monotonic) / self.io_size;
        assert(total_blocks > 0);
        return @import("utils").rng.range_at_most(&self.rng, u64, 0, total_blocks - 1);
    }
};

fn frontier_stream(shared: *Shared, stream: u32) anyerror!Stats {
    const cfg = shared.cfg;
    const env = shared.env;
    if (stream == 0) {
        var blocks: runner.SequentialBlocks = .init(shared.total_blocks, 1, std.math.maxInt(u64));
        const publish: PublishLen = .{ .current_len = &shared.current_len };
        return runner.run_write_loop(
            env.gpa,
            env.io,
            shared.blob,
            shared.deadline_ns,
            shared.payload.?,
            cfg.sync_mode,
            &blocks,
            publish,
        );
    }
    const worker = stream - 1;
    var blocks: FrontierBlocks = .{
        .rng = .init(worker_seed(cfg.seed, worker)),
        .current_len = &shared.current_len,
        .io_size = cfg.io_size,
    };
    const buffer = try env.gpa.alloc(u8, cfg.io_size);
    defer env.gpa.free(buffer);
    return read_loop(shared, buffer, &blocks);
}

/// Runs `stream(shared, index)` for every slot of `out` concurrently and collects their stats.
/// On any failure the remaining streams are canceled, collected stats are freed, and the
/// first error is returned.
fn join_all(
    shared: *Shared,
    comptime stream: fn (*Shared, u32) anyerror!Stats,
    out: []Stats,
) !void {
    assert(out.len > 0 and out.len <= config_mod.inflight_max + 1);
    const io = shared.env.io;
    const gpa = shared.env.gpa;
    var futures: [config_mod.inflight_max + 1]Io.Future(anyerror!Stats) = undefined;
    var started: u32 = 0;
    errdefer for (futures[0..started]) |*future| {
        var stats = future.cancel(io) catch continue;
        stats.deinit(gpa);
    };
    while (started < out.len) : (started += 1) {
        futures[started] = try io.concurrent(stream, .{ shared, started });
    }
    var first_error: ?anyerror = null;
    for (futures[0..started], out) |*future, *slot| {
        if (future.await(io)) |stats| {
            slot.* = stats;
        } else |err| {
            slot.* = .{};
            first_error = first_error orelse err;
        }
    }
    started = 0;
    if (first_error) |err| {
        for (out) |*stats| stats.deinit(gpa);
        return err;
    }
}

/// Prepares the page cache before the timed phase: `cold` evicts the blob's pages, `warm`
/// reads through the file (each sequential worker covers a strided slice; random workers
/// draw 3 × total_blocks reads in all, which misses about e^-3 of the pages).
fn prepare_cache(shared: *Shared) !void {
    const cfg = shared.cfg;
    const env = shared.env;
    const cache = cfg.cache.?;
    if (cache == .cold) {
        return filesystem.drop_page_cache(env.io, env.root, partition, blob_name);
    }
    const inflight: u64 = cfg.inflight;
    const total_blocks = shared.total_blocks;
    const buffer = try env.gpa.alloc(u8, cfg.io_size);
    defer env.gpa.free(buffer);
    for (0..cfg.inflight) |index| {
        const worker: u32 = @intCast(index);
        if (cfg.workload == .read_seq) {
            var blocks: runner.SequentialBlocks =
                .init(worker % total_blocks, inflight, total_blocks);
            const ops = div_ceil(total_blocks, inflight);
            try runner.warm_read_loop(shared.blob, buffer, ops, &blocks);
        } else {
            const ops = @max(div_ceil(total_blocks *| 3, inflight), 1);
            var blocks: runner.RandomBlocks = .init(worker_seed(cfg.seed, worker), total_blocks);
            try runner.warm_read_loop(shared.blob, buffer, ops, &blocks);
        }
    }
}

fn div_ceil(numerator: u64, denominator: u64) u64 {
    assert(denominator > 0);
    return numerator / denominator + @intFromBool(numerator % denominator != 0);
}

/// The benchmark blob at `file_size`, preallocated.
fn prepare_fixed(env: *const Env, file_size: u64) !iface.Blob {
    return filesystem.prepare_blob(env.io, env.storage, env.root, partition, blob_name, file_size);
}

fn read_loop(shared: *Shared, buffer: []u8, blocks: anytype) !Stats {
    const env = shared.env;
    return runner.run_read_loop(env.gpa, env.io, shared.blob, shared.deadline_ns, buffer, blocks);
}
