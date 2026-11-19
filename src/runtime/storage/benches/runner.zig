//! Timed I/O loops and helpers (commonware `runtime/src/storage/benches/runner.rs`).
//!
//! commonware draws random offsets from `SmallRng`; here they come from `utils.rng.TestRng`
//! seeded the same way, so offsets differ from commonware's but stay deterministic per seed.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");
const iface = @import("runtime").storage;
const config_mod = @import("config.zig");
const filesystem = @import("filesystem.zig");
const Stats = @import("report.zig").Stats;
const Payload = filesystem.Payload;
const SyncMode = config_mod.SyncMode;
const SyncMethod = config_mod.SyncMethod;

/// Operations between deadline checks: polling the clock on every operation perturbs
/// hot-cache runs, so a worker may overshoot the deadline by up to this many operations.
pub const deadline_check_stride = 8;

/// Operations between latency samples: a constant stride avoids front-biasing the
/// distribution.
pub const latency_sample_stride = 16;

/// Block indices in sequential, strided order, wrapping around `total_blocks`
/// (commonware `sequential_blocks`).
pub const SequentialBlocks = struct {
    block: u64,
    stride: u64,
    total_blocks: u64,

    pub fn init(start: u64, stride: u64, total_blocks: u64) SequentialBlocks {
        assert(total_blocks > 0 and start < total_blocks);
        return .{ .block = start, .stride = stride, .total_blocks = total_blocks };
    }

    pub fn next(self: *SequentialBlocks) u64 {
        const current = self.block;
        // `total_blocks` is `maxInt(u64)` for an append stream, which never wraps in practice.
        self.block = (self.block +% self.stride) % self.total_blocks;
        assert(current < self.total_blocks);
        return current;
    }
};

/// Uniformly random block indices in `[0, total_blocks)` (commonware `random_blocks`).
pub const RandomBlocks = struct {
    rng: utils.rng.TestRng,
    total_blocks: u64,

    pub fn init(seed: u64, total_blocks: u64) RandomBlocks {
        assert(total_blocks > 0);
        return .{ .rng = .init(seed), .total_blocks = total_blocks };
    }

    pub fn next(self: *RandomBlocks) u64 {
        const block = utils.rng.range_at_most(&self.rng, u64, 0, self.total_blocks - 1);
        assert(block < self.total_blocks);
        return block;
    }
};

/// Read loop without statistics, for cache warm-up.
pub fn warm_read_loop(blob: iface.Blob, buffer: []u8, ops: u64, blocks: anytype) !void {
    const io_size: u64 = buffer.len;
    for (0..ops) |_| try blob.read_at(blocks.next() * io_size, buffer);
}

/// Whether the timed loop should keep running; reads the clock only every
/// `deadline_check_stride` operations.
pub fn should_continue(io: Io, deadline_ns: u64, completed_ops: u64) bool {
    if (completed_ops % deadline_check_stride != 0) return true;
    return filesystem.now_ns(io, .awake) < deadline_ns;
}

/// Whether to record a latency sample for this operation.
pub fn should_sample_latency(completed_ops: u64) bool {
    return completed_ops % latency_sample_stride == 0;
}

fn sample_start(io: Io, ops: u64) ?u64 {
    return if (should_sample_latency(ops)) filesystem.now_ns(io, .awake) else null;
}

fn elapsed_since(io: Io, started: ?u64) ?u64 {
    const start = started orelse return null;
    return filesystem.now_ns(io, .awake) -| start;
}

/// Timed read loop that collects sampled latency statistics.
pub fn run_read_loop(
    gpa: Allocator,
    io: Io,
    blob: iface.Blob,
    deadline_ns: u64,
    buffer: []u8,
    blocks: anytype,
) !Stats {
    var stats: Stats = .{};
    errdefer stats.deinit(gpa);
    const io_size: u64 = buffer.len;
    while (should_continue(io, deadline_ns, stats.ops)) {
        const offset = blocks.next() * io_size;
        const started = sample_start(io, stats.ops);
        try blob.read_at(offset, buffer);
        try stats.record(gpa, io_size, elapsed_since(io, started));
    }
    return stats;
}

/// Timed write loop with caller-defined offsets. Latency covers only `write_at`; periodic
/// syncs are excluded. `after_write.call(end_offset)` runs after each completed write (the
/// frontier writer publishes the visible length to concurrent readers with it).
pub fn run_write_loop(
    gpa: Allocator,
    io: Io,
    blob: iface.Blob,
    deadline_ns: u64,
    payload: *const Payload,
    sync_mode: SyncMode,
    blocks: anytype,
    after_write: anytype,
) !Stats {
    var stats: Stats = .{};
    errdefer stats.deinit(gpa);
    var writes_since_sync: u64 = 0;
    const io_size: u64 = payload.bytes.len;
    while (should_continue(io, deadline_ns, stats.ops)) {
        const offset = blocks.next() * io_size;
        const started = sample_start(io, stats.ops);
        try blob.write_at_vectored(offset, payload.chunks(), .{});
        try stats.record(gpa, io_size, elapsed_since(io, started));
        after_write.call(offset + io_size);
        writes_since_sync += 1;
        if (sync_mode == .every and writes_since_sync == sync_mode.every) {
            try blob.sync();
            writes_since_sync = 0;
        }
    }
    // Flush the last partial batch so `every` reports only durable writes.
    if (sync_mode == .every and writes_since_sync != 0) try blob.sync();
    return stats;
}

/// Timed durable write loop with caller-defined offsets.
pub fn run_sync_write_loop(
    gpa: Allocator,
    io: Io,
    blob: iface.Blob,
    deadline_ns: u64,
    payload: *const Payload,
    sync_method: SyncMethod,
    blocks: anytype,
) !Stats {
    var stats: Stats = .{};
    errdefer stats.deinit(gpa);
    const io_size: u64 = payload.bytes.len;
    while (should_continue(io, deadline_ns, stats.ops)) {
        const offset = blocks.next() * io_size;
        const started = sample_start(io, stats.ops);
        switch (sync_method) {
            .write_then_sync => {
                try blob.write_at_vectored(offset, payload.chunks(), .{});
                try blob.sync();
            },
            .write_and_sync => {
                try blob.write_at_vectored(offset, payload.chunks(), .{ .sync = true });
            },
        }
        try stats.record(gpa, io_size, elapsed_since(io, started));
    }
    return stats;
}

/// An `after_write` that does nothing.
pub const NoAfterWrite = struct {
    pub fn call(_: NoAfterWrite, _: u64) void {}
};
