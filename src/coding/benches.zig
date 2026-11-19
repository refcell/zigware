//! Benchmarks of the coding schemes (commonware `coding/src/benches`): encode and decode
//! times (`coding_scheme_times`) and shard sizes (`coding_scheme_sizes`), with commonware's
//! names, message lengths, shard counts, concurrency, and shard selections.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const coding = @import("coding");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");

const Scheme = coding.ReedSolomon(cryptography.Sha256);
const Config = coding.Config;
const Encoding = coding.reed_solomon.Encoding(Scheme.Commitment);
const Rng = utils.rng.ChaCha8Rng;

const chunk_counts = [_]u16{ 10, 25, 50, 100, 250 };
const concurrencies = [_]usize{ 1, 8 };
const message_lengths = [_]usize{ 1 << 20, 1 << 22, 1 << 23 };
const size_lengths = [_]usize{
    1 << 8, 1 << 12, 1 << 16, 1 << 19, 1 << 20, 1 << 22, 1 << 23, 1 << 24,
};

/// The shards a decode benchmark provides, as commonware's `ShardSelection`.
const ShardSelection = enum {
    best,
    exception,
    worst,
    interleaved,

    /// `min` shard indices: the first `min` (`best`), shifted by one (`exception`), the next
    /// `min` (`worst`), or alternating between the two (`interleaved`).
    fn indices(selection: ShardSelection, min: u16, out: []u16) []u16 {
        assert(out.len >= min);
        assert(min > 0);
        for (out[0..min], 0..) |*index, i_usize| {
            const i: u16 = @intCast(i_usize);
            index.* = switch (selection) {
                .best => i,
                .exception => i + 1,
                .worst => min + i,
                .interleaved => if (i % 2 == 0) i / 2 else min + i / 2,
            };
        }
        return out[0..min];
    }
};

/// The extra decode cases: message bytes, total shards, concurrency, and shard selection.
const DecodeCase = struct { usize, u16, usize, ShardSelection };
const decode_extra_cases = [_]DecodeCase{
    .{ 1 << 12, 20, 1, .interleaved },  .{ 1 << 20, 20, 1, .interleaved },
    .{ 1 << 20, 20, 4, .interleaved },  .{ 1 << 23, 20, 1, .interleaved },
    .{ 1 << 23, 20, 4, .interleaved },  .{ 1 << 20, 100, 4, .interleaved },
    .{ 1 << 20, 250, 4, .interleaved }, .{ 1 << 20, 500, 4, .interleaved },
    .{ 1 << 20, 20, 4, .best },         .{ 1 << 20, 20, 4, .worst },
};

fn config_of(chunks: u16, min: u16) Config {
    assert(min > 0 and min < chunks);
    return .{ .minimum_shards = min, .extra_shards = chunks - min };
}

/// Encodes fresh random data each iteration; the data is drawn untimed.
fn EncodeWorkload(comptime Strategy: type) type {
    return struct {
        gpa: Allocator,
        config: Config,
        strategy: Strategy,
        rng: *Rng,
        data: []u8,
        encoding: ?Encoding = null,

        pub fn before_iter(workload: *@This()) void {
            workload.teardown();
            workload.rng.fill_bytes(workload.data);
        }

        pub fn iter(workload: *@This()) !usize {
            assert(workload.encoding == null);
            const encoding = try Scheme.encode(
                workload.gpa,
                workload.config,
                workload.data,
                workload.strategy,
            );
            workload.encoding = encoding;
            return encoding.shards.len;
        }

        pub fn teardown(workload: *@This()) void {
            if (workload.encoding) |*encoding| encoding.deinit(workload.gpa);
            workload.encoding = null;
        }
    };
}

/// Decodes from `min` checked shards each iteration; encoding and checking are untimed.
fn DecodeWorkload(comptime Strategy: type) type {
    return struct {
        gpa: Allocator,
        config: Config,
        strategy: Strategy,
        selection: ShardSelection,
        rng: *Rng,
        data: []u8,
        checked: []Scheme.CheckedShard,
        encoding: ?Encoding = null,
        decoded: ?[]u8 = null,

        pub fn before_iter(workload: *@This()) !void {
            workload.teardown();
            workload.rng.fill_bytes(workload.data);
            const gpa = workload.gpa;
            const config = workload.config;
            const strategy = workload.strategy;
            workload.encoding = try Scheme.encode(gpa, config, workload.data, strategy);
            const encoding = &workload.encoding.?;
            var buffer: [std.math.maxInt(u16)]u16 = undefined;
            const indices = workload.selection.indices(config.minimum_shards, &buffer);
            assert(indices.len == workload.checked.len);
            for (indices, workload.checked) |index, *checked| {
                const shard = &encoding.shards[index];
                checked.* = try Scheme.check(config, &encoding.commitment, index, shard, strategy);
            }
        }

        pub fn iter(workload: *@This()) !usize {
            assert(workload.decoded == null);
            const encoding = &workload.encoding.?;
            const decoded = try Scheme.decode(
                workload.gpa,
                workload.config,
                &encoding.commitment,
                workload.checked,
                workload.strategy,
            );
            workload.decoded = decoded;
            assert(decoded.len == workload.data.len);
            return decoded.len;
        }

        pub fn teardown(workload: *@This()) void {
            if (workload.decoded) |decoded| workload.gpa.free(decoded);
            if (workload.encoding) |*encoding| encoding.deinit(workload.gpa);
            workload.decoded = null;
            workload.encoding = null;
        }
    };
}

const Case = struct {
    msg_len: usize,
    chunks: u16,
    conc: usize,
};

fn bench_encode_with(runner: *bench.Runner, rng: *Rng, case: Case, strategy: anytype) !void {
    const gpa = runner.allocator;
    const data = try gpa.alloc(u8, case.msg_len);
    defer gpa.free(data);
    var workload: EncodeWorkload(@TypeOf(strategy)) = .{
        .gpa = gpa,
        .config = config_of(case.chunks, case.chunks / 3),
        .strategy = strategy,
        .rng = rng,
        .data = data,
    };
    defer workload.teardown();
    const benchmark = bench.Benchmark.init("reed_solomon::encode")
        .with_param("msg_len", case.msg_len)
        .with_param("chunks", case.chunks)
        .with_param("conc", case.conc);
    try runner.run(benchmark, &workload);
}

fn bench_decode_with(
    runner: *bench.Runner,
    rng: *Rng,
    case: Case,
    selections: []const ShardSelection,
    strategy: anytype,
) !void {
    const gpa = runner.allocator;
    const min: u16 = @intCast(utils.N3f1.max_faults(case.chunks) + 1);
    const data = try gpa.alloc(u8, case.msg_len);
    defer gpa.free(data);
    const checked = try gpa.alloc(Scheme.CheckedShard, min);
    defer gpa.free(checked);
    for (selections) |selection| {
        var workload: DecodeWorkload(@TypeOf(strategy)) = .{
            .gpa = gpa,
            .config = config_of(case.chunks, min),
            .strategy = strategy,
            .selection = selection,
            .rng = rng,
            .data = data,
            .checked = checked,
        };
        defer workload.teardown();
        const benchmark = bench.Benchmark.init("reed_solomon::decode")
            .with_param("msg_len", case.msg_len)
            .with_param("chunks", case.chunks)
            .with_param("min_shards", min)
            .with_param("conc", case.conc)
            .with_param("shard_selection", selection);
        try runner.run(benchmark, &workload);
    }
}

/// Runs one encode case, or one decode case per selection, sequentially when `conc` is one
/// and otherwise on a pool of `conc` threads (the caller and `conc - 1` workers).
fn bench_case(
    runner: *bench.Runner,
    rng: *Rng,
    case: Case,
    selections: ?[]const ShardSelection,
) !void {
    assert(case.conc > 0);
    assert(case.chunks >= 3);
    if (case.conc == 1) {
        const strategy = parallel.sequential;
        if (selections) |s| return bench_decode_with(runner, rng, case, s, strategy);
        return bench_encode_with(runner, rng, case, strategy);
    }
    const threads: u32 = @intCast(case.conc - 1);
    const pool = try parallel.ThreadPool.create(runner.allocator, runner.io, .{
        .threads = threads,
    });
    defer pool.destroy();
    const strategy = parallel.Rayon.init(pool);
    if (selections) |s| return bench_decode_with(runner, rng, case, s, strategy);
    return bench_encode_with(runner, rng, case, strategy);
}

fn bench_times(runner: *bench.Runner) !void {
    const lengths = runner.inputs.pick(
        []const usize,
        &.{1 << 10},
        &message_lengths,
        &message_lengths,
    );
    const chunks_list = runner.inputs.pick(
        []const u16,
        chunk_counts[0..1],
        &chunk_counts,
        &chunk_counts,
    );
    const selections = std.enums.values(ShardSelection);
    var rng: Rng = .init(0);
    for (lengths) |msg_len| for (chunks_list) |chunks| for (concurrencies) |conc| {
        try bench_case(runner, &rng, .{ .msg_len = msg_len, .chunks = chunks, .conc = conc }, null);
    };
    rng = .init(0);
    for (lengths) |msg_len| for (chunks_list) |chunks| for (concurrencies) |conc| {
        const case: Case = .{ .msg_len = msg_len, .chunks = chunks, .conc = conc };
        try bench_case(runner, &rng, case, selections);
    };
    const extra = runner.inputs.pick(
        []const DecodeCase,
        &.{},
        &decode_extra_cases,
        &decode_extra_cases,
    );
    for (extra) |entry| {
        const case: Case = .{ .msg_len = entry[0], .chunks = entry[1], .conc = entry[2] };
        try bench_case(runner, &rng, case, &.{entry[3]});
    }
}

/// Encodes sequentially and reports the encoded size of the first shard as `shard_bytes`, as
/// commonware's `coding_scheme_sizes` prints it.
const SizeWorkload = struct {
    gpa: Allocator,
    config: Config,
    data: []const u8,
    shard_bytes: u64 = 0,

    pub fn iter(workload: *SizeWorkload) !u64 {
        var encoding = try Scheme.encode(
            workload.gpa,
            workload.config,
            workload.data,
            parallel.sequential,
        );
        defer encoding.deinit(workload.gpa);
        workload.shard_bytes = encoding.shards[0].encode_size();
        assert(workload.shard_bytes > 0);
        return workload.shard_bytes;
    }

    pub fn metrics(workload: *const SizeWorkload, buffer: []bench.Metric) []const bench.Metric {
        assert(buffer.len >= 1);
        assert(workload.shard_bytes > 0);
        buffer[0] = .init("shard_bytes", workload.shard_bytes);
        return buffer[0..1];
    }
};

fn bench_sizes(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const lengths = runner.inputs.pick(
        []const usize,
        size_lengths[0..1],
        &size_lengths,
        &size_lengths,
    );
    const chunks_list = runner.inputs.pick(
        []const u16,
        chunk_counts[0..1],
        &chunk_counts,
        &chunk_counts,
    );
    var rng: Rng = .init(0);
    for (lengths) |msg_len| for (chunks_list) |chunks| {
        const data = try gpa.alloc(u8, msg_len);
        defer gpa.free(data);
        rng.fill_bytes(data);
        var workload: SizeWorkload = .{
            .gpa = gpa,
            .config = config_of(chunks, chunks / 3),
            .data = data,
        };
        const benchmark = bench.Benchmark.init("reed_solomon size (shard)")
            .with_param("msg_len", msg_len)
            .with_param("chunks", chunks);
        try runner.run(benchmark, &workload);
    };
}

pub fn run(runner: *bench.Runner) !void {
    var retaining: Retaining = .{ .backing = runner.allocator, .io = runner.io };
    defer retaining.deinit();
    const backing = runner.allocator;
    runner.allocator = retaining.allocator();
    defer runner.allocator = backing;
    try bench_times(runner);
    try bench_sizes(runner);
}

/// The benches' allocator: `backing`, but freed blocks of at least `threshold_bytes` are kept
/// and handed back to the next allocation of the same size and alignment. Commonware's benches
/// run on glibc malloc, which reuses freed large blocks the same way; std's general-purpose
/// allocator unmaps them, so every encode and decode would fault its megabytes of codeword in
/// afresh (about 340 times commonware's page faults on `msg_len=4194304 chunks=10`).
const Retaining = struct {
    backing: Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    blocks: [capacity]Block = @splat(.{}),

    const capacity = 32;
    const threshold_bytes = 1 << 16;
    const Alignment = std.mem.Alignment;
    const Block = struct { ptr: ?[*]u8 = null, len: usize = 0, alignment: Alignment = .@"1" };

    fn allocator(self: *Retaining) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn deinit(self: *Retaining) void {
        for (&self.blocks) |*block| {
            const ptr = block.ptr orelse continue;
            self.backing.rawFree(ptr[0..block.len], block.alignment, @returnAddress());
            block.* = .{};
        }
        assert(for (self.blocks) |block| (if (block.ptr != null) break false) else true);
    }

    fn alloc(context: *anyopaque, len: usize, alignment: Alignment, ra: usize) ?[*]u8 {
        const self: *Retaining = @ptrCast(@alignCast(context));
        assert(len > 0);
        if (len >= threshold_bytes) {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            for (&self.blocks) |*block| {
                const ptr = block.ptr orelse continue;
                if (block.len != len or block.alignment != alignment) continue;
                block.* = .{};
                return ptr;
            }
        }
        return self.backing.rawAlloc(len, alignment, ra);
    }

    fn free(context: *anyopaque, memory: []u8, alignment: Alignment, ra: usize) void {
        const self: *Retaining = @ptrCast(@alignCast(context));
        assert(memory.len > 0);
        if (memory.len >= threshold_bytes) {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            for (&self.blocks) |*block| {
                if (block.ptr != null) continue;
                block.* = .{ .ptr = memory.ptr, .len = memory.len, .alignment = alignment };
                return;
            }
        }
        self.backing.rawFree(memory, alignment, ra);
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: Alignment, len: usize, ra: usize) bool {
        const self: *Retaining = @ptrCast(@alignCast(context));
        return self.backing.rawResize(memory, alignment, len, ra);
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: Alignment,
        len: usize,
        ra: usize,
    ) ?[*]u8 {
        const self: *Retaining = @ptrCast(@alignCast(context));
        return self.backing.rawRemap(memory, alignment, len, ra);
    }
};
