//! Benchmarks of the Reed-Solomon encoder, decoder, rates, and engines (commonware
//! `cryptography/src/reed_solomon/benches/bench.rs`), with commonware's names and cases.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const utils = @import("utils");

const rs = cryptography.reed_solomon;
const engine = rs.engine;
const rate = rs.rate;
const Chunk = engine.Chunk;
const GF_ORDER = engine.GF_ORDER;
const SHARD_CHUNK_BYTES = engine.SHARD_CHUNK_BYTES;

/// Shard size in bytes used by every benchmark.
const SHARD_BYTES: usize = 1024;

const Case = struct { original: usize, recovery: usize };

/// The default encoder and decoder cases: powers of two with equal counts, then unequal counts
/// and counts that are not powers of two.
const main_cases = [_]Case{
    .{ .original = 32, .recovery = 32 },       .{ .original = 64, .recovery = 64 },
    .{ .original = 128, .recovery = 128 },     .{ .original = 256, .recovery = 256 },
    .{ .original = 512, .recovery = 512 },     .{ .original = 1024, .recovery = 1024 },
    .{ .original = 2048, .recovery = 2048 },   .{ .original = 4096, .recovery = 4096 },
    .{ .original = 8192, .recovery = 8192 },   .{ .original = 16384, .recovery = 16384 },
    .{ .original = 32768, .recovery = 32768 }, .{ .original = 128, .recovery = 1024 },
    .{ .original = 1000, .recovery = 100 },    .{ .original = 1000, .recovery = 10000 },
    .{ .original = 1024, .recovery = 128 },    .{ .original = 1024, .recovery = 8192 },
    .{ .original = 8192, .recovery = 1024 },   .{ .original = 8192, .recovery = 16384 },
    .{ .original = 8192, .recovery = 57344 },  .{ .original = 10000, .recovery = 1000 },
    .{ .original = 16384, .recovery = 8192 },  .{ .original = 16385, .recovery = 16385 },
    .{ .original = 57344, .recovery = 8192 },
};

/// The high and low rate cases.
const rate_cases = [_]Case{
    .{ .original = 1024, .recovery = 1024 }, .{ .original = 1024, .recovery = 1025 },
    .{ .original = 1025, .recovery = 1024 }, .{ .original = 1024, .recovery = 2048 },
    .{ .original = 2048, .recovery = 1024 }, .{ .original = 1025, .recovery = 1025 },
    .{ .original = 1025, .recovery = 2048 }, .{ .original = 2048, .recovery = 1025 },
    .{ .original = 2048, .recovery = 2048 },
};

/// One small case for the smoke run under `zig build test`.
const smoke_cases = [_]Case{.{ .original = 32, .recovery = 32 }};

/// `shard_count` shards of `shard_bytes` random bytes from a `ChaCha8Rng` seeded with
/// `[seed; 32]`, filled in order as commonware's `generate_shards`. The caller frees them with
/// `free_shards`.
fn generate_shards(gpa: Allocator, shard_count: usize, shard_bytes: usize, seed: u8) ![][]u8 {
    assert(shard_bytes % SHARD_CHUNK_BYTES == 0);
    assert(shard_count > 0);
    var rng: utils.rng.ChaCha8Rng = .init_key(@splat(seed));
    const flat = try gpa.alloc(u8, shard_count * shard_bytes);
    errdefer gpa.free(flat);
    rng.fill_bytes(flat);
    const shards = try gpa.alloc([]u8, shard_count);
    for (shards, 0..) |*shard, index| shard.* = flat[index * shard_bytes ..][0..shard_bytes];
    return shards;
}

fn free_shards(gpa: Allocator, shards: [][]u8) void {
    assert(shards.len > 0);
    const shard_bytes = shards[0].len;
    gpa.free(shards[0].ptr[0 .. shards.len * shard_bytes]);
    gpa.free(shards);
}

/// The recovery shards for `original`, encoded with the default `Encoder`.
fn encode_recovery(gpa: Allocator, case: Case, original: []const []const u8) ![][]u8 {
    assert(original.len == case.original);
    var encoder: rs.Encoder = try .init(gpa, case.original, case.recovery, SHARD_BYTES);
    defer encoder.deinit(gpa);
    for (original) |shard| try encoder.add_original_shard(shard);
    var result = try encoder.encode();
    defer result.deinit();
    const recovery = try generate_shards(gpa, case.recovery, SHARD_BYTES, 0);
    var iterator = result.recovery_iter();
    for (recovery) |shard| @memcpy(shard, iterator.next().?);
    assert(iterator.next() == null);
    return recovery;
}

/// Adds every original and encodes, as one benchmark iteration.
fn EncodeWorkload(comptime Encoder: type) type {
    return struct {
        encoder: *Encoder,
        original: []const []const u8,

        pub fn iter(workload: *@This()) !usize {
            for (workload.original) |shard| try workload.encoder.add_original_shard(shard);
            var result = try workload.encoder.encode();
            defer result.deinit();
            assert(result.recovery(0) != null);
            return workload.original.len;
        }
    };
}

/// Adds the first `original_provided` originals and `recovery_provided` recovery shards and
/// decodes, as one benchmark iteration.
fn DecodeWorkload(comptime Decoder: type) type {
    return struct {
        decoder: *Decoder,
        original: []const []const u8,
        recovery: []const []const u8,
        original_provided: usize,
        recovery_provided: usize,

        pub fn iter(workload: *@This()) !usize {
            assert(workload.original_provided <= workload.original.len);
            assert(workload.recovery_provided <= workload.recovery.len);
            const decoder = workload.decoder;
            for (workload.original[0..workload.original_provided], 0..) |shard, index| {
                try decoder.add_original_shard(index, shard);
            }
            for (workload.recovery[0..workload.recovery_provided], 0..) |shard, index| {
                try decoder.add_recovery_shard(index, shard);
            }
            var result = (if (Decoder == rs.Decoder)
                try decoder.decode()
            else
                try decoder.decode(false)).?;
            result.deinit();
            return workload.recovery_provided;
        }
    };
}

fn case_name(prefix: []const u8, label: ?[]const u8, case: Case) bench.Benchmark {
    var benchmark = bench.Benchmark.init(prefix);
    if (label) |name| benchmark = benchmark.with_param("rate", name);
    return benchmark
        .with_param("original", case.original)
        .with_param("recovery", case.recovery)
        .with_param("shard_bytes", SHARD_BYTES);
}

fn bench_encoder(
    runner: *bench.Runner,
    comptime Encoder: type,
    prefix: []const u8,
    label: ?[]const u8,
    case: Case,
) !void {
    const gpa = runner.allocator;
    const original = try generate_shards(gpa, case.original, SHARD_BYTES, 0);
    defer free_shards(gpa, original);
    var encoder = if (Encoder == rs.Encoder)
        try Encoder.init(gpa, case.original, case.recovery, SHARD_BYTES)
    else
        try Encoder.init(gpa, case.original, case.recovery, SHARD_BYTES, .init(), null);
    defer encoder.deinit(gpa);
    var workload: EncodeWorkload(Encoder) = .{ .encoder = &encoder, .original = original };
    try runner.run(case_name(prefix, label, case), &workload);
}

/// Benchmarks decoding `case` after losing `loss` originals, replaced by recovery shards.
fn bench_decoder(
    runner: *bench.Runner,
    comptime Decoder: type,
    benchmark: bench.Benchmark,
    case: Case,
    loss: usize,
) !void {
    assert(loss <= @min(case.original, case.recovery));
    const gpa = runner.allocator;
    const original = try generate_shards(gpa, case.original, SHARD_BYTES, 0);
    defer free_shards(gpa, original);
    const recovery = try encode_recovery(gpa, case, original);
    defer free_shards(gpa, recovery);
    var decoder = if (Decoder == rs.Decoder)
        try Decoder.init(gpa, case.original, case.recovery, SHARD_BYTES)
    else
        try Decoder.init(gpa, case.original, case.recovery, SHARD_BYTES, .init(), null);
    defer decoder.deinit(gpa);
    var workload: DecodeWorkload(Decoder) = .{
        .decoder = &decoder,
        .original = original,
        .recovery = recovery,
        .original_provided = case.original - loss,
        .recovery_provided = loss,
    };
    try runner.run(benchmark, &workload);
}

/// The default `Encoder` and `Decoder`. Decoding runs at 1% and 100% loss, where a loss of N%
/// drops N% of `min(original, recovery)` originals, rounded up.
fn benchmarks_main(runner: *bench.Runner) !void {
    const cases = runner.inputs.pick([]const Case, &smoke_cases, &main_cases, &main_cases);
    for (cases) |case| {
        try bench_encoder(runner, rs.Encoder, "reed_solomon::encoder", null, case);
    }
    for (cases) |case| {
        const max_loss = @min(case.original, case.recovery);
        for ([_]usize{ 1, 100 }) |loss_percent| {
            const loss = std.math.divCeil(usize, max_loss * loss_percent, 100) catch unreachable;
            const benchmark = case_name("reed_solomon::decoder", null, case)
                .with_param("loss", loss_percent);
            try bench_decoder(runner, rs.Decoder, benchmark, case, loss);
        }
    }
}

/// The high and low rate encoders and decoders with `DefaultEngine`. Each decoder loses
/// `min(original, recovery)` originals.
fn benchmarks_rate(runner: *bench.Runner) !void {
    const E = engine.DefaultEngine;
    const cases = runner.inputs.pick([]const Case, &smoke_cases, &rate_cases, &rate_cases);
    const label = "rate";
    for (cases) |case| {
        const prefix = "reed_solomon::high_rate_encoder";
        try bench_encoder(runner, rate.HighRateEncoder(E), prefix, label, case);
    }
    for (cases) |case| {
        const prefix = "reed_solomon::low_rate_encoder";
        try bench_encoder(runner, rate.LowRateEncoder(E), prefix, label, case);
    }
    for (cases) |case| {
        const benchmark = case_name("reed_solomon::high_rate_decoder", label, case);
        const loss = @min(case.original, case.recovery);
        try bench_decoder(runner, rate.HighRateDecoder(E), benchmark, case, loss);
    }
    for (cases) |case| {
        const benchmark = case_name("reed_solomon::low_rate_decoder", label, case);
        const loss = @min(case.original, case.recovery);
        try bench_decoder(runner, rate.LowRateDecoder(E), benchmark, case, loss);
    }
}

fn EvalPolyWorkload(comptime E: type) type {
    return struct {
        data: *[GF_ORDER]engine.GfElement,
        truncated_size: usize,

        pub fn iter(workload: *@This()) engine.GfElement {
            engine.eval_poly(E, workload.data, workload.truncated_size);
            return workload.data[0];
        }
    };
}

fn MulWorkload(comptime E: type) type {
    return struct {
        engine: E,
        x: []Chunk,

        pub fn iter(workload: *@This()) u8 {
            workload.engine.mul(workload.x, 12345);
            return workload.x[0][0];
        }
    };
}

fn TransformWorkload(comptime E: type, comptime inverse: bool) type {
    return struct {
        engine: E,
        shards: engine.ShardsRefMut,

        pub fn iter(workload: *@This()) u8 {
            const shards = workload.shards;
            if (inverse) {
                workload.engine.ifft(shards, 0, 128, 128, 128);
            } else {
                workload.engine.fft(shards, 0, 128, 128, 128);
            }
            return shards.get(0)[0][0];
        }
    };
}

/// Benchmarks `eval_poly`, `mul`, and 128-shard `fft` and `ifft` for engine `E`.
fn benchmarks_engine_one(runner: *bench.Runner, comptime E: type, name: []const u8) !void {
    const gpa = runner.allocator;
    const chunk_count = SHARD_BYTES / SHARD_CHUNK_BYTES;
    var rng: utils.rng.ChaCha8Rng = .init_key(@splat(0));
    const data = try gpa.create([GF_ORDER]engine.GfElement);
    defer gpa.destroy(data);
    for (data) |*element| element.* = @truncate(rng.next_u32());

    const eval_name = bench.Benchmark.init("reed_solomon::engine_eval_poly")
        .with_param("engine", name);
    var eval_full: EvalPolyWorkload(E) = .{ .data = data, .truncated_size = GF_ORDER };
    try runner.run(eval_name.with_param("elems", GF_ORDER), &eval_full);
    var eval_truncated: EvalPolyWorkload(E) = .{ .data = data, .truncated_size = GF_ORDER / 8 };
    const truncated_name = eval_name.with_param("elems", GF_ORDER / 8)
        .with_param("mode", "truncated");
    try runner.run(truncated_name, &eval_truncated);

    const eng: E = .init();
    const x = try generate_shards(gpa, 1, SHARD_BYTES, 0);
    defer free_shards(gpa, x);
    var mul: MulWorkload(E) = .{ .engine = eng, .x = std.mem.bytesAsSlice(Chunk, x[0]) };
    const mul_name = bench.Benchmark.init("reed_solomon::engine_mul").with_param("engine", name)
        .with_param("shard_bytes", SHARD_BYTES);
    try runner.run(mul_name, &mul);

    const shards_data = try generate_shards(gpa, 1, 128 * SHARD_BYTES, 0);
    defer free_shards(gpa, shards_data);
    const chunks = std.mem.bytesAsSlice(Chunk, shards_data[0]);
    const shards: engine.ShardsRefMut = .init(128, chunk_count, chunks);
    var fft: TransformWorkload(E, false) = .{ .engine = eng, .shards = shards };
    const fft_name = bench.Benchmark.init("reed_solomon::engine_fft").with_param("engine", name)
        .with_param("shards", 128);
    try runner.run(fft_name, &fft);
    var ifft: TransformWorkload(E, true) = .{ .engine = eng, .shards = shards };
    const ifft_name = bench.Benchmark.init("reed_solomon::engine_ifft").with_param("engine", name)
        .with_param("shards", 128);
    try runner.run(ifft_name, &ifft);
}

/// Benchmarks every engine available on the target.
fn benchmarks_engine(runner: *bench.Runner) !void {
    try benchmarks_engine_one(runner, engine.Naive, "naive");
    try benchmarks_engine_one(runner, engine.Scalar, "scalar");
    if (engine.Simd != engine.Scalar) {
        try benchmarks_engine_one(runner, engine.Simd, engine.simd_name);
    }
    if (engine.avx512_available) try benchmarks_engine_one(runner, engine.Avx512, "avx512");
}

pub fn run(runner: *bench.Runner) !void {
    try benchmarks_main(runner);
    try benchmarks_rate(runner);
    try benchmarks_engine(runner);
}
