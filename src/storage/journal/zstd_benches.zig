//! Benchmarks of the journal's zstd encoder: compressing sample text and journal-like records
//! with match finding (`compress`) against the raw-block path it replaced (`store`). Each run
//! reports `frame_bytes` and `ratio_permille` (frame size per thousand input bytes); the
//! input size over the time per iteration is the throughput.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const storage = @import("storage");

const zstd = storage.journal.zstd;

const Kind = enum { text, records };

const EncodeWorkload = struct {
    gpa: Allocator,
    data: []const u8,
    mode: zstd.Mode,
    out: std.ArrayList(u8) = .empty,
    frame_bytes: usize = 0,

    pub fn iter(workload: *EncodeWorkload) !usize {
        workload.out.clearRetainingCapacity();
        const data = workload.data;
        const frame = try zstd.encode_into(workload.gpa, data, &workload.out, workload.mode);
        workload.frame_bytes = frame.len;
        assert(frame.len <= zstd.compress_bound(workload.data.len));
        return frame.len;
    }

    pub fn metrics(workload: *const EncodeWorkload, buffer: []bench.Metric) []const bench.Metric {
        assert(buffer.len >= 2);
        assert(workload.data.len > 0);
        buffer[0] = .init("frame_bytes", workload.frame_bytes);
        buffer[1] = .init("ratio_permille", workload.frame_bytes * 1000 / workload.data.len);
        return buffer[0..2];
    }
};

pub fn run(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const usize,
        &.{1_000},
        &.{ 1_000, 64_000, 1_000_000 },
        &.{ 1_000, 64_000, 1_000_000, 16_000_000 },
    );
    for (sizes) |size| {
        const data = try gpa.alloc(u8, size);
        defer gpa.free(data);
        for ([_]Kind{ .text, .records }) |kind| {
            var prng = std.Random.DefaultPrng.init(0x7a737464);
            switch (kind) {
                .text => zstd.corpus.text(prng.random(), data),
                .records => zstd.corpus.records(prng.random(), data),
            }
            for ([_]zstd.Mode{ .store, .compress }) |mode| {
                const benchmark = bench.Benchmark.init("journal::zstd::encode")
                    .with_param("mode", mode)
                    .with_param("data", kind)
                    .with_param("bytes", size);
                var workload: EncodeWorkload = .{ .gpa = gpa, .data = data, .mode = mode };
                defer workload.out.deinit(gpa);
                try runner.run(benchmark, &workload);
            }
        }
    }
}
