//! Bitmap benchmarks (commonware `utils/src/bitmap/benches`): `BitMap` popcount and encoding,
//! and the roaring `Bitmap`'s `impl=ours` cases. The `impl=roaring-rs` cases measure an
//! external Rust crate and have no counterpart.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const codec = @import("codec");
const utils = @import("utils");

const Roaring = utils.bitmap.roaring.Bitmap;
const chunk_sizes = .{ 4, 8, 16, 32 };

pub fn run(runner: *bench.Runner) !void {
    try bench_count_ones(runner);
    try bench_write(runner);
    try bench_roaring_build(runner);
    try bench_roaring_queries(runner);
    try bench_roaring_sets(runner);
    try bench_roaring_write(runner);
}

// bitmap::count_ones, bitmap::write

fn CountOnesWorkload(comptime chunk: usize) type {
    return struct {
        bitmap: *const utils.bitmap.BitMap(chunk),

        pub fn iter(workload: *@This()) u64 {
            const bitmap = workload.bitmap;
            std.mem.doNotOptimizeAway(bitmap);
            return bitmap.count_ones();
        }
    };
}

fn bench_count_ones(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const all = [_]u64{ 64, 1 << 10, 1 << 14, 1 << 18, 1 << 22, 1 << 28 };
    const sizes = runner.inputs.pick([]const u64, &.{ 64, 1 << 10 }, &all, &all);
    for (sizes) |size| {
        inline for (chunk_sizes) |chunk| {
            var rng = utils.rng.TestRng.init(size);
            var bitmap: utils.bitmap.BitMap(chunk) = .empty;
            defer bitmap.deinit(gpa);
            for (0..size) |_| try bitmap.push(gpa, utils.rng.boolean(&rng));
            var workload: CountOnesWorkload(chunk) = .{ .bitmap = &bitmap };
            const name = bench.Benchmark.init("bitmap::count_ones").with_param("size", size)
                .with_param("chunk_size", chunk);
            try runner.run(name, &workload);
        }
    }
}

/// Encodes `value` into one reused buffer, measuring the encoder rather than the allocator.
fn WriteWorkload(comptime T: type) type {
    return struct {
        value: *const T,
        buffer: []u8,

        pub fn iter(workload: *@This()) usize {
            var writer: codec.Writer = .init(workload.buffer);
            workload.value.write(&writer);
            assert(writer.end == workload.buffer.len);
            return writer.end;
        }
    };
}

fn bench_write(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const all = [_]u64{ 64, 1 << 10, 1 << 14, 1 << 18, 1 << 22, 1 << 26 };
    const sizes = runner.inputs.pick([]const u64, &.{ 64, 1 << 10 }, &all, &all);
    for (sizes) |size| {
        inline for (chunk_sizes) |chunk| {
            const BitMap = utils.bitmap.BitMap(chunk);
            var bitmap = try BitMap.ones(gpa, size);
            defer bitmap.deinit(gpa);
            const buffer = try gpa.alloc(u8, bitmap.encode_size());
            defer gpa.free(buffer);
            var workload: WriteWorkload(BitMap) = .{ .value = &bitmap, .buffer = buffer };
            const name = bench.Benchmark.init("bitmap::write").with_param("size", size)
                .with_param("chunk_size", chunk);
            try runner.run(name, &workload);
        }
    }
}

// bitmap::roaring_{insert,insert_range,contains,iteration,union,intersection,difference,write}

fn roaring_name(comptime prefix: []const u8, count: u64) bench.Benchmark {
    return bench.Benchmark.init("bitmap::" ++ prefix).with_param("count", count)
        .with_param("impl", "ours");
}

/// Builds a fresh bitmap each iteration: `count` multiples of 7, or the range `0..count`.
const BuildWorkload = struct {
    gpa: Allocator,
    count: u64,
    range: bool,

    pub fn iter(workload: *BuildWorkload) !u64 {
        var bitmap: Roaring = .empty;
        defer bitmap.deinit(workload.gpa);
        if (workload.range) {
            _ = try bitmap.insert_range(workload.gpa, 0, workload.count);
        } else {
            for (0..workload.count) |i| _ = try bitmap.insert(workload.gpa, i * 7);
        }
        assert(bitmap.len() == workload.count);
        return bitmap.len();
    }
};

fn bench_roaring_build(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const insert_counts = runner.inputs.pick([]const u64, &.{100}, &.{ 100, 1000, 10000 }, &.{
        100, 1000, 10000,
    });
    for (insert_counts) |count| {
        var workload: BuildWorkload = .{ .gpa = gpa, .count = count, .range = false };
        try runner.run(roaring_name("roaring_insert", count), &workload);
    }
    for (query_counts(runner)) |count| {
        var workload: BuildWorkload = .{ .gpa = gpa, .count = count, .range = true };
        try runner.run(roaring_name("roaring_insert_range", count), &workload);
    }
}

fn query_counts(runner: *bench.Runner) []const u64 {
    return runner.inputs.pick([]const u64, &.{1000}, &.{ 1000, 10000, 100000 }, &.{
        1000, 10000, 100000,
    });
}

fn multiples(gpa: Allocator, count: u64, step: u64) !Roaring {
    var bitmap: Roaring = .empty;
    errdefer bitmap.deinit(gpa);
    for (0..count) |i| _ = try bitmap.insert(gpa, i * step);
    assert(bitmap.len() == count);
    return bitmap;
}

/// Looks up every multiple of 3 in a bitmap of them, or counts a bitmap of multiples of 7.
const QueryWorkload = struct {
    bitmap: *const Roaring,
    count: u64,
    iterate: bool,

    pub fn iter(workload: *QueryWorkload) u64 {
        var found: u64 = 0;
        if (workload.iterate) {
            var it = workload.bitmap.iter();
            while (it.next()) |_| found += 1;
        } else {
            for (0..workload.count) |i| {
                if (workload.bitmap.contains(i * 3)) found += 1;
            }
        }
        assert(found == workload.count);
        return found;
    }
};

fn bench_roaring_queries(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    for (query_counts(runner)) |count| {
        var threes = try multiples(gpa, count, 3);
        defer threes.deinit(gpa);
        var contains: QueryWorkload = .{ .bitmap = &threes, .count = count, .iterate = false };
        try runner.run(roaring_name("roaring_contains", count), &contains);
    }
    for (query_counts(runner)) |count| {
        var sevens = try multiples(gpa, count, 7);
        defer sevens.deinit(gpa);
        var iteration: QueryWorkload = .{ .bitmap = &sevens, .count = count, .iterate = true };
        try runner.run(roaring_name("roaring_iteration", count), &iteration);
    }
}

const SetOp = enum { @"union", intersection, difference };

/// One set operation on the multiples of 2 and of 3, unlimited.
const SetWorkload = struct {
    gpa: Allocator,
    a: *const Roaring,
    b: *const Roaring,
    op: SetOp,

    pub fn iter(workload: *SetWorkload) !u64 {
        const limit = std.math.maxInt(u64);
        var result = switch (workload.op) {
            .@"union" => try workload.a.@"union"(workload.b, workload.gpa, limit),
            .intersection => try workload.a.intersection(workload.b, workload.gpa, limit),
            .difference => try workload.a.difference(workload.b, workload.gpa, limit),
        };
        defer result.deinit(workload.gpa);
        return result.len();
    }
};

fn bench_roaring_sets(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const counts = runner.inputs.pick([]const u64, &.{1000}, &.{ 1000, 10000 }, &.{
        1000, 10000,
    });
    inline for (.{ SetOp.@"union", SetOp.intersection, SetOp.difference }) |op| {
        for (counts) |count| {
            var twos = try multiples(gpa, count, 2);
            defer twos.deinit(gpa);
            var threes = try multiples(gpa, count, 3);
            defer threes.deinit(gpa);
            var workload: SetWorkload = .{ .gpa = gpa, .a = &twos, .b = &threes, .op = op };
            try runner.run(roaring_name("roaring_" ++ @tagName(op), count), &workload);
        }
    }
}

/// `containers` containers of 5000 alternating values each.
fn alternating(gpa: Allocator, containers: u64) !Roaring {
    var bitmap: Roaring = .empty;
    errdefer bitmap.deinit(gpa);
    for (0..containers) |key| {
        const base = key << 16;
        for (0..5000) |i| _ = try bitmap.insert(gpa, base + i * 2);
    }
    assert(bitmap.len() == containers * 5000);
    return bitmap;
}

fn bench_roaring_write(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const counts = runner.inputs.pick([]const u64, &.{1}, &.{ 1, 16, 64 }, &.{ 1, 16, 64 });
    for (counts) |containers| {
        var bitmap = try alternating(gpa, containers);
        defer bitmap.deinit(gpa);
        const buffer = try gpa.alloc(u8, bitmap.encode_size());
        defer gpa.free(buffer);
        var workload: WriteWorkload(Roaring) = .{ .value = &bitmap, .buffer = buffer };
        const name = bench.Benchmark.init("bitmap::roaring_write")
            .with_param("containers", containers).with_param("shape", "bitmap");
        try runner.run(name, &workload);
    }
}
