//! Benchmarks of hex encoding, decoding, and display (commonware `formatting/src/benches`),
//! with commonware's names and sizes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const formatting = @import("formatting");

const sizes = [_]usize{ 16, 32, 64, 256, 1024, 16 * 1024 };

/// `size` random bytes, seeded by `size` as commonware seeds each size; the caller frees.
fn random_bytes(gpa: Allocator, size: usize) ![]u8 {
    assert(size > 0);
    var prng: std.Random.DefaultPrng = .init(size);
    const bytes = try gpa.alloc(u8, size);
    prng.random().bytes(bytes);
    return bytes;
}

/// `hex` with whitespace injected before every 8th character after the first, behind
/// `prefix`; the caller frees.
fn ugly(gpa: Allocator, hex: []const u8, prefix: []const u8) ![]u8 {
    assert(hex.len > 0);
    const out = try gpa.alloc(u8, prefix.len + hex.len + (hex.len - 1) / 8);
    @memcpy(out[0..prefix.len], prefix);
    var len = prefix.len;
    for (hex, 0..) |char, index| {
        if (index > 0 and index % 8 == 0) {
            out[len] = ' ';
            len += 1;
        }
        out[len] = char;
        len += 1;
    }
    assert(len == out.len);
    return out;
}

const EncodeWorkload = struct {
    gpa: Allocator,
    bytes: []const u8,

    pub fn iter(workload: *EncodeWorkload) !usize {
        const hex = try formatting.hex(workload.gpa, workload.bytes);
        defer workload.gpa.free(hex);
        assert(hex.len == 2 * workload.bytes.len);
        return hex.len;
    }
};

/// Decodes the inputs in turn: one pristine input, or the `0x` and `0X` ugly inputs
/// alternately to exercise both prefix-stripping paths.
const DecodeWorkload = struct {
    gpa: Allocator,
    inputs: []const []const u8,
    next: usize = 0,

    pub fn iter(workload: *DecodeWorkload) !usize {
        assert(workload.next < workload.inputs.len);
        const input = workload.inputs[workload.next];
        workload.next = (workload.next + 1) % workload.inputs.len;
        const bytes = (try formatting.from_hex(workload.gpa, input)).?;
        defer workload.gpa.free(bytes);
        assert(bytes.len > 0);
        return bytes.len;
    }
};

/// Formats `Hex` into one reused buffer, measuring the formatter rather than the allocator.
const DisplayWorkload = struct {
    bytes: []const u8,
    out: []u8,

    pub fn iter(workload: *DisplayWorkload) !usize {
        var writer: std.Io.Writer = .fixed(workload.out);
        try writer.print("{f}", .{formatting.fmt_hex(workload.bytes)});
        assert(writer.end == 2 * workload.bytes.len);
        return writer.end;
    }
};

fn bench_size(runner: *bench.Runner, size: usize) !void {
    const gpa = runner.allocator;
    const bytes = try random_bytes(gpa, size);
    defer gpa.free(bytes);

    var encode: EncodeWorkload = .{ .gpa = gpa, .bytes = bytes };
    try runner.run(bench.Benchmark.init("formatting::encode").with_param("size", size), &encode);

    const pristine = try formatting.hex(gpa, bytes);
    defer gpa.free(pristine);
    const ugly_lower = try ugly(gpa, pristine, "0x");
    defer gpa.free(ugly_lower);
    const ugly_upper = try ugly(gpa, pristine, "0X");
    defer gpa.free(ugly_upper);
    const decode_name = bench.Benchmark.init("formatting::decode");
    var decode_pristine: DecodeWorkload = .{ .gpa = gpa, .inputs = &.{pristine} };
    const pristine_name = decode_name.with_param("input", "pristine").with_param("size", size);
    try runner.run(pristine_name, &decode_pristine);
    var decode_ugly: DecodeWorkload = .{ .gpa = gpa, .inputs = &.{ ugly_lower, ugly_upper } };
    const ugly_name = decode_name.with_param("input", "ugly").with_param("size", size);
    try runner.run(ugly_name, &decode_ugly);

    const out = try gpa.alloc(u8, 2 * size);
    defer gpa.free(out);
    var display: DisplayWorkload = .{ .bytes = bytes, .out = out };
    const display_name = bench.Benchmark.init("formatting::display").with_param("size", size);
    try runner.run(display_name, &display);
}

pub fn run(runner: *bench.Runner) !void {
    for (runner.inputs.pick([]const usize, sizes[0..1], &sizes, &sizes)) |size| {
        try bench_size(runner, size);
    }
}
