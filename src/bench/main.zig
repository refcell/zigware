//! The benchmark harness `zig build bench` and `zig build test` run, once per package with a
//! `src/<package>/benches.zig` (imported here as `benches`).
//!
//! Arguments follow Criterion: `--bench` measures, `--test` or no `--bench` runs every
//! benchmark once on the smoke inputs, `--list` lists names, and other non-flag arguments
//! (or any after `--`) are name filters. `--warm-up-ms N`, `--measurement-ms N`, and
//! `--samples N` tune measurement. `COMMONWARE_BENCH_FULL=1` selects the full inputs, and
//! `COMMONWARE_BENCH_METRICS_PATH` names a JSONL file custom metrics are appended to.

const std = @import("std");
const allocator = @import("allocator");
const bench = @import("bench");
const benches = @import("benches");

/// Measured builds run on `allocator.Heap` (mimalloc's layout and default config), as every
/// commonware bench binary sets `mimalloc::MiMalloc` with `Config::DEFAULT` as its global
/// allocator. Safety-checked builds (the smoke runs in `zig build test`) keep `init.gpa`, which
/// checks for leaks.
const measured_heap = !std.debug.runtime_safety;

const filters_max = 64;

const Parsed = struct {
    filters: [filters_max][]const u8 = undefined,
    filters_len: usize = 0,
    list: bool = false,
    config: bench.RunnerConfig = .{},
};

fn parse_number(arg: ?[]const u8) !u64 {
    const text = arg orelse return error.MissingValue;
    return std.fmt.parseInt(u64, text, 10);
}

fn parse(args: []const []const u8) !Parsed {
    var parsed: Parsed = .{};
    var index: usize = 0;
    var filters_only = false;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        const next = if (index + 1 < args.len) args[index + 1] else null;
        if (!filters_only and std.mem.eql(u8, arg, "--")) {
            filters_only = true;
        } else if (!filters_only and std.mem.eql(u8, arg, "--list")) {
            parsed.list = true;
        } else if (!filters_only and std.mem.eql(u8, arg, "--warm-up-ms")) {
            parsed.config.warm_up_ns = try parse_number(next) * std.time.ns_per_ms;
            index += 1;
        } else if (!filters_only and std.mem.eql(u8, arg, "--measurement-ms")) {
            parsed.config.measurement_ns = try parse_number(next) * std.time.ns_per_ms;
            index += 1;
        } else if (!filters_only and std.mem.eql(u8, arg, "--samples")) {
            const samples = try parse_number(next);
            if (samples == 0 or samples > bench.runner_module.samples_max) return error.Samples;
            parsed.config.samples = @intCast(samples);
            index += 1;
        } else if (filters_only or !std.mem.startsWith(u8, arg, "--")) {
            if (parsed.filters_len == filters_max) return error.TooManyFilters;
            parsed.filters[parsed.filters_len] = arg;
            parsed.filters_len += 1;
        }
    }
    return parsed;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const all_args = try init.minimal.args.toSlice(init.arena.allocator());
    const args: []const []const u8 = @ptrCast(all_args[@min(all_args.len, 1)..]);
    const parsed = try parse(args);

    var out_buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &out_buffer);

    var metrics_file: ?std.Io.File = null;
    defer if (metrics_file) |file| file.close(io);
    var metrics_buffer: [4096]u8 = undefined;
    var metrics_writer: std.Io.File.Writer = undefined;
    if (init.environ_map.get(bench.metrics_path_env)) |path| {
        const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false });
        metrics_file = file;
        metrics_writer = file.writer(io, &metrics_buffer);
        try metrics_writer.seekTo(try file.length(io));
    }

    var heap: allocator.Heap = if (measured_heap) .init(io, .default) else undefined;
    defer if (measured_heap) heap.deinit();
    const gpa = if (measured_heap) heap.allocator() else init.gpa;
    var runner: bench.Runner = .{
        .io = io,
        .allocator = gpa,
        .out = &out.interface,
        .inputs = bench.Inputs.current(args, init.environ_map.get(bench.full_env)),
        .filters = parsed.filters[0..parsed.filters_len],
        .list = parsed.list,
        .config = parsed.config,
        .metrics_out = if (metrics_file != null) &metrics_writer.interface else null,
    };
    try benches.run(&runner);
    try out.interface.flush();
}
