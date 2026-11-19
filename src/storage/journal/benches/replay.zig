//! `journal::fixed_replay` and `journal::variable_replay`: replaying every item of a journal
//! populated once per item count, with uncached reads first because cached replays leave
//! pages resident (as commonware orders them).

const std = @import("std");
const assert = std.debug.assert;
const bench = @import("bench");
const common = @import("common.zig");

const item_size = 32;
/// commonware's crate-level `ITEMS_PER_BLOB`.
const items_per_blob: u64 = 100_000;

const Kind = enum { fixed, variable };

const Options = struct { read_options: common.ReadOptions, label: []const u8 };
const options_all = [_]Options{
    .{ .read_options = .{ .dont_cache = true }, .label = "dont_cache" },
    .{ .read_options = .{}, .label = "cache" },
};
const buffers = [_]usize{ 16_384, 65_536, 1_048_576 };
const item_counts = [_]u64{ 1_000, 10_000, 100_000, 500_000 };

pub fn run(runner: *bench.Runner) !void {
    // commonware smoke-tests every count; unoptimized builds take seconds on the larger ones.
    const counts = runner.inputs.pick([]const u64, item_counts[0..1], &item_counts, &item_counts);
    for (counts) |items| try run_items(runner, .fixed, items);
    for (counts) |items| try run_items(runner, .variable, items);
}

fn benchmark_of(kind: Kind, items: u64, buffer: usize, options: Options) bench.Benchmark {
    const name = switch (kind) {
        .fixed => "journal::fixed_replay",
        .variable => "journal::variable_replay",
    };
    return bench.Benchmark.init(name)
        .with_param("items", items)
        .with_param("buffer", buffer)
        .with_param("size", item_size)
        .with_param("read_options", options.label);
}

fn run_items(runner: *bench.Runner, comptime kind: Kind, items: u64) !void {
    var any = false;
    for (options_all) |options| {
        for (buffers) |buffer| {
            any = any or runner.matches(benchmark_of(kind, items, buffer, options).name());
        }
    }
    if (!any) return;

    const gpa = runner.allocator;
    var disk: common.Disk = undefined;
    try disk.init(runner.io, gpa, "replay", runner.inputs);
    defer disk.deinit();
    var cache_ref = try common.CacheRef.init(gpa, common.page_size, common.page_cache_size);
    defer cache_ref.deinit();
    var journal = switch (kind) {
        .fixed => try common.open_fixed(
            item_size,
            gpa,
            &disk,
            &cache_ref,
            "test-partition",
            items_per_blob,
        ),
        .variable => try common.open_variable(
            item_size,
            gpa,
            &disk,
            &cache_ref,
            "variable-test-partition",
            items_per_blob,
        ),
    };
    var destroyed = false;
    defer if (!destroyed) journal.deinit();
    try common.append_random(&journal, item_size, items);

    for (options_all) |options| {
        for (buffers) |buffer| {
            var workload: Replay(@TypeOf(journal)) = .{
                .journal = &journal,
                .buffer = buffer,
                .read_options = options.read_options,
            };
            try runner.run(benchmark_of(kind, items, buffer, options), &workload);
        }
    }
    destroyed = true;
    try journal.destroy();
}

fn Replay(comptime J: type) type {
    return struct {
        const Self = @This();

        journal: *J,
        buffer: usize,
        read_options: common.ReadOptions,

        pub fn iter(self: *Self) !u64 {
            const bounds = self.journal.get_bounds();
            var replay = try self.journal.replay_options(bounds, self.buffer, self.read_options);
            defer replay.deinit();
            const seen = try common.drain(&replay);
            assert(seen == bounds.end - bounds.start);
            return seen;
        }
    };
}
