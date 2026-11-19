//! `journal::fixed_append`: appending random items to a fresh fixed journal, then syncing.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

const partition = "test-partition";
const items_per_blob: u64 = 10_000;
/// Keep enough records in one blob to repeatedly cross the 1 MiB write buffer.
const large_items_per_blob: u64 = 1_000_000;
const item_size = 32;

const Case = struct { items: u64, items_per_blob: u64 };

const cases_standard = [_]Case{
    .{ .items = 1_000, .items_per_blob = items_per_blob },
    .{ .items = 10_000, .items_per_blob = items_per_blob },
    .{ .items = 100_000, .items_per_blob = items_per_blob },
    .{ .items = 1_000_000, .items_per_blob = items_per_blob },
    .{ .items = 100_000, .items_per_blob = large_items_per_blob },
    .{ .items = 1_000_000, .items_per_blob = large_items_per_blob },
};
const cases_smoke = [_]Case{
    .{ .items = 1_000, .items_per_blob = items_per_blob },
    .{ .items = 1_000, .items_per_blob = large_items_per_blob },
};

pub fn run(runner: *bench.Runner) !void {
    const cases = runner.inputs.pick([]const Case, &cases_smoke, &cases_standard, &cases_standard);
    for (cases) |case| {
        var benchmark = bench.Benchmark.init("journal::fixed_append")
            .with_param("items", case.items)
            .with_param("size", item_size);
        if (case.items_per_blob != items_per_blob) {
            benchmark = benchmark.with_param("items_per_blob", case.items_per_blob);
        }
        if (!runner.matches(benchmark.name())) continue;
        var workload: Append = .{
            .gpa = runner.allocator,
            .io = runner.io,
            .inputs = runner.inputs,
            .case = case,
        };
        try runner.run(benchmark, &workload);
    }
}

/// Each iteration opens a fresh journal (untimed), then appends and syncs (timed); the next
/// iteration destroys it first.
const Append = struct {
    gpa: Allocator,
    io: std.Io,
    inputs: bench.Inputs,
    case: Case,
    disk: common.Disk = undefined,
    cache_ref: common.CacheRef = undefined,
    journal: ?common.FixedJournal(item_size) = null,

    pub fn setup(workload: *Append) !void {
        assert(workload.journal == null);
        try workload.disk.init(workload.io, workload.gpa, "fixed-append", workload.inputs);
        const cache = common.CacheRef.init(workload.gpa, common.page_size, common.page_cache_size);
        workload.cache_ref = cache catch |err| {
            workload.disk.deinit();
            return err;
        };
    }

    pub fn before_iter(workload: *Append) !void {
        try workload.destroy();
        workload.journal = try common.open_fixed(
            item_size,
            workload.gpa,
            &workload.disk,
            &workload.cache_ref,
            partition,
            workload.case.items_per_blob,
        );
        assert(workload.journal.?.size() == 0);
    }

    pub fn iter(workload: *Append) !u64 {
        const journal = &workload.journal.?;
        try common.append_random(journal, item_size, workload.case.items);
        return journal.size();
    }

    pub fn teardown(workload: *Append) !void {
        defer workload.disk.deinit();
        defer workload.cache_ref.deinit();
        try workload.destroy();
    }

    fn destroy(workload: *Append) !void {
        var journal = workload.journal orelse return;
        workload.journal = null;
        try journal.destroy();
        assert(workload.journal == null);
    }
};
