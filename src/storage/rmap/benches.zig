//! Benchmark of the range map (commonware `storage/src/rmap/benches`): `insert` adds the
//! values `0..items` in a fresh random order to an empty map. The shuffle and the map's
//! teardown are untimed, as in commonware's `iter_custom`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const support = @import("../bench_support.zig");

const RMap = storage.rmap.RMap;

const InsertWorkload = struct {
    gpa: Allocator,
    indices: []u64,
    rng: utils.TestRng,
    map: RMap = .empty,

    pub fn before_iter(self: *InsertWorkload) void {
        self.map.deinit(self.gpa);
        self.map = .empty;
        runtime.rng.shuffle(&self.rng, u64, self.indices);
    }

    pub fn iter(self: *InsertWorkload) !usize {
        for (self.indices) |index| try self.map.insert(self.gpa, index);
        // Every value of `0..items` is present, so the map is one range.
        assert(self.map.count() == 1);
        return self.map.count();
    }

    pub fn teardown(self: *InsertWorkload) void {
        self.map.deinit(self.gpa);
        self.map = .empty;
    }
};

pub fn run(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const all = [_]usize{ 10_000, 50_000, 100_000, 500_000, 1_000_000 };
    for (support.cases(usize, runner, &all, 1)) |items| {
        const indices = try gpa.alloc(u64, items);
        defer gpa.free(indices);
        for (indices, 0..) |*index, value| index.* = value;
        var workload: InsertWorkload = .{ .gpa = gpa, .indices = indices, .rng = .init(0) };
        defer workload.teardown();
        try runner.run(bench.Benchmark.init("rmap::insert").with_param("items", items), &workload);
    }
}
