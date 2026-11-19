//! `journal::append_sync`: steady-state cost of appending one item and making it durable.
//! `commit` makes items durable without updating the checkpoint, so it is a control. Syncs
//! here complete synchronously, so `start_sync` has no handle to await.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

const partition = "append-sync-partition";
const item_size = 256;
/// Items per blob or section, so steady state includes starting new ones.
const items_per_blob: u64 = 64;

const Kind = enum { fixed, variable };
const Mode = enum { sync, start_sync, commit };

pub fn run(runner: *bench.Runner) !void {
    inline for (.{ Kind.fixed, Kind.variable }) |kind| {
        for ([_]Mode{ .sync, .start_sync, .commit }) |mode| {
            const benchmark = bench.Benchmark.init("journal::append_sync")
                .with_param("journal", kind)
                .with_param("mode", mode);
            var workload: Cycle(kind) = .{
                .gpa = runner.allocator,
                .io = runner.io,
                .inputs = runner.inputs,
                .mode = mode,
            };
            try runner.run(benchmark, &workload);
        }
    }
}

fn Cycle(comptime kind: Kind) type {
    const J = switch (kind) {
        .fixed => common.FixedJournal(item_size),
        .variable => common.VariableJournal(item_size),
    };
    return struct {
        const Self = @This();
        const item: [item_size]u8 = @splat(0xAB);

        gpa: Allocator,
        io: std.Io,
        inputs: bench.Inputs,
        mode: Mode,
        disk: common.Disk = undefined,
        cache_ref: common.CacheRef = undefined,
        journal: J = undefined,

        /// Open the journal and populate both copies of its checkpoint.
        pub fn setup(self: *Self) !void {
            try self.disk.init(self.io, self.gpa, "append-sync", self.inputs);
            errdefer self.disk.deinit();
            self.cache_ref = try .init(self.gpa, common.page_size, common.page_cache_size);
            errdefer self.cache_ref.deinit();
            const open = switch (kind) {
                .fixed => common.open_fixed,
                .variable => common.open_variable,
            };
            self.journal = try open(
                item_size,
                self.gpa,
                &self.disk,
                &self.cache_ref,
                partition,
                items_per_blob,
            );
            errdefer self.journal.deinit();
            for (0..2) |_| _ = try self.iter();
            assert(self.journal.size() == 2);
        }

        pub fn iter(self: *Self) !u64 {
            const position = try self.journal.append(item);
            switch (self.mode) {
                .sync => try self.journal.sync(),
                .start_sync => try self.journal.start_sync(),
                .commit => try self.journal.commit(),
            }
            assert(position + 1 == self.journal.size());
            return position;
        }

        pub fn teardown(self: *Self) !void {
            defer self.disk.deinit();
            defer self.cache_ref.deinit();
            try self.journal.destroy();
        }
    };
}
