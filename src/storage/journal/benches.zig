//! Benchmarks of the journals (commonware `storage/src/journal/benches`, bench `journal`), one
//! file per commonware module under `benches/` (`read_random.zig` and `replay.zig` cover the
//! fixed and variable modules of the same name). They run on the production storage in a
//! temporary directory, as commonware's run on the tokio runtime.

const std = @import("std");
const assert = std.debug.assert;
const allocator = @import("allocator");
const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
    // commonware's journal bench installs mimalloc with its default configuration as the
    // global allocator (`benches/bench.rs`); `Heap` is the port, so allocation-heavy paths
    // (prepared batches, replay buffers) pay what they pay there. The smoke run under
    // `zig build test` keeps the leak-checking test allocator.
    var heap = allocator.Heap.init(runner.io, .default);
    defer heap.deinit();
    const outer = runner.allocator;
    if (runner.inputs != .smoke) runner.allocator = heap.allocator();
    defer runner.allocator = outer;
    assert((runner.inputs == .smoke) == (runner.allocator.ptr == outer.ptr));
    try @import("benches/append_sync.zig").run(runner);
    try @import("benches/fixed_append.zig").run(runner);
    try @import("benches/fixed_append_buffered.zig").run(runner);
    try @import("benches/read_random.zig").run(runner);
    try @import("benches/fixed_read_sequential.zig").run(runner);
    try @import("benches/replay.zig").run(runner);
    try @import("benches/read_cached.zig").run(runner);
    try @import("benches/segmented_variable_append_buffered.zig").run(runner);
    try @import("benches/variable_prepare_append.zig").run(runner);
    try @import("benches/variable_read_compressed.zig").run(runner);
}
