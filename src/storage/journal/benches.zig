//! Benchmarks of the journals (commonware `storage/src/journal/benches`, bench `journal`), one
//! file per commonware module under `benches/` (`read_random.zig` and `replay.zig` cover the
//! fixed and variable modules of the same name). They run on the production storage in a
//! temporary directory, as commonware's run on the tokio runtime.

const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
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
