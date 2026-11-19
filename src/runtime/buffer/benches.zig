//! Benchmarks of the page cache through its `Writer` (commonware
//! `runtime/src/utils/buffer/benches`, bench `buffer_paged`), one file per commonware module
//! under `benches/`, on the deterministic and production storage.

const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
    try @import("benches/append.zig").run(runner);
    try @import("benches/read.zig").run(runner);
    try @import("benches/sync.zig").run(runner);
}
