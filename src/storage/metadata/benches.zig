//! Benchmarks of the metadata store (commonware `storage/src/metadata/benches`, bench
//! `metadata`), one file per commonware module under `benches/`.

const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
    try @import("benches/sync.zig").run(runner);
    try @import("benches/overwrite.zig").run(runner);
    try @import("benches/restart.zig").run(runner);
}
