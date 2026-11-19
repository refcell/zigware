//! Benchmarks of the storage package, one file per module (`zig build bench`).

const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
    try @import("archive/benches.zig").run(runner);
    try @import("bmt/benches.zig").run(runner);
    try @import("freezer/benches.zig").run(runner);
    try @import("index/benches.zig").run(runner);
    try @import("merkle/benches.zig").run(runner);
    try @import("journal/zstd_benches.zig").run(runner);
    try @import("journal/benches.zig").run(runner);
    try @import("metadata/benches.zig").run(runner);
    try @import("qmdb/benches/mod.zig").run(runner);
}
