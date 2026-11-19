//! Benchmarks of the QMDB databases (commonware `storage/src/qmdb/benches`), one file per
//! commonware bench, with commonware's names, constants, and workloads. They run over the
//! production disk storage, as commonware's tokio runtime does; smoke inputs use the in-memory
//! storage. This lane ports the `any`, `immutable`, `keyless`, and `store` variants;
//! storage-qmdb-sync adds `current` (docs/lanes/storage-qmdb.md).

const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
    try @import("generate.zig").run(runner);
    try @import("init.zig").run(runner);
    try @import("apply_batch.zig").run(runner);
    try @import("merkleize.zig").run(runner);
    try @import("chained_growth.zig").run(runner);
}
