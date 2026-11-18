//! Benchmarks of the cryptography package, one file per module (`zig build bench`).

const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
    try @import("reed_solomon/benches.zig").run(runner);
    try @import("bls12381/benches.zig").run(runner);
    try @import("benches/hashes.zig").run(runner);
    try @import("benches/signatures.zig").run(runner);
    try @import("benches/primitives.zig").run(runner);
}
