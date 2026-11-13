//! Benchmarks of the cryptography package, one file per module (`zig build bench`).

const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
    try @import("reed_solomon/benches.zig").run(runner);
}
