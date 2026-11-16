//! glue's benchmarks: transfers' CPU stages (commonware `glue/src/transfers/benches`).

const bench = @import("bench");

pub fn run(runner: *bench.Runner) !void {
    try @import("transfers/benches.zig").run(runner);
}
