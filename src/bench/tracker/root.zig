//! The benchmark tracker (commonware's `benchmark-tracker` binary, `bench/src/bin`): reads a
//! configuration of tracked benchmarks and their regression gates, compares a run's metrics
//! with a baseline, and writes `current.toml`, `comparison.toml`, `summary.toml`, and the
//! `comment.md` report.
//!
//! Commonware collects metrics by running Gungraun (callgrind) benches; that runner needs
//! valgrind and cargo, so it is not ported. The parsing of its JSON lines (`output.zig`) and
//! of the custom metric lines `bench.Benchmark.metrics_json` writes is, so results from either
//! source compare the same way.

const std = @import("std");

pub const toml = @import("toml.zig");
pub const config = @import("config.zig");
pub const Benchmark = config.Benchmark;
pub const Gate = config.Gate;
pub const Direction = config.Direction;
pub const load_config = config.load_config;
pub const tracked_labels = config.tracked_labels;
pub const callgrind_metrics = config.callgrind_metrics;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
}
