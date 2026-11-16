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
pub const output = @import("output.zig");
pub const Metrics = output.Metrics;
pub const parse_lines = output.parse_lines;
pub const custom_metrics = output.custom_metrics;
pub const results = @import("results.zig");
pub const BenchResult = results.BenchResult;
pub const Comparison = results.Comparison;
pub const compare = results.compare;
pub const load_baseline = results.load_baseline;
pub const write_outputs = results.write_outputs;
pub const render = @import("render.zig");
pub const render_report = render.render_report;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
    _ = @import("results_tests.zig");
}
