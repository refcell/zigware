# bench

Abstract benchmark workloads.

A Zig port of commonware's
[`commonware-bench`](https://github.com/commonwarexyz/monorepo/tree/main/bench).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The bench backlog in [docs/lanes/parallel.md](../../docs/lanes/parallel.md) is done. The
tracker's runner is not ported.

## Modules

- `Benchmark`, `Inputs`, `Metric` ([root.zig](root.zig)): a benchmark's name and parameters,
  the smoke, standard, and full input sizes, and custom metrics written as JSON lines.
- `criterion` ([root.zig](root.zig)): times a workload over a given iteration count, like
  Criterion's `iter_custom`.
- `Runner` ([runner.zig](runner.zig)): measures workloads for `zig build bench`, runs each
  once for `zig build test`, and lists names.
- [main.zig](main.zig): the harness `zig build bench` and `zig build test` run once per
  package with a `src/<package>/benches.zig`.
- `tracker` ([tracker/root.zig](tracker/root.zig)): commonware's `benchmark-tracker` logic. It
  loads the tracking config, parses result lines, compares a run with a baseline, and writes
  the output files and report.

## Testing

```sh
zig build test-bench  # unit tests, tracker fixtures, and the seeded tracker parser fuzz
```

A `std.testing.fuzz` target drives the tracker parsers too; for long runs use
`zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

All of these are recorded in the
[parallel lane decisions](../../docs/lanes/parallel.md#decisions).

- There is no Criterion or Gungraun. `Runner` warms up by doubling, then takes 20 samples over
  about 1 s and prints the min, median, and max time per iteration.
- Harnesses are discovered by file, so a package adds benches without editing `build.zig`.
- The tracker's runner is not ported: it runs `cargo bench` under Gungraun and valgrind. Its
  config, output parsing, comparison, output files, and report are ported.
- The tracker reads a small TOML subset (no multi-line strings or dates) instead of using the
  `toml` crate. Config errors keep commonware's messages.
