# Lane: examples-estimator

Owns `examples/estimator/` and its entry in `build.zig`'s `examples` list. The estimator is
zigware's first runnable example and the first README demo.

Reference: `~/.cache/zigware/commonware-ref/examples/estimator` (lib.rs, main.rs, p50/p90
latency JSON, the `.lazy` task files). It simulates a mechanism described in the `.lazy`
DSL (propose, broadcast, reply, wait/collect thresholds, AND/OR) on peers spread across AWS
regions with real region-to-region latencies, in virtual time on the deterministic runtime,
and prints latency statistics. It needs p2p's `simulated` network (`Oracle`, links with
latency and jitter, `Recipients`); the p2p lane is landing it now. Until then, build
everything that does not need it (DSL parser, region/latency tables, distribution parsing,
statistics, output, CLI) and run against a minimal in-lane stand-in, then switch.

## Decisions
- `rust.zig` reproduces the Rust std behavior the output depends on: `{:.2}` (exact decimal,
  ties to even; Zig's `{d:.2}` differs on values like 0.125), `Duration::from_secs_f64`,
  `str::lines`, and `parse::<f64/u32>` with their error kinds.
- Commands are stored in postfix order and parsed with an explicit operator stack (no
  recursion). Leaves are evaluated left to right, as commonware's recursive evaluation does.
- Where commonware panics, the estimator prints `error: <commonware's panic message>` and
  exits 101. clap's help, version, and usage errors are reproduced as text with exit code 2.
- Statistics agree with commonware in distribution, not sample for sample (coordinator
  decision): the scheduler consumes the RNG in a different order. `simulate_test.zig` checks
  means and medians against a captured commonware run, with tolerances.
- `--version` prints the build's `version` option (`0.0.0` today), not commonware's crate
  version.
- `--reload` is not supported (no HTTP client in-lane); it fails with a clear message.

## Backlog
- [x] `.lazy` DSL parser and task model, with lib.rs's parser tests. Copy the `.lazy` files and
  p50/p90 latency data into `examples/estimator/` (they are public data in the repo).
- [x] CLI (`<TASK> --distribution region:count[:bandwidth],... --reload-latencies` etc. as in
  main.rs), statistics (mean, median, std dev per proposer and averaged), output format
  matching commonware's.
- [x] Simulation on `runtime.deterministic.Runner` and `p2p.simulated`: same seed, same
  output. `zig build run-estimator -- examples/estimator/simplex.lazy --distribution ...`.
- [ ] Every `.lazy` file in the reference runs; port main.rs/lib.rs tests. (lib.rs tests,
  `accepts_config`, and `validate` over every file are ported; next, an end-to-end run of
  each file.)
- [x] A short `examples/estimator/README.md` with the commands the README demo uses.

- [ ] `--reload`: fetch cloudping.co through the runtime's network.

## Log
- 2026-11-13: DSL parser, latency data, statistics, clap-identical CLI, colored output, and
  the simulation on runtime.deterministic + p2p.simulated. `zig build run-estimator` works.
