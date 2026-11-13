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

## Backlog
- [ ] `.lazy` DSL parser and task model, with lib.rs's parser tests. Copy the `.lazy` files and
  p50/p90 latency data into `examples/estimator/` (they are public data in the repo).
- [ ] CLI (`<TASK> --distribution region:count[:bandwidth],... --reload-latencies` etc. as in
  main.rs), statistics (mean, median, std dev per proposer and averaged), output format
  matching commonware's.
- [ ] Simulation on `runtime.deterministic.Runner` and `p2p.simulated`: same seed, same
  output. `zig build run-estimator -- examples/estimator/simplex.lazy --distribution ...`.
- [ ] Every `.lazy` file in the reference runs; port main.rs/lib.rs tests.
- [ ] A short `examples/estimator/README.md` with the commands the README demo uses.

## Log
