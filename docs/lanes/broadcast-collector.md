# Lane: broadcast-collector

Owns `src/broadcast` and `src/collector` (moved from broadcast-resolver, which keeps
`src/resolver`). Worked by the actor-stream thread after its backlog finished.

Reference: `~/.cache/zigware/commonware-ref/{broadcast,collector}` (about 5.7k Rust lines).
Both are actors over p2p. They build on `actor.mailbox`, `p2p` (lib types and
`p2p.simulated`, API in docs/lanes/p2p.md), the deterministic runtime,
`runtime.telemetry.metrics`, and `cryptography` (certificate schemes, mocks).

broadcast `buffered` comes first: consensus marshal (T-01a1d5ef-5571-7424-8220-609c9811da57)
needs it.

## Backlog
- [ ] broadcast lib.rs traits.
- [ ] broadcast buffered: config, ingress, metrics, engine, mocks, with the mod.rs tests on
  p2p.simulated; the conformance hashes if any.
- [ ] collector lib.rs, p2p wire (with conformance hashes), engine, mocks, tests.
- [ ] Fuzz targets (broadcast/fuzz, collector/fuzz).

## Log
