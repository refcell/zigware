# Lane: broadcast-resolver

Owns `src/broadcast`, `src/resolver`, `src/collector`.

Reference: `~/.cache/zigware/commonware-ref/{broadcast,resolver,collector}`. All three are
actors over p2p (`actor` mailbox on main, p2p's lib types on main, p2p `simulated` landing
now). Start with the parts that need only codec, cryptography, utils, and actor: the lib.rs
traits, wire formats (resolver p2p/wire.rs, collector p2p wire), and the pure state
(fetcher, inflight, score, subscribers, delivery); then the engines and the multi-peer tests
on p2p's simulated network and the deterministic runtime.

## Backlog
- [ ] resolver: lib.rs traits, opaque.rs, delivery.rs, subscribers.rs, ingress.rs.
- [ ] resolver p2p: wire.rs (byte-identical, conformance hashes), fetcher, inflight, score,
  config, engine, ingress, mocks; port mod.rs tests on p2p simulated.
- [ ] broadcast: lib.rs and buffered (engine, ingress, config, mocks) with its tests.
- [ ] collector: lib.rs and p2p (engine, wire) with its tests.
- [ ] Fuzz targets (broadcast/fuzz, collector/fuzz) and metrics once the runtime registry
  lands.

## Log
