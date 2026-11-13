# Lane: p2p

Owns `src/p2p`.

Reference: `~/.cache/zigware/commonware-ref/p2p/src`. Start with the parts that run on the
deterministic runtime alone: `simulated` only needs task spawning and time from
`std.Io` (on main via `runtime.deterministic.Runner`). `authenticated` needs stream's
handshake and the runtime's network, which the actor-stream and runtime lanes are landing.

## Backlog
- [ ] types.rs, sizing.rs, lib.rs traits (`Sender`, `Receiver`, `Blocker`, `Manager`,
  `Recipients`, channels) as comptime interfaces.
- [ ] utils: codec (wrapped sender/receiver), limited, mux (channel multiplexing), mocks.
- [ ] simulated: network with links (latency, jitter, success rate), bandwidth limits,
  transmitter scheduling, partitions, peer sets, Byzantine blocking. Port its tests; it is
  the test bed for broadcast, resolver, and consensus, so keep it deterministic per seed.
- [ ] authenticated: router, relay, throttle, dialing, connection over stream's
  handshake, then discovery and lookup (actors, types, codec identical to commonware).
- [ ] Fuzz targets (commonware p2p/fuzz).

## Log
