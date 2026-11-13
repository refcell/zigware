# Lane: p2p

Owns `src/p2p`.

Reference: `~/.cache/zigware/commonware-ref/p2p/src`. Start with the parts that run on the
deterministic runtime alone: `simulated` only needs task spawning and time from
`std.Io` (on main via `runtime.deterministic.Runner`). `authenticated` needs stream's
handshake and the runtime's network, which the actor-stream and runtime lanes are landing.

## Public API (on main)
- `p2p.Channel` (`u64`), `p2p.Message(P)` (`peer`, `payload`), `p2p.Recipients(P)`
  (`all`/`some`/`one`, `union_with(gpa, a, b)`, `peers()`, `deinit`), `p2p.Check(Checked)`
  (`checked` or `limited: utils.SystemTime`), `p2p.TrackedPeers(P)` (`primary`/`secondary` as
  `codec.Set(P)`, `union(gpa)`), `p2p.PeerSetUpdate(P)`, `p2p.Feedback`/`p2p.Unreliable`
  (re-exported from actor).
- Interface checks: `assert_unlimited_sender`, `assert_limited_sender`, `assert_receiver`,
  `assert_manager`, `assert_blocker` (decls documented at the top of `src/p2p/root.zig`).
- `p2p.types`: `Hostname`, `Ingress` (`socket`/`dns`), `Address` (`symmetric`/`asymmetric`),
  `is_global(IpAddr)`; codec encodings match commonware's conformance hashes.
- `p2p.sizing`: `max_message_size`, `peer_set_limit`, `max_retained_peers`, `peer_set_size`.

## Decisions
- `Hostname` and `is_global` live in `p2p/types.zig` until the utils lane ports
  `hostname.rs`/`net.rs`; validation and wire format are commonware's, so the switch changes
  no bytes. `Hostname` is stored inline (253 bytes), so `Ingress`/`Address` never allocate.
- p2p imports `conformance` (a dev-dependency in commonware) for its conformance tests.
- `Recipients.union_with` returns a new value (inputs borrowed); a `some` result is owned by
  the caller. Message payloads are byte slices until the runtime lane ports `IoBuf`.
- p2p carries its own seeded fuzz driver (`p2p.fuzz.run`, same as codec's) until
  `invariants.minifuzz` lands.

## Backlog
- [x] types.rs, sizing.rs, lib.rs traits (`Sender`, `Receiver`, `Blocker`, `Manager`,
  `Recipients`, channels) as comptime interfaces; Ingress/Address conformance; decode fuzz.
- [ ] utils: codec (wrapped sender/receiver), limited, mux (channel multiplexing), mocks.
- [ ] simulated: network with links (latency, jitter, success rate), bandwidth limits,
  transmitter scheduling, partitions, peer sets, Byzantine blocking. Port its tests; it is
  the test bed for broadcast, resolver, and consensus, so keep it deterministic per seed.
- [ ] authenticated: router, relay, throttle, dialing, connection over stream's
  handshake, then discovery and lookup (actors, types, codec identical to commonware).
- [ ] Fuzz targets (commonware p2p/fuzz).

## Log
- 2026-11-13: lib.rs types and interface checks, types.rs (Ingress, Address, Hostname,
  is_global) with commonware conformance hashes, sizing.rs, decode-canonical fuzz.
