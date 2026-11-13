# Lane: consensus-simplex

Owns `src/consensus` except `marshal/` and `aggregation/` (later lanes): `root.zig`,
`types.zig`, `reporter.zig`, and `simplex/`.

Reference: `~/.cache/zigware/commonware-ref/consensus/src/{lib.rs,types.rs,reporter.rs,simplex}`.
The wire types need only codec, cryptography, and utils, which are on main. The actors
(voter, batcher, resolver) and the engine need p2p's simulated network, broadcast, and
resolver; those lanes are running, so do the types first and the actors as they land.

## Backlog
- [ ] consensus lib.rs traits (`Automaton`, `Relay`, `Reporter`, `Supervisor`, `Monitor`,
  `Epochable`, `Viewable`, ...) as comptime interfaces; types.rs (Epoch, View, Round, Height,
  their deltas and codecs) with its conformance hashes; reporter.rs.
- [ ] simplex types.rs: Proposal, Notarize, Nullify, Finalize, their certificates, Voter and
  Backfiller messages, Activity, and the attributable faults; codec byte-identical and every
  simplex conformance hash matching.
- [ ] simplex scheme: ed25519 now; bls12381_multisig and bls12381_threshold as the bls-math
  lane lands them; secp256r1 when crypto lands it. elector.rs (leader election).
- [ ] simplex config, limits, metrics, and the actors (voter, batcher, resolver) and engine,
  on p2p's simulated network and the deterministic runtime.
- [ ] simplex mod.rs tests: the full multi-node DST suite with the Byzantine mocks
  (conflicter, equivocator, impersonator, nuller, outdated, twins, ...), seeded.
- [ ] Fuzz targets (commonware consensus/fuzz).

## Log
