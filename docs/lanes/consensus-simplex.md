# Lane: consensus-simplex

Owns `src/consensus` except `marshal/` and `aggregation/` (later lanes): `root.zig`,
`types.zig`, `reporter.zig`, and `simplex/`.

Reference: `~/.cache/zigware/commonware-ref/consensus/src/{lib.rs,types.rs,reporter.rs,simplex}`.
The wire types need only codec, cryptography, and utils, which are on main. The actors
(voter, batcher, resolver) and the engine need p2p's simulated network, broadcast, and
resolver; those lanes are running, so do the types first and the actors as they land.

## Public API (on main)
- `consensus.types`: `Epoch`, `Height`, `View` (non-exhaustive `enum(u64)`: `new`, `get`,
  `zero`, `is_zero`, `next` (panics on overflow), `previous`, `saturating_add/sub`,
  `checked_sub`, `delta_from`, `range`, `order`, `{f}`; codec as a `u64` varint),
  `EpochDelta`/`HeightDelta`/`ViewDelta` (`Delta(T)`), `ViewRange`/`HeightRange`
  (`next`, `next_back`, `len`), `TermLength` (`new(NonZero(u32))`, `one`, `max`, `get`), View
  term math (`term_start`, `term_end`, `is_term_start`, `same_term`, `next_term_start`,
  `term_index`, `covers`, `covering_range`, `admits`), `Round` (packed, `==` works; `new`,
  `order`, codec epoch then view), `EpochInfo`, `EpochPhase`, `FixedEpocher`,
  `assert_epocher`, `Participant` (re-export of `utils.Participant`).

## Decisions
- `Epoch`/`Height`/`View`/deltas are non-exhaustive `enum(u64)` so they compare with `==`,
  hash, and never mix with each other or raw integers (commonware's newtypes).
- `Round` is a `packed struct(u128)` so `==` works; its fields are public (`round.epoch`).
- `covering_range` returns the inclusive pair `{ start, end }` instead of `RangeInclusive`.
- `coding::Commitment` (and its `TestCommitment` conformance hash) waits for the coding
  lane's `Config`.
- consensus also imports `conformance` and `invariants` (test-only, like commonware's
  dev-dependencies).

## Backlog
- [x] types.rs: Epoch, Height, View, deltas, ranges, TermLength, Round, FixedEpocher, with
  every test and the Epoch/Height/View/Round conformance hashes. (Commitment: see Decisions.)
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
- 2026-11-13: types.rs (Epoch/Height/View/Round, term math, FixedEpocher); 4 conformance
  hashes match.
