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
- `consensus.traits` (lib.rs as comptime interfaces): `assert_epochable`/`viewable`/
  `heightable`, `round(x)`, `assert_block`, `assert_certifiable_block`, `assert_automaton`,
  `assert_certifiable_automaton` with default-supplying `prepare`/`certify`, `Handoff(D)`,
  `assert_relay`, `assert_reporter`, `assert_monitor`; see the top of `traits.zig`.
- `consensus.reporter`: `Optional(R)`, `Reporters(R1, R2)`, `combine`.
- `consensus.simplex.types` (generic over a scheme `S` with `S.Signature`, `S.Certificate`,
  `S.max_certificate_size`, and a digest `D`): `Proposal(D)`, `Context(D, P)`, `Subject(D)`
  (`message` is the signed bytes), `Notarize`/`Nullify`/`Finalize` (proposal or round plus
  `Attestation(S)`), `Notarization`/`Nullification`/`Finalization`, `ConflictingNotarize`,
  `ConflictingFinalize`, `NullifyFinalize`, the `Vote`/`Certificate`/`Artifact`/`Activity`
  unions (`epoch`, `view`, `eql`, codec), `Certification`, `AttributableMap(T)`.
- `consensus.simplex.Attestation(S)` and `Deferred(T)` (a fixed-size value kept as its
  bytes and decoded on demand, commonware's `Lazy`).
- `consensus.simplex.scheme.bls12381_threshold.vrf`: `Signature(V)`, `Certificate(V)`,
  `Seed(V)` wire types.

## Decisions
- `Epoch`/`Height`/`View`/deltas are non-exhaustive `enum(u64)` so they compare with `==`,
  hash, and never mix with each other or raw integers (commonware's newtypes).
- `Round` is a `packed struct(u128)` so `==` works; its fields are public (`round.epoch`).
- `covering_range` returns the inclusive pair `{ start, end }` instead of `RangeInclusive`.
- `coding::Commitment` (and its `TestCommitment` conformance hash) waits for the coding
  lane's `Config`.
- Automaton/CertifiableAutomaton methods block on `std.Io` (`propose(io, ctx) !?Digest`)
  instead of returning oneshot receivers; null is a closed channel. Callers run them with
  `io.async` to wait on several at once.
- `Attestation(S)` lives in `simplex/attestation.zig` until the crypto lane ports
  `certificate.rs`; same wire format, then switch to `cryptography.certificate`.
- Signatures in attestations and VRF certificates are `Deferred(T)`: the fixed bytes inline,
  decoded on `get()` (no cache), instead of `Lazy`'s borrowed view, so a decoded vote never
  points into a network buffer. Equality is byte equality.
- Fault evidence fields are `first`/`second` (commonware `notarize_1`/`notarize_2`).
- Conformance hashes that need BLS or ed25519 key generation skip in Debug without
  `-Dslow-tests`, like the crypto lane; ReleaseSafe CI runs them.
- consensus also imports `conformance` and `invariants` (test-only, like commonware's
  dev-dependencies).

## Backlog
- [x] types.rs: Epoch, Height, View, deltas, ranges, TermLength, Round, FixedEpocher, with
  every test and the Epoch/Height/View/Round conformance hashes. (Commitment: see Decisions.)
- [x] consensus lib.rs traits (`Automaton`, `CertifiableAutomaton`, `Handoff`, `Relay`,
  `Reporter`, `Monitor`, `Epochable`, `Viewable`, `Block`, ...) as comptime interfaces;
  reporter.rs.
- [x] simplex types.rs: Proposal, Context, Notarize, Nullify, Finalize, their certificates,
  Vote/Certificate/Artifact/Activity, the attributable faults, AttributableMap; all 15
  simplex types hashes and the 3 threshold-VRF wire-type hashes match. (Signing tests follow
  with the schemes.)
- [ ] types.rs `coding::Commitment` and the `TestCommitment` hash (coding.Config landed).
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
- 2026-11-13: lib.rs traits as comptime interfaces (`traits.zig`) and reporter.rs.
- 2026-11-13: simplex wire types, attestation stand-in, VRF Signature/Certificate/Seed; 18
  conformance hashes match.
