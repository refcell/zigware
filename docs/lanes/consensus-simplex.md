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
- `consensus.types.coding`: `Commitment(BlockDigest, Root, Context)` (100 bytes: three
  32-byte zero-padded digest fields and a `coding.Config`; `init`, `block`, `root`,
  `context`, `config`, `empty`, `eql`, `order`, codec validating every field),
  `commitment_size`, `commitment_digest_size`.
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
  unions (`epoch`, `view`, `eql`, codec), `Certification`, `AttributableMap(T)`. Votes have
  `sign(gpa, scheme, proposal|round) !?Self`, `verify(gpa, rng, scheme, strategy) !bool`,
  `subject()`; certificates have `from_votes(gpa, scheme, votes, strategy)`, `verify`, `clone`;
  `Vote` has `signer`/`verify`, `Certificate` has `verify`/`clone`.
- `consensus.simplex.Attestation(S)` and `Deferred(T)`: re-exports of
  `cryptography.certificate`'s. `Subject(D)` implements `certificate.assert_subject`
  (`Namespace`, `namespace`, `message(gpa)`, plus allocation-free `message_to(buffer)`).
- `consensus.simplex.scheme.Namespace` (`derive`, `clone`, `deinit`, `of(subject)`; the
  `_NOTARIZE`/`_NULLIFY`/`_FINALIZE`/`_SEED` suffixes).
- `consensus.simplex.scheme.ed25519`: `Scheme(D)` (crypto's `ed25519.certificate.Scheme`
  over `Subject(D)` and `N3f1`) and `fixture(D, gpa, rng, namespace, n)`.
- `consensus.simplex.scheme.bls12381_multisig`: `Scheme(D, P, V)` and `fixture(S, ...)`;
  `consensus.simplex.scheme.secp256r1`: `Scheme(D, P)` and `fixture(S, ...)`;
  `consensus.simplex.scheme.bls12381_threshold.standard`: `Scheme(D, P, V)` and
  `fixture(S, ...)` (crypto's schemes over simplex subjects).
- `consensus.simplex.Lookahead` (`init(terms)`, `admits`, `admits_outbound`,
  `in_admission_window`, `admission_limit`, `issuance_floor`), `Viewport` (`floor`,
  `retains`, `admits_vote`, `admits_certificate`), `Plan(P)` (`prepare`, `propose`,
  `forward` with `p2p.Recipients(P)`).
- `consensus.simplex.elector`: `Terms` (`rotating`, `stable`), `RoundRobin(H)` (`default`,
  `shuffled(seed)`, `with_term`, `build(gpa, n)`), `RoundRobinElector` (`elect(round, {})`,
  `terms`, `deinit`), `Random(H)` (`init(.v0/.v1)`, `select_leader`, `build(V, n)`),
  `RandomElector(H, V)` (`elect(round, ?*const vrf.Certificate(V))`), `assert_elector`
  (`mode` `.scheduled`/`.dynamic`, `Input`).
- `consensus.simplex.limits.max_payload_size(S, D, participants)`.
- `consensus.simplex.config`: `Config(P)` (P declares `Scheme`, `Elector`, `Blocker`,
  `Digest`, `Automaton`, `Relay`, `Reporter`, `Strategy`;
  `check(gpa, rng) !?[]const u8`, `assert_valid(gpa, rng)`), `Floor(S, D)`, `SkipPolicy`, `SkipBudget`, `ForwardPolicy`.
- `consensus.simplex.metrics`: label sets `Peer(P)`, `Leader(P)`, `Timeout(P)` with
  `TimeoutReason`, `Outbound`, `Inbound(P)` with `MessageType`, `HandoffEvent`,
  `HandoffAbandoned`; enum labels print commonware's variant names.
- `consensus.simplex.scheme.bls12381_threshold.vrf`: `Signature(V)`, `Certificate(V)`,
  `Seed(V)` wire types.
- `consensus.simplex.actors.batcher`: `votes.VoteTracker(S, D)`, `verifier.Verifier(S, D)`
  and `Batch(C)` (optimistic assembly with per-vote fallback), `round.Round(S, B, D, R)`
  (`add_network`, `accept_vote`, `record_certificate`, `try_construct`, `missing_voters`),
  `ingress.Message`/`Pending`/`Mailbox` (`update`, `constructed`), and `actor.Actor(P)`
  (`init(gpa, io, Config(P))` returns the actor and its `Mailbox`; `run(voter, votes,
  certificates)` until a source closes or the task is canceled). `P` declares `Scheme`,
  `Digest`, `Blocker`, `Reporter`, `Relay`, `Strategy`, and `Receiver` (any p2p receiver
  with `recv() !?Message` or `recv() !Message`).
- `consensus.simplex.actors.voter.ingress`: `Message` (`proposal`, `timeout`,
  `verified{gpa, certificate}`, `discard`), `Pending`, `Mailbox` (`proposal`, `timeout`,
  `recovered`); `slot.Slot(D)` (proposal status and equivocation); `round.Round(S, D)` (the
  per-round state machine: leader, proposal, nullify/finalize decision and deadlines in
  runtime nanoseconds, certificates, certification, replay); `state.State(S, E, D)` (the
  per-epoch state machine: `set_genesis`/`set_floor`, `try_propose`/`proposed`,
  `try_verify`/`verified`, `add_notarization`/`add_nullification`/`add_finalization`,
  `construct_notarize`/`construct_finalize`/`construct_nullify`, `certify_candidates`/
  `certified`, `next_timeout`/`trigger_timeout`, `get_best_certificate`, `replay`, `prune`);
  `views.ViewSet`/`ViewMap(T)`.
- `consensus.simplex.actors.ask`: `Ask`, `Kind`, `Until`.

## Decisions
- `Epoch`/`Height`/`View`/deltas are non-exhaustive `enum(u64)` so they compare with `==`,
  hash, and never mix with each other or raw integers (commonware's newtypes).
- `Round` is a `packed struct(u128)` so `==` works; its fields are public (`round.epoch`).
- `covering_range` returns the inclusive pair `{ start, end }` instead of `RangeInclusive`.
- Automaton/CertifiableAutomaton methods block on `std.Io` (`propose(io, ctx) !?Digest`)
  instead of returning oneshot receivers; null is a closed channel. Callers run them with
  `io.async` to wait on several at once.
- `Attestation(S)` and `Deferred(T)` come from `cryptography.certificate` (the stand-in is
  gone); simplex keeps only the `Attestation::arbitrary` generator its conformance needs.
- Signatures in attestations and VRF certificates are `Deferred(T)`: the fixed bytes inline,
  decoded on `get()` (no cache), instead of `Lazy`'s borrowed view, so a decoded vote never
  points into a network buffer. Equality is byte equality.
- Fault evidence fields are `first`/`second` (commonware `notarize_1`/`notarize_2`).
- Conformance hashes that need BLS or ed25519 key generation skip in Debug without
  `-Dslow-tests`, like the crypto lane; ReleaseSafe CI runs them.
- Elector `build` takes the participant count, not the set (commonware reads only its
  length). `mode`/`Input` replace the sealed `Mode` trait.
- Random V0/V1 conformance hashes and the threshold-certificate elector tests wait for the
  bls-math lane's threshold signatures; `select_leader` is checked against independently
  computed values instead.
- `Config(P)` takes one parameter type declaring commonware's eight type parameters.
  `check` returns the violated rule's message so tests can see it, and `assert_valid` panics
  with it. The floor check uses the certificate scheme surface
  `verify_certificate(gpa, rng, Subject(D), *const Certificate, strategy) !bool`.
- consensus also imports `conformance` and `invariants` (test-only, like commonware's
  dev-dependencies).
- Actors replace `select_loop!` with `actors/inbox.zig`: one pump task per source feeds a
  bounded `std.Io.Queue`, and the actor handles one event, then its `on_end` work. Time and
  randomness come from `std.Io` (`actors/context.zig`), so the deterministic runtime replays
  a run. Batcher rounds live in a view-sorted list rather than a `BTreeMap`. Certificate
  construction runs inline (no offload). Metrics and tracing spans in the actors follow.

## Backlog
- [x] types.rs: Epoch, Height, View, deltas, ranges, TermLength, Round, FixedEpocher, with
  every test and the Epoch/Height/View/Round conformance hashes. 
- [x] consensus lib.rs traits (`Automaton`, `CertifiableAutomaton`, `Handoff`, `Relay`,
  `Reporter`, `Monitor`, `Epochable`, `Viewable`, `Block`, ...) as comptime interfaces;
  reporter.rs.
- [x] simplex types.rs: Proposal, Context, Notarize, Nullify, Finalize, their certificates,
  Vote/Certificate/Artifact/Activity, the attributable faults, AttributableMap; all 15
  simplex types hashes and the 3 threshold-VRF wire-type hashes match. (Signing tests follow
  with the schemes.)
- [x] types.rs `coding::Commitment` (`types.coding.Commitment(BlockDigest, Root, Context)`)
  with its tests and the `TestCommitment` conformance hash.
- [x] elector.rs: RoundRobin (shuffled, stable terms) and Random (V0/V1) with their tests;
  RoundRobinShuffleConformance matches. (Random V0/V1 hashes: after threshold signing.)
- [ ] simplex scheme: ed25519, bls12381_multisig, secp256r1, bls12381_threshold standard
  done (on crypto's certificate schemes); bls12381_threshold vrf (signing, seeds) next.
- [x] limits.rs (`max_payload_size`), checked against the widest VRF encodings; the
  per-scheme widest-encoding tests follow with the schemes.
- [x] config.rs (Config, Floor, skip and forward policies) with its validation rules.
- [ ] simplex metrics, and the actors (voter, batcher, resolver) and engine,
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
- 2026-11-13: types.rs `coding::Commitment`; TestCommitment conformance hash matches.
- 2026-11-13: elector.rs (RoundRobin, Random); RoundRobinShuffleConformance matches.
- 2026-11-13: limits.rs (`max_payload_size`).
- 2026-11-13: config.rs (Config, Floor, SkipPolicy, ForwardPolicy).
- 2026-11-13: simplex ed25519 scheme and Namespace on crypto's certificate.rs; the
  Attestation stand-in is removed.
- 2026-11-13: metrics.rs label sets on runtime.telemetry.metrics.
- 2026-11-13: simplex bls12381_multisig and secp256r1 schemes.
- 2026-11-13: simplex bls12381_threshold standard scheme; Lookahead, Viewport, Plan.
- 2026-11-13: sign/verify/assemble/clone on the simplex vote and certificate types.
- 2026-11-13: batcher VoteTracker, Verifier, Round, and the batcher/voter mailboxes.
- 2026-11-13: batcher actor on an Io.Queue inbox, tested on the deterministic runtime.
- 2026-11-16: voter Slot and Round with their commonware tests.
- 2026-11-16: voter State with the core state.rs tests (13 of 141 so far).
