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
  `check(gpa, rng) !?[]const u8`, `assert_valid(gpa, rng)`), `Floor(S, D)`, `SkipPolicy`,
  `SkipBudget`, `ForwardPolicy`.
- `consensus.simplex.metrics`: label sets `Peer(P)`, `Leader(P)`, `Timeout(P)` with
  `TimeoutReason`, `Outbound`, `Inbound(P)` with `MessageType`, `HandoffEvent`,
  `HandoffAbandoned`; enum labels print commonware's variant names.
- `consensus.simplex.scheme.bls12381_threshold.vrf`: `Signature(V)`, `Certificate(V)`,
  `Seed(V)` (`verify(scheme)`, `decrypt(ciphertext)`), `seed(V, *notarization_or_finalization)`
  (`Seedable`), `encrypt(V, gpa, rng, identity, namespace, target, message)`, `decrypt_with`,
  `Scheme(D, P, V)` (commonware `vrf::Scheme<P, V>`: `signer`, `verifier`, `member`,
  `certificate_verifier`, `identity`, `share`, `polynomial`, `encrypt`, plus the certificate-scheme
  surface; not attributable, batchable), and `fixture(S, gpa, rng, namespace, n)`.
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
- `consensus.simplex.actors.voter.actor.Actor(P)`: `init(gpa, io, Config(P))` returns the
  actor and its `Mailbox`; `run(batcher, resolver, *vote_sender, *certificate_sender)`
  recovers from its journal, then drives proposal, verification, certification, voting,
  and timeouts until the mailbox closes or the task is canceled.
- `consensus.simplex.actors.resolver`: `ingress` (`Message`, `Pending`, `Mailbox` with
  `updated`/`certified`/`replayed`/`resolve`; `HandlerMessage`, `HandlerPending`, and
  `Handler`, the p2p engine's consumer and producer), `state.State(S, D)` (held and served
  certificates, `Effect`s, `settled`/`key_settled`/`produce`), and `actor.Actor(P)` (runs
  `resolver.p2p.Engine` over a `StaticProvider` and hands recovered certificates to the
  voter).
- `consensus.simplex.Engine(P)`: `init(ctx, Config)` builds the three actors; spawn
  `Engine.run(ctx, *engine, votes, certificates, backfill)` (each a `Channel(P)` of sender
  and receiver) as a task, abort its handle to stop, then `deinit`. `P` adds `Context`,
  `Sender`, and `Receiver` to `Config`'s parameters; `P.Automaton` is a pointer.
- `consensus.simplex.scheme.reporter.AttributableReporter(S, D, Rng, Strategy, R)`:
  `init(gpa, io, rng, scheme, reporter, strategy, verify)` wraps reporter pointer `R`,
  verifying peer votes and faults when `verify` is set and dropping them for
  non-attributable schemes; certificates always pass. Activities stay borrowed.
- `consensus.simplex.mocks.twins` (commonware `mocks/twins.rs`): `cases(gpa, rng,
  Framework{participants, faults, rounds, mode, max_cases})` returns owned `Case`s
  (`compromised` indices and a `Scenario`; `free_cases`). `Scenario.masks/route(view,
  term_length, ...)`, `view_masks`/`view_route`, `partition`, `index_of`, and
  `Elector(E)` (scripted leaders per term, then fallback `E`). `SplitTarget` is p2p's
  `simulated.SplitTarget`. Drawing matches rand 0.10 for the same RNG.
- `consensus.simplex.mocks.scheme` (commonware `mocks/scheme.rs`): `Scheme(D)` (crypto's mock
  certificate scheme over simplex subjects, N3f1, ed25519 identities) and `fixture(D, gpa, rng,
  namespace, n)`.
- `consensus.simplex.mocks`: `relay.Relay(D, P)` (`deregister(key)` and `deregister_all`
  return once no delivery can reach the removed listeners), `application.Application(H, P)`
  (the automaton and relay, with simulated latency from p2p's `Normal`),
  `application.genesis`, and `reporter.Reporter(S, D)` (verifies and records activity;
  `wait_for_finalized`, `finalized`, `latest_finalized`, `votes(view)` signer bitmaps,
  `notarized`, `nullified`, `max_nullify_view`, `fault_list`, `assert_no_faults`,
  `assert_no_invalid`); Byzantine `conflicter.Conflicter(S, H)`, `nuller.Nuller(S, H)`,
  `impersonator.Impersonator(S, H)`, `outdated.Outdated(S, H)`, and
  `reconfigurer.Reconfigurer(S, H)`, `nullify_only.NullifyOnly(S, H)` (`run(sender, receiver)`
  on the vote channel), `equivocator.Equivocator(S, H, P, E)` (`run(votes,
  certificates)`), and `wrapped.Scheme(Inner)` with `Behavior` (`honest`,
  `corrupt_signature`, `recovery_failure`), a by-value wrapper of a certificate scheme.

## Decisions
- Twins: commonware's recursive generator helpers (compositions, the transition DFS, fault
  allocation) are lexicographic successor steps and an odometer here (TigerStyle: no
  recursion), emitting in the same order. The brute-force reference enumerator test is not
  ported; the single-round space is checked against its closed form, and enumerated
  multi-round scenarios are checked distinct.
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
- The VRF scheme seeds its two same-message batches (vote, then seed) with ChaCha20 keys
  drawn from `rng`, where commonware uses `StdRng`; the draws only pick verification weights,
  so results match. Its sharing parameters are named `sharing` (`polynomial` is the accessor).
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
- Twins campaigns (`twins_campaign_test.zig`) send every engine's traffic through p2p's
  split senders: honest validators keep the primary half of a pass-through split, twins split
  by the scenario's per-round recipient sets, and a twin's resolver channel drops sends and
  routes nothing (commonware's `inert_channel`). A message's view is read from its tag and
  leading round. Debug builds run 2 of the 20 cases per campaign. The mock reporter flags
  signers that vote for two payloads in one view (`equivocating_signers`), standing in for
  commonware's per-payload signer maps.
- Tracing: each actor holds a `traces.Tracer` (default `.none`) that the engine sets from the
  actor's child context under commonware's module path (`trace_target`), and emits
  commonware's events at the same sites and levels. View and epoch fields go out as integers
  (`.get()`), which print the same as their `format`. Spans and the
  events inside voter `state.rs`/`round.rs`/`slot.rs` (no tracer in the state machine yet)
  follow.
- The voter runs each automaton request as an `io.concurrent` task that pushes its answer
  into the inbox; ids discard answers that raced a cancelation. Senders are held by pointer
  (p2p's limited sender is stateful) and the peers each send returns are freed.
- The engine takes a built elector (`P.Elector`, which the caller owns) instead of an
  elector config, since the electors' builders differ in what they allocate. It copies the
  scheme and borrows its owned data from the caller. Any actor stopping ends the engine,
  which aborts the rest (commonware's `select!` over the handles); actors run as
  `runtime.Context` children `batcher`, `voter`, and `resolver`.
- The resolver's `Handler` borrows the actor's handler-mailbox sender, because the p2p
  engine never releases its consumer or producer. `StaticProvider` (commonware's
  `p2p::utils`) lives in the resolver actor until p2p ports it. `Ask` declares a two-byte
  codec only so the resolver can order subscribers through codec; it never travels.
- The resolver stops when its mailbox closes or its task is canceled; it does not watch the
  p2p engine's task (commonware breaks when that task ends).
- The mock application is the automaton itself (blocking calls from the voter's request
  tasks) rather than an actor answering oneshot requests; one mutex serializes its
  simulated work as commonware's actor loop does. The mock reporter keeps per-view sets and
  counts, not commonware's per-signer maps; the per-signer checks follow with the full
  `all_online` port.

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
  RoundRobinShuffleConformance and RandomV0/V1SelectLeaderConformance match.
- [x] simplex scheme: ed25519, bls12381_multisig, secp256r1, bls12381_threshold standard
  (on crypto's certificate schemes) and bls12381_threshold vrf (signing, seeds) with its
  tests, including timelock encrypt/decrypt to a round's seed.
- [x] limits.rs (`max_payload_size`), checked against the widest VRF encodings; the
  per-scheme widest-encoding tests follow with the schemes.
- [x] config.rs (Config, Floor, skip and forward policies) with its validation rules.
- [x] simplex metrics, and the actors (voter, batcher, resolver) and engine, on p2p's
  simulated network and the deterministic runtime: 4 honest nodes finalize.
- [ ] Port the rest of state.rs's tests (37 of 141), the resolver actor.rs tests, and the
  voter/resolver ingress tests; add actor metrics. (Resolver state.rs: all 23 done.)
  Handed to the runtime lane on 2026-11-16. Ported in voter/state_test.zig, in
  commonware's order: everything from `certificate_candidates_respect_force_flag` through
  `parent_payload_reports_missing_term_anchor` (including the timeout, stall, inactivity,
  and skip-budget tests, without their timeout-metric counters, and except
  `decided_views_close_their_view_span`, which waits on view spans), plus
  `certification_lifecycle`, `entry_certificate_prioritizes_...`, `only_notarize_before_
  nullify`, `nullification_skips_to_next_term_start`, `term_safety_blocks_finalize_after_
  nullify`, `try_verify_waits_for_missing_parent_certification`, and the
  `parent_payload_rejects_intra_term_view_skip` case. Everything from
  `optimistic_views_zero_disables_intra_term_lookahead` on is still to do.
- [ ] simplex mod.rs tests (ed25519, round robin). Done: all_online (Debug runs 50 views
  where commonware runs 100), partition, slow_and_lossy_links, determinism, the Byzantine
  conflicter, nuller, impersonator, reconfigurer, invalid (2 seeds each, 20 or 50 views;
  commonware runs 5 seeds of 50), outdated, equivocator, backfill, unclean_shutdown (100
  views across journal-recovering restarts), one_offline (its leader-labelled metrics wait
  on the actor metrics), slow_validator, all_recovery, all_crash_after_nullify,
  received_certificates_are_reported, survives_burst, engine_shutdown (abort and graceful;
  commonware's running-task count waits on the runtime's task metrics), and
  attributable_reporter_filtering, and split_views_no_lockup (with the nullify-only mock).
  The twins campaigns (sampled, sustained, stable leader, optimistic; the large ones in
  slow builds) run on the mock scheme.
  tle (threshold VRF, Random elector, MinPk and MinSig; slow builds) decrypts at the target
  round's seed. The four slow-certifier DSTs (stable leader optimistic, stable leader,
  rotating, and short-term handoff votes; slow builds) finalize 200 views with no
  nullification. The three certified-split DSTs (group-led view, lone holder leads
  first, displaced certified view) heal through targeted repair, and both cross-term
  certified splits (terms of 5 views; backfill suppressed or allowed) finalize view 26
  through recursive parent repair. hailstorm (10 restarts of a random validator, keeping
  its reporter, then commonware's fork checks; two runs replay the same auditor state;
  rotating and stable leader) runs in slow and ReleaseSafe builds. Debug runs without
  `-Dslow-tests` shrink the heavier DSTs (`quick` in engine_test.zig: fewer views and
  seeds; one twins case per campaign; MinPk only for the threshold VRF tests) so
  test-consensus stays near 2 minutes. observer (a linked peer outside the committee),
  non_genesis_floor_joiner (rotating and stable leader; the joiner starts from a mid-term
  finalization), and dishonest_leader_certification_rejected (ed25519) pass. Twins nodes
  reject mismatched payloads, as commonware's `mocks` build does. The twins pipelined
  handoff campaign (applications vote handoffs through the prefix, then wait) checks that
  honest and twin applications returned handoffs; its early-vote count waits on the
  voter's handoff metrics. Next: per-scheme twins, the per-scheme fixture variants, and
  the rest, seeded.
- [ ] Tracing: actor events are done (voter, batcher, resolver, engine). The voter opens
  commonware's `simplex.voter.start`, `.timeout`, `.process`, and `.notify` spans, and
  events inside them carry them. Still to do: the per-view spans (`view_span`), the
  propose/verify/certify/journal spans, the batcher and resolver spans, and the voter
  state machine's events.
- [x] Fuzz targets (commonware consensus/fuzz): owned by the crypto lane in
  `src/consensus/fuzz/`.

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
- 2026-11-16: voter and resolver actors, engine, mocks; 4 honest nodes finalize (DST).
- 2026-11-16: DST: all_online, partition heals, slow and lossy links, seed determinism.
- 2026-11-16: Byzantine conflicter and nuller mocks with their DSTs (reported and blocked).
- 2026-11-16: Byzantine impersonator and outdated mocks with their DSTs.
- 2026-11-16: backfill DST (a late validator catches up while another is cut off).
- 2026-11-16: resolver state.rs tests (all 23).
- 2026-11-16: unclean_shutdown DST (random crashes, journal recovery, 100 views).
- 2026-11-16: one_offline DST; the reporter mock records vote signers per view.
- 2026-11-16: slow_validator DST.
- 2026-11-16: all_recovery and all_crash_after_nullify DSTs.
- 2026-11-16: Byzantine equivocator mock with its DST; the relay mock deregisters one
  validator (waiting out in-flight deliveries) so one engine can crash and restart.
- 2026-11-16: invalid DST on the wrapped (signature-corrupting) scheme mock; every DST
  engine now signs through the wrapper.
- 2026-11-16: received_certificates_are_reported and survives_burst DSTs; the application
  mock can stall proposals.
- 2026-11-16: the engine ends on `context.stopped()`, as commonware's does; engine_shutdown
  DSTs (abort and graceful stop).
- 2026-11-16: scheme/reporter.rs (AttributableReporter, all 6 tests) and the
  attributable_reporter_filtering DST; every DST engine reports through the wrapper.
- 2026-11-16: Byzantine reconfigurer mock with its DST.
- 2026-11-16: nullify-only mock and the split_views_no_lockup DST.
- 2026-11-16: twins scenario generator (mocks/twins.rs), iterative, with its core tests.
- 2026-11-16: bls12381_threshold vrf Scheme (signing, seeds, Seedable) with vrf.rs's tests;
  Random V0/V1 select-leader conformance hashes match.
- 2026-11-16: twins uses p2p's `simulated.SplitTarget` (5826612); the stand-in is removed.
- 2026-11-16: commonware's tracing events in the voter, batcher, resolver, and engine, at
  commonware's targets, with a Collector-checked DST.
- 2026-11-16: simplex mocks/scheme.rs (the mock certificate scheme) and the twins campaigns
  on p2p's split senders and receivers.
- 2026-11-16: the tle DST on the threshold VRF scheme; the mock reporter keeps notarizations.
- 2026-11-16: the slow-certifier DSTs; the Harness takes the round-robin terms, the handoff
  decision, and verify/certify latencies.
- 2026-11-16: the certified-split DSTs; the mock reporter answers `certified(view)`.
- 2026-11-16: the cross-term certified-split DSTs (commonware's epoch 2 schedule is kept by
  naming each honest validator by the term it leads).
- 2026-11-16: hailstorm DSTs; Debug-only DST sizes (`quick`) cut test-consensus's Debug time.
- 2026-11-16: observer, non-genesis floor joiner, and dishonest-leader DSTs; the Harness takes
  a floor finalization and a certifier; the mock reporter keeps finalizations.
- 2026-11-16: voter state.rs timeout, stall, and inactivity tests (26 of 141); timeout-metric
  assertions wait on the voter's metrics.
- 2026-11-16: voter state.rs skip-budget, timeout-reset, and term-anchor tests (37 of 141).
- 2026-11-16: twins pipelined handoff campaign; the mock application takes `handoff_until`.
- 2026-11-18: voter tracing spans (start, timeout, process, notify); fixtures_test.zig runs
  all_online on all 8 canonical fixtures (ReleaseSafe and slow builds).
