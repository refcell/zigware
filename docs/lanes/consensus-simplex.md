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
  `HandoffAbandoned`; enum labels print commonware's variant names. The actors' registered
  sets: `StateMetrics(P)` (voter `state`), `VoterMetrics`, `BatcherMetrics(P)`, each with
  `register(scope)` and `deinit`; `consensus.traits.latency_buckets` is commonware's
  `LATENCY`.
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
- [x] limits.rs (`max_payload_size`) with all four widest-encoding tests on real fixtures
  (ed25519, secp256r1, and multisig at 1, 4, 127, and 128 participants; threshold standard
  and VRF, MinPk and MinSig, at 4 and 33; Debug runs the small committees).
- [x] config.rs (Config, Floor, skip and forward policies) with its validation rules.
- [x] simplex metrics, and the actors (voter, batcher, resolver) and engine, on p2p's
  simulated network and the deterministic runtime: 4 honest nodes finalize.
- [x] Port the rest of state.rs's tests, the resolver actor.rs tests, and the
  voter/resolver ingress tests. (Resolver state.rs: all 23 done.) The actor metrics are
  done (2026-11-18, back in this lane): voter (outbound, handoff events and abandonments,
  four latency histograms), its state (current and tracked views, issuance probes,
  timeouts and nullifications by leader), and batcher (added, processed, inbound by peer,
  latest vote per peer, batch size, construct latency and fallback). commonware's
  resolver actor registers none of its own.
  Handed to the runtime lane on 2026-11-16. Ported in voter/state_test.zig, in
  commonware's order: everything from `certificate_candidates_respect_force_flag` through
  `parent_payload_reports_missing_term_anchor` (including the timeout, stall, inactivity,
  and skip-budget tests; the p2p lane added their timeout-metric counters on 2026-11-18),
  plus
  `certification_lifecycle`, `entry_certificate_prioritizes_...`, `only_notarize_before_
  nullify`, `nullification_skips_to_next_term_start`, `term_safety_blocks_finalize_after_
  nullify`, `try_verify_waits_for_missing_parent_certification`, and the
  `parent_payload_rejects_intra_term_view_skip` case, `optimistic_views_zero_disables_
  intra_term_lookahead`, and `try_verify_requests_uncertified_cross_term_parent`. The rest,
  from `try_verify_only_resolves_ancestry_once_certification_requested` to the end, is
  done (p2p lane, 2026-11-18) in voter/state_late_test.zig, with planted bugs per group,
  plus a zigware-only replay-binding test (no state.rs case fails when replay drops a
  vote's parent binding). Covered by state_test.zig's own cases instead:
  `term_length_one_nullification_advances_by_one`. With view spans and the state metrics
  on main, `decided_views_close_their_view_span` and the `issuance_window_probes` check
  are ported too: every state.rs test has a counterpart. Ingress: done (resolver/ingress_test.zig,
  voter/ingress_test.zig). Actor metrics: simplex owns them again.
  Resolver actor.rs (resolver/actor_test.zig): every handler-level case is ported, from
  `scan_fetches_issue_as_one_batch` through `validate_rejects_finalization_from_different_
  epoch`, plus a zigware-only below-view notarization rejection (a servable-view plant
  survived every ported case). The 7 cases that run the whole actor on p2p's simulated
  network are in resolver/actor_network_test.zig (2026-11-18): both targeted-backfill
  cases, retry delay vs request timeout (on `requests_sent_total`), member without a
  share, untargeted parent fetch, served requests holding channel capacity, and unresolved
  delivery not blocking a nullification fetch. The inert and rate-limited senders are
  test-local `TestSender`/`SilentReceiver` types. `pr_5097_regression` is ported: `HandlerMessage.deliver`
  carries an owned root copy of the fetch's span (`span: ?*Span`), and processing runs
  under `simplex.resolver.deliver` as its child. `Handler.deliver` keeps an owned copy of the
  first subscriber's fetch span (`resolver.own_span`), and the test runs through it.
- [x] simplex mod.rs tests. Every `test_for_all_fixtures` callee runs on all 8 fixtures:
  fixtures_test.zig ports 16 (all_online, one_offline with its metrics, partition,
  slow_and_lossy_links, backfill, slow_validator, all_recovery, all_crash_after_nullify,
  unclean_shutdown, determinism, the conflicter, nuller, impersonator, reconfigurer, and
  outdated Byzantine DSTs, and twins), plus distinct_states, and engine_test.zig, a generic
  `Suite(F, selected)`, runs the other 11 (equivocator, invalid,
  received_certificates_are_reported, survives_burst, children_shutdown_on_engine_abort,
  graceful_shutdown, attributable_reporter_filtering, split_views_no_lockup, hailstorm,
  observer, non_genesis_floor_joiner). ed25519 runs every engine_test DST in every build
  (Debug shrinks them, `quick`). Per push, ReleaseSafe runs a quick slice of fixtures_test
  on one fixture per scheme family (without twins and partition, about 40 and 50 s each);
  engine_test's Suite on the other seven fixtures, the per-fixture twins and partition,
  and every twins campaign but "twins sampled" run in slow builds (nightly), at full size,
  to keep per-push CI near its 25-minute target. The engine reports through
  `AttributableReporter` only in attributable_reporter_filtering, as commonware does. The
  twins campaigns (sampled, pipelined handoff, sustained, stable leader, optimistic; the
  large ones in slow builds), tle, the four slow-certifier DSTs, the certified splits and
  cross-term certified splits, hailstorm and floor joiner with a stable leader, and
  dishonest_leader_certification_rejected are ported. The 13 DSTs left by the 2026-11-19 audit are in
  engine_optimistic_test.zig (broadcast-collector lane, on engine_test's harness), each on the
  fixture commonware runs it on: ed25519 for the three pipelined_handoff DSTs,
  stable_leader_optimistic_blocks_faster_than_network_latency,
  stable_leader_finalizes_full_term_without_nullification, and the stable-leader optimistic
  unclean_shutdown, backfill, partition, slow_and_lossy_links, and equivocator; the mock
  scheme (`MockFixture`) for one_offline_stable_leader and 1k; threshold VRF MinPk on two
  Rayon threads (`RayonVrfFixture`) for all_online_rayon. Per push: Debug runs the four
  latency DSTs (40 measured views rather than 100) and the parent-nullify one; ReleaseSafe
  also runs the stable-leader variants and rayon (quick sizes, about 17 s and 6 s); the
  1000-view full term and 1k run in slow builds. A fixture with `harness_only` hosts only
  these (engine_test's DSTs skip it). Since 2026-11-19 the VRF scheme verifies and recovers
  through its strategy (joined vote and seed batches, as in commonware), so the rayon DST
  fails on a Rayon chunking bug.
- [x] mod.rs remainder: the 13 DSTs named above, ported by the broadcast-collector lane on
  2026-11-19 (engine_optimistic_test.zig).
- [ ] actors/voter/mod.rs: the 96 voter-actor tests (restart and floor journaling, the
  pipelined handoff build lifecycle, nullify on failed or dropped propose and verify,
  certification ordering and replay). None are ported; they need a voter-actor harness
  with a mock batcher, resolver, and automaton on the deterministic runtime. Handed to the
  runtime lane on 2026-11-19 (actors/voter/tests/).
- [x] actors/batcher/mod.rs: all 76 tests ported (2026-11-19). Lookup (T-01a1d59c) landed
  6 in actor_late_test.zig (8905ff8, ed25519): 4935 conflicting votes, 6506 and 6513
  same-term optimistic future votes, 6819 and 6966 activity-window reporting, and 7128
  constructed votes not future-bounded. Round-level ones in round_test.zig: forwarding
  a notarization's proposal without a leader, certificate vote release and retention,
  nullify-finalize conflicts with held and compacted evidence, our own votes reported
  once, finalization- and finalize-established proposals, both skipped-round cases, and
  conflicting-finalize evidence; in actor_test.zig, a future
  notarization forwarded without a leader, a tampered certificate blocking its sender,
  vote and certificate deduplication, skipping votes for finalized views, and blocking a
  resent notarize or finalize with another attestation, and votes below the current view
  (reported but not assembled; with historical votes, conflicts detected), and a buffered
  next-term lane quorum assembling on term entry.
  verifier.rs: 29 of its 32 have counterparts
  (lazy vote buffers, quorum reservations, the ready, exact-quorum, empty-pending, and
  verified-quorum cases, late leader votes, non-batchable finalize accounting, and nullify
  and finalize bookkeeping, 2026-11-19); its 3 panicking cases are not ported (below).
- [x] Panicking tests are not ported: Zig test runners cannot catch a panic in process.
  These are commonware's `#[should_panic]` cases in elector.rs (3), types.rs
  (`issue_2944_regression_*_new`, 2), vrf.rs (12 constructor and certificate-verifier
  checks), mocks/twins.rs (`route_with_groups_panics_when_sender_is_missing`,
  `cases_panic_on_scenario_overflow`, `cases_reject_more_than_64_participants`,
  `route_panics_when_sender_is_missing_from_participants`), voter/round.rs (the 2
  replay-conflict cases), and batcher verifier.rs (3). Each guarded path asserts or panics
  in the Zig code. mocks/twins.rs `route_with_groups_covers_reachable_split_targets`
  has no counterpart because routing here takes participant-index masks
  (`route_masks`, covered by the route tests), and
  `compressed_counts_match_reference_enumeration` would need commonware's 200-line
  brute-force enumerator; the single-round space is checked against its closed form.
- [x] Tracing: actor events are done (voter, batcher, resolver, engine). The voter opens
  commonware's `simplex.voter.start`, `.timeout`, `.process`, and `.notify` spans, and
  events inside them carry them. Each view's root `simplex.voter.view` span opens on entry
  and closes once decided; `.propose`, `.verify`, `.certify`, `.notify`, and `.timeout`
  nest under it while open. Our spans are plain values with no identity, so a round keeps
  only its span state and the root is rebuilt as the parent (the same output as
  commonware's stored span). The batcher adopts the voter's view span on `update`
  (`simplex.batcher.process`, `.verify_certificate`, and certificate construction nest
  under it). The resolver opens `simplex.resolver.process`, `.deliver`, and `.validate`;
  `process` and `deliver` are roots because mailbox and fetch spans are not carried across
  tasks. Not ported: spans no event of ours is emitted in (journal sync/prune, replay,
  produce, resolved, fetch, batcher construct). The voter state machine's 11 events
  (state.rs 7, round.rs 3, slot.rs 1) are emitted by State under commonware's `state`,
  `round`, and `slot` targets inside the voter's open span (2026-11-19); proposals are
  traced as their round and parent, since `Proposal` has no formatter. The view-1 leader
  election at genesis happens before the voter hands the state its tracer, so it is not
  traced.
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
- 2026-11-18: simplex actor metrics (voter, voter state, batcher) with commonware's names,
  help, and labels, registered under the engine's `voter`, `voter_state`, and `batcher`
  scopes. DST validators get per-node scopes (`validator{public_key}`, twins
  `<role>{index}`); one_offline checks the offline leader's timeouts and nullifications;
  twins handoff counts early votes. Histograms now hold up to 40 buckets (`LATENCY` has 36).
- 2026-11-18: simplex view spans (voter roots, batcher adoption) with propose, verify,
  certify, batcher process/verify_certificate, and resolver process/deliver/validate spans.
- 2026-11-18: pr_5097_regression: resolver deliveries run under their fetch's span.
- 2026-11-18: the 7 networked resolver actor.rs cases (actor_network_test.zig).
- 2026-11-18: fixtures_test.zig runs one_offline (with its metric checks), partition,
  slow_and_lossy_links, backfill, and commonware's per-fixture `twins` on all 8 fixtures.
  twins_campaign_test.zig is a generic `Suite(F)`. Slow builds (nightly) run full sizes;
  ReleaseSafe runs a quick slice (fewer views, shorter waits, one twins case per fixture:
  3 min for every fixture DST together); Debug skips them.
- 2026-11-19: The message conformance hashes, the large twins campaigns, and all-fixtures
  all_online run only in slow builds (nightly), in every mode. commonware hashes all
  `default_cases` vectors together, so a smaller count can't be checked. The per-push fixture
  slice runs one fixture per scheme family (VRF MinPk, standard MinSig, multisig MinPk,
  secp256r1): about 1 min in ReleaseSafe.
- 2026-11-19: The resolver `Handler.deliver` keeps an owned copy of the first subscriber's fetch
  span (`resolver.own_span`), so pr_5097_regression now runs through the handler, as in
  commonware.
- 2026-11-19: slow_validator, all_recovery, and all_crash_after_nullify run on every fixture
  (`Cluster.slow`, `Cluster.crash_all`). The quick ReleaseSafe slice of every fixture DST
  takes 2 min together.
- 2026-11-19: unclean_shutdown runs on every fixture, with a fixed-rng fixture
  (`Cluster.start_with`) and short timeouts (`Options.short_timeouts`).
- 2026-11-19: determinism (1 seed per push, 5 in slow builds), distinct_states (slow builds),
  and the conflicter, nuller, impersonator, reconfigurer, and outdated DSTs run on every
  fixture (`Byzantine(F)`, `Cluster.start_byzantine`). Every fixture DST's quick slice now
  takes 3 min together in ReleaseSafe.
- 2026-11-19: engine_test.zig is a generic `Suite(F, selected)`, so every
  `test_for_all_fixtures` DST runs on all 8 fixtures. limits.rs's widest encodings,
  types.rs's wrong-namespace, wrong-scheme, sub-quorum, and fault-evidence tests (all 8
  schemes), vrf.rs's attributability and verifier-only checks, and 6 more twins.rs cases are
  ported. An audit against commonware's simplex tests found 453 of 724 ported (counting
  macro expansions per fixture); the voter and batcher actor tests are the open gap. All 21
  simplex conformance entries match; commonware has no simplex benches.
- 2026-11-19: CI time: "all fixtures: twins", "all fixtures: partition heals", the
  non-ed25519 engine_test Suite instances, and four of the five mock-scheme twins campaigns
  (all but sampled) run in ReleaseSafe only with `-Dslow-tests`; Debug keeps its one-case
  campaigns.
- 2026-11-19: batcher actor_test.zig ports the 8 leader-activity tests on 5 validators with
  skipping enabled: fail-open while the network is quiet, inactivity after quorum
  activity, the leader-nullify fast path after an inactivity hint, leader nullifies and
  relayed certificates counting as activity, and the view-entry and wrong-view nullify
  hints.
- 2026-11-19: batcher actor_test.zig ports the 11 forwarding tests: silent-voter and
  silent-leader forwards on view advance (local and network notarizations), self and
  member-only exclusion, conflicting and nullify-only voters included, finalize voters
  excluded, and the leader's proposal reaching the voter before, after, and ahead of the
  leader update. The harness records relay forwards and takes `forward`, `member_only`,
  `view_retention`, and `floor` options. Split: lookup (T-01a1d59c) ports 4935, 6506,
  6513, 6819, 6966, and 7128 in actor_late_test.zig.
- 2026-11-19: the batcher actor harness is generic (actors/batcher/actor_harness.zig,
  `Kit(S, make)`); the quorum-to-notarization actor test runs on all 8 schemes, and
  round_scheme_test.zig ports mixed trusted and pending certification, optimistic assembly
  fallback (both quorum shapes, every scheme), per-kind fallback isolation, VRF seed-only
  corruption, the constructed quorum before a leader update, and the constructed leader
  notarize counted once. BLS cases run outside Debug or with `-Dslow-tests`.
- 2026-11-19: the rest of my batcher mod.rs share: Round restores (constructed finalize,
  notarization-restored finalizes), local certificate authority, kind priority, no mixed
  finalizes across an override, a filtered finalize's conflict still reported; in the
  actor, buffered finalizations drained by the leader's notarize, a network notarization,
  or one pass over every ready kind, future finalizes unlocked by their notarization and
  an old notarization after its nullification (both on every scheme), the VRF
  optimistic-recovery fallback with its block and counter, and verification on a
  two-worker pool.

- 2026-11-19: voter state tracing: leader elected, proposal set from a certificate and
  certificate equivocation (round), occupied-slot warning (slot), entry certificate not
  found, finalize withheld after a same-term nullify, missing parent during proposal,
  failed verification and uncertified ancestry, certification precheck failure, and an
  optimistic ancestor missing its nullification (state).
- 2026-11-19: open item, assigned to broadcast-collector (T-01a1d58d): the threshold schemes
  ignore `strategy` (`_ = strategy;` in vrf.zig's five verify and assemble paths, and in
  bls12381 certificate/threshold.zig), so all_online_rayon cannot catch a strategy bug.
- 2026-11-19 (runtime lane, voter mod.rs port): the voter now checks `next_timeout()` before
  releasing a held handoff candidate, as commonware's biased `select_loop!` polls
  `sleep_until(deadline)` ahead of `propose_wait`. Before, a leader timeout that expired
  while the parent's certification sync was parked still let the candidate be voted
  (test_pipelined_handoff_held_build_becomes_ineligible_at_leader_timeout). Open: the inbox's
  `next_event` still returns a queued event ahead of an already expired deadline.
- 2026-11-19 (runtime lane): the inbox's `next_until` now returns null for an already
  expired deadline even with events queued, closing the item above: commonware's biased
  `select_loop!` fires `sleep_until(deadline)` before any other branch. Only the voter
  passes a deadline; the batcher and resolver call `next()`.
- 2026-11-19 (runtime lane): voter mailbox messages are processed under commonware's enqueue
  span (`simplex.voter.mailbox.proposal`, `.timeout`, `.recovered`) as the parent of
  `simplex.voter.process`. Zig spans are stack values, so the voter opens that span from the
  message when it processes it, with the message's epoch, view, and reason or certificate
  kind; the enqueuing task's own span ancestry is not carried. Ported for
  `test_view_spans_track_automaton_boundary` (actors/voter/tests/spans.zig).
- 2026-11-19: upstream drift audit (crypto lane) from the simplex test audit's reference
  commit 43b357a41 to a9ffc25f3. 162216038 is lint-only (redundant `.clone()`s in mod.rs
  tests and the outdated/reconfigurer mocks); 883eae27e moves `consensus/fuzz/src` to
  `consensus/src/fuzz` with an unchanged run harness, puts the twins and wrapped mocks under
  an ALPHA stability scope, and replaces proptest with minifuzz. No actor, engine, or type
  behavior drifted. Ported from 883eae27e into fuzz/simplex.zig: `Scheme`, `ConnectedPlan`,
  and `Plan` (drawn in commonware's `Arbitrary` order, including the one-variant scenario
  tag), a per-push test that decodes a fixed plan and runs it on ed25519, and, under
  `-Dslow-tests`, test_fuzz_plan, test_connected_boundaries, and the six
  `minifuzz_*_connected` (search limit 100, 30 containers each). Each draw-order plant
  (term and handoff swapped, scenario tag skipped) fails the per-push test.
