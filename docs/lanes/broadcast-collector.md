# Lane: broadcast-collector

Owns `src/broadcast` and `src/collector` (moved from broadcast-resolver, which keeps
`src/resolver`). Worked by the actor-stream thread after its backlog finished.

Reference: `~/.cache/zigware/commonware-ref/{broadcast,collector}` (about 5.7k Rust lines).
Both are actors over p2p. They build on `actor.mailbox`, `p2p` (lib types and
`p2p.simulated`, API in docs/lanes/p2p.md), the deterministic runtime,
`runtime.telemetry.metrics`, and `cryptography` (certificate schemes, mocks).

broadcast `buffered` comes first: consensus marshal (T-01a1d5ef-5571-7424-8220-609c9811da57)
needs it.

Also owns `src/consensus/marshal/coding/`, marshal's erasure-coded variant
(`consensus/src/marshal/coding`, about 18k Rust lines), and its `pub const coding` line in
`marshal/root.zig`. consensus-marshal keeps everything else in marshal: core (the `Variant`
and buffer contracts in `core/variant.zig`, Actor, Mailbox), standard, ancestry, store,
limits, config, application, resolver, conformance, and mocks, including the shared test
harness. The coding parts of commonware's `mocks/harness.rs` (`CodingHarness`, `CodingB`,
`CodingCtx`, `make_coding_block`, `genesis_commitment`) go in `coding/harness.zig` on top of
that harness. It builds on `coding` (ReedSolomon), `consensus.types.coding.Commitment`,
`broadcast.buffered`, `resolver.p2p`, and `storage.archive`.

## Public API (on main)
- `broadcast.assert_broadcaster(B)`: `B.Recipients`, `B.Message`, `b.broadcast(recipients,
  message)` returning `Feedback` (in an `Allocator.Error!` union when it may allocate).
- `broadcast.buffered.Engine(M, D, B, N)`: `M` is Digestible (`M.Digest`, `digest()`) and a
  codec type (decoded with `Config.codec_config`, freed with `M.deinit(gpa)`), `D` a p2p
  `Manager` (peer sets), `B` a `Blocker`, `N` provides `N.Sender`/`N.Receiver`
  (`p2p.simulated.Network(P)` does). `Engine.init(gpa, io, &scope, Config) !{engine,
  mailbox}`; `engine.start(sender, receiver) !Io.Future(Error!void)` takes ownership of the
  network; cancel the future to stop it (the engine frees itself). Metrics register under
  `scope` (`peer`, `receive`, `subscribe`, `get`, `waiters`), `scope_mailbox_backoff`, and
  `scope_ingress_decode`.
- `broadcast.buffered.Mailbox(P, M)` (a Broadcaster): `broadcast(recipients, Digested(M))
  !Feedback` (takes the handle, copies `some` recipients), `subscribe(digest)
  !oneshot.Receiver(Digested(M))` (`error.Closed` once the engine stopped), `get(digest)
  !?Digested(M)` (caller owns the handle), `clone`, `deinit`.
- `broadcast.buffered.mocks.TestMessage` (`init`, `shared`, codec with `RangeCfg(usize)`).
- `broadcast.Digested(T)` (`digested.zig`): a shared, reference-counted value with its
  digest (commonware's `Arc<T>` form; `cryptography.Digested` borrows): `compute(gpa, value)`, `precomputed(gpa, value, digest)`, `inner`, `digest`,
  `clone`, `deinit`/`discard`, `eql`, codec `write`/`encode_size` (no decoding).
- `collector.assert_originator`, `assert_handler`, `assert_monitor` (lib.rs traits).
  `Handler.process(*H, origin, request, oneshot.Sender(Response))` and
  `Monitor.collected(*M, handler, response, count)` may return an error union.
- `collector.p2p.Engine(H, M, B, N)`: request and response types come from the handler.
  `Engine.init(gpa, io, &scope, Config{blocker, monitor, handler, mailbox_size,
  priority_request, request_codec, priority_response, response_codec}) !{engine, mailbox}`
  (the engine owns and `deinit`s the handler and monitor); `engine.start(request_sender,
  request_receiver, response_sender, response_receiver) !Io.Future(Error!void)`.
  `N.RequestSender`, when declared, types the request sender. Metrics: `outstanding`,
  `requests_total`, `responses_total`, `mailbox_backoff_total`.
- `collector.p2p.Mailbox(P, R)` (Originator): `send(recipients, request) !Feedback`,
  `cancel(commitment) !Feedback`, `clone`, `deinit`.
- `collector.p2p.mocks`: `types.Request`/`types.Response`, `Handler`, `Monitor`, `Failing`.

- `consensus` marshal coding types (`src/consensus/marshal/coding/types.zig`; `B` the
  application block, `C` a coding scheme, `H` the context hasher):
  `Shard(B, C, H)` (`init(commitment, index, inner)`, owns its inner shard and bytes;
  `commitment()`, `clone(gpa)`, `deinit(gpa)`, `eql`, codec with cfg = largest block size,
  `max_encode_size`), `CodedBlock(B, C, H)` (`encode(gpa, Digested(B), config, strategy)`,
  `precomputed(Digested(B), commitment)`, `from_decoded(gpa, B, config, expected, strategy)
  DecodeError!` with `expected` a `.trusted`/`.untrusted` commitment, `shards(gpa, strategy)`
  (coded on demand), `shard(gpa, index) !?Shard`, `inner`, `inner_digested`, `commitment`,
  `digest`, `parent`, `height`, `context`, `clone`, `deinit(gpa)`, `eql`, write-only codec),
  `StoredCodedBlock(B, C, H)` (`init(CodedBlock)`, `from_shared`, `into_coded_block`, codec
  with `B`'s cfg), `DecodeError`, `CommitmentOf(B, C, H)`, `hash_context(H, gpa, context)`,
  `coding_config_for_participants(n)`.

## Decisions
- `broadcast.Digested` owns its value (reference counted) because the cache, waiters, and
  responders share values decoded from the network; `cryptography.Digested` borrows. It
  hashes inline (commonware runs the hash as a job on a `Strategy`).
- No `Strategy` in the buffered config: p2p's `WrappedBackgroundReceiver` is not ported, so
  the engine's ingress task decodes inline (commonware with `Sequential`), blocks peers whose
  messages fail to decode, and drops decoded messages beyond the receiver's capacity. It
  records `ingress_decode{status}`; its internal mailbox's always-zero backoff counter is not
  registered.
- The engine's `select_loop!` is a signal (mutex and condition) fed by an ingress task and
  two forwarders with one-item slots, checked in commonware's biased order: peer sets,
  mailbox, network. The initial peer set is applied before any queued request.
- Overflow `drain` peeks at the front request and pops it only once the inbox accepts it, so a
  rejected broadcast stays indexed for coalescing without the reinsert allocation.
- collector: the engine's `select_loop!` is the same signal design (biased: mailbox,
  handler replies, requests, responses); each handler reply is awaited by its own task in an
  `Io.Group` (commonware's futures `Pool`). Commonware's collector has no conformance hashes
  (its wire is the request and response encodings, which the mocks check byte for byte).
- `count_running_tasks` has no counterpart; the shutdown tests check that aborted engines free
  everything (testing allocator) and close their mailboxes.
- Fuzz: `broadcast/fuzz.zig` (`broadcast_engine_operations`) and `collector/fuzz.zig`
  (`collector`) draw their inputs like commonware's `arbitrary` impls, and the `Recipients::Some`
  shuffle is rand 0.10's `SliceRandom::shuffle` (checked against rand 0.10.3 vectors). Each has
  a minifuzz test, a coverage-guided `testing.fuzz` test, and a seeded random-input test: the
  generators never run out of data, so minifuzz keeps its 8-byte start and only reaches the
  first action, while random inputs reach gets, subscriptions, engine restarts, and replies.

- marshal coding types: a `Shard` owns its inner shard's bytes (decoding copies them out of
  the message; `CodedBlock.shard` copies them out of the shared encoding), where commonware
  shares `Bytes`. `CodedBlock.from_decoded` returns `ConfigMismatch`, `BlockDigestMismatch`,
  `RecommitFailed`, or `CommitmentMismatch` for commonware's `Invalid("CodedBlock", ...)`
  messages. Strategy jobs run inline. The two `should_panic` tests and the iobufs test have
  no counterpart.

- marshal coding validation: `validate_proposal(H, gpa, commitment, config, ?context)`,
  `validate_block(H, gpa, epocher, *block, *parent, context, commitment, parent_commitment)`,
  `validate_reconstruction(H, gpa, *block, config, commitment, strategy)`; errors carry no
  payload (commonware's `ContextDigest(expected, actual)` is plain `ContextDigest`). A
  context's epoch is its `epoch()` method or, for `Round`, its field.

- marshal coding shards: reconstruction runs inline when enough shards are held (commonware
  runs a strategy job and completes it as an event), so a record never holds an in-flight
  job; the tests that drive jobs by hand (`finished`, unstarted engines) check the same
  outcomes through the mailbox. The engine's event loop follows the buffered broadcast
  engine: forwarder tasks feed one signal in commonware's biased order (peer sets, mailbox,
  network). Tests that drive commonware's unstarted engine call its public handlers
  (`handle_gather`, `handle_network_shard`, `disperse_shards`, `cache_block`, `trim`,
  `subscribe_assigned`, `subscribe_commitment`) after `attach_sender` and
  `update_primary_peers`, and inspect `records` and `buffered`.

## Backlog
- [x] broadcast lib.rs traits.
- [x] broadcast buffered: config, ingress, metrics, engine, mocks, with every mod.rs test on
  p2p.simulated (commonware has no broadcast conformance hashes).
- [x] collector lib.rs, p2p ingress (overflow policy), engine, mocks, with every ingress.rs
  and mod.rs test (commonware has no collector conformance hashes).
- [x] Fuzz targets (broadcast/fuzz, collector/fuzz).
- [x] marshal coding `types`: Shard, CodedBlock, StoredCodedBlock, `hash_context`,
  `coding_config_for_participants`, with their tests and the Shard conformance hash.
- [x] Coding tests on `marshal.mocks.block.EmptyBlock`; `pub const coding` in marshal/root.zig.
- [ ] Once ancestry and application land: move validation's copies of `has_contiguous_height`
  and `is_block_in_expected_epoch` to `marshal.ancestry` and `marshal.application.validation`.
- [x] marshal coding `shards`: mailbox, metrics, reconstruction state, engine, e2e test.
- [ ] marshal coding `shards`: the rest of engine.rs's tests (25 of about 70 ported: the
  window, subscription, epoch, assigned-shard, leader duplicate and equivocation, and
  failed-reconstruction tests).
- [ ] marshal coding `variant` (Coding) against core's `assert_variant` (with `clone_block`,
  `deinit_block`) and `assert_buffer` on the shards Mailbox.
- [x] marshal coding `validation` (proposal, block, reconstruction) with its 17 tests.
- [ ] marshal coding `variant` (Coding), `marshaled` (Marshaled, MarshaledConfig), once
  consensus-marshal's core lands.
- [ ] marshal coding: `coding/harness.zig` and the `coding/mod.rs` tests, once the shared
  harness lands; the coding fuzz entries in `consensus/fuzz`.

## Log
- 2026-11-13: broadcast lib.rs and buffered (engine, mailbox, overflow policy, metrics,
  mocks) with all 27 mod.rs tests; `broadcast.Digested`.
- 2026-11-13: collector lib.rs traits and p2p engine, mailbox, mocks, with 5 policy and 13
  engine tests.
- 2026-11-16: broadcast and collector fuzz targets (minifuzz, coverage-guided, and seeded
  random inputs).
- 2026-11-16: marshal coding types (Shard, CodedBlock, StoredCodedBlock); the Shard
  conformance hash matches.
- 2026-11-16: marshal coding validation with its 17 tests.
- 2026-11-16: marshal coding shards engine (mailbox, metrics, state, engine) with the e2e
  dispersal test; coding moved onto `marshal.mocks.block` and marshal/root.zig.
- 2026-11-16: 24 more shards engine tests: fixture tests on p2p.simulated and handler tests
  on an unstarted engine (`engine_harness.zig`).
