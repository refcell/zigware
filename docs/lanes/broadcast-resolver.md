# Lane: broadcast-resolver

Owns `src/resolver`. `src/broadcast` and `src/collector` moved to the broadcast-collector
lane (docs/lanes/broadcast-collector.md).

Reference: `~/.cache/zigware/commonware-ref/{broadcast,resolver,collector}`. All three are
actors over p2p (`actor` mailbox on main, p2p's lib types on main, p2p `simulated` landing
now). Start with the parts that need only codec, cryptography, utils, and actor: the lib.rs
traits, wire formats (resolver p2p/wire.rs, collector p2p wire), and the pure state
(fetcher, inflight, score, subscribers, delivery); then the engines and the multi-peer tests
on p2p's simulated network and the deterministic runtime.

## Public API (on main)
- `resolver.Fetch(K, S)` (`key`, `subscriber`, `from_key`, `order`), `resolver.Delivery(K, S)`
  (`key`, `subscribers: []const S`), `resolver.Outcome` (`invalid`, `resolved: Resolution`,
  `unresolved`, `ignored`; `from(Outcome or bool)`), `resolver.Resolution`,
  `resolver.Predicate(K, S)` (inline-captured retain predicate: `init(captured, fn)`, `call`),
  `resolver.order`/`eql` (codec order, `void` subscribers equal).
- Interface checks `assert_consumer`, `assert_resolver`, `assert_targeted_resolver` (decls at the
  top of `src/resolver/root.zig`).
- `resolver.subscribers.Tracker(K, S)`: `insert`, `remove`, `clear`, `retain(gpa, predicate,
  *removed)`, `pending` (borrowed, ascending), `remove_delivered`, `contains`, `count`.
- `resolver.p2p.wire`: `Message(Key)` (`id`, `payload`), `Payload(Key)` (`request`,
  `response: codec.Bytes`, `error`), `request_overhead`, `response_overhead_max`,
  `max_message_size(Key, value_size)`; commonware's two conformance hashes match.
- `resolver.ingress`: `Message(K, S, M)` (mailbox message: `fetch: Batch`, `retain: Predicate`;
  `fetch_one`, reliable `handle` that coalesces by key, `discard`), `FetchKey(K, S, M)`,
  `Pending(K, S, M)` (the overflow), `Targets(P)` metadata (null = unrestricted).
- `resolver.delivery`: `Tracker(C, Context, State)` (`init(gpa, io, consumer)`, `insert`,
  `insert_with_state`, `remove`, `remove_with_state`, `take_state`, `state_mut`, `retain`,
  `drain`, `deliver`, `redeliver`, `accept_response`, `response_accepted`, `discard_response`,
  `next_completion` (`error.Aborted` for a canceled delivery without a verdict),
  `try_next_completion`, `pending`) and `Completion(K, S, Context)` (owns its subscribers).
- Consumer contract: `C.Key`, `C.Value`, `C.Subscriber`, `C.Outcome` (`bool` or `Outcome`),
  `deliver(self, Delivery, value) !utils.channel.oneshot.Receiver(C.Outcome)`, optional
  `deinit_value(gpa, value)`.
- `resolver.@"opaque"` (commonware `opaque`; `opaque` is a Zig keyword): `Actor(F, C)` with
  `spawn(P, gpa, io, scope, fetcher, consumer, config)` returning `.{ resolver, future, actor }`
  (stop: `resolver.deinit()`, then `future.await(io)`), `create`/`run`/`destroy` for driving
  it by hand, `fetch_count(status)`; `Resolver(K, S, P)` handle (`fetch`, `fetch_all`,
  `retain`, `fetch_targeted`, `fetch_all_targeted`, `clone`, `deinit`); `Config`
  (`mailbox_size`, `fetch_retry_delay_ns`); `Status`. Fetcher contract:
  `fetch(self, io, key) Io.Cancelable!?Value`. Metrics: `<scope>_actor_fetch_total{status}`.
- `resolver.Targeted(K, S, P)` (`fetch`, `targets`); `resolver.delivery.Signal` and
  `Tracker.init_with_signal`, `has_completion_locked`, `close_canceled` for actors that wait
  on one signal.
- `resolver.p2p.score.Score` (`record(elapsed: utils.Duration, bytes: u64)`, `weight() u64`).
- `resolver.p2p.Fetcher(P, Key)` (commonware `p2p::fetcher`): `init(gpa, io, scope, Config(P))`
  (`me`, `fetch_timeout`, `retry_delay`, `priority_requests`), `fetch(*sender)` over any p2p
  limited sender, `add_ready`, `add_retry`, `retain(predicate with call(key))`,
  `get_pending_deadline`, `get_active_deadline`, `pop_active`, `pop_response(id, peer)`,
  `record_response`, `pop_missing`, `reconcile(peers)`, `set_blocked(peers)`, `add_targets`,
  `clear_targets`, `clear`, `has_targets`, `targets_of`, `len_pending`, `len_active`.
  Metrics: `peer_performance{peer}`, `requests_created{status}`, `requests_sent{status}`,
  `resolves` (network buckets).
- `resolver.p2p.Engine(resolver.p2p.engine.Params(P, Provider, Blocker, Consumer, Producer,
  NetSender, NetReceiver))` (commonware `p2p::Engine`): `spawn(gpa, io, scope, Config, sender,
  receiver)` returns `{ mailbox, future, engine }` (new + start); stop with `mailbox.deinit()`
  then `future.await(io)`, or abort with `future.cancel(io)`; the engine frees itself either
  way. `create`/`run`/`destroy` drive it by hand. Metrics under `scope`: `fetch_pending`,
  `fetch_active`, `serve_processing`, `fetch_total{status}`, `cancel_total{status}`,
  `serve_total{status}`, `serve_duration`, `fetch_duration`; the fetcher's under
  `scope.child("fetcher")`.
- `resolver.p2p.Config(P, D, B, C, Pro)`: `peer_provider`, `blocker`, `consumer`, `producer`,
  `mailbox_size`, `me: ?P`, `fetch_timeout`, `fetch_retry_delay`, `priority_requests`,
  `priority_responses`.
- `resolver.p2p.Mailbox(K, P, S)` (a TargetedResolver): `fetch`, `fetch_all`,
  `fetch_targeted`, `fetch_all_targeted`, `retain`, `clone`, `deinit`; each returns
  `Allocator.Error!Feedback` and reports closed after shutdown.
- Producer contract (`resolver.p2p.assert_producer`): `Key` and
  `produce(self, key) !oneshot.Receiver(resolver.p2p.Produced)`; `Produced{ bytes, gpa }` is
  freed by the engine; closing the receiver without a value means "no data". Blocker:
  `block(peer) Feedback` and `blocked()` returning a subscription with `recv(gpa) !?[]P`
  (null once closed). Provider: `subscribe()` (p2p `Manager`).
- `resolver.p2p.inflight.Inflight(C, P)` (delivery tracker with `Source{peer, elapsed,
  bytes}` context and a fetch-duration timer per key).
- `resolver.p2p.mocks.Key` (one-byte test key), `resolver.p2p.mocks.Consumer(K, S)` (byte
  values, expected values, `next_event`/`try_event`, events carry their subscribers),
  `resolver.p2p.mocks.Producer(K)` (`init(gpa, io)`, `insert`, `produce`, `deinit`).
- Small addition in p2p's directory: `p2p.utils.watch` `Subscription.recv(gpa)` (blocks until
  a value, null once closed).
- Shared, in the utils directory (needed by the resolver fetcher): `utils.sampling.WeightedIndex`
  (`init(gpa, weights)`, `set`, `weight`, `total`, `sample(rng)`, `sample_uniform(rng)`,
  `without_replacement(gpa)`, `into_without_replacement(gpa)`) and `WithoutReplacement`
  (`sample`, `sample_uniform`, `is_empty`, `deinit` restores weights), matching commonware's
  draws; `utils.PrioritySet(I, P)` (`put`, `get`, `remove`, `reconcile`, `retain`, `peek`,
  `pop`, `items` ascending); `utils.rng.range_at_most`/`range_less_than` accept `u128`.
- Shared, in the utils directory at the coordinator's request: `utils.channel.oneshot`
  (`channel(T, gpa, io)` -> `.{ sender, receiver }`; `Sender.send` (consumes, `error.Closed`
  when refused), `is_closed`, `closed()` (wait), `deinit`; `Receiver.recv` (cancelable,
  `error.Closed`), `try_recv` (`Empty`/`Closed`), `close`, `is_ready`, `deinit`; values that
  own resources declare `discard`). tokio oneshot semantics over `std.Io` mutex/condition.

## Decisions
- Spans: `Fetch.span` is borrowed; ingress, the subscriber tracker, and the engines keep an
  owned root copy per subscriber (`resolver.own_span`: our spans point at their parents, so a
  copy drops them), first fetch wins. `Delivery.spans` pairs them with `subscribers`, borrowed
  for the consumer's `deliver` call. Ordering and equality ignore spans, as in commonware.
- `Delivery.subscribers` is a slice (never empty, asserted) instead of `NonEmptyVec`.
- Retain predicates are `Predicate(K, S)` values with inline captured state (at most 64 bytes)
  so they queue in a mailbox without allocation; generic code takes any `predicate` with
  `call(key, subscriber) bool`.
- `subscribers.Tracker.pending`/`remove_delivered` return borrowed slices instead of clones.
- resolver imports `conformance` (a dev-dependency in commonware) for its conformance test.
- Wire `Message` and `Payload` declare `write_bufs`/`encode_inline_size`, so
  `runtime.iobuf.encode_iobufs` pushes a response's value as its own chunk.
- Ingress batches carry the mailbox allocator (`Batch.gpa`) because the mailbox's `discard`
  takes none; `handle` asserts every batch uses the mailbox's allocator. The pending-fetch
  index hashes each key's codec encoding (Wyhash), so keys need a bounded encoding.
- The delivery tracker runs each verdict wait as a `std.Io` task (commonware's future pool)
  that queues finished slots; cancellation is decided when a completion is read and canceled
  receivers are closed then, matching commonware's biased `select!` and lazy close. The
  tracker owns cached values (freed through `C.deinit_value` when declared) and lends them to
  `deliver` for the call. `test_redeliver_requires_cached_response` (`should_panic`) is a
  death test (`utils.death`).
- `utils.channel.oneshot.Receiver.recv` returns `error.Closed` once the receiver is closed
  without a value (tokio behavior; the delivery tracker relies on it).
- Actors wait on one `delivery.Signal` instead of `select_loop!`: fetch and verdict tasks
  queue results and broadcast it, a forwarder task moves mailbox messages into a one-message
  inbox (keeping mailbox backpressure), and retry deadlines bound the wait. Each turn handles
  one event in commonware's arm order. Fetch aborts are `std.Io` cancelations.
- Metrics go to `runtime.telemetry.metrics` through a `Scope` the caller passes (it stands in
  for commonware's context). Status counters use runtime's `metrics.status.Counter`
  (`resolver.@"opaque".Status` is its `Status`).
- Seeded fuzz uses `p2p.fuzz.run` (the same driver as codec's). Fuzz bodies draw their
  operations from `smith.bytes` rather than `smith.value`/`eos`: on random seeded input,
  `value` of a small type returns its minimum and `eos` ends the input almost at once. Models
  derive expectations independently of the code under test (the fetcher model has its own
  pending order), and the delivery model polls several scheduling rounds because a verdict
  task can take more than one round to queue its completion.
- The p2p fetcher keeps peers, blocked peers, and per-key targets and retry counts in sorted
  arrays ordered by `codec.order` instead of hash maps; selection draws from `std.Io`'s
  randomness and time from `Io.Clock.real`, so it is deterministic under the deterministic
  runtime (sampling matches commonware's for the same random stream). Its tests reach into
  fields as commonware's do; `test_add_retry_duplicate_panics` is a death test.
- The p2p engine is generic over `Params(...)` (one type parameter) and uses forwarder tasks
  for peer sets, blocked sets, the mailbox, and the network that fill one-slot inboxes under
  the shared `delivery.Signal`; each turn handles one event in commonware's select order, then
  sends at most one due fetch. Serves run as tasks that wait on the producer's receiver.
- Engine tests run on `p2p.simulated` and the deterministic runtime (`engine_test.zig`,
  `engine_delivery_test.zig`). Commonware's `count_running_tasks` checks have no runtime
  counterpart: aborts await every engine task and `testing.allocator` reports leaks. The
  Blocking consumer mocks resolve gates on the test's task instead of a per-delivery task.
  `test_stale_response_after_requester_restart_is_ignored` runs on p2p's authenticated
  lookup network over the deterministic transport (`engine_lookup_test.zig`); answering the
  new request with the old value makes it time out, so it checks the request-ID guard.
- Beyond commonware's tests, a DST seed sweep (16 seeds) runs the engine on 50%-loss links
  with keys spread over three servers and a mid-flight retain: every kept key arrives exactly
  once with its value. A failing seed prints itself; the run replays from it.

## Backlog
- [x] resolver: lib.rs, subscribers, ingress, delivery, opaque (with metrics).
- [x] resolver p2p: wire.rs (conformance hashes match), score, fetcher (60 tests), inflight,
  config, metrics, engine, ingress, mocks; all 50 of commonware's mod.rs tests (49 on p2p
  simulated, the requester-restart test on p2p authenticated lookup).
- [x] Resolver fuzz targets (commonware has no resolver fuzz crate): wire decode is canonical;
  model checks of the subscriber tracker, ingress coalescing, the p2p fetcher state machine,
  and the delivery tracker lifecycle. Each model check was mutation-tested (a planted bug in
  the code under test fails within a few iterations).
- Moved to the broadcast-collector lane: broadcast and collector.

### Test audit: resolver (2026-11-19, commonware 43b357a41)

Drift check (commonware 43b357a41 to a9ffc25f3, p2p lane, 2026-11-19): 7de47bdd1 (issue 5720)
applies a verdict the consumer already sent before a fetch joins its key, so the verdict cannot
retire the new subscribers. Ported: `delivery.zig` `Tracker.try_completion` (with
`utils.channel.oneshot` `Receiver.is_resolved`), `p2p/inflight.zig` `try_delivery`, and calls at the
top of the p2p engine's and the opaque actor's `add_fetch`, with the three new tests: delivery.rs
`test_try_completion_takes_a_sent_verdict` ("try_completion takes a sent verdict"), and the
`issue_5720_regression` tests of p2p/engine.rs (engine_delivery_test.zig) and opaque.rs
(opaque_test.zig), each named "verdict sent before a repeat fetch does not retire it". Each fails
with its fix removed. As in commonware, a taken completion is reported once more as `error.Aborted`
(its abandoned wait), which both actors ignore. The existing "fetch after accepted verdict restarts"
passes even without the fix (the verdict task queues before the engine reads the fetch), so the
direct engine test is the one that covers it.

Every `#[test]`/`#[test_traced]`/`#[rstest]` fn in commonware `resolver/src`, matched to a zigware
test by name or by reading both bodies (a zigware test may cover several). 178 tests: 178 ported, 0
open, 0 not portable (the 8 inflight tests below are ported in src/resolver/p2p/inflight_test.zig).

| commonware file | tests | ported | open | not portable |
|---|---|---|---|---|
| `delivery.rs` | 9 | 9 | 0 | 0 |
| `ingress.rs` | 11 | 11 | 0 | 0 |
| `opaque.rs` | 13 | 13 | 0 | 0 |
| `subscribers.rs` | 5 | 5 | 0 | 0 |
| `p2p/fetcher.rs` | 58 | 58 | 0 | 0 |
| `p2p/inflight.rs` | 9 | 9 | 0 | 0 |
| `p2p/ingress.rs` | 7 | 7 | 0 | 0 |
| `p2p/mod.rs` | 51 | 51 | 0 | 0 |
| `p2p/score.rs` | 7 | 7 | 0 | 0 |
| `p2p/wire.rs` | 8 | 8 | 0 | 0 |

Ported since the audit:
- [x] `p2p/inflight.rs` `test_insert_contains_cancel_remove_round_trip`: Inflight
  insert/contains/cancel round trip, with a second cancel returning false. Goes in
  src/resolver/p2p/inflight.zig, which has no tests; delivery.zig "insert contains remove round
  trip" covers only the underlying Tracker
- [x] `p2p/inflight.rs` `test_cancel_suppresses_duration_metric`: Inflight.cancel after insert
  leaves the fetch-duration histogram count at 0. Goes in src/resolver/p2p/inflight.zig
- [x] `p2p/inflight.rs` `test_complete_records_duration_metric`: Inflight.complete after insert
  records one fetch-duration observation (count 1). Goes in src/resolver/p2p/inflight.zig
- [x] `p2p/inflight.rs` `test_retain_drops_non_matching_and_suppresses_metric`: Inflight.retain with
  an odd-key predicate drops 1 of keys 1..3, keeps 1 and 3, and the duration count stays 0. Goes in
  src/resolver/p2p/inflight.zig
- [x] `p2p/inflight.rs` `test_drain_removes_all_and_suppresses_metric`: Inflight.drain returns 2,
  removes both keys, and the duration count stays 0. Goes in src/resolver/p2p/inflight.zig
- [x] `p2p/inflight.rs` `test_deliver_completes_with_consumer_result`: Inflight.deliver(peer, 17ms,
  "data") -> next_delivery has the key, the Source{peer, 17ms, 4} context, a Complete outcome, and
  not canceled; the consumer saw (key, value). Goes in src/resolver/p2p/inflight.zig (delivery.zig
  "deliver completes with context and consumer result" covers only the Tracker with a u8 context)
- [x] `p2p/inflight.rs` `test_cancellation_preserves_ready_verdict_without_recording_duration`:
  After deliver then cancel (or drain), next_delivery is canceled but keeps the Source context and
  Complete outcome; the key is gone and the duration count is 0. Goes in
  src/resolver/p2p/inflight.zig (engine_delivery_test "cancellation preserves submitted verdict" is
  engine-level and checks no metric)
- [x] `p2p/inflight.rs` `test_cancel_after_completion_is_idempotent`: deliver -> next_delivery
  Complete -> complete(key); a later cancel returns false without asserting. Goes in
  src/resolver/p2p/inflight.zig

Ported on `utils.death.expect_panic` (9d412335), each failing with its panic removed:
- [x] `delivery.rs` `test_redeliver_requires_cached_response` ("redeliver requires a cached
  response", delivery.zig)
- [x] `p2p/inflight.rs` `test_complete_panics_on_missing_key` (inflight_test.zig)
- [x] `p2p/wire.rs` `test_max_message_size_beyond_prefix` (wire.zig)
- [x] `p2p/fetcher.rs` `test_add_retry_duplicate_panics` ("add retry of a pending key panics",
  fetcher_test.zig)

Not-portable review (2026-11-19, coding lane): before 6 (5 counted, plus the uncounted
`test_add_retry_duplicate_panics`). The two wire `encode_iobufs` tests were stale:
`runtime.iobuf` has existed since da3bee6. They are ported in p2p/wire.zig with
`Message.write_bufs` and `Payload.write_bufs`, and catch a response written with the request
tag. After: 4, all panic (zigware asserts or unwraps too), since ported as death tests.

## Log
- 2026-11-13: resolver lib.rs types, subscribers tracker, p2p wire (conformance hashes match).
- 2026-11-13: resolver ingress (coalescing mailbox policy, targets metadata).
- 2026-11-13: shared `utils.channel.oneshot` (tokio semantics over std.Io), with a model fuzz.

- 2026-11-13: resolver delivery tracker and mock consumer; oneshot recv wakes on close.
- 2026-11-13: resolver p2p score (throughput weights, commonware test values).
- 2026-11-13: resolver opaque actor (all 13 commonware tests) with the fetch metrics family.
- 2026-11-13: utils sampling (WeightedIndex, commonware vectors), PrioritySet, u128 ranges.
- 2026-11-13: resolver p2p fetcher with its commonware tests (exact score vectors match).
- 2026-11-16: resolver p2p engine, inflight, config, metrics, ingress, mock producer; 49 of 50
  commonware engine tests on p2p.simulated (held/gated verdicts, cancellation, shutdown).
- 2026-11-16: resolver fuzz targets: ingress, fetcher, and delivery tracker model checks.
- 2026-11-18: resolver.p2p engine stall under load fixed: forwarders wait on their own
  conditions (a timed engine wait consumed their wakes), network messages queue in a ring.
  Delivery completions and the opaque actor's waiters got their own conditions too.
- 2026-11-18: fetch spans carried per subscriber from `Fetch` to `Delivery` (p2p and opaque),
  with commonware's `each_subscriber_keeps_its_own_fetch_span`.
- 2026-11-18: marshal standard/mod.rs slice: `tests/common.zig` and `tests/floor.zig` (39 of
  43 tests; the 3 should_panic tests and the identity-job gate have no Zig counterpart).
