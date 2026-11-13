# Lane: broadcast-resolver

Owns `src/broadcast`, `src/resolver`, `src/collector`.

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
- `resolver.p2p.score.Score` (`record(elapsed: utils.Duration, bytes: u64)`, `weight() u64`).
- `resolver.p2p.mocks.Key` (one-byte test key), `resolver.p2p.mocks.Consumer(K, S)` (byte
  values, expected values, `next_event`/`try_event`).
- Shared, in the utils directory at the coordinator's request: `utils.channel.oneshot`
  (`channel(T, gpa, io)` -> `.{ sender, receiver }`; `Sender.send` (consumes, `error.Closed`
  when refused), `is_closed`, `closed()` (wait), `deinit`; `Receiver.recv` (cancelable,
  `error.Closed`), `try_recv` (`Empty`/`Closed`), `close`, `is_ready`, `deinit`; values that
  own resources declare `discard`). tokio oneshot semantics over `std.Io` mutex/condition.

## Decisions
- No tracing in zigware, so `Fetch`, `Delivery`, and the subscriber tracker carry no spans;
  ordering and equality ignore spans in commonware too.
- `Delivery.subscribers` is a slice (never empty, asserted) instead of `NonEmptyVec`.
- Retain predicates are `Predicate(K, S)` values with inline captured state (at most 64 bytes)
  so they queue in a mailbox without allocation; generic code takes any `predicate` with
  `call(key, subscriber) bool`.
- `subscribers.Tracker.pending`/`remove_delivered` return borrowed slices instead of clones.
- resolver imports `conformance` (a dev-dependency in commonware) for its conformance test.
- Wire `encode_iobufs` tests have no counterpart (no `IoBufs` yet; writes go to one buffer).
- Ingress batches carry the mailbox allocator (`Batch.gpa`) because the mailbox's `discard`
  takes none; `handle` asserts every batch uses the mailbox's allocator. The pending-fetch
  index hashes each key's codec encoding (Wyhash), so keys need a bounded encoding.
- The delivery tracker runs each verdict wait as a `std.Io` task (commonware's future pool)
  that queues finished slots; cancellation is decided when a completion is read and canceled
  receivers are closed then, matching commonware's biased `select!` and lazy close. The
  tracker owns cached values (freed through `C.deinit_value` when declared) and lends them to
  `deliver` for the call. `test_redeliver_requires_cached_response` (`should_panic`) is an
  assertion here.
- `utils.channel.oneshot.Receiver.recv` returns `error.Closed` once the receiver is closed
  without a value (tokio behavior; the delivery tracker relies on it).
- Seeded fuzz uses `p2p.fuzz.run` (the same driver as codec's).

## Backlog
- [ ] resolver: lib.rs, subscribers, ingress, delivery (done); opaque.rs.
- [ ] resolver p2p: wire.rs (done, conformance hashes match), score (done), fetcher, inflight,
  config, engine, ingress, mocks; port mod.rs tests on p2p simulated.
- [ ] broadcast: lib.rs and buffered (engine, ingress, config, mocks) with its tests.
- [ ] collector: lib.rs and p2p (engine, wire) with its tests.
- [ ] Fuzz targets (broadcast/fuzz, collector/fuzz) and metrics once the runtime registry
  lands.

## Log
- 2026-11-13: resolver lib.rs types, subscribers tracker, p2p wire (conformance hashes match).
- 2026-11-13: resolver ingress (coalescing mailbox policy, targets metadata).
- 2026-11-13: shared `utils.channel.oneshot` (tokio semantics over std.Io), with a model fuzz.

- 2026-11-13: resolver delivery tracker and mock consumer; oneshot recv wakes on close.
- 2026-11-13: resolver p2p score (throughput weights, commonware test values).
