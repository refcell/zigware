# Lane: broadcast-collector

Owns `src/broadcast` and `src/collector` (moved from broadcast-resolver, which keeps
`src/resolver`). Worked by the actor-stream thread after its backlog finished.

Reference: `~/.cache/zigware/commonware-ref/{broadcast,collector}` (about 5.7k Rust lines).
Both are actors over p2p. They build on `actor.mailbox`, `p2p` (lib types and
`p2p.simulated`, API in docs/lanes/p2p.md), the deterministic runtime,
`runtime.telemetry.metrics`, and `cryptography` (certificate schemes, mocks).

broadcast `buffered` comes first: consensus marshal (T-01a1d5ef-5571-7424-8220-609c9811da57)
needs it.

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

## Backlog
- [x] broadcast lib.rs traits.
- [x] broadcast buffered: config, ingress, metrics, engine, mocks, with every mod.rs test on
  p2p.simulated (commonware has no broadcast conformance hashes).
- [x] collector lib.rs, p2p ingress (overflow policy), engine, mocks, with every ingress.rs
  and mod.rs test (commonware has no collector conformance hashes).
- [ ] Fuzz targets (broadcast/fuzz, collector/fuzz).

## Log
- 2026-11-13: broadcast lib.rs and buffered (engine, mailbox, overflow policy, metrics,
  mocks) with all 27 mod.rs tests; `broadcast.Digested`.
- 2026-11-13: collector lib.rs traits and p2p engine, mailbox, mocks, with 5 policy and 13
  engine tests.
