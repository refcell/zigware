# Lane: actor-stream

Owns `src/actor`, `src/stream`.

Reference: `~/.cache/zigware/commonware-ref/{actor,stream}`. Both run on the runtime lane's
deterministic runtime (`runtime.deterministic.Runner`, `runner.io()` is a full `std.Io`;
see docs/lanes/runtime.md). Write library code against `std.Io`.

## Public API (on main)

### actor
- `actor.Feedback` (`ok`, `backoff`, `closed`; `accepted()`), `actor.Unreliable(T)`
  (`outcome: T` / `rejected`; `new`, `is_rejected`, `get`, `accepted`, `eql`).
- `actor.mailbox.new(T, gpa, io, capacity) !Pair(T)` returns `.{ .sender, .receiver }`;
  `new_with_metrics(T, gpa, io, &scope, capacity)` also registers `<scope>_backoff_total`.
  `Sender(T)`: `enqueue(message)` (returns `Feedback`, or `Unreliable(Feedback)` when the
  policy can reject; wrapped in `Allocator.Error!` when `handle` can fail), `clone`, `deinit`,
  `capacity`, `is_closed`, `backoff_total`. `Receiver(T)`: `recv() Cancelable!?T` (null once
  every sender is gone and the buffer is drained), `try_recv() error{Empty,Disconnected}!T`,
  `deinit` (closes and discards what is buffered), `backoff_total`.
- A message type is its own policy: `pub const Overflow` (`std.Deque(T)` or a custom type
  with `empty`, `deinit`, `is_empty`, `drain(pusher)`), `pub fn handle(gpa, *Overflow, T)`
  returning `void` (reliable, commonware `Policy`) or `bool` (unreliable, `UnreliablePolicy`),
  optionally as an `Allocator.Error!` union, and optional `pub fn discard(T) void` (Rust
  `Drop`: cancel responders, release resources). See the top of `src/actor/mailbox.zig`.

### stream
- Transport contract (commonware `runtime::{Sink, Stream}`), duck-typed:
  `sink.send(bufs: []const []const u8) !void`, `stream.recv(out: []u8) !void` (exactly
  `out.len` bytes), `stream.peek(max_len) []const u8`, the runtime's contract
  (`runtime.mocks`). Tests use `runtime.mocks.channel(gpa, io)` and the deterministic network
  (`runner.network()`: bind, accept, dial).
- `stream.utils.codec`: `send_frame(sink, parts, max_message_size)`,
  `recv_frame(stream, buffer, max_message_size) ![]u8` (payload in `buffer`, which holds at
  least `max_message_size` bytes), `recv_length`, `validate_frame_len`, `Error`.
- `stream.Accepted(PublicKey)` and the handshake contract (top of `src/stream/root.zig`):
  `public_key`, `dial(io, namespace, peer, *stream, *sink) !Transcript`,
  `listen(io, namespace, bouncer, *stream, *sink) !Accepted(PublicKey)`; bouncers provide
  `admit(peer) !bool`.
- `stream.cups`: `Cups(Handshake, Cipher)` with `init(handshake, version)`, `public_key`,
  `max_size`, `dial(gpa, io, namespace, max_message_size, peer, stream, sink)` returning a
  `Connection` (`sender`, `receiver`, `deinit(gpa)`), and `listen(gpa, io, namespace,
  max_message_size, bouncer, stream, sink)` returning `.{ peer, connection }`. Both take
  ownership of the stream and sink. `Sender(C, Sink)`: `send(message)`, `send_many(messages)`.
  `Receiver(C, Stream)`: `recv() ![]const u8` (valid until the next `recv`). Free functions
  `ciphers`, `header_len`, `record_len`, `tag_size`, `max_payload`; `Version` (`v0`, `v1`).
- `stream.sake.Sake(S)` (fields `signer`, `synchrony_bound_ms`, `max_handshake_age_ms`,
  `version`) implements the handshake contract over `cryptography.handshake.sake`;
  `stream.SakeCups(S, C)` is `cups.Cups(sake.Sake(S), C)`, the authenticated transport p2p
  uses. Randomness comes from `io.random` (the runtime RNG), time from `Io.Clock.real`.
- `stream.utils.Timeout(U)`: `init(upgrader, timeout: Io.Duration)`, `dial`/`listen` with the
  upgrader's arguments plus `error.Timeout`; the deadline starts at the call, covers the
  bouncer, and cancels the attempt (releasing its connection) on expiry.

## Decisions
- The mailbox guards ready and overflow with one `std.Io.Mutex` and parks the receiver on a
  `std.Io.Condition`, instead of crossbeam's lock-free ready queue, the activity word, and an
  `AtomicWaker`. Same delivery semantics, simpler, and deterministic on the runtime.
- Handles are values: `clone`/`deinit` replace `Clone`/`Drop`; the state is freed when the
  last handle goes. Dropped messages go through the type's optional `discard`, called
  outside the lock on receiver close so a discarded message may own a sender of its mailbox.
- Mailbox benches: `iter_batched(LargeInput)` setup is `before_iter` (untimed).
  `recv_waiting` runs on the deterministic runtime (single-threaded like `block_on`); the
  producer sleeps until the receiver has parked for each message, so its time includes
  scheduler cycles the reference's single poll does not have.
- `mailbox.new` takes no metrics context; its backoff counter is detached, like commonware's
  test `mocks::Metrics`. `new_with_metrics(T, gpa, io, *const Scope, capacity)` registers it
  as `<scope>_backoff_total`. Stream has no metrics in commonware.
- Stream transports receive into caller buffers (no allocation per frame); framing errors
  carry no runtime error payload, and `error.Canceled` passes through. The sink/stream
  contract and mock channel live in `stream` until the runtime lane ships its network; then
  stream switches to the runtime's types. Commonware's `test_recv_frame_max_length` (a 4 GiB
  declared frame left pending) has no counterpart: Zig reads `usize` lengths without overflow
  and the caller buffer bounds the frame.
- CUPS halves own their buffers. The receiver's holds the largest record body and is
  allocated at split; the sender's starts at one largest record and grows to the largest batch
  sent (after the whole batch is sized), so a batch is one sink call like commonware's and
  steady-state sends do not allocate. Errors carry no payload (commonware reports the
  oversized payload length). `test_recv_decrypts_unique_frame_in_place` has no counterpart:
  records always decrypt in the receiver's own buffer.
- `Timeout` runs the attempt and the deadline as `std.Io.Select` tasks. An attempt that
  finishes as the deadline fires still wins (commonware's biased `select!`). A canceled
  fiber must run to unwind, so a timed-out call returns a few scheduler cycles (1 ms each
  in the deterministic runtime) after its deadline; commonware drops the future at once.
- The stream conformance hashes (CupsV0, CupsV1, SakeV0CupsV1, SakeV1CupsV0) are not
  ported. Commonware's deterministic executor shuffles each iteration's ready queue with the
  same `StdRng` that draws the test's keys, ephemeral keys, and message bytes, so those bytes
  depend on how many tasks are ready per iteration. Fibers block at different points than
  polled futures, so the counts differ and the hashes cannot match (the same reason the
  runtime lane gives for auditor digests). Wire identity is covered piecewise instead: SAKE
  message encodings and transcripts by cryptography's SakeV0/V1 conformance hashes, ChaCha20-
  Poly1305 by its Seal hash, and CUPS record bytes by `record encoding` against an
  independent oracle. The coordinator accepted this on 2026-11-13: the deterministic runtime
  will not imitate commonware's polling order, and these hashes stay unported.
- Loom tests (thread interleavings of the lock-free paths) have no counterpart: the paths
  they check do not exist here. Concurrency is covered on the deterministic runtime instead
  (parked receivers, three producers, same-seed replay) plus a seeded FIFO fuzz.

## Backlog
- [x] actor: mailbox (bounded ready queue plus policy-managed overflow), `Feedback`,
  `Unreliable`, with commonware's tests on the deterministic runtime and a seeded fuzz.
- [x] Actor mailbox benches (actor/src/benches/mailbox.rs) in `src/actor/benches.zig`, with
  commonware's names (`mailbox::mailbox::<group>/<params>`) and constants.
- [x] Mailbox `backoff` counter in the metrics registry (`mailbox_backoff_total`), with
  commonware's metric-text assertions.
- [x] stream utils: length-prefixed framing codec (utils/codec.rs) with its tests, a mock
  sink/stream channel, and a seeded wire-bytes fuzz.
- [x] stream utils: `Timeout` (utils/timeout.rs) with the upgrader tests from lib.rs.
- [x] stream cups protocol (cups/protocol.rs) with its tests, against a test handshake.
- [x] stream sake (sake/protocol.rs) over `cryptography.handshake.sake`, with its tests.
- [x] stream sake conformance hashes: not ported, by coordinator decision (see Decisions).
- [x] stream fuzz targets (commonware stream/fuzz: transport, connection, lazy_transport,
  e2e with a corrupting/forging/tampering adversary) in `src/stream/fuzz.zig`, seeded in
  `zig build test` and coverage-guided under `--fuzz`.
- [x] Stream transport contract and tests on `runtime.mocks` and `runtime.network`;
  `src/stream/mocks.zig` deleted. SakeCups is also tested over bind/accept/dial.

### Test audit: stream (2026-11-19, commonware 43b357a41)

Every `#[test]`/`#[test_traced]`/`#[rstest]` fn in commonware `stream/src`, matched to a zigware
test by name or by reading both bodies (a zigware test may cover several). 39 tests: 35 ported, 1
open, 3 not portable.

| commonware file | tests | ported | open | not portable |
|---|---|---|---|---|
| `lib.rs` | 4 | 3 | 1 | 0 |
| `cups/protocol.rs` | 14 | 13 | 0 | 1 |
| `sake/protocol.rs` | 9 | 8 | 0 | 1 |
| `utils/codec.rs` | 12 | 11 | 0 | 1 |

Open:
- [x] `lib.rs` `handshake_starts_timeout_when_called`: The deadline starts at the dial/listen call,
  not when awaited: start an attempt with a pending upgrader, sleep 100ms past the 50ms timeout
  before awaiting, expect error.Timeout and released channels, for dialer and listener. Goes in
  src/stream/utils/timeout_test.zig (Zig calls are eager, so this may only need to check that the
  attempt returns Timeout without waiting another 50ms)

Not portable:
- `cups/protocol.rs` `test_header_len_rejects_oversized_payload`: #[should_panic] (header_len panics
  on payload > MAX_SIZE); Zig asserts cannot be caught in tests
- `sake/protocol.rs` `test_recv_decrypts_unique_frame_in_place`: Checks that IoBufs plaintext points
  into the stream's returned buffer; Zig receivers always decrypt in their own buffer (no zero-copy
  stream buffers); recorded in docs/lanes/actor-stream.md Decisions
- `utils/codec.rs` `test_recv_frame_max_length`: Checks summed recv request lengths for a pending 4
  GiB frame (u32 overflow in receive requests); Zig receives into a caller buffer bounded by the
  frame limit and reads usize lengths, so the path does not exist; recorded in
  docs/lanes/actor-stream.md Decisions

### Upstream drift (commonware 43b357a41..a9ffc25f3, 2026-11-19)

26 upstream commits since the audit base. None changes actor or stream behavior or tests:
- `actor/Cargo.toml`, `stream/Cargo.toml`, `stream/fuzz/Cargo.toml`: `rust-version.workspace`
  and `[lints.cargo] unused_dependencies` (162216038). Build metadata; not portable.
- 883eae27e (proptest to minifuzz) touches no actor or stream file.

qmdb parallel snapshot init (this lane's ce3e897), over `storage/src/qmdb/snapshot.rs`,
`storage/src/index/partitioned`, and the any/current init paths:
- 42898af31: `build_snapshot` keys the index by `key.as_ref()`. zigware's index already takes
  key bytes (`value_mod.bytes`), so no change.
- a9ffc25f3: `op.inactivity_floor().is_some()` became `op.is_commit()`. `Committable::is_commit`
  defaults to the former, and the only override (immutable `Operation`) is true exactly for
  `Commit`, which always carries a floor, so snapshot.zig's check is equivalent. The same commit
  renumbers every qmdb operation tag (commit 0, update 1, delete 2, set 3, append 4) and
  regenerates `storage/conformance.toml`; that is the storage-qmdb lane's codec and was reported
  to it.
- 102430409, 90960d81c, 8bf364011 (store strategy, immutable floor-bounded reads and
  `commit_floor_at` init, unified sync targets) change storage-qmdb and storage-qmdb-sync code
  outside snapshot building; reported to those lanes.
- No upstream change to init concurrency (`SnapshotBuild::Concurrency`) or partitioned index.

## Log
- 2026-11-13: actor `Feedback`, `Unreliable`, and `mailbox` with commonware's tests.
- 2026-11-13: stream framing codec, mock sink/stream channel, framing fuzz.
- 2026-11-13: stream cups (record protocol, cipher derivation) and the handshake contract.
- 2026-11-13: stream sake and `SakeCups`; cups sender sends each batch in one sink call.
- 2026-11-13: stream `Timeout` with lib.rs's upgrader tests.
- 2026-11-13: stream fuzz targets (transport, connection, lazy_transport, e2e).
- 2026-11-13: conformance-hash decision recorded; remaining items wait on bench and runtime.
- 2026-11-13: stream moved onto runtime.mocks and runtime.network (buffer size 0 allowed in
  runtime.mocks, as in commonware).
- 2026-11-13: mailbox `backoff` counter registered through `new_with_metrics`.
- 2026-11-13: actor mailbox benches; the lane backlog is done.

## Test audit (2026-11-19, against main)

Every commonware `#[test]` in this lane's crates (macro and rstest cases expanded where noted), matched by reading both sides: ported (a Zig test checks the behavior, often one consolidated test), open, or not portable with the reason. Written by the consensus-marshal lane; tick a box when its test lands.

### actor
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| mailbox.rs | 46 | 27 | 0 | 19 |
| Total | 46 | 27 | 0 | 19 |

Open:
- None

Not portable:
- `mailbox.rs` loom tests (`#[cfg(feature = "loom")]`): these check thread interleavings of the
  lock-free ready queue, activity word, and AtomicWaker. Zig uses one Io.Mutex and Condition
  instead (docs/lanes/actor-stream.md, Decisions: "Loom tests ... have no counterpart"):
  `sender_drop_racing_waker_registration_wakes_or_disconnects`,
  `sender_enqueue_then_drop_racing_poll_recv_drains_message`,
  `sender_enqueue_then_drop_racing_try_recv_drains_message`,
  `handled_enqueue_wakes_registered_receiver`,
  `receiver_drop_racing_ready_fast_path_feedback_wakes_if_ready`,
  `receiver_drop_racing_ready_enqueue_drops_message`,
  `receiver_drop_racing_overflow_enqueue_drops_messages`,
  `receiver_drop_drains_ready_message_published_under_overflow_lock`,
  `receiver_drop_drains_overflow_message_published_under_overflow_lock`,
  `concurrent_close_and_ready_enqueue_remains_closed`,
  `concurrent_close_and_overflow_enqueue_remains_closed`,
  `concurrent_spill_and_refill_preserves_messages`,
  `concurrent_spill_senders_preserve_messages`,
  `concurrent_replace_keeps_one_overflow_message`,
  `stale_overflow_hint_retries_ready_before_policy`,
  `concurrent_overflow_cannot_be_bypassed_by_ready_fast_path`,
  `concurrent_overflow_mutation_does_not_hide_published_overflow`,
  `published_overflow_wakes_pending_receiver`,
  `concurrent_refill_and_enqueue_preserves_overflow_order`

