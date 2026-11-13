# Lane: actor-stream

Owns `src/actor`, `src/stream`.

Reference: `~/.cache/zigware/commonware-ref/{actor,stream}`. Both run on the runtime lane's
deterministic runtime (`runtime.deterministic.Runner`, `runner.io()` is a full `std.Io`;
see docs/lanes/runtime.md). Write library code against `std.Io`.

## Public API (on main)

### actor
- `actor.Feedback` (`ok`, `backoff`, `closed`; `accepted()`), `actor.Unreliable(T)`
  (`outcome: T` / `rejected`; `new`, `is_rejected`, `get`, `accepted`, `eql`).
- `actor.mailbox.new(T, gpa, io, capacity) !Pair(T)` returns `.{ .sender, .receiver }`.
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
  `out.len` bytes), `stream.peek(max_len) []const u8`. `stream.mocks.channel(gpa, io)` /
  `channel_with_buffer_size` give an in-memory `Sink`/`Stream` pair with commonware's
  `mocks::Channel` buffering and backpressure.
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

## Decisions
- The mailbox guards ready and overflow with one `std.Io.Mutex` and parks the receiver on a
  `std.Io.Condition`, instead of crossbeam's lock-free ready queue, the activity word, and an
  `AtomicWaker`. Same delivery semantics, simpler, and deterministic on the runtime.
- Handles are values: `clone`/`deinit` replace `Clone`/`Drop`; the state is freed when the
  last handle goes. Dropped messages go through the type's optional `discard`, called
  outside the lock on receiver close so a discarded message may own a sender of its mailbox.
- The backoff metric is `backoff_total()` until the runtime has a metrics registry.
- Stream transports receive into caller buffers (no allocation per frame); framing errors
  carry no runtime error payload, and `error.Canceled` passes through. The sink/stream
  contract and mock channel live in `stream` until the runtime lane ships its network; then
  stream switches to the runtime's types. Commonware's `test_recv_frame_max_length` (a 4 GiB
  declared frame left pending) has no counterpart: Zig reads `usize` lengths without overflow
  and the caller buffer bounds the frame.
- CUPS halves own one buffer each, sized for the largest record and allocated when the
  connection is split. `send_many` packs records into that buffer and flushes when it fills,
  so a batch larger than one record limit takes several sink calls (commonware: one call per
  batch); the bytes on the wire are identical. Errors carry no payload (commonware reports the
  oversized payload length).
- Loom tests (thread interleavings of the lock-free paths) have no counterpart: the paths
  they check do not exist here. Concurrency is covered on the deterministic runtime instead
  (parked receivers, three producers, same-seed replay) plus a seeded FIFO fuzz.

## Backlog
- [x] actor: mailbox (bounded ready queue plus policy-managed overflow), `Feedback`,
  `Unreliable`, with commonware's tests on the deterministic runtime and a seeded fuzz.
- [ ] actor: mailbox benches (actor/src/benches/mailbox.rs) once `bench` lands; metrics
  counter once the runtime registry lands.
- [x] stream utils: length-prefixed framing codec (utils/codec.rs) with its tests, a mock
  sink/stream channel, and a seeded wire-bytes fuzz.
- [ ] stream utils: `Timeout` (utils/timeout.rs), with the `Upgrader` interface (lib.rs).
- [x] stream cups protocol (cups/protocol.rs) with its tests, against a test handshake.
- [ ] stream sake: the authenticated handshake protocol and encrypted send/receive, wire
  format and conformance hashes identical to commonware's. Uses cryptography's ed25519,
  chacha20_poly1305, transcript, and handshake as the crypto lane lands them; coordinate
  with it (thread in docs/lanes/README.md) if you need one of those sooner.
- [ ] Tests over the runtime's deterministic network once it lands (in-memory sink/stream
  pairs before then), plus fuzz targets (commonware stream/fuzz).

## Log
- 2026-11-13: actor `Feedback`, `Unreliable`, and `mailbox` with commonware's tests.
- 2026-11-13: stream framing codec, mock sink/stream channel, framing fuzz.
- 2026-11-13: stream cups (record protocol, cipher derivation) and the handshake contract.
