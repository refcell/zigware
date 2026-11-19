# Lane: p2p

Owns `src/p2p`, except `src/p2p/authenticated/lookup/`, which the parallel lane owns (split
agreed 2026-11-16 to shorten this backlog). The shared authenticated core (data, dialing,
throttle, outbox, router, channels) and discovery stay here; lookup builds on them and keeps
its own peer, dialer, and listener rather than refactoring discovery's.

Reference: `~/.cache/zigware/commonware-ref/p2p/src`. Start with the parts that run on the
deterministic runtime alone: `simulated` only needs task spawning and time from
`std.Io` (on main via `runtime.deterministic.Runner`). `authenticated` needs stream's
handshake and the runtime's network, which the actor-stream and runtime lanes are landing.

## Public API (on main)
- `p2p.Channel` (`u64`), `p2p.Message(P)` (`peer`, `payload`), `p2p.Recipients(P)`
  (`all`/`some`/`one`, `union_with(gpa, a, b)`, `peers()`, `deinit`), `p2p.Check(Checked)`
  (`checked` or `limited: utils.SystemTime`), `p2p.TrackedPeers(P)` (`primary`/`secondary` as
  `codec.Set(P)`, `union(gpa)`), `p2p.PeerSetUpdate(P)`, `p2p.Feedback`/`p2p.Unreliable`
  (re-exported from actor).
- Interface checks: `assert_unlimited_sender`, `assert_limited_sender`, `assert_receiver`,
  `assert_manager`, `assert_blocker` (decls documented at the top of `src/p2p/root.zig`).
- `p2p.types`: `Ingress` (`socket`/`dns`, hosts are `utils.Hostname`), `Address`
  (`symmetric`/`asymmetric`); codec encodings match commonware's conformance hashes.
- `p2p.sizing`: `max_message_size`, `peer_set_limit`, `max_retained_peers`, `peer_set_size`.
- `p2p.Quota` (`per_second`, `per_minute`, `per_hour`, `with_period`, `allow_burst`,
  `burst_size`) and `p2p.KeyedRateLimiter(K)` (`check_key` returns null or the earliest
  `SystemTime`, `retain_recent`): governor 0.10's keyed GCRA, step for step.
- `p2p.utils.LimitedSender(S, C)` (`init(gpa, io, sender, quota, connected)`, `clone`,
  `deinit`, `check(recipients) !Check(Checked)`), `p2p.utils.CheckedSender(S)`
  (`recipients`, `send(parts, priority)`, `into_inner`, `deinit`), `filter_rate_limited`,
  and `p2p.utils.Watch(T)` (latest-value channel: `publish`, `close`, `subscribe`,
  `Subscription.try_recv(gpa)`).
- `p2p.simulated.bandwidth` (`allocate`, `duration`, `transfer`, `Rate`, `Flow`) and
  `p2p.simulated.transmitter.State(P, M)` (`limit`, `enqueue`, `next`, `advance`, appending
  `Completion`s), on `simulated.Rational` (exact, over `std.math.big.int`) and
  `simulated.sorted_map.SortedMap` (BTreeMap order).
- `p2p.simulated.channel.Unbounded(T)` (unbounded mpsc over actor's mailbox; undeliverable
  values are released with `deinit`) and `p2p.simulated.tracker.Tracker(P)` (peer-set window,
  role counts, `Update` subscriptions).
- `p2p.simulated.Network(P)`: `init(gpa, io, Config)` / `init_with_peers(gpa, io, Config,
  TrackedPeers)` return `*Network`; spawn `io.concurrent(Network(P).run, .{network})`, then
  `close()`, await the task, and `deinit()` after every handle is released. `oracle()` gives
  `Oracle` (`control(me)`, `manager()`, `add_link(a, b, Link{latency, jitter,
  success_rate})`, `remove_link`, `limit_bandwidth(peer, ?egress, ?ingress)`, `blocked(gpa)`,
  `unblock`). `Control` has `register(channel, Quota) !Registered{sender, receiver}`,
  `manager()`, `block(peer)`, `blocked()`, `reset_peer_sets()`. `Manager` has `track(id,
  TrackedPeers) Feedback`, `peer_set(gpa, id)`, `subscribe()`. `Sender` is a
  `LimitedSender` (`send(recipients, parts, priority) ![]P` returns the attempted peers,
  caller-owned; `check` for the two-step form; `deinit`). `Receiver` has `recv() !Message(P)`
  (free with `message.deinit()`), `try_recv`, `capacity()`, `deinit`. Errors: `NetworkClosed`,
  `LinkingSelf`, `LinkExists`, `LinkMissing`. Optional `Config.scope` (a metrics `Scope`, as
  commonware's network context) registers `messages_sent` and `messages_received`
  (`simulated.metrics.Message{origin, recipient, channel}` labels); optional `Config.tracer`
  receives commonware's events under `commonware_p2p::simulated::network` (trace-level
  `dropping message` with its reason, eviction debug events, `overwriting existing channel`).
- `p2p.simulated.Normal` (`init(mean, std_dev)`, `sample(rng)`), `simulated.normal.standard`
  and `duration_ms`: rand_distr's `Normal<f64>`, bit-identical for the same RNG stream.
- `p2p.authenticated.Data` (wire frame: channel varint, length-prefixed message),
  `data.Header` (prefix, channel, and length for a zero-copy send), `max_payload_overhead`,
  `max_size(stream_max)`, and `authenticated.lookup.Message` (`data` or `ping`); both match
  commonware's conformance hashes.
- `p2p.AddressableTrackedPeers(P)` (`primary`/`secondary` as `codec.Map(P, types.Address)`),
  `authenticated.dialing` (`DialStatus`, `ReserveResult`, `earliest`), and lookup's
  `Record` and `Directory(P)` (track, overwrite, dial/listen reservations, blocks,
  dialable/listenable); callers pass `now` and an RNG.
- `authenticated.throttle.Throttle` (inbound rate limit that waits), `outbox.Outbox`
  (kill > high > low queues with a ping deadline) and `outbox.Frame` (a data frame encoded
  once and shared), `router.Router(P)` (connected peers, `content`, `Connected` source), and
  `channels.Channels(P)` (`register(channel, quota)` returns a limited `Sender` and a lossy
  `Receiver` sized `max_peers * burst`).
- `authenticated.discovery.types`: `Payload(P)` (`data`, `greeting`, `bit_vec`, `peers`;
  `Cfg = PayloadConfig`), `BitVec`, `Info(P)` (`sign(public_key, namespace, ingress,
  timestamp, signer)`, `verify`), `InfoVerifier(P)` (`validate(now, infos)`,
  `validate_info`), and `max_gossip_size(P, max_bit_vec, max_peers)`; all three match
  commonware's conformance hashes (secp256r1 keys).
- `authenticated.discovery.directory.Directory(P)` (bootstrappers, track with knowledge bit
  sets, update_peers, dial/listen reservations with `Metadata`, connect/release, blocks,
  `infos(bit_vec)`, `random_bit_vec`, dialable/acceptable), with `record.Record(P)` and
  `bit_set.BitSet(P)`; callers pass `now` and an RNG.
- `authenticated.discovery.Network(U, Transport)`: `U` is a stream upgrader such as
  `stream.SakeCups(ed25519.PrivateKey, ChaCha20Poly1305)` (its `handshake.signer` signs
  discovery records); `Transport` is `runtime.network.deterministic.Network` or the production
  `Network`. `Net.Config.local(base)` / `.recommended(base)` take `.{ upgrader, namespace,
  listen (Io.net.IpAddress), dialable (Ingress), bootstrappers ([]const Bootstrapper{peer,
  ingress}), max_peers_per_set, max_message_size, mailbox_size }`; adjust fields after.
  `Net.create(gpa, io, *transport, scope, config) !*Net` (metrics under `scope`, commonware's
  network context: `tracker_directory_*`, `listener_handshake*`, `dialer_attempts`,
  `spawner_messages_{sent,received,rate_limited}`), `register(channel, Quota) !Registered{sender,
  receiver}` (before `run`), `oracle()` (`track(index, TrackedPeers)`, `peer_set`, `subscribe`,
  `block`, `blocked`), `run() !void` (spawn with `io.concurrent`; cancel to stop, after which
  receivers report `NetworkClosed`), and `destroy()` after deinitializing senders. Shared
  pieces: `discovery.tracker.Tracker(P)`, `discovery.peer.Peer(P)`, `utils.IoRng`, and
  `utils.shuffle` (rand 0.10 `shuffle`/`partial_shuffle`). `Net.Config.tracer`
  (`traces.Tracer`, default `.none`; set it from `ctx.tracer("")`) receives commonware's
  tracing events, each under its commonware module path (`commonware_p2p::authenticated::
  discovery::{network, actors::listener, actors::dialer, actors::spawner::actor,
  actors::peer::actor, actors::tracker::directory}`). `p2p.Ingress` formats like Rust's
  `Debug` (`Socket(1.2.3.4:5)`, `Dns { host: Hostname("x"), port: 5 }`). `Net.Config.resolver`
  (`?runtime.resolver.Resolver`: `runner.dns.resolver()` on the deterministic runner, the
  production runner's system resolver) resolves DNS ingress before dialing; without it DNS
  ingress is never dialed.
- `authenticated.lookup.Network(U, Transport)` (parallel lane): like discovery's, with
  `Net.Config.local/recommended(.{ upgrader, namespace, listen, max_peers_per_set,
  max_message_size, mailbox_size })`, `create(gpa, io, *transport, scope, config)`,
  `register`, `run`, `destroy`. `oracle()` is an `AddressableManager`: `track(index,
  AddressableTrackedPeers)`, `overwrite(PeerMap)`, `peer_set`, `subscribe`, `block`,
  `blocked`. `lookup.Tracker(P)` is the locked tracker it uses.
- `simulated` twins (commonware split senders and receivers): `Net.Sender` is now a struct
  wrapping the `LimitedSender` (`check`, `send`, `clone`, `deinit` unchanged) with
  `sender.split_with(forwarder) .{ primary, secondary }` of `Net.SplitSender(F)`; a forwarder
  has `forward(f, origin: SplitOrigin, recipients, message: []const u8) ?Recipients` (null
  drops the send; rate limits check the original recipients). `receiver.split_with(gpa, io,
  router) !.{ primary, secondary }` (both `Net.Receiver`, same capacity); a router has
  `route(r, *const p2p.Message(P)) SplitTarget` (`none`, `primary`, `secondary`, `both`). A
  routing task runs until the network closes the channel or both halves are deinitialized.
  `simulated.SplitTarget`, `simulated.SplitOrigin`, `simulated.split`.
- `p2p.Message(P)` owns its payload when `gpa` is set; release it with `deinit`.
- Senders take a message as parts (`[]const []const u8`, concatenated), like stream frames.

## Decisions
- `Ingress`/`Address` use `utils.Hostname` (stored inline) and `utils.net.is_global`, so they
  never allocate.
- p2p imports `conformance` (a dev-dependency in commonware) for its conformance tests.
- `Recipients.union_with` returns a new value (inputs borrowed); a `some` result is owned by
  the caller. Message payloads are byte slices until the runtime lane ports `IoBuf`.
- `Quota`/`KeyedRateLimiter` (commonware re-exports them from governor via runtime) live in
  `p2p/rate_limit.zig` until the runtime lane takes them; keys sit in a sorted array so the
  limiter is deterministic and needs no hashing of public keys.
- `utils.Watch` stands in for `channel::ring` with capacity 1 (the only way p2p uses it)
  until the utils lane ports channels. Values are owned copies on both sides.
- A `CheckedSender` that is never sent must be released with `deinit` (Rust drops it).
- The simulator keeps commonware's exact `BigRational` bandwidth math (`simulated/rational.zig`)
  and BTreeMap iteration order (`SortedMap`), so flow ids, rates, and completion times match.
  Payloads are opaque to the transmitter (`M` with a `len`); the network owns them.
- The simulated network runs operations in the caller's task under one `Io.Mutex` instead of
  an actor fed by an ingress queue, and a single `run` task drives the transmitter and timed
  deliveries straight into per-(peer, channel) unbounded mailboxes instead of simulated
  sockets. Order of sends, link changes, and arrival times per link match commonware;
  `priority` does not reorder sends.
- Link latency uses `simulated.Normal`, a port of `rand_distr` 0.6.0's ziggurat
  `StandardNormal`; it matches Rust bit for bit over 100k samples from `StdRng` seed 0, and
  latencies use Rust's `as_secs_f64() * 1000.0` and `as u64`. Success rates sample like
  `Probability` (0 and 1 draw nothing). Whole-run streams can still differ from commonware's,
  because the deterministic runtime's scheduler draws from the same RNG and the network's
  task layout differs from commonware's actor.
- Lookup's directory takes the current time and an RNG per call instead of owning a
  context, and keeps peers in key order (commonware's HashMap results are sorted before
  use). Reservations are `Metadata` values that the owner releases explicitly.
- The authenticated router is shared state behind a lock instead of an actor: `content`
  encodes the frame once and queues it on each recipient's outbox in the caller's task. A
  connection's control, high, and low mailboxes are one locked outbox read in the same
  priority order, with a timed wait for pings. Channel inbound queues grow on demand rather
  than preallocating `max_peers * burst` slots.
- Discovery runs its dialer, listener, unblock timer, handshakes, and connections as tasks in
  one `Io.Group` owned by `Network.run`, with the tracker as locked state instead of an actor;
  the tracker's mailbox messages are methods with the same effects in the same order. Gossip
  goes on each connection's outbox control queue (kill > control > high > low). A finished
  listener or dialer does not stop the network as commonware's `select!` does; cancelation
  does. DNS ingress is never dialed until the runtime has a resolver, and the transport dial
  relies on the handshake timeout and the transport's own connect timeout instead of a
  separate `dial_timeout` race.
- Metric names, help texts, and labels follow commonware. Commonware has no `p2p_connections`
  gauge any more (removed in #3324); count `tracker_directory_connected` samples instead.
  Recording a per-peer series never fails an operation: when its label cannot be allocated,
  the sample is skipped. Simulated link success rates sample through `utils.Probability`
  and must be exactly representable (as `probability!` requires).
- Lookup (parallel lane) mirrors discovery's task layout and keeps its own peer, dialer, and
  listener. The listener's registered-IP set is tracker state refreshed exactly where
  commonware's tracker sends `listener.set`, and read under the tracker's lock. Pings are
  sent alone or ahead of a batch of queued frames.
- Lookup tests not ported, and why: `test_broadcast_slow_peer_no_blocking` exercises
  only the shared router and is router.zig's "a full slow peer does not block broadcasts";
  `test_message_too_large` and the panicking halves of
  `test_construction_enforces_handshake_message_limit` /
  `test_max_message_size_exceeds_stream_limit` expect panics, which Zig tests cannot catch
  (the accepted boundaries are tested). The shutdown tests check that canceling `run`
  returns with no handshake in flight and receivers closed, instead of counting tasks per
  actor: one `Io.Group` owns every task. Lookup's directory reuses discovery's `Metrics(P)`
  (same six series, names, and help) under `<network>_tracker_directory`.
- p2p carries its own seeded fuzz driver (`p2p.fuzz.run`, same as codec's) until
  `invariants.minifuzz` lands.

## Backlog
- [x] types.rs, sizing.rs, lib.rs traits (`Sender`, `Receiver`, `Blocker`, `Manager`,
  `Recipients`, channels) as comptime interfaces; Ingress/Address conformance; decode fuzz.
- [x] Rate limiter: `Quota` and governor's keyed GCRA (`rate_limit.zig`).
- [x] utils: limited (`LimitedSender`, `CheckedSender`) with its tests.
- [x] simulated: bandwidth planner and transmitter with their tests.
- [x] simulated: unbounded channel and peer-set tracker.
- [x] simulated: network core (Oracle, Control, Manager, links with latency/jitter/success
  rate, rate-limited senders, receivers, peer-set tracking) with its first tests.
- [x] simulated: dynamic links, peer-set window and own/network-wide peer sets, and every
  bandwidth test (contention, sharing, staggered, pipe reservation, zero limits).
- [x] simulated: ziggurat `Normal` for byte-identical latency samples.
- [x] simulated: blocked subscriptions, disconnect_on_block, operations after shutdown.
- [x] simulated: split senders and receivers (`SplitTarget`, `SplitOrigin`, forwarders,
  routers) with commonware's split tests.
- [x] simulated: metrics (`messages_sent`, `messages_received`) and tracing events.
- [x] simulated: duplicate channel, link before registration, register and link, max_size
  on the payload, FIFO burst, peer-set subscriptions (four tests), clean shutdown (25 seeds).
- [x] simulated: `SocketManager` (`oracle.socket_manager()`, `control.socket_manager()`)
  with the socket-manager tests; max_peers_per_set counting and split-peer seeding tests.
- [x] simulated: dynamic peers, overlapping primary/secondary, broadcast transmit latency,
  cross-index primary wins, unordered sets. `test_get_next_socket` has no counterpart (links
  deliver into channels, with no sockets), nor do the `should_panic` tests (same messages).
- [x] authenticated: router, relay, throttle, dialing, channels.
- [x] discovery: types (conformance), tracker record/bit set/directory, tracker, peer
  connections, dialer, listener, Network/Config/Oracle, connectivity over the deterministic
  network.
- [x] discovery: metrics (directory, listener, dialer, per-connection messages).
- [x] discovery mod.rs tests: run_network over modes One/Some/All with determinism, payload
  limit below the gossip bound, pre-start send, operations after shutdown, clean shutdown,
  stream boundary, too-large payload not delivered, rate limiting, slow peer (router).
- [x] discovery mod.rs tests: unordered peer sets, subscription includes self, graceful
  shutdown.
- [x] discovery mod.rs test: multi-index oracle (20 peers by default, commonware's 100 under
  fuzz soak: 100 peers hold about 10,000 connections and 3 GB in one process).
- [x] discovery mod.rs tests: restarts (many, simultaneous, new address that must be dialed
  by the other side), duplicate addresses (disconnected over 25 seeds, connected).
- [x] discovery: DNS ingress dialing through `Config.resolver`, with the mod.rs DNS tests
  (bootstrapper resolution, determinism, failure then success, private IPs, mixed IPs).
- [x] discovery: tracing events at commonware's sites (runtime.telemetry.traces).
- [x] lookup (parallel lane): tracker, peer, dialer, listener, Network with Config and Oracle,
  commonware's mod.rs tests (but DNS, see decisions), and the directory's metrics.
- [x] lookup DNS tests on the runtime resolver (`Config.resolver`, as discovery has it).
- [x] utils codec, mux, mocks, and `WrappedBackgroundReceiver` (bls-math lane, 6f151f7).
- [x] Fuzz targets (commonware p2p/fuzz): bls-math lane, src/p2p/fuzz/ (5bd7641, a847216).

### Test audit: p2p (2026-11-19, commonware 43b357a41)

Every `#[test]`/`#[test_traced]`/`#[rstest]` fn in commonware `p2p/src`, matched to a zigware test
by name or by reading both bodies (a zigware test may cover several). 476 tests: 463 ported, 0
open, 13 not portable. The 86 first found open are all ported now (ticked under Open below),
none reclassified; the table was recounted on 2026-11-19. 18 `#[should_panic]` tests moved from
not portable to ported on `utils.death` (see Not portable below).

Not-portable re-audit (2026-11-19, against main after async `start_sync`, `DelayedSync`,
faulty's `Storage.wrap`, and the drain and recancel rules): of the 31, none became portable
through those changes. 20 were `#[should_panic]`; 18 of them are now ported on
`utils.death.expect_panic`, which reruns the test binary as a child (AGENTS.md). Each was
checked with a planted bug that removes its panic.
- Ported on `utils.death`: sizing (2), channels `derived_capacity_panics_on_overflow`,
  discovery and lookup `mod.rs` stream limits (4), bit_set `test_index_out_of_bounds_positive`
  (it indexes `ordered`, so its plant is in the test), tracker
  `test_peer_set_limit_counts_secondary_peers`, discovery and lookup `record.rs` (8), and
  mux `test_sub_sender_panics_above_limit_less_prefix`.
- The other 2 panic in APIs zigware does not have: `outbound_mailbox_size` and p2p's
  `stream::Config::new`.
- The other 11 test Rust structure zigware replaced, and main still has the replacements: the
  router and spawner actors' mailboxes (router.zig is locked shared state; connections start
  in an `Io.Group`), lookup's listener actor (`listen_loop` calls the tracker), the
  `stream::Config` wrapper, `From<SocketAddr>`, and BitSet's `IntoIterator`.

`lib.rs`'s `recipient_unions` is one rstest fn of 25 cases (5 x 5 values); the zigware test covers
all 25.

Drift check (2026-11-19, commonware a9ffc25f3): since 43b357a41 only 162216038 touches `p2p/`
(Cargo `rust-version` and lint settings, and a dropped `.clone()` in `simulated/network.rs`). No
test was added or changed, and no behavior changed, so the table above still holds.

Lookup's `dial_timeout` is configured but unused by design (the dial relies on the handshake
and transport connect timeouts, see Decisions), so its dialer timeout test is to be adapted to that.

| commonware file | tests | ported | open | not portable |
|---|---|---|---|---|
| `lib.rs` | 1 | 1 | 0 | 0 |
| `sizing.rs` | 7 | 7 | 0 | 0 |
| `types.rs` | 13 | 12 | 0 | 1 |
| `authenticated/channels.rs` | 4 | 2 | 0 | 2 |
| `authenticated/data.rs` | 5 | 5 | 0 | 0 |
| `authenticated/relay.rs` | 2 | 2 | 0 | 0 |
| `authenticated/stream.rs` | 3 | 1 | 0 | 2 |
| `authenticated/throttle.rs` | 2 | 2 | 0 | 0 |
| `authenticated/discovery/mod.rs` | 30 | 30 | 0 | 0 |
| `authenticated/discovery/network.rs` | 2 | 2 | 0 | 0 |
| `authenticated/discovery/types.rs` | 22 | 22 | 0 | 0 |
| `authenticated/discovery/actors/dialer.rs` | 6 | 6 | 0 | 0 |
| `authenticated/discovery/actors/listener.rs` | 4 | 4 | 0 | 0 |
| `authenticated/discovery/actors/peer/actor.rs` | 6 | 6 | 0 | 0 |
| `authenticated/discovery/actors/peer/ingress.rs` | 1 | 1 | 0 | 0 |
| `authenticated/discovery/actors/spawner/actor.rs` | 2 | 2 | 0 | 0 |
| `authenticated/discovery/actors/spawner/ingress.rs` | 1 | 0 | 0 | 1 |
| `authenticated/discovery/actors/tracker/actor.rs` | 22 | 22 | 0 | 0 |
| `authenticated/discovery/actors/tracker/bit_set.rs` | 11 | 10 | 0 | 1 |
| `authenticated/discovery/actors/tracker/directory.rs` | 28 | 28 | 0 | 0 |
| `authenticated/discovery/actors/tracker/ingress.rs` | 2 | 2 | 0 | 0 |
| `authenticated/discovery/actors/tracker/record.rs` | 24 | 24 | 0 | 0 |
| `authenticated/lookup/mod.rs` | 29 | 29 | 0 | 0 |
| `authenticated/lookup/types.rs` | 6 | 6 | 0 | 0 |
| `authenticated/lookup/actors/dialer.rs` | 6 | 6 | 0 | 0 |
| `authenticated/lookup/actors/listener.rs` | 7 | 6 | 0 | 1 |
| `authenticated/lookup/actors/peer/actor.rs` | 3 | 3 | 0 | 0 |
| `authenticated/lookup/actors/peer/ingress.rs` | 1 | 1 | 0 | 0 |
| `authenticated/lookup/actors/spawner/ingress.rs` | 1 | 0 | 0 | 1 |
| `authenticated/lookup/actors/tracker/actor.rs` | 27 | 27 | 0 | 0 |
| `authenticated/lookup/actors/tracker/directory.rs` | 39 | 39 | 0 | 0 |
| `authenticated/lookup/actors/tracker/ingress.rs` | 1 | 1 | 0 | 0 |
| `authenticated/lookup/actors/tracker/record.rs` | 19 | 19 | 0 | 0 |
| `authenticated/router/actor.rs` | 1 | 0 | 0 | 1 |
| `authenticated/router/ingress.rs` | 3 | 0 | 0 | 3 |
| `simulated/bandwidth.rs` | 12 | 12 | 0 | 0 |
| `simulated/mod.rs` | 48 | 48 | 0 | 0 |
| `simulated/network.rs` | 20 | 20 | 0 | 0 |
| `simulated/transmitter.rs` | 16 | 16 | 0 | 0 |
| `utils/codec.rs` | 10 | 10 | 0 | 0 |
| `utils/limited.rs` | 12 | 12 | 0 | 0 |
| `utils/mux.rs` | 15 | 15 | 0 | 0 |
| `utils/mocks/mod.rs` | 2 | 2 | 0 | 0 |

Open:
- [x] `authenticated/data.rs` `test_decode_does_not_allocate`: decode a Data frame with a
  failing/counting allocator and assert message is a slice into the input buffer;
  src/p2p/authenticated/data.zig. Ported in data_alloc_test.zig (73c919e).
- [x] `authenticated/discovery/mod.rs` `test_tokio_connectivity`: run connectivity (10 peers,
  Mode.one) on runtime.production instead of the deterministic runner; no p2p test uses the
  production runner. Goes in network_test.zig
- [x] `authenticated/discovery/actors/dialer.rs` `test_dial_timeout_releases_reservation`: a dial to
  a listener that never handshakes releases its reservation; zigware has no separate dial_timeout
  race (Decisions), so adapt to release after the handshake timeout. network_test.zig
- [x] `authenticated/discovery/actors/dialer.rs` `test_dialer_dials_one_peer_per_tick`: dial_loop
  dials at most one peer per dial_frequency tick (2-4 dials in 3 ticks with 10 dialable peers);
  network_test.zig or a test in network.zig (dial_loop/next_deadline are private)
- [x] `authenticated/discovery/actors/dialer.rs` `test_dialer_uses_tracker_next_query_deadline`:
  next_deadline clamps a tracker next_query_at below dial_frequency up to dial_frequency (1 refresh
  in 350 ms at 500 ms frequency); test of next_deadline in network.zig
- [x] `authenticated/discovery/actors/dialer.rs` `test_dialer_drains_queue_at_dial_frequency`: a
  queued batch of 3 peers is dialed one per dial_frequency (3 dials in 250 ms at 100 ms) with
  next_query_at null; network.zig
- [x] `authenticated/discovery/actors/dialer.rs`
  `test_dialer_does_not_panic_when_dial_frequency_exceeds_peer_connection_cooldown`: next_deadline
  with cooldown < dial_frequency and empty queue refreshes every dial_frequency without panicking;
  network.zig
- [x] `authenticated/discovery/actors/dialer.rs`
  `test_dialer_does_not_panic_with_unbounded_peer_connection_cooldown`: next_deadline with
  peer_connection_cooldown = max saturates and follows next_query_at (4 refreshes in 350 ms);
  network.zig
- [x] `authenticated/discovery/actors/listener.rs` `rate_limits_ip`: repeated inbound connections
  from one IP with a 1/hour per-IP quota count handshake_ip_rate_limited_total 3 and subnet 0;
  network_test.zig (listen_loop/admit, counters exist untested)
- [x] `authenticated/discovery/actors/listener.rs` `rate_limits_subnet`: same with a 1/hour
  per-subnet quota: handshake_subnet_rate_limited_total 3, ip 0; network_test.zig
- [x] `authenticated/discovery/actors/listener.rs` `rate_limits_both`: both quotas 1/hour: ip and
  subnet rate-limited totals both 3; network_test.zig
- [x] `authenticated/discovery/actors/listener.rs` `blocks_private_ips`: with
  allow_private_ips=false an inbound localhost connection is rejected and counts
  handshakes_blocked_total 1; network_test.zig
- [x] `authenticated/discovery/actors/peer/actor.rs`
  `greeting_and_queued_data_progress_with_backpressure`: Peer.run over a small-buffer connection
  pair: queued bit vecs/peers/data and the greeting flow both ways, and sent/received per-type
  metrics are greeting 1, bit_vec 2, peers 1, data 1; peer.zig (no peer tests exist)
- [x] `authenticated/discovery/actors/peer/actor.rs` `test_missing_greeting_returns_error`: Peer.run
  returns error.MissingGreeting when the first frame is not a greeting; peer.zig
- [x] `authenticated/discovery/actors/peer/actor.rs` `test_duplicate_greeting_returns_error`:
  Peer.run returns error.DuplicateGreeting on a second greeting; peer.zig
- [x] `authenticated/discovery/actors/peer/actor.rs`
  `test_greeting_public_key_mismatch_returns_error`: Peer.run returns error.GreetingMismatch when
  the greeting key differs from the authenticated peer; peer.zig
- [x] `authenticated/discovery/actors/peer/actor.rs`
  `test_invalid_channel_no_unbounded_metric_cardinality`: data on an unregistered channel returns
  error.InvalidChannel, increments the per-peer invalid counter once, and creates no per-channel
  series; peer.zig
- [x] `authenticated/discovery/actors/peer/actor.rs` `test_oversized_data_returns_error`: data one
  byte over max_message_size makes Peer.run fail with a decode error; peer.zig ("a payload above the
  receiver's limit is never delivered" checks only non-delivery at network level)
- [x] `authenticated/discovery/actors/peer/ingress.rs` `kill_retained_on_overflow`: with the outbox
  control queue full (extra control frame dropped), kill still lands and try_next yields .killed;
  outbox.zig (existing tests cover drop-when-full and kill separately, never kill after overflow)
- [x] `authenticated/discovery/actors/spawner/actor.rs` `tracker_rejection_sends_no_greeting`: when
  tracker.connect returns null, serve sends no greeting on the connection; network_test.zig (serve
  is private; drive via an untracked peer connecting)
- [x] `authenticated/discovery/actors/spawner/actor.rs` `router_rejection_sends_no_greeting`: when
  router.ready fails (router shut down), serve sends no greeting; network_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_connect_unauthorized_peer_returns_none`: Tracker.connect returns null for an untracked peer
  as dialer and as listener; new src/p2p/authenticated/discovery/tracker_test.zig (tracker.zig has
  no tests; lookup has the counterpart)
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_connect_authorized_peer_receives_tracker_info`: after track+listen, Tracker.connect returns
  our own Info (key, ingress, verifies in ip namespace); tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs` `test_construct_no_sets_tracked`:
  Tracker.construct with no tracked sets (bootstrapper connected) queues nothing on the outbox;
  tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_handle_bit_vec_for_unknown_index_sends_no_peers`: Tracker.bit_vec for an unknown index
  queues no peers frame (directory_test only checks infos returns empty); tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs` `test_block_peer_standard_behavior`:
  Tracker.block of a connected peer kills its outbox and removes it from dialable; tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_register_disconnects_removed_peer_with_known_mailbox`: Tracker.track of a set without a
  connected peer kills that peer's outbox (directory_test checks only the returned kill list);
  tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_reserved_removed_peer_rejected_on_connect`: a peer reserved then dropped from the sets gets
  null from Tracker.connect and no kill, and its reservation is still releasable; tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_register_keeps_connected_peer_present_across_rollover`: a connected peer present in the new
  set is not killed when the old set rolls off, and construct still sends it a bit vec;
  tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_block_clears_peer_mailbox_and_only_kills_once`: blocking a connected peer kills its outbox
  once and forgets it, so a second block sends no kill; tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_blocked_subscription_tracks_block_and_expiry`: Tracker.blocked_subscription starts empty,
  shows the blocked peer with expiry, late subscribers see it, and both see empty after run_unblock;
  tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs` `test_block_peer_already_blocked_is_noop`:
  blocking a tracked peer twice is a no-op and Tracker.connect then returns null without a kill;
  tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs` `test_handle_peers_learns_unknown_peer`:
  Tracker.peers with info for a newly tracked peer, then a bit_vec from a connected peer, queues a
  peers frame holding that info; tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_handle_peers_rejects_older_info_for_known_peer`: an older Info passed to Tracker.peers is
  ignored, so gossip still carries the newer timestamp (record_test covers only Record.update);
  tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs` `test_dialable_message`: Tracker.dialable
  lists a configured bootstrapper with no sets tracked; tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_secondary_peers_are_connectable_but_not_primary`: subscription update lists secondary
  separately from primary, secondary is acceptable, and after gossip it is still not dialable;
  tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs`
  `test_overlapping_primary_secondary_no_duplicate_in_subscription`: the subscription update for a
  peer in both roles lists it as primary only (latest and all) and it is acceptable;
  tracker_test.zig (directory_test checks latest_update, not the subscription)
- [x] `authenticated/discovery/actors/tracker/actor.rs` `test_dial_message`: Tracker.dial of a
  bootstrapper returns dialer metadata with its ingress, and dial of an unknown peer returns null;
  tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs` `test_bitvec_kill_on_length_mismatch`: a bit
  vec whose length differs from the set kills the sender's outbox (directory_test checks only infos
  returning null); tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/actor.rs` `test_bit_vec_comprehensive`: end to end:
  unauthorized connect null, construct sends bit vec with self/learned peer bits, bit_vec answers
  with peers, eviction kills, construct picks only live indices; tracker_test.zig
- [x] `authenticated/discovery/actors/tracker/bit_set.rs`
  `test_knowledge_reflects_updates_and_cloning`: a copy_knowledge snapshot stays unchanged after
  later updates (current test only checks the copy equals the live bits); bit_set.zig
- [x] `authenticated/discovery/actors/tracker/bit_set.rs` `test_single_peer_set`: a one-peer set has
  len 1, position 0, and update toggles its single bit; bit_set.zig
- [x] `authenticated/discovery/actors/tracker/directory.rs` `test_block_peer_multiple_times`:
  blocking a tracked peer and an unknown peer three times each: repeats are no-ops and the blocked
  metric stays set (only a double block of an unknown peer is tested); directory_test.zig
- [x] `authenticated/discovery/actors/tracker/directory.rs`
  `test_blocked_peer_remains_blocked_on_update`: update_peers on a blocked peer stores the new
  ingress but keeps it blocked until expiry, then the info stays; directory_test.zig
- [x] `authenticated/discovery/actors/tracker/directory.rs` `test_blocked_peer_not_dialable`:
  blocked peer leaves dialable and returns after unblock_expired (only the leave half is in "blocked
  peers are neither dialable nor shared"); directory_test.zig
- [x] `authenticated/discovery/actors/tracker/directory.rs` `test_blocked_peer_info_not_sharable`: a
  connected peer that is blocked and then released has no sharable info, before or after unblock;
  directory_test.zig (the Zig test checks only infos while still connected)
- [x] `authenticated/discovery/actors/tracker/directory.rs` `test_infos_excludes_blocked_peers`:
  after block+release of one of two connected peers, infos returns only the other (the Zig test
  stops before release and expects both); directory_test.zig
- [x] `authenticated/discovery/actors/tracker/directory.rs` `test_dialable_empty`: dialable on a
  directory with no peers returns no peers and a null next_query_at; directory_test.zig
- [x] `authenticated/discovery/actors/tracker/directory.rs`
  `test_dialable_expired_block_without_unblock`: once a block expires, dialable lists the peer with
  no stale next_query_at and dial succeeds even without unblock_expired; directory_test.zig
- [x] `authenticated/discovery/actors/tracker/directory.rs`
  `test_reblock_after_expired_block_without_unblock`: re-blocking a peer whose block expired
  (unblock_expired not run) makes it undialable and unreservable again; directory_test.zig
- [x] `authenticated/discovery/actors/tracker/directory.rs`
  `test_block_with_unbounded_duration_does_not_panic`: block with block_duration = max saturates
  without panicking and the peer is ineligible (lookup has "block with an unbounded duration
  saturates", discovery does not); directory_test.zig
- [x] `authenticated/discovery/actors/tracker/record.rs` `test_update_with_different_public_key`: a
  discovered record accepts a newer Info signed by a different key, based on the timestamp alone;
  record_test.zig
- [x] `authenticated/discovery/actors/tracker/record.rs` `test_eligible_logic`: eligibility follows
  primary set counts for unknown and discovered records, and an updated bootstrapper stays eligible
  (only the secondary increment and initial states are tested); record_test.zig
- [x] `authenticated/discovery/actors/tracker/record.rs`
  `test_reserve_with_unbounded_cooldown_does_not_panic`: reserve with a max cooldown succeeds, and
  after release returns rate_limited without overflowing; record_test.zig
- [x] `authenticated/lookup/mod.rs` `test_determinism_one`: Mode::One over 10 seeds with replay
  comparison (lookup network_test.zig)
- [x] `authenticated/lookup/mod.rs` `test_determinism_some`: run_network in Mode::Some (each peer
  sends to a subset) over seeds 0..10, running each seed twice and comparing auditor state; zig
  connectivity only covers Mode::All with no replay comparison; goes in lookup/network_test.zig
- [x] `authenticated/lookup/mod.rs` `test_tokio_connectivity`: run_network (10 peers, Mode::One) on
  the production runtime over real sockets; runtime.production exists, but the lane skipped the
  discovery twin as redundant with the deterministic run (docs/lanes/p2p.md 2026-11-18); would go in
  lookup/network_test.zig
- [x] `authenticated/lookup/types.rs` `test_decode_does_not_allocate`: decode a lookup Message::Data
  with a failing allocator and check the payload slice points into the input buffer (discovery has
  this for Payload in discovery/types_test.zig, lookup does not); goes in lookup/types.zig
- [x] `authenticated/lookup/actors/dialer.rs` `test_dial_timeout_releases_reservation`: a dial to a
  peer that never answers releases its reservation after dial_timeout; zigware's lookup (and
  discovery) config has dial_timeout, but network.zig dial_peer never applies it, so the behavior is
  missing too; goes in lookup/network_test.zig after dial_peer applies the timeout
  Done as handshake-timeout release in lookup/network_dialer_test.zig.
- [x] `authenticated/lookup/actors/dialer.rs` `test_dialer_dials_one_peer_per_tick`: with many
  dialable peers, dial_loop makes one dial per dial_frequency tick (2-4 dials in 3 ticks); could
  count dialer_attempts in a lookup network test or test dial_loop/next_deadline in network.zig
- [x] `authenticated/lookup/actors/dialer.rs` `test_dialer_uses_tracker_next_query_deadline`: with
  nothing dialable and next_query_at sooner than dial_frequency, the refresh is held to
  dial_frequency (1 refresh in 350ms at 500ms freq); unit test of Network.next_deadline in
  lookup/network.zig
- [x] `authenticated/lookup/actors/dialer.rs`
  `test_dialer_keeps_dialing_queued_peers_when_next_query_deadline_is_unknown`: queued peers keep
  draining at dial_frequency when next_query_at is null (3 dials in 250ms at 100ms);
  dial_loop/next_deadline test in lookup/network.zig
- [x] `authenticated/lookup/actors/dialer.rs`
  `test_dialer_does_not_panic_when_dial_frequency_exceeds_peer_connection_cooldown`: cooldown (50ms)
  < dial_frequency (200ms) must not invert the [min,max] clamp; next_deadline unit test in
  lookup/network.zig
- [x] `authenticated/lookup/actors/dialer.rs`
  `test_dialer_does_not_panic_with_unbounded_peer_connection_cooldown`: peer_connection_cooldown =
  Duration::MAX saturates, and next_query_at still drives refreshes; next_deadline unit test in
  lookup/network.zig
- [x] `authenticated/lookup/actors/listener.rs` `rate_limits_ip`: repeated inbound connects from one
  IP beyond the per-IP quota raise handshake_ip_rate_limited_total to 3 (subnet 0, blocked 0);
  lookup network test over the deterministic transport checking listener counters
  (network_lifecycle_test.zig or a new listener test)
- [x] `authenticated/lookup/actors/listener.rs` `rate_limits_subnet`: same as rate_limits_ip with
  the per-subnet quota: handshake_subnet_rate_limited_total 3, ip 0; lookup network test checking
  listener counters
- [x] `authenticated/lookup/actors/listener.rs` `rate_limits_both`: both quotas at 1/hour: ip and
  subnet rate-limited counters both reach 3 (each limit charged even when the other rejects, as
  Network.admit does); lookup network test checking listener counters
- [x] `authenticated/lookup/actors/listener.rs` `blocks_unregistered_ips`: an inbound connect from
  an IP no tracked peer uses raises handshakes_blocked_total to 1; lookup network test checking
  listener counters
- [x] `authenticated/lookup/actors/listener.rs` `allows_unregistered_ips`: with bypass_ip_check, an
  unregistered IP is not blocked (handshakes_blocked_total 0); lookup network test checking listener
  counters
- [x] `authenticated/lookup/actors/listener.rs` `blocks_private_ips`: with allow_private_ips=false
  (and bypass_ip_check), an inbound connect from a registered loopback IP still raises
  handshakes_blocked_total; lookup network test checking listener counters
- [x] `authenticated/lookup/actors/peer/actor.rs`
  `test_invalid_channel_no_unbounded_metric_cardinality`: a Data frame on an unregistered channel
  ends the connection with InvalidChannel and adds no per-channel metric series (peer.zig deliver
  counts meters.invalid); peer test with an upgraded stream pair (needs a peer.zig test harness)
- [x] `authenticated/lookup/actors/peer/actor.rs`
  `test_batches_outbound_sends_into_single_runtime_write`: with send_batch_size 2, two queued sends
  go out in one sink write (counting sink), in order; peer.zig sender task test
- [x] `authenticated/lookup/actors/peer/actor.rs` `test_oversized_data_returns_error`: a Data frame
  one byte over max_message_size (but within the stream frame limit) ends the peer with a decode
  error; peer.zig test
- [x] `authenticated/lookup/actors/peer/ingress.rs` `kill_retained_on_overflow`: two kills into a
  full one-slot peer mailbox yield exactly one Kill and nothing after; zigware's shared outbox.zig
  ("kill comes first and closes later sends") checks one kill with room left, not a repeated kill on
  a full outbox; goes in authenticated/outbox.zig
  Done in lookup/peer_test.zig; outbox.zig has the discovery case.
- [x] `authenticated/lookup/actors/tracker/actor.rs`
  `test_add_set_severs_connection_on_address_change`: tracking a new set that moves a connected peer
  to a new address kills its connection and moves the registered IP; tracker_test.zig covers only
  reserved, not connected, peers for a tracked change (.tracked); goes in lookup/tracker_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs` `test_track_overwrite`: re-tracking a
  primary peer at a new address updates its ingress and directory_updates_total=1, other peers keep
  theirs, our own key never gets an ingress, and a stale index returns null; zig checks only the
  stale index ("track returns only live peers for teardown") and the update counter for secondaries;
  goes in lookup/directory_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs`
  `test_track_primary_wins_conflicting_overlap_when_updating_existing_address`: a connected peer
  re-tracked as primary at a new address and secondary at the old one is killed, keeps the primary
  (new) ingress, dials the new address, and only the new IP is listenable; goes in
  lookup/directory_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs`
  `test_blocked_peer_remains_blocked_on_update`: a blocked peer re-tracked at a new address stays
  blocked, takes the new ingress, and keeps it after unblock_expired; goes in
  lookup/directory_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs` `test_asymmetric_addresses`: asymmetric
  ingress/egress records and listenable egress IPs (lookup/directory_test.zig)
- [x] `authenticated/lookup/actors/tracker/directory.rs`
  `test_listenable_ip_collision_eligible_wins`: two peers sharing an egress IP: the IP stays
  listenable while either is eligible and drops only when both are blocked; goes in
  lookup/directory_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs` `test_dialable_empty`: an empty directory's
  dialable() has no peers and next_query_at null; goes in lookup/directory_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs`
  `test_dialable_expired_block_without_unblock`: after a block expires but before unblock_expired,
  dialable() lists the peer with next_query_at null and dial() succeeds; zig checks only eligible()
  at expiry; goes in lookup/directory_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs` `test_overwrite_peer_not_in_set`: overwrite
  of a peer whose only set was evicted (max_sets=1) returns false; zig checks only a never-tracked
  key; goes in lookup/directory_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs` `test_overwrite_blocked_peer`: overwrite of
  a blocked peer succeeds and updates its ingress, and after unblock_expired it is dialable at the
  new address; tracker_test.zig "an overwritten blocked peer stays out of the listener's set" checks
  only the listenable side; goes in lookup/directory_test.zig
- [x] `authenticated/lookup/actors/tracker/directory.rs`
  `test_dial_rejects_dns_ingress_when_disabled_after_address_change`: with allow_dns=false,
  overwriting a dialable peer to a DNS ingress removes it from dialable() and dial() returns null;
  discovery has "dial rejects an ingress disallowed after an update", lookup does not; goes in
  lookup/directory_test.zig
- [x] `simulated/mod.rs` `register_peer_set`: manager.peer_set(0) is null before any track;
  track(0xFF, {pk1,pk2}) then peer_set(0xFF) == primary set;
  src/p2p/simulated/network_peers_test.zig (only partly covered by 'peer set window management').
  Ported in network_register_test.zig (73c919e).

Not portable:
- `types.rs` `test_from_socket_addr`: tests Rust From<SocketAddr> for Ingress/Address; Zig has no
  From conversion (union literals .{ .socket = a } / .{ .symmetric = a } replace it)
- `authenticated/channels.rs` `registered_rates_size_shared_outbound_mailbox`: tests
  Channels::outbound_mailbox_size for the router actor's shared mailbox; zigware's router is locked
  shared state (router.zig) with no mailbox, outboxes are sized by config.mailbox_size
- `authenticated/channels.rs` `outbound_mailbox_size_panics_on_overflow`: should_panic; also
  outbound_mailbox_size absent (router.zig replaces router mailbox)
- `authenticated/stream.rs` `test_max_message_size_above_limit`: should_panic in
  `stream::Config::new`, which zigware does not have; the same limit panics in discovery's and
  lookup's `Network.create`, whose death tests are ported
- `authenticated/stream.rs` `test_dial_forwards_namespace_and_limit`: tests the stream::Config
  wrapper, absent in zigware: discovery/lookup network.zig pass stream_namespace and max_frame_size
  to the upgrader directly (partly covered by lookup/network_test.zig 'the frame fits the payload
  limit and its overhead' and discovery 'a payload above the receiver's limit is never delivered')
- `authenticated/discovery/actors/spawner/ingress.rs`
  `spawn_overflow_rejects_message_and_releases_reservation`: tests the bounded spawner mailbox;
  zigware has no spawner actor: the handshake task calls Network.serve directly in the Io.Group
  (Decisions), so there is no spawn queue to overflow
- `authenticated/discovery/actors/tracker/bit_set.rs` `test_into_iterator`: tests Rust's
  IntoIterator impl; zigware's BitSet exposes peers as the public `ordered` slice with no iterator,
  and its order is checked by "initialization sorts peers and knows none"
- `authenticated/lookup/actors/listener.rs` `mailbox_keeps_latest_registered_ips`: tests the
  listener's latest-value update mailbox; zigware has no listener actor: listen_loop calls
  tracker.registered(ip) directly under the tracker lock (network.zig Network.registered)
- `authenticated/lookup/actors/spawner/ingress.rs`
  `spawn_overflow_rejects_message_and_releases_reservation`: tests the spawner actor's bounded
  mailbox; zigware has no spawner: connections start with network.tasks.concurrent on one Io.Group,
  and a failed spawn releases the reservation inline (network.zig dial_loop/listen_loop catch)
- `authenticated/router/actor.rs` `subscribe_retains_only_open_initial_sender`: tests router actor's
  open_subscriptions list of ring senders; replaced by router.zig's Watch(P) subscription (no
  per-subscriber sender list)
- `authenticated/router/ingress.rs` `test_unbound_messenger_accepts_and_drops_content`: tests
  Messenger::unbound/bind to the router actor mailbox; zigware's Router is shared locked state
  created before channels, no unbound messenger
- `authenticated/router/ingress.rs` `test_unbound_messenger_defers_subscriptions`: tests deferred
  SubscribePeers mailbox message on bind; replaced by Router.source().subscribe() on Watch
- `authenticated/router/ingress.rs` `test_overflow_rejects_content_but_retains_control`: tests
  router actor mailbox overflow (content rejected, Release retained); router.zig has no mailbox.
  Per-connection analog: outbox.zig 'control frames go ahead of data and drop when full'

### Fuzz coverage audit: network-facing crates (2026-11-19)

Scope (coordinator): p2p, resolver, broadcast and collector, simplex and marshal wire types,
and stream; the parallel lane audits the rest. "Both" means a seeded fuzz in `zig build test`
and a `std.testing.fuzz` target: `codec.fuzz.run`, `utils.fuzz.run`, and `p2p.fuzz.run` run
the body seeded and then under `std.testing.fuzz`, so a test through them counts for both.

Before:
- Missing both, network-facing: p2p discovery `Payload` and the `Info`, `BitVec`, and `Data`
  it dispatches into (`authenticated/discovery/types.zig`, `authenticated/data.zig`), and
  lookup `Message` (`authenticated/lookup/types.zig`). These decode every frame a peer sends.
- Covered by both: p2p `Ingress`/`Address` ("fuzz p2p types decode canonical"); resolver p2p
  wire `Message` ("fuzz: wire decode is canonical"); simplex votes, certificates, and VRF
  seeds for every scheme (`consensus/fuzz/messages.zig`); marshal resolver `Key`
  (`marshal/fuzz.zig`) and coding types (`marshal/coding/fuzz.zig`); aggregation `Item`,
  `TipAck`, `Activity`; broadcast and collector messages (their `fuzz.zig`); stream frames
  (`stream/utils/codec_test.zig`, `stream/fuzz.zig`).
- State machines: p2p simulated, discovery, and lookup networks (`p2p/fuzz/`), broadcast and
  collector engines, the simplex engines and twins, and resolver's fetcher, delivery tracker,
  subscriber tracker, and ingress coalescing each have a fuzz against a model or invariants.
- Test-only `read`s (mock keys, blocks, digests) need none.
- commonware fuzz targets: p2p `discovery`, `lookup`, `simulated`; broadcast
  `broadcast_engine_operations`; collector `collector`; consensus `attributable_map`,
  `simplex_elector`, `simplex_messages`, the 12 `simplex_*` scheme and twin targets, and the new
  `consensus` dispatcher over them; stream `connection`, `e2e`, `lazy_transport`, `transport`.
  Each has a zigware counterpart (`consensus` is a `Plan` enum over the simplex targets, which
  zigware runs one test each). resolver has no commonware fuzz target.

After:
- [x] `authenticated/wire_fuzz_test.zig` "fuzz authenticated wire decoders are canonical and
  bounded": mutates encodings of a greeting, a peer list, a bit vector, data, lookup data and
  ping, plus seeds one past each limit (4 peers, 129 bits, a 65-byte message), and raw bytes
  after a drawn prefix. Any decode of `Payload`, lookup `Message`, or `Data` re-encodes to its
  input and stays within its limits. Planted bugs: lookup accepting prefix 2 as `ping`
  (caught by the fuzz), peer list limit one too high (caught).
- Left: the resolver and p2p engines' network handlers decode first and drop undecodable
  frames, so the decoder fuzzes cover their parsing; driving `handle_network` with arbitrary
  decoded messages has no commonware counterpart and is not added.

### Live interop with commonware (2026-11-19, commonware a9ffc25f3)

- [x] Discovery, through the chat examples: `etc/scripts/interop.sh` builds commonware's
  `examples/chat` offline from the reference clone (target directory outside the repo) and
  zigware's chat, then `etc/scripts/interop_chat.py` runs them in pseudo-terminals as friends 1
  (commonware, bootstrapper) and 2 (zigware). Each side sends a chat line until the other side
  shows it as a received line. Both directions arrive (2 to 17 s, depending on discovery's dial
  timing), which needs SAKE, CUPS with ChaCha20-Poly1305, and discovery's greeting, bit vector,
  and peer exchange to agree byte for byte. A control run with a dead bootstrapper fails. The
  script skips (exit 0) without cargo, python3, or the reference clone.
- [x] Lookup, one-off: a scratch commonware lookup peer (Rust, kept outside the repo at
  `~/.cache/zigware/interop/lookup-peer`, built offline against the reference's `Cargo.lock`)
  and a scratch zigware lookup peer on the production runtime, ed25519 seeds 1 and 2 tracked at
  id 0 on 127.0.0.1. Each sent a message on channel 0 and received the other's from the right
  key. With different namespaces, neither side connects. Not scripted, because the Rust peer
  is not in the repo.
- [x] Consensus, through the log examples (`etc/scripts/interop_log.py`, run by `interop.sh`):
  commonware's `examples/log` validators 0 and 1 and zigware's validators 2 and 3 form one
  simplex committee over discovery. Within about 30 s, 100 views were finalized by all four
  with identical digests, about half proposed by each implementation. Votes, notarizations,
  finalizations, and proposals cross between Rust and Zig and verify on both sides. A zigware
  validator stopped for 10 s and restarted on its storage finalized later views with the same
  digests within 4 s. Pure-Rust and pure-Zig networks nullify the same share of views (about
  1 in 4, in pairs every 6 views), as the mixed one does, at similar throughput.
  - [x] Simplex's resolver channel, both ways (`INTEROP_LOG_RESOLVER=1`, run by `interop.sh`
    as `rrrz` and `zzzr`). Validator 3 is stopped for 8 s and restarted, up to 8 times, until
    its log shows `received certificate for request`: the view it requested, received, and
    verified. Then it must finalize 10 later views with the others' digests. In `rrrz` it runs
    zigware and its three peers run commonware, and the reverse in `zzzr`, so only the other
    implementation can serve the response. Both resolvers log serves only at trace, so that
    is the serve-side evidence. First runs: zigware fetched view 48 from commonware on the 1st
    restart, and commonware fetched view 122 from zigware on the 2nd.
    - Trigger, from probes of `consensus/src/simplex/actors/resolver/state.rs`: the restarted
      node recovers its floor from the journal. If it assembles a notarization or
      nullification above that floor, from current-view votes, before a finalization covers
      the gap, `fetch_missing` requests the gap's term anchors. Otherwise a broadcast
      finalization raises the floor first and nothing is fetched. Over 5 restarts of 8 s
      each, zigware fetched in 4 and commonware in 2. A pause (SIGSTOP) or a longer stop
      (20–30 s) fetched less often.
    - A probe run once aborted with `network failed: BindFailed`: it reused fixed ports while
      the previous run's sockets still held them. That was the harness, not the listener,
      which sets SO_REUSEADDR as tokio does. interop.sh gives each run its own ports.
  - Example GUI differences, not wire: commonware's Activity lines carry span fields and its
    colors do not render under tmux.
  - Demo: `record-demo.sh interop-log` (docs/assets/interop-log-demo.{gif,mp4}).
- [x] dkg, through the dkg examples (`etc/scripts/interop_dkg.py`, run by `interop.sh`). This
  covers buffered broadcast, marshal block sync, glue's threshold DKG and per-epoch reshare,
  and QMDB state sync. One `commonware-dkg setup` (6 participants, committees of 4) drives
  two runs:
  - `rrzz`: commonware players 0 and 1 and zigware players 2 and 3 run the epoch-0 bootstrap
    DKG, and all six `genesis.json` files come out identical. Validators `rrzzr` (0–4)
    finalized 225 heights with identical digests and completed 3 reshares each. zigware's
    validator 5 then joined with `--state-sync`. It probed a recent finalized block from
    peers, synced to height 255 instead of replaying from genesis, and finalized 22 more
    heights with the others' digests.
  - `zzrr`: validators `zzrrz` finalized 256 heights, and commonware's validator 5 joined. Its
    debug log must show glue's probe `requesting boundary block` from peers. Without their
    answer it cannot start above genesis. Marshal's `starting fetch for floor block` and
    resolver deliveries (`received block`, `received finalization`, `received notarization`)
    are reported when seen. Deliveries appeared in 6 of 8 runs; in the other two the floor
    block arrived by broadcast or the probe first, which retires marshal's request.
  - One zigware joiner, in about 8 runs, exited with status 0 and no log line after finalizing
    3 blocks. A zigware actor returned cleanly, and supervision then stops the validator, as
    commonware's `Handle::select` does. It was at info level, so it is not yet known which
    actor. The harness now runs both joiners at debug, and a validator that exits fails the
    run. Closed: after 3d338a0, where glue's probes warn on a failed bootstrap activation
    and propagate `error.Canceled` instead of returning cleanly, 12 runs had no silent exit.
    One more run failed earlier: commonware's bootstrap panicked on `failed to bind listener`
    because another process held its port. interop_dkg.py now starts each network at the
    first base whose six ports bind.
  - An earlier six-validator run (`rrzzrz`, all launched together) finalized 2,612 heights
    through 33 epochs, each a successful reshare, with no digest mismatch. A joiner whose
    peers are all the other implementation (`rrrrr`+z, `zzzzz`+r) synced and matched too.
  - After a join, finalization slows to about 3 blocks/s for about 25 s and then recovers. A
    pure commonware network does the same: the joiner's floor lands past the epoch's
    midpoint, so it sits out that ceremony and counts as faulty (commonware's dkg README).
  - Demo: `record-demo.sh interop-dkg` (docs/assets/interop-dkg-demo.{gif,mp4}, 57 s). It
    shows the mixed bootstrap with identical genesis files, then six titled panes: `rrzzr`,
    and zigware's validator 5 joining with `--state-sync`. They show the same digests at
    every eighth height through each epoch's reshare. In the recorded run all six agreed on
    heights 191–383, where the joiner synced in at 191.
  - Found on the way, not interop: a pure-zigware dkg network aborted in 2 of 6 runs. The
    cause is a null unwrap in glue's inclusion window (`.closed` after `.scan` took the
    request in the same window). The coding lane fixed it in f1e5c99, with a regression
    test.
- [x] Bridge, through the bridge examples (`etc/scripts/interop_bridge.py`, run by
  `interop.sh`).
  - Setup: one dealing sets up both networks. zigware's `bridge-dealer` and commonware's
    `dealer` print byte-identical polynomials, publics, and shares for seeds 1 and 2.
  - Mix: each network runs two validators of each implementation.
  - Indexers: there are two runs. One has a commonware indexer (`rrzzzzrr`, validators 1–8);
    the other has a zigware indexer (`zzrrrrzz`).
  - Pass: each network finalizes 20+ views with one payload from all four validators. In each
    network, validators of both implementations must have proposed a finalized `Bridge` block
    carrying the other network's certificate. A validator verifies the fetched certificate
    against the other network's key before proposing, and every voter verifies it again.
  - Local result: both runs passed, in 15 s (commonware indexer) and 7 s (zigware indexer).
    The views finalized by all four were 21 and 31 in the first run, and 23 and 24 in the
    second.
  - Control: zigware's validators were given a third network's key as `--other-public`.
    Both networks kept finalizing (36 and 63 views), but no `Bridge` block finalized.
    commonware's proposals failed zigware's verification, so they missed the 3-of-4 quorum,
    and zigware's validators found nothing to bridge. So the pass condition depends on
    certificates verifying across implementations.
  - Found on the way, not interop: zigware's bridge application asserts
    `this_network != other_network`, and commonware's has no such check. Given its own
    network's key as `--other-public`, zigware's validator aborts, while commonware's runs
    and bridges its own network's certificates. Reported to the examples lane.
- No wire mismatch turned up, so no vector was added.
- [x] Nightly CI: nightly.yml's `interop` job (`gh workflow run nightly.yml -f only=interop`
  runs it alone) fetches commonware at the pinned revision, builds its chat, log, dkg, and
  bridge examples with cargo (registry and target cached by revision, saved once the build
  succeeds), and runs interop.sh. A skip fails the job, and a failed run uploads
  `interop-logs`: the dkg nodes' logs, the log validators' screens, and the chat screens,
  which the drivers keep under `$TMPDIR`. First run on CI: 44565356294, 17 minutes, green.

### Upstream finding: commonware's flood sender starves its tokio worker (not reported yet)

Held for Andreas's decision on whether to report it upstream; nothing has been filed.
Seen at commonware `a9ffc25f3`, in `examples/flood/src/bin/flood.rs`, while doing the flood
head-to-head in docs/BENCHMARKS.md.

`flood_sender` loops on `flood_sender.check(Recipients::All)` and `checked.send(msg, true)`.
It awaits only when the check is rate-limited. When the check passes but no send is accepted
(before discovery has connected any peer, or when the quota never limits), the loop never
yields. The network tasks it wakes sit in that worker's LIFO slot, which other workers cannot
steal, so they never run. No peer sends its discovery greeting. After the handshakes, about
140 bytes cross each connection, and every peer's `flood_receiver_latency_count` stays 0.
That happens with 2 or 8 worker threads and with 2 or 4 peers.

Minimal repro, on one machine:
1. Apply patch 1, so several peers can share a machine.
2. Run `examples/flood/local.sh 2 <dir> 1024 200` to write a two-peer deployment.
3. In `<dir>`, start each peer with `flood --hosts hosts.yaml --config <key>.yaml`.
4. After 10 s, `curl 127.0.0.{1,2}:9090/metrics` shows `flood_receiver_latency_count 0` while
   `flood_sender_messages_total` grows. The logs show `completed handshake` and
   `peer started` on every peer, and nothing after.

Apply patch 2 and the same deployment receives 600 msg/s per peer. Even with patch 2, an
unthrottled rate (`local.sh 4 <dir> 1024 1000000`) still receives 0, because the quota never
limits the loop, while zigware's flood receives 450–740k per peer. zigware's sender has the
same loop, but it runs on its own `std.Io.Threaded` thread, so the spin starves nothing.

Patch 1 binds a loopback host to its own IP, as zigware's flood does. It is a local-run
convenience, not part of the bug:

```diff
-            Some(SocketAddr::new(
-                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
-                METRICS_PORT,
-            )),
+            Some(SocketAddr::new(local_bind(&peers, &public_key), METRICS_PORT)),
...
-            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.port),
+            SocketAddr::new(local_bind(&peers, &public_key), config.port),
             SocketAddr::new(*ip, config.port),
...
+/// A loopback host binds its own IP, not 0.0.0.0, so several peers share one machine.
+fn local_bind(peers: &HashMap<PublicKey, IpAddr>, me: &PublicKey) -> IpAddr {
+    let ip = *peers.get(me).expect("Could not find self in IPs");
+    if ip.is_loopback() { ip } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) }
+}
```

Patch 2 is the fix: the sender yields when a send is not accepted.

```diff
                     if checked.send(msg, true).accepted() {
                         messages.inc();
+                    } else {
+                        commonware_runtime::reschedule().await;
                     }
```

## Log
- 2026-11-19: end-to-end flood comparison (4 local peers, `etc/scripts/flood-compare.py`,
  docs/BENCHMARKS.md). zigware reaches the quota cap at every rate commonware does, up to
  131072 msg/s per peer, with 5 to 10 times lower mean latency. Where commonware saturates
  (262144) it delivers about 3 times as much. commonware's flood sender starves its tokio
  worker locally (an upstream bug, recorded there) and needed a `reschedule` patch to run.
- 2026-11-19: head-to-head of p2p's hot paths (stream's cipher and handshake; p2p and stream
  have no benches of their own) in docs/BENCHMARKS.md. seal_open went from 2.7 to 3.3 times
  commonware to 0.66 to 1.00 (a lane-per-block ChaCha20 keystream), and sake from 1.33 to 0.55
  (fixed-base tables for ed25519 and X25519 public keys, `ed25519/base_mul.zig`). The crypto
  lane was told before the edits.
- 2026-11-16: (parallel lane) lookup: graceful and clean shutdown, rate limiting, restarts,
  duplicate addresses, multi-index, and custom handshake tests; directory metrics with
  commonware's metric tests.
- 2026-11-16: (parallel lane) lookup Network: peer connections (pings, data), dialer,
  listener with registered-IP admission, and connectivity over the deterministic network.
- 2026-11-16: (parallel lane) lookup Config and tracker (locked state: track with addresses,
  overwrite, registered IPs for the listener, blocks, subscriptions) with the tracker actor
  tests.
- 2026-11-13: lib.rs types and interface checks, types.rs (Ingress, Address, Hostname,
  is_global) with commonware conformance hashes, sizing.rs, decode-canonical fuzz.
- 2026-11-13: Quota and KeyedRateLimiter (governor GCRA port).
- 2026-11-13: utils.limited (LimitedSender, CheckedSender) and utils.Watch.
- 2026-11-13: simulated bandwidth planner (exact rationals) and transmitter; types.zig moved to
  utils.Hostname and utils.net.is_global.
- 2026-11-13: simulated unbounded channel and peer-set tracker.
- 2026-11-13: simulated network core: Oracle, links, send/receive, peer sets, blocking.
- 2026-11-13: simulated link, peer-set, and bandwidth tests; fiber stacks end in a zeroed
  frame so stack traces captured on a fiber stop at its top.
- 2026-11-13: rand_distr ziggurat Normal for link latency, bit-identical to Rust.
- 2026-11-13: simulated blocking and shutdown tests.
- 2026-11-13: authenticated Data frame and lookup Message with conformance hashes.
- 2026-11-13: lookup record and directory with their tests.
- 2026-11-13: authenticated throttle, outbox, router, and channels.
- 2026-11-13: discovery wire types (Payload, BitVec, Info, InfoVerifier) with conformance.
- 2026-11-16: discovery tracker record, bit set, and directory with their tests.
- 2026-11-16: discovery tracker, peer connections, dialer, listener, and Network; five peers
  connect through one bootstrapper on the deterministic network.
- 2026-11-16: discovery metrics (directory, listener, dialer, spawner message counters);
  `Network.create` takes a metrics scope; simulated links sample through `utils.Probability`.
- 2026-11-16: discovery mod.rs tests (connectivity modes and determinism, limits, shutdown,
  rate limiting) and the router slow-peer test.

- 2026-11-16: discovery unordered-set, subscription, and graceful-shutdown tests;
  `Oracle.blocked()` returns an error union like every `Blocker`.
- 2026-11-16: discovery multi-index oracle test.
- 2026-11-16: simulated split senders and receivers for twins, with the split tests.
- 2026-11-16: discovery restart and duplicate-address tests.
- 2026-11-16: discovery tracing events at commonware's sites, with Collector tests.
- 2026-11-16: simulated metrics (messages sent and received per link and channel) and
  tracing events.
- 2026-11-16: simulated channel, link, payload-limit, burst-order, subscription, and
  clean-shutdown tests.
- 2026-11-16: discovery dials DNS ingress through the runtime resolver; DNS tests; slow
  discovery and transmitter tests shrink in Debug.
- 2026-11-18: simulated ordering, role, and broadcast-bandwidth tests; simulated mod.rs and
  network.rs tests are all ported.
- 2026-11-18 (parallel lane): lookup dials DNS ingress through `Config.resolver`; the four
  lookup DNS tests.
- 2026-11-18: discovery mod.rs recheck: every test is ported or has a reason. The slow-peer
  test lives in router.zig; `test_tokio_connectivity` runs on the production runtime, which
  `run_network` already covers on the deterministic one; the `should_panic` tests
  (`max_message_size_exceeds_stream_limit`, `above_stream_boundary`, `message_too_large`)
  panic at the same sites with commonware's messages. The p2p lane's own backlog is done;
  `[-]` items belong to other lanes.
- 2026-11-19: discovery audit batches. `test_tokio_connectivity` now runs (10 peers, Mode::One,
  real TCP on `runtime.production`), replacing the 2026-11-18 skip; the connectivity helpers
  take any transport. Its nodes listen from a random base port that `free_base_port` checks
  binds first, not commonware's fixed 3000, because lanes and CI jobs sharing a host run the
  suite at once. The spawner rejection tests call `Network.serve` (now `pub`) directly over a
  real handshake: a block after reservation stands in for the tracker's dropped responder, a
  closed router for its dropped channels. `kill_retained_on_overflow` checks that a kill
  lands with the control queue full; a zigware kill drains the queue and comes first (where
  commonware queues it last), so the test checks `.killed` rather than the order.
- 2026-11-19: lookup `test_tokio_connectivity` in lookup/network_production_test.zig: 10 peers,
  Mode::One, real TCP on `runtime.production`, from a probed random base port like discovery's.
  It reuses network_test.zig's public helpers rather than making the lookup harness generic.
- 2026-11-19: the real-socket connectivity tests (discovery and lookup) failed silently once on
  CI's loaded arm release runner. Their base ports were drawn from [20000, 60000), inside the
  Linux ephemeral range, so an outgoing connection could take a node's port between the probe and
  its bind; that node never listened and the loop ran out its rounds with no output (release
  builds print no trace). Ports now come from [10000, 32000), below Linux's and macOS's ephemeral
  ranges; `wait_listening` dials every port before the run, and a port that never accepts retries
  the attempt on fresh ports (3 tries); a timeout prints the unheard pairs (discovery) or missing
  deliveries (lookup, now at least 120 s) and failed metric checks print the metrics.
