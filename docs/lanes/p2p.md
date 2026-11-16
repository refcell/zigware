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
  `LinkingSelf`, `LinkExists`, `LinkMissing`.
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
  `utils.shuffle` (rand 0.10 `shuffle`/`partial_shuffle`).
- `authenticated.lookup.Network(U, Transport)` (parallel lane): like discovery's, with
  `Net.Config.local/recommended(.{ upgrader, namespace, listen, max_peers_per_set,
  max_message_size, mailbox_size })`, `create(gpa, io, *transport, scope, config)`,
  `register`, `run`, `destroy`. `oracle()` is an `AddressableManager`: `track(index,
  AddressableTrackedPeers)`, `overwrite(PeerMap)`, `peer_set`, `subscribe`, `block`,
  `blocked`. `lookup.Tracker(P)` is the locked tracker it uses.
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
- p2p carries its own seeded fuzz driver (`p2p.fuzz.run`, same as codec's) until
  `invariants.minifuzz` lands.

## Backlog
- [x] types.rs, sizing.rs, lib.rs traits (`Sender`, `Receiver`, `Blocker`, `Manager`,
  `Recipients`, channels) as comptime interfaces; Ingress/Address conformance; decode fuzz.
- [x] Rate limiter: `Quota` and governor's keyed GCRA (`rate_limit.zig`).
- [x] utils: limited (`LimitedSender`, `CheckedSender`) with its tests.
- [ ] utils: codec (wrapped sender/receiver), mux (channel multiplexing), mocks,
  `StaticProvider`.
- [x] simulated: bandwidth planner and transmitter with their tests.
- [x] simulated: unbounded channel and peer-set tracker.
- [x] simulated: network core (Oracle, Control, Manager, links with latency/jitter/success
  rate, rate-limited senders, receivers, peer-set tracking) with its first tests.
- [x] simulated: dynamic links, peer-set window and own/network-wide peer sets, and every
  bandwidth test (contention, sharing, staggered, pipe reservation, zero limits).
- [x] simulated: ziggurat `Normal` for byte-identical latency samples.
- [x] simulated: blocked subscriptions, disconnect_on_block, operations after shutdown.
- [ ] simulated: remaining mod.rs tests (peer-set subscriptions, socket manager, clean
  shutdown, duplicate channel), split senders and receivers, metrics (runtime.telemetry).
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
- [ ] discovery mod.rs tests: multi-index oracle, restarts (many, simultaneous, new address),
  duplicate addresses, DNS (after a resolver exists).
- [ ] lookup (parallel lane): tracker, peer, dialer, listener, Network with Config and Oracle
  (done, with connectivity); the rest of commonware's lookup mod.rs tests and the directory's
  metrics.
- [ ] utils codec: `WrappedBackgroundReceiver` (decode on a parallel Strategy); then tell
  broadcast-collector so buffered's config can take the Strategy (low priority, after
  discovery).
- [ ] Fuzz targets (commonware p2p/fuzz).

## Log
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
