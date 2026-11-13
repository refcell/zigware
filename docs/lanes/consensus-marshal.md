# Lane: consensus-marshal

Owns `src/consensus/aggregation/` and `src/consensus/marshal/`. Add the `pub const` lines to
`src/consensus/root.zig` (owned by consensus-simplex; additive edits).

Reference: `~/.cache/zigware/commonware-ref/consensus/src/{aggregation,marshal}`.

Aggregation (about 4.6k Rust lines) needs only what is on main: consensus types,
cryptography's certificate schemes (ed25519, secp256r1, bls12381 multisig and threshold),
`actor.mailbox`, `utils` oneshot, `runtime.telemetry.metrics`, and `p2p.simulated`. Do it first.

Marshal (about 57k lines) orders finalized blocks from simplex into an application. It uses
`broadcast.buffered` and `resolver.p2p` (broadcast-resolver lane, in progress),
`storage.archive` (storage-archive lane, in progress), and `coding` (on main). Start with its
pure parts (ancestry, store traits, limits, config, conformance types, coding shard types),
then the core and standard actors as those packages land.

## Public API (on main)
- `consensus.aggregation.types`: `Item(D)` (height, digest; also the certificate `Subject`,
  signing the encoded item under `Namespace`), `Namespace` (`_AGG_ACK` suffix), `Ack(S, D)`
  (`sign(gpa, *const S, epoch, item) !?Ack`, `verify(gpa, rng, *const S, strategy)`),
  `TipAck(S, D)`, `Certificate(S, D)` (`from_acks(gpa, *const S, acks, strategy)`, `verify`,
  `clone`, `deinit`), `Activity(S, D)` (`ack`/`certified`/`tip`, `height()`), `Error`,
  `blockable(err)`. All with codec and `arbitrary`.
- `consensus.aggregation.scheme`: `ed25519.Scheme(D)`, `secp256r1.Scheme(D, P)`,
  `bls12381_multisig.Scheme(D, P, V)`, `bls12381_threshold.Scheme(D, P, V)`, each with
  `fixture(S, gpa, rng, namespace, n)`; `assert_scheme(S, D)`.
- `consensus.aggregation.max_payload_size(S, D)`; `consensus.aggregation.SafeTip(P)`
  (`init(gpa, *const Set)`, `reconcile`, `update`, `get`, `deinit`).

## Decisions
- `Item(D)` is the certificate subject itself (passed by value); commonware uses `&Item<D>`.
- `Error` variants carry no payload. `Certificate.from_acks` returns `InsufficientAttestations`
  without commonware's expected/found counts.
- `SafeTip` allocates its validator, tip, and heap arrays at `init` (heaps are sorted
  (height, count) arrays in place of `BTreeMap`), so updates and reconciles never allocate.
  Its `should_panic` tests have no counterpart (Zig cannot catch panics); a seeded fuzz
  against a sorting reference covers the heaps instead.
- The aggregation conformance hashes use test-local wire types for
  `bls12381_threshold::Scheme<_, MinSig>` (a MinSig point with commonware's `G1::arbitrary`),
  as simplex does; the BLS conformance and codec tests skip in Debug without `-Dslow-tests`.

## Backlog
- [x] aggregation: types (all 5 conformance hashes match), scheme, limits, safe_tip.
- [ ] aggregation: config, metrics, engine, mocks; port mod.rs tests on p2p.simulated with
  each certificate scheme.
- [ ] marshal: ancestry, store, limits, config, conformance types, application traits.
- [ ] marshal resolver, core, standard (and coding) actors with their mocks and tests.
- [ ] Fuzz targets (consensus/fuzz entries for aggregation and marshal).

## Log
- 2026-11-13: aggregation types, schemes, limits, safe_tip; 5 conformance hashes match.
