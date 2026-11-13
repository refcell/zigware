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

## Backlog
- [ ] aggregation: types (with conformance hashes), scheme, safe_tip, limits, config,
  metrics, engine, mocks; port mod.rs tests on p2p.simulated with each certificate scheme.
- [ ] marshal: ancestry, store, limits, config, conformance types, application traits.
- [ ] marshal resolver, core, standard (and coding) actors with their mocks and tests.
- [ ] Fuzz targets (consensus/fuzz entries for aggregation and marshal).

## Log
