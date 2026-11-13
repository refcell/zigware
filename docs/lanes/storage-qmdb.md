# Lane: storage-qmdb

Owns `src/storage/qmdb/`. Add the `pub const qmdb` line to `src/storage/root.zig` (additive).

Reference: `~/.cache/zigware/commonware-ref/storage/src/qmdb` (about 95k Rust lines). This
lane does the shared modules and the keyless, immutable, and any databases. `current`,
`sync`, and `compact` (about 34k lines) go to a second lane once `any` lands.

Builds on (all on main unless noted): `storage.journal.contiguous.fixed` (9717c08),
`storage.journal.segmented.{variable,glob}`, `storage.index` (unordered, ordered,
partitioned, immutable), `storage.merkle` (MMR and MMB, Mem, proofs, ProofStore),
`storage.AuthenticatedBitMap`, `storage.metadata`, `runtime.storage.memory`,
`runtime.buffer`, `runtime.telemetry.metrics`, and the deterministic runner's storage.
Not yet on main: persisted merkle (storage-merkle lane) and `journal/authenticated.rs`
(storage-journal lane). Both lanes are porting them now; until they land, work on the parts
that don't need them and keep a small interface where you must.

## Backlog
- [ ] Shared: operation, value, floor, chain, snapshot, cache, bitmap, metrics, verify, and
  the store traits, with codec conformance hashes (conformance.rs lists them).
- [ ] keyless (with its tests and conformance hashes).
- [ ] immutable.
- [ ] any (ordered and unordered, fixed and variable).
- [ ] Fuzz targets under storage/fuzz for these databases; benches under `benches.zig`.

## Log
