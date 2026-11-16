# Lane: clearing

Owns `src/clearing`.

Reference: `~/.cache/zigware/commonware-ref/clearing` (about 16k Rust lines: lib.rs and
`bajillion`: amounts, close, lookup, matrix, namespace, payment, settlement, summary,
validator, tests). Its dependencies are all on main: codec, cryptography (incl. bls12381 and
the certificate mocks), parallel, utils, storage `bmt` and `merkle` (mmr, mmb), conformance,
formatting, and the deterministic runtime for tests. qmdb is only mentioned in comments.

## Backlog
- [ ] lib.rs types and traits.
- [ ] bajillion: namespace, amounts, payment, matrix, summary, lookup, settlement, close,
  validator, with their conformance hashes and commonware's tests (tests.rs).
- [ ] Fuzz targets (clearing/fuzz) and benches (`src/clearing/benches.zig`).

## Log
