# Lane: storage-merkle

Owns `src/storage/{merkle,bmt,bitmap,index,rmap}`, `src/storage/translator.zig`, and
`src/storage/root.zig` (other storage lanes add their `pub const` lines there).

Reference: `~/.cache/zigware/commonware-ref/storage/src`. These modules are mostly pure data
structures over cryptography's hashers; build them against `cryptography`'s `Hasher`
interface (sha256), stubbing with `std.crypto.hash.sha2.Sha256` until it lands. Persisted
variants need `runtime` storage; do them after its interface lands.

## Backlog
- [ ] translator.rs (key translators) and rmap (range map).
- [ ] merkle/mmr: in-memory MMR (append, root, proofs, range proofs, verification), node
  positions and peaks math identical to commonware, proof codec. Port its tests and vectors.
- [ ] merkle/mmb and shared merkle proof types.
- [ ] bmt (binary merkle tree) with proofs and multi-proofs.
- [ ] bitmap (authenticated bitmap over MMR).
- [ ] index (ordered/unordered, partitioned) over translators.
- [ ] merkle/persisted (journaled MMR) once runtime storage lands.
- [ ] Fuzz targets (storage/fuzz entries for these modules).

## Log
