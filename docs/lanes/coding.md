# Lane: coding

Owns `src/coding` and `src/cryptography/reed_solomon/` (taken over from the crypto lane;
add the `pub const reed_solomon` line to `src/cryptography/root.zig`, additive edit).

Reference: `~/.cache/zigware/commonware-ref/{coding,cryptography/src/reed_solomon}`. Coding
commits to shards with storage's bmt and merkle (storage-merkle lane) and cryptography's
hashers (on main).

## Backlog
- [ ] reed_solomon: GF(2^16) arithmetic, engines (scalar first, then `@Vector` SIMD),
  rate encoder/decoder (high and low rate), wrappers, same output as commonware's port of
  reed-solomon-simd. Port its tests and fuzz target.
- [ ] coding: the Scheme interface, reed_solomon scheme (encode into shards with a BMT
  commitment, check, reshard, decode from any k shards), shard selection, codec encodings
  identical to commonware's. Port lib.rs and reed_solomon.rs tests.
- [ ] Fuzz targets (commonware coding/fuzz) and conformance hashes.

## Log
