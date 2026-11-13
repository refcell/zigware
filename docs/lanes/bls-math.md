# Lane: bls-math

Owns `src/math`, `src/simd`, `src/cryptography/bls12381/`. Add
`pub const bls12381 = @import("bls12381/root.zig");` to `src/cryptography/root.zig` (owned by
lane crypto; additive edit).

Reference: `~/.cache/zigware/commonware-ref/{math,simd,cryptography/src/bls12381}`.
A from-scratch zero-dependency BLS12-381 (fields, G1/G2, pairing, hash-to-curve, MSM) already
exists in `~/needlefish/src/common/crypto/bls12_381` and `montgomery.zig` (same author, MIT);
adapting it is allowed and faster than starting over. Commonware's encodings, DSTs, and
variants (MinPk, MinSig) must match exactly.

## Backlog
- [ ] math: algebra traits, fields (goldilocks), poly (polynomials, evaluation,
  interpolation), ntt, synthetic. Port math's tests.
- [ ] simd: the operations commonware abstracts (simd/src/core.rs), scalar + `@Vector`
  implementations with the consistency tests.
- [ ] bls12381 primitives: group elements, scalars, compressed codec, hash-to-curve with
  commonware's DSTs, sign/verify, aggregate, MinPk and MinSig variants, batch verify. Vectors.
- [ ] bls12381 threshold: polynomial shares, partial signatures, recovery (primitives/ops).
- [ ] bls12381 dkg (Joint-Feldman / reshare) and tle (timelock encryption).
- [ ] bls12381 certificate schemes (multisig, threshold) and scheme.rs.
- [ ] Fuzz targets (commonware math/fuzz, simd/fuzz, bls parts of cryptography/fuzz).

## Decisions
- Algebraic types are value types with `zero`/`one` decls and `add`/`sub`/`neg`/`mul`/`inv`/
  `eql` methods; `math.algebra` documents the interfaces and supplies trait defaults
  (`exp`, `scale`, `double`, `msm`, `div_2`). A module element `K` over scalars `R` multiplies
  with `K.mul(K, R)`, so groups and fields share one `Space` interface.
- Until `invariants.minifuzz` lands, `math.fuzz` provides `Unstructured` and the seeded and
  `std.testing.fuzz` drivers; fuzz plans are `fn (void, *Unstructured) !void`.
- Until `codec` lands, fixed-size types expose `encode_size`, `encode() [N]u8`, and
  `decode(*const [N]u8) error{Invalid}!T` with commonware's byte layout (big-endian ints).
- Until `parallel` lands, `Strategy` parameters are omitted (sequential); results are identical.
- Conformance hashes (math/conformance.toml) wait for the `conformance` harness.
- Randomness is injected as `std.Random` (commonware's `CryptoRng`).

## Log
- 2026-11-13: math algebra interfaces, goldilocks field, test field/group, fuzz driver.
