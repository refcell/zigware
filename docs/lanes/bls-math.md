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
- Encodings use the `codec` package interface (`fixed_size`/`encode_size`, `write`, `read`,
  `Cfg`); `Poly(K).Cfg` is `codec.SliceCfg` (zero coefficients always rejected) and
  `Poly(K).max_encode_size_with(n)` is commonware's `Poly::max_encode_size(n)`.
- Until `parallel` lands, `Strategy` parameters are omitted (sequential); results are identical.
- Conformance hashes (math/conformance.toml) wait for the `conformance` harness.
- Randomness is injected as a `utils.rng` generator pointer (`next_u64`/`fill_bytes`, commonware's
  `CryptoRng`), so ported tests draw the same values as the Rust tests.

## Log
- 2026-11-13: math algebra interfaces, goldilocks field, test field/group, fuzz driver.
- 2026-11-13: math poly (Poly, commit, Interpolator) and varint wire helpers.
