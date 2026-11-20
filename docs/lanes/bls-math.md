# Lane: bls-math

Owns `src/math`, `src/simd`, `src/cryptography/bls12381/`. Add
`pub const bls12381 = @import("bls12381/root.zig");` to `src/cryptography/root.zig` (owned by
lane crypto; additive edit).

Also owns, by agreement with p2p, commonware `p2p/src/utils` codec, mux, and mocks:
`src/p2p/utils/{codec,codec_test,mux,mux_test}.zig` and `src/p2p/utils/mocks/`, re-exported
from `src/p2p/utils/mod.zig`. p2p keeps limited, watch, io_rng, and shuffle.

Reference: `~/.cache/zigware/commonware-ref/{math,simd,cryptography/src/bls12381}`.
A from-scratch zero-dependency BLS12-381 (fields, G1/G2, pairing, hash-to-curve, MSM) already
exists in `~/needlefish/src/common/crypto/bls12_381` and `montgomery.zig` (same author, MIT);
adapting it is allowed and faster than starting over. Commonware's encodings, DSTs, and
variants (MinPk, MinSig) must match exactly.

## Backlog
- [x] math: algebra traits, fields (goldilocks), poly (polynomials, evaluation,
  interpolation), ntt, synthetic. Port math's tests, and its five `CodecConformance` hashes
  via `conformance.verify` against `src/math/conformance.toml` (math/conformance_test.zig).
- [x] simd: the operations commonware abstracts (simd/src/core.rs), scalar + `@Vector`
  implementations with the consistency tests.
- [x] bls12381 primitives: group elements, scalars, compressed codec, hash-to-curve with
  commonware's DSTs, sign/verify, aggregate, MinPk and MinSig variants, batch verify. Vectors.
- [x] bls12381 threshold: polynomial shares, partial signatures, recovery (primitives/ops),
  and the trusted dealer `dkg.feldman_desmedt.deal_anonymous`.
- [x] bls12381 codec conformance entries (group, partial signature, aggregate types, tle
  Ciphertext) via `conformance.verify` against `src/cryptography/conformance.toml`.
- [x] bls12381 tle (timelock encryption) with commonware ciphertext vectors.
- [x] bls12381 certificate schemes (multisig, threshold) on `cryptography.certificate`, with
  their `Certificate<MinSig>` conformance hashes and mocks fixtures.
- [x] bls12381 dkg feldman_desmedt: Info, Dealer, Player, Logs, observe, deal, reshare,
  the test plan and its tests, and the message and FeldmanTranscript conformance hashes.
- [x] bls12381 scheme.rs (PrivateKey, PublicKey, Signature) with its conformance hashes.
- [x] bls12381 dkg golden (commonware `dkg::golden`): the eVRF over banderwagon with its
  bulletproofs conversion, the eVRF keys, `Setup`, `vrf_batch_checked`, `VrfCommitments`
  and `check_batch`, `Info`, `Output`, `Dealing`, the (signed) dealer logs,
  deal/observe/play, the test plan with every commonware test, and the dkg_golden fuzz
  target. commonware has no golden conformance entries.
- [x] Fuzz targets: math (the crate plan), simd (differential), and the bls12381 decode,
  primitive, threshold, aggregate, batch, tle, and dkg_feldman_desmedt targets.
- [x] Benchmarks: math (`interpolation`) and bls12381 (`benches/*.rs`) in
  `src/<package>/benches.zig`, with commonware's names and its `conc=1` cases. The golden
  benchmarks skip the Debug smoke run: building their eVRF setup takes minutes there.
- [x] banderwagon (commonware `cryptography/src/banderwagon.rs`, moved from the crypto lane) as
  `cryptography.banderwagon`: F, G (codec, hash_to_group), GVar and the circuit gadgets,
  with every commonware test and the go-ipa fixed vectors. commonware has no banderwagon
  conformance entries or fuzz target; a decode fuzz target is added.
- [x] p2p utils codec: `wrap`, `WrappedSender`, `WrappedReceiver`, and
  `WrappedBackgroundReceiver` (decodes through a `parallel` strategy) with codec.rs's tests.
- [x] p2p utils mux: `Muxer`, `MuxHandle`, `SubSender`, `SubReceiver`, `GlobalSender`,
  backup channel, `parse`, `prefixed`, with mux.rs's tests (not the `should_panic` one).
- [x] p2p utils mocks: inert sender and receiver with their tests.
- [x] Cryptography benches (taken over from the crypto lane) in
  `src/cryptography/benches/{hashes,signatures,primitives}.zig`: blake3, sha256, sha512,
  ed25519, secp256r1, bloomfilter, chacha20_poly1305, lthash, sake, and bulletproofs ipa, with
  commonware's names and cases.
- [x] p2p fuzz targets (commonware p2p/fuzz), taken over from p2p: simulated
  (`src/p2p/fuzz/simulated.zig`), discovery and lookup (`src/p2p/fuzz/authenticated.zig`).
- [x] marshal standard/mod.rs lines 1987-2543 (the cache-epoch tests), a slice from
  consensus-marshal: `src/consensus/marshal/standard/tests/cache_epoch.zig`. The
  interrupted-prune test found a double release in `core/cache.zig`'s failed destroy (fixed by
  consensus-marshal, 8b17760).
- [x] Check marshal's and aggregation's threshold paths against the simplex VRF scheme:
  aggregation's matched; marshal limits gained commonware's two VRF fixture cases.

## Decisions
- p2p utils codec: payloads are byte slices, so decoded values are copies, not views of the
  frame; a background receiver's `V` must own its memory. Its decode loop is a receive task
  that submits each decode to the strategy as it arrives and a completion task that awaits
  decodes in arrival order (commonware forwards in completion order). A canceled background
  receiver still awaits and forwards the decodes it submitted, since a Zig task must be
  awaited.
- Cryptography benches: `blake3::hash_message` has commonware's `conc=1` and `conc=8` rows
  since `hash_across` splits a message (61ef1580); `bulletproofs::ipa::verify`'s `conc=8` rows
  time the same sequential `eval`. Inputs commonware rebuilds per iteration are reset in `before_iter` or
  built once when no iteration changes them. Smoke runs use the first case of each list.
- p2p fuzz: inputs decode from `Unstructured` as commonware's `Arbitrary` derive does, and
  the coverage-guided target runs commonware's decoder unchanged. The seeded minifuzz run
  first `densify`s the input (at most four peers, two channels, every channel registered,
  every pair linked reliably, short messages), since uniform draws almost never line up a
  send and a receive; a planted payload corruption fails it at a replayable branch.
  The discovery and lookup targets share one harness (commonware's `NetworkScheme`); their
  seeded run lets the cluster connect for a simulated minute first (`settle_ms`), since
  commonware's draws otherwise send before any connection exists.
- p2p utils mux: the routing table is shared under a mutex instead of commonware's control
  channel, so `register` and a released `SubReceiver` update it directly; the muxer stops
  once every handle and subchannel receiver is released, or when the wrapped receiver fails.
  The builder typestates are `Muxer.build`'s `Options`. Commonware's mocks `Metrics` has no
  counterpart: a metrics `Scope` over a scratch `Registry` serves.
- golden: commonware ignores `fake_mask_filtered` because a comment says `check_batch`
  rejects the whole batch; its batched check (and ours) falls back to each dealer, so the
  test runs here and passes. Plans hold up to 16 dealers or players, as bit masks.
- Algebraic types are value types with `zero`/`one` decls and `add`/`sub`/`neg`/`mul`/`inv`/
  `eql` methods; `math.algebra` documents the interfaces and supplies trait defaults
  (`exp`, `scale`, `double`, `msm`, `div_2`). A module element `K` over scalars `R` multiplies
  with `K.mul(K, R)`, so groups and fields share one `Space` interface.
- Property tests run on `invariants.minifuzz` with commonware's draw order;
  `math.testing.smith_body` adapts a minifuzz body to `std.testing.fuzz`.
- banderwagon `F` stores a canonical `u256` and multiplies with a `u512` product reduced
  modulo `r` (commonware uses double-and-add; the results are equal). The circuit gadgets
  issue their `Var` operations in commonware's order so circuits match node for node, and
  `scalar_mul_many_in_circuit` writes into a caller slice instead of returning a `Vec`.
- Encodings use the `codec` package interface (`fixed_size`/`encode_size`, `write`, `read`,
  `Cfg`); `Poly(K).Cfg` is `codec.SliceCfg` (zero coefficients always rejected) and
  `Poly(K).max_encode_size_with(n)` is commonware's `Poly::max_encode_size(n)`.
- `Strategy` parameters (`strategy: anytype`, parallel package) are taken where commonware's
  parallel paths are ported; results never depend on the strategy shape. `Poly.interpolate_strategy`
  (commonware `interpolate(evals, strategy)`) sums through `K.msm_strategy` when `K` provides
  one, else runs `interpolate`; `G1`/`G2.msm_strategy` sum in strategy-cut tiles
  (`arithmetic.msm.msm_tiled`). Ops without a ported parallel path stay sequential.
- math's conformance entries (test `F`/`G`, goldilocks `F`, `Poly<F>`, `Matrix<F>`) run in the
  default `zig build test` (about 4 s in Debug); `math` depends on `conformance` as commonware's
  dev-dependency does.
- Randomness is injected as a `utils.rng` generator pointer (`next_u64`/`fill_bytes`, commonware's
  `CryptoRng`), so ported tests draw the same values as the Rust tests.

- BLS12-381 arithmetic is adapted from needlefish. Scalar multiplication of points is
  variable time (GLV/GLS windows); commonware uses blst's constant-time code. Signing with a
  secret scalar therefore leaks timing; a constant-time ladder is a follow-up.
- `threshold.batch_verify_same_message` returns positions of invalid partials (out-of-range
  indices first, then failed verifications ascending) instead of references; same set.
- Slow test cases (every noble vector, large bisections) run in release builds or with
  `-Dslow-tests`; Debug runs a deterministic subset.
- A local Rust oracle (not committed) built against commonware-ref produced the byte vectors
  for points, hashes, dealings, shares, and recovered signatures.

- Certificate schemes fold commonware's `impl_certificate_bls12381_*!` macro and `Generic` into
  `Scheme(Subject, Faults, P, V)`. The threshold scheme's 12 `#[should_panic]` tests (certificate
  verifier on a vote, mismatched sharing) are death tests through `utils.death.expect_panic`,
  one Zig test per variant, since the helper reruns its whole calling test in a child.

- feldman_desmedt: `Dealer`, `Player`, and `Logs` borrow their `Info` (commonware moves a
  clone into each), so the `Info` must outlive them. `Logs.select` returns a `Selection` of
  log pointers borrowed from the `Logs`; `select`, `observe`, and `Player.finalize` take
  `*Logs` and update its check cache where commonware consumes a clone. Errors carry no
  data: `Failure::InsufficientLogs` is `error.InsufficientLogs` plus an optional `*Failure`
  out-parameter (faults as a sorted slice, since `FaultReason` has no wire format), and
  `DealerMessageError::InvalidCommitmentDegree` drops its expected/actual degrees (the
  signed-log `FaultReason` keeps them). `Player.resume_from` takes the logs as a slice of
  `{ dealer, log }` pairs. The test plan's 3+ round cases run only in release builds or with
  `-Dslow-tests`.

- scheme: `PublicKey.verify_batch` hashes each 64-entry chunk's messages through its `strategy`
  (`map_into`), as commonware does, then checks one random linear combination per chunk,
  drawing scalars in commonware's order; the
  `projected_batch_indexes_zero_sized_items` test runs on `parallel.sequential` only, not
  commonware's `mocks::explore` shapes.

- Fuzz: `bls12381_decode` checks round-trips and agreement with the group decoders instead
  of differential checks against blst, which zigware does not have.

- simd: one `@Vector` implementation per profile (scalar 64-bit, x86_v3 256, x86_v4c 512,
  neon/arm_v9 128) stands in for both commonware's emulated and native tokens; `dispatch`
  picks the compile target's best profile at comptime. Profile-only instructions are `void`
  on other profiles, so misuse is a compile error. Operations declare `pub const Output`.

## Drift: simd (commonware 43b357a41..a9ffc25f3)

- [x] 21eb7bbf9 "Require tokens and vectors to be Send and Sync": adds `Send + Sync + 'static`
  bounds to `Simd` and its vector types, plus README and doc text. Classified as no port: Zig
  has no Send/Sync, and our tokens and vectors are plain values that any thread may hold. No
  test, vector, or behavior changed.
- [x] 162216038 "Track floating Rust compilers and pin lint tools": gates the x86-64 native
  backend on `target_feature = "sse2"` and drops a `clone()` of a `Copy` value in the
  operation test. Classified as already matched: `native_profile` selects `x86_v3` only with
  avx2 (which implies sse2) and `x86_v4c` only with avx512, else `scalar`, so an x86-64
  target without sse2 already gets the portable backend. No test changed behavior.

## Log
- 2026-11-13: math algebra interfaces, goldilocks field, test field/group, fuzz driver.
- 2026-11-13: math poly (Poly, commit, Interpolator) and varint wire helpers.
- 2026-11-13: math ntt (NTT, recovery, vanishing, Lagrange), synthetic, codec migration.
- 2026-11-13: simd backends, profile instructions, dispatch, consistency, SHA-256 checks.
- 2026-11-13: math property tests on invariants.minifuzz; temporary fuzz driver removed.
- 2026-11-13: bls12381 arithmetic, group, variants, ops, aggregate, batch, noble/eth vectors.
- 2026-11-13: bls12381 sharing, threshold ops, deal_anonymous; vectors match commonware.
- 2026-11-13: bls12381 tle and the bls12381 codec conformance hashes (11 entries).

- 2026-11-13: bls12381 multisig and threshold certificate schemes with conformance hashes.
- 2026-11-13: feldman_desmedt messages and their 8 conformance hashes; round info, dealer,
  and the FeldmanTranscript conformance hashes.
- 2026-11-13: feldman_desmedt Logs, observe, Player, deal, the test plan, and 48 tests.
- 2026-11-13: bls12381 scheme keys and signatures with their 3 conformance hashes.

## Test audit (2026-11-19, against main)

Every commonware `#[test]` in this lane's crates (macro and rstest cases expanded where noted), matched by reading both sides: ported (a Zig test checks the behavior, often one consolidated test), open, or not portable with the reason. Written by the consensus-marshal lane; tick a box when its test lands.

### math
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| algebra.rs | 1 | 1 | 0 | 0 |
| fields/goldilocks.rs | 7 | 7 | 0 | 0 |
| ntt.rs | 7 | 7 | 0 | 0 |
| poly.rs | 4 | 4 | 0 | 0 |
| synthetic.rs | 3 | 3 | 0 | 0 |
| test.rs | 2 | 2 | 0 | 0 |
| Total | 24 | 24 | 0 | 0 |

Open:
- none

Not portable:
- none


### Test audit: bls-math (2026-11-19, commonware 43b357a41, p2p lane)

Drift check (commonware 43b357a41 to a9ffc25f3, p2p lane, 2026-11-19): `math/algebra.rs` renames an
import, `bls12381/dkg/feldman_desmedt.rs` drops clones in its test plan, and
`math/proptest-regressions/ntt.txt` is deleted. No behavior or test change.

Every `#[test]`/`#[rstest]` fn in commonware `cryptography/src/bls12381`, with each `#[case]` and
each test-generating macro expansion counted separately, matched to a zigware test by name or by
reading both bodies (a zigware test may cover several). 288 tests: 267 ported, 5 open, 16 not
portable.

Since ported (actor-stream lane, strategy-tiled msm): `test_msm_parallel_g1`,
`test_msm_parallel_g2`,
`test_msm_parallel_edge_cases_g1`, `test_msm_parallel_edge_cases_g2`,
`msm_tiled_covers_every_window_of_every_point`, and
`msm_matches_naive_sum_through_cut_and_padded_tiles`, in
src/cryptography/bls12381/primitives/group_msm_tests.zig. That makes 273 ported, 2 open, and 13 not
portable. The Zig tile kernel reads only its own range, so one-point tiles are not padded; the
coverage test checks a twelve-worker cut of 64 points still reaches a one-point tile.

Since ported (bls-math lane, death tests): the 12 threshold `#[should_panic]` tests, in
src/cryptography/bls12381/certificate/threshold_tests.zig. That makes 285 ported, 2 open, and 1 not
portable. Planting a missing panic at each of the four preconditions (or a different message)
fails all 12.

The two open entries were already ported: `test_g2_msm` ("group: g2 msm on empty input and many
points", 44045a40; 50,000 points outside Debug) and `test_rejects_malleability` ("ops:
verify_same_signer rejects offsets that cancel in the aggregate", 09f7d33f; equal batch weights
fail it). That makes 287 ported, 0 open, and 1 not portable.

| commonware file | tests | ported | open | not portable |
|---|---|---|---|---|
| `bls12381/scheme.rs` | 8 | 8 | 0 | 0 |
| `bls12381/tle.rs` | 10 | 10 | 0 | 0 |
| `bls12381/certificate/multisig/mod.rs` | 24 | 24 | 0 | 0 |
| `bls12381/certificate/threshold/mod.rs` | 33 | 33 | 0 | 0 |
| `bls12381/dkg/feldman_desmedt.rs` | 48 | 48 | 0 | 0 |
| `bls12381/dkg/golden/mod.rs` | 32 | 32 | 0 | 0 |
| `bls12381/dkg/golden/evrf/banderwagon.rs` | 8 | 7 | 0 | 1 |
| `bls12381/dkg/golden/evrf/mod.rs` | 5 | 5 | 0 | 0 |
| `bls12381/primitives/group.rs` | 34 | 34 | 0 | 0 |
| `bls12381/primitives/sharing.rs` | 5 | 5 | 0 | 0 |
| `bls12381/primitives/variant.rs` | 4 | 4 | 0 | 0 |
| `bls12381/primitives/ops/aggregate.rs` | 5 | 5 | 0 | 0 |
| `bls12381/primitives/ops/batch.rs` | 6 | 6 | 0 | 0 |
| `bls12381/primitives/ops/mod.rs` | 47 | 47 | 0 | 0 |
| `bls12381/primitives/ops/threshold.rs` | 19 | 19 | 0 | 0 |

Open:
- [x] `bls12381/primitives/group.rs` `test_g2_msm`: Zig
  src/cryptography/bls12381/primitives/group_tests.zig "group: msm matches the naive sum" covers G2
  at 1 and 10 points (random, identity point, zero scalar, all-zero scalars/points, single) but not
  G2 empty input or the 50,000-point G2 case (large-window path); add both to group_tests.zig (big
  case behind -Dslow-tests)
- [x] `bls12381/primitives/ops/batch.rs` `test_rejects_malleability`: batch::verify_same_signer
  malleability: for MinPk and MinSig sign two messages with one key, forge sig1-delta and
  sig2+delta, check each fails verify_message, the aggregates are equal and naive aggregate verify
  over hm1+hm2 accepts, then batch.verify_same_signer rejects the forged entries and accepts the
  valid ones. Zig has the cancelling-offset check only for V.batch_verify with two signers
  (ops/tests.zig "variant: batch verify accepts valid and rejects empty, identity, and forgeries")
  and for verify_same_message bisection, not for verify_same_signer. Add to
  src/cryptography/bls12381/primitives/ops/tests.zig

Not portable:
- `bls12381/dkg/golden/evrf/banderwagon.rs` `measure_circuit_size_per_receiver`: #[ignore]
  diagnostic that only eprintln!s circuit sizes and asserts nothing; no behavior to port (circuit
  capacity exactness is asserted in src/cryptography/bls12381/dkg/golden/evrf/banderwagon_tests.zig
  build helper)
