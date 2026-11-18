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
  interpolation), ntt, synthetic. Port math's tests. (Conformance hashes wait for the
  `conformance` harness.)
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
- [ ] marshal standard/mod.rs lines 1987-2543 (the cache-epoch tests), a slice from
  consensus-marshal: `src/consensus/marshal/standard/tests/cache_epoch.zig`. Seven of eight
  pass. The interrupted-prune test is skipped until consensus-marshal fixes `core/cache.zig`'s
  `prune_by_view`, which deinitializes archives a failed destroy already released.
- [x] Check marshal's and aggregation's threshold paths against the simplex VRF scheme:
  aggregation's matched; marshal limits gained commonware's two VRF fixture cases.

## Decisions
- p2p utils codec: payloads are byte slices, so decoded values are copies, not views of the
  frame; a background receiver's `V` must own its memory. Its decode loop is a receive task
  that submits each decode to the strategy as it arrives and a completion task that awaits
  decodes in arrival order (commonware forwards in completion order). A canceled background
  receiver still awaits and forwards the decodes it submitted, since a Zig task must be
  awaited.
- Cryptography benches: `blake3::hash_message` keeps only `conc=1` (zigware's `hash_across`
  does not split a message); `bulletproofs::ipa::verify`'s `conc=8` rows time the same
  sequential `eval`. Inputs commonware rebuilds per iteration are reset in `before_iter` or
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
- `Strategy` parameters are omitted (sequential) in math and bls12381 ops; results do not
  depend on the strategy. Adding `strategy: anytype` (parallel package) is a later step.
- Conformance hashes (math/conformance.toml) wait for the `conformance` harness.
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
  `Scheme(Subject, Faults, P, V)`. The threshold scheme's `#[should_panic]` tests (certificate
  verifier on a vote, mismatched sharing) still panic but are not ported: Zig cannot catch a
  panic.

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

- scheme: `PublicKey.verify_batch` takes a `strategy` but runs sequentially (one random linear
  combination per 64 entries, drawing scalars in commonware's order); the
  `projected_batch_indexes_zero_sized_items` test runs on `parallel.sequential` only, not
  commonware's `mocks::explore` shapes.

- Fuzz: `bls12381_decode` checks round-trips and agreement with the group decoders instead
  of differential checks against blst, which zigware does not have.

- simd: one `@Vector` implementation per profile (scalar 64-bit, x86_v3 256, x86_v4c 512,
  neon/arm_v9 128) stands in for both commonware's emulated and native tokens; `dispatch`
  picks the compile target's best profile at comptime. Profile-only instructions are `void`
  on other profiles, so misuse is a compile error. Operations declare `pub const Output`.

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
