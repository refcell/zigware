# Lane: crypto

Owns `src/cryptography` except `src/cryptography/bls12381/` (lane bls-math). You own
`src/cryptography/root.zig`; bls-math adds its `pub const bls12381 = ...` line there.

Reference: `~/.cache/zigware/commonware-ref/cryptography`. Uses `codec` for encodings: until
it lands, write fixed-size `encode`/`decode` methods and switch when codec's API is in.

## Backlog
Order (coordinator): ed25519, then what `stream` needs (chacha20_poly1305, transcript,
handshake), then certificate, secp256r1, the rest, zk last. banderwagon moved to bls-math.
`reed_solomon/` belongs to the coding lane.
- [x] Core signing traits as comptime interfaces (`signer.zig`): `Signer`/`PrivateKey`,
  `Verifier`/`PublicKey`, `Signature`, `BatchVerifier` + `BatchEntry`, `Recoverable`.
- [x] Remaining lib.rs traits: `Digestible`, `Committable`, `Digested` (`digestible.zig`);
  `Cipher` is in `signer.zig`.
- [x] Hashes: sha256, sha512, blake3, keccak256, crc32 (CRC-32C) on `std.crypto`/`std.hash`,
  with commonware's test vectors and the hasher differential fuzz (`fuzz.zig`).
- [x] `CodecConformance` hashes (`codec_conformance_test.zig`, commonware's
  `conformance.toml` copied unchanged): the five digests, `Summary`, ed25519 keys and
  signatures, and the sake `Ack`/`Syn`/`SynAck`/`EphemeralPublicKey`.
- [x] ed25519: keys, namespaced sign/verify, ZIP-215 verification, batch verify, codec;
  RFC 8032, Wycheproof, and ZIP-215 vectors; decode and batch fuzz targets.
- [x] ed25519 `certificate` scheme and its conformance hash, with the `fixture` mock.
- [x] chacha20_poly1305 (`Cipher`) with the `Seal` conformance hash.
- [x] transcript.rs with the `TranscriptV0Ops`/`TranscriptV1Ops` conformance hashes.
- [x] secret.rs: `Secret(T)` (redacted format, constant-time `eql`, zeroizing `deinit`).
- [x] handshake (sake) used by `stream`: V0/V1, X25519 on std, `SakeV0`/`SakeV1`
  conformance hashes, RFC 7748 and Wycheproof X25519 vectors, message decode fuzz.
- [x] sake: `test_v1_rejects_derived_identity` (secp256r1 key substitution).
- [x] certificate.rs: `Signers`, `Attestation`, `Verification`, assembly and bisection,
  `Scoped`/`ConstantProvider`, `mocks.Fixture`, and the `Signers`/`Attestation`
  conformance hashes.
- [x] certificate mocks: the ledger-backed mock scheme (`impl_certificate_mock!`,
  `certificate.mocks.Scheme(Subject, Faults, P, Options)`, `mocks.fixture`).
- [x] secp256r1: standard and recoverable signatures and codec on `std.crypto.ecc.P256`, with
  its own RFC 6979 signer and key recovery; commonware's vectors, the four `CodecConformance`
  hashes, and the `secp256r1_{standard,recoverable}_decode` fuzz targets.
- [x] secp256r1 `certificate` scheme with its conformance hash and `fixture` mock.
- [x] lthash: `LtHash` with commonware-generated checksums, the `CodecConformance<LtHash>`
  hash, and the `lthash_operations`/`metamorph_lthash` fuzz targets.
- [x] bloomfilter: `BloomFilter(H)` with its tests, `CodecConformance<BloomFilter>`, and the
  `bloomfilter` fuzz target (`New` constructor).
- [x] bloomfilter `with_rate`/`optimal_*`/estimates, the `RationalOptimalBits` hash, and the
  fuzz target's `WithRate` constructor (over `utils.BigRational`).
- [x] zk circuit (`zk/circuit.zig`): `Context`, `Var`, `BoolVar`, `Selector`, and the
  minifuzz satisfaction plan.
- [x] zk bulletproofs ipa (`zk/bulletproofs/ipa.zig`): `Setup`, `Claim`, `Witness`, `Proof`,
  `prove`, `verify`, `Setup.eval`, the prover fuzz plan, and its 3 conformance hashes.
- [x] zk bulletproofs circuit (`zk/bulletproofs/circuit.zig`, `zkc.zig`): `SparseMatrix`,
  `Circuit`, `Setup` (`hashed`, `eval`, `eval_check_batched`), `Witness`, `Claim`, `Proof`,
  `prove`, `verify`, the `zk.circuit` converter, and the fuzz plan.
- [x] zk `pedersen_to_plain`: `Setup`, `Witness`, `Claim`, `Proof`, `prove`, `verify`, the
  BLS12-381 prover plan, and its 3 conformance hashes. (banderwagon moved to bls-math.)
- [x] Fuzz targets (commonware cryptography/fuzz) and conformance hashes: every target and
  every `conformance.toml` entry outside bls12381/ and reed_solomon/ has a Zig counterpart.
- [x] Consensus fuzz (commonware `consensus/fuzz`, in `src/consensus/fuzz/`, owned here by
  agreement with consensus-simplex): simplex_messages, simplex_elector, attributable_map.
- [x] Consensus fuzz `bounds`, `types`, and `invariants` (the safety checker, `find`/`check`,
  with commonware's ten invariant tests; a violation is a `Kind` and a view, not a panic).
- [x] Consensus engine fuzzers (`fuzz/strategy.zig`, `disrupter.zig`, `recorder.zig`,
  `harness.zig`, `simplex.zig`): simplex_ed25519, simplex_secp256r1, and simplex_bls12381
  multisig and threshold (MinPk, MinSig), with commonware's connected tests.
- [x] The `_twin` engine fuzzers (`fuzz/twin.zig` splits a Byzantine identity's channels
  per view with simplex's `twins.view_masks`/`view_route` over p2p's split senders and
  receivers; the primary half runs the engine, the secondary a disrupter).
- Benches moved to bls-math (coordinator handover).
- [x] qmdb sync (`src/storage/qmdb/sync/`, handed over by storage-qmdb-sync): the `Database`
  interface and `Persisted` adapter (`database.zig`), `Source`/`Feedback`/`JournalSource`
  (`source.zig`), the engine (`engine.zig`, commonware's unit tests in `engine_test.zig`),
  keyless and immutable sync glue, and the shared harness (`harness.zig`, `Tests(H)`:
  commonware's `harness/full.rs` tests, the five per-harness `engine.rs` retention tests, and
  the three issue-5669 interrupted-destroy regressions), instantiated for keyless and
  immutable over commonware's variable harnesses in both families. storage-qmdb-sync owns
  any, current, and compact sync glue and the `qmdb_any_*_sync` fuzz targets.
- [ ] simplex voter `actors/voter/mod.rs` tests, shared with runtime (T-01a1d57b-1bfd): runtime
  ports lines 881-6716 (52 tests), this lane 6717-end (44 tests) in
  `src/consensus/simplex/actors/voter/tests/{nullify,certification,verification,replay,
  timeout}_test.zig`, each `Tests(h)` over runtime's fixture-generic `Harness(F)` with
  commonware's per-test scheme coverage. Done (each group checked by a planted bug): the four
  nullify fast-path tests, recovered_finalization_is_reported, missed_notarization_is_fetched,
  failed_certification_blocks_direct_descendant_verify, the finalization and conflicting
  notarization in-flight verification cancels, certification_precludes_verification,
  invalid_ancestry_emits_nullify_immediately, and
  dropped_verify_still_votes_after_prior_participation, no_recertification_after_replay
  (replay_test.zig), and no_self_verify_when_proposing,
  no_self_propose_or_verify_after_restart, nullify_after_crash_in_propose_window, and
  no_self_verify_after_restart (own_proposal_test.zig). Next: 10127
  (certifies_own_proposal_when_proposing) onward in file order.
  - no_recertification_after_replay: replay marks a view certified both in `Round.replay` and
    in the actor's `handle_certification`; dropping either alone still passes, and dropping
    both is caught as a voter panic (the replayed view cannot advance), not a recertify.
  - The restart tests use the harness's `VoterStack.replace` (fresh recording automaton,
    commonware's new mock application); no_recertification_after_replay uses `restart` so
    the automaton's `certify_calls` count spans the restart.
  - finalization_cancels_inflight_verification's final check (no notarize for the finalized
    view) is defended at four layers (the actor's drop, `verified`'s staleness check,
    `admits_outbound`, and `verification_matches`); removing all four together still does
    not break it, so its planted bug targets the in-flight precondition instead.

## Log
- Digests are `Digest(length, name)`: one distinct type per hasher, encoded as raw bytes.
  They implement the codec interface (`fixed_size`, `write`, `read`).
- `Hasher.finalize` resets the hasher in place and returns the digest (Rust returns the reset
  hasher by value). `hash_many` writes into a caller-provided digest slice instead of
  returning a `Vec`, so hashing never allocates.
- `strategy` parameters (`hash_across`, `hash_pair`, `hash_many`) take any value and run on
  the calling thread until the parallel package lands; the digests are identical.
- `Crc32.resume` is `Crc32.resume_from` (`resume` is a Zig keyword).
- `ChaCha20Rng` (`rng.zig`) is byte-identical to Rust `rand_chacha` 0.10, so `from_seed(u64)`
  keys match commonware's `Signer::from_seed`.
- ed25519 verification is ZIP-215 on std's Edwards25519 arithmetic (`ed25519/core.zig`):
  lenient point decoding, canonical `s`, cofactored check. Small-order keys go through an
  own variable-time multiscalar loop because std's `mul*Public` rejects them.
- ed25519 batch verification derives its coefficients from a transcript as commonware
  does (see the strategy entry below).
- `verify_batch(rng, items, projector, strategy)`: `projector.project(index, *const Item)`
  returns a `BatchEntry`; `cryptography.entries` projects a slice of entries.
- Conformance hashes that run signature schemes thousands of times skip in Debug unless
  `-Dslow-tests` (`conformance.skip_slow`); CI's ReleaseSafe run checks them.
- `Transcript.resume` is `resume_from`; `Transcript::sample` is `sample_label`.
  `Summary` is `Digest(32, "transcript")`; `Summary::sign`/`verify` are `sign_summary` and
  `verify_summary`.
- SAKE is `handshake.sake.Sake(Signer)`: `Context.init`, `dial_start`, `listen_start`,
  `dial_end`, `listen_end`; results are structs (`DialStart`, `ListenStart`, `DialEnd`).
  Errors carry no payload (`InvalidTimestamp` drops the value and range). Ephemeral and
  shared secrets are zeroized once used.
- secp256r1 signs with its own RFC 6979 nonce generator (HMAC-SHA256, no additional data)
  instead of `std.crypto.sign.ecdsa`, whose nonce mixes in a noise block and is not RFC 6979;
  only std's P256 field, scalar, and point arithmetic is used. Verification is plain ECDSA
  (commonware verifies with aws-lc-rs on x86_64 and aarch64 and `p256` elsewhere; both
  agree on decoded, low-s signatures). Keys are `PrivateKey.from_bytes`, signatures
  `sign_raw`/`verify_raw` without namespace framing, as for ed25519.
- certificate.rs's traits are comptime interfaces (`assert_subject`, `assert_verifier`,
  `assert_scheme`). Scheme operations take `(gpa, rng, subject, ...)` and return
  `Allocator.Error!` on top of commonware's result; `optimistic_assemble` returns an
  `Assembled` union (certificate or verification) instead of `Result`. A subject's
  `message(gpa)` returns an owned slice, and its `Namespace` declares `derive`, `clone`, and
  `deinit` (`BytesNamespace` is commonware's `Vec<u8>`). `AssemblyError` drops payloads.
- `Lazy<Signature>` in attestations and certificates is `certificate.Deferred(T)`: the fixed
  encoding inline, decoded on `get()`, so wire bytes match and decoded values outlive their
  buffer. An ed25519 signature is any 64 bytes, so the ed25519 malformed-`Lazy` test cases
  have no counterpart; secp256r1 covers malformed signatures.
- commonware's `impl_certificate_ed25519!(Subject, Namespace, Faults)` plus `Generic` is
  `ed25519.certificate.Scheme(Subject, Faults)` with `Subject.Namespace`;
  `impl_certificate_secp256r1!` with `Scheme<P>` is
  `secp256r1.certificate.Scheme(Subject, Faults, P)`. Both share
  `certificate.Individual(Sig, context)` for the certificate and its `assemble`.
- The mock scheme's const generics are `mocks.Options` (`attributable`, `batchable`,
  `allow_invalid`); its `Shared` ledger is reference counted (each scheme holds one) and
  guarded by a spin `std.atomic.Mutex`, since mocks get no `std.Io`. Signed subjects are
  stored as `union_unique(namespace, message)`. `Assembled.deinit` skips certificates
  without `deinit` (the mock's `U64`).
- Hashers and ed25519 batch verification take `parallel` strategies (`assert_strategy`);
  `hash_many` is commonware's one-lane `hash_batches` over
  `run_batches`; ed25519 `verify_batch` shards like commonware (one seed per call, one
  equation per batch, coefficients committed to the batch ordinal) but splits by index range
  without the first-key-byte counting sort, which only helps an implementation that coalesces
  repeated keys. `hash_across`/`hash_pair` stay on the calling thread: Blake3's parallel
  subtree hashing needs chaining values that `std.crypto.hash.Blake3` does not expose.
- `{}` passed as a strategy still means `parallel.sequential` (`hasher.resolve_strategy`), so
  other lanes' placeholder calls keep compiling until they switch.
- `Digested(T)` holds a borrowed `*const T` instead of an `Arc<T>`: the owner keeps the value
  alive and unchanged while a `Digested` refers to it. `compute(value, strategy)` hashes
  synchronously through `digest_across` (no future). It has `write`/`encode_size` but no
  `read`, so it is not a codec type; encode it with `digested.write(writer)`.
- zk circuits build through an explicit `Context(F)` (`.verifier` or `.prover`) instead of
  `build`/`build_with_values` closures, with buffers sized up front from a `Capacity`, so var
  arithmetic never fails (exceeding the capacity panics). Var arithmetic is method calls
  (`add`, `sub`, `mul`, `neg`, `div`, `inv`); allocation order matches commonware's, so the
  circuits match node for node. Witness initializers are `init.call(values)` structs, or
  `witness_value` for a known value.
- zk bulletproofs ipa: `prove(G, gpa, &transcript, &setup, claim, &witness, strategy)` and
  `verify(G, gpa, &transcript, &virtual_setup, claim, proof)` take the group and read the
  field from `G.Scalar`; both borrow their witness or proof (Rust moves them).
  `Setup.eval(gpa, F, context, f)` calls `f(context, gpa, &virtual)` in place of Rust's
  closure. The prover folds generators with `strategy.join` of two `map_into`s, like
  commonware; MSMs use `math.algebra.msm`, which takes no strategy. `verify` returns null
  for a setup shorter than the claimed length, where commonware panics on the slice.

- zk bulletproofs circuit: commonware gives `SparseMatrix`, `Circuit`, and `Claim` only
  `Write`; zigware encodes them with `circuit.encode_write_only` (the codec functions also
  require `read`). `SparseMatrix` keeps its entries sorted by `(row, col)` in a list (Rust's
  `BTreeMap`) and inserts zeros through `entry`, like `IndexMut`. `prove` and `verify` keep
  their temporaries in an arena. `prove` returns null for witness lengths that do not match
  the circuit, where commonware would panic. The `zkc` converter keeps commonware's visit
  order, explicit stack, and `Location` ordering, so converted circuits match column for
  column. `Setup.eval_check_batched` uses an explicit stack of index ranges.
- bloomfilter sizing: `with_rate(gpa, n, &fp_rate)`, `optimal_bits`, and `optimal_hashers` take
  `u64` counts (Rust `usize`). `optimal_bits` truncates the u128 ceiling to u64 like Rust's `as
  usize`. In Debug a `with_rate` costs about a second (exact log2 squares ~1M-bit integers), so
  the seeded fuzz draws `WithRate` only in its first four iterations, and `RationalOptimalBits`
  is a slow test.
- Consensus fuzz targets (`src/consensus/fuzz/`) keep commonware's properties but draw some
  inputs differently so the debug-mode seeded runs stay fast and reach real cases.
  simplex_messages also edits a valid encoding per arm (overwrite, bit flip, truncate,
  append) besides decoding raw bytes. Its threshold VRF seeds are signed with simplex's
  `vrf.Scheme` fixture. simplex_elector draws only the committee size (electors never
  see keys) and draws certificate points from a table. The round-robin arms also run alone
  at minifuzz's default bound; all arms together run 256 cases, because a random elector
  decodes points on every election. attributable_map picks one of 8 precomputed dummy
  signatures by the drawn seed. A planted bug in each target fails its default seeded run:
  BitMap accepting set trailing bits, round-robin indices off by one, and an AttributableMap
  insert that overwrites a duplicate signer.
- Engine fuzzers (`src/consensus/fuzz/harness.zig`): the runtime is seeded by a drawn `u64`
  (commonware feeds raw bytes to a `FuzzRng`), the disrupter polls its three receivers in
  order instead of selecting, and a run still going after 600 s of simulated time fails
  with `error.Timeout` (commonware hangs until the fuzzer times out). Honest reporters keep
  verified certificates (`recorder.zig`), and `invariants.find` checks them after the run.
  Honest applications set simplex's `reject_mismatches` (commonware's `mocks` feature):
  replayed payloads at another round or parent fail verification instead of panicking. In
  Debug only ed25519 runs its seeded fuzz by default (2 cases; 1 for the twin); the other
  schemes run a seeded connected test (BLS12-381 to view 3), and their seeded fuzz,
  single-input `std.testing.fuzz` runs, and twin runs (5 to 30 s each in Debug, because the
  disrupter signs every 100 ms) need ReleaseSafe, `-Dslow-tests`, `-Dfuzz-soak`, or `--fuzz`.
  Twin runs use 500 ms links and a 1.5 s certification timeout, as commonware's do.
  Planted bug: `N3f1.quorum` off by one makes honest engines assemble
  2-of-4 certificates, which the connected test and the first fuzz case report as
  `insufficient_signatures`. Beyond commonware (its disrupter never gets a
  skipping proposal past the mock application, and its invariants see only certificates,
  so a faithful port missed both bugs below): each honest recorder also keeps its own
  notarize, nullify, and finalize votes, and `invariants.check_votes` fails on a replica
  that voted nullify and finalize in one view (`nullify_and_finalize_vote`) or notarized
  over a parent the protocol forbids (`invalid_notarize_parent`, the same parent rules as
  finalized ancestry). The disrupter also listens on the mock relay and, once per proposed
  view `h`, proposes `h + 1` over the proposal below `h` with contents the mock
  application accepts (`send_skip_proposal`), so a skipping proposal reaches verification.
  Planted missing-nullification check (parent span): all five default ed25519 runs fail
  (`invalid_notarize_parent`, `finalized_between_parent_and_child`). Planted
  finalize-after-nullify (`construct_finalize` ignoring a nullify decision): the three
  default ed25519 twin runs fail with `nullify_and_finalize_vote`.
- qmdb sync engine: fetch tasks start eagerly (`io.concurrent`), while commonware's request
  futures run only when its biased select polls them. Woken events are handled in that
  select's order (finish, then target updates, then fetch results), and a queued update is
  polled before fetch results, so a fetch a queued update retains out is ignored rather than
  failing the sync on a source that has already pruned it (found by the harness's
  bounds-increase case over immutable).
- qmdb sync harness: ops come from a seed (`apply_ops(db, seed, count, metadata)`), and the
  checks regenerate them, instead of commonware's `Vec<Op>`. Every database in a test shares
  one page cache. Plain Debug builds run the 1000-op `test_sync` cases only at fetch batch
  100, skip the update cases over 100 ops, and use 200-op histories for subset/existing-db
  (release builds and `-Dslow-tests` run commonware's sizes).
- CI time: `utils.rational.log2` takes digits from a 120-bit interval when it decides them
  (exact fallback; the RationalOptimalBits hash is unchanged), so the bloom filter tests take
  8 s instead of about 79 s in ReleaseSafe. The certificate Attestation and ed25519
  Certificate conformance hashes (about 40 s in ReleaseSafe) run only with `-Dslow-tests`
  (`conformance.skip_unless_slow`, nightly on every platform); `Signers` stays per push.

### Test audit: crypto (2026-11-19, commonware 43b357a41, p2p lane)

Every `#[test]`/`#[rstest]` fn in commonware `cryptography/src (outside bls12381 and reed_solomon)`,
with each `#[case]` and each test-generating macro expansion counted separately, matched to a
zigware test by name or by reading both bodies (a zigware test may cover several). 435 tests: 394
ported, 27 open, 14 not portable.

| commonware file | tests | ported | open | not portable |
|---|---|---|---|---|
| `banderwagon.rs` | 27 | 27 | 0 | 0 |
| `certificate.rs` | 29 | 20 | 9 | 0 |
| `chacha20_poly1305.rs` | 7 | 7 | 0 | 0 |
| `fuzz.rs` | 5 | 5 | 0 | 0 |
| `lib.rs` | 42 | 29 | 12 | 1 |
| `secret.rs` | 7 | 6 | 0 | 1 |
| `sha512.rs` | 8 | 5 | 1 | 2 |
| `transcript.rs` | 24 | 22 | 1 | 1 |
| `blake3/mod.rs` | 7 | 6 | 0 | 1 |
| `bloomfilter/mod.rs` | 14 | 14 | 0 | 0 |
| `certificate/mocks.rs` | 20 | 16 | 0 | 4 |
| `crc32/mod.rs` | 13 | 13 | 0 | 0 |
| `ed25519/scheme.rs` | 22 | 19 | 1 | 2 |
| `ed25519/certificate/mod.rs` | 26 | 25 | 0 | 1 |
| `ed25519/core/batch.rs` | 3 | 2 | 1 | 0 |
| `ed25519/core/verification_key.rs` | 1 | 1 | 0 | 0 |
| `handshake/sake/protocol.rs` | 7 | 7 | 0 | 0 |
| `keccak256/mod.rs` | 4 | 4 | 0 | 0 |
| `lthash/mod.rs` | 11 | 11 | 0 | 0 |
| `secp256r1/common.rs` | 1 | 1 | 0 | 0 |
| `secp256r1/recoverable.rs` | 50 | 50 | 0 | 0 |
| `secp256r1/standard.rs` | 47 | 47 | 0 | 0 |
| `secp256r1/certificate/mod.rs` | 27 | 26 | 1 | 0 |
| `sha256/mod.rs` | 10 | 9 | 1 | 0 |
| `sha512/padding.rs` | 1 | 0 | 0 | 1 |
| `zk/circuit.rs` | 6 | 6 | 0 | 0 |
| `zk/pedersen_to_plain.rs` | 3 | 3 | 0 | 0 |
| `zk/bulletproofs/circuit.rs` | 10 | 10 | 0 | 0 |
| `zk/bulletproofs/ipa.rs` | 3 | 3 | 0 | 0 |

Open:
- [ ] `certificate.rs` `test_threshold_recovers_exact_certificate_with_verified_attestations`:
  Threshold (MinPk and MinSig) optimistic_assemble with 1 prior verified + quorum-1 pending returns
  a certificate equal to a direct assemble, makes zero attestation verifications (Recording
  wrapper), verifies under SUBJECT but not OTHER_SUBJECT, and with an extra unused bad vote beyond
  quorum still returns the exact same certificate (lowest-quorum recovery). Zig "threshold
  certificate: optimistic assembly" only checks pending-only success and a 1-invalid fallback
  (MinSig only). Add to src/cryptography/bls12381/certificate/threshold_tests.zig (needs a
  call-recording scheme wrapper)
- [ ] `certificate.rs` `test_multisig_optimistic_assemble_uses_one_certificate_check`: Multisig
  (MinPk and MinSig, PoP-checked keys) optimistic_assemble with 1 prior + pending quorum certifies
  with exactly one verify_certificate call and zero attestation verifications, and the certificate
  rejects OTHER_SUBJECT. Zig "multisig: optimistic assembly" has no prior inputs, no call counting,
  MinSig only. Add to src/cryptography/bls12381/certificate/multisig_tests.zig with a recording
  wrapper
- [ ] `certificate.rs` `test_rejected_certificate_verifies_pending_halves_directly`: Generic
  optimistic_assemble over threshold MinPk for n in {1,5,7} with a quorum of OTHER_SUBJECT votes:
  verified empty, invalid = all pending signers, and attestation verification calls are exactly the
  two halves (or one batch when quorum is 1). Zig "certificate generic optimistic assemble falls
  back to verifying halves" (ed25519, n=7, 2 bad) checks invalid/verified but not the all-invalid
  case, the n=1 path, or the half-split call pattern. Add to src/cryptography/certificate_test.zig
  or src/cryptography/bls12381/certificate/threshold_tests.zig with a recording wrapper
- [ ] `certificate.rs` `test_malformed_assembly_falls_back_to_pending_halves`: Generic
  optimistic_assemble over threshold MinPk where pending[0] has an undecodable signature (assembly
  fails with MalformedSignature): for count quorum and n, verified = count-1, invalid = [0], calls =
  halves, and with count>quorum the survivors assemble and verify. No Zig test feeds a malformed
  signature to optimistic_assemble. Add to src/cryptography/bls12381/certificate/threshold_tests.zig
  (0xff Deferred bytes as in the assemble-rejects test)
- [ ] `certificate.rs` `test_optimistic_assemble_retains_verified_inputs`: Generic
  optimistic_assemble (threshold MinPk) with 2 prior verified + pending [accepted, rejected]:
  verified == [accepted] only (prior not echoed), invalid == [rejected], calls
  [[accepted],[rejected]]; then a verified replacement plus prior assembles a valid certificate. Zig
  secp256r1 "optimistic assemble verifies pending once" covers a similar flow only for secp256r1 own
  override, not the generic path or call pattern. Add to
  src/cryptography/bls12381/certificate/threshold_tests.zig or src/cryptography/certificate_test.zig
- [ ] `certificate.rs` `test_optimistic_assemble_with_verified_votes`: Generic optimistic_assemble
  (threshold MinPk) with pending_len 0/1/2 over a verified prior: certifies with exactly one
  assemble, one verify_certificate only when pending is non-empty (zero for verified-only), and zero
  attestation verifications. Zig ed25519 "optimistic assemble reuses verified attestations" and
  secp256r1 "verifies pending once" test the analogous property for their own schemes only. Add to
  src/cryptography/bls12381/certificate/threshold_tests.zig with a recording wrapper
- [ ] `certificate.rs` `test_optimistic_assemble_retries_with_replacements`: Threshold MinPk, n=10,
  failures 1 and 2: a failed quorum keeps local and valid peer votes, a second round with a new
  faulty signer mixed with honest replacements reports exactly that signer with one assemble, one
  certificate check, and per-signer attestation calls, and a final honest replacement certifies (and
  rejects OTHER_SUBJECT). No Zig counterpart. Add to
  src/cryptography/bls12381/certificate/threshold_tests.zig with a recording wrapper
- [ ] `certificate.rs` `test_optimistic_assemble_below_quorum`: Generic optimistic_assemble
  (threshold MinPk) with 2 valid pending below quorum: verified == pending, invalid empty, and
  attestation calls are the two halves. Zig "certificate optimistic assemble requires a quorum"
  checks the verified/invalid outcome for ed25519 own optimistic_assemble but not the generic path
  nor the half-split call pattern. Add to src/cryptography/bls12381/certificate/threshold_tests.zig
  or src/cryptography/certificate_test.zig
- [ ] `certificate.rs` `test_optimistic_assemble_unknown_pending_signer`: Generic
  optimistic_assemble (threshold MinPk) with pending[0].signer = 999 (assembly fails UnknownSigner):
  verified quorum-1, invalid [999], attestation calls [[999,1],[2,3]]. No Zig counterpart. Add to
  src/cryptography/bls12381/certificate/threshold_tests.zig or src/cryptography/certificate_test.zig
- [ ] `lib.rs` `test_bls12381_validate`: Only a fixed-vector decode/encode/eql round trip exists
  (bls12381/scheme_tests.zig "bls12381 scheme: codec public key"). Missing: random key decoded from
  its bytes is eql with order == .eq, and a second random key differs. Add to
  src/cryptography/bls12381/scheme_tests.zig (bls-math lane)
- [ ] `lib.rs` `test_bls12381_validate_invalid_public_key`: No test asserts that decoding 1024 zero
  bytes as bls12381 scheme.PublicKey fails; the decode fuzz (fuzz_tests.zig "bls12381 fuzz: decode",
  length 1024 included) only checks the result agrees with MinPk.Public decode. Add an expectError
  to src/cryptography/bls12381/scheme_tests.zig
- [ ] `lib.rs` `test_bls12381_sign_and_verify_wrong_message`: No single-signature PublicKey.verify
  with a wrong message at the scheme level; only verify_batch with a changed message ("bls12381
  scheme: batch verify invalid message") and the primitive-level noble tamper checks. Add
  !verify(ns, "wrong_message", sig) to src/cryptography/bls12381/scheme_tests.zig
- [ ] `lib.rs` `test_bls12381_empty_namespace`: No deterministic test signs and verifies with an
  empty namespace through scheme.PublicKey.verify; the only "" namespace use is the batch in
  "bls12381 scheme: projected batch indexes zero-sized items" (batch path, slow-only) and fuzz-drawn
  namespaces. Add to src/cryptography/bls12381/scheme_tests.zig
- [ ] `lib.rs` `test_secp256r1_standard_validate`: secp256r1/tests.zig "secp256r1 codec round trips"
  checks decode(encode(pk)).eql(pk) for a fixed key, but nothing checks order == .eq for the decoded
  key or that a second random key differs. Add to src/cryptography/secp256r1/tests.zig (inline for
  schemes covers both)
- [ ] `lib.rs` `test_secp256r1_standard_public_key_order`: No test checks that PublicKey.order/eql
  (which compare decoded points via inner.order) agree with byte-wise ordering of the 33-byte
  encodings over 16 random keys and their decoded copies. Add to
  src/cryptography/secp256r1/tests.zig
- [ ] `lib.rs` `test_secp256r1_standard_sign_and_verify_wrong_message`: No namespaced verify with a
  wrong message (scheme sign checks only a wrong namespace; vectors use verify_raw). Add !verify(ns,
  "wrong_message", sig) to src/cryptography/secp256r1/tests.zig
- [ ] `lib.rs` `test_secp256r1_standard_invalid_signature_publickey_pair`: No test verifies a
  signature under a different key's public key and expects false. Add to
  src/cryptography/secp256r1/tests.zig (from_seed(0) signs, from_seed(1).public_key() rejects)
- [ ] `lib.rs` `test_secp256r1_recoverable_validate`: Same gap as the standard scheme: no order ==
  .eq for decoded key and no distinct-key check. Add to src/cryptography/secp256r1/tests.zig
- [ ] `lib.rs` `test_secp256r1_recoverable_public_key_order`: Same gap as the standard scheme:
  order/eql vs byte order of encodings untested. Add to src/cryptography/secp256r1/tests.zig
- [ ] `lib.rs` `test_secp256r1_recoverable_sign_and_verify_wrong_message`: No namespaced verify with
  a wrong message for the recoverable scheme either. Add to src/cryptography/secp256r1/tests.zig
- [ ] `lib.rs` `test_secp256r1_recoverable_invalid_signature_publickey_pair`: No test that another
  key's public key rejects the signature (recover_signer checks a flipped signature, not a wrong
  key). Add to src/cryptography/secp256r1/tests.zig
- [ ] `sha512.rs` `test_hash_many_overlapping_messages`: No test hashes overlapping/aliased slices
  of one buffer through Sha512.hash_many (20 messages backing[lane..lane*13+100], and 9 aliases of
  the whole buffer) on sequential and a parallel strategy. Add to src/cryptography/sha512.zig
- [ ] `transcript.rs` `test_shuffle_label_and_history_matter`: Label part is checked (t shuffle A vs
  B), but history is not isolated: Zig compares with_data/"shuffle" against t/"A", which differ in
  both label and history. Add same-label different-history check (v0 test shuffle A vs v0 test +
  commit DATA shuffle A) to src/cryptography/transcript_test.zig "transcript shuffle and sample"
- [ ] `ed25519/scheme.rs` `projected_batch_borrows_records`: src/cryptography/ed25519/tests.zig
  "ed25519 projected batch over records, empty, and noncanonical s" ports the records,
  record-pointer identity, per-record alteration, noncanonical s and empty cases but runs only
  parallel.sequential; missing: run each verdict under parallel.mocks.explore (serial, parallel,
  seeded shapes) as commonware does, in src/cryptography/ed25519/tests.zig
- [ ] `ed25519/core/batch.rs` `test_verify_rejects_each_altered_item_in_every_shape`:
  src/cryptography/ed25519/tests.zig "ed25519 batch rejects each altered item in every shape" ports
  the 1..3 x 1..3 loops and per-item alteration but verifies only under parallel.sequential;
  missing: run Fixture.verify through parallel.mocks.explore so serial, parallel and seeded split
  shapes are each checked, in src/cryptography/ed25519/tests.zig
- [ ] `secp256r1/certificate/mod.rs` `test_scheme_clone_and_verifier`: verifier.sign returning null
  is asserted in "secp256r1 certificate sign, verify, and filter attestations", but no test clones a
  secp256r1 signer Scheme (Scheme.clone exists in secp256r1/certificate.zig) and asserts the clone
  still signs; add to src/cryptography/secp256r1/certificate_test.zig
- [ ] `sha256/mod.rs` `test_hash_many_aliased_unaligned_inputs_match_individual_hashes`: No test
  passes overlapping, unaligned slices of one buffer (backing[lane..lane+129], counts 1..16) or 16
  aliases of one slice through Sha256.hash_many on sequential and parallel strategies. Add to
  src/cryptography/sha256.zig

Not portable:
- `lib.rs` `test_hash_batches_shares_whole_units`: Tests the lanes parameter and caller-supplied
  batch closure of Rust hash_batches; zigware's hasher.hash_batches is fixed at one lane with no
  closure (docs/lanes/crypto.md Log: hash_many is commonware's one-lane hash_batches over
  run_batches), so whole-unit share cutting for lanes 2/8/16 has no counterpart; batch splitting
  itself is tested in src/parallel/tests.zig "run_batches supplies ordered balanced ranges"
- `secret.rs` `test_debug_redacted`: Rust Debug impl; zigware Secret has only the Display-equivalent
  format ({f}) and a debug_text constant (secret.zig "secret is redacted" asserts the constant,
  which is tautological), there is no separate Debug formatter to exercise
- `sha512.rs` `test_avx512_detection`: Checks runtime AVX-512F detection for the x86_64 multi-lane
  kernel; zigware SHA-512 is std.crypto.hash.sha2.Sha512 with no arch kernels or feature detection
  (docs/lanes/crypto.md: hashes on std.crypto)
- `sha512.rs` `test_sha3_detection`: Checks aarch64 SHA3 feature detection for the paired kernel;
  zigware has no arch-specific SHA-512 backend (std.crypto, docs/lanes/crypto.md)
- `transcript.rs` `test_append_overflow_does_not_hash`: Relies on catch_unwind of the overflow
  panic; zigware's Transcript.append @panics on u64 overflow (checked before hashing) and panics are
  not testable in-process
- `blake3/mod.rs` `test_hash_splits_long_messages`: Counts jobs a Rayon worker runs when hash_across
  splits a message of MIN_SPLIT_LEN or more into subtrees; zigware Blake3.hash_across never splits
  (docs/lanes/crypto.md Log: Blake3 parallel subtree hashing needs chaining values
  std.crypto.hash.Blake3 does not expose)
- `certificate/mocks.rs` `signature_overflow_panics`: Rust #[should_panic]; zigware mocks.zig panics
  at the same point (Shared.next @panic(what ++ " overflow"), what="signature") and Zig tests cannot
  catch a panic in-process; recorded in the mocks.zig and mocks_test.zig module docs
- `certificate/mocks.rs` `certificate_overflow_panics`: Rust #[should_panic]; zigware mocks.zig
  panics at the same point (Shared.next @panic(what ++ " overflow"), what="certificate") and Zig
  tests cannot catch a panic in-process; recorded in the mocks.zig and mocks_test.zig module docs
- `certificate/mocks.rs` `strict_invalid_requests_panic`: Rust #[should_panic]; zigware mocks.zig
  panics at the same point (invalid() @panic("invalid mock certificate request: " ++ reason)) and
  Zig tests cannot catch a panic in-process; recorded in the mocks.zig and mocks_test.zig module
  docs
- `certificate/mocks.rs` `strict_invalid_assembly_requests_panic`: Rust #[should_panic]; zigware
  mocks.zig panics at the same point (assembly_error() std.debug.panic("invalid mock certificate
  request: {s}")) and Zig tests cannot catch a panic in-process; recorded in the mocks.zig and
  mocks_test.zig module docs
- `ed25519/scheme.rs` `test_from_signing_key`: Tests Rust From<ed_core::SigningKey> for PrivateKey;
  zigware PrivateKey has no SigningKey conversion (only random/from_seed/from_bytes), so there is no
  API to test
- `ed25519/scheme.rs` `test_from_private_key_to_public_key`: Tests Rust From<PrivateKey> for
  PublicKey agreeing with public_key(); zigware has only PrivateKey.public_key() and no From
  conversion trait
- `ed25519/certificate/mod.rs` `test_certificate_rejects_malformed_signature`: Builds a malformed
  Lazy<Signature> from 3 bytes; zigware Deferred(T) keeps the fixed 64-byte encoding inline and
  every 64 bytes decode as an ed25519 signature, so no malformed ed25519 attestation/certificate
  exists (docs/lanes/crypto.md: ed25519 malformed-Lazy cases have no counterpart; secp256r1 covers
  malformed signatures)
- `sha512/padding.rs` `test_blocks_pad_messages`: Tests the block()/block_count() padding helper of
  commonware's multi-message SHA-512 kernels; zigware has no such module and pads inside
  std.crypto.hash.sha2.Sha512 (docs/lanes/crypto.md: hashes on std.crypto)
- 2026-11-19 (p2p lane): std.fmt's `{}` and `{any}` ignore `format` and print every struct
  field, so `Secret`, ed25519, secp256r1, and X25519 private keys printed their bytes (bls
  `Private` escaped only by fmt's depth limit of 3). Key material now lives in
  `secret.Opaque(T)` fields, an untagged union that std.fmt prints as `.{ ... }` at any depth;
  `redaction_test.zig` checks every private key type through `{any}`, `{}`, `{f}`, and a
  depth-16 print. `expectEqual` cannot compare such fields, so tests compare `== null`.
