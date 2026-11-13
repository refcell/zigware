# Lane: crypto

Owns `src/cryptography` except `src/cryptography/bls12381/` (lane bls-math). You own
`src/cryptography/root.zig`; bls-math adds its `pub const bls12381 = ...` line there.

Reference: `~/.cache/zigware/commonware-ref/cryptography`. Uses `codec` for encodings: until
it lands, write fixed-size `encode`/`decode` methods and switch when codec's API is in.

## Backlog
Order (coordinator): ed25519, then what `stream` needs (chacha20_poly1305, transcript,
handshake), then certificate, secp256r1, the rest, zk and banderwagon last.
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
- [ ] bloomfilter `with_rate`/`optimal_*`/estimates and the `RationalOptimalBits` hash (waits
  for `utils.rational`'s `BigRational` and `log2_floor`).
- [x] zk circuit (`zk/circuit.zig`): `Context`, `Var`, `BoolVar`, `Selector`, and the
  minifuzz satisfaction plan.
- [ ] zk bulletproofs (ipa, circuit) and `pedersen_to_plain`, then banderwagon (needs the
  bls12381 `Scalar` from the bls-math lane).
- [ ] Fuzz targets (commonware cryptography/fuzz) and conformance hashes.

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
