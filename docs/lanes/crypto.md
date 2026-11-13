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
- [ ] Remaining lib.rs traits: `Digestible`, `Committable`, `Digested`, `Cipher`.
- [x] Hashes: sha256, sha512, blake3, keccak256, crc32 (CRC-32C) on `std.crypto`/`std.hash`,
  with commonware's test vectors and the hasher differential fuzz (`fuzz.zig`).
- [ ] Hash codec conformance hashes (`CodecConformance<Digest>`), once codec/conformance ship
  the `arbitrary` + ChaCha8 value generator.
- [x] ed25519: keys, namespaced sign/verify, ZIP-215 verification, batch verify, codec;
  RFC 8032, Wycheproof, and ZIP-215 vectors; decode and batch fuzz targets.
- [ ] ed25519 conformance hashes and `certificate` scheme (after certificate.rs).
- [x] chacha20_poly1305 (`Cipher`) with the `Seal` conformance hash.
- [x] transcript.rs with the `TranscriptV0Ops`/`TranscriptV1Ops` conformance hashes.
- [ ] secret.rs.
- [x] handshake (sake) used by `stream`: V0/V1, X25519 on std, `SakeV0`/`SakeV1`
  conformance hashes, RFC 7748 and Wycheproof X25519 vectors, message decode fuzz.
- [ ] sake: `test_v1_rejects_derived_identity` (needs secp256r1) and `CodecConformance` of
  Syn/SynAck/Ack (needs the codec `arbitrary` generator).
- [ ] certificate.rs: the certificate scheme abstraction and mocks.
- [ ] secp256r1: standard and recoverable signatures, codec, certificate scheme.
- [ ] lthash, bloomfilter (+ conformance).
- [ ] banderwagon, zk (bulletproofs, pedersen) last.
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
  does, always as one shard (batch index 0) on the calling thread.
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
