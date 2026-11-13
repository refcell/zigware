# Lane: crypto

Owns `src/cryptography` except `src/cryptography/bls12381/` (lane bls-math). You own
`src/cryptography/root.zig`; bls-math adds its `pub const bls12381 = ...` line there.

Reference: `~/.cache/zigware/commonware-ref/cryptography`. Uses `codec` for encodings: until
it lands, write fixed-size `encode`/`decode` methods and switch when codec's API is in.

## Backlog
- [ ] Core traits as comptime interfaces: `Signer`, `PrivateKey`, `PublicKey`, `Signature`,
  `Verifier`, `BatchVerifier`, `Hasher`, `Digest`, `Committable`/`Digestible` (lib.rs).
- [x] Hashes: sha256, sha512, blake3, keccak256, crc32 (CRC-32C) on `std.crypto`/`std.hash`,
  with commonware's test vectors and the hasher differential fuzz (`fuzz.zig`).
- [ ] Hash codec conformance hashes (`CodecConformance<Digest>`), once codec/conformance ship
  the `arbitrary` + ChaCha8 value generator.
- [ ] ed25519: keys, sign/verify with commonware's namespace/union_unique message framing,
  batch verify, codec encodings, `certificate` scheme. Vectors from ed25519/.
- [ ] secp256r1: standard and recoverable signatures, codec, certificate scheme.
- [ ] certificate.rs: the certificate scheme abstraction and mocks.
- [ ] chacha20_poly1305, transcript.rs, secret.rs, lthash, bloomfilter (+ conformance).
- [ ] handshake (sake) used by `stream`.
- [ ] reed_solomon (needed by `coding`), banderwagon, zk (bulletproofs, pedersen) last.
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
