# Lane: crypto

Owns `src/cryptography` except `src/cryptography/bls12381/` (lane bls-math). You own
`src/cryptography/root.zig`; bls-math adds its `pub const bls12381 = ...` line there.

Reference: `~/.cache/zigware/commonware-ref/cryptography`. Uses `codec` for encodings: until
it lands, write fixed-size `encode`/`decode` methods and switch when codec's API is in.

## Backlog
- [ ] Core traits as comptime interfaces: `Signer`, `PrivateKey`, `PublicKey`, `Signature`,
  `Verifier`, `BatchVerifier`, `Hasher`, `Digest`, `Committable`/`Digestible` (lib.rs).
- [ ] Hashes: sha256 (with namespaced union/digest helpers), sha512, blake3, keccak256,
  crc32. Use `std.crypto` where it is correct and fast; match commonware's test vectors.
- [ ] ed25519: keys, sign/verify with commonware's namespace/union_unique message framing,
  batch verify, codec encodings, `certificate` scheme. Vectors from ed25519/.
- [ ] secp256r1: standard and recoverable signatures, codec, certificate scheme.
- [ ] certificate.rs: the certificate scheme abstraction and mocks.
- [ ] chacha20_poly1305, transcript.rs, secret.rs, lthash, bloomfilter (+ conformance).
- [ ] handshake (sake) used by `stream`.
- [ ] reed_solomon (needed by `coding`), banderwagon, zk (bulletproofs, pedersen) last.
- [ ] Fuzz targets (commonware cryptography/fuzz) and conformance hashes.

## Log
