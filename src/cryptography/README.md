# cryptography

Generate keys, sign arbitrary messages, and deterministically verify untrusted signatures.

A Zig port of commonware's
[`commonware-cryptography`](https://github.com/commonwarexyz/monorepo/tree/main/cryptography).

## Status

Upstream stability varies by primitive. **BETA** (wire and storage formats are stable, and
breaking changes come with a migration path): `bls12381`, `certificate`, `ed25519`, `secret`,
`transcript`, `sha256`, `blake3`, `crc32`, `chacha20_poly1305`, `handshake`, and the signing
and hashing traits. A few items inside these modules are ALPHA. Everything else is **ALPHA**
(breaking changes expected). See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
Every cryptography item in the backlog of [docs/lanes/crypto.md](../../docs/lanes/crypto.md)
is checked off. Its one open item is the simplex voter tests, which live in `consensus`.
`bls12381/` is tracked in [docs/lanes/bls-math.md](../../docs/lanes/bls-math.md) and
`reed_solomon/` in [docs/lanes/coding.md](../../docs/lanes/coding.md). Every backlog item in
both is checked off.

## Modules

- `signer`, `digestible` ([signer.zig](signer.zig), [digestible.zig](digestible.zig)): the
  signing, `Cipher`, `Digestible`, and `Committable` traits as comptime interfaces.
- `digest`, `hasher` ([digest.zig](digest.zig), [hasher.zig](hasher.zig)): `Digest(length,
  name)`, one distinct type per hasher, and the hasher interface (`assert_hasher`).
- `Sha256`, `Sha512`, `Blake3`, `Keccak256`, `Crc32` ([sha256.zig](sha256.zig),
  [sha512.zig](sha512.zig), [blake3.zig](blake3.zig), [keccak256.zig](keccak256.zig),
  [crc32.zig](crc32.zig)): hashers. `Crc32` is CRC-32C and only detects accidental corruption.
- `ed25519` ([ed25519.zig](ed25519.zig)): Ed25519 keys and signatures, verified with ZIP-215.
- `secp256r1` ([secp256r1.zig](secp256r1.zig)): P-256 keys with deterministic, low-`s`
  signatures, in `standard` and `recoverable` forms.
- `bls12381` ([bls12381/root.zig](bls12381/root.zig)): BLS12-381 signatures, threshold
  signatures, DKG, and timelock encryption.
- `certificate` ([certificate.zig](certificate.zig)): attestations from participants that a
  quorum assembles into a certificate.
- `ChaCha20Poly1305` ([chacha20_poly1305.zig](chacha20_poly1305.zig)): authenticated
  encryption of an ordered sequence of messages under one key.
- `Transcript` ([transcript.zig](transcript.zig)): hashes a sequence of messages into a
  `Summary`, and forks, signs, and draws randomness from it.
- `handshake` ([handshake.zig](handshake.zig)): the `sake` authenticated key exchange.
- `Secret` ([secret.zig](secret.zig)): a secret value that never formats, compares in constant
  time, and is zeroized on `deinit`.
- `ChaCha20Rng` ([rng.zig](rng.zig)): byte-identical to Rust `rand_chacha` 0.10, so
  `from_seed` keys match commonware's.
- `LtHash`, `BloomFilter` ([lthash.zig](lthash.zig), [bloomfilter.zig](bloomfilter.zig)): a
  homomorphic lattice hash and a Bloom filter.
- `reed_solomon` ([reed_solomon/root.zig](reed_solomon/root.zig)): Reed-Solomon erasure
  coding over GF(2^16).
- `zk`, `banderwagon` ([zk.zig](zk.zig), [banderwagon.zig](banderwagon.zig)): arithmetic
  circuits, Bulletproofs, and the Pedersen-to-plain proof, and the Banderwagon group.

## Testing

```sh
zig build test-cryptography                    # unit tests, vectors, and seeded fuzz
zig build bench -Dbench-filter=ed25519::       # ed25519 benchmarks (ReleaseFast)
```

Other bench prefixes: `sha256::`, `sha512::`, `blake3::`, `secp256r1::`, `bls12381::`,
`chacha20_poly1305::`, `lthash::`, `bloomfilter::`, `sake::`, `bulletproofs::`, and
`reed_solomon::`. `zig build test` also runs each benchmark once on its smoke inputs.
`-Dslow-tests` runs the slow conformance hashes. For long fuzz runs, use
`zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

- BLS operations take a `strategy` only where commonware's parallel path is ported:
  `PublicKey.verify_batch` hashes messages through it, and `G1`/`G2.msm_strategy` sums in
  strategy-cut tiles. Results never depend on the strategy shape
  ([bls-math decisions](../../docs/lanes/bls-math.md#decisions)).
- Traits are comptime interfaces, and each hasher has its own `Digest` type. See the
  [crypto lane log](../../docs/lanes/crypto.md#log).
- Hashing never allocates. `finalize` resets the hasher in place, and `hash_many` writes into
  a caller-provided slice. See the [crypto lane log](../../docs/lanes/crypto.md#log).
- `hash_across` and `hash_pair` run on the calling thread, because `std.crypto`'s BLAKE3 does
  not expose the chaining values that parallel subtree hashing needs. Digests are identical.
  See the [crypto lane log](../../docs/lanes/crypto.md#log).
- secp256r1 signs with its own RFC 6979 nonce generator on std's P-256 arithmetic, since
  `std.crypto.sign.ecdsa` is not RFC 6979. See the
  [crypto lane log](../../docs/lanes/crypto.md#log).
- Errors carry no payload. For example, SAKE's `InvalidTimestamp` drops the value and range.
  See the [crypto lane log](../../docs/lanes/crypto.md#log).
- BLS12-381 scalar multiplication is variable time, where commonware uses blst's constant-time
  code, so signing leaks timing. See the
  [bls-math lane decisions](../../docs/lanes/bls-math.md#decisions).
- The Reed-Solomon engine is chosen at compile time, not by runtime CPU detection. Every
  engine produces identical bytes. See the
  [coding lane decisions](../../docs/lanes/coding.md#decisions).
