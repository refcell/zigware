# curve25519

Perform Curve25519 field/group arithmetic, Ed25519 signing and verification, and X25519 key
exchange.

A Zig port of commonware's [`commonware-cryptography-curve25519`][crate].

[crate]: https://github.com/commonwarexyz/monorepo/tree/main/cryptography/curve25519

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
Every backlog item in [docs/lanes/curve25519.md](../../../docs/lanes/curve25519.md) is checked
off: vectors, conformance hashes, unit tests, fuzz plans, benches, and batch verification.

## Modules

- `signing` ([signing.zig](signing.zig)): `SigningKey`, `VerifyingKey`, and `Signature`.
  Ed25519 with namespaced and raw signing, ZIP-215 verification, and batch verification.
- `key_exchange` ([key_exchange.zig](key_exchange.zig)): X25519 (RFC 7748). `exchange` rejects
  an all-zero shared secret, and `deinit` zeroizes secret keys and shared secrets.
- `batch` ([batch.zig](batch.zig)): the crate's batch verification, with SHA-512 counter-mode
  coefficients and a bucket multi-scalar multiplication.

## Testing

```sh
zig build test-curve25519                         # unit tests, vectors, and seeded fuzz
zig build bench -Dbench-filter=curve25519::       # sign, verify, x25519 (ReleaseFast)
```

`-Dbench-filter=batch_verify::` runs the batch verification benchmark. `zig build test` also
runs each benchmark once on its smoke inputs. The fuzz plans run as minifuzz searches and as
a coverage-guided target ([fuzz_test.zig](fuzz_test.zig)). For long fuzz runs, use
`zig build test --fuzz -Doptimize=ReleaseSafe`. The conformance test skips in Debug unless
you pass `-Dslow-tests`.

## Differences from commonware

Unless noted, these are recorded in the
[curve25519 lane decisions](../../../docs/lanes/curve25519.md#decisions).

- Field and group arithmetic is `std.crypto`'s (`ed25519.core` with a lenient decoder, and
  `std.crypto.dh.X25519`), where the vectors prove it agrees. Single verification ports the
  crate's half-size Straus check and its AVX-512 IFMA point backend. The bucket MSM runs on IFMA,
  then curve25519-dalek's AVX2 backend, then std's arithmetic. The crate's portable and NEON
  backends are not ported. See the [crypto lane log](../../../docs/lanes/crypto.md#log) and
  [BENCHMARKS.md](../../../docs/BENCHMARKS.md#updates-since-the-table).
- `verify_batch` takes no allocator. Each batch is cut into chunks of at most 128 signatures on
  the stack, and the window width is fixed at 6 bits, so `width_for` is not ported.
- The verdict of a batch depends only on its items and seed, at every thread count.
- The fuzz tests compare against [reference.zig](reference.zig), an independent, naive
  implementation, instead of `ed25519-consensus` and `x25519-dalek`.
- The package lives at `src/cryptography/curve25519`, like the crate.
