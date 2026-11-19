# coding

Encode data to enable recovery from a subset of fragments.

A Zig port of commonware's
[`commonware-coding`](https://github.com/commonwarexyz/monorepo/tree/main/coding).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port is complete. [docs/lanes/coding.md](../../docs/lanes/coding.md) tracks it,
including its test audit.

## Modules

- `Config`, `assert_scheme` ([root.zig](root.zig)): shard counts, and the comptime `Scheme`
  interface every coding scheme provides.
- `reed_solomon`, `ReedSolomon(H)` ([reed_solomon/mod.zig](reed_solomon/mod.zig)): a
  Reed-Solomon scheme whose shards are provable against a binary Merkle tree.
- `fuzz` ([fuzz.zig](fuzz.zig)): the `reed_solomon` fuzz target of commonware's `coding/fuzz`.

## Testing

```sh
zig build test-coding                          # unit tests, including the minifuzz searches
zig build bench -Dbench-filter=reed_solomon    # encode, decode, and size benchmarks (ReleaseFast)
```

`zig build test` also runs each benchmark once on its smoke inputs. For long, coverage-guided
fuzzing, run `zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

All of these are recorded in the [coding lane decisions](../../docs/lanes/coding.md#decisions).

- Errors carry no payload. Their names match commonware's `Error` variants.
- Shards and checked shards borrow their bytes from the encoding's `codeword` or the decoded
  input, instead of holding a `Bytes` refcount. `Encoding.deinit` frees them.
- Each stripe task creates its own coder and reuses it across its tiles. Commonware caches one
  encoder and decoder per thread.
- The engine is chosen at compile time (`DefaultEngine = Simd`, which is `Scalar` without AVX2
  or NEON) instead of by runtime CPU detection. Every engine produces identical bytes.
- `encode_iobufs` is not ported, because the codec has no vectored writes.
