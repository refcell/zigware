# math

Create and manipulate mathematical objects.

A Zig port of commonware's
[`commonware-math`](https://github.com/commonwarexyz/monorepo/tree/main/math).

## Status

Stability upstream varies by primitive. lib.rs puts `algebra` and `poly` in the **BETA** scope.
`fields::goldilocks`, `ntt`, `synthetic`, `test`, and `fuzz` are ALPHA, and so are a few items
inside `algebra` and `poly`.
See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
The math backlog item in [docs/lanes/bls-math.md](../../docs/lanes/bls-math.md) is done, and
its test audit ports all 24 of math's tests. The lane records that math's conformance hashes
wait for the `conformance` harness.

## Modules

- `algebra` ([algebra.zig](algebra.zig)): comptime interfaces for additive groups, rings,
  fields, modules (`Space`), and cryptographic groups, with `exp`, `scale`, and `msm`.
- `fields.goldilocks` ([fields/goldilocks.zig](fields/goldilocks.zig)): the field of integers
  modulo 2^64 - 2^32 + 1.
- `ntt` ([ntt.zig](ntt.zig)): number theoretic transforms, batch evaluation and interpolation,
  and erasure recovery.
- `poly` ([poly.zig](poly.zig)): `Poly(K)` polynomials, commitments, and interpolation.
- `synthetic` ([synthetic.zig](synthetic.zig)): `Synthetic(F, G)`, linear combinations of free
  generators and concrete points.
- `testing` ([testing.zig](testing.zig)): a small prime field `F` and group `G` for testing
  generic code, and `smith_body`, which runs minifuzz bodies under `std.testing.fuzz`.
- `fuzz_plan` ([root.zig](root.zig)): the crate's fuzz plan, which picks one module's plan.

## Testing

```sh
zig build test-math                           # unit tests and the seeded minifuzz plan
zig build bench -Dbench-filter=interpolation  # interpolation benchmarks (ReleaseFast)
```

`zig build test` also runs each benchmark once on its smoke inputs. For long, coverage-guided
fuzz runs, use `zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

All of these are recorded in the
[bls-math lane decisions](../../docs/lanes/bls-math.md#decisions).

- Algebraic types are value types with `zero` and `one` decls and `add`, `sub`, `neg`, `mul`,
  `inv`, and `eql` methods. `math.algebra` supplies the trait defaults.
- Groups and fields share one `Space` interface: a module element `K` over scalars `R`
  multiplies with `K.mul(K, R)`.
- `Poly(K).Cfg` is `codec.SliceCfg`, which always rejects zero coefficients.
  `Poly(K).max_encode_size_with(n)` is commonware's `Poly::max_encode_size(n)`.
- Randomness comes in as a `utils.rng` generator pointer, so ported tests draw the same values
  as the Rust tests.
- Property tests run on `invariants.minifuzz` with commonware's draw order.
