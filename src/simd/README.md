# simd

Abstract over SIMD operations.

A Zig port of commonware's
[`commonware-simd`](https://github.com/commonwarexyz/monorepo/tree/main/simd).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The simd items in the backlog of [docs/lanes/bls-math.md](../../docs/lanes/bls-math.md) are
checked: the operations of commonware's `core.rs`, scalar and `@Vector` implementations with
the consistency tests, and a differential fuzz target.

## Modules

- `Profile`, `Backend` ([core.zig](core.zig)): the backend profiles (`scalar`, `x86_v3`,
  `x86_v4c`, `neon`, `arm_v9`) and a zero-size token per profile whose methods operate on
  vectors of `u8`, `u32`, and `u64` lanes.
- `EmulatedScalar`, `EmulatedX86V3`, `EmulatedX86V4C`, `EmulatedNeon`, `EmulatedArmV9`
  ([core.zig](core.zig)): the backend for each profile.
- `native_profile`, `Native` ([core.zig](core.zig)): the best profile for the compile target's
  CPU features, and its backend.
- `dispatch`, `test_dispatch` ([core.zig](core.zig)): run an operation on the `Native`
  backend, or on the scalar backend so tests agree on every host. An operation declares
  `Output`, a `portable` path, and optional profile paths.
- `check_consistent` ([core.zig](core.zig)): checks that an operation gives the scalar
  backend's output on every other profile.

## Testing

```sh
zig build test-simd  # unit tests, including the seeded differential fuzz
```

A `std.testing.fuzz` target checks the common instructions against lane oracles too; for long
runs use `zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

- One `@Vector` implementation per profile stands in for both commonware's emulated and native
  tokens. See the [bls-math lane decisions](../../docs/lanes/bls-math.md#decisions).
- `dispatch` picks the compile target's best profile at comptime. See the
  [bls-math lane decisions](../../docs/lanes/bls-math.md#decisions).
- Profile-only instructions are `void` on other profiles, so misusing one is a compile error.
  See the [bls-math lane decisions](../../docs/lanes/bls-math.md#decisions).
- Tokens and vectors carry no `Send` or `Sync` bounds: Zig has none, and they are plain values
  any thread may hold. See the [simd drift notes][simd-drift].

[simd-drift]: ../../docs/lanes/bls-math.md#drift-simd-commonware-43b357a41a9ffc25f3
