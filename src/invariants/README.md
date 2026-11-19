# invariants

Define and exercise invariants.

A Zig port of commonware's
[`commonware-invariants`](https://github.com/commonwarexyz/monorepo/tree/main/invariants).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The invariants item in the backlog of [docs/lanes/codec.md](../../docs/lanes/codec.md) is
checked: minifuzz and `Unstructured`, with the crate's tests and a byte-exact sampler vector.

## Modules

- `minifuzz` ([minifuzz.zig](minifuzz.zig)): a deterministic fuzz harness for unit tests.
  `run` uses the default `Builder`; `Builder` sets the seed, search limit or time, minimum
  iterations, and a token to reproduce. A failure prints a `MINIFUZZ_BRANCH` token that
  replays it.
- `Unstructured` ([unstructured.zig](unstructured.zig)): arbitrary 1.4's byte decoder. The same
  bytes give the same values as in Rust.

## Testing

```sh
zig build test-invariants                           # unit tests, including minifuzz searches
zig build test -Dminifuzz-branch=0x...              # replay a minifuzz failure in every test
zig build test-invariants -Dfuzz-soak=10            # run ten times more search cases
```

## Differences from commonware

- minifuzz runs `default_search_limit` (10000) cases times `-Dfuzz-soak`, instead of searching
  for 10 s, because time needs a `std.Io`. `with_search_time(io, duration)` takes one. See the
  [codec lane decisions](../../docs/lanes/codec.md#decisions).
- The default seed comes from `-Dfuzz-seed` instead of the OS. See the
  [codec lane decisions](../../docs/lanes/codec.md#decisions).
- A failure replays with `-Dminifuzz-branch` instead of the `MINIFUZZ_BRANCH` environment
  variable. See the [codec lane decisions](../../docs/lanes/codec.md#decisions).
- After the search passes, minifuzz runs long-input cases of 128, 512, and 2048 random bytes,
  so bodies whose generators pad with zeros reach their later actions. See the
  [codec lane's minifuzz API][minifuzz-api].

[minifuzz-api]: ../../docs/lanes/codec.md#invariants-minifuzz-for-other-lanes-property-tests
